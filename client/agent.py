#########################
######## Imports ########
#region##################
import platform
import getpass
import socket
import ctypes
import os
import subprocess
import re
import json
from datetime import datetime
import time
import urllib.request
import urllib.error
import winreg
import ssl

#endregion###############
# Configuration Options #
#region##################

DISARM = True
DEBUG_PRINT = True
BACKUPDIR = ""
LOGFILE = "log.txt" #"agent_log.txt"
MTU_MIN = 1200
MTU_DEFAULT = 1300
MTU_MAX = 1514
AGENT_NAME="agenttest1"
SERVER_URL="https://127.0.0.1:8080/beacon" #192.168.1.37
AUTH_TOKEN="testtoken"
AGENT_TYPE="stabvest"
SERVER_TIMEOUT=5
REGISTRY_HIVE = winreg.HKEY_LOCAL_MACHINE
SERVICE_PATH = r"SYSTEM\\CurrentControlSet\\Services\\service_name" #replace with actual service name

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

#endregion###############
# Generic Helper Funcs ##
#region##################

def print_debug(msg):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if (DEBUG_PRINT):
        print(msg)
    if LOGFILE:
        if len(LOGFILE) > 0:
            with open(LOGFILE, "a") as f:
                f.write(f"{timestamp} {msg}\n")
    return

def get_reg_val(key, service_path=SERVICE_PATH, reg_hive=REGISTRY_HIVE):
    '''
    Given a registry key name (variable), returns its value from the specified service path and hive.
    Args: key(String), service_path(String), reg_hive(winreg.HKEY_*)
    Returns: result(deepnds on the type of the registry key)
    '''
    result = None
    try:
        oKey = winreg.OpenKeyEx(reg_hive, service_path)
        result = winreg.QueryValueEx(oKey, key)[0] 
        winreg.CloseKey(oKey)
    except Exception as e:
        print_debug(f"get_reg_val(): {e}")
    return result

def get_os(simple=False):
    """
    Gets the approximately OS used, simplified to highest level possible
    For example: Ubuntu, Debian, Rocky, RHEL, Windows Workstation (7 8 10 11), Windows Server (2012 2016 2022 2025)

    Args: simple(Bool)
    Returns: osType(String)
    """
    system = platform.system()

    if system == "Linux":
        if simple:
            return platform.dist()[1] # Ubuntu, debian, redhat
        return ' '.join(platform.dist()) # Ubuntu 10.04 lucid, debian 4.0 , fedora 17 Beefy Miracle, redhat 5.6 Tikanga, redhat 5.9 Final (<- centos)

    if simple:
        return platform.system() # Windows, FreeBSD
    return f"{platform.system()} {platform.release()}" #Windows 10, Windows 2016Server, FreeBSD XXX

def get_perms():
    """
    Gets the execution perm level (user and elevation level).
    Intentionally
    Returns: isRunAsElevated(bool), runAsUser(String)
    """

    system = platform.system()

    if system == "Windows":
        try:
            # Windows admin check using IsUserAnAdmin
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            # Fallback if call fails
            is_admin = False

        # Determine domain/local username
        # USERDOMAIN = domain or machine name
        domain = os.environ.get("USERDOMAIN", None)
        user = getpass.getuser()

        if domain:
            runAsUser = f"{domain}\\{user}"
        else:
            runAsUser = user
        
        return is_admin, runAsUser
    
    if system in ("Linux", "FreeBSD"):
        # euid 0 - root OR sudo
        is_root = (os.geteuid() == 0)

        # Detect sudo
        sudo_user = os.environ.get("SUDO_USER")
        if sudo_user:
            runAsUser = sudo_user
        else:
            # Normal user or directly root
            runAsUser = getpass.getuser()

        return is_root, runAsUser
    
    # Unknown OS - shouldn't reach
    print_debug("get_perms(): reached unexpected unsupported OS block")
    return False, runAsUser

def get_primary_ip():
    """
    Attempts to get the primary IP address of the local machine.
    Returns: ip(String) or "0.0.0.0" if failed
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Connect to an external host (e.g., Google's public DNS or test-net-3)
        # This doesn't send any data, just establishes a connection to find out which local interface would be used.
        s.connect(("8.8.8.8", 80)) # 203.0.113.2 # Doesn't need to be reachable. Use non-routable address for stealth
        ip_address = s.getsockname()[0]
    except Exception as E:
        ip_address = "0.0.0.0"
        print_debug(f"get_primary_ip(): {E}")
    finally:
        s.close()
    return ip_address

def get_system_details():
    """
    Builds the overall system info dictionary
    Returns: sysInfo(dict)
    """
    sysInfo = {
        "os": get_os(),
        "executionUser": get_perms()[1],
        "executionAdmin": get_perms()[0],
        "hostname": socket.gethostname(), #alt: socket.getfqdn()
        "ipadd": get_primary_ip()
    }
    return sysInfo

def create_backup_primary(path,backupDir=BACKUPDIR):
    """
    Creates a new primary backup by compressing the value of the path variable into a zip folder and placing it at backupDir.
    If there is already a file at backupDir, move it to backupDir-TIMESTAMP and return that path.
    All backup files should be timestomped to a random value plus or minus 24 hours to the value of /bin/sh or C:\\Windows\\system32\\cmd.exe
    Returns: Success(bool), oldDir(String)
    """
    return True, ""

def run_powershell(cmd,noisy=True):
    """
    Run a PowerShell command and return stdout text.

    Returns: output if success, "" if failure
    """
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", cmd],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        if noisy:
            print_debug(f"PowerShell error: {result.stderr}")
        return "" # This probably breaks a lot tbh
    return result.stdout

def audit_command(command,package="",packageManager="apt"):
    """
    Given a command, ensures that it is available.
    Unmasks the binary, makes it executable, reinstalls it if missing.
    Currently does not support Windows.
    Returns Success(bool) and RemediationAttempted(bool)
    """
    return True, True

#endregion###############
## Server Comms Funcs ###
#region##################

def send_message(oldStatus,newStatus,message,systemInfo=get_system_details()):
    """
    Sends the specified data to the server
    Handles the full process and attaching agent name/auth

    Args: message(any)
    Returns: status(Bool)
    """
    if not SERVER_URL:
        # Server comms are intentionally disabled
        # Maybe redirect to print_debug instead?
        return True

    # Prep payload
    payload = {
        "name": AGENT_NAME,
        "hostname": systemInfo["hostname"],
        "ip": systemInfo["ipadd"],
        "os": systemInfo["os"],
        "executionUser": systemInfo["executionUser"],
        "executionAdmin": systemInfo["executionAdmin"],
        "auth": AUTH_TOKEN,
        "beacon_type": AGENT_TYPE,
        "oldStatus": oldStatus,
        "newStatus": newStatus,
        "message": message
    }

    try:
        # Prepare data
        data = json.dumps(payload).encode("utf-8")

        # Build request
        req = urllib.request.Request(
            SERVER_URL,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )

        # Send payload
        with urllib.request.urlopen(req, timeout=SERVER_TIMEOUT, context=CTX) as response:
            if response.getcode() == 200:
                # Parse result if we get one. Actually, we don't care as it's just one way
                #response_body = response.read().decode("utf-8")
                #result = json.loads(response_body)
                return True
            else:
                print_debug(f"[-] Server error: {response.getcode()}")

    # Error handling
    except urllib.error.HTTPError as e:
        print_debug(f"[!] HTTP error: {e.code} {e.reason}")
    except urllib.error.URLError as e:
        print_debug(f"[!] URL error: {e.reason}")
    except Exception as e:
        # Various requests errors - networking failure or 4xx/5xx code from server
        print_debug(f"[!] Beacon error: {e}")
    return False

#endregion###############
# Network Protect Funcs #
#region##################

def interface_get_primary():
    """
    Determines the primary network interface based on finding the interface with the primary IP.
    Returns: interface(String)
    """
    system = platform.system()

    if system == "Windows":
        return interface_get_primary_windows(get_primary_ip())
    else:
        return interface_get_primary_unix(get_primary_ip())

def interface_get_primary_windows(ip):
    """
    Gets interface name on unix using "ip" or "ifconfig"
    TODO: make this not be AI slop
    Returns: interface(String) or None
    """
    output = subprocess.check_output(["ipconfig"], text=True, encoding="utf-8", errors="ignore")

    current_iface = None
    for line in output.splitlines():
        line = line.strip()

        # Interface header (e.g., "Ethernet adapter Ethernet:")
        m = re.match(r"(.+?) adapter (.+?):", line, re.IGNORECASE)
        if m:
            current_iface = m.group(2)
            continue

        # IPv4 Address line
        if "IPv4 Address" in line and ip in line:
            return current_iface

    return None

def interface_get_primary_unix(ip):
    """
    Gets interface name on unix using "ip" or "ifconfig"
    TODO: make this not be AI slop
    Returns: interface(String) or None
    """
    # Try "ip address"
    try:
        output = subprocess.check_output(["ip", "-4", "addr"], text=True)
        iface = None
        for line in output.splitlines():
            line = line.strip()

            # Match interface header: "2: ens33:"
            m = re.match(r"\d+:\s+([^:]+):", line)
            if m:
                iface = m.group(1)
                continue

            # Match "inet 192.168.1.10/24"
            if line.startswith("inet ") and ip in line:
                return iface
    except Exception:
        pass

    # Fallback: try "ifconfig"
    try:
        output = subprocess.check_output(["ifconfig"], text=True)
        iface = None
        for line in output.splitlines():
            # Interface header: "eth0: flags=..."
            m = re.match(r"^([a-zA-Z0-9._-]+):\s", line)
            if m:
                iface = m.group(1)
                continue

            # "inet 192.168.1.10"
            if "inet " in line and ip in line:
                return iface
    except Exception:
        pass

    return None

def interface_address(interface,ip_address,subnet,gateway):
    """
    Wrapper for interface_address_*

    Given an interface name, check if its IP address and gateway are set, and restore them from backup if not
    Note: Does NOT determine if ip_address and gateway exist but doesn't match the backup
    
    Args: interface name(string), ip_address(string), subnet(int), gateway(string)
    Returns: oldStatus(bool), newStatus(bool), issues(list of strings)
    """
    system = platform.system()

    if system == "Windows":
        return interface_address_windows(interface,ip_address,subnet,gateway)
    else:
        return False, False, [f"interface_address(): not implemented for system {system}."] # TODO

def interface_address_windows(interface,ip_address,subnet,gateway):
    """
    Given an interface name, check if its IP address and gateway are set, and restore them from backup if not
    Note: Does NOT determine if ip_address and gateway exist but doesn't match the backup
    
    Args: interface name(string), ip_address(string), subnet(int), gateway(string)
    Returns: oldStatus(bool), newStatus(bool), issues(list of strings)
    """
    issues = []

    # Query configuration
    query_cmd = fr"""
        Get-NetIPConfiguration -InterfaceAlias '{interface}' |
        Select-Object IPv4Address, IPv4DefaultGateway | ConvertTo-Json
    """

    output = run_powershell(query_cmd)
    if not output:
        #print_debug(f"interface_address_windows({interface}): Failed to query interface")
        return False, False, [f"Failed to query interface {interface} due to PowerShell error."]

    # Parse JSON result
    try:
        data = json.loads(output)
    except json.JSONDecodeError as E:
        #print_debug(f"interface_address_windows({interface}): Error parsing PowerShell output")
        return False, False, [f"Failed to query interface {interface} due to PowerShell JSON parsing error."]

    # Determine if address or gateway exist
    has_address = bool(data.get("IPv4Address"))
    has_gateway = bool(data.get("IPv4DefaultGateway"))

    # Diagnostics
    if has_address and has_gateway:
        return True, True, []

    statusFix = True
    # Fix missing IPv4 address
    if not has_address:
        set_ip_cmd = fr"""
            New-NetIPAddress -InterfaceAlias '{interface}' |
            -IPAddress {ip_address} -PrefixLength {subnet}
        """
        if DISARM:
            #print_debug(f"interface_address_windows({interface}): DISARMED, but told to set IP address: {ip_address}/{subnet}")
            issues.append(f"Missing IPv4 Address for interface {interface}, DISARMED.")
            statusFix = False
        else:
            #print_debug(f"interface_address_windows({interface}): Setting IP address: {ip_address}/{subnet}")
            if not run_powershell(set_ip_cmd):
                statusFix = False
                issues.append(f"Missing IPv4 Address for interface {interface}, FAILED to restore {ip_address}/{subnet}.")
            else:
                issues.append(f"Missing IPv4 Address for interface {interface}, RESTORED {ip_address}/{subnet}.")

    # Fix missing gateway
    if not has_gateway:
        set_gw_cmd = (
            f"New-NetRoute -InterfaceAlias '{interface}' "
            f"-DestinationPrefix '0.0.0.0/0' -NextHop {gateway}"
        )
        if DISARM:
            #print_debug(f"interface_address_windows({interface}): DISARMED, but told to set gateway address: {gateway}")
            issues.append(f"Missing Gateway Address for interface {interface}, DISARMED.")
            statusFix = False
        else:
            #print_debug(f"interface_address_windows({interface}): Setting gateway address: {gateway}")
            if not run_powershell(set_gw_cmd):
                statusFix = False
                issues.append(f"Missing Gateway Address for interface {interface}, FAILED to restore {gateway}.")
            else:
                issues.append(f"Missing Gateway Address for interface {interface}, RESTORED {gateway}.")

    return False, statusFix, issues

def interface_mtu(interface=interface_get_primary(),mtu_minimum=MTU_MIN,mtu_maximum=MTU_MAX,mtu_default=MTU_DEFAULT):
    """
    Wrapper for interface_mtu_*

    Given an interface name, check if its MTU is within an acceptable range and remediate if not
    
    Args: interface name(string), mtu_min(int), mtu_max(int), mtu_default(int)
    Returns: oldStatus(bool), newStatus(bool), issues(list of strings)
    """
    system = platform.system()

    if system == "Windows":
        return interface_mtu_windows(interface,mtu_minimum,mtu_maximum,mtu_default)
    else:
        return False, False, [f"interface_mtu(): not implemented for system {system}."] # TODO

def interface_mtu_windows(interface=interface_get_primary(),mtu_minimum=MTU_MIN,mtu_maximum=MTU_MAX,mtu_default=MTU_DEFAULT):
    """
    Given an interface name, check if its MTU is within an acceptable range and remediate if not
    
    Args: interface name(string), mtu_min(int), mtu_max(int), mtu_default(int)
    Returns: oldStatus(bool), newStatus(bool), issues(list of strings)
    """

    ps_get_mtu = fr"""
    Get-NetIPInterface -InterfaceAlias "{interface}" -AddressFamily IPv4 |
        Select-Object -ExpandProperty NlMtu
    """

    output = run_powershell(ps_get_mtu).strip()
    if not output:
        return False, False, [f"Failed to query MTU for interface '{interface}' due to PowerShell error."]

    if not output.isdigit():
        #print_debug(f"interface_mtu_windows(): Failed to query MTU for interface '{interface}'. Output: {output}")
        return False, False, [f"Failed to query MTU for interface '{interface}' due to invalid PowerShell output parsing."]

    old_mtu = int(output)

    # Check MTU range
    if old_mtu < mtu_minimum or old_mtu > mtu_maximum:
        new_mtu = mtu_default

        ps_set_mtu = fr'''
        Set-NetIPInterface -InterfaceAlias "{interface}" -NlMtu {new_mtu}
        '''

        if DISARM:
            #print_debug(f"DISARMED, but told to updated MTU for '{interface}' from {old_mtu} to {new_mtu}")
            return False, False, [f"Interface {interface}'s MTU was set to {old_mtu}, DISARMED."]
        else:
            #print_debug(f"Updated MTU for '{interface}' from {old_mtu} to {new_mtu}")
            if run_powershell(ps_set_mtu):
                return False, True, [f"Interface {interface}'s MTU was set to {old_mtu}, RESTORED new mtu {new_mtu}."]
            else:
                return False, False, [f"Interface {interface}'s MTU was set to {old_mtu}, FAILED to restore new mtu {new_mtu}."]

    return True, True, []

def interface_ttl(interface=interface_get_primary()):
    """
    Wrapper for interface_ttl_*

    Given an interface name, check if its TTL is within an acceptable range and remediate if not
    
    Args: interface name(string)
    Returns: oldStatus(bool), newStatus(bool), issues(list of strings)
    """
    system = platform.system()

    if system == "Windows":
        return interface_mtu_windows(interface)
    else:
        return False, False, [f"interface_ttl(): not implemented for system {system}."] # TODO

def interface_ttl_windows():
    """
    Given an interface name, check if its TTL is within an acceptable range and remediate if not
    
    Args: interface name(string)
    Returns: oldStatus(bool), newStatus(bool), issues(list of strings)
    """

    check_script = r"""
    $path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"

    if (Test-Path -Path "$path\DefaultTTL" -ErrorAction SilentlyContinue) {
        Write-Output 'True'
    }
    elseif (Test-Path -Path "$path\DefaultCurHopLimit" -ErrorAction SilentlyContinue) {
        Write-Output 'True'
    }
    else {
        Write-Output 'False'
    }
    """

    result = run_powershell(check_script).strip()
    
    if result:
        # Reg key exists and is (presumably) not the default, so report and delete it
        delete_script = r"""
        $path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"

        if (Test-Path "$path\DefaultTTL" -ErrorAction SilentlyContinue) {
            Remove-ItemProperty -Path $path -Name "DefaultTTL"
        }
        if (Test-Path "$path\DefaultCurHopLimit" -ErrorAction SilentlyContinue) {
            Remove-ItemProperty -Path $path -Name "DefaultCurHopLimit"
        }

        Write-Output 'Deleted'
        """
        if DISARM:
            #print_debug(f"interface_ttl_windows(): DISARMED, but bad TTL detected and told to delete!")
            return False, False, [f"Bad system TTL set, DISARMED."]
        else:
            ps_result = run_powershell(delete_script).strip()
            if ps_result:
                return False, True, [f"Bad system TTL set, RESTORED default TTL."]
            return False, False, [f"Bad system TTL set, FAILED to restore default TTL."]

    # Reg key(s) do not exist so system is (presumably) using the default of 128 (good)
    return True, True, []

def interface_down(interface=interface_get_primary()):
    """
    Wrapper for interface_down_*

    Given an interface name, check if it is in the down state and remediate if yes
    
    Args: interface name(string)
    Returns: oldStatus(bool), newStatus(bool), issues(list of strings)
    """
    system = platform.system()

    if system == "Windows":
        return interface_down_windows(interface)
    else:
        return False, False, [f"interface_down(): not implemented for system {system}."] # TODO

def interface_down_windows(interface=interface_get_primary()):
    """
    Given an interface name, check if it is in the down state and remediate if yes
    
    Args: interface name(string)
    Returns: oldStatus(bool), newStatus(bool), issues(list of strings)
    """

    ps_check = fr"""
    $iface = '{interface}'
    $int = Get-NetAdapter -Name $iface

    if ($int -eq $null) {{
        Write-Output 'NotFound'
    }}
    elseif ($int.Status -eq 'Up') {{
        Write-Output 'Up'
    }}
    else {{
        Write-Output 'Down'
    }}
    """

    status = run_powershell(ps_check).strip()
    
    if not status:
        return False, False, [f"Interface {interface}'s up/down status cannot be determined due to PowerShell error."]

    if status == "NotFound":
        #print_debug(f"interface_down_windows({interface}): Interface not found.")
        return False, False, [f"Interface {interface}'s up/down status cannot be determined as it cannot be found."]

    if status == "Down":
        ps_enable = fr"""
        Enable-NetAdapter -Name '{interface}' -Confirm:$false
        """ # Write-Output 'Enabled'
        if DISARM:
           # print_debug(f"interface_down_windows({interface}): DISARMED, but told to enable interface")
            return False, False, [f"Interface {interface} was set to DOWN, DISARMED."]
        else:
            if run_powershell(ps_enable).strip():
                return False, True, [f"Interface {interface} was set to DOWN, RESTORED UP state."]
            return False, False, [f"Interface {interface} was set to DOWN, FAILED to restore UP state."]
    
    return True, True, []

def interface_uninstall():
    # Not fully implemented
    """
    Wrapper for interface_uninstall_*

    Detects and remediates core networking breaks
    
    Returns: oldStatus(bool), newStatus(bool), issue(string)
    """
    return False, False, [f"interface_uninstall(): not implemented."]

    system = platform.system()

    if system == "Windows":
        return interface_uninstall_windows()
    else:
        return False, False, [f"interface_uninstall(): not implemented for system {system}."] # TODO

def interface_uninstall_windows(interface_name,ipv4_address,prefix_length,gateway,dns_servers):
    # Heavily vibecoded, just left as a placeholder/idea for now
    """
    Detects whether IPv4 is uninstalled on Windows.
    If uninstalled, reinstalls IPv4.
    Then restores static IPv4 settings (address, gateway, DNS).
    """

    # --- Step 1: detect IPv4 presence ---
    ps_detect = r'''
    $int = Get-NetIPInterface -AddressFamily IPv4 -ErrorAction SilentlyContinue
    if ($int -eq $null -or $int.Count -eq 0) { "Missing" } else { "Present" }
    '''

    ipv4_state = run_powershell(ps_detect).strip()

    # --- Step 2: reinstall IPv4 if missing ---
    if ipv4_state == "Missing":
        print("[+] IPv4 is not installed. Reinstalling...")
        ps_install = r'''
        netsh interface ipv4 install
        Write-Output "Installed"
        '''
        run_powershell(ps_install)
    else:
        print("[+] IPv4 already installed.")

    # --- Step 3: restore IPv4 address ---
    print(f"[+] Restoring IPv4 address on {interface_name}...")
    ps_set_ip = fr'''
    netsh interface ipv4 set address name="{interface_name}" static {ipv4_address} {prefix_length} {gateway}
    '''
    run_powershell(ps_set_ip)

    # --- Step 4: restore DNS ---
    print("[+] Restoring DNS servers...")
    # Clear existing DNS entries
    ps_clear_dns = fr'''
    netsh interface ipv4 set dnsservers name="{interface_name}" source=static address={dns_servers[0]} register=primary
    '''
    run_powershell(ps_clear_dns)

    # Add additional DNS servers, if any
    for dns in dns_servers[1:]:
        ps_add_dns = fr'''
        netsh interface ipv4 add dnsservers name="{interface_name}" address={dns} index=2
        '''
        run_powershell(ps_add_dns)

    print("[+] IPv4 configuration restored successfully.")
    return True

def interface_main(interface,ip_address,subnet,gateway):
    """
    Given an interface, detect and remediate (if possible) common issues and returns the remediated issue
    Supports: interface down, bad mtu, no IP address, no route, no default gateway, no connection to 8.8.8.8
    
    Args: interface(String), defaults to interface_get_primary()
    Returns: interfacePriorStatus(bool), interfaceNewStatus(book), issues( list of strings)
    """
    oldStatus = True
    newStatus = True
    issues = []

    # Interface Uninstalled
    # Not implemented
    """
    result_oldStatus, result_newStatus, result_issues = interface_uninstall()
    if not result_oldStatus:
        oldStatus = False
    if not result_newStatus:
        newStatus = False
    for issue in result_issues:
        issues.append(issue)
    """

    # Interface Address
    result_oldStatus, result_newStatus, result_issues = interface_address(interface,ip_address,subnet,gateway)
    if not result_oldStatus:
        oldStatus = False
    if not result_newStatus:
        newStatus = False
    for issue in result_issues:
        issues.append(issue)

    # Interface Down
    result_oldStatus, result_newStatus, result_issues = interface_down()
    if not result_oldStatus:
        oldStatus = False
    if not result_newStatus:
        newStatus = False
    for issue in result_issues:
        issues.append(issue)

    # MTU
    result_oldStatus, result_newStatus, result_issues = interface_mtu(interface)
    if not result_oldStatus:
        oldStatus = False
    if not result_newStatus:
        newStatus = False
    for issue in result_issues:
        issues.append(issue)
    
    # TTL
    result_oldStatus, result_newStatus, result_issues = interface_ttl()
    if not result_oldStatus:
        oldStatus = False
    if not result_newStatus:
        newStatus = False
    for issue in result_issues:
        issues.append(issue)

    return oldStatus, newStatus, issues

def firewall_rules_audit(port,direction="in",action="block"):
    """
    Wrapper for OS-specific firewall_rules_audit_* functions

    Get firewall rules that block traffic on a specific LocalPort and return their names
    Supports ports where firewall rule affects that specific port, range of ports including that port, or firewall rule using comma separated list
    Does NOT support "any port" firewall rules
    
    Args: port (string), direction (string, in or out), action (string, block or accept)
    Returns: issues(list of strings), dictionary of matching rules, with fields Name, DisplayName, Action, Direction, Profile
    """
    system = platform.system()

    if system == "Windows":
        return firewall_rules_audit_windows(port,direction,action)
    else:
        return [f"firewall_rules_audit(): not implemented for system {system}."], dict() # TODO

def firewall_rules_audit_windows(port,direction="in",action="block"):
    """
    Uses Powershell to get Windows Firewall rules that block traffic on a specific LocalPort and return their names
    Supports ports where firewall rule affects that specific port, range of ports including that port, or firewall rule using comma separated list
    Does NOT support "any port" firewall rules
    
    Args: port (string), direction (string, in or out), action (string, block or accept)
    Returns: issues(list of strings), dictionary of matching rules, with fields Name, DisplayName, Action, Direction, Profile
    """

    # Currently unused as returns too many matches
    #if ($lp -eq 'Any') {{ return $true }}

    ps_query = fr"""
    $rules = Get-NetFirewallPortFilter |
        Where-Object {{
            $lp = $_.LocalPort

            if ($lp -like '*,*') {{
                return $lp.Split(',') -contains '{port}'
            }}

            if ($lp -like '*-*') {{
                $a, $b = $lp.Split('-')
                return ({port} -ge [int]$a -and {port} -le [int]$b)
            }}

            return $lp -eq '{port}'
        }} |
        Get-NetFirewallRule |
        Where-Object {{ $_.Direction -eq '{direction}' -and $_.Action -eq '{action}' }} |
        Select-Object Name, DisplayName, Action, Direction, Profile

    if (-not $rules) {{
        "none found"
    }} else {{
        $rules | ConvertTo-Json
    }}
    """

    output = run_powershell(ps_query).strip()

    if not output:
        #print_debug(f"firewall_rules_audit_windows({port},{direction},{action}): No matching firewall rules found")
        return [f"Could not get firewall rule information due to PowerShell error."], dict()

    if output.strip() == "none found":
        return [], dict()
    
    # Convert JSON into Python objects
    try:
        rules = json.loads(output)
    except json.JSONDecodeError:
        #print_debug("Could not decode PowerShell JSON output.")
        #print_debug("Output was:", output)
        return [f"Could not get firewall rule information due to PowerShell JSON error."], dict()

    # Handle the case where PowerShell returns a single object instead of a list
    if isinstance(rules, dict):
        rules = [rules]

    return [], rules

def firewall_rules_delete(rules):
    """
    Wrapper for OS-specific firewall_rules_delete_* functions

    Given a firewall rules dict, deletes each rule
    
    Args: firewall rules dict (Name, DisplayName, Action, Direction, Profile)
    returns: status(bool), issues(list of strings)
    """
    system = platform.system()

    if system == "Windows":
        return firewall_rules_delete_windows(rules)
    else:
        return False, [f"firewall_rules_delete(): not implemented for system {system}."] # TODO

def firewall_rules_delete_windows(rules,port):
    """
    Given a firewall rules dict, deletes each rule
    
    Args: firewall rules dict (Name, DisplayName, Action, Direction, Profile)
    returns: status(bool), issues(list of strings)
    """
    issues = []
    # Delete the rules by Name
    #print_debug("firewall_rules_delete_windows(): Deleting rules...")
    status = True
    for rule in rules:
        if (not DISARM):
            delete_cmd = f"Remove-NetFirewallRule -Name '{rule['Name']}'"
            output = run_powershell(delete_cmd)
            if output:
                #print_debug(f"firewall_rules_delete_windows(): Removed rule: {rule['Name']} ({rule['DisplayName']})")
                issues.append(f"SUCCESSFULLY removed firewall rule: {rule['Name']}/{rule['DisplayName']}: {rule['Action']} {port} {rule['Direction']} on profile {rule['Profile']}.")
            else:
                #print_debug(f"firewall_rules_delete_windows(): FAILED to remove rule: {rule['Name']} ({rule['DisplayName']})")
                issues.append(f"FAILED to remove firewall rule: {rule['Name']}/{rule['DisplayName']}: {rule['Action']} {port} {rule['Direction']} on profile {rule['Profile']}.")
                status = False
        else:
            status = False
            #print_debug(f"firewall_rules_delete_windows(): DISARMED, but told to remove rule: {rule['Name']} ({rule['DisplayName']})")
            issues.append(f"DISARMED, but told to remove firewall rule: {rule['Name']}/{rule['DisplayName']}: {rule['Action']} {port} {rule['Direction']} on profile {rule['Profile']}.")

    #print_debug("firewall_rules_delete_windows(): All provided rules deleted.")
    return status, issues

def firewall_rules_create(port,direction,action):
    """
    Wrapper for OS-specific firewall_rules_create_* functions

    Creates the specified firewall rule

    Args: Port, Direction (inbound/outbound), Action (allow/block)
    Returns: Status(bool), issues(list of strings)
    """
    system = platform.system()

    if system == "Windows":
        return firewall_rules_create_windows(port,direction,action)
    else:
        return False, [f"firewall_rules_create(): not implemented for system {system}."] # TODO

def firewall_rules_create_windows(port,direction,action):
    """
    Creates the specified firewall rule on Windows

    Args: Port, Direction (inbound/outbound), Action (allow/block)
    Returns: Status(bool), issues(list of strings)
    """

    rule_name = f"Stabvest_Rule_{port}_{direction}_{action}"

    ps_cmd = fr"""
    New-NetFirewallRule -DisplayName "{rule_name}" \
                        -Direction {direction} \
                        -Action {action} \
                        -LocalPort {port} \
                        -Profile Any \
                        -ErrorAction Stop
    """

    if DISARM:
        #print_debug(f"firewall_rules_create_windows(): DISARMED, but told to create Stabvest_Rule_{port}_{direction}_{action}")
        return False, [f"DISARMED, but told to create firewall rule Stabvest_Rule_{port}_{direction}_{action}"] # TODO do naming scheme as a config option
    if run_powershell(ps_cmd):
        return True, [f"SUCCESSFULLY created firewall rule Stabvest_Rule_{port}_{direction}_{action}"]
    else:
        return False, [f"FAILED to create firewall rule Stabvest_Rule_{port}_{direction}_{action}"]

def firewall_policy_audit(direction):
    """
    Wrapper for OS-specific firewall_policy_audit_* functions

    Check if any Firewall profile is set to block all connections.

    Args: direction (string, "Inbound" or "Outbound")
    Returns: funcStatus(bool saying if there's errors during execution), policyStatus(bool){True if no policies are set to default deny, False if at least one policy is set to default deny}, issues(list of strings)
    """
    system = platform.system()

    if system == "Windows":
        return firewall_policy_audit_windows(direction)
    else:
        return False, False, [f"firewall_policy_audit(): not implemented for system {system}."] # TODO

def firewall_policy_audit_windows(direction):
    """
    Check if any Windows Firewall profile is set to block all inbound connections.

    Args: direction (string, "Inbound" or "Outbound")
    Returns: funcStatus(bool saying if there's errors during execution), policyStatus(bool){True if no policies are set to default deny, False if at least one policy is set to default deny}, issues(list of strings)
    """
    ps_cmd = f"""
    Get-NetFirewallProfile |
        Select-Object Name, Default{direction}Action |
        ConvertTo-Json
    """
    output = run_powershell(ps_cmd)
    issues = []

    if not output:
        #print_debug("No firewall profile data returned.")
        return False, False, [f"Failed to load firewall policy information due to PowerShell error."]

    try:
        profiles = json.loads(output)
    except json.JSONDecodeError:
        #print_debug("firewall_policy_audit_windows(): Could not decode PowerShell JSON output.")
        return False, False, [f"Failed to load firewall policy information due to could not decode PowerShell JSON output."]

    # Normalize single-object case
    if isinstance(profiles, dict):
        profiles = [profiles]

    for p in profiles:
        if (p[f"Default{direction}Action"] == "Block"):
            # We don't actually care about specific profile but may as well record it
            issues.append([f"Default firewall policy on profile {p[f"Name"]} for direction {direction} is set to BLOCK."])
        
    if issues:
        return True, False, issues
        
    return True, True, []

def firewall_main(protectedPorts):
    """
    Detect and remediate common firewall issues and returns the remediated issue
    Supports: block scored port (including port range), block all without allowing port (including port range)
    
    Args: ports([Array containing single ports as strings])
    Returns: firewallOldStatus(bool), firewallNewStatus(book), issues(String)
    """
    oldStatus = True
    newStatus = True
    issues = []

    # Ports
    for port in protectedPorts:
        result_issues, matched_rules = firewall_rules_audit(port,"in","block")
        if matched_rules:
            oldStatus = False
            remediateStatus, result_issues = firewall_rules_delete(matched_rules,port)
            if not remediateStatus:
                newStatus = False
            for issue in result_issues:
                issues.append(issue)
        else:
            for issue in result_issues:
                issues.append(issue)
        
        result_issues, matched_rules = firewall_rules_audit(port,"out","block")
        if matched_rules:
            oldStatus = False
            remediateStatus, result_issues = firewall_rules_delete(matched_rules,port)
            if not remediateStatus:
                newStatus = False
            for issue in result_issues:
                issues.append(issue)
        else:
            for issue in result_issues:
                issues.append(issue)

    # Policy
    for direction in ["Inbound","Outbound"]:
        funcStatus, policyStatus, result_issues = firewall_policy_audit(direction)
        if funcStatus:
            if not policyStatus:
                for port in protectedPorts:
                    dirShort = ""
                    if direction == "Inbound":
                        dirShort = "in"
                    else:
                        dirShort = "out"
                    if not firewall_rules_audit(port,dirShort,"allow"):
                        result_status, result_issues = firewall_rules_create(port,direction.lower(),"allow")
                        if not result_status:
                            newStatus = False
                        oldStatus = False
                        msgMain = [f"Default {direction} policy is deny_all and no specific {direction.lower()} allow rule for port {port} exists."]
                        for issue in result_issues:
                            msgMain.append(issue)
                        issues.append(" ".join(msgMain))
        else:
            for issue in result_issues:
                issues.append(issue)

    # TODO: windows has additional options like rule per executable

    return oldStatus, newStatus, issues

#endregion###############
## File Protect Funcs ###
#region##################

def file_restore():
    return True

def file_diff():
    return True

#endregion###############
# Service Protect Funcs #
#region##################

def service_audit(service):
    """
    Wrapper for OS-specific service_audit_* functions

    Given the name of a Windows service, detect if it is nonfunctional and attempt fixes.
    Supports: service not running (script prints the last status message of the service and starts it), service not set to automatic start (script sets it to automatic), service not found (script does not do anything but returns that as the issue)
    
    Returns: Returns: oldStatus(bool), newStatus(bool), issues(list of strings)
    """
    system = platform.system()

    if system == "Windows":
        return service_audit_windows(service)
    else:
        return False, False, [f"service_audit(): not implemented for system {system}."] # TODO

def service_audit_windows(service_name):
    """
    Given the name of a Windows service, detect if it is nonfunctional and attempt fixes.
    Supports: service not running (script prints the last status message of the service and starts it), service not set to automatic start (script sets it to automatic), service not found (script does not do anything but returns that as the issue)

    Returns: Returns: oldStatus(bool), newStatus(bool), issues(list of strings)
    """
    # 1. Check whether service exists and get its current state
    ps_check = fr"""
    $svc = Get-Service -Name '{service_name}' -ErrorAction SilentlyContinue
    if ($svc -eq $null) {{
        Write-Output 'NotFound'
    }} else {{
        $obj = New-Object PSObject -Property @{{
            Status = $svc.Status
            StartType = (Get-CimInstance Win32_Service -Filter "Name='{service_name}'").StartMode
        }}
        $obj | ConvertTo-Json
    }}
    """

    raw = run_powershell(ps_check).strip()
    if not raw:
        return False, False, [f"FAILED to get status information for service {service_name}, PowerShell error."]

    # Case: Service not found
    if raw == "NotFound" or raw == "":
        return False, False, [f"ServiceNotFound for service {service_name}."]

    # Parse the JSON result
    try:
        data = json.loads(raw)
    except:
        return False, False, [f"FAILED to get status information for service {service_name}, PowerShell JSON parse error."]

    current_status  = data.get("Status", "")
    current_start   = data.get("StartType", "")

    oldStatus = True
    if (current_status == "Running") or (current_start not in ("Auto", "Automatic")):
        oldStatus = False

    # Track whether we changed anything
    newStatus = oldStatus
    issues = []

    # ----------------------------------------------------------
    # 2. If service is not running - start it
    # ----------------------------------------------------------
    if current_status != "Running":
        issue_msg = "ServiceStopped"
        ps_start = fr"""
        Start-Service -Name '{service_name}'
        """

        if DISARM:
            issues.append(f"Service {service_name} not running, DISARMED.")
            newStatus = False
        else:
            if run_powershell(ps_start):
                issues.append(f"Service {service_name} not running, RESTORED service to START state (assuming it started successfully... TODO).")
                newStatus = True # Assume successful start. TODO don't assume
            else:
                issues.append(f"Service {service_name} not running, FAILED to start service.")

    # ----------------------------------------------------------
    # 3. If service is not Automatic - set it to Automatic
    # ----------------------------------------------------------
    if current_start not in ("Auto", "Automatic"):
        issue_msg = issue_msg or "WrongStartType"

        ps_auto = fr"""
        Set-Service -Name '{service_name}' -StartupType Automatic
        """

        if DISARM:
            #print(f"[DISARM] Would set {service_name} startup to Automatic")
            issues.append(f"Service {service_name} not set to automatic start, DISARMED.")
        else:
            if run_powershell(ps_auto):
                issues.append(f"Service {service_name} not set to automatic start, RESTORED to automatic start.")
                newStatus = True
            else:
                issues.append(f"Service {service_name} not set to automatic start, FAILED to set to automatic start.")

    return oldStatus, newStatus, issues

def service_uninstall(service,package):
    """
    Wrapper for service_uninstall_*

    Given a service, see if it is installed (service is found/responsible package is installed) and perform appropriate remediation if not.

    Args: service name (string), package name (string)
    Returns: Returns: oldStatus(bool), newStatus(bool), issues(list of strings)
    """

    if (not service) and (not package):
        print_debug(f"service_uninstall({service},{package}): provided with empty args despite failsafes elsewhere?")
        return True, True, [] # no package or service provided. unreachable as should be handled elsewhere but oh well

    system = platform.system()

    if system == "Windows":
        return service_uninstall_windows(service,package)
    else:
        return False, False, [f"service_uninstall(): not implemented for system {system}."] # TODO

def service_uninstall_windows(service,package):
    """
    Given a service, see if it is installed (service is found/responsible package is installed) and perform appropriate remediation if not.

    Args: service name (string)
    Returns: Returns: oldStatus(bool), newStatus(bool), issue(string)
    """

    issues = []
    old_status = False
    new_status = False

    # ---------------------------------------------------------
    # 1. Check if Windows feature (package) is installed
    # ---------------------------------------------------------
    if package:
        feature_cmd = (
            f"Get-WindowsOptionalFeature -Online -FeatureName {package} | ConvertTo-Json"
        )
        feature_raw = run_powershell(feature_cmd)

        if not feature_raw:
            return False, False, [f"FAILED to get install status for required package {package} for service {service} due to PowerShell error."]

        try:
            feature = json.loads(feature_raw)
        except:
            feature = {} # error handling for this is handled below

        feature_state = feature.get("State", "")

        if feature_state == "Enabled":
            old_status = True
        else:
            if DISARM:
                issues.append(f"Missing required package {package} for service {service}, DISARMED.")
            else:
                # Remediate only when disarm == False
                enable_cmd = ( # This will take a while to run! TODO message server?
                    f"Enable-WindowsOptionalFeature -Online -FeatureName {package} -All -NoRestart"
                )
                if run_powershell(enable_cmd):
                    issues.append(f"Missing required package {package} for service {service}, FAILED to reinstall package due to PowerShell error.")

                # re-check state
                feature_raw = run_powershell(feature_cmd)
                try:
                    feature = json.loads(feature_raw)
                except:
                    feature = {}

                feature_state = feature.get("State", "")
                if feature_state == "Enabled":
                    new_status = True
                else:
                    issues.append(f"Missing required package {package} for service {service}, FAILED to reinstall package due to unknown error.")

    # ---------------------------------------------------------
    # 2. Check if Windows service exists
    # ---------------------------------------------------------
    if service:
        svc_cmd = (
            f"Get-Service -Name {service} | ConvertTo-Json"
        )
        svc_raw = run_powershell(svc_cmd)

        if not svc_raw:
            issues.append(f"Missing service {service}, FAILED to restore due to PowerShell get error and remediation not being implemented.")
            old_status = False
            new_status = False
            return old_status, new_status, issues

        try:
            svc = json.loads(svc_raw)
        except:
            svc = None

        if not svc:
            issues.append(f"Missing service {service}, FAILED to restore due to PowerShell get json parse error and remediation not being implemented.")
            new_status = False
            return old_status, new_status, issues

        # If we reached here, the service is present
        new_status = True
        new_status = True

        return old_status, new_status, issues

    print_debug(f"service_uninstall_windows({service},{package}): reached end of func which is unexpected, possible logic error")
    return True, True, [] # no package or service provided. unreachable as should be handled elsewhere but oh well

def service_integrity(service,backupDict):
    """
    Wrapper for OS-specific service_integrity_* functions

    Given the name of a Windows service, check its attributes against a dict of known good attributes and restore if needed
    
    Returns: Returns: oldStatus(bool), newStatus(bool), issues(list of string)
    """
    return False, False, [f"service_integrity(): not implemented."] # TODO

    system = platform.system()

    if system == "Windows":
        return service_integrity_windows(service,backupDict)
    else:
        return False, False, [f"service_integrity(): not implemented for system {system}."] # TODO
    
def service_integrity_windows(service,backupDict):
    """
    Given the name of a Windows service, check its attributes against a dict of known good attributes and restore if needed
    
    Returns: Returns: oldStatus(bool), newStatus(bool), issues(list of strings)
    """
    return False, False, []
    
def service_main(services,packages):
    """
    Performs detection and remediation of common service problems
    
    Args: services (list of service names)
    Returns: Returns: oldStatus(bool), newStatus(bool), issue(string)
    """

    if len(services) != len(packages):
        return False, False, [f"service_main({services},{packages}): services and packages lists are not the same size."]

    oldStatus = True
    newStatus = True
    issues = []

    for service,package in zip(services,packages):

        # dunno why this would happen as this is handled above
        if (not service) and (not package):
            continue

        # Check if service is found, attempt reinstall, and early out if failed
        result_oldStatus, result_newStatus, result_issues = service_uninstall(service,package)
        if not result_oldStatus:
            oldStatus = False
        if not result_newStatus:
            newStatus = False
        for issue in result_issues:
            issues.append(issue)

        # Check for service integrity
        """ # TODO
        result_oldStatus, result_newStatus, result_issues = service_integrity(service)
        if not result_oldStatus:
            oldStatus = False
        if not result_newStatus:
            newStatus = False
        for issue in result_issues:
            issues.append(issue)
        """

        # Check if service is running/enabled
        result_oldStatus, result_newStatus, result_issues = service_audit(service)
        if not result_oldStatus:
            oldStatus = False
        if not result_newStatus:
            newStatus = False
        for issue in result_issues:
            issues.append(issue)

        # Check service last run status
        # TODO

    return oldStatus, newStatus, issues

#endregion###############
### Interaction Funcs ###
#region##################

def pause_countdown(seconds=60):
    """
    Handles countdown of pause.
    Returns: Success(bool)
    """
    return resume(True)

def pause(seconds=60):
    """
    Pauses protection for the specified time period.
    Sends message to server.
    Returns: Success(bool)
    """
    send_message(True,True,f"pausing for seconds {seconds}")
    return True

def resume(scheduled=False):
    """
    Resumes protection.
    Clears current pause countdown (if any).
    Sends message to server.
    Returns: Success(bool)
    """
    send_message(True,True,f"resuming - scheduled: {scheduled}")
    return True

def reregister():
    """
    Performs a re-init of protected files for legitimate changes
    Returns Success(bool)
    """
    send_message(True,True,"reregister")
    return True

#endregion###############
######### Main ##########
#region##################

def init_int_vars(interface=interface_get_primary()):
    """
    Reads the current IPv4 address, prefix, and gateway for the interface.
    """

    # Query current config
    query_cmd = fr"""
        Get-NetIPConfiguration -InterfaceAlias '{interface}' | 
        Select-Object IPv4Address, IPv4DefaultGateway | ConvertTo-Json
    """

    output = run_powershell(query_cmd)
    if not output:
        print_debug(f"init_int_vars({interface}): Failed to query interface '{interface}'.")
        return "", "", ""    
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        print_debug(f"init_int_vars({interface}): Error parsing PowerShell output.")
        return "", "", ""

    # Extract current IP/prefix
    if data.get("IPv4Address"):
        addressData = data["IPv4Address"][0]
        props = addressData.get("CimInstanceProperties", "")
        match = re.search(r'IPv4Address\s*=\s*"([^"]+)"', props)
        if match:
            ip_address = match.group(1)
        match = re.search(r'PrefixLength\s*=\s*([0-9]+)', props)
        if match:
            prefix = int(match.group(1))
    else:
        ip_address = None
        prefix = None

    # Extract gateway
    query_cmd = fr"""
        Get-NetIPConfiguration -InterfaceAlias "{interface}" |
        Select-Object -ExpandProperty IPv4DefaultGateway | ConvertTo-Json
    """

    output = run_powershell(query_cmd)
    if not output:
        print_debug(f"init_int_vars({interface}): Failed to query interface '{interface}' for gateway info.")
        return "", "", ""
    
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        print_debug(f"init_int_vars({interface}): Error parsing PowerShell output for gateway info.")
        return "", "", ""
    
    if data.get("NextHop"):
        gateway = data["NextHop"]
    else:
        gateway = None

    print_debug(f"init_int_vars({interface}): {ip_address} {prefix} {gateway}")
    return ip_address, prefix, gateway

def test_network():
    # vars
    interface = interface_get_primary() # This needs valid network conf to work
    ip_address,prefix,gateway = init_int_vars()

    # main
    print(f"interface_get_primary(): {interface}")
    #print(f"interface_mtu(): {interface_mtu()}")
    #print(f"interface_ttl(): {interface_ttl()}")
    print(f"interface_main({interface,ip_address,prefix,gateway}): {interface_main(interface,ip_address,prefix,gateway)}")
    #print(f"firewall_rules_audit_windows('81'): {firewall_rules_audit_windows("81")}")
    print(f"firewall_main(['81','82']): {firewall_main(["81","82"])}")

def test_service():
    service = "AxInstSV"
    print(f"service_audit({service}): {service_audit(service)}")

def test_main():
    print(f"get_system_details(): {get_system_details()}")
    #test_network()
    test_service()

def main():
    paused = False
    sleeptime = 60
    ports = [81]
    services = ["AxInstSV"]
    packages = [""]
    ip_address,prefix,gateway = init_int_vars()

    #test_main()
    #return

    oldStatus = True
    newStatus = True
    oldIssues = []
    newIssues = []

    print_debug(f"main(): System details - {get_system_details()}")

    while not paused:

        sent_msg = False
        suppressed_send = False

        # Firewall
        print_debug(f"main(): running firewall checks")
        result_oldStatus, result_newStatus, result_issues = firewall_main(ports)
        if not result_oldStatus:
            oldStatus = False
        if not result_newStatus:
            newStatus = False
        for issue in result_issues:
            newIssues.append(f"Firewall Issue - {issue}")

            print_debug(newIssues[-1])
            if newIssues[-1] not in oldIssues:
                send_message(result_oldStatus,result_newStatus,newIssues[-1])
                sent_msg = True
            else:
                suppressed_send = True

        # Interface
        print_debug(f"main(): running interface checks")
        result_oldStatus, result_newStatus, result_issues = interface_main(interface_get_primary(),ip_address,prefix,gateway)
        if not result_oldStatus:
            oldStatus = False
        if not result_newStatus:
            newStatus = False
        for issue in result_issues:
            newIssues.append(f"Interface Issue - {issue}")

            print_debug(newIssues[-1])
            if newIssues[-1] not in oldIssues:
                send_message(result_oldStatus,result_newStatus,newIssues[-1])
                sent_msg = True
            else:
                suppressed_send = True

        # Service
        print_debug(f"main(): running service checks")
        result_oldStatus, result_newStatus, result_issues = service_main(services,packages)
        if not result_oldStatus:
            oldStatus = False
        if not result_newStatus:
            newStatus = False
        for issue in result_issues:
            newIssues.append(f"Service Issue - {issue}")

            print_debug(newIssues[-1])
            if newIssues[-1] not in oldIssues:
                send_message(result_oldStatus,result_newStatus,newIssues[-1])
                sent_msg = True
            else:
                suppressed_send = True

        if not sent_msg:
            if suppressed_send:
                send_message(True,True,"no new issues; at least one prior issue still exists but suppressing redundant alert")
            else:
                send_message(True,True,"all good")

        # Finish up
        print_debug(f"main(): oldStatus - {oldStatus}")
        print_debug(f"main(): newStatus - {newStatus}")
        #for issue in issues:
            #print_debug(f"main(): issue - {issue}")
            #send_message(oldStatus,newStatus,issue)
        
        print_debug(f"main(): sleeping for {sleeptime} seconds")
        print_debug(f"")

        oldIssues = newIssues
        newIssues = []
        
        time.sleep(sleeptime)

if __name__ == "__main__":
    main()

#endregion###############