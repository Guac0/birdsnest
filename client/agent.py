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

#endregion###############
# Configuration Options #
#region##################

DISARM = True
DEBUG_PRINT = True
BACKUPDIR = ""
LOGFILE = "" #"agent_log.txt"
MTU_MIN = 1200
MTU_DEFAULT = 1300
MTU_MAX = 1514

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

def get_os():
    """
    Gets the approximately OS used, simplified to highest level possible
    For example: Ubuntu, Debian, Rocky, RHEL, Windows Workstation (7 8 10 11), Windows Server (2012 2016 2022 2025)
    Returns: osType(String)
    """
    system = platform.system()

    if system == "Linux":
        return ' '.join(platform.dist()) # Ubuntu 10.04 lucid, debian 4.0 , fedora 17 Beefy Miracle, redhat 5.6 Tikanga, redhat 5.9 Final (<- centos)

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
        # euid 0 → root OR sudo
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

def run_powershell(cmd):
    """
    Run a PowerShell command and return stdout text.

    Returns: output if success, "" if failure
    """
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", cmd],
        capture_output=True, text=True
    )
    if result.returncode != 0:
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

def send_message(message):
    """
    Sends the specified data to the server
    Handles the full process and attaching agent name/auth
    Args: message(any)
    Returns: status(Bool)
    """
    return True

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

def interface_mtu(interface=interface_get_primary(),mtu_minimum=MTU_MIN,mtu_maximum=MTU_MAX,mtu_default=MTU_DEFAULT):
    """
    Wrapper for interface_mtu_*

    Given an interface name, check if its MTU is within an acceptable range and remediate if not
    
    Args: interface name(string), mtu_min(int), mtu_max(int), mtu_default(int)
    Returns: oldStatus(bool), newStatus(bool), issue(string)
    """
    system = platform.system()

    if system == "Windows":
        return interface_mtu_windows(interface,mtu_minimum,mtu_maximum,mtu_default)
    else:
        return False # TODO

def interface_mtu_windows(interface=interface_get_primary(),mtu_minimum=MTU_MIN,mtu_maximum=MTU_MAX,mtu_default=MTU_DEFAULT):
    """
    Given an interface name, check if its MTU is within an acceptable range and remediate if not
    
    Args: interface name(string), mtu_min(int), mtu_max(int), mtu_default(int)
    Returns: oldStatus(bool), newStatus(bool), issue(string)
    """

    ps_get_mtu = fr"""
    Get-NetIPInterface -InterfaceAlias "{interface}" -AddressFamily IPv4 |
        Select-Object -ExpandProperty NlMtu
    """

    output = run_powershell(ps_get_mtu).strip()

    if not output.isdigit():
        print_debug(f"interface_mtu_windows(): Failed to query MTU for interface '{interface}'. Output: {output}")
        return False, False, f"interface_mtu_windows(): Failed to query MTU for interface '{interface}'. Output: {output}"

    old_mtu = int(output)

    # Check MTU range
    if old_mtu < mtu_minimum or old_mtu > mtu_maximum:
        new_mtu = mtu_default

        ps_set_mtu = fr'''
        Set-NetIPInterface -InterfaceAlias "{interface}" -NlMtu {new_mtu}
        '''

        if DISARM:
            print_debug(f"DISARMED, but told to updated MTU for '{interface}' from {old_mtu} to {new_mtu}")
            return False, False, f"Interface {interface}'s MTU was set to {old_mtu}, attempted remediation but DISARMED"
        else:
            print_debug(f"Updated MTU for '{interface}' from {old_mtu} to {new_mtu}")
            if run_powershell(ps_set_mtu):
                return False, True, f"Interface {interface}'s MTU was set to {old_mtu}"
            else:
                return False, False, f"Interface {interface}'s MTU was set to {old_mtu}"

    return True, True, ""

def interface_ttl(interface=interface_get_primary()):
    """
    Wrapper for interface_ttl_*

    Given an interface name, check if its TTL is within an acceptable range and remediate if not
    
    Args: interface name(string)
    Returns: oldStatus(bool), newStatus(bool), issue(string)
    """
    system = platform.system()

    if system == "Windows":
        return interface_mtu_windows(interface)
    else:
        return False # TODO

def interface_ttl_windows():
    """
    Given an interface name, check if its TTL is within an acceptable range and remediate if not
    
    Args: interface name(string)
    Returns: oldStatus(bool), newStatus(bool), issue(string)
    """

    check_script = r"""
    $path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'

    if (Test-Path -Path '$path\DefaultTTL' -ErrorAction SilentlyContinue) {
        Write-Output 'True'
    }
    elseif (Test-Path -Path '$path\DefaultCurHopLimit' -ErrorAction SilentlyContinue) {
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
        $path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'

        if (Test-Path '$path\DefaultTTL') {
            Remove-ItemProperty -Path $path -Name 'DefaultTTL'
        }
        if (Test-Path '$path\DefaultCurHopLimit') {
            Remove-ItemProperty -Path $path -Name 'DefaultCurHopLimit'
        }

        Write-Output 'Deleted'
        """
        if DISARM:
            print_debug(f"interface_ttl_windows(): DISARMED, but bad TTL detected and told to delete!")
            return False, False, "Bad TTL set, attempted remediation but DISARMED"
        else:
            ps_result = run_powershell(delete_script).strip()
            if ps_result:
                return False, True, f"Bad TTL set"
            return False, False, f"Bad TTL set"

    # Reg key does not exist so system is (presumably) using the default of 128 (good)
    return True, True, ""

def interface_down(interface=interface_get_primary()):
    """
    Wrapper for interface_down_*

    Given an interface name, check if it is in the down state and remediate if yes
    
    Args: interface name(string)
    Returns: oldStatus(bool), newStatus(bool), issue(string)
    """
    system = platform.system()

    if system == "Windows":
        return interface_down_windows(interface)
    else:
        return False # TODO

def interface_down_windows(interface=interface_get_primary()):
    """
    Given an interface name, check if it is in the down state and remediate if yes
    
    Args: interface name(string)
    Returns: oldStatus(bool), newStatus(bool), issue(string)
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

    if status == "NotFound":
        print_debug(f"interface_down_windows({interface}): Interface not found.")
        return True, True, "" # TODO consistent errors

    if status == "Down":
        ps_enable = fr"""
        Enable-NetAdapter -Name '{interface}' -Confirm:$false
        """ # Write-Output 'Enabled'
        if DISARM:
            print_debug(f"interface_down_windows({interface}): DISARMED, but told to enable interface")
            return False, False, f"Interface {interface} was set to DOWN, attempted remediation but DISARMED"
        else:
            if run_powershell(ps_enable).strip():
                return False, True, f"Interface {interface} was set to DOWN"
            return False, False, f"Interface {interface} was set to DOWN"
    
    return True, True, ""

def interface_uninstall():
    # Not fully implemented
    """
    Wrapper for interface_uninstall_*

    Detects and remediates core networking breaks
    
    Returns: oldStatus(bool), newStatus(bool), issue(string)
    """
    return False

    system = platform.system()

    if system == "Windows":
        return interface_uninstall_windows()
    else:
        return False # TODO

def interface_uninstall_windows(
    interface_name,
    ipv4_address,
    prefix_length,
    gateway,
    dns_servers
):
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

def interface_main(interface=interface_get_primary()):
    """
    Given an interface, detect and remediate (if possible) common issues and returns the remediated issue
    Supports: interface down, bad mtu, no IP address, no route, no default gateway, no connection to 8.8.8.8
    
    Args: interface(String), defaults to interface_get_primary()
    Returns: interfacePriorStatus(bool), interfaceNewStatus(book), issue(String)
    """
    oldStatus = True
    newStatus = True
    issues = []

    # Interface Down
    result_oldStatus, result_newStatus, issue = interface_down()
    if not result_oldStatus:
        oldStatus = False
    if not result_newStatus:
        newStatus = False
    if issue:
        issues.append(issue)

    # MTU
    result_oldStatus, result_newStatus, issue = interface_mtu(interface)
    if not result_oldStatus:
        oldStatus = False
    if not result_newStatus:
        newStatus = False
    if issue:
        issues.append(issue)
    
    # TTL
    result_oldStatus, result_newStatus, issue = interface_ttl()
    if not result_oldStatus:
        oldStatus = False
    if not result_newStatus:
        newStatus = False
    if issue:
        issues.append(issue)

    return oldStatus, newStatus, issues

def firewall_rules_audit(port,direction="in",action="block"):
    """
    Wrapper for OS-specific firewall_rules_audit_* functions

    Get firewall rules that block traffic on a specific LocalPort and return their names
    Supports ports where firewall rule affects that specific port, range of ports including that port, or firewall rule using comma separated list
    Does NOT support "any port" firewall rules
    
    Args: port (string), direction (string, in or out), action (string, block or accept)
    Returns: dictionary of matching rules, with fields Name, DisplayName, Action, Direction, Profile
    """
    system = platform.system()

    if system == "Windows":
        return firewall_rules_audit_windows(port,direction,action)
    else:
        return False # TODO

def firewall_rules_audit_windows(port,direction="in",action="block"):
    """
    Uses Powershell to get Windows Firewall rules that block traffic on a specific LocalPort and return their names
    Supports ports where firewall rule affects that specific port, range of ports including that port, or firewall rule using comma separated list
    Does NOT support "any port" firewall rules
    
    Args: port (string), direction (string, in or out), action (string, block or accept)
    Returns: dictionary of matching rules, with fields Name, DisplayName, Action, Direction, Profile
    """

    # Currently unused as returns too many matches
    #if ($lp -eq 'Any') {{ return $true }}

    ps_query = fr"""
    Get-NetFirewallPortFilter |
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
        Select-Object Name, DisplayName, Action, Direction, Profile |
        ConvertTo-Json
    """

    output = run_powershell(ps_query).strip()

    if not output:
        print_debug(f"firewall_rules_audit_windows({port},{direction},{action}): No matching firewall rules found")
        return dict()

    # Convert JSON into Python objects
    try:
        rules = json.loads(output)
    except json.JSONDecodeError:
        print_debug("Could not decode PowerShell JSON output.")
        print_debug("Output was:", output)
        return

    # Handle the case where PowerShell returns a single object instead of a list
    if isinstance(rules, dict):
        rules = [rules]

    return rules

def firewall_rules_delete(rules):
    """
    Wrapper for OS-specific firewall_rules_delete_* functions

    Given a firewall rules dict, deletes each rule
    
    Args: firewall rules dict (Name, DisplayName, Action, Direction, Profile)
    returns: True if shell reports no failures when deleting rules, False if shell reports at least one failure
    """
    system = platform.system()

    if system == "Windows":
        return firewall_rules_delete_windows(rules)
    else:
        return False # TODO

def firewall_rules_delete_windows(rules):
    """
    Given a firewall rules dict, deletes each rule
    
    Args: firewall rules dict (Name, DisplayName, Action, Direction, Profile)
    returns: True if Powershell reports no failures when deleting rules, False if Powershell reports at least one failure
    """
    # Delete the rules by Name
    print_debug("firewall_rules_delete_windows(): Deleting rules...")
    status = True
    for rule in rules:
        if (not DISARM):
            delete_cmd = f"Remove-NetFirewallRule -Name '{rule['Name']}'"
            output = run_powershell(delete_cmd)
            if output:
                print_debug(f"firewall_rules_delete_windows(): Removed rule: {rule['Name']} ({rule['DisplayName']})")
            else:
                print_debug(f"firewall_rules_delete_windows(): FAILED to remove rule: {rule['Name']} ({rule['DisplayName']})")
                status = False
        else:
            status = False
            print_debug(f"firewall_rules_delete_windows(): DISARMED, but told to remove rule: {rule['Name']} ({rule['DisplayName']})")

    print_debug("firewall_rules_delete_windows(): All provided rules deleted.")
    return status

def firewall_rules_create(port,direction,action):
    """
    Wrapper for OS-specific firewall_rules_create_* functions

    Creates the specified firewall rule on Windows

    Args: Port, Direction (inbound/outbound), Action (allow/block)
    Returns: True if success, False if fail
    """
    system = platform.system()

    if system == "Windows":
        return firewall_rules_create_windows(port,direction,action)
    else:
        return False # TODO

def firewall_rules_create_windows(port,direction,action):
    """
    Creates the specified firewall rule on Windows

    Args: Port, Direction (inbound/outbound), Action (allow/block)
    Returns: True if success, False if fail
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
        print_debug(f"firewall_rules_create_windows(): DISARMED, but told to create Stabvest_Rule_{port}_{direction}_{action}")
        return False
    if run_powershell(ps_cmd):
        return True
    else:
        return False

def firewall_policy_audit():
    """
    Wrapper for OS-specific firewall_policy_audit_* functions

    Check if any Firewall profile is set to block all inbound connections.

    Returns: True if no policies are set to default deny, False if at least one policy is set to default deny
    """
    system = platform.system()

    if system == "Windows":
        return firewall_policy_audit_windows()
    else:
        return False # TODO

def firewall_policy_audit_windows():
    """
    Check if any Windows Firewall profile is set to block all inbound connections.

    Returns: True if no policies are set to default deny, False if at least one policy is set to default deny
    """
    ps_cmd = """
    Get-NetFirewallProfile |
        Select-Object Name, DefaultInboundAction |
        ConvertTo-Json
    """
    output = run_powershell(ps_cmd)

    if not output:
        print_debug("No firewall profile data returned.")
        return False

    profiles = json.loads(output)

    # Normalize single-object case
    if isinstance(profiles, dict):
        profiles = [profiles]

    for p in profiles:
        if (p["DefaultInboundAction"] == "Block"):
            return False
        
    return True

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
        matched_rules = firewall_rules_audit(port,"in","block")
        if matched_rules:
            oldStatus = False
            for rule in matched_rules:
                issues.append(rule)
            remediateStatus = firewall_rules_delete(matched_rules)
            if not remediateStatus:
                newStatus = False
        
        matched_rules = firewall_rules_audit(port,"out","block")
        if matched_rules:
            oldStatus = False
            for rule in matched_rules:
                issues.append(rule)
            remediateStatus = firewall_rules_delete(matched_rules)
            if not remediateStatus:
                newStatus = False

    # Policy
    if (not firewall_policy_audit()):
        for port in protectedPorts:
            if not firewall_rules_audit(port,"in","allow"):
                if not firewall_rules_create(port,"inbound","allow"):
                    newStatus = False
                oldStatus = False
                issues.append(f"Default policy is deny_all and no specific inbound allow rule for port {port} exists")
            if not firewall_rules_audit(port,"out","allow"):
                if not firewall_rules_create(port,"outbound","allow"):
                    newStatus = False
                oldStatus = False
                issues.append(f"Default policy is deny_all and no specific outbound allow rule for port {port} exists")

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

def service_get_status():
    return True

def service_restart():
    return True

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
    send_message(f"pausing for seconds {seconds}")
    return True

def resume(scheduled=False):
    """
    Resumes protection.
    Clears current pause countdown (if any).
    Sends message to server.
    Returns: Success(bool)
    """
    send_message("resuming")
    return True

def reregister():
    """
    Performs a re-init of protected files for legitimate changes
    Returns Success(bool)
    """
    send_message("reregister")
    return True

#endregion###############
######### Main ##########
#region##################

if __name__ == "__main__":
    # TODO
    print(f"interface_get_primary(): {interface_get_primary()}")
    print(f"get_system_details(): {get_system_details()}")
    #print(f"interface_mtu(): {interface_mtu()}")
    #print(f"interface_ttl(): {interface_ttl()}")
    print(f"interface_main(): {interface_main()}")
    #print(f"firewall_rules_audit_windows('81'): {firewall_rules_audit_windows("81")}")
    print(f"firewall_main(['81','82']): {firewall_main(["81","82"])}")

#endregion###############