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
LOGFILE = "agent_log.txt"

#endregion###############
# Generic Helper Funcs ##
#region##################

def print_debug(msg):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if (DEBUG_PRINT):
        print(msg)
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

def get_primary_interface():
    """
    Determines the primary network interface based on finding the interface with the primary IP.
    Returns: interface(String)
    """
    system = platform.system()

    if system == "Windows":
        return get_primary_interface_windows(get_primary_ip())
    else:
        return get_primary_interface_unix(get_primary_ip())

def get_primary_interface_windows(ip):
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

def get_primary_interface_unix(ip):
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

def check_interface(interface=get_primary_interface()):
    """
    Given an interface, detect and remediate (if possible) common issues and returns the remediated issue
    Supports: interface down, bad mtu, no IP address, no route, no default gateway, no connection to 8.8.8.8
    Args: interface(String), defaults to get_primary_interface()
    Returns: interfacePriorStatus(bool), interfaceNewStatus(book), issue(String)
    """
    return True, True, ""

def firewall_audit_rules_windows(port,direction="in",action="block"):
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
        print_debug(f"firewall_audit_rules_windows({port},{direction},{action}): No matching firewall rules found")
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

def firewall_audit_rules(port,direction="in",action="block"):
    """
    Wrapper for OS-specific firewall_audit_rules_* functions

    Get firewall rules that block traffic on a specific LocalPort and return their names
    Supports ports where firewall rule affects that specific port, range of ports including that port, or firewall rule using comma separated list
    Does NOT support "any port" firewall rules
    
    Args: port (string), direction (string, in or out), action (string, block or accept)
    Returns: dictionary of matching rules, with fields Name, DisplayName, Action, Direction, Profile
    """
    system = platform.system()

    if system == "Windows":
        return firewall_audit_rules_windows(port,direction,action)
    else:
        return False # TODO

def firewall_delete_rules_windows(rules):
    """
    Given a firewall rules dict, deletes each rule
    
    Args: firewall rules dict (Name, DisplayName, Action, Direction, Profile)
    returns: True if Powershell reports no failures when deleting rules, False if Powershell reports at least one failure
    """
    # Delete the rules by Name
    print_debug("firewall_delete_rules_windows(): Deleting rules...")
    status = True
    for rule in rules:
        if (not DISARM):
            delete_cmd = f"Remove-NetFirewallRule -Name '{rule['Name']}'"
            output = run_powershell(delete_cmd)
            if output:
                print_debug(f"firewall_delete_rules_windows(): Removed rule: {rule['Name']} ({rule['DisplayName']})")
            else:
                print_debug(f"firewall_delete_rules_windows(): FAILED to remove rule: {rule['Name']} ({rule['DisplayName']})")
                status = False
        else:
            print_debug(f"firewall_delete_rules_windows(): DISARMED, but told to remove rule: {rule['Name']} ({rule['DisplayName']})")

    print_debug("firewall_delete_rules_windows(): All provided rules deleted.")
    return status

def firewall_delete_rules(rules):
    """
    Wrapper for OS-specific firewall_delete_rules_* functions

    Given a firewall rules dict, deletes each rule
    
    Args: firewall rules dict (Name, DisplayName, Action, Direction, Profile)
    returns: True if shell reports no failures when deleting rules, False if shell reports at least one failure
    """
    system = platform.system()

    if system == "Windows":
        return firewall_delete_rules_windows(rules)
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
        return True
    if run_powershell(ps_cmd):
        return True
    else:
        return False

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

def check_firewall(protectedPorts):
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
        matched_rules = firewall_audit_rules(port,"in","block")
        if matched_rules:
            oldStatus = False
            for rule in matched_rules:
                issues.append(rule)
            remediateStatus = firewall_delete_rules(matched_rules)
            if not remediateStatus:
                newStatus = False
        
        matched_rules = firewall_audit_rules(port,"out","block")
        if matched_rules:
            oldStatus = False
            for rule in matched_rules:
                issues.append(rule)
            remediateStatus = firewall_delete_rules(matched_rules)
            if not remediateStatus:
                newStatus = False

    # Policy
    if (not firewall_policy_audit()):
        for port in protectedPorts:
            if not firewall_audit_rules(port,"in","allow"):
                if not firewall_rules_create(port,"inbound","allow"):
                    newStatus = False
                oldStatus = False
                issues.append(f"Default policy is deny_all and no specific inbound allow rule for port {port} exists")
            if not firewall_audit_rules(port,"out","allow"):
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
    print(f"get_primary_interface(): {get_primary_interface()}")
    print(f"get_system_details(): {get_system_details()}")
    #print(f"firewall_audit_rules_windows('81'): {firewall_audit_rules_windows("81")}")
    print(f"check_firewall(['81','82']): {check_firewall(["81","82"])}")

#endregion###############