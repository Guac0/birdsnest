#########################
######## Imports ########
#region##################

#endregion###############
# Configuration Options #
#region##################

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
    return True

def get_perms():
    """
    Gets the execution perm level (user and elevation level).
    Returns: isRunAsElevated(bool), runAsUser(String)
    """
    return True, ""

def get_primary_ip():
    """
    Attempts to get the primary IP address of the local machine.
    Returns: ip(String)
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Connect to an external host (e.g., Google's public DNS)
        # This doesn't send any data, just establishes a connection
        # to find out which local interface would be used.
        s.connect(("8.8.8.8", 80))
        ip_address = s.getsockname()[0]
    except Exception:
        ip_address = "Unable to determine IP"
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
        "hostname": socket.hostname(),
        "ipadd": get_primary_ip
    }
    return sysInfo

def create_backup_primary(path,backupDir=BACKUPDIR):
    """
    Creates a new primary backup by compressing the value of the path variable into a zip folder and placing it at backupDir.
    If there is already a file at backupDir, move it to backupDir-TIMESTAMP and return that path.
    All backup files should be timestomped to a random value plus or minus 24 hours to the value of /bin/sh or C:\Windows\system32\cmd.exe
    Returns: Success(bool), oldDir(String)
    """
    return True, ""

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
    Determines the primary network interface.
    Returns: interface(String)
    """
    return ""

def check_interface(interface=get_primary_interface()):
    """
    Given an interface, detect and remediate (if possible) common issues and returns the remediated issue
    Supports: interface down, bad mtu, no IP address, no route, no default gateway, no connection to 8.8.8.8
    Args: interface(String), defaults to get_primary_interface()
    Returns: interfacePriorStatus(bool), interfaceNewStatus(book), issue(String)
    """
    return True, True, ""

def check_firewall(protectedPort):
    """
    Detect and remediate common firewall issues and returns the remediated issue
    Supports: block scored port (including port range), block all without allowing port (including port range)
    Args: interface(String), defaults to get_primary_interface()
    Returns: firewallOldStatus(bool), firewallNewStatus(book), issue(String)
    """
    return True, True, ""

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
    beacon_loop(interval)

#endregion###############