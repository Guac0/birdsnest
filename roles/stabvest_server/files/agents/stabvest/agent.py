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
import ssl
import shutil
import base64
from pathlib import Path
import ast
#import winreg
#import win32serviceutil
#import win32service
#import win32event
#import sys
#import servicemanager
#import threading

#endregion###############
# Configuration Options #
#region##################

CONFIG_DEFAULTS = {
    "AGENT_NAME": "test1",
    "AUTH_TOKEN": "testtoken",
    "SERVER_URL": "https://127.0.0.1:8080/",
    "SERVER_TIMEOUT": 5,
    "SLEEPTIME": 60,
    "DISARM": True,
    "IPTABLES_PATH": "iptables",
    "PORTS": [81],
    "SERVICES": ["AxInstSV"],
    "PACKAGES": [""],
    "SERVICE_BACKUPS": {
        "PathName": "C:\\\\Windows\\\\system32\\\\svchost.exe -k AxInstSVGroup",
        "StartName": "LocalSystem",
        "Dependencies": [],
        "DisplayName": "ActiveX Installer (AxInstSV)",
        "StartType": "Manual"
    },
    "PROTECTED_FOLDERS": ["var/www"],
    "DEBUG_PRINT": True,
    "BACKUPDIR": "",
    "LOGFILE": "log.txt",
    "STATUSFILE": "status.txt",
    "MTU_MIN": 1200,
    "MTU_DEFAULT": 1300,
    "MTU_MAX": 1514,
    "LINUX_DEFAULT_TTL": 64,
    "AGENT_TYPE": "stabvest"
    #"SERVICE_BACKUPS": {
    #    "PathName": "C:\Windows\System32\svchost.exe -k LocalService",
    #    "StartName": "LocalSystem",
    #    "Dependencies": ["RpcSs"],
    #    "DisplayName": "Windows Time",
    #    "StartType": "auto"
    #}
}

def load_config(path):
    config = CONFIG_DEFAULTS.copy()
    badPath = False

    if os.path.exists(path):
        with open(path, "r") as f:
            config.update(json.load(f))
    else:
        badPath = True

    # Generate timestamp once
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    # Replace placeholders in strings
    for key, value in config.items():
        if isinstance(value, str):
            config[key] = value.format(
                HOST=config.get("HOST"),
                PORT=config.get("PORT"),
                timestamp=timestamp
            )

    if badPath:
        print(f"[-] {timestamp} load_config(): config file path not found: {path}")
        with open(config.get("LOGFILE"), "a") as f: # intentionally not the correct logfile format
            f.write(f"[{timestamp}] CRITICAL - load_config(): config file path not found: {path}")

    #config["PUBLIC_URL"] = f"http://{config['HOST']}:{config['PORT']}"
    #config["LOGFILE"] = f"log_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt"
    #config["SAVEFILE"] = f"save_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.json"

    return config

def get_iptables_save_path():
    # 1. Check for Alpine (uses /etc/conf.d/iptables or rules-save)
    if os.path.exists("/etc/alpine-release"):
        return "/etc/iptables/rules-save"
    
    # 2. Check for RHEL-based (Rocky, CentOS, Alma)
    if os.path.exists("/etc/redhat-release"):
        return "/etc/sysconfig/iptables"
    
    # 3. Check for Debian/Ubuntu (Standard location for iptables-persistent)
    # Note: Requires 'iptables-persistent' package to be installed
    try:
        dist_info = platform.freedesktop_os_release()
        id_like = dist_info.get("ID_LIKE", "").lower()
        dist_id = dist_info.get("ID", "").lower()
        
        if "debian" in id_like or "ubuntu" in dist_id:
            return "/etc/iptables/rules.v4"
    except (AttributeError, OSError):
        # Fallback for older Python versions or minimal environments
        if os.path.exists("/etc/debian_version"):
            return "/etc/iptables/rules.v4"

    # Default fallback (manual export)
    return "/etc/iptables.rules"

CONFIG = load_config("config.json") # relative to cwd!
DISARM = CONFIG["DISARM"]
IPTABLES_PATH = CONFIG["IPTABLES_PATH"]
DEBUG_PRINT = CONFIG["DEBUG_PRINT"]
BACKUPDIR = CONFIG["BACKUPDIR"]
LOGFILE = CONFIG["LOGFILE"]
STATUSFILE = CONFIG["STATUSFILE"]
MTU_MIN = CONFIG["MTU_MIN"]
MTU_DEFAULT = CONFIG["MTU_DEFAULT"]
MTU_MAX = CONFIG["MTU_MAX"]
LINUX_DEFAULT_TTL = CONFIG["LINUX_DEFAULT_TTL"]
AGENT_NAME = CONFIG["AGENT_NAME"]
DISARM = CONFIG["DISARM"]
AUTH_TOKEN = CONFIG["AUTH_TOKEN"]
AGENT_TYPE = CONFIG["AGENT_TYPE"]
SERVER_URL = CONFIG["SERVER_URL"]
SERVER_TIMEOUT = CONFIG["SERVER_TIMEOUT"]
SLEEPTIME = CONFIG["SLEEPTIME"]
PORTS = CONFIG["PORTS"]
SERVICES = CONFIG["SERVICES"]
PACKAGES = CONFIG["PACKAGES"]
SERVICE_BACKUPS = CONFIG["SERVICE_BACKUPS"]
PROTECTED_FOLDERS = CONFIG["PROTECTED_FOLDERS"]
if isinstance(PROTECTED_FOLDERS, str):
    PROTECTED_FOLDERS = ast.literal_eval(PROTECTED_FOLDERS)
IPTABLES_SAVE_PATH = get_iptables_save_path()
PAUSED = False

#REGISTRY_HIVE = winreg.HKEY_LOCAL_MACHINE
#SERVICE_PATH = r"SYSTEM\\CurrentControlSet\\Services\\service_name" #replace with actual service name

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

def get_platform_dist():
    sys_platform = platform.system()

    # --- Windows Handling ---
    if sys_platform == "Windows":
        # platform.win32_ver() returns (release, version, csd, ptype)
        release, version, csd, ptype = platform.win32_ver()
        return ("Windows", release, version)

    # --- Linux Handling ---
    if sys_platform == "Linux":
        # 1. Try Python 3.10+ native method (Standardized os-release)
        if hasattr(platform, 'freedesktop_os_release'):
            try:
                info = platform.freedesktop_os_release()
                return (info.get('ID', 'linux'), info.get('VERSION_ID', ''), info.get('NAME', ''))
            except OSError:
                pass

        # 2. Manual parsing for older Python versions (< 3.10)
        if os.path.isfile("/etc/os-release"):
            info = {}
            with open("/etc/os-release") as f:
                for line in f:
                    # Parse KEY=VALUE, ignoring comments and empty lines
                    match = re.match(r'^([A-Z_]+)="?([^"\n]+)"?$', line)
                    if match:
                        info[match.group(1)] = match.group(2)
            
            return (
                info.get('ID', 'linux'), 
                info.get('VERSION_ID', info.get('VERSION', '')), 
                info.get('PRETTY_NAME', '')
            )

    # Fallback for MacOS or unknown systems
    return (sys_platform, platform.release(), platform.version())

"""
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
"""

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
            return get_platform_dist()[1] # Ubuntu, debian, redhat
        return ' '.join(get_platform_dist()) # Ubuntu 10.04 lucid, debian 4.0 , fedora 17 Beefy Miracle, redhat 5.6 Tikanga, redhat 5.9 Final (<- centos)

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

def hash_id(*args):
    # hash any number of args so that we have a single value to use as the id that remains unique if multiple items have similar fields
    # Does not need to be secure
    combined = "|".join(map(str, args))
    encoded = base64.b64encode(combined.encode("utf-8")).decode("utf-8")
    return encoded
    #return hashlib.sha256(f"{ip}|{hostname}".encode()).hexdigest() #sha256 hash - too complex to use on frontend

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

def run_bash(cmd, noisy=True):
    """
    Run a shell command (using Bash by default) and return stdout text.

    Args:
        cmd (str): The command string to execute.
        noisy (bool): If True, prints error details to stderr.

    Returns: 
        str: The output (stdout) text if successful, "" if failure.
    """
    # Note: On most Linux systems, omitting the shell path 
    # lets subprocess use the system's default shell, 
    # which is typically Bash.
    
    # We use 'shell=True' here to allow the command string 'cmd' 
    # to be processed by the shell (e.g., for pipes, redirects, variables).
    # SECURITY NOTE: Using shell=True can be dangerous if the command 
    # string comes from an untrusted source, as it enables shell injection. 
    # Use with caution.
    
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            executable="/bin/bash", # Explicitly use bash for consistency
            capture_output=True, 
            text=True,
            check=False # Do not raise a CalledProcessError on non-zero exit code
        )
        if result.returncode != 0:
            if noisy:
                # Errors usually go to stderr, but we can also print the exit code
                print_debug(f"Shell command failed with exit code {result.returncode}")
                if result.stderr:
                    print_debug(f"Shell stderr: {result.stderr.strip()}")
            return ""
            
        return result.stdout.strip() or "SUCCESS"
    except FileNotFoundError:
        if noisy:
            print_debug("Error: The /bin/bash executable was not found.")
        return ""

def run_git(args, cwd):
    """Executes git commands with SSL verification disabled."""
    # -c http.sslVerify=false disables SSL checks for the specific command
    cmd = ["git", "-c", "http.sslVerify=false"] + args
    result = subprocess.run(
        cmd, 
        cwd=cwd, 
        capture_output=True, 
        text=True, 
        shell=(platform.system() == "Windows")
    )
    if result.returncode != 0:
        # Errors usually go to stderr, but we can also print the exit code
        print_debug(f"Shell command failed with exit code {result.returncode}")
        if result.stderr:
            print_debug(f"Shell stderr: {result.stderr.strip()}")
    return result

def setup_git_agent(repo_dir, protected_folders, systemInfo=None):
    """Initializes git config and creates initial 'good' and 'bad' baselines."""
    if systemInfo is None:
        systemInfo = get_system_details()
        
    try:
        # 1. Clone or Init Repo
        if not os.path.exists(repo_dir):
            agent_hash = hash_id(AGENT_NAME, systemInfo["hostname"], systemInfo["ipadd"], systemInfo["os"])
            repo_url = f"{SERVER_URL}git/{agent_hash}.git"
            run_git(["clone", repo_url, Path(repo_dir).name], os.path.dirname(Path(repo_dir).resolve()))
        
        run_git(["config", "user.name", "Agent"], repo_dir)
        run_git(["config", "user.email", f"agent@{systemInfo['hostname']}.local"], repo_dir)

        # 2. Create 'good' branch baseline
        run_git(["checkout", "-b", "good"], cwd=repo_dir)
        
        # Sync every folder in the list into its own slug-folder
        for folder in protected_folders:
            sync_protected_to_repo(repo_dir, folder)
            
        run_git(["add", "."], cwd=repo_dir)
        run_git(["commit", "-m", "initialCommitGood"], cwd=repo_dir)
        run_git(["push", "-u", "origin", "good"], cwd=repo_dir)

        # 3. Create 'bad' branch baseline
        run_git(["checkout", "-b", "bad"], cwd=repo_dir)
        # (Files are already synced from the step above)
        run_git(["add", "."], cwd=repo_dir)
        run_git(["commit", "-m", "initialCommitBad"], cwd=repo_dir)
        run_git(["push", "-u", "origin", "bad"], cwd=repo_dir)

        # Switch back to good as the default working state
        run_git(["checkout", "good"], cwd=repo_dir)
        return True

    except Exception as E:
        print_debug(f"Critical error in setup_git_agent: {E}")
        return False
    
def audit_command(command,package="",packageManager="apt"):
    """
    Given a command, ensures that it is available.
    Unmasks the binary, makes it executable, reinstalls it if missing.
    Currently does not support Windows.
    Returns Success(bool) and RemediationAttempted(bool)
    """
    return True, True

def get_pause_status(file=STATUSFILE):
    """
    Evaluates the contents of STATUSFUL and modifies pause attributes accordingly.
    """
    try:
        with open(file,"r+") as f:
            firstline = f.readline().strip()
            if len(firstline) < 1:
                return False,False,0
            preferServer = firstline.lower() == "true"
            pausedUntilEpoch = float(f.readline().strip())
            if round(pausedUntilEpoch) != 0:
                if pausedUntilEpoch > time.time():
                    # Sleep has not elapsed
                    return preferServer, True, pausedUntilEpoch
                else:
                    # Sleep has elapsed
                    f.seek(0)
                    f.write(f"{preferServer}\n0\n")
                    f.truncate()
                    return preferServer, False, 0
            else:
                return preferServer, False, 0
    except FileNotFoundError:
        with open(file,"w") as f:
            f.write(f"false\n0\n")
        return False, False, 0
    except ValueError:
        # Failed conversion to int
        with open(file,"w") as f:
            f.write(f"false\n0\n")
        return False, False, 0
    except Exception as E:
        print_debug(f"get_pause_status(): unknown error - {E}")
        with open(file,"w") as f:
            f.write(f"false\n0\n")
        return False, False, 0
        


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
    url = SERVER_URL + "beacon"

    # Prep payload
    payload = {
        "name": AGENT_NAME,
        "hostname": systemInfo["hostname"],
        "ip": systemInfo["ipadd"],
        "os": systemInfo["os"],
        "executionUser": systemInfo["executionUser"],
        "executionAdmin": systemInfo["executionAdmin"],
        "auth": AUTH_TOKEN,
        "agent_type": AGENT_TYPE,
        "oldStatus": oldStatus,
        "newStatus": newStatus,
        "message": message
    }

    try:
        # Prepare data
        data = json.dumps(payload).encode("utf-8")

        # Build request
        req = urllib.request.Request(
            url,
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
                print_debug(f"send_message(): sent msg to server: [{oldStatus,newStatus,message}]")
                return response.read()
            else:
                print_debug(f"send_message(): Server error: {response.getcode()}")

    # Error handling
    except urllib.error.HTTPError as e:
        print_debug(f"[send_message(): HTTP error: {e.code} {e.reason}")
    except urllib.error.URLError as e:
        print_debug(f"send_message(): URL error: {e.reason}")
    except Exception as e:
        # Various requests errors - networking failure or 4xx/5xx code from server
        print_debug(f"send_message(): Beacon error: {e}")
    return False

def get_pause_state_server(systemInfo=get_system_details()):
    """
    Gets pause state from server

    Returns: pauseTimeEpoch (int), -1 for failure
    """
    if not SERVER_URL:
        # Server comms are intentionally disabled
        # Maybe redirect to print_debug instead?
        return True
    
    url = SERVER_URL + "get_pause"

    # Prep payload
    payload = {
        "name": AGENT_NAME,
        "hostname": systemInfo["hostname"],
        "ip": systemInfo["ipadd"],
        "os": systemInfo["os"],
        "executionUser": systemInfo["executionUser"],
        "executionAdmin": systemInfo["executionAdmin"],
        "auth": AUTH_TOKEN,
        "agent_type": AGENT_TYPE
    }

    try:
        # Prepare data
        data = json.dumps(payload).encode("utf-8")

        # Build request
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )

        # Send payload
        with urllib.request.urlopen(req, timeout=SERVER_TIMEOUT, context=CTX) as response:
            if response.getcode() == 200:
                response_body = response.read().decode("utf-8")
                #result = json.loads(response_body)
                timeInt = float(response_body)
                print_debug(f"get_pause_state_server(): sent msg to server with response {response_body}")
                return timeInt
            else:
                print_debug(f"get_pause_state_server(): Server error: {response.getcode()}")

    # Error handling
    except urllib.error.HTTPError as e:
        print_debug(f"get_pause_state_server(): HTTP error: {e.code} {e.reason}")
    except urllib.error.URLError as e:
        print_debug(f"get_pause_state_server(): URL error: {e.reason}")
    except ValueError:
        print_debug(f"get_pause_state_server(): could not convert received value to int")
    except Exception as e:
        # Various requests errors - networking failure or 4xx/5xx code from server
        print_debug(f"get_pause_state_server(): Beacon error: {e}")
    return -1

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
        return interface_get_primary_linux(get_primary_ip())

def interface_get_primary_windows(ip):
    """
    Gets interface name on linux using "ip" or "ifconfig"
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

def interface_get_primary_linux(ip):
    """
    Gets interface name on linux using "ip" or "ifconfig"
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
        return interface_address_linux(interface,ip_address,subnet,gateway)
        #return False, False, [f"interface_address(): not implemented for system {system}."] # TODO

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

def interface_address_linux(interface, ip_address, subnet, gateway):
    """
    Given an interface name, check if its IP address and gateway are set, 
    and restore them from backup if not (using the 'ip' command).

    Args: 
        interface (str): Interface name (e.g., 'eth0', 'ens192').
        ip_address (str): The desired static IP address (e.g., '192.168.1.100').
        subnet (int): The subnet prefix length (e.g., 24).
        gateway (str): The desired default gateway IP (e.g., '192.168.1.1').

    Returns: 
        tuple: (oldStatus, newStatus, issues)
               oldStatus (bool): True if IP and Gateway were initially present.
               newStatus (bool): True if IP and Gateway are present after the function runs.
               issues (list of strings): List of actions taken or failures.
    """
    issues = []
    
    # 1. Query current configuration using 'ip addr' and 'ip route'
    # The 'ip' command is highly reliable on Rocky Linux/CentOS 8.
    
    # Query IP address information
    ip_addr_cmd = f"ip addr show dev {interface}"
    addr_output = run_bash(ip_addr_cmd, noisy=True)

    # Query default gateway information
    ip_route_cmd = "ip route show default"
    route_output = run_bash(ip_route_cmd, noisy=True)

    if not addr_output:
        print_debug(f"interface_address_linux({interface}): Failed to query interface IP (ip addr)")
        return False, False, [f"Failed to query interface {interface} (ip addr error)."]

    # 2. Determine if address and gateway exist
    
    # Check for IP address: Look for the specific IP/CIDR in the 'ip addr' output
    # Example output line: inet 192.168.1.100/24 brd 192.168.1.255 scope global dynamic ens192
    cidr = f"{ip_address}/{subnet}"
    # Use re.escape to handle potential regex characters in the IP/CIDR string
    has_address = bool(re.search(fr"inet\s+{re.escape(cidr)}\s+", addr_output))

    # Check for Gateway: Look for the specific gateway IP in the 'ip route' output
    # Example output line: default via 192.168.1.1 dev ens192 proto dhcp src 192.168.1.100 metric 100
    has_gateway = bool(re.search(fr"default\s+via\s+{re.escape(gateway)}\s+dev\s+{interface}\s+", route_output))
    
    old_status = has_address and has_gateway
    new_status = old_status

    # 3. Diagnostics and Fixes
    
    # Case 1: Everything is already set correctly
    if old_status:
        return True, True, []

    status_fix = True

    # Fix missing IPv4 address
    if not has_address:
        # Use 'ip addr add' to set the IP address
        set_ip_cmd = f"ip addr add {cidr} dev {interface}"
        
        if DISARM:
            issues.append(f"Missing IPv4 Address for interface {interface}, DISARMED.")
            status_fix = False
        else:
            print_debug(f"interface_address_linux({interface}): Setting IP address: {cidr}")
            if not run_bash(set_ip_cmd):
                status_fix = False
                issues.append(f"Missing IPv4 Address for interface {interface}, FAILED to restore {cidr}.")
            else:
                issues.append(f"Missing IPv4 Address for interface {interface}, RESTORED {cidr}.")
    
    # Fix missing gateway
    if not has_gateway:
        # Use 'ip route add' to set the default gateway
        # Note: We must first delete any *other* existing default route before adding a new one,
        # otherwise 'ip route add' might fail with "File exists".
        # However, for simplicity and matching the original's intent of only setting missing config,
        # we'll use a single command. If the system has a bad default route, this simple check/fix 
        # would need enhancement (e.g., deleting the old one first).
        
        set_gw_cmd = f"ip route add default via {gateway} dev {interface}"
        
        if DISARM:
            issues.append(f"Missing Gateway Address for interface {interface}, DISARMED.")
            status_fix = False
        else:
            print_debug(f"interface_address_linux({interface}): Setting gateway address: {gateway}")
            if not run_bash(set_gw_cmd):
                status_fix = False
                issues.append(f"Missing Gateway Address for interface {interface}, FAILED to restore {gateway}.")
            else:
                issues.append(f"Missing Gateway Address for interface {interface}, RESTORED {gateway}.")

    # Re-check status if a fix was attempted
    if status_fix:
        # Re-query IP address and gateway status after attempted fixes
        addr_output_new = run_bash(ip_addr_cmd, noisy=True)
        route_output_new = run_bash(ip_route_cmd, noisy=True)
        
        has_address_new = bool(re.search(fr"inet\s+{re.escape(cidr)}\s+", addr_output_new))
        has_gateway_new = bool(re.search(fr"default\s+via\s+{re.escape(gateway)}\s+dev\s+{interface}\s+", route_output_new))
        
        new_status = has_address_new and has_gateway_new
    else:
        new_status = False # If we failed to fix anything, the status is False
        
    return old_status, new_status, issues

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
        return interface_mtu_linux(interface,mtu_minimum,mtu_maximum,mtu_default)
        #return False, False, [f"interface_mtu(): not implemented for system {system}."] # TODO

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

def interface_mtu_linux(interface=interface_get_primary(), mtu_minimum=MTU_MIN, mtu_maximum=MTU_MAX, mtu_default=MTU_DEFAULT):
    """
    Given an interface name, check if its MTU is within an acceptable range 
    and remediate if not (using the 'ip' command).

    Args: 
        interface (str): Interface name (e.g., 'eth0', 'ens192').
        mtu_minimum (int): Minimum acceptable MTU value.
        mtu_maximum (int): Maximum acceptable MTU value.
        mtu_default (int): MTU value to set if the current one is out of range.

    Returns: 
        tuple: (oldStatus, newStatus, issues)
               oldStatus (bool): True if MTU was initially in range.
               newStatus (bool): True if MTU is in range after the function runs.
               issues (list of strings): List of actions taken or failures.
    """
    
    # 1. Query current MTU using the 'ip' command
    # Command: ip link show [interface]
    ip_get_mtu = f"ip link show dev {interface}"
    
    output = run_bash(ip_get_mtu)
    if not output:
        return False, False, [f"Failed to query MTU for interface '{interface}' due to shell error."]

    # 2. Parse the MTU value
    # Example output snippet: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc ...
    match = re.search(r"mtu\s+(\d+)\s+", output)
    
    if not match:
        return False, False, [f"Failed to parse MTU for interface '{interface}'. Output: {output}"]

    old_mtu = int(match.group(1))
    
    # 3. Check MTU range
    if old_mtu < mtu_minimum or old_mtu > mtu_maximum:
        new_mtu = mtu_default
        
        # Command: ip link set dev [interface] mtu [new_mtu]
        ip_set_mtu = f"ip link set dev {interface} mtu {new_mtu}"
        
        if DISARM:
            print_debug(f"DISARMED, but told to update MTU for '{interface}' from {old_mtu} to {new_mtu}")
            return False, False, [f"Interface {interface}'s MTU was set to {old_mtu}, DISARMED."]
        else:
            print_debug(f"Updated MTU for '{interface}' from {old_mtu} to {new_mtu}")
            if run_bash(ip_set_mtu):
                # 4. Verification (re-query the MTU)
                output_new = run_bash(ip_get_mtu)
                match_new = re.search(r"mtu\s+(\d+)\s+", output_new)
                
                if match_new and int(match_new.group(1)) == new_mtu:
                    return False, True, [f"Interface {interface}'s MTU was set to {old_mtu}, RESTORED new mtu {new_mtu}."]
                else:
                    return False, False, [f"Interface {interface}'s MTU was set to {old_mtu}, FAILED to verify new mtu {new_mtu}."]
            else:
                return False, False, [f"Interface {interface}'s MTU was set to {old_mtu}, FAILED to restore new mtu {new_mtu}."]

    # 5. MTU is within the acceptable range
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
        return interface_mtu_linux(interface)
        #return False, False, [f"interface_ttl(): not implemented for system {system}."] # TODO

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

def interface_ttl_linux():
    """
    Checks if the system-wide IPv4 TTL or IPv6 Hop Limit is set to a value 
    other than the Linux default (64) and resets it if it is.
    
    Returns: 
        tuple: (oldStatus, newStatus, issues)
               oldStatus (bool): True if TTL/Hop Limits were initially default (64).
               newStatus (bool): True if TTL/Hop Limits are default (64) after run.
               issues (list of strings): List of actions taken or failures.
    """
    issues = []
    
    # Sysctl parameters for controlling default TTL/Hop Limit
    IPV4_TTL_PARAM = "net.ipv4.ip_default_ttl"
    IPV6_HL_PARAM = "net.ipv6.conf.default.hop_limit" # Used if global IPv6 param doesn't exist

    # 1. Query current TTL and Hop Limit values
    # Use 'sysctl' to query the running kernel values
    
    # Query IPv4 TTL
    ttl_query_cmd = f"sysctl -n {IPV4_TTL_PARAM}"
    current_ttl_output = run_bash(ttl_query_cmd, noisy=True)

    # Query IPv6 Hop Limit
    hl_query_cmd = f"sysctl -n {IPV6_HL_PARAM}"
    current_hl_output = run_bash(hl_query_cmd, noisy=True)

    # Convert outputs to integers, default to LINUX_DEFAULT_TTL if query fails or value is missing
    try:
        current_ttl = int(current_ttl_output)
    except (ValueError, TypeError):
        current_ttl = LINUX_DEFAULT_TTL
    
    try:
        current_hl = int(current_hl_output)
    except (ValueError, TypeError):
        current_hl = LINUX_DEFAULT_TTL

    # 2. Determine if values are customized (i.e., not the default 64)
    ttl_customized = current_ttl != LINUX_DEFAULT_TTL
    hl_customized = current_hl != LINUX_DEFAULT_TTL
    
    old_status = not (ttl_customized or hl_customized)

    # 3. Check status and remediate if needed
    if old_status:
        # Values are already the default (good)
        return True, True, []

    status_fix = True

    # Remediate IPv4 TTL
    if ttl_customized:
        set_ttl_cmd = f"sysctl -w {IPV4_TTL_PARAM}={LINUX_DEFAULT_TTL}"
        if DISARM:
            issues.append(f"Bad IPv4 TTL ({current_ttl}) detected, DISARMED.")
            status_fix = False
        else:
            print_debug(f"Remediating IPv4 TTL from {current_ttl} to {LINUX_DEFAULT_TTL}")
            if run_bash(set_ttl_cmd, noisy=True):
                issues.append(f"Bad IPv4 TTL ({current_ttl}) detected, RESTORED to {LINUX_DEFAULT_TTL}.")
            else:
                issues.append(f"Bad IPv4 TTL ({current_ttl}) detected, FAILED to restore.")
                status_fix = False

    # Remediate IPv6 Hop Limit
    if hl_customized:
        set_hl_cmd = f"sysctl -w {IPV6_HL_PARAM}={LINUX_DEFAULT_TTL}"
        if DISARM:
            issues.append(f"Bad IPv6 Hop Limit ({current_hl}) detected, DISARMED.")
            status_fix = False
        else:
            print_debug(f"Remediating IPv6 Hop Limit from {current_hl} to {LINUX_DEFAULT_TTL}")
            if run_bash(set_hl_cmd, noisy=True):
                issues.append(f"Bad IPv6 Hop Limit ({current_hl}) detected, RESTORED to {LINUX_DEFAULT_TTL}.")
            else:
                issues.append(f"Bad IPv6 Hop Limit ({current_hl}) detected, FAILED to restore.")
                status_fix = False
    
    # 4. Final verification
    new_status = False
    if status_fix:
        # Re-query the values to verify
        new_ttl_output = run_bash(ttl_query_cmd, noisy=True)
        new_hl_output = run_bash(hl_query_cmd, noisy=True)
        
        try:
            new_ttl = int(new_ttl_output)
            new_hl = int(new_hl_output)
        except (ValueError, TypeError):
            # If the re-query fails, assume the fix failed
            return False, False, issues
            
        new_status = (new_ttl == LINUX_DEFAULT_TTL and new_hl == LINUX_DEFAULT_TTL)

    # NOTE: This only changes the *running* kernel value. For persistence 
    # across reboots, the function would also need to remove or edit the 
    # corresponding entries in /etc/sysctl.conf or /etc/sysctl.d/*.conf files.
    
    return old_status, new_status, issues

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
        return interface_down_linux(interface)
        #return False, False, [f"interface_down(): not implemented for system {system}."] # TODO

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

def interface_down_linux(interface=interface_get_primary()):
    """
    Given an interface name, check if it is administratively down (SHUTDOWN)
    and remediate by bringing it up using the 'ip' command.
    
    Args: 
        interface (str): Interface name (e.g., 'eth0', 'ens192').

    Returns: 
        tuple: (oldStatus, newStatus, issues)
               oldStatus (bool): True if the interface was initially UP.
               newStatus (bool): True if the interface is UP after the function runs.
               issues (list of strings): List of actions taken or failures.
    """
    issues = []
    
    # 1. Query current interface status using 'ip link'
    # This command provides both administrative and operational status.
    # Output flags: UP means administratively up, DOWN means administratively down.
    # LOWER_UP means link is physically connected (operational state UP).
    ip_check_cmd = f"ip link show dev {interface}"
    
    output = run_bash(ip_check_cmd)
    if not output:
        # This usually means the interface was not found or a shell error occurred
        return False, False, [f"Interface {interface} cannot be queried (Not Found or shell error)."]

    # 2. Determine if the interface is administratively UP or DOWN
    # Check for the 'UP' flag in the output (e.g., <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500)
    # If the 'UP' flag is missing, the interface is administratively down.
    
    status_match = re.search(r"<\S+>", output)
    if not status_match:
        # Interface found, but status flags are missing, which is highly unusual.
        return False, False, [f"Interface {interface}'s status flags could not be parsed."]

    flags = status_match.group(0)
    
    is_up = "UP" in flags
    old_status = is_up
    
    # 3. Remediate if the interface is DOWN
    if not is_up:
        # If it's administratively DOWN, bring it UP
        ip_set_up_cmd = f"ip link set dev {interface} up"
        
        if DISARM:
            print_debug(f"interface_down_linux({interface}): DISARMED, but told to enable interface")
            return False, False, [f"Interface {interface} was set to DOWN, DISARMED."]
        else:
            print_debug(f"interface_down_linux({interface}): Setting interface UP.")
            if run_bash(ip_set_up_cmd):
                # Check status again to verify the fix
                output_new = run_bash(ip_check_cmd)
                status_match_new = re.search(r"<\S+>", output_new)
                
                new_status = False
                if status_match_new and "UP" in status_match_new.group(0):
                    new_status = True
                    return False, new_status, [f"Interface {interface} was set to DOWN, RESTORED UP state."]
                else:
                    return False, new_status, [f"Interface {interface} was set to DOWN, FAILED to restore UP state."]
            else:
                return False, False, [f"Interface {interface} was set to DOWN, FAILED to restore UP state (command failed)."]

    # 4. Interface is already UP
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
        print_debug("[+] IPv4 is not installed. Reinstalling...")
        ps_install = r'''
        netsh interface ipv4 install
        Write-Output "Installed"
        '''
        run_powershell(ps_install)
    else:
        print_debug("[+] IPv4 already installed.")

    # --- Step 3: restore IPv4 address ---
    print_debug(f"[+] Restoring IPv4 address on {interface_name}...")
    ps_set_ip = fr'''
    netsh interface ipv4 set address name="{interface_name}" static {ipv4_address} {prefix_length} {gateway}
    '''
    run_powershell(ps_set_ip)

    # --- Step 4: restore DNS ---
    print_debug("[+] Restoring DNS servers...")
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

    print_debug("[+] IPv4 configuration restored successfully.")
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

    # Interface 
    """
    result_oldStatus, result_newStatus, result_issues = interface_address(interface,ip_address,subnet,gateway)
    if not result_oldStatus:
        oldStatus = False
    if not result_newStatus:
        newStatus = False
    for issue in result_issues:
        issues.append(issue)
    """

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
        return firewall_rules_audit_linux(port,direction,action)
        #return [f"firewall_rules_audit(): not implemented for system {system}."], dict() # TODO

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
            if ($lp -eq 'Any') {{ return $true }}
            if ($lp -like '*,*') {{
                return $lp.Split(',') -contains '{port}'
            }}

            if ($lp -like '*-*') {{
                $range = $lp.Split('-')
                $a = [int]$range[0].Trim()
                $b = [int]$range[1].Trim()
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

def firewall_rules_audit_linux(port, direction="in", action="block"):
    """
    Uses iptables to audit firewall rules, returning the protocol, chain, 
    index, and specification needed for deletion.
    
    Args: 
        port (str): The specific port number (e.g., "80", "443").
        direction (str): 'in' (INPUT chain) or 'out' (OUTPUT chain).
        action (str): 'block' (DROP/REJECT) or 'accept' (ACCEPT).
        
    Returns: 
        tuple: (issues, matching_rules)
               issues (list of strings): List of errors encountered.
               matching_rules (list of dicts): List of matching rules found with full detail.
    """
    issues = []
    matching_rules = []
    
    chain = "INPUT" if direction.lower() == "in" else "OUTPUT"
    targets = ["DROP", "REJECT"] if action.lower() == "block" else ["ACCEPT"]
    
    # 1. Query iptables rules with numbering (-nL --line-numbers)
    # This gives us the crucial rule index number.
    ip_query_cmd = f"{IPTABLES_PATH} -t filter -nL {chain} --line-numbers"
    output = run_bash(ip_query_cmd)

    if not output:
        return [f"Could not run '{ip_query_cmd}' or no rules found."], []

    # 2. Parse rules line by line
    
    # Regex to capture the index, protocol, destination port, and target
    # Example line: 1    DROP       all  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:80
    rule_regex = re.compile(
        fr"^\s*(?P<index>\d+)\s+(?P<target>DROP|REJECT|ACCEPT)\s+"  # Index and Target
        fr"(?P<prot>[a-z\d]+|\*)\s+.*?"                               # Protocol (* or tcp/udp/icmp)
        fr"(?P<spec>[sd]ports?)\s*:?\s*(?P<port_spec>[\d,\-]+)"           # dpt/spt and Port Spec (optional, uses non-greedy match)
    )

    for line in output.splitlines():
        # Check if the line is a rule, excluding the chain header/footer
        if not line.strip().startswith(('Chain', 'num', 'target', 'policy', 'pkts')):
            
            match = rule_regex.search(line)
            
            if match and match.group('target') in targets:
                # Rule is in the correct CHAIN and has the correct ACTION (Target)
                
                # Protocol (e.g., 'tcp', 'udp', 'all' -> *)
                protocol = match.group('prot')
                
                # Check for port match (Windows LocalPort logic)
                # Note: We assume local port (dpt) for inbound, and remote port (spt) for outbound
                port_definition = match.group('port_spec')
                
                is_port_match = False
                if port_definition:
                    # Logic to check single port, range, or list (same as previous implementation)
                    separator = ':' if ':' in port_definition else '-'
                    if ',' in port_definition and str(port) in port_definition.split(','):
                        is_port_match = True
                    elif separator in port_definition:
                        try:
                            a, b = map(int, port_definition.split(separator))
                            target_port = int(port)
                            if a <= target_port <= b:
                                is_port_match = True
                        except ValueError:
                            issues.append(f"Warning: Could not parse port range in rule: {line}")
                    elif port_definition == str(port):
                        is_port_match = True

                    if is_port_match:
                        # Full rule line captured for spec reference in deletion
                        # (Need to extract the rule spec without index, target, etc.)
                        
                        # Re-run iptables-save to get a clean spec, or reconstruct it
                        # Since re-running is complex, let's use the full display line as spec placeholder
                        full_spec_line = line.strip()

                        rule_dict = {
                            "Chain": chain,
                            "Index": match.group('index'),
                            "Protocol": protocol,
                            "Action": match.group('target'),
                            "Direction": direction.upper(),
                            "DisplayName": full_spec_line, # Rule definition including index
                            "Rule_Spec": full_spec_line # Using the full line as a spec placeholder for now
                        }
                        matching_rules.append(rule_dict)

    return issues, matching_rules

def firewall_rules_delete(rules,port):
    """
    Wrapper for OS-specific firewall_rules_delete_* functions

    Given a firewall rules dict, deletes each rule
    
    Args: firewall rules dict (Name, DisplayName, Action, Direction, Profile)
    returns: status(bool), issues(list of strings)
    """
    system = platform.system()

    if system == "Windows":
        return firewall_rules_delete_windows(rules,port)
    else:
        return firewall_rules_delete_linux(rules)
        #return False, [f"firewall_rules_delete(): not implemented for system {system}."] # TODO

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

def firewall_rules_delete_linux(rules):
    """
    Given a list of firewall rule dictionaries (must contain Chain and Index), 
    deletes each rule by its number and persists the change.
    
    Args: 
        rules (list of dicts): List of matching rules from the audit function.
        
    Returns: 
        tuple: (status, issues)
               status (bool): True if all rules were successfully deleted and persisted.
               issues (list of strings): List of actions taken or failures.
    """
    issues = []
    overall_status = True
    
    # We must delete rules in reverse order of their index to avoid shifting indices 
    # of rules that are yet to be deleted.
    rules.sort(key=lambda r: int(r['Index']), reverse=True)
    
    for rule in rules:
        chain = rule.get('Chain')
        index = rule.get('Index')
        display_name = rule.get('DisplayName', 'N/A')
        
        if not (chain and index):
            issues.append(f"FAILED: Rule {display_name} is missing Chain or Index and cannot be deleted.")
            overall_status = False
            continue

        # 1. Delete the rule by number
        # Format: iptables -D [CHAIN] [INDEX_NUMBER]
        delete_cmd = f"{IPTABLES_PATH} -D {chain} {index}"
        
        if DISARM:
            issues.append(f"DISARMED, but told to remove firewall rule: {chain} rule #{index}")
            continue
        else:
            
            print_debug(f"Attempting delete: {delete_cmd} (Rule: {display_name})")
            
            if run_bash(delete_cmd):
                # Success (iptables returns empty output on success)
                issues.append(f"SUCCESSFULLY removed firewall rule from {chain} at index #{index}.")
            else:
                # Failure
                issues.append(f"FAILED to remove firewall rule from {chain} at index #{index}. Command failed.")
                overall_status = False

    # 2. Persist the changes (Crucial for iptables)
    if not DISARM:
        persist_cmd = f"{IPTABLES_PATH}-save > {IPTABLES_SAVE_PATH}"
        
        if overall_status:
            print_debug("Attempting to persist iptables rules...")
            if run_bash(persist_cmd):
                #issues.append("SUCCESS: Running iptables rules saved (persistent).")
                pass
            else:
                issues.append("WARNING: FAILED to persist iptables changes. Rule deletion is *NOT* permanent.")
                overall_status = False 

    return overall_status, issues

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
        return firewall_rules_create_linux(port,direction,action)
        #return False, [f"firewall_rules_create(): not implemented for system {system}."] # TODO

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

def firewall_rules_create_linux(port, direction, action, protocol="tcp"):
    """
    Creates the specified iptables rule on Rocky Linux/CentOS 8 and persists it.

    Args: 
        port (str): The port number (e.g., "80", "443").
        direction (str): 'inbound' or 'outbound'.
        action (str): 'allow' (ACCEPT) or 'block' (DROP).
        protocol (str): Protocol to use, defaults to 'tcp'. Use 'all' or 'udp' if needed.

    Returns: 
        tuple: (status, issues)
               status (bool): True if the rule was successfully created and persisted.
               issues (list of strings): List of actions taken or failures.
    """
    issues = []
    
    # 1. Map arguments to iptables terminology
    
    # Direction maps to CHAIN: 'inbound' -> INPUT, 'outbound' -> OUTPUT
    if direction.lower() == "inbound":
        chain = "INPUT"
        port_flag = "--dport" # Destination port for inbound traffic
    elif direction.lower() == "outbound":
        chain = "OUTPUT"
        port_flag = "--sport" # Source port for outbound traffic (usually ignored for simple outbound rules)
    else:
        return False, [f"FAILED: Invalid direction '{direction}'. Must be 'inbound' or 'outbound'."]

    # Action maps to TARGET: 'allow' -> ACCEPT, 'block' -> DROP
    if action.lower() == "allow":
        target = "ACCEPT"
    elif action.lower() == "block":
        target = "DROP"
    else:
        return False, [f"FAILED: Invalid action '{action}'. Must be 'allow' or 'block'."]

    # 2. Construct the iptables command
    # Use -A (Append) to add the rule to the end of the chain.
    
    # Base command: sudo iptables -A [CHAIN]
    # Protocol: -p [PROTOCOL]
    # Port: --dport/--sport [PORT]
    # Target: -j [TARGET]
    
    # Note: iptables requires -m tcp/udp when using --dport/--sport
    
    if protocol.lower() == "tcp" or protocol.lower() == "udp":
        module_spec = f"-m {protocol.lower()}"
    else:
        # For protocols like 'all' or 'icmp', the module is usually omitted
        module_spec = ""
        port_flag = "" # Port specification is usually irrelevant for non-tcp/udp rules

    rule_spec = f"-p {protocol.lower()} {module_spec} {port_flag} {port} -j {target}"
    iptables_cmd = f"{IPTABLES_PATH} -A {chain} {rule_spec}"
    
    # 3. Execute the command
    
    rule_description = f"{target} on port {port} ({protocol.upper()}) {direction.upper()}"

    if DISARM:
        print_debug(f"firewall_rules_create_linux(): DISARMED, but told to create rule: {iptables_cmd}")
        return False, [f"DISARMED, but told to create firewall rule: {rule_description}"]
    else:

        print_debug(f"Creating iptables rule: {iptables_cmd}")
        if run_bash(iptables_cmd):
            issues.append(f"SUCCESSFULLY created firewall rule: {rule_description} (running kernel).")
            
            # 4. Persist the change (Crucial for iptables)
            persist_cmd = f"{IPTABLES_PATH}-save > {IPTABLES_SAVE_PATH}"
            
            print_debug("Attempting to persist iptables rules...")
            if run_bash(persist_cmd):
                #issues.append("SUCCESS: Running iptables rules saved to disk (persistent).")
                return False, issues
            else:
                issues.append("FAILED to persist iptables changes. Rule is *NOT* permanent across reboots.")
                return False, issues
        else:
            return False, [f"FAILED to create firewall rule: {rule_description}. Check permissions/syntax."]
    
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
        return firewall_policy_audit_linux(direction)
        #return False, False, [f"firewall_policy_audit(): not implemented for system {system}."] # TODO

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
            issues.append([f"Default firewall policy on profile {p['Name']} for direction {direction} is set to BLOCK."])
        
    if issues:
        return True, False, issues
        
    return True, True, []

def firewall_policy_audit_linux(direction):
    """
    Check if the iptables default policy for the relevant chain is set to BLOCK (DROP/REJECT).

    Args: 
        direction (str): "Inbound" (checks INPUT chain) or "Outbound" (checks OUTPUT chain).
        
    Returns: 
        tuple: (funcStatus, policyStatus, issues)
               funcStatus (bool): True if execution completed without error.
               policyStatus (bool): True if policy is set to ACCEPT (default deny is FALSE).
               issues (list of strings): Details of any default deny policy found.
    """
    issues = []
    
    # 1. Map direction to iptables CHAIN
    if direction.lower() == "inbound":
        chain = "INPUT"
    elif direction.lower() == "outbound":
        chain = "OUTPUT"
    else:
        return False, False, [f"Failed: Invalid direction '{direction}'. Must be 'Inbound' or 'Outbound'."]

    # 2. Query the current policy for the target chain
    # iptables -L -n --line-numbers will list policies, but -S gives a clean policy output.
    ip_query_cmd = f"{IPTABLES_PATH} -t filter -S {chain}"
    output = run_bash(ip_query_cmd)

    if not output:
        # This typically means iptables is not running or a permission error
        return False, False, [f"Failed to load iptables policy for {chain} due to shell error."]

    # 3. Parse the policy
    # Expected output format: -P INPUT ACCEPT [0:0] or -P INPUT DROP [0:0]
    policy_regex = re.compile(fr"^-P\s+{chain}\s+(?P<action>ACCEPT|DROP|REJECT)(?:\s+\[\d+:\d+\])?")
    
    match = policy_regex.search(output)
    
    if not match:
        return False, False, [f"Failed to parse iptables policy for {chain}. Unexpected output."]

    default_action = match.group('action')

    # 4. Determine policy status
    
    # Default Policy is considered 'bad' (policyStatus=False) if it's set to DROP or REJECT.
    if default_action in ["DROP", "REJECT"]:
        issues.append(f"Default firewall policy for {chain} ({direction}) is set to BLOCK ({default_action}).")
        policy_status = False
    else:
        policy_status = True # ACCEPT is considered the "safe" status in this context.

    return True, policy_status, issues

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

    return oldStatus, newStatus, issues

    # TODO: windows has additional options like rule per executable

#endregion###############
## File Protect Funcs ###
#region##################

def apply_security_policy(target_path):
    """
    Applies the security policy: 
    Not immutable, Owner/Admin: RWX, Users: R.
    """
    is_windows = platform.system() == "Windows"
    
    # 1. Remove Immutability / Read-Only Flags
    try:
        if is_windows:
            # Remove Read-Only (R), System (S), and Hidden (H) attributes
            subprocess.run(["attrib", "-R", "-S", "-H", target_path, "/S", "/D"], capture_output=True)
        else:
            # Linux (chattr) and BSD/FreeBSD (chflags)
            if platform.system() in ["FreeBSD", "Darwin"]:
                subprocess.run(["chflags", "-R", "noschg", target_path], capture_output=True)
            else:
                subprocess.run(["chattr", "-R", "-i", target_path], capture_output=True)
    except Exception:
        pass # Some filesystems might not support these flags

    # 2. Apply Access Permissions
    if is_windows:
        # Reset inheritance and grant permissions
        # /grant:r = replace permissions
        # Administrators:(OI)(CI)F = Full access to Admins, Inherit to files/folders
        # Users:(OI)(CI)R = Read access to all users
        cmds = [
            ["icacls", target_path, "/reset", "/T", "/C"],
            ["icacls", target_path, "/grant:r", "Administrators:(OI)(CI)F", "/T", "/C"],
            ["icacls", target_path, "/grant:r", "Users:(OI)(CI)R", "/T", "/C"]
        ]
        for cmd in cmds:
            subprocess.run(cmd, capture_output=True)
    else:
        # Unix-like (Debian, Ubuntu, RHEL, Alpine, FreeBSD)
        # 7 = rwx (Owner), 4 = r (Group), 4 = r (Others)
        os.chmod(target_path, 0o744)
        for root, dirs, files in os.walk(target_path):
            for d in dirs:
                os.chmod(os.path.join(root, d), 0o744)
            for f in files:
                os.chmod(os.path.join(root, f), 0o744)

def get_path_slug(path):
    """Converts a system path into a safe, flat folder name for the repo."""
    # Remove drive letters (C:) and replace separators with underscores
    clean_path = re.sub(r'^[a-zA-Z]:', '', path)
    slug = re.sub(r'[^a-zA-Z0-9]', '_', clean_path).strip('_')
    return slug if slug else "root_dir"

def sync_protected_to_repo(repo_dir, protected_folder):
    """Copies a specific folder into its designated sub-folder in the repo."""
    slug = get_path_slug(protected_folder)
    dest_in_repo = os.path.join(repo_dir, slug)
    
    # Apply security policy before copying
    apply_security_policy(protected_folder)
    
    # If it's a single file, use copy; if directory, use copytree
    if os.path.isfile(protected_folder):
        os.makedirs(dest_in_repo, exist_ok=True)
        shutil.copy(protected_folder, os.path.join(dest_in_repo, os.path.basename(protected_folder)))
    else:
        shutil.copytree(protected_folder, dest_in_repo, dirs_exist_ok=True)
    
    apply_security_policy(dest_in_repo)

def restore_protected_from_repo(repo_dir, protected_folder):
    """Restores a specific folder from its slug-folder in the repo."""
    slug = get_path_slug(protected_folder)
    source_in_repo = os.path.join(repo_dir, slug)
    
    if not os.path.exists(source_in_repo):
        return
        
    if os.path.basename(protected_folder) in os.listdir(source_in_repo):
        # Extract the file from the slug directory
        file_name = os.path.basename(protected_folder)
        shutil.copy(os.path.join(source_in_repo, file_name), protected_folder)
    else:
        shutil.copytree(source_in_repo, protected_folder, dirs_exist_ok=True)
    
    apply_security_policy(protected_folder)

def get_latest_commit_stats(branch_name,repo_dir):
    """
    Returns the number of changes and a list of file names for 
    the latest commit on the specified branch.
    """
    # --name-status gives us: 
    # M path/to/file (Modified)
    # A path/to/file (Added/Created)
    # D path/to/file (Deleted)
    result = run_git(["show", "--format=", "--name-status", branch_name],repo_dir)
    
    if result.returncode != 0 or not result.stdout.strip():
        return {"count": 0, "files": []}

    lines = result.stdout.strip().split('\n')
    files_info = []
    
    for line in lines:
        if not line: continue
        # Split status (M, A, D) from the path
        parts = line.split(maxsplit=1)
        if len(parts) == 2:
            status, file_path = parts
            status_map = {'M': 'Modified', 'A': 'Created', 'D': 'Deleted'}
            friendly_status = status_map.get(status, status)
            files_info.append(f"{friendly_status}: {file_path}")

    return {
        "count": len(files_info),
        "files": files_info
    }

def file_protect_main(repo_dir, protected_folders):
    """Main logic for the agent sync loop supporting multiple paths."""
    try:
        # 1. Pull latest 'good' state from remote
        run_git(["checkout", "good"], repo_dir)
        run_git(["pull", "origin", "good"], repo_dir)

        for item in os.listdir(repo_dir):
            if item == ".git":
                continue
            path = os.path.join(repo_dir, item)
            if os.path.isdir(path):
                shutil.rmtree(path)
            else:
                os.remove(path)
        
        # 2. Sync all protected folders to their sub-directories in the repo
        for folder in protected_folders:
            if os.path.exists(folder):
                sync_protected_to_repo(repo_dir, folder)
            else:
                print_debug(f"Warning: Protected path {folder} not found. Skipping sync.")
        
        # 3. Check for differences across the entire repo
        run_git(["add", "."], repo_dir)
        diff_check = run_git(["diff", "--cached", "--quiet"], repo_dir)

        # exit_code 1 means there are changes somewhere in the repo
        if diff_check.returncode != 0:
            try:
                # 1. Get the current commit hash from the 'good' branch for the baseline name
                # 'git rev-parse --short HEAD' gives us the 7-character hash
                hash_result = run_git(["rev-parse", "--short", "HEAD"], repo_dir)
                good_hash = hash_result.stdout.strip() if hash_result.returncode == 0 else "unknown"

                # 2. Stash the malicious changes currently in the working directory
                run_git(["stash"], repo_dir)
                
                # 3. Move to the 'bad' branch and pull latest
                run_git(["checkout", "bad"], repo_dir)
                run_git(["pull", "origin", "bad"], repo_dir)
                
                # 4. Sync 'bad' branch working tree to match 'good' state exactly
                run_git(["checkout", "good", "."], repo_dir) 
                run_git(["add", "."], repo_dir)
                
                # 5. Commit the Baseline using the captured hash
                # Using --allow-empty in case the previous 'bad' state was already identical to this 'good' hash
                run_git(["commit", "--allow-empty", "-m", f"baseline-{good_hash}"], repo_dir)

                # 6. Apply the malicious changes back on top of the clean baseline
                stash_apply = run_git(["stash", "pop"], repo_dir)
                if stash_apply.returncode != 0:
                    # Resolve conflicts by preferring the malicious changes (the "popped" stash)
                    run_git(["checkout", "--theirs", "."], repo_dir)
                    run_git(["add", "."], repo_dir)
                    run_git(["commit", "-m", "auto-resolveconflict"], repo_dir)
                
                # 7. Commit and Push the 'bad' state
                timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
                run_git(["add", "."], repo_dir)
                run_git(["commit", "-m", f"auto-malicious-{timestamp}"], repo_dir)
                run_git(["push", "-u", "origin", "bad"], repo_dir)
                
                # Get details of what changed for the alert message
                changes = get_latest_commit_stats("bad", repo_dir)
                
                # 4. RESTORATION
                run_git(["checkout", "good"], repo_dir)
                if not DISARM:
                    win = platform.system() == "Windows"
                    for s in SERVICES:
                        cmd = ["net", "stop", s] if win else ["service", s, "stop"]
                        subprocess.run(cmd, capture_output=True)
                    # Restore every protected folder from its 'good' repo sub-folder
                    for folder in protected_folders:
                        restore_protected_from_repo(repo_dir, folder)
                    for s in SERVICES:
                        cmd = ["net", "start", s] if win else ["service", s, "start"]
                        subprocess.run(cmd, capture_output=True)
                    
                    msg = f"SECURITY ALERT: {changes['count']} unauthorized changes restored across protected paths: {changes['files']}"
                    return False, True, [msg]
                else:
                    msg = f"SECURITY ALERT: {changes['count']} changes detected (DISARMED): {changes['files']}"
                    return False, False, [msg]

            except Exception as E:
                return False, False, [f"Changes detected but restoration failed: {E}"]
        
        # No changes detected
        return True, True, []

    except Exception as E:
        return False, False, [f"Integrity check error: {E}"]
    
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
        return service_audit_linux(service)
        #return False, False, [f"service_audit(): not implemented for system {system}."] # TODO

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

def service_audit_linux(service_name):
    """
    Given the name of a systemd service, detect if it is nonfunctional (not running 
    or not enabled for auto-start) and attempt fixes using systemctl.
    
    Args:
        service_name (str): The name of the systemd unit (e.g., 'httpd.service').

    Returns: 
        tuple: (oldStatus, newStatus, issues)
               oldStatus (bool): True if the service was initially OK.
               newStatus (bool): True if the service is OK after fixes.
               issues (list of strings): List of actions taken or failures.
    """
    issues = []
    
    # 1. Check whether service exists and get its current state
    
    # systemctl is-active --quiet and is-enabled --quiet provide quick checks,
    # but systemctl show gives all data in a parsable format.
    systemctl_show_cmd = f"systemctl show --no-pager {service_name}"
    raw = run_bash(systemctl_show_cmd).strip()

    if not raw:
        # Check if the error is "not found" (exit code 1) or a shell issue
        systemctl_check = run_bash(f"systemctl status {service_name}", noisy=True)
        if "not-found" in systemctl_check.lower():
            return False, False, [f"ServiceNotFound for service {service_name}."]
        else:
            return False, False, [f"FAILED to get status information for service {service_name}, systemctl error."]

    # Parse the output to extract key parameters
    data = {}
    for line in raw.splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            data[key] = value

    current_active_state = data.get("ActiveState", "").lower() # running, inactive, failed, etc.
    current_load_state = data.get("LoadState", "").lower()     # loaded, not-found, etc.
    current_enable_state = data.get("UnitFileState", "").lower() # enabled, disabled, static, etc.

    # If the service is loaded but not enabled (manual start type), or if it's not running
    is_running = current_active_state == "active"
    is_enabled = current_enable_state in ["enabled", "enabled-runtime", "static", "indirect"] # Equivalent to Automatic start type
    
    oldStatus = is_running and is_enabled
    
    # Track whether we changed anything
    newStatus = oldStatus
    
    # ----------------------------------------------------------
    # 2. If service is not running - start it (Fix Active State)
    # ----------------------------------------------------------
    if not is_running:
        start_cmd = f"systemctl start {service_name}"
        
        if DISARM:
            issues.append(f"Service {service_name} is stopped, DISARMED.")
            newStatus = False
        else:
            # Check for service status before and after start
            if run_bash(start_cmd):
                # Verify state change
                time.sleep(1)
                verify_cmd = f"systemctl is-active {service_name}"
                if run_bash(verify_cmd).strip() == "active":
                    issues.append(f"Service {service_name} was stopped, RESTORED to START state.")
                    newStatus = True
                else:
                    issues.append(f"Service {service_name} was stopped, FAILED to verify START state.")
            else:
                issues.append(f"Service {service_name} was stopped, FAILED to execute start command.")

    # ----------------------------------------------------------
    # 3. If service is not Automatic (Enabled) - set it to Automatic (Fix Enable State)
    # ----------------------------------------------------------
    if not is_enabled:
        enable_cmd = f"systemctl enable {service_name}"
        
        if DISARM:
            issues.append(f"Service {service_name} not set to automatic start (disabled), DISARMED.")
        else:
            # Need to disable silent flag for error detection
            if run_bash(enable_cmd):
                # Verify state change
                verify_cmd = f"systemctl is-enabled {service_name}"
                if run_bash(verify_cmd).strip() == "enabled":
                    issues.append(f"Service {service_name} was disabled, RESTORED to automatic start (enabled).")
                    newStatus = True
                else:
                    issues.append(f"Service {service_name} was disabled, FAILED to verify automatic start.")
            else:
                issues.append(f"Service {service_name} was disabled, FAILED to execute enable command.")

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
        return service_uninstall_linux(service,package)
        #return False, False, [f"service_uninstall(): not implemented for system {system}."] # TODO

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

def service_uninstall_linux(service, package):
    """
    Given a service unit name and responsible RPM package name, checks if 
    both are installed/exist and attempts to install the package if missing.

    Args: 
        service (str): The systemd unit name (e.g., 'httpd.service').
        package (str): The RPM package name (e.g., 'httpd').
        
    Returns: 
        tuple: (oldStatus, newStatus, issues)
               oldStatus (bool): True if both package and service were initially present.
               newStatus (bool): True if both are present after remediation (or if DISARMED).
               issues (list of strings): List of actions taken or failures.
    """
    issues = []
    
    # Initial status assumption (will be set by checks)
    package_present_initial = False
    service_present_initial = False

    # ---------------------------------------------------------
    # 1. Check if the RPM package is installed
    # ---------------------------------------------------------
    if package:
        # rpm -q returns the package name and version if installed, nothing if not.
        rpm_check_cmd = f"rpm -q {package}"
        rpm_output = run_bash(rpm_check_cmd, noisy=True)

        # Output will contain "is not installed" on stderr/stdout if missing, or nothing on success
        if "is not installed" not in rpm_output and rpm_output != "":
            package_present_initial = True
            print_debug(f"Package {package} is installed.")
        else:
            #issues.append(f"Missing required package {package} for service {service}.")
            
            if not DISARM:
                # Attempt to install the missing package using dnf (default for Rocky/CentOS 8)
                install_cmd = f"dnf install -y {package}"
                print_debug(f"Attempting to install package {package}...")
                
                if run_bash(install_cmd):
                    issues.append(f"Missing required package {package}, RESTORED by installing package.")
                    
                    # Re-check package state after install
                    if "is not installed" not in run_bash(rpm_check_cmd, noisy=True) and run_bash(rpm_check_cmd, noisy=True) != "":
                        package_present_after = True
                    else:
                        package_present_after = False
                        issues.append(f"FAILED to verify installation of package {package}.")
                else:
                    issues.append(f"Missing required package {package}, FAILED to install package using dnf.")
                    package_present_after = False
            else:
                issues.append(f"Missing required package {package} for service {service}, DISARMED.")
                package_present_after = False
    else:
        # If no package is specified, assume this check is irrelevant
        package_present_initial = True
        package_present_after = True
        
    # ---------------------------------------------------------
    # 2. Check if the service unit file exists
    # ---------------------------------------------------------
    if service:
        # systemctl status will fail (return code 3) if the unit file is not found.
        # systemctl show will return error for non-existent service
        svc_check_cmd = f"systemctl show --no-pager {service}"
        svc_output = run_bash(svc_check_cmd, noisy=True)

        if "not-found" not in svc_output and svc_output != "":
            service_present_initial = True
            service_present_after = True # If the package was successfully installed, the service should now exist
        else:
            issues.append(f"Missing service unit file {service}.")
            # If the package was installed, the service *should* exist now (service_present_after handled below)
            service_present_after = False
            
            # If the package was newly installed, re-check service presence
            if not package_present_initial and package_present_after and service_present_initial == False:
                 if "not-found" not in run_bash(svc_check_cmd, noisy=True) and run_bash(svc_check_cmd, noisy=True) != "":
                    service_present_after = True
                    issues.append(f"Service {service} restored by package installation.")

    else:
        service_present_initial = True
        service_present_after = True
        
    # ---------------------------------------------------------
    # 3. Final Status Calculation
    # ---------------------------------------------------------
    
    old_status = package_present_initial and service_present_initial
    new_status = package_present_after and service_present_after

    # Edge case: If old_status was False but new_status is False and we tried to remediate
    if not old_status and not new_status and not DISARM:
        # If package was missing and remediation failed, ensure status reflects the failure
        if not package_present_after:
             issues.append(f"Overall FAILED to restore missing service/package.")
        if not service_present_after:
             issues.append(f"Overall FAILED to find service {service} even after package install.")
    
    return old_status, new_status, issues

def service_integrity(service,backupDict):
    """
    Wrapper for OS-specific service_integrity_* functions

    Given the name of a Windows service, check its attributes against a dict of known good attributes and restore if needed
    
    Returns: Returns: oldStatus(bool), newStatus(bool), issues(list of string)
    """
    system = platform.system()

    if system == "Windows":
        return service_integrity_windows(service,backupDict)
    else:
        return True, True, []
        #return service_integrity_linux(service,backupDict)
        #return False, False, [f"service_integrity(): not implemented for system {system}."] # TODO
    
def service_integrity_windows(service_name, backupDict):
    """
    Given the name of a Windows service, check its attributes against a dict of 
    known good attributes and restore or recreate if needed.
    
    backupDict must contain:
    - "PathName": The expected executable path (e.g., "C:\\Windows\\System32\\svchost.exe -k LocalService")
    - "StartName": The expected service account (e.g., "LocalSystem")
    - "Dependencies": The expected list of dependent service names (e.g., ["RpcSs"])
    - "DisplayName": The service display name (e.g., "Windows Time")
    - "StartType": The service startup type (e.g., "auto", "demand", "disabled")
    
    Returns: oldStatus(bool), newStatus(bool), issues(list of strings)
    """
    
    # 1. Check whether service exists and get its current attributes
    ps_check = fr"""
    $svc = Get-CimInstance Win32_Service -Filter "Name='{service_name}'" -ErrorAction SilentlyContinue
    if ($svc -eq $null) {{
        Write-Output 'NotFound'
    }} else {{
        $obj = New-Object PSObject -Property @{{
            StartName = $svc.StartName
            PathName = $svc.PathName
            Dependencies = $svc.DependsOn
        }}
        $obj | ConvertTo-Json
    }}
    """
    
    raw = run_powershell(ps_check).strip()
    if not raw:
        return False, False, [f"FAILED to get integrity information for service {service_name}, PowerShell error."]

    oldStatus = True
    newStatus = oldStatus
    issues = []

    # ----------------------------------------------------------
    # 1.5. If Service is NotFound - recreate it
    # ----------------------------------------------------------
    if raw == "NotFound" or raw == "":
        
        # Service is missing, so initial state is bad
        oldStatus = False 

        # Extract required attributes from backupDict for recreation
        expected_path_name = backupDict.get("PathName", "")
        expected_display_name = backupDict.get("DisplayName", service_name)
        expected_start_type = backupDict.get("StartType", "auto").lower()
        expected_start_name = backupDict.get("StartName", "LocalSystem")
        
        # Format dependencies for sc.exe: list of services separated by '/'
        dependencies_str = "/".join(backupDict.get("Dependencies", []))

        # Check for minimum required attributes for creation
        if not expected_path_name:
            issues.append(f"Service {service_name} was MISSING, FAILED to create (PathName not in backupDict).")
            return oldStatus, False, issues

        # Construct the sc.exe create command
        # Note: 'binpath=' and 'obj=' are required for creation.
        ps_create = fr"""
        sc.exe create "{service_name}" ^
            binpath= "{expected_path_name}" ^
            displayname= "{expected_display_name}" ^
            start= {expected_start_type} ^
            obj= "{expected_start_name}" ^
            depend= "{dependencies_str}"
        """
        
        if DISARM:
            issues.append(f"Service {service_name} was MISSING, DISARMED. (Would attempt to create it.)")
            return oldStatus, False, issues 
        else:
            if run_powershell(ps_create):
                issues.append(f"Service {service_name} was MISSING, RESTORED by creating the service.")
                # After creation, the service is present and attributes are set from backupDict
                return oldStatus, True, issues 
            else:
                issues.append(f"Service {service_name} was MISSING, FAILED to create service.")
                return oldStatus, False, issues 

    # --- Continue to attribute checks if service was found ---

    # Parse the JSON result
    try:
        data = json.loads(raw)
    except:
        return False, False, [f"FAILED to get integrity information for service {service_name}, PowerShell JSON parse error. Raw: {raw[:50]}..."]

    current_start_name = data.get("StartName", "")
    current_path_name  = data.get("PathName", "")
    current_dependencies = data.get("Dependencies", [])

    expected_start_name = backupDict.get("StartName", "").strip()
    expected_path_name  = backupDict.get("PathName", "").strip()
    expected_dependencies = backupDict.get("Dependencies", [])
    
    # Normalize and sort dependencies for comparison
    current_dependencies_sorted = sorted([d.lower() for d in current_dependencies])
    expected_dependencies_sorted = sorted([d.lower() for d in expected_dependencies])

    # Re-evaluate initial state (in case any check below fails)
    if (current_start_name != expected_start_name) or \
       (current_path_name.lower().strip() != expected_path_name.lower().strip()) or \
       (current_dependencies_sorted != expected_dependencies_sorted):
        oldStatus = False

    # ----------------------------------------------------------
    # 2. If PathName is incorrect - restore it
    # ----------------------------------------------------------
    if current_path_name.lower().strip() != expected_path_name.lower().strip():
        # NOTE: PathName/binPath change requires the service to be STOPPED first.
        ps_path_fix = fr"""
        Stop-Service -Name '{service_name}' -Force -ErrorAction SilentlyContinue | Out-Null
        sc.exe config "{service_name}" binPath= "{expected_path_name}"
        Start-Service -Name '{service_name}' -ErrorAction SilentlyContinue | Out-Null
        """

        if DISARM:
            issues.append(f"Service {service_name} PathName ('{current_path_name}') is incorrect, DISARMED. (Expected: {expected_path_name})")
        else:
            if run_powershell(ps_path_fix):
                issues.append(f"Service {service_name} PathName from ('{current_path_name}') to {expected_path_name} restored. Service stopped/restarted.")
                newStatus = True
            else:
                issues.append(f"Service {service_name} PathName from ('{current_path_name}') to {expected_path_name} restoration FAILED.")
                
    # ----------------------------------------------------------
    # 3. If StartName is incorrect - restore it
    # ----------------------------------------------------------
    if current_start_name != expected_start_name:
        
        # Only support built-in accounts without needing a password parameter
        ps_start_name_fix = None
        if expected_start_name in ("LocalSystem", "NT AUTHORITY\\LocalSystem"):
             # For built-in accounts, password is set to an empty string
             ps_start_name_fix = fr"""sc.exe config "{service_name}" obj= "LocalSystem" password= "" """
        elif expected_start_name in ("LocalService", "NT AUTHORITY\\LocalService"):
             ps_start_name_fix = fr"""sc.exe config "{service_name}" obj= "NT AUTHORITY\LocalService" password= "" """
        
        if ps_start_name_fix is None:
            issues.append(f"Service {service_name} StartName ('{current_start_name}') is incorrect, expected '{expected_start_name}'. RESTORE IMPOSSIBLE (user account password needed).")
        else:
            if DISARM:
                issues.append(f"Service {service_name} StartName ('{current_start_name}') is incorrect, DISARMED. (Expected: {expected_start_name})")
            else:
                if run_powershell(ps_start_name_fix):
                    issues.append(f"Service {service_name} StartName ('{current_start_name}') restored to '{expected_start_name}'.")
                    newStatus = True
                else:
                    issues.append(f"Service {service_name} StartName ('{current_start_name}') restoration FAILED. (Expected: {expected_start_name})")


    # ----------------------------------------------------------
    # 4. If Dependencies are incorrect - restore them
    # ----------------------------------------------------------
    if current_dependencies_sorted != expected_dependencies_sorted:
        
        # Format the expected list into a slash-separated string for sc.exe
        dependency_list_str = "/".join(expected_dependencies)

        # NOTE: Changing Dependencies requires the service to be STOPPED first.
        ps_dep_fix = fr"""
        Stop-Service -Name '{service_name}' -Force -ErrorAction SilentlyContinue | Out-Null
        sc.exe config "{service_name}" depend= "{dependency_list_str}"
        Start-Service -Name '{service_name}' -ErrorAction SilentlyContinue | Out-Null
        """

        if DISARM:
            issues.append(f"Service {service_name} Dependencies are incorrect, DISARMED. (Expected: {expected_dependencies}) (Actual: {current_dependencies_sorted})")
        else:
            if run_powershell(ps_dep_fix):
                issues.append(f"Service {service_name} Dependencies restored to '{expected_dependencies}'. Service stopped/restarted. Old bad dependencies: {current_dependencies_sorted}")
                newStatus = True
            else:
                issues.append(f"Service {service_name} Dependencies restoration FAILED. Old bad dependencies: {current_dependencies_sorted}. Current dependencies: {expected_dependencies}")

    return oldStatus, newStatus, issues

def service_integrity_linux(service_name, backupDict):
    """
    Given the name of a systemd service, check its attributes against a dict of 
    known good attributes and report required remediation.

    backupDict must contain:
    - "ExecStart": The expected executable path (e.g., "/usr/sbin/sshd -D")
    - "User": The expected user account (e.g., "root")
    - "Requires" / "After": Expected list of dependent service names (e.g., ["network.target"])
    - "StartType": The service startup type (e.g., "enabled", "disabled") - checked elsewhere, but included for completeness.

    NOTE: Linux remediation for integrity (PathName/User) is complex (modifying unit files)
    and is only reported as an issue here, not automatically fixed.

    Returns: oldStatus(bool), newStatus(bool), issues(list of strings)
    """
    return True, True, []
    oldStatus = True
    newStatus = True
    issues = []
    
    # 1. Check service existence and get current attributes
    show_cmd = f"systemctl show --no-pager {service_name}"
    raw = run_bash(show_cmd).strip()

    # Check for Not Found case
    if "not-found" in raw.lower() or not raw:
        oldStatus = False
        newStatus = False
        issues.append(f"ServiceNotFound for service {service_name}.")
        # NOTE: Recreation logic is omitted due to complexity (installing package is preferred method)
        return oldStatus, newStatus, issues

    # Parse key attributes from systemctl output
    current_attrs = {}
    for line in raw.splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            # Map systemd fields to Windows backupDict fields for internal comparison
            if key == "ExecStart":
                # systemd gives the full ExecStart line, including the path and args
                current_attrs["ExecStart"] = value.split('=', 1)[-1].strip() # Get the command part
            elif key == "User":
                current_attrs["User"] = value
            elif key == "Requires":
                # Requires are space-separated; we use lowercase and sort for comparison
                current_attrs["Requires"] = sorted([d.lower() for d in value.split()])
    
    # Map backupDict to expected systemd attributes
    expected_exec_start = backupDict.get("ExecStart", "").strip()
    expected_user = backupDict.get("User", "").strip()
    # Normalize expected dependencies
    expected_dependencies = backupDict.get("Dependencies", [])
    if isinstance(expected_dependencies, str):
        expected_dependencies = ast.literal_eval(expected_dependencies)
    expected_dependencies = sorted([d.lower() for d in backupDict.get("Dependencies", [])])
    
    
    # 2. Integrity Checks (Audit)
    
    # Check 1: Executable Path/Command (Windows PathName -> Linux ExecStart)
    current_exec_start = current_attrs.get("ExecStart", "").strip()
    if current_exec_start.lower() != expected_exec_start.lower():
        oldStatus = False
        
        issue_msg = f"ExecStart (PathName) is incorrect. Current: '{current_exec_start}', Expected: '{expected_exec_start}'."
        issues.append(issue_msg)
        
        # Remediation for Linux is complex (requires modifying the unit file)
        if not DISARM:
            issues.append("-> Remediation failed: Cannot automatically modify systemd unit file.")
            newStatus = False

    # Check 2: User Account (Windows StartName -> Linux User)
    current_user = current_attrs.get("User", "").strip()
    if current_user.lower() != expected_user.lower():
        oldStatus = False
        
        issue_msg = f"User (StartName) is incorrect. Current: '{current_user}', Expected: '{expected_user}'."
        issues.append(issue_msg)
        
        if not DISARM:
            issues.append("-> Remediation failed: Cannot automatically modify systemd unit file for User.")
            newStatus = False

    # Check 3: Dependencies (Windows Dependencies -> Linux Requires/After)
    current_dependencies = current_attrs.get("Requires", [])
    if current_dependencies != expected_dependencies:
        oldStatus = False
        
        issue_msg = f"Dependencies (Requires/After) are incorrect. Current: {current_dependencies}, Expected: {expected_dependencies}."
        issues.append(issue_msg)
        
        if not DISARM:
            # Unlike Windows, systemd dependencies can often be changed dynamically without a reboot
            # However, the audit only shows REQUIRED dependencies, not all configured ones.
            # Automated fixing is avoided for safety.
            issues.append("-> Remediation failed: Cannot automatically modify systemd unit file for Dependencies.")
            newStatus = False
            
    if DISARM and not oldStatus:
         issues.append("Integrity check failed, DISARMED. No restoration attempted.")

    return oldStatus, newStatus, issues

def service_backup(service):
    """
    Wrapper for OS-specific service_backup* functions

    Given the name of a Windows service, create a backupDict as used in service_integrity()
    
    Returns: backupDict(dict)
    """
    system = platform.system()

    if system == "Windows":
        return service_backup_windows(service)
    else:
        return {}
        #service_backup_linux(service)
        #return None # TODO

def service_backup_windows(service_name):
    """
    Queries the local Windows system for the current configuration of a service
    and returns a backup dictionary.

    Args:
        service_name (str): The name of the Windows service (e.g., 'Dnscache').

    Returns:
        dict: A backup dictionary containing the service's current attributes, 
              or None if the service is not found or an error occurs.
    """
    
    # PowerShell command to query all required attributes using Win32_Service
    ps_query = fr"""
    $svc = Get-CimInstance Win32_Service -Filter "Name='{service_name}'" -ErrorAction SilentlyContinue
    if ($svc -eq $null) {{
        Write-Output 'NotFound'
    }} else {{
        $obj = New-Object PSObject -Property @{{
            PathName = $svc.PathName
            StartName = $svc.StartName
            Dependencies = $svc.DependsOn
            DisplayName = $svc.DisplayName
            StartType = $svc.StartMode
        }}
        $obj | ConvertTo-Json
    }}
    """
    
    raw = run_powershell(ps_query).strip()
    
    if not raw or raw == "NotFound":
        print(f"[ERROR] Service '{service_name}' not found or PowerShell error during query.")
        return None

    # Parse the JSON result
    try:
        data = json.loads(raw)
        
        # Ensure StartType is lowercased to match the expected format ('auto', 'manual', 'disabled')
        data['StartType'] = data['StartType'].lower()
        
        # Ensure Dependencies is a list, even if it's null (PowerShell often returns null for no dependencies)
        if data['Dependencies'] is None:
            data['Dependencies'] = []
            
        return data
        
    except Exception as e:
        print(f"[ERROR] Failed to parse JSON configuration for '{service_name}': {e}")
        return None

def service_backup_linux(service_name):
    """
    Queries the local systemd configuration for a service and returns a backup dictionary,
    mapping systemd attributes to the Windows backup keys.

    Args:
        service_name (str): The name of the systemd unit (e.g., 'sshd.service').

    Returns:
        dict: A backup dictionary containing the service's current attributes, 
              or None if the service is not found or an error occurs.
    """
    
    # 1. Use systemctl show to get detailed unit properties
    # --no-pager ensures clean output, and -p allows selecting specific properties,
    # but querying all and parsing is often simpler.
    systemctl_show_cmd = f"systemctl show --no-pager {service_name}"
    raw = run_bash(systemctl_show_cmd).strip()

    # Check for service existence/query success
    if not raw or "not-found" in raw.lower():
        print_debug(f"[ERROR] Service '{service_name}' not found or systemctl error during query.")
        return None

    # 2. Parse the output
    systemd_attrs = {}
    for line in raw.splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            systemd_attrs[key] = value

    # 3. Get UnitFileState separately (Enabled/Disabled/Static)
    # This determines the startup type.
    systemctl_enabled_cmd = f"systemctl is-enabled {service_name}"
    enable_state = run_bash(systemctl_enabled_cmd, noisy=True).strip().lower()
    
    # 4. Map systemd attributes to Windows backup keys
    
    # ExecStart contains the path and arguments, which is equivalent to PathName
    exec_start_line = systemd_attrs.get("ExecStart", "")
    
    # systemd ExecStart is usually formatted as: ExecStart={path}{args}
    # We strip the leading "ExecStart=" and quotes if present.
    if exec_start_line:
        path_name = exec_start_line.split('=', 1)[-1].strip()
    else:
        path_name = ""
        
    # Dependencies: Windows uses DependsOn; systemd uses Requires, Wants, After, etc.
    # We will use the 'Requires' list as the core dependency set.
    # systemd dependencies are space-separated strings.
    requires_str = systemd_attrs.get("Requires", "")
    dependencies = [dep for dep in requires_str.split() if dep]

    # StartName: Windows uses the service account; systemd uses User/Group
    # We'll use the User field as the primary equivalent.
    start_name = systemd_attrs.get("User", "root") # Defaulting to root if User is not explicitly set (common for system services)
    
    # DisplayName: Systemd uses Description
    display_name = systemd_attrs.get("Description", service_name)

    # StartType: Windows uses Auto/Manual/Disabled; systemd uses Enabled/Disabled/Static
    if enable_state == "enabled":
        start_type = "auto"
    elif enable_state in ["disabled", "static"]:
        start_type = "disabled"
    else:
        # Catch for 'manual' equivalent or unknown state
        start_type = "manual" 

    backup_dict = {
        "PathName": path_name,                # Linux: ExecStart command/path
        "StartName": start_name,              # Linux: User running the service
        "Dependencies": dependencies,         # Linux: Requires dependencies (subset of all dependencies)
        "DisplayName": display_name,          # Linux: Description
        "StartType": start_type.lower()       # Linux: Based on systemctl is-enabled
    }

    return backup_dict

def service_lastrun(service):
    """
    Wrapper for OS-specific service_lastrun* functions

    Given the name of a Windows service, detect if it is running. If not, get the last error message and return it

    Returns: Returns: oldStatus(bool), newStatus(bool), issues(list of strings)
    """
    system = platform.system()

    if system == "Windows":
        return service_lastrun_windows(service)
    else:
        return service_lastrun_linux(service)
        #return False, False, [f"service_lastrun(): not implemented for system {system}."] # TODO

def service_lastrun_windows(service_name):
    """
    Given the name of a Windows service, detect if it is running. If not, get the last error message and return it

    Returns: Returns: oldStatus(bool), newStatus(bool), issues(list of strings)
    """
    
    oldStatus = True  # Assume running (good state) initially
    newStatus = True  # Since we are not attempting a fix, newStatus = oldStatus unless an issue is found
    issues = []

    # 1. Check whether service exists and get its current state (Status)
    ps_check = fr"""
    $svc = Get-Service -Name '{service_name}' -ErrorAction SilentlyContinue
    if ($svc -eq $null) {{
        Write-Output 'NotFound'
    }} else {{
        $obj = New-Object PSObject -Property @{{
            Status = $svc.Status
        }}
        $obj | ConvertTo-Json
    }}
    """

    raw = run_powershell(ps_check).strip()
    
    if not raw:
        oldStatus = False
        newStatus = False
        issues.append(f"FAILED to get status information for service {service_name}, PowerShell error.")
        return oldStatus, newStatus, issues

    # Case: Service not found
    if raw == "NotFound" or raw == "":
        oldStatus = False
        newStatus = False
        issues.append(f"Status Check: ServiceNotFound {service_name}.")
        return oldStatus, newStatus, issues

    # Parse the JSON result
    try:
        data = json.loads(raw)
    except:
        oldStatus = False
        newStatus = False
        issues.append(f"FAILED to get status information for service {service_name}, PowerShell JSON parse error.")
        return oldStatus, newStatus, issues

    current_status = data.get("Status", "Unknown")

    # ----------------------------------------------------------
    # 2. If the service is running, return OK status
    # ----------------------------------------------------------
    if current_status == "Running":
        return oldStatus, newStatus, issues

    # The service is NOT running (bad state)
    oldStatus = False
    newStatus = False 

    # ----------------------------------------------------------
    # 3. If the service is NOT running, get its last exit code
    # ----------------------------------------------------------
    
    ps_exit_code_query = fr"sc.exe qc {service_name}"
    qc_output = run_powershell(ps_exit_code_query, noisy=True)

    if not qc_output:
        issues.append(f"Service Status: {current_status}. FAILED to query exit codes via sc.exe.")
        return oldStatus, newStatus, issues

    # Use regular expressions to extract the exit codes
    win32_match = re.search(r"WIN32_EXIT_CODE\s+:\s+(\d+)", qc_output, re.IGNORECASE)
    service_match = re.search(r"SERVICE_EXIT_CODE\s+:\s+(\d+)", qc_output, re.IGNORECASE)

    win32_code = int(win32_match.group(1)) if win32_match else -1
    service_code = int(service_match.group(1)) if service_match else -1

    # Analyze the codes
    if win32_code == 0:
        analysis_message = f"Service Status: {current_status}. Last stop was **clean** (WIN32_EXIT_CODE: 0)."
    elif win32_code == 1066:
        analysis_message = f"Service Status: {current_status}. Last stop was due to a **Service-Specific Error Code**: {service_code} (WIN32_EXIT_CODE: 1066)."
    elif win32_code != -1:
        analysis_message = f"Service Status: {current_status}. Last stop was due to **System Error Code**: {win32_code}."
    else:
        analysis_message = f"Service Status: {current_status}. Could not determine the last exit reason (Codes unavailable)."
        
    issues.append(analysis_message)
        
    return oldStatus, newStatus, issues

def service_lastrun_linux(service_name):
    """
    Given the name of a systemd service, detects if it is running (active). 
    If not, it retrieves the last exit code or error message from the system journal.

    Args:
        service_name (str): The name of the systemd unit (e.g., 'httpd.service').

    Returns: 
        tuple: (oldStatus, newStatus, issues)
               oldStatus (bool): True if the service was initially OK (active).
               newStatus (bool): Equals oldStatus, as no remediation is attempted.
               issues (list of strings): Last exit code/error message if stopped, or not found.
    """
    oldStatus = True  # Assume running (good state) initially
    newStatus = True  
    issues = []

    # 1. Check service existence and active status
    
    # systemctl is-active returns 'active' and exit code 0 if running, or another state/exit code > 0 if not.
    systemctl_active_cmd = f"systemctl is-active {service_name}"
    current_status = run_bash(systemctl_active_cmd, noisy=True).strip()
    
    # Check if the service exists at all
    systemctl_check = run_bash(f"systemctl status {service_name}", noisy=True)
    
    if "not-found" in systemctl_check.lower():
        oldStatus = False
        newStatus = False
        issues.append(f"Status Check: ServiceNotFound {service_name}.")
        return oldStatus, newStatus, issues
        
    # 2. If the service is running, return OK status
    if current_status == "active":
        return oldStatus, newStatus, issues

    # The service is NOT running (bad state)
    oldStatus = False
    newStatus = False 

    # 3. If the service is NOT running, get its last failure information
    
    # A. Get the last recorded exit code via systemctl show
    show_cmd = f"systemctl show --no-pager {service_name}"
    show_output = run_bash(show_cmd, noisy=True)
    
    exit_code = "N/A"
    
    # Parse the output to extract key parameters
    data = {}
    for line in show_output.splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            data[key] = value

    main_pid = data.get("MainPID", "0")
    if main_pid == "0":
        # If MainPID is 0, the service is not running. Check the exit code.
        exit_code_raw = data.get("ExecMainCode", data.get("ExecStopCode", None))
        if exit_code_raw is not None:
             exit_code = exit_code_raw

    # B. Get the last few lines of the system journal for the service
    # -u unit: specifies the service unit
    # -n 5: last 5 lines
    # --no-pager: prevent pager
    journal_cmd = f"journalctl -u {service_name} -n 5 --no-pager"
    journal_output = run_bash(journal_cmd, noisy=True).strip()

    analysis_message = f"Service {service_name} Status: {current_status}."
    
    # Check for specific failure states
    if current_status == "failed":
        analysis_message += " Service transitioned to a FAILED state."

    analysis_message += f" Last known exit code: {exit_code}."

    issues.append(analysis_message)
    
    #if journal_output:
    #    issues.append("--- Last 5 Journal Entries ---")
    #    issues.extend(journal_output.splitlines())
    #else:
    #    issues.append("Could not retrieve journal entries (check permissions or log retention).")
        
    return oldStatus, newStatus, issues

def service_main(services,packages,service_backups):
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
        """
        result_oldStatus, result_newStatus, result_issues = service_uninstall(service,package)
        if not result_oldStatus:
            oldStatus = False
        if not result_newStatus:
            newStatus = False
        for issue in result_issues:
            issues.append(issue)
        """

        # Check for service integrity
        try:
            result_oldStatus, result_newStatus, result_issues = service_integrity(service,SERVICE_BACKUPS[service])
            if not result_oldStatus:
                oldStatus = False
            if not result_newStatus:
                newStatus = False
            for issue in result_issues:
                issues.append(issue)
        except KeyError:
            print_debug(f"service_main(): no backup data available for {service}")

        # Check if service is running/enabled
        result_oldStatus, result_newStatus, result_issues = service_audit(service)
        if not result_oldStatus:
            oldStatus = False
        if not result_newStatus:
            newStatus = False
        for issue in result_issues:
            issues.append(issue)

        # Check service last run status
        result_oldStatus, result_newStatus, result_issues = service_lastrun(service)
        if not result_oldStatus:
            oldStatus = False
        if not result_newStatus:
            newStatus = False
        for issue in result_issues:
            issues.append(issue)

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
### Windows Service #####
#region##################

"""
class MyService(win32serviceutil.ServiceFramework):
    _svc_name_ = f"Stabvest_{AGENT_NAME}"
    _svc_display_name_ = f"Stabvest_{AGENT_NAME}"

    def __init__(self, args):
        super().__init__(args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.stop_event)

    def SvcDoRun(self):
        servicemanager.LogInfoMsg("Service starting...")
        
        thread = threading.Thread(target=main, args=(self.stop_event,), daemon=True)
        thread.start()
        
        self.ReportServiceStatus(win32service.SERVICE_RUNNING)
        
        win32event.WaitForSingleObject(self.stop_event, win32event.INFINITE)
        
        self.ReportServiceStatus(win32service.SERVICE_STOPPED)
        servicemanager.LogInfoMsg("Service stopped.")
        servicemanager.LogInfoMsg("Service starting...")
        self.ReportServiceStatus(win32service.SERVICE_RUNNING)
        
        try:
            main(stop_event=self.stop_event)
        except Exception as e:
            servicemanager.LogErrorMsg(str(e))
        finally:
            self.ReportServiceStatus(win32service.SERVICE_STOPPED)
            servicemanager.LogInfoMsg("Service stopped.")
"""

#endregion###############
######### Main ##########
#region##################

def init_int_vars(interface=interface_get_primary()):
    system = platform.system()

    if system == "Windows":
        return init_int_vars_windows(interface)
    else:
        return init_int_vars_linux(interface)
    
def init_int_vars_windows(interface=interface_get_primary()):
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

def init_int_vars_linux(interface):
    """
    Linux version: Reads current IPv4 address, prefix, and gateway for the interface.
    Uses 'ip -j' to parse JSON directly.
    """
    ip_address = None
    prefix = None
    gateway = None

    # 1. Get IP Address and Prefix
    try:
        # 'ip -j addr show' returns a list of dictionaries for each interface
        cmd = ["ip", "-j", "addr", "show", interface]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        addr_data = json.loads(result.stdout)

        if addr_data:
            # Filter for IPv4 (inet) addresses
            ipv4_infos = [addr for addr in addr_data[0].get("addr_info", []) if addr.get("family") == "inet"]
            if ipv4_infos:
                ip_address = ipv4_infos[0].get("local")
                prefix = ipv4_infos[0].get("prefixlen")
    except (subprocess.CalledProcessError, json.JSONDecodeError, IndexError) as e:
        print_debug(f"init_int_vars_linux({interface}): Failed to query IP address. Error: {e}")

    # 2. Get Default Gateway
    try:
        # 'ip -j route show default' shows the default gateway route
        cmd = ["ip", "-j", "route", "show", "default", "dev", interface]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        route_data = json.loads(result.stdout)

        if route_data:
            # The gateway is the 'gateway' or 'via' field
            gateway = route_data[0].get("gateway")
    except (subprocess.CalledProcessError, json.JSONDecodeError, IndexError) as e:
        print_debug(f"init_int_vars_linux({interface}): Failed to query gateway. Error: {e}")

    print_debug(f"init_int_vars_linux({interface}): {ip_address} {prefix} {gateway}")
    return ip_address, prefix, gateway

def test_network():
    # vars
    interface = interface_get_primary() # This needs valid network conf to work
    ip_address,prefix,gateway = init_int_vars()

    # main
    print_debug(f"interface_get_primary(): {interface}")
    #print(f"interface_mtu(): {interface_mtu()}")
    #print(f"interface_ttl(): {interface_ttl()}")
    print_debug(f"interface_main({interface,ip_address,prefix,gateway}): {interface_main(interface,ip_address,prefix,gateway)}")
    #print(f"firewall_rules_audit_windows('81'): {firewall_rules_audit_windows('81')}")
    print_debug(f"firewall_main(['81','82']): {firewall_main(['81','82'])}")

def test_service():
    service = "AxInstSV"
    print_debug(f"service_audit({service}): {service_audit(service)}")

def test_main():
    print_debug(f"get_system_details(): {get_system_details()}")
    #test_network()
    test_service()

def main(stop_event=None):
    # TODO daemon-reload if service file was changed!
    global PAUSED
    ip_address,prefix,gateway = init_int_vars() # TODO

    systemInfo = get_system_details()
    agent_id = hash_id(AGENT_NAME, systemInfo["hostname"], systemInfo["ipadd"], systemInfo["os"])
    repo_url = os.path.join(f"{SERVER_URL}git",f"{agent_id}.git")
    repo_dir = f"{os.path.join(os.path.dirname(os.path(__file__).resolve()),f'{agent_id}.git')}"

    send_message(True,True,f"Register")
    
    setup_git_agent(repo_dir,PROTECTED_FOLDERS) # todo works for multiple folders

    #test_main()
    #return

    oldStatus = True
    newStatus = True
    oldIssues = []
    newIssues = []

    for service in SERVICES:
        try:
            if not SERVICE_BACKUPS[service]:
                SERVICE_BACKUPS[service] = service_backup(service)
        except KeyError:
                SERVICE_BACKUPS[service] = service_backup(service)

    print_debug(f"main(): System details - {get_system_details()}")

    while True:
        oldStatus = True
        newStatus = True

        pausedEpochServer = get_pause_state_server()

        pausePreferServer, pausedStatus, pausedEpochLocal = get_pause_status()

        if pausedEpochServer != -1:
            if pausedEpochServer == 0:
                # Server thinks client should be active but doesn't really care
                if pausePreferServer:
                    with open(STATUSFILE,"w") as f:
                        f.write(f"true\n0\n")
                    pausedStatus = False
                    pausedEpochLocal = 0
            else:
                if pausedEpochServer == 1:
                    # Force resume
                    with open(STATUSFILE,"w") as f:
                        f.write(f"{pausePreferServer}\n0\n")
                    pausedStatus = False
                    pausedEpochLocal = 0
                else:
                    # Server thinks client should be in a paused state until pausedEpochServer epoch time
                    # This does hold a binding effect as otherwise the server PAUSE function doesnt work
                    with open(STATUSFILE,"w") as f:
                        f.write(f"{pausePreferServer}\n{pausedEpochServer}\n")
                    pausedStatus = True
                    pausedEpochLocal = pausedEpochServer

        sent_msg = False
        suppressed_send = False
        
        if PAUSED != pausedStatus:
            PAUSED = pausedStatus
            
            if PAUSED:
                # Send alert if agent is freshly moving into PAUSED state
                suppressed_send = True
                send_message(False,False,f"Agent moved into PAUSE status for {int(pausedEpochLocal - time.time())} seconds")
            else:
                send_message(True,True,f"Agent moved into ACTIVE status (from PAUSE)")

        if not PAUSED:

            # Firewall
            print_debug(f"main(): running firewall checks")
            result_oldStatus, result_newStatus, result_issues = firewall_main(PORTS)
            if not result_oldStatus:
                oldStatus = False
            if not result_newStatus:
                newStatus = False
            for issue in result_issues:
                newIssues.append(f"Firewall - {issue}")
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
                newIssues.append(f"Interface - {issue}")
                print_debug(newIssues[-1])
                if newIssues[-1] not in oldIssues:
                    send_message(result_oldStatus,result_newStatus,newIssues[-1])
                    sent_msg = True
                else:
                    suppressed_send = True

            # Service
            print_debug(f"main(): running service checks")
            result_oldStatus, result_newStatus, result_issues = service_main(SERVICES,PACKAGES,SERVICE_BACKUPS)
            if not result_oldStatus:
                oldStatus = False
            if not result_newStatus:
                newStatus = False
            for issue in result_issues:
                newIssues.append(f"Service - {issue}")
                print_debug(newIssues[-1])
                if newIssues[-1] not in oldIssues:
                    send_message(result_oldStatus,result_newStatus,newIssues[-1])
                    sent_msg = True
                else:
                    suppressed_send = True

            # Files
            print_debug(f"main(): running file checks")
            result_issues_main = []
            #for protected_folder in PROTECTED_FOLDERS:
            result_oldStatus, result_newStatus, result_issues = file_protect_main(repo_dir,PROTECTED_FOLDERS)
            if not result_oldStatus:
                oldStatus = False
            if not result_newStatus:
                newStatus = False
            for issue in result_issues:
                result_issues_main.append(f"{issue}")
            for issue in result_issues_main:
                newIssues.append(f"File - {issue}")
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
            
            print_debug(f"main(): sleeping for {SLEEPTIME} seconds")
            print_debug(f"")

            oldIssues = newIssues
            newIssues = []
        else:
            if not suppressed_send:
                # Do not trigger alert
                send_message(True,False,f"Agent still in PAUSE status for {int(pausedEpochLocal - time.time())} seconds remaining")
        
        # SERVICE-SAFE SLEEP for windows service
        """
        system = platform.system()
        if system == "Windows":
            if len(sys.argv) > 1:
                for _ in range(sleeptime):
                    if stop_event is not None:
                        if win32event.WaitForSingleObject(stop_event, 0) == win32event.WAIT_OBJECT_0:
                            print_debug("Service stop requested during sleep.")
                            return
                    time.sleep(1)
            else:
                time.sleep(sleeptime)
        else:
            time.sleep(sleeptime)
        """
        time.sleep(SLEEPTIME)

if __name__ == "__main__":

    """
    system = platform.system()

    if system == "Windows":
        if len(sys.argv) == 1:
            servicemanager.Initialize()
            servicemanager.PrepareToHostSingle(MyService)
            servicemanager.StartServiceCtrlDispatcher()
        else:
            win32serviceutil.HandleCommandLine(MyService)

        if len(sys.argv) > 1:
            # related to interacting as windows service
            win32serviceutil.HandleCommandLine(MyService)
        else:
            # Normal execution
            main()
    else:
        main()
    """
    main()

#endregion###############