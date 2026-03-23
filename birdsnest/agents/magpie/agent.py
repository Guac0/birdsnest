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
import sys
import signal
import hashlib
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
    "SERVER_URL": "https://127.0.0.1:8000/",
    "SERVER_TIMEOUT": 5,
    "SLEEPTIME": 60,
    "DISARM": True,
    "IPTABLES_PATH": "iptables",
    "PORTS": [81],
    "SERVICES": ["AxInstSV"],
    "PACKAGES": [""],
    "SERVICE_BACKUPS": {},
    #"SERVICE_BACKUPS": {
    #    "PathName": "C:\\\\Windows\\\\system32\\\\svchost.exe -k AxInstSVGroup",
    #    "StartName": "LocalSystem",
    #    "Dependencies": [],
    #    "DisplayName": "ActiveX Installer (AxInstSV)",
    #    "StartType": "Manual"
    #},
    "PROTECTED_FOLDERS": ["var/www"],
    "DEBUG_PRINT": True,
    "BACKUPDIR": "",
    "LOGFILE": "log.txt",
    "STATUSFILE": "status.txt",
    "MTU_MIN": 1200,
    "MTU_DEFAULT": 1300,
    "MTU_MAX": 1514,
    "LINUX_DEFAULT_TTL": 64,
    "AGENT_TYPE": "magpie"
}

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
        # On linux systems, equivalent functionality is achieved by just protecting the service file with the file protection functionality.

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
    ps_query = r"""
    $svc = Get-CimInstance Win32_Service -Filter "Name='{service_name}'" -ErrorAction SilentlyContinue
    if ($svc -eq $null) { 
        Write-Output 'NotFound'
    }  else { 
        $obj = New-Object PSObject -Property @{ 
            PathName = $svc.PathName
            StartName = $svc.StartName
            Dependencies = $svc.DependsOn
            DisplayName = $svc.DisplayName
            StartType = $svc.StartMode
        } 
        $obj | ConvertTo-Json
    } 
    """.format(service_name=service_name)
    
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
                HOST=config.get("SERVER_URL").split(":")[-1],
                PORT=":".join(config.get("SERVER_URL").split(":")[:-1]),  
                timestamp=timestamp
            )

    if badPath:
        print(f"[-] {timestamp} load_config(): config file path not found: {path}")
        with open(config.get("LOGFILE"), "a") as f: # intentionally not the correct logfile format
            f.write(f"[{timestamp}] CRITICAL - load_config(): config file path not found: {path}")

    #config["PUBLIC_URL"] = f"http://{config['HOST']}:{config['PORT']}"
    #config["LOGFILE"] = f"log_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt"

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

def populate_initial_backups(config, path):
    """
    If SERVICE_BACKUPS is empty, snapshots the current state of listed services
    and saves them back to the config file.
    """
    modified = False
    
    # Check if we have services to protect but no backup data
    if config.get("SERVICES") and not config.get("SERVICE_BACKUPS"):
        print("[+] SERVICE_BACKUPS is empty. Initializing from current system state...")
        new_backups = {}
        
        for svc_name in config["SERVICES"]:
            backup_data = service_backup(svc_name)
            if backup_data:
                new_backups[svc_name] = backup_data
                print(f"    - Snapshotted service: {svc_name}")
        
        if new_backups:
            config["SERVICE_BACKUPS"] = new_backups
            modified = True

    # If we updated the config, write it back to disk to persist the "Known Good" state
    if modified:
        try:
            with open(path, "w") as f:
                json.dump(config, f, indent=4)
            print(f"[+] Initial configuration persisted to {path}")
        except Exception as e:
            print(f"[-] Failed to persist initial config: {e}")

    return config

CONFIG = load_config("config.json") # relative to cwd!
CONFIG = populate_initial_backups(CONFIG, "config.json")
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
    return False, ""

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
    return hashlib.sha256(combined.encode("utf-8")).hexdigest() 

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

def run_bash(cmd, shellStatus=True, noisy=True):
    """
    Run a shell command (using Bash by default) and return stdout text.

    Args:
        cmd (str): The command string to execute.
        noisy (bool): If True, prints error details to stderr.

    Returns:
        subprocess.CompletedProcess: Object containing .returncode, .stdout, and .stderr
    """
    # Note: On most Linux systems, omitting the shell path 
    # lets subprocess use the system's default shell, 
    # which is typically Bash.
    
    # We use 'shell=True' here to allow the command string 'cmd' 
    # to be processed by the shell (e.g., for pipes, redirects, variables).
    # SECURITY NOTE: Using shell=True can be dangerous if the command 
    # string comes from an untrusted source, as it enables shell injection. 
    # Use with caution.
    
    executable_path = shutil.which("bash")
        
    # Fallback to standard sh if bash isn't installed
    if not executable_path:
        for path in ["/usr/local/bin/bash", "/bin/sh", "/usr/bin/sh"]:
            if os.path.exists(path):
                executable_path = path
                break

    try:
        result = subprocess.run(
            cmd,
            shell=shellStatus,
            executable=executable_path,
            capture_output=True, 
            text=True,
            check=False # Do not raise a CalledProcessError on non-zero exit code
        )

        if result.returncode != 0 and noisy:
            print_debug(f"run_bash(): Command failed [{result.returncode}]: {cmd}")
            if result.stderr.strip():
                print_debug(f"    Stderr: {result.stderr.strip()}")
        return result
        
    except Exception as e:
        if noisy:
            print_debug(f"run_bash(): System error executing command: {e}")
        # Return a mock object so calling code doesn't crash on attribute access
        return subprocess.CompletedProcess(args=cmd, returncode=1, stdout="", stderr=str(e))

def run_git(args, cwd):
    """Executes git commands with SSL verification disabled."""
    try:
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
            print_debug(f"Git shell command failed with exit code {result.returncode}. Command: {["git", "-c", "http.sslVerify=false"] + args}")
            if result.stderr.strip():
                print_debug(f"    Git shell stderr: {result.stderr.strip()}")
        return result
    except Exception as e:
        print_debug(f"run_git(): System error executing command ({["git", "-c", "http.sslVerify=false"] + args}): {e}")
        # Return a mock object so calling code doesn't crash on attribute access
        return subprocess.CompletedProcess(args=cmd, returncode=1, stdout="", stderr=str(e))

def setup_git_agent(repo_dir, protected_folders, systemInfo=None):
    """Initializes git config and creates initial 'good' and 'bad' baselines."""
    if systemInfo is None:
        systemInfo = get_system_details()
        
    try:
        # 1. Clone or Init Repo
        if not os.path.exists(repo_dir):
            agent_hash = hash_id(AGENT_NAME, systemInfo["hostname"], systemInfo["ipadd"], systemInfo["os"])
            repo_url = f"{SERVER_URL}agent/git/{agent_hash}.git"
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
        run_git(["commit", "-m", "initialCommitBad"], cwd=repo_dir) #initially fails. TODO clean up.
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
        
def persist_iptables_rules(noisy=True):
    """
    Persists current iptables rules to disk based on the Linux distribution.
    Uses 'service iptables save' for RHEL/CentOS and 'netfilter-persistent' for Debian.
    
    Returns: subprocess completion object
    """
    # 1. Try RHEL/CentOS style (iptables-services)
    if shutil.which("service"):
        # Check if the iptables service is specifically available
        check_svc = run_bash("service iptables status", noisy=False)
        if check_svc.stdout.strip():
            print_debug("Detected RHEL-style iptables; persisting via service...")
            return run_bash("service iptables save", noisy=noisy)

    # 2. Try Debian/Ubuntu style (iptables-persistent)
    if shutil.which("netfilter-persistent"):
        print_debug("Detected Debian-style iptables; persisting via netfilter-persistent...")
        return run_bash("netfilter-persistent save", noisy=noisy)

    # 3. Universal Fallback (Manual Redirection)
    # This requires knowing the OS to pick the right path
    distro = get_platform_dist()[0].lower() # Using your existing helper
    
    path = ""
    if "debian" in distro or "ubuntu" in distro:
        path = "/etc/iptables/rules.v4"
    elif "rhel" in distro or "centos" in distro or "rocky" in distro:
        path = "/etc/sysconfig/iptables"
    
    if path:
        print_debug(f"No manager found. Falling back to manual save to {path}...")
        # Note: run_bash must handle '>' redirection correctly
        return run_bash(f"{IPTABLES_PATH}-save > {path}", noisy=noisy)

    print_debug("Failed to persist: No known persistence method found for this distro.")
    return False


#endregion###############
## Server Comms Funcs ###
#region##################

def send_message(endpoint,oldStatus=True,newStatus=True,message="",systemInfo=get_system_details()):
    """
    Sends the specified data to the server
    Handles the full process and attaching agent name/auth

    Args: message(any)
    Returns: status(Bool)
    """
    global AUTH_TOKEN
    if not SERVER_URL:
        # Server comms are intentionally disabled
        # Maybe redirect to print_debug instead?
        return True
    url = SERVER_URL + endpoint

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
                print_debug(f"send_message({url}): sent msg to server: [{oldStatus,newStatus,message}]")
                response_text = response.read().decode('utf-8')
                if endpoint == "agent/beacon/magpie":
                    if response_text != AUTH_TOKEN:
                        AUTH_TOKEN = response_text
                        print_debug(f"send_message({url}): updating auth token value to new value from server {AUTH_TOKEN}")
                return response_text
            else:
                print_debug(f"send_message({url}): Server error: {response.getcode()}")

    # Error handling
    except urllib.error.HTTPError as e:
        print_debug(f"[send_message({url}): HTTP error: {e.code} {e.reason}")
    except urllib.error.URLError as e:
        print_debug(f"send_message({url}): URL error: {e.reason}")
    except Exception as e:
        # Various requests errors - networking failure or 4xx/5xx code from server
        print_debug(f"send_message({url}): Beacon error: {e}")
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
        return interface_get_primary_linux(get_primary_ip())

def interface_get_primary_windows(ip):
    """
    Gets interface name on linux using "ip" or "ifconfig"
    Returns: interface(String) or None
    """
    query = f"Get-NetIPAddress -IPAddress '{ip}' | Select-Object -ExpandProperty InterfaceAlias"
    # Assuming run_powershell is defined in your project
    output = run_powershell(query).strip()
    return output if output else None

def interface_get_primary_linux(ip):
    """
    Unified getter for Linux (Debian, RHEL, Alpine) and FreeBSD.
    Uses shutil.which to locate binaries dynamically across different distributions.
    """
    system = platform.system()
    
    # --- Strategy 1: Modern 'ip' command (JSON-capable) ---
    if system == "Linux":
        ip_bin = shutil.which("ip")
        if ip_bin:
            # We pass noisy=False because a failure here just means we fall back to ifconfig
            res = run_bash(f"{ip_bin} -j addr", noisy=False)
            
            if res.returncode == 0 and res.stdout.strip():
                try:
                    addr_data = json.loads(res.stdout)
                    for iface in addr_data:
                        for addr in iface.get("addr_info", []):
                            if addr.get("local") == ip:
                                return iface.get("ifname")
                except (json.JSONDecodeError, KeyError) as e:
                    print_debug(f"interface_get_primary_linux(): Failed to parse 'ip -j' output: {e}")
            else:
                print_debug(f"interface_get_primary_linux(): falling back to ifconfig mode as ip binary not found")

    # --- Strategy 2: Legacy 'ifconfig' parsing (Linux/FreeBSD fallback) ---
    ifconfig_bin = shutil.which("ifconfig")
    if ifconfig_bin:
        res = run_bash(ifconfig_bin, noisy=False)
        
        if res.returncode == 0 and res.stdout.strip():
            iface = None
            # Standard regex to find interface names at start of lines
            for line in res.stdout.splitlines():
                header_match = re.match(r"^([a-zA-Z0-9._-]+)[:\s]", line)
                if header_match:
                    iface = header_match.group(1)
                
                # Check if the target IP is associated with the current interface block
                if "inet " in line and ip in line:
                    return iface
        elif res.returncode != 0:
            print_debug(f"interface_get_primary_linux(): ifconfig failed with code {res.returncode} and error {res.stderr.strip()}")
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

def interface_address_windows(interface,ip_address,subnet,gateway):
    """
    Given an interface name, check if its IP address and gateway are set, and restore them from backup if not
    Note: Does NOT determine if ip_address and gateway exist but doesn't match the backup
    
    Args: interface name(string), ip_address(string), subnet(int), gateway(string)
    Returns: oldStatus(bool), newStatus(bool), issues(list of strings)
    """
    issues = []
    query_cmd = fr"Get-NetIPConfiguration -InterfaceAlias '{interface}' | Select-Object IPv4Address, IPv4DefaultGateway | ConvertTo-Json"
    output = run_powershell(query_cmd)
    
    if not output:
        return False, False, [f"Failed to query interface {interface}"]

    try:
        data = json.loads(output)
    except:
        return False, False, [f"JSON parse error for {interface}"]

    has_address = bool(data.get("IPv4Address"))
    has_gateway = bool(data.get("IPv4DefaultGateway"))

    if has_address and has_gateway:
        return True, True, []

    statusFix = True
    if not has_address:
        # Fixed: Removed stray pipe before -IPAddress
        set_ip_cmd = fr"New-NetIPAddress -InterfaceAlias '{interface}' -IPAddress {ip_address} -PrefixLength {subnet}"
        if DISARM:
            issues.append(f"Missing IPv4 Address for {interface}, DISARMED.")
            statusFix = False
        else:
            if not run_powershell(set_ip_cmd):
                statusFix = False
                issues.append(f"Failed to restore {ip_address}/{subnet} on {interface}.")
            else:
                issues.append(f"Restored {ip_address}/{subnet} on {interface}.")

    if not has_gateway:
        set_gw_cmd = fr"New-NetRoute -InterfaceAlias '{interface}' -DestinationPrefix '0.0.0.0/0' -NextHop {gateway}"
        if DISARM:
            issues.append(f"Missing Gateway for {interface}, DISARMED.")
            statusFix = False
        else:
            if not run_powershell(set_gw_cmd):
                statusFix = False
                issues.append(f"Failed to restore gateway {gateway} on {interface}.")
            else:
                issues.append(f"Restored gateway {gateway} on {interface}.")

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

    if addr_output.returncode != 0:
        print_debug(f"interface_address_linux({interface}): Failed to query interface IP (ip addr). Error: {addr_output.stderr.strip()}")
        return False, False, [f"Failed to query interface {interface} (ip addr error).  Error: {addr_output.stderr.strip()}"]
    if route_output.returncode != 0:
        print_debug(f"interface_address_linux({interface}): Failed to query interface IP (default gateway). Error: {route_output.stderr.strip()}")
        return False, False, [f"Failed to query interface {interface} (default gateway error).  Error: {route_output.stderr.strip()}"]

    # 2. Determine if address and gateway exist
    
    # Check for IP address: Look for the specific IP/CIDR in the 'ip addr' output
    # Example output line: inet 192.168.1.100/24 brd 192.168.1.255 scope global dynamic ens192
    cidr = f"{ip_address}/{subnet}"
    # Use re.escape to handle potential regex characters in the IP/CIDR string
    has_address = bool(re.search(fr"inet\s+{re.escape(cidr)}\s+", addr_output.stdout.strip()))

    # Check for Gateway: Look for the specific gateway IP in the 'ip route' output
    # Example output line: default via 192.168.1.1 dev ens192 proto dhcp src 192.168.1.100 metric 100
    has_gateway = bool(re.search(fr"default\s+via\s+{re.escape(gateway)}\s+dev\s+{interface}\s+", route_output.stdout.strip()))
    
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
            res = run_bash(set_ip_cmd)
            if res.returncode != 0:
                status_fix = False
                issues.append(f"Missing IPv4 Address for interface {interface}, FAILED to restore {cidr}. Error: {res.stderr.strip()}")
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
            result = run_bash(set_gw_cmd)
            if result.returncode != 0:
                status_fix = False
                issues.append(f"Missing Gateway Address for interface {interface}, FAILED to restore {gateway}. Error: {result.stderr.strip()}")
            else:
                issues.append(f"Missing Gateway Address for interface {interface}, RESTORED {gateway}.")

    # Re-check status if a fix was attempted
    if status_fix:
        # Re-query IP address and gateway status after attempted fixes
        addr_output_new = run_bash(ip_addr_cmd, noisy=True)
        route_output_new = run_bash(ip_route_cmd, noisy=True)

        if addr_output_new.returncode != 0:
            print_debug(f"interface_address_linux({interface}): Failed to query new interface IP (ip addr). Error: {addr_output_new.stderr.strip()}")
            issues.append(f"Failed to query interface {interface} for checking that fix worked (ip addr error).  Error: {addr_output_new.stderr.strip()}")
            new_status = False
        elif route_output_new.returncode != 0:
            print_debug(f"interface_address_linux({interface}): Failed to query new interface IP (default gateway). Error: {route_output_new.stderr.strip()}")
            issues.append(f"Failed to query interface {interface} for checking that fix worked (default gateway error).  Error: {route_output_new.stderr.strip()}")
            new_status = False
        else:
            has_address_new = bool(re.search(fr"inet\s+{re.escape(cidr)}\s+", addr_output_new.stdout.strip()))
            has_gateway_new = bool(re.search(fr"default\s+via\s+{re.escape(gateway)}\s+dev\s+{interface}\s+", route_output_new.stdout.strip()))
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
    ip_get_mtu = f"ip link show dev {interface}"
    
    output = run_bash(ip_get_mtu)
    if output.returncode != 0:
        return False, False, [f"Failed to query MTU for interface '{interface}' due to shell error - {output.stderr.strip()}"]

    # 2. Parse the MTU value
    # Example output snippet: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc ...
    match = re.search(r"mtu\s+(\d+)\s+", output.stdout.strip())
    
    if not match:
        return False, False, [f"Failed to parse MTU for interface '{interface}'. Output: {output.stdout.strip()}"]

    old_mtu = int(match.group(1))
    
    # 3. Check MTU range
    if old_mtu < mtu_minimum or old_mtu > mtu_maximum:
        new_mtu = mtu_default
        
        ip_set_mtu = f"ip link set dev {interface} mtu {new_mtu}"
        
        if DISARM:
            print_debug(f"DISARMED, but told to update MTU for '{interface}' from {old_mtu} to {new_mtu}")
            return False, False, [f"Interface {interface}'s MTU was set to {old_mtu}, DISARMED."]
        else:
            print_debug(f"Updated MTU for '{interface}' from {old_mtu} to {new_mtu}")
            result = run_bash(ip_set_mtu)
            if result.returncode == 0:
                # 4. Verification (re-query the MTU)
                output_new = run_bash(ip_get_mtu)
                match_new = re.search(r"mtu\s+(\d+)\s+", output_new.stdout.strip())
                
                if match_new and int(match_new.group(1)) == new_mtu:
                    return False, True, [f"Interface {interface}'s MTU was set to {old_mtu}, RESTORED new mtu {new_mtu}."]
                else:
                    return False, False, [f"Interface {interface}'s MTU was set to {old_mtu}, FAILED to verify new mtu {new_mtu}. MTU command stdout: {output_new.stdout.strip()}. MTU command stderr: {output_new.stderr.strip()}"]
            else:
                return False, False, [f"Interface {interface}'s MTU was set to {old_mtu}, FAILED to restore new mtu {new_mtu}. Error: {result.stderr.strip()}"]

    # 5. MTU is within the acceptable range
    return True, True, []

def interface_ttl():
    """
    Wrapper for interface_ttl_*

    Given an interface name, check if its TTL is within an acceptable range and remediate if not
    
    Args: interface name(string)
    Returns: oldStatus(bool), newStatus(bool), issues(list of strings)
    """
    system = platform.system()

    if system == "Windows":
        return interface_ttl_windows()
    else:
        return interface_ttl_linux()

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

    if current_ttl_output.returncode != 0:
        return False, False, [f"Failed to query TTL due to shell error - {current_ttl_output.stderr.strip()}"]
    if current_hl_output.returncode != 0:
        return False, False, [f"Failed to query TTL due to shell error - {current_hl_output.stderr.strip()}"]

    # Convert outputs to integers, default to LINUX_DEFAULT_TTL if query fails or value is missing
    try:
        current_ttl = int(current_ttl_output.stdout.strip())
    except (ValueError, TypeError):
        current_ttl = LINUX_DEFAULT_TTL
    
    try:
        current_hl = int(current_hl_output.stdout.strip())
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
            result = run_bash(set_ttl_cmd, noisy=True)
            if result.returncode == 0:
                issues.append(f"Bad IPv4 TTL ({current_ttl}) detected, RESTORED to {LINUX_DEFAULT_TTL}.")
            else:
                issues.append(f"Bad IPv4 TTL ({current_ttl}) detected, FAILED to restore. Error: {result.stderr.strip()}")
                status_fix = False

    # Remediate IPv6 Hop Limit
    if hl_customized:
        set_hl_cmd = f"sysctl -w {IPV6_HL_PARAM}={LINUX_DEFAULT_TTL}"
        if DISARM:
            issues.append(f"Bad IPv6 Hop Limit ({current_hl}) detected, DISARMED.")
            status_fix = False
        else:
            print_debug(f"Remediating IPv6 Hop Limit from {current_hl} to {LINUX_DEFAULT_TTL}")
            result = run_bash(set_hl_cmd, noisy=True)
            if result.returncode == 0:
                issues.append(f"Bad IPv6 Hop Limit ({current_hl}) detected, RESTORED to {LINUX_DEFAULT_TTL}.")
            else:
                issues.append(f"Bad IPv6 Hop Limit ({current_hl}) detected, FAILED to restore. Error: {result.stderr.strip()}")
                status_fix = False
    
    # 4. Final verification
    new_status = False
    if status_fix:
        # Re-query the values to verify
        new_ttl_output = run_bash(ttl_query_cmd, noisy=True)
        new_hl_output = run_bash(hl_query_cmd, noisy=True)

        if new_ttl_output.returncode != 0:
            issues.append(f"Failed to query TTL due to shell error - {new_ttl_output.stderr.strip()}")
            return False, False, issues
        if new_hl_output.returncode != 0:
            issues.append(f"Failed to query TTL due to shell error - {new_hl_output.stderr.strip()}")
            return False, False, issues

        try:
            new_ttl = int(new_ttl_output.stdout.strip())
            new_hl = int(new_hl_output.stdout.strip())
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

def interface_down_windows(interface=interface_get_primary()):
    """
    Given an interface name, check if it is in the down state and remediate if yes
    
    Args: interface name(string)
    Returns: oldStatus(bool), newStatus(bool), issues(list of strings)
    """

    ps_check = r"""
    $iface = '{interface_name}'
    $int = Get-NetAdapter -Name $iface

    if ($int -eq $null) {
        Write-Output 'NotFound'
    }
    elseif ($int.Status -eq 'Up') {
        Write-Output 'Up'
    }
    else {
        Write-Output 'Down'
    }
    """.format(interface_name=interface)

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
    if interface is None:
        interface = interface_get_primary()
        
    issues = []
    ip_check_cmd = f"ip link show dev {interface}"
    output = run_bash(ip_check_cmd)
    
    if output.returncode != 0:
        return False, False, [f"Interface {interface} could not be queried - {output.stderr.strip()}."]

    # Look specifically for the state in the flags
    is_up = ",UP" in output.stdout.strip() or "<UP" in output.stdout.strip()
    if is_up:
        return True, True, []

    if DISARM:
        return False, False, [f"Interface {interface} is DOWN, DISARMED."]
    
    result = run_bash(f"ip link set dev {interface} up")
    if result.returncode == 0:
        return False, True, [f"Interface {interface} was DOWN, RESTORED UP state."]
    
    return False, False, [f"Interface {interface} was DOWN, FAILED to restore to UP state. Error: {result.stderr.strip()}"]

def interface_uninstall():
    # TODO - Not fully implemented
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
        return False, False, [f"interface_uninstall(): not implemented for system {system}."]

def interface_uninstall_windows(interface_name,ipv4_address,prefix_length,gateway,dns_servers):
    # Heavily vibecoded, just left as a placeholder/idea for now
    """
    Detects whether IPv4 is uninstalled on Windows.
    If uninstalled, reinstalls IPv4.
    Then restores static IPv4 settings (address, gateway, DNS).
    """

    issues = []
    
    # Check if IPv4 is enabled/bound on the adapter
    ps_detect = fr'''
    $bind = Get-NetAdapterBinding -ComponentID "ms_tcpip" -InterfaceAlias "{interface_name}" -ErrorAction SilentlyContinue
    if ($bind.Enabled -eq $true) {{ "Present" }} else {{ "Missing" }}
    '''
    
    ipv4_state = run_powershell(ps_detect).strip()
    old_status = (ipv4_state == "Present")
    
    if not old_status:
        if DISARM:
            issues.append(f"IPv4 binding missing on {interface_name}, DISARMED.")
            return False, False, issues
        
        # Re-enable the binding and reset the stack
        ps_fix = fr'Enable-NetAdapterBinding -ComponentID "ms_tcpip" -InterfaceAlias "{interface_name}"'
        run_powershell(ps_fix)
        issues.append(f"IPv4 binding restored on {interface_name}.")

    # Restore IP configuration using PowerShell (more reliable than netsh for modern OS)
    # We use -ErrorAction SilentlyContinue because if the IP is already there, New-NetIPAddress errors.
    ps_restore = r"""
    $params = @{{
        InterfaceAlias = "{interface_name}"
        IPAddress = "{ipv4_address}"
        PrefixLength = {prefix_length}
        DefaultGateway = "{gateway}"
    }}
    New-NetIPAddress @params -ErrorAction SilentlyContinue
    Set-DnsClientServerAddress -InterfaceAlias "{interface_name}" -ServerAddresses ({",".join([f"'{d}'" for d in dns_servers])})
    """.format(interface_name=interface_name, ipv4_address=ipv4_address, prefix_length=prefix_length, gateway=gateway,dns_servers=dns_servers)
    
    run_powershell(ps_restore)
    issues.append(f"Standard IPv4 configuration applied to {interface_name}.")
    
    return old_status, True, issues

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
    # Drastic and unlikely to be a real break. ignore.
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

    ps_query = r"""
    $rules = Get-NetFirewallPortFilter |
        Where-Object {
            $lp = $_.LocalPort
            if ($lp -eq 'Any') { return $true }
            if ($lp -like '*,*') {
                return $lp.Split(',') -contains '{port}'
            }

            if ($lp -like '*-*') {
                $range = $lp.Split('-')
                $a = [int]$range[0].Trim()
                $b = [int]$range[1].Trim()
                return ({port} -ge [int]$a -and {port} -le [int]$b)
            }

            return $lp -eq '{port}'
        } |
        Get-NetFirewallRule |
        Where-Object { $_.Direction -eq '{direction}' -and $_.Action -eq '{action}' } |
        Select-Object Name, DisplayName, Action, Direction, Profile

    if (-not $rules) {
        "none found"
    } else {
        $rules | ConvertTo-Json
    }
    """.format(port=port, direction=direction, action=action)

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
    Uses iptables -S to audit firewall rules for better reliability across RHEL/Debian.
    """
    issues = []
    matching_rules = []
    
    # Map directions and targets
    chain = "INPUT" if direction.lower() == "in" else "OUTPUT"
    # iptables -S uses the real target names
    targets = ["DROP", "REJECT"] if action.lower() == "block" else ["ACCEPT"]
    
    # 1. Use -S (Select) instead of -L. It is much easier to parse.
    # We still need --line-numbers for deletion, but -S doesn't support them.
    # So we get the clean specs from -S and correlate with -L indices.
    ip_query_cmd = f"{IPTABLES_PATH} -t filter -S {chain}"
    output = run_bash(ip_query_cmd)

    if output.returncode != 0:
        return [f"Error when running firewall rules query command: {output.stderr.strip()}"], []
    if not output.stdout.strip():
        return [f"Firewall rules audit did not output any data despite not erroring."], []

    # 2. Parse rules. Each line looks like: -A INPUT -p tcp -m tcp --dport 80 -j DROP
    for index, line in enumerate(output.stdout.strip().splitlines(), 1):
        if not line.startswith("-A"):
            continue # Skip policy lines like -P INPUT ACCEPT

        parts = line.split()
        
        # Check if Target matches
        try:
            target_index = parts.index("-j") + 1
            rule_target = parts[target_index]
        except (ValueError, IndexError):
            continue

        if rule_target in targets:
            # Check for port specification
            # Look for --dport (inbound) or --sport (outbound)
            port_flag = "--dport" if direction.lower() == "in" else "--sport"
            
            port_spec = ""
            if port_flag in parts:
                port_spec = parts[parts.index(port_flag) + 1]
            
            is_port_match = False
            
            if port_spec:
                # Handle List (80,443)
                if "," in port_spec:
                    if str(port) in port_spec.split(","):
                        is_port_match = True
                # Handle Range (80:90)
                elif ":" in port_spec or "-" in port_spec:
                    sep = ":" if ":" in port_spec else "-"
                    try:
                        start, end = map(int, port_spec.split(sep))
                        if start <= int(port) <= end:
                            is_port_match = True
                    except ValueError:
                        issues.append(f"Warning: Could not parse range {port_spec}")
                # Handle Single Port
                elif port_spec == str(port):
                    is_port_match = True
            
            if is_port_match:
                # Extract protocol
                protocol = "all"
                if "-p" in parts:
                    protocol = parts[parts.index("-p") + 1]

                # Note: We subtract lines that aren't rules to find the real index,
                # but it's more reliable to just use the count of '-A' lines.
                # However, for deletion, we actually need the index from -L --line-numbers.
                # Here we use a simplified version for the audit return.
                rule_dict = {
                    "Chain": chain,
                    "Index": str(index - 1), # Placeholder: deletion should re-verify index
                    "Protocol": protocol,
                    "Action": rule_target,
                    "Direction": direction.upper(),
                    "DisplayName": line,
                    "Rule_Spec": line
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
            
            result = run_bash(delete_cmd)
            if result.returncode == 0:
                # Success (iptables returns empty output on success)
                issues.append(f"SUCCESSFULLY removed firewall rule from {chain} at index #{index}.")
            else:
                # Failure
                issues.append(f"FAILED to remove firewall rule from {chain} at index #{index}. Error: {result.stderr.strip()}")
                overall_status = False

    # 2. Persist the changes (Crucial for iptables)
    if not DISARM:
        if overall_status:
            print_debug("Attempting to persist iptables rules...")
            res = persist_iptables_rules()
            if res.returncode == 0:
                #issues.append("SUCCESS: Running iptables rules saved (persistent).")
                pass
            else:
                issues.append(f"WARNING: FAILED to persist iptables changes. Rule deletion is NOT permanent. Error: {res.stderr.strip()}")
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

def firewall_rules_create_windows(port,direction,action):
    """
    Creates the specified firewall rule on Windows

    Args: Port, Direction (inbound/outbound), Action (allow/block)
    Returns: Status(bool), issues(list of strings)
    """

    rule_name = f"Magpie_Rule_{port}_{direction}_{action}"

    ps_cmd = fr"""
    New-NetFirewallRule -DisplayName "{rule_name}" `
                        -Direction {direction} `
                        -Action {action} `
                        -LocalPort {port} `
                        -Profile Any `
                        -ErrorAction Stop
    """

    if DISARM:
        #print_debug(f"firewall_rules_create_windows(): DISARMED, but told to create Magpie_Rule_{port}_{direction}_{action}")
        return False, [f"DISARMED, but told to create firewall rule Magpie_Rule_{port}_{direction}_{action}"] # TODO do naming scheme as a config option
    if run_powershell(ps_cmd):
        return True, [f"SUCCESSFULLY created firewall rule Magpie_Rule_{port}_{direction}_{action}"]
    else:
        return False, [f"FAILED to create firewall rule Magpie_Rule_{port}_{direction}_{action}"]

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
        result = run_bash(iptables_cmd)
        if result.returncode == 0:
            issues.append(f"SUCCESSFULLY created firewall rule: {rule_description} (running kernel).")
            
            # 4. Persist the change (Crucial for iptables)
            #persist_cmd = f"{IPTABLES_PATH}-save > {IPTABLES_SAVE_PATH}"
            
            print_debug("Attempting to persist iptables rules...")
            res = persist_iptables_rules()
            if res.returncode == 0:
                #issues.append("SUCCESS: Running iptables rules saved to disk (persistent).")
                return False, issues
            else:
                issues.append(f"FAILED to persist iptables changes. Rule is NOT permanent across reboots. Error: {res.stderr.strip()}")
                return False, issues
        else:
            return False, [f"FAILED to create firewall rule: {rule_description}. Error: {result.stderr.strip()}"]
    
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

    if output.returncode != 0:
        # This typically means iptables is not running or a permission error
        return False, False, [f"Failed to load iptables policy for {chain}. Error: {output.stderr.strip()}"]
    if not output.stdout.strip():
        return False, False, [f"Failed to load iptables policy for {chain}. No data returned despite not erroring."]

    # 3. Parse the policy
    # Expected output format: -P INPUT ACCEPT [0:0] or -P INPUT DROP [0:0]
    policy_regex = re.compile(fr"^-P\s+{chain}\s+(?P<action>ACCEPT|DROP|REJECT)(?:\s+\[\d+:\d+\])?")
    
    match = policy_regex.search(output.stdout.strip())
    
    if not match:
        return False, False, [f"Failed to parse iptables policy for {chain}. Unexpected output (regex failed): {output.stdout.strip()}"]

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
            subprocess.run(["attrib", "-R", "-S", "-H", target_path, "/S", "/D"], capture_output=True)
        else:
            if platform.system() in ["FreeBSD", "Darwin"]:
                subprocess.run(["chflags", "-R", "noschg", target_path], capture_output=True)
            else:
                # chattr is specific to ext2/3/4; ignore errors on other FS (like XFS on RHEL)
                subprocess.run(["chattr", "-R", "-i", target_path], capture_output=True)
    except Exception:
        pass

    # 2. Apply Access Permissions
    if is_windows:
        cmds = [
            ["icacls", target_path, "/reset", "/T", "/C"],
            ["icacls", target_path, "/grant:r", "*S-1-5-32-544:(OI)(CI)F", "/T", "/C"], # Administrators SID
            ["icacls", target_path, "/grant:r", "*S-1-5-32-545:(OI)(CI)R", "/T", "/C"]  # Users SID
        ]
        for cmd in cmds:
            subprocess.run(cmd, capture_output=True)
    else:
        # Linux (Debian, RHEL)
        # Directories need +x to be accessible; files do not.
        if os.path.isdir(target_path):
            os.chmod(target_path, 0o755) # rwxr-xr-x
        else:
            os.chmod(target_path, 0o744) # rwxr--r--

        for root, dirs, files in os.walk(target_path):
            for d in dirs:
                os.chmod(os.path.join(root, d), 0o755)
            for f in files:
                os.chmod(os.path.join(root, f), 0o744)

def get_path_slug(path):
    """Converts a system path into a safe, flat folder name for the repo."""
    # Convert backslashes to forward slashes for unified processing
    normalized = path.replace('\\', '/')
    # Remove drive letters and leading slashes
    clean_path = re.sub(r'^[a-zA-Z]:', '', normalized).lstrip('/')
    slug = re.sub(r'[^a-zA-Z0-9]', '_', clean_path).strip('_')
    return slug if slug else "root_dir"

def sync_protected_to_repo(repo_dir, protected_folder):
    """Copies a specific folder into its designated sub-folder in the repo."""
    slug = get_path_slug(protected_folder)
    dest_in_repo = os.path.join(repo_dir, slug)
    
    apply_security_policy(protected_folder)
    
    if os.path.isfile(protected_folder):
        os.makedirs(dest_in_repo, exist_ok=True)
        shutil.copy2(protected_folder, os.path.join(dest_in_repo, os.path.basename(protected_folder)))
    else:
        # copytree with dirs_exist_ok handles existing destination folders
        shutil.copytree(protected_folder, dest_in_repo, dirs_exist_ok=True, copy_function=shutil.copy2)
    
    apply_security_policy(dest_in_repo)

def restore_protected_from_repo(repo_dir, protected_folder):
    """
    Restores a specific folder from its slug-folder in the repo.
    """
    slug = get_path_slug(protected_folder)
    source_in_repo = os.path.join(repo_dir, slug)
    status = True
    issue = ""
    
    if not os.path.exists(source_in_repo):
        return status
    
    try:
        if os.path.isfile(protected_folder):
            # If target is a file, find the file inside the slug folder
            file_name = os.path.basename(protected_folder)
            shutil.copy2(os.path.join(source_in_repo, file_name), protected_folder)
        else:
            shutil.copytree(source_in_repo, protected_folder, dirs_exist_ok=True, copy_function=shutil.copy2)
        
        apply_security_policy(protected_folder)

        # OS-Specific Reload Logic
        if platform.system() != "Windows":
            path_str = str(protected_folder).lower()
            if any(x in path_str for x in ['systemd/system', 'init.d', 'rc.d']):
                if shutil.which("systemctl"):
                    result = run_bash("systemctl daemon-reload")
                    if result.returncode != 0:
                        status = False
                        issue = f"Restored {protected_folder}, but could not reload system service definitions. Error: {result.stderr.strip()}"
                elif shutil.which("rc-update"): # Alpine/OpenRC
                    result = run_bash("rc-update -u")
                    if result.returncode != 0:
                        status = False
                        issue = f"Restored {protected_folder}, but could not reload system service definitions. Error: {result.stderr.strip()}"
    except Exception as E:
        print_debug(f"restore_protected_from_repo failed on {protected_folder}: {E}")
        status = False
        issue = f"Failed to restore {protected_folder}. Error: {E}"
    return status, issue

def get_latest_commit_stats(branch_name, repo_dir):
    """
    Returns the number of changes and a list of file names for
    the latest commit on the specified branch.
    """
    result = run_git(["show", "--format=", "--name-status", branch_name], repo_dir)
    
    if not result or result.returncode != 0:
        return {"count": 0, "files": []}

    lines = result.stdout.strip().split('\n')
    files_info = []
    status_map = {'M': 'Modified', 'A': 'Created', 'D': 'Deleted', 'R': 'Renamed'}
    
    for line in lines:
        if not line.strip(): continue
        parts = line.split(maxsplit=1)
        if len(parts) == 2:
            status, file_path = parts
            friendly_status = status_map.get(status[0], status) # Handle "M90" etc
            files_info.append(f"{friendly_status}: {file_path}")

    return {"count": len(files_info), "files": files_info}
    
def file_protect_main(repo_dir, protected_folders):
    """Main logic for the agent sync loop supporting multiple paths."""
    try:
        assert len(repo_dir) > 60, f"invalid repo_dir - suspiciously short (may lead to bad path). value: {repo_dir}"
        # 1. Standardize local repo state
        run_git(["checkout", "good"], repo_dir)
        run_git(["pull", "origin", "good"], repo_dir)

        # Clear working tree (excluding .git)
        for item in os.listdir(repo_dir):
            if item == ".git": continue
            path = os.path.join(repo_dir, item)
            if os.path.isdir(path): shutil.rmtree(path)
            else: os.remove(path)
        
        # 2. Capture current state of the system
        for folder in protected_folders:
            if os.path.exists(folder):
                sync_protected_to_repo(repo_dir, folder)
        
        # 3. Diff check
        run_git(["add", "."], repo_dir)
        diff_check = run_git(["diff", "--cached", "--quiet"], repo_dir)

        if diff_check.returncode != 0:
            try:
                hash_result = run_git(["rev-parse", "--short", "HEAD"], repo_dir)
                good_hash = hash_result.stdout.strip() if hash_result.returncode == 0 else "unknown"

                run_git(["stash"], repo_dir)
                run_git(["checkout", "bad"], repo_dir)
                run_git(["pull", "origin", "bad"], repo_dir)
                
                # Align 'bad' branch to 'good' baseline
                run_git(["checkout", "good", "."], repo_dir) 
                run_git(["add", "."], repo_dir)
                run_git(["commit", "--allow-empty", "-m", f"baseline-{good_hash}"], repo_dir)

                # Re-apply the changes found on the system
                if run_git(["stash", "pop"], repo_dir).returncode != 0:
                    run_git(["checkout", "--theirs", "."], repo_dir)
                    run_git(["add", "."], repo_dir)
                    run_git(["commit", "-m", "auto-resolveconflict"], repo_dir)
                
                timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
                run_git(["add", "."], repo_dir)
                run_git(["commit", "-m", f"auto-malicious-{timestamp}"], repo_dir)
                run_git(["push", "-u", "origin", "bad"], repo_dir)
                
                changes = get_latest_commit_stats("bad", repo_dir)
                
                # 4. RESTORATION
                run_git(["checkout", "good"], repo_dir)
                if not DISARM:
                    status = True
                    issues = [f"{changes['count']} unauthorized changes found: {changes['files']}"]
                    is_win = platform.system() == "Windows"
                    
                    # Stop services
                    for s in SERVICES:
                        if is_win:
                            cmd = ["net", "stop", s]
                            result = run_powershell(cmd)
                            if not result:
                                issues.append(f"Failed to stop service {s} before restoring its files. Error: N/A")
                        else:
                            cmd = ["systemctl", "stop", s]
                            result = run_bash(cmd)
                            if result.returncode != 0:
                                issues.append(f"Failed to stop service {s} before restoring its files. Error: {result.stderr.strip()}")
                        
                    for folder in protected_folders:
                        folder_status, issue = restore_protected_from_repo(repo_dir, folder)
                        if not folder_status:
                            status = False
                            issues.append(issue)
                            
                    # Restart services
                    for s in SERVICES:
                        if is_win:
                            cmd = ["net", "start", s]
                            result = run_powershell(cmd)
                            if not result:
                                issues.append(f"Failed to start service {s} before restoring its files. Error: N/A")
                        else:
                            cmd = ["systemctl", "start", s]
                            result = run_bash(cmd)
                            if result.returncode != 0:
                                issues.append(f"Failed to start service {s} before restoring its files. Error: {result.stderr.strip()}")
                    
                    return False, status, issues
                else:
                    return False, False, [f"Changes detected (DISARMED): {changes['files']}"]

            except Exception as E:
                return False, False, [f"Restoration logic failed: {E}"]
        
        return True, True, []
    except Exception as E:
        return False, False, [f"Integrity check fatal error: {E}"] 
    
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

def service_audit_windows(service_name):
    """
    Given the name of a Windows service, detect if it is nonfunctional and attempt fixes.
    Supports: service not running (script prints the last status message of the service and starts it), service not set to automatic start (script sets it to automatic), service not found (script does not do anything but returns that as the issue)

    Returns: Returns: oldStatus(bool), newStatus(bool), issues(list of strings)
    """

    ps_check = r"""
    $svc = Get-Service -Name '{service_name}' -ErrorAction SilentlyContinue
    if ($svc -eq $null) {
        Write-Output 'NotFound'
    } else {
        $obj = [PSCustomObject]@{
            Status = $svc.Status.ToString()
            StartType = $svc.StartType.ToString()
        }
        $obj | ConvertTo-Json
    }
    """.format(service_name=service_name)

    raw = run_powershell(ps_check).strip()
    if not raw or raw == "NotFound":
        return False, False, [f"ServiceNotFound for service {service_name}."]

    try:
        data = json.loads(raw)
    except:
        return False, False, [f"FAILED to parse service JSON for {service_name}."]

    current_status = data.get("Status", "")
    current_start = data.get("StartType", "")

    # FIXED: oldStatus is True only if service is Running AND Automatic
    is_running = current_status == "Running"
    is_auto = current_start in ("Automatic", "Auto")
    oldStatus = is_running and is_auto
    
    newStatus = oldStatus
    issues = []

    if not is_running:
        if DISARM:
            issues.append(f"Service {service_name} not running, DISARMED.")
        else:
            run_powershell(f"Start-Service -Name '{service_name}'")
            # Verify
            verify = run_powershell(f"(Get-Service '{service_name}').Status").strip()
            if verify == "Running":
                issues.append(f"Service {service_name} was stopped, RESTORED to START state.")
                is_running = True
            else:
                issues.append(f"Service {service_name} was stopped, FAILED to start.")

    if not is_auto:
        if DISARM:
            issues.append(f"Service {service_name} not set to automatic, DISARMED.")
        else:
            if run_powershell(f"Set-Service -Name '{service_name}' -StartupType Automatic"):
                issues.append(f"Service {service_name} set to Automatic.")
                is_auto = True
    
    newStatus = is_running and is_auto
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
    
    # 1. Get current state using systemctl show
    systemctl_show_cmd = f"systemctl show --no-pager {service_name}"
    raw = run_bash(systemctl_show_cmd)

    if raw.returncode != 0:
        return False, False, [f"ServiceNotFound: could not query logs for {service_name}. Error: {raw.stderr.strip()}"]
    raw = raw.stdout.strip()
    if not raw or "LoadState=not-found" in raw:
        return False, False, [f"ServiceNotFound: {service_name} is not loaded on this system."]

    # Parse properties
    data = {}
    for line in raw.splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            data[key] = value

    active_state = data.get("ActiveState", "").lower()    # active, inactive, failed
    unit_state = data.get("UnitFileState", "").lower()     # enabled, disabled, static, masked
    load_state = data.get("LoadState", "").lower()

    # Determine initial health
    # Note: 'static' and 'alias' are considered 'effectively enabled' because they don't use symlinks
    is_running = (active_state == "active")
    is_enabled = unit_state in ["enabled", "enabled-runtime", "static", "indirect"]
    
    old_status = is_running and is_enabled
    current_running = is_running
    current_enabled = is_enabled

    # MASKED handling
    if unit_state == "masked":
        if DISARM:
            issues.append(f"Service {service_name} is MASKED, DISARMED.")
        else:
            # Step A: Unmask the service
            result = run_bash(f"systemctl unmask {service_name}")
            if result.returncode == 0:
                issues.append(f"Service {service_name} was MASKED, UNMASKED successfully.")
                # Update unit_state so the next block can enable it
                unit_state = "disabled" 
            else:
                issues.append(f"Service {service_name} is MASKED and FAILED to unmask. Error: {result.stderr.strip()}")

    # 2. Fix Active State (Start if stopped)
    if not is_running:
        if DISARM:
            issues.append(f"Service {service_name} is {active_state}, DISARMED.")
        else:
            result = run_bash(f"systemctl start {service_name}")
            if result.returncode != 0:
                issues.append(f"Service {service_name} was {active_state}, attempted to restore to active but failed. Error: {result.stderr.strip()}")
            else:
                # Quick verification that it started fine
                result = run_bash(f"systemctl is-active {service_name}")
                if result.returncode != 0:
                    issues.append(f"Service {service_name} was {active_state}, attempted to restore to active but service failed after launching. Error: {result.stderr.strip()}")
                else:
                    if result.stdout.strip() == "active":
                        issues.append(f"Service {service_name} was {active_state}, RESTORED to active.")
                        current_running = True
                    else:
                        issues.append(f"Service {service_name} FAILED to start.")

    # 3. Fix Enabled State (Enable if disabled)
    # Only attempt to enable if it's actually 'disabled'. 'static' cannot be enabled.
    if unit_state == "disabled":
        if DISARM:
            issues.append(f"Service {service_name} is disabled, DISARMED.")
        else:
            result = run_bash(f"systemctl enable {service_name}")
            if result.returncode == 0:
                issues.append(f"Service {service_name} was disabled, RESTORED to enabled.")
                current_enabled = True
            else:
                issues.append(f"Service {service_name} FAILED to enable.")

    new_status = current_running and current_enabled
    return old_status, new_status, issues

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

def service_uninstall_windows(service, package):
    """
    Given a service, see if it is installed (service is found/responsible package is installed) and perform appropriate remediation if not.

    Args: service name (string)

    Returns: Returns: oldStatus(bool), newStatus(bool), issue(string)
    """

    issues = []
    old_status = False
    
    # Check Package/Feature
    pkg_found = False
    if package:
        # Check Optional Features first
        feat_check = run_powershell(f"Get-WindowsOptionalFeature -Online -FeatureName {package} -ErrorAction SilentlyContinue | ConvertTo-Json")
        if feat_check:
            data = json.loads(feat_check)
            if data.get("State") == "Enabled":
                pkg_found = True
        
        if not pkg_found:
            if DISARM:
                issues.append(f"Package {package} missing, DISARMED.")
            else:
                run_powershell(f"Enable-WindowsOptionalFeature -Online -FeatureName {package} -All -NoRestart")
                pkg_found = True # Simplified check
    
    # Check Service
    svc_found = False
    if service:
        svc_check = run_powershell(f"Get-Service -Name {service} -ErrorAction SilentlyContinue")
        svc_found = bool(svc_check)
        if not svc_found:
            issues.append(f"Service {service} missing. Manual reinstallation required.")

    old_status = (pkg_found if package else True) and (svc_found if service else True)
    # We assume if we didn't fail a command, the new state is "better" or equal
    return old_status, (pkg_found and svc_found), issues

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
    is_debian = os.path.exists("/usr/bin/apt-get")
    
    # 1. Check Package
    package_present_initial = False
    if package:
        check_cmd = f"dpkg -l {package}" if is_debian else f"rpm -q {package}"
        res = run_bash(check_cmd, noisy=False)
        if res.returncode != 0:
            issues.append(f"Could not check if package {package} is present. Error: {res.stderr.strip()}")
        else:
            res = res.stdout.strip()
            # Simplified presence check
            package_present_initial = (res != "" and "not installed" not in res.lower())

            if not package_present_initial:
                if DISARM:
                    issues.append(f"Missing package {package}, DISARMED.")
                else:
                    install_cmd = f"apt-get install -y {package}" if is_debian else f"dnf install -y {package}"
                    result = run_bash(install_cmd)
                    if result.returncode == 0:
                        issues.append(f"Restored package {package} via {'apt' if is_debian else 'dnf'}.")
                    else:
                        issues.append(f"FAILED to install package {package}. Error: {result.stderr.strip()}")

    # 2. Check Service
    service_present_initial = False
    if service:
        svc_check = run_bash(f"systemctl show --no-pager {service}")
        if svc_check.returncode != 0:
            issues.append(f"Could not show details for service {service}. Error: {svc_check.stderr.strip()}")
        else:
            svc_check = svc_check.stdout.strip()
            service_present_initial = (svc_check != "" and "LoadState=loaded" in svc_check)
            
            if not service_present_initial and not DISARM:
                # Re-check after package install
                svc_check = run_bash(f"systemctl show --no-pager {service}")
                if svc_check.returncode != 0:
                    issues.append(f"Could not show details for service {service}. Error: {svc_check.stderr.strip()}")
                svc_check = svc_check.stdout.strip()
                if "LoadState=loaded" in svc_check:
                    issues.append(f"Service {service} restored by package installation.")
                    service_present_after = True
                else:
                    service_present_after = False
            else:
                service_present_after = service_present_initial

    package_present_after = package_present_initial or (not DISARM) # Simplified for return
    oldStatus = (package_present_initial if package else True) and (service_present_initial if service else True)
    newStatus = (package_present_after) and (service_present_after if service else True)
    
    return oldStatus, newStatus, issues

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
        # On linux systems, equivalent functionality is achieved by just protecting the service file with the file protection functionality.
    
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
    ps_check = r"""
    $svc = Get-CimInstance Win32_Service -Filter "Name='{service_name}'" -ErrorAction SilentlyContinue
    if ($svc -eq $null) { 
        Write-Output 'NotFound'
    }  else { 
        $obj = New-Object PSObject -Property @{ 
            StartName = $svc.StartName
            PathName = $svc.PathName
            Dependencies = $svc.DependsOn
        } 
        $obj | ConvertTo-Json
    } 
    """.format(service_name=service_name)
    
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
    if (current_start_name != expected_start_name) or (current_path_name.lower().strip() != expected_path_name.lower().strip()) or (current_dependencies_sorted != expected_dependencies_sorted):
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

def service_lastrun_windows(service_name):
    """
    Given the name of a Windows service, detect if it is running. If not, get the last error message and return it

    Returns: Returns: oldStatus(bool), newStatus(bool), issues(list of strings)
    """
    
    oldStatus = True
    newStatus = True
    issues = []

    # 1. Get Status and ExitCode via CIM
    ps_check = r"""
    $svc = Get-CimInstance Win32_Service -Filter "Name='{service_name}'"
    if ($null -eq $svc) {{ 
        Write-Output 'NotFound'
    }} else {{ 
        $obj = [PSCustomObject]@{ 
            Status = $svc.State
            ExitCode = $svc.ExitCode
        } 
        $obj | ConvertTo-Json
    }} 
    """.format(service_name=service_name)

    raw = run_powershell(ps_check).strip()
    
    if not raw or raw == "NotFound":
        return False, False, [f"Status Check: ServiceNotFound {service_name}."]

    try:
        data = json.loads(raw)
    except:
        return False, False, [f"FAILED to parse status for {service_name}."]

    current_status = data.get("Status", "Unknown")
    exit_code = data.get("ExitCode", 0)

    # 2. Status Analysis
    if current_status == "Running":
        return True, True, []

    oldStatus = False
    newStatus = False 

    # 3. Analyze Exit Code
    # Standard Win32 Error Codes: 0 = Success, 1066 = Service Specific
    if exit_code == 0:
        msg = f"Service {service_name} is {current_status}. Last stop was clean (0)."
    elif exit_code == 1066:
        # For 1066, we'd ideally need the 'ServiceSpecificExitCode' property too
        msg = f"Service {service_name} is {current_status}. Stopped with a Service-Specific error (1066)."
    else:
        msg = f"Service {service_name} is {current_status}. Last exit code: {exit_code}."
        
    issues.append(msg)
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
    oldStatus = True
    newStatus = True
    issues = []

    # 1. Check Active Status
    # systemctl is-active is reliable for a quick boolean
    active_check = run_bash(f"systemctl is-active {service_name}")
    if active_check.returncode != 0:
        issues.append(f"Could not check if service {service_name} is active. Error: {active_check.stderr.strip()}")
    active_check = active_check.stdout.strip()

    if active_check == "active":
        return True, True, []

    # 2. Retrieve Detailed Failure Data
    show_cmd = f"systemctl show --no-pager {service_name}"
    raw = run_bash(show_cmd)
    if raw.returncode != 0:
        issues.append(f"Could not get logs for service {service_name}. Error: {raw.stderr.strip()}")
    raw = raw.stdout.strip()

    if "LoadState=not-found" in raw:
        return False, False, [f"Status Check: ServiceNotFound {service_name}."]

    data = {}
    for line in raw.splitlines():
        if '=' in line:
            k, v = line.split('=', 1)
            data[k] = v

    oldStatus = False
    newStatus = False

    # 3. Extract Exit Status and Reason
    # ExecMainStatus is the numeric code (e.g. 1, 2)
    # Result gives the category (e.g. exit-code, signal, timeout)
    exit_status = data.get("ExecMainStatus", "0")
    result = data.get("Result", "unknown")
    
    analysis_msg = f"Service {service_name} is {active_check}."
    
    if result != "success":
        analysis_msg += f" Termination reason: {result} (Code: {exit_status})."
    else:
        analysis_msg += " Last exit was successful (0)."

    issues.append(analysis_msg)
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
    send_message("agent/beacon/magpie",True,True,f"pausing for seconds {seconds}")
    return True

def resume(scheduled=False):
    """
    Resumes protection.
    Clears current pause countdown (if any).
    Sends message to server.
    Returns: Success(bool)
    """
    send_message("agent/beacon/magpie",True,True,f"resuming - scheduled: {scheduled}")
    return True

def reregister():
    """
    Performs a re-init of protected files for legitimate changes
    Returns Success(bool)
    """
    send_message("agent/beacon/magpie",True,True,"reregister")
    return True

#endregion###############
### Windows Service #####
#region##################

"""
class MyService(win32serviceutil.ServiceFramework):
    _svc_name_ = f"Magpie_{AGENT_NAME}"
    _svc_display_name_ = f"Magpie_{AGENT_NAME}"

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

    # Simplified PowerShell to get IP and Prefix in one go
    query_cmd = fr"""
        Get-NetIPAddress -InterfaceAlias '{interface}' -AddressFamily IPv4 | 
        Select-Object IPAddress, PrefixLength | ConvertTo-Json
    """

    output = run_powershell(query_cmd).strip()
    ip_address = None
    prefix = None
    gateway = None

    if output:
        try:
            # Handle cases where multiple IPs might be returned (returns a list)
            data = json.loads(output)
            if isinstance(data, list):
                data = data[0]
            ip_address = data.get("IPAddress")
            prefix = data.get("PrefixLength")
        except json.JSONDecodeError:
            print_debug(f"init_int_vars_windows({interface}): JSON parse error.")

    # Get Gateway - Selected directly
    query_gw = fr"""
        Get-NetIPConfiguration -InterfaceAlias '{interface}' | 
        Select-Object -ExpandProperty IPv4DefaultGateway | Select-Object NextHop | ConvertTo-Json
    """
    
    gw_output = run_powershell(query_gw).strip()
    if gw_output:
        try:
            gw_data = json.loads(gw_output)
            # ExpandProperty might return an object or a list of objects
            if isinstance(gw_data, list):
                gateway = gw_data[0].get("NextHop")
            else:
                gateway = gw_data.get("NextHop")
        except json.JSONDecodeError:
             print_debug(f"init_int_vars_windows({interface}): Gateway JSON parse error.")

    print_debug(f"init_int_vars_windows({interface}): {ip_address} {prefix} {gateway}")
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
        cmd = ["ip", "-j", "addr", "show", interface]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        addr_data = json.loads(result.stdout.strip())

        if addr_data and "addr_info" in addr_data[0]:
            # Filter for IPv4 (inet) addresses and take the first valid local
            for addr in addr_data[0]["addr_info"]:
                if addr.get("family") == "inet":
                    ip_address = addr.get("local")
                    prefix = addr.get("prefixlen")
                    break # Take the primary
    except Exception as e:
        print_debug(f"init_int_vars_linux({interface}): IP query failed: {e}")

    # 2. Get Default Gateway
    try:
        # Better: Filter specifically for the default route on this device
        cmd = ["ip", "-j", "route", "show", "default", "dev", interface]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        route_data = json.loads(result.stdout.strip())

        if route_data:
            # Matches 'gateway' (RHEL/CentOS) or 'via' (Standard iproute2)
            gateway = route_data[0].get("gateway") or route_data[0].get("via")
    except Exception as e:
        print_debug(f"init_int_vars_linux({interface}): Gateway query failed: {e}")

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

def signal_handler(sig, frame):
    print_debug("Service stopping due to receiving signal handler")
    sys.exit(0)

def main(stop_event=None):
    # force the working directory to the script's location
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    global PAUSED
    ip_address,prefix,gateway = init_int_vars()

    systemInfo = get_system_details()
    agent_id = hash_id(AGENT_NAME, systemInfo["hostname"], systemInfo["ipadd"], systemInfo["os"])
    repo_url = os.path.join(f"{SERVER_URL}agent/git",f"{agent_id}.git")
    repo_dir = f"{os.path.join(os.path.dirname(os.path.abspath(__file__)),f'{agent_id}.git')}"

    send_message("agent/beacon/magpie",True,True,f"Register")
    
    setup_git_agent(repo_dir,PROTECTED_FOLDERS)

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

        pausedEpochServer = send_message("agent/get_pause")
        if pausedEpochServer:
            pausedEpochServer = float(pausedEpochServer)
        else:
            pausedEpochServer = -1

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
                send_message("agent/beacon/magpie",False,False,f"Agent moved into PAUSE status for {int(pausedEpochLocal - time.time())} seconds")
            else:
                send_message("agent/beacon/magpie",True,True,f"Agent moved into ACTIVE status (from PAUSE)")

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
                    send_message("agent/beacon/magpie",result_oldStatus,result_newStatus,newIssues[-1])
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
                    send_message("agent/beacon/magpie",result_oldStatus,result_newStatus,newIssues[-1])
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
                    send_message("agent/beacon/magpie",result_oldStatus,result_newStatus,newIssues[-1])
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
                    send_message("agent/beacon/magpie",result_oldStatus,result_newStatus,newIssues[-1])
                    sent_msg = True
                else:
                    suppressed_send = True

            if not sent_msg:
                if suppressed_send:
                    send_message("agent/beacon/magpie",True,True,"no new issues; at least one prior issue still exists but suppressing redundant alert")
                else:
                    send_message("agent/beacon/magpie",True,True,"all good")

            # Finish up
            print_debug(f"main(): oldStatus - {oldStatus}")
            print_debug(f"main(): newStatus - {newStatus}")
            #for issue in issues:
                #print_debug(f"main(): issue - {issue}")
                #send_message("agent/beacon/magpie",oldStatus,newStatus,issue)
            
            print_debug(f"main(): sleeping for {SLEEPTIME} seconds")
            print_debug(f"")

            oldIssues = newIssues
            newIssues = []
        else:
            if not suppressed_send:
                # Do not trigger alert
                send_message("agent/beacon/magpie",True,False,f"Agent still in PAUSE status for {int(pausedEpochLocal - time.time())} seconds remaining")
        
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
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    main()

#endregion###############