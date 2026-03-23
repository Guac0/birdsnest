#########################
######## Imports ########
#region##################
# apt install -y passwd login
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
import signal
import sys
from datetime import timedelta
from abc import ABC, abstractmethod
import struct
import sqlite3
import grp
import pwd
import shlex
try:
    import win32evtlog
    import win32net
    import win32netcon
    import win32security
    import pywintypes
    import win32evtlogutil
    import winreg
    import win32serviceutil
    import win32service
    import win32event
    WINDOWS_LIBS_LOADED = True
except ImportError:
    WINDOWS_LIBS_LOADED = False
#import servicemanager
#import threading

#endregion###############
# Configuration Options #
#region##################

CONFIG_DEFAULTS = {
    "AGENT_NAME": "kingfisher",
    "AUTH_TOKEN": "testtoken",
    "SLEEPTIME": 60,
    "SERVER_URL": "https://127.0.0.1:8000/",
    "SERVER_TIMEOUT": 5,
    "DEBUG_PRINT": True,
    "LOGFILE": "log.txt",
    "STATUSFILE": "status.txt",
    "STATE_FILE": "state.json",
    "AGENT_TYPE": "kingfisher",
    "DISARM": True
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

CONFIG = load_config("config.json") # relative to cwd!
DEBUG_PRINT = CONFIG["DEBUG_PRINT"]
LOGFILE = CONFIG["LOGFILE"]
STATUSFILE = CONFIG["STATUSFILE"]
AGENT_NAME = CONFIG["AGENT_NAME"]
AUTH_TOKEN = CONFIG["AUTH_TOKEN"]
AGENT_TYPE = CONFIG["AGENT_TYPE"]
SERVER_URL = CONFIG["SERVER_URL"]
SERVER_TIMEOUT = CONFIG["SERVER_TIMEOUT"]
SLEEPTIME = CONFIG["SLEEPTIME"]
STATE_FILE = CONFIG["STATE_FILE"]
DISARM = CONFIG["DISARM"]

PAUSED = False

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
            print_debug(f"PowerShell error: {result.stderr.strip()}")
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
            if result.stderr:
                print_debug(f"    Stderr: {result.stderr.strip()}")
        return result
        
    except Exception as e:
        if noisy:
            print_debug(f"run_bash(): System error executing command: {e}")
        # Return a mock object so calling code doesn't crash on attribute access
        return subprocess.CompletedProcess(args=cmd, returncode=1, stdout="", stderr=str(e))

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

def get_admin_group_name():
    # S-1-5-32-544 is the universal SID for the local Administrators group
    try:
        sid = win32security.StringToSid("S-1-5-32-544")
        name, domain, type = win32security.LookupAccountSid(None, sid)
        print_debug(f"get_admin_group_name - selected {name} as Administrators group name")
        return name # Returns "Administrators" on English, "Administrateurs" on French, etc.
    except Exception as E:
        print_debug(f"ERROR: get_admin_group_name - unexpected error, defaulting to Administrators: {E}")
        return "Administrators"

def get_user_provider():
    """
    Factory function to automatically detect the OS and return 
    the appropriate UserProvider instance.
    """
    os_type = platform.system().lower()

    if os_type == "windows":
        print_debug("System detected: Windows. Loading WindowsProvider.")
        return WindowsProvider()

    elif os_type == "linux":
        # platform.freedesktop_os_release() is the modern way to get distro ID
        # It reads /etc/os-release
        try:
            os_info = platform.freedesktop_os_release()
            distro_id = os_info.get("ID", "").lower()
            distro_like = os_info.get("ID_LIKE", "").lower()
        except AttributeError:
            # Fallback for older Python versions
            distro_id = "unknown"
            distro_like = ""

        if distro_id in ["debian", "ubuntu", "kali"]:
            print_debug(f"System detected: {distro_id.capitalize()}. Loading DebianProvider.")
            return DebianProvider()
        
        elif distro_id in ["rhel", "fedora", "rocky", "almalinux"] or "rhel" in distro_like:
            print_debug(f"System detected: {distro_id.upper()}. Loading RHELProvider.")
            return RHELProvider()

        if distro_id == "alpine":
            print_debug("System detected: Alpine. Loading AlpineProvider.")
            return AlpineProvider()
        
        else:
            print_debug(f"Unknown Linux distro ({distro_id}). Defaulting to DebianProvider logic.")
            return DebianProvider()

    elif os_type == "freebsd":
        print_debug("System detected: FreeBSD. Loading FreeBSDProvider.")
        return FreeBSDProvider()

    else:
        raise OSError(f"{AGENT_TYPE} does not currently support the operating system: {os_type}")
    
#endregion###############
## Server Comms Funcs ###
#region##################

def send_message(endpoint,oldStatus=True,newStatus=True,message="",authInfo=None,systemInfo=get_system_details()):
    """
    Sends the specified data to the server
    Handles the full process and attaching agent name/auth

    Args: message(any)
    Returns: response(str)
    """
    global AUTH_TOKEN

    if not SERVER_URL:
        # Server comms are intentionally disabled
        # Maybe redirect to print_debug instead?
        return True
    url = SERVER_URL + endpoint

    # Prep payload
    if authInfo != None:
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
            "message": message,
            "timestamp": authInfo["timestamp"],
            "user": authInfo["user"],
            "srcip": authInfo["srcip"],
            "login_type": authInfo["login_type"],
            "successful": authInfo["successful"]
        }
    else:
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
                if endpoint == f"agent/beacon/{AGENT_TYPE}":
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
    return ""

#endregion###############
######## Parsers ########
#region##################

class UserProvider(ABC):
    """Abstract Base Class defining the contract for User Management."""

    @abstractmethod
    def get_all_users(self):
        """Returns a list of dicts: [{'username': str, 'is_admin': bool, 'is_locked': bool, "last_login": int (unix timestamp)}]"""
        pass

    @abstractmethod
    def change_password(self, username, new_password):
        """Updates the password for the specified user."""
        pass

    @abstractmethod
    def lock_account(self, username, should_be_locked):
        """Disables or locks the account to prevent login, or vice versa."""
        pass

    @abstractmethod
    def set_admin_status(self, username, should_be_admin):
        """Adds or removes the user from the high-privilege group."""
        pass

    @abstractmethod
    def delete_user(self, username):
        """Removes the user account from the system."""
        pass

    @abstractmethod
    def create_user(self, username, password, should_be_admin): # , shell="/bin/bash"
        """Creates a new local user with the provided credentials."""
        pass
    
    #@abstractmethod
    #def change_shell(self, username, shell="/bin/bash"):
    #    """Changes the default terminal for the user."""
    #    pass

if WINDOWS_LIBS_LOADED:
    class WindowsProvider(UserProvider):
        def __init__(self):
            # Local machine is denoted by None in win32net calls
            self.server = None
            self.admingrpname = get_admin_group_name()

        def get_all_users(self):
            try:
                users = []
                resume = 0
                while True:
                    try:
                        # Level 3 provides the most comprehensive local user info
                        data, total, resume = win32net.NetUserEnum(
                            self.server, 
                            3, 
                            win32netcon.FILTER_NORMAL_ACCOUNT, 
                            resume
                        )
                        
                        for user in data:
                            # 1. Admin Status (via localized group check)
                            groups = win32net.NetUserGetLocalGroups(self.server, user['name'])
                            is_admin = self.admingrpname in groups # See note below on localization

                            # 2. Lock Status
                            is_locked = bool(user['flags'] & win32netcon.UF_ACCOUNTDISABLE)
                            
                            # 3. Unix Timestamp (Integer)
                            # Windows last_logon is already in seconds since Jan 1, 1970
                            last_login_ts = int(user['last_logon'])

                            # 4. Local vs Domain Detection
                            # UF_TEMP_DUPLICATE_ACCOUNT or checking the 'workstations' field 
                            # can be unreliable. The most robust way for an agent is to check 
                            # the account's flag for 'UF_SCRIPT' (common for local) or 
                            # comparing the domain SID, but here we use the 'priv' level 
                            # and flags context.
                            account_type = "local"
                            if user['flags'] & win32netcon.UF_WORKSTATION_TRUST_ACCOUNT:
                                account_type = "domain"
                            elif user['auth_flags'] & win32netcon.AF_OP_PRINT: # Extra domain-level check
                                account_type = "domain"

                            users.append({
                                'username': user['name'],
                                'admin': is_admin,
                                'locked': is_locked,
                                'last_login': last_login_ts,
                                'account_type': account_type
                            })
                    except Exception as E:
                        print_debug(f"WARNING: get_all_users - unexpected error: {E}")
                    if not resume:
                        break
                print_debug(f"OK: Read {len(users)} users from system")
                return users
            except Exception as E:
                print_debug(f"ERROR: get_all_users - {E}")
                return {}

        def change_password(self, username, new_password):
            if DISARM:
                print_debug(f"OK: Attempted to change password for user {username} to 'REDACTED', but DISARMED")
                return False
            try:
                user_info = {'password': new_password}
                win32net.NetUserSetInfo(self.server, username, 1003, user_info)
                print_debug(f"OK: Changed password for user {username} to 'REDACTED'")
                return True
            except Exception as E:
                print_debug(f"ERROR: change_password({username}, 'REDACTED') - {E}")
                return False

        def lock_account(self, username, should_be_locked):
            if DISARM:
                print_debug(f"OK: Attempted to change lock state for user {username} to {should_be_locked}', but DISARMED")
                return False
            try:
                # Level 1008 accesses the USER_INFO_1008 structure (flags only)
                user_info = win32net.NetUserGetInfo(self.server, username, 1008)
                
                if should_be_locked:
                    # Bitwise OR to set the DISABLE flag
                    user_info['flags'] |= win32netcon.UF_ACCOUNTDISABLE
                else:
                    # Bitwise AND with NOT to clear the DISABLE flag
                    user_info['flags'] &= ~win32netcon.UF_ACCOUNTDISABLE
                    
                win32net.NetUserSetInfo(self.server, username, 1008, user_info)
                if should_be_locked:
                    print_debug(f"OK: Locked/disabled account for user {username}")
                else:
                    print_debug(f"OK: Unlocked/enabled account for user {username}")
                return True
            except Exception as E:
                print_debug(f"ERROR: lock_account({username}) - {E}")
                return False

        def set_admin_status(self, username, should_be_admin):
            if DISARM:
                print_debug(f"OK: Attempted to change admin state for user {username} to {should_be_admin}, but DISARMED")
                return False
            try:
                if should_be_admin:
                    win32net.NetLocalGroupAddMembers(self.server, self.admingrpname, 3, [username])
                    print_debug(f"OK: Added Admin access to user {username}")
                else:
                    win32net.NetLocalGroupDelMembers(self.server, self.admingrpname, [username])
                    print_debug(f"OK: Removed Admin access to user {username}")
                return True
            except Exception as E:
                print_debug(f"ERROR: set_admin_status({username}, {should_be_admin}) - {E}")
                return False

        def delete_user(self, username):
            if DISARM:
                print_debug(f"OK: Attempted to delete user {username}, but DISARMED")
                return False
            try:
                win32net.NetUserDel(self.server, username)
                print_debug(f"OK: Deleted user {username}")
                return True
            except Exception as E:
                print_debug(f"ERROR: delete_user({username}) - {E}")
                return False

        def create_user(self, username, password, should_be_admin):
            if DISARM:
                print_debug(f"OK: Attempted to create user {username} but password 'REDACTED' and admin status {should_be_admin}, but DISARMED")
                return False
            try:
                user_data = {
                    'name': username,
                    'password': password,
                    'priv': win32netcon.USER_PRIV_USER,
                    'comment': f"Created by {AGENT_TYPE}",
                    'flags': win32netcon.UF_SCRIPT | win32netcon.UF_NORMAL_ACCOUNT
                }
                win32net.NetUserAdd(self.server, 1, user_data)
                print_debug(f"OK: Created regular user {username} with password 'REDACTED'")
                
                if should_be_admin:
                    if not self.set_admin_status(username, True):
                        raise Exception("set_admin_status returned False")
                return True
            except Exception as E:
                print_debug(f"ERROR: create_user({username},'redacted',{should_be_admin}) - {E}")
                return False
else:
    # This prevents the program from crashing if WindowsAuthWatcher is referenced 
    # in an OS-generic loop or factory.
    class WindowsProvider(UserProvider):
        def __init__(self, *args, **kwargs):
            print_debug(f"CRITICAL: WindowsProvided inited but WINDOWS_LIBS_LOADED is false!")
            pass
        def get_all_users(self): return False
        def change_password(self, username, new_password): return False
        def lock_account(self, username): return False
        def set_admin_status(self, username, should_be_admin): return False
        def delete_user(self, username): return False
        def create_user(self, username, password, should_be_admin): return False
        
class DebianProvider(UserProvider):
    def __init__(self):
        self.admingrpname = "sudo"

    def _get_last_login(self, username, uid):
        """Hierarchical lastlog lookup: Binary -> SQLite -> CLI."""
        # 1. Binary Sparse File (/var/log/lastlog)
        binary_path = '/var/log/lastlog'
        if os.path.exists(binary_path):
            fmt = 'I32s256s' 
            size = struct.calcsize(fmt)
            try:
                with open(binary_path, 'rb') as f:
                    f.seek(uid * size)
                    data = f.read(size)
                    if data:
                        return int(struct.unpack(fmt, data)[0])
            except: pass

        # 2. SQLite (lastlog2)
        db_path = '/var/lib/lastlog/lastlog2.db'
        if os.path.exists(db_path):
            try:
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                cursor.execute("SELECT time FROM lastlog2 WHERE user=?", (username,))
                row = cursor.fetchone()
                conn.close()
                if row: return int(row[0])
            except: pass

        # 3. CLI Fallback
        print_debug("_get_last_login - falling back to CLI method")
        res = run_bash(f"lastlog -u {shlex.quote(username)}")
        # Simple check: if output doesn't contain 'Never', it's likely been used
        if "**Never logged in**" not in res.stdout.strip():
            # Note: Parsing exact timestamps from CLI is brittle; 
            # for a SIEM, binary/DB is the source of truth.
            # Just return 1 to signify that there was a login at some point.
            return 1 
        return 0

    def get_all_users(self):
        try:
            users = []
            try:
                admins = grp.getgrnam(self.admingrpname).gr_mem
            except KeyError as E:
                print_debug(f"ERROR: get_all_users - failed to get admin list: {E}")
                admins = []

            for p in pwd.getpwall():
                try:
                    # Filter for human users or specific SIEM targets
                    if p.pw_uid < 1000 and p.pw_name != "root":
                        continue

                    # Lock Status via passwd -S (Replaces deprecated spwd)
                    is_locked = False
                    result = run_bash(f"passwd -S {shlex.quote(p.pw_name)}", noisy=False)
                    
                    try:
                        #f result.stdout.split()[1] == 'P':
                        if result.stdout.split()[1] == 'L':
                            is_locked = True
                    except Exception as E:
                        print_debug(f"get_all_users(): Error when running passwd -S {shlex.quote(p.pw_name)}, defaulting user state to unlocked")
                        pass

                    # Local vs Domain Detection
                    # If user is in /etc/passwd, they are local. 
                    # Network users (LDAP/AD) usually only appear in getpwall() via SSSD/NSCD
                    account_type = "local"
                    with open('/etc/passwd', 'r') as f:
                        if p.pw_name not in f.read():
                            account_type = "domain"

                    users.append({
                        'username': p.pw_name,
                        'admin': p.pw_name in admins or p.pw_name == "root",
                        'locked': is_locked,
                        'last_login': self._get_last_login(p.pw_name, p.pw_uid),
                        'account_type': account_type
                    })
                except Exception as E:
                    print_debug(f"WARNING: get_all_users iteration for {p.pw_name} failed: {E}")

            print_debug(f"OK: Read {len(users)} users from system")
            return users
        except Exception as E:
            print_debug(f"ERROR: get_all_users - {E}")
            return []

    def change_password(self, username, new_password):
        if DISARM:
            print_debug(f"OK: Attempted to change password for user {username} to 'REDACTED', but DISARMED")
            return False
        try:
            # chpasswd is the standard for non-interactive password updates
            cmd = f"echo '{username}:{new_password}' | chpasswd"
            result = run_bash(cmd)
            if result.returncode != 0:
                raise Exception(f"chpasswd command failed - {result.stdout.strip()}")
            
            print_debug(f"OK: Changed password for user {username} to 'REDACTED'")
            return True
        except Exception as E:
            print_debug(f"ERROR: change_password({username}, 'REDACTED') - {E}")
            return False

    def lock_account(self, username, should_be_locked):
        if DISARM:
            print_debug(f"OK: Attempted to change lock state for user {username} to {should_be_locked}', but DISARMED")
            return False
        try:
            action = "--lock" if should_be_locked else "--unlock"
            result = run_bash(f"usermod {action} {shlex.quote(username)}")
            if result.returncode != 0:
                raise Exception(f"usermod {action} failed - {result.stderr.strip()}")

            status = "Locked/disabled" if should_be_locked else "Unlocked/enabled"
            print_debug(f"OK: {status} account for user {username}")
            return True
        except Exception as E:
            print_debug(f"ERROR: lock_account({username}) - {E}")
            return False

    def set_admin_status(self, username, should_be_admin):
        if DISARM:
            print_debug(f"OK: Attempted to change admin state for user {username} to {should_be_admin}, but DISARMED")
            return False
        try:
            if should_be_admin:
                res = run_bash(f"usermod -aG {self.admingrpname} {shlex.quote(username)}")
            else:
                res = run_bash(f"gpasswd -d {shlex.quote(username)} {self.admingrpname}")
            
            if (res.returncode != 0) and should_be_admin: # Check failure
                raise Exception(f"Admin status update failed - {res.stderr.strip()}")
                
            status = "Added Admin access to" if should_be_admin else "Removed Admin access from"
            print_debug(f"OK: {status} user {username}")
            return True
        except Exception as E:
            print_debug(f"ERROR: set_admin_status({username}, {should_be_admin}) - {E}")
            return False

    def delete_user(self, username):
        if DISARM:
            print_debug(f"OK: Attempted to delete user {username}, but DISARMED")
            return False
        try:
            # Do not remove home for later analysis
            result = run_bash(f"userdel {shlex.quote(username)}")
            if result.returncode != 0:
                raise Exception(f"userdel command failed - {result.stderr.strip()}")
            print_debug(f"OK: Deleted user {username}")
            return True
        except Exception as E:
            print_debug(f"ERROR: delete_user({username}) - {E}")
            return False

    def create_user(self, username, password, should_be_admin):
        if DISARM:
            print_debug(f"OK: Attempted to create user {username} but password 'REDACTED' and admin status {should_be_admin}, but DISARMED")
            return False
        try:
            # -m creates home dir, -s sets default shell
            create_cmd = f"useradd -m -s /bin/bash {shlex.quote(username)}"
            result = run_bash(create_cmd)
            if result.returncode != 0:
                raise Exception(f"useradd command failed - {result.stderr.strip()}")
            
            print_debug(f"OK: Created regular user {username} with password 'REDACTED'")
            
            if not self.change_password(username, password):
                raise Exception("Initial password set failed")

            if should_be_admin:
                if not self.set_admin_status(username, True):
                    raise Exception("Initial admin promotion failed")
            return True
        except Exception as E:
            print_debug(f"ERROR: create_user({username}, 'REDACTED', {should_be_admin}) - {E}")
            return False

class RHELProvider(UserProvider):
    def __init__(self):
        # RHEL/Rocky/Fedora use 'wheel' for sudoers by default
        self.admingrpname = "wheel"

    def _get_last_login(self, username, uid):
        """Hierarchical lastlog lookup for RHEL-family systems."""
        # 1. Binary Sparse File (/var/log/lastlog)
        # RHEL still uses this by default in 8.x and 9.x
        binary_path = '/var/log/lastlog'
        if os.path.exists(binary_path):
            fmt = 'I32s256s' 
            size = struct.calcsize(fmt)
            try:
                with open(binary_path, 'rb') as f:
                    f.seek(uid * size)
                    data = f.read(size)
                    if data:
                        return int(struct.unpack(fmt, data)[0])
            except: pass

        # 2. SQLite (lastlog2) - Emerging standard in Fedora/Rawhide
        db_path = '/var/lib/lastlog/lastlog2.db'
        if os.path.exists(db_path):
            try:
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                cursor.execute("SELECT time FROM lastlog2 WHERE user=?", (username,))
                row = cursor.fetchone()
                conn.close()
                if row: return int(row[0])
            except: pass

        # 3. CLI Fallback
        print_debug("_get_last_login - falling back to CLI method")
        res = run_bash(f"lastlog -u {shlex.quote(username)}", noisy=False)
        if "**Never logged in**" not in res.stdout.strip():
            return 1 
        return 0

    def get_all_users(self):
        try:
            users = []
            try:
                # Check for 'wheel' group members
                admins = grp.getgrnam(self.admingrpname).gr_mem
            except KeyError as E:
                print_debug(f"ERROR: get_all_users - failed to get admin list: {E}")
                admins = []

            for p in pwd.getpwall():
                try:
                    # Filter for human users (RHEL usually starts UIDs at 1000)
                    if p.pw_uid < 1000 and p.pw_name != "root":
                        continue

                    # Lock Status via passwd -S
                    is_locked = True
                    result = run_bash(f"passwd -S {shlex.quote(p.pw_name)}", noisy=False)
                    if result.stdout.strip():
                        # RHEL output format: username <status> <date> ...
                        # status 'PS' or 'P' means password set; 'LK' or 'L' means locked
                        status_char = result.stdout.strip().split()[1]
                        if status_char in ['P', 'PS']:
                            is_locked = False

                    # Local vs Domain Detection (sssd check)
                    account_type = "local"
                    with open('/etc/passwd', 'r') as f:
                        if p.pw_name not in f.read():
                            # RHEL heavily uses SSSD for AD/IDM integration
                            account_type = "domain"

                    users.append({
                        'username': p.pw_name,
                        'admin': p.pw_name in admins or p.pw_name == "root",
                        'locked': is_locked,
                        'last_login': self._get_last_login(p.pw_name, p.pw_uid),
                        'account_type': account_type
                    })
                except Exception as E:
                    print_debug(f"WARNING: get_all_users iteration for {p.pw_name} failed: {E}")

            print_debug(f"OK: Read {len(users)} users from RHEL system")
            return users
        except Exception as E:
            print_debug(f"ERROR: get_all_users - {E}")
            return []

    def change_password(self, username, new_password):
        if DISARM:
            print_debug(f"OK: Attempted to change password for user {username} to 'REDACTED', but DISARMED")
            return False
        try:
            # RHEL's chpasswd works identically to Debian's
            cmd = f"echo '{username}:{new_password}' | chpasswd"
            result = run_bash(cmd)
            if result.returncode != 0:
                raise Exception(f"chpasswd command failed - {result.stderr.strip()}")
            
            print_debug(f"OK: Changed password for user {username}")
            return True
        except Exception as E:
            print_debug(f"ERROR: change_password({username}) - {E}")
            return False

    def lock_account(self, username, should_be_locked):
        if DISARM:
            print_debug(f"OK: Attempted to change lock state for user {username} to {should_be_locked}', but DISARMED")
            return False
        try:
            action = "--lock" if should_be_locked else "--unlock"
            result = run_bash(f"usermod {action} {shlex.quote(username)}")
            if result.returncode != 0:
                raise Exception(f"usermod {action} failed - {result.stdout.strip()}")

            status = "Locked/disabled" if should_be_locked else "Unlocked/enabled"
            print_debug(f"OK: {status} account for user {username}")
            return True
        except Exception as E:
            print_debug(f"ERROR: lock_account({username}) - {E}")
            return False

    def set_admin_status(self, username, should_be_admin):
        if DISARM:
            print_debug(f"OK: Attempted to change admin state for user {username} to {should_be_admin}, but DISARMED")
            return False
        try:
            if should_be_admin:
                # -aG appends the user to 'wheel'
                res = run_bash(f"usermod -aG {self.admingrpname} {shlex.quote(username)}")
            else:
                # gpasswd -d is standard for removing from groups in RHEL
                res = run_bash(f"gpasswd -d {shlex.quote(username)} {self.admingrpname}")
            
            if (res.returncode != 0) and should_be_admin:
                raise Exception(f"Admin status update failed - {res.stderr}")
                
            status = "Added Admin access to" if should_be_admin else "Removed Admin access from"
            print_debug(f"OK: {status} user {username}")
            return True
        except Exception as E:
            print_debug(f"ERROR: set_admin_status({username}) - {E}")
            return False

    def delete_user(self, username):
        if DISARM:
            print_debug(f"OK: Attempted to delete user {username}, but DISARMED")
            return False
        try:
            # Keep home dir for later analysis
            result = run_bash(f"userdel {shlex.quote(username)}")
            if result.returncode != 0:
                raise Exception(f"userdel command failed - {result.stderr.strip()}")
            print_debug(f"OK: Deleted user {username}")
            return True
        except Exception as E:
            print_debug(f"ERROR: delete_user({username}) - {E}")
            return False

    def create_user(self, username, password, should_be_admin):
        if DISARM:
            print_debug(f"OK: Attempted to create user {username} but password 'REDACTED' and admin status {should_be_admin}, but DISARMED")
            return False
        try:
            # RHEL useradd -m is explicit home directory creation
            create_cmd = f"useradd -m {shlex.quote(username)}"
            result = run_bash(create_cmd)
            if result.returncode != 0:
                raise Exception(f"useradd command failed - {result.stderr.split()}")
            
            if not self.change_password(username, password):
                raise Exception("Initial password set failed")

            if should_be_admin:
                if not self.set_admin_status(username, True):
                    raise Exception("Initial admin promotion failed")
            return True
        except Exception as E:
            print_debug(f"ERROR: create_user({username}) - {E}")
            return False

class AlpineProvider(UserProvider):
    def __init__(self):
        # Alpine uses 'wheel' for privileged access
        self.admingrpname = "wheel"

    def _get_last_login(self, username, uid):
        """
        Alpine/musl does not natively support the utmp/lastlog binary format.
        Unless 'shadow-login' is installed, /var/log/lastlog will not exist.
        """
        binary_path = '/var/log/lastlog'
        if os.path.exists(binary_path):
            # If the file exists, we can try the Debian-style binary parse
            # (Implementation omitted for brevity, identical to DebianProvider)
            pass

        # Most Alpine containers/installs rely on 'last' from the 'util-linux' package
        # if telemetry is needed. Otherwise, BusyBox 'last' is very limited.
        res = run_bash(f"last | grep {shlex.quote(username)}", noisy=False)
        if res.stdout.strip():
            return 1
        return 0

    def get_all_users(self):
        try:
            users = []
            try:
                admins = grp.getgrnam(self.admingrpname).gr_mem
            except KeyError as E:
                print_debug(f"ERROR: get_all_users - failed to get admin list: {E}")
                admins = []

            for p in pwd.getpwall():
                try:
                    # Filter for human users
                    if p.pw_uid < 1000 and p.pw_name != "root":
                        continue

                    # Lock Status: Alpine's BusyBox passwd -S output is different.
                    # It usually shows 'L' for locked, 'P' for password.
                    is_locked = False
                    result = run_bash(f"passwd -S {shlex.quote(p.pw_name)}")
                    if result.returncode == 0:
                        parts = result.stdout.strip().split()
                        # BusyBox passwd -S: "username L 03/15/2026 ..."
                        # BusyBox / standard Linux passwd -S format:
                        # Index 0: username
                        # Index 1: status flag ('L'=locked, 'P'=unlocked/password, 'NP'=no password)
                        
                        if len(parts) >= 2:
                            # 3. Only flip to True if we explicitly see the 'L' flag
                            if parts[1] == 'L':
                                is_locked = True
                        #if len(parts) >= 2 and parts[1] == 'P':
                        #    is_locked = False
                    else:
                        print_debug(f"get_all_users() - failed to execute passwd -S - {result.stderr.stdout()}")

                    users.append({
                        'username': p.pw_name,
                        'admin': p.pw_name in admins or p.pw_name == "root",
                        'locked': is_locked,
                        'last_login': self._get_last_login(p.pw_name, p.pw_uid),
                        'account_type': "local"
                    })
                except Exception as E:
                    print_debug(f"WARNING: get_all_users iteration for {p.pw_name} failed: {E}")

            return users
        except Exception as E:
            print_debug(f"ERROR: get_all_users - {E}")
            return []

    def change_password(self, username, new_password):
        if DISARM:
            print_debug(f"OK: Attempted to change password for user {username} to 'REDACTED', but DISARMED")
            return False
        try:
            # Alpine's chpasswd works similarly
            cmd = f"echo '{username}:{new_password}' | chpasswd"
            result = run_bash(cmd)
            if result.returncode != 0:
                raise Exception(f"chpasswd failed - {result.stderr.strip()}")
            return True
        except Exception as E:
            print_debug(f"ERROR: change_password({username}) - {E}")
            return False

    def lock_account(self, username, should_be_locked):
        if DISARM:
            print_debug(f"OK: Attempted to change lock state for user {username} to {should_be_locked}', but DISARMED")
            return False
        try:
            # BusyBox usermod uses -L and -U
            action = "-L" if should_be_locked else "-U"
            result = run_bash(f"usermod {action} {shlex.quote(username)}")
            if result.returncode != 0:
                raise Exception(f"usermod {action} failed - {result.stderr.strip()}")
            return True
        except Exception as E:
            print_debug(f"ERROR: lock_account({username}) - {E}")
            return False

    def set_admin_status(self, username, should_be_admin):
        if DISARM:
            print_debug(f"OK: Attempted to change admin state for user {username} to {should_be_admin}, but DISARMED")
            return False
        try:
            if should_be_admin:
                # Add user to wheel group
                res = run_bash(f"addgroup {shlex.quote(username)} {self.admingrpname}")
            else:
                # Remove user from wheel group (delgroup user group)
                res = run_bash(f"delgroup {shlex.quote(username)} {self.admingrpname}")
            
            if (res.returncode != 0) and should_be_admin:
                raise Exception(f"Admin status update failed - {res.stderr.strip()}")
            return True
        except Exception as E:
            print_debug(f"ERROR: set_admin_status({username}) - {E}")
            return False

    def delete_user(self, username):
        if DISARM:
            print_debug(f"OK: Attempted to delete user {username}, but DISARMED")
            return False
        try:
            result = run_bash(f"deluser {shlex.quote(username)}")
            if result.returncode != 0:
                raise Exception(f"deluser command failed - {result.stderr.strip()}")
            return True
        except Exception as E:
            print_debug(f"ERROR: delete_user({username}) - {E}")
            return False

    def create_user(self, username, password, should_be_admin):
        if DISARM:
            print_debug(f"OK: Attempted to create user {username} but password 'REDACTED' and admin status {should_be_admin}, but DISARMED")
            return False
        try:
            # Alpine uses 'adduser' (BusyBox) or 'useradd' (shadow)
            # -D suppresses password prompt
            create_cmd = f"adduser -D -s /bin/sh {shlex.quote(username)}"
            result = run_bash(create_cmd)
            if result.returncode != 0:
                raise Exception(f"adduser command failed - {result.stderr.strip()}")
            
            self.change_password(username, password)
            if should_be_admin:
                self.set_admin_status(username, True)
            return True
        except Exception as E:
            print_debug(f"ERROR: create_user({username}) - {E}")
            return False
        
class FreeBSDProvider(UserProvider):
    def __init__(self):
        # FreeBSD uses 'wheel' to allow 'su -' or sudo access
        self.admingrpname = "wheel"

    def _get_last_login(self, username, uid):
        """
        FreeBSD uses /var/log/lastlog, but the format differs from Linux.
        We fallback to the 'last' command which is robust on BSD.
        """
        # -n 1: Get most recent login
        # -h: No header
        res = run_bash(f"last -n 1 {shlex.quote(username)}", noisy=False)
        if "never logged in" not in res.stdout.strip().lower():
            # For a SIEM, an existence check is the baseline; 
            # parsing BSD 'last' output to Unix Epoch is brittle via CLI.
            return 1 
        return 0

    def get_all_users(self):
        try:
            users = []
            try:
                admins = grp.getgrnam(self.admingrpname).gr_mem
            except KeyError as E:
                print_debug(f"ERROR: get_all_users - failed to get admin list: {E}")
                admins = []

            for p in pwd.getpwall():
                try:
                    # Filter for human users (FreeBSD typically starts UIDs at 1000)
                    if p.pw_uid < 1000 and p.pw_name != "root":
                        continue

                    # Lock Status: FreeBSD stores 'bool' lock status in the login class 
                    # or via a prefix in the password field in /etc/master.passwd.
                    # The 'pw' utility is the cleanest way to check.
                    is_locked = False
                    # 'pw user show' returns info; we check the shell or account expiration
                    user_info = run_bash(f"pw user show {shlex.quote(p.pw_name)}", noisy=False)
                    # If account is locked, FreeBSD often appends '*LOCKED*' to the info string
                    if "*LOCKED*" in user_info.stdout.strip():
                        is_locked = True

                    users.append({
                        'username': p.pw_name,
                        'admin': p.pw_name in admins or p.pw_name == "root",
                        'locked': is_locked,
                        'last_login': self._get_last_login(p.pw_name, p.pw_uid),
                        'account_type': "local"
                    })
                except Exception as E:
                    print_debug(f"WARNING: get_all_users iteration for {p.pw_name} failed: {E}")

            print_debug(f"OK: Read {len(users)} users from system")
            return users
        except Exception as E:
            print_debug(f"ERROR: get_all_users - {E}")
            return []

    def change_password(self, username, new_password):
        if DISARM:
            print_debug(f"OK: Attempted to change password for user {username} to 'REDACTED', but DISARMED")
            return False
        try:
            # FreeBSD 'pw' accepts password via stdin
            cmd = f"echo {shlex.quote(new_password)} | pw usermod {shlex.quote(username)} -h 0"
            result = run_bash(cmd)
            if result.returncode != 0:
                raise Exception(f"pw usermod password update failed - {result.stderr.split()}")
            
            print_debug(f"OK: Changed password for user {username}")
            return True
        except Exception as E:
            print_debug(f"ERROR: change_password({username}) - {E}")
            return False

    def lock_account(self, username, should_be_locked):
        if DISARM:
            print_debug(f"OK: Attempted to change lock state for user {username} to {should_be_locked}', but DISARMED")
            return False
        try:
            action = "Locked/disabled" if should_be_locked else "Unlocked/enabled"
            result = run_bash(f"pw {action} {shlex.quote(username)}")
            if result.returncode != 0:
                raise Exception(f"pw {action} failed - {result.stderr.strip()}")

            print_debug(f"OK: {action.capitalize()}ed account for user {username}")
            return True
        except Exception as E:
            print_debug(f"ERROR: lock_account({username}) - {E}")
            return False

    def set_admin_status(self, username, should_be_admin):
        if DISARM:
            print_debug(f"OK: Attempted to change admin state for user {username} to {should_be_admin}, but DISARMED")
            return False
        try:
            if should_be_admin:
                # -m adds user to group in FreeBSD
                res = run_bash(f"pw groupmod {self.admingrpname} -m {shlex.quote(username)}")
            else:
                # -d deletes user from group
                res = run_bash(f"pw groupmod {self.admingrpname} -d {shlex.quote(username)}")
            
            if (res.returncode != 0) and should_be_admin:
                raise Exception("Admin status update failed")
                
            print_debug(f"OK: Updated admin status for {username}")
            return True
        except Exception as E:
            print_debug(f"ERROR: set_admin_status({username}) - {E}")
            return False

    def delete_user(self, username):
        if DISARM:
            print_debug(f"OK: Attempted to delete user {username}, but DISARMED")
            return False
        try:
            # -r removes home directory
            result = run_bash(f"pw userdel {shlex.quote(username)} -r")
            if result.returncode != 0:
                raise Exception(f"pw userdel failed - {result.stderr.strip()}")
            print_debug(f"OK: Deleted user {username}")
            return True
        except Exception as E:
            print_debug(f"ERROR: delete_user({username}) - {E}")
            return False

    def create_user(self, username, password, should_be_admin):
        if DISARM:
            print_debug(f"OK: Attempted to create user {username} but password 'REDACTED' and admin status {should_be_admin}, but DISARMED")
            return False
        try:
            # -n: name, -m: create home, -s: shell, -h 0: read password from stdin
            create_cmd = f"echo {shlex.quote(password)} | pw useradd {shlex.quote(username)} -m -s /bin/sh -h 0"
            result = run_bash(create_cmd)
            if result.returncode != 0:
                raise Exception(f"pw useradd failed - {result.stderr.strip()}")
            
            print_debug(f"OK: Created regular user {username}")
            
            if should_be_admin:
                if not self.set_admin_status(username, True):
                    raise Exception("Initial admin promotion failed")
            return True
        except Exception as E:
            print_debug(f"ERROR: create_user({username}) - {E}")
            return False
        
#endregion###############
###### Main Logic #######
#region##################

def main_logic(provider):
    """
    Implements one interation of the main program logic.

    Sends current user info to server and parses response for commands.
    TODO - If new user info does not match last user info, triggers an alert.

    Note that initial register message is handled in main()
    """
    
    users = provider.get_all_users()

    send_message(f"agent/beacon/{AGENT_TYPE}",True,True,str(users))

    try:
        while True:
            try:
                waiting_command = send_message(f"agent/get_task",True,True,"")
                print_debug(f"main_logic: received task msg {waiting_command}")

                if not waiting_command: # error
                    break
                if waiting_command == "no pending tasks":
                    break

                data = json.loads(waiting_command)
                task_id = data.get('task_id')
                task_command = data.get('task')
                local_index = data.get('local_index')

                parts = task_command.split(" ")
                status = False
                if parts[0] == "change_password":
                    status = provider.change_password(parts[1],parts[2])

                elif parts[0] == "lock_account":
                    boolEval = parts[2].strip().lower() == 'true'
                    status = provider.lock_account(parts[1],boolEval)

                elif parts[0] == "set_admin_status":
                    boolEval = parts[2].strip().lower() == 'true'
                    status = provider.set_admin_status(parts[1],boolEval)

                elif parts[0] == "delete_user":
                    status = provider.delete_user(parts[1])

                elif parts[0] == "create_user":
                    boolEval = parts[3].strip().lower() == 'true'
                    status = provider.create_user(parts[1],parts[2],boolEval)

                else:
                    print_debug(f"WARNING: main_logic - cmd parts[0] '{parts[0]}' does not match any known command")
                    status = False
                
                send_message(f"agent/set_task_result",True,True,json.dumps({"task_id": task_id, "result": str(status).lower()}, separators=(',', ':')))
            except Exception as E:
                print_debug(f"ERROR: unexpected error in main_logic iteration: {E}")
    except Exception as E:
        print_debug(f"ERROR: unexpected error in main_logic: {E}")
    return

#endregion###############
######### Main ##########
#region##################

def signal_handler(sig, frame):
    print_debug("Service stopping due to receiving signal handler")
    sys.exit(0)

def main(stop_event=None):
    global PAUSED

    # force the working directory to the script's location
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    send_message(f"agent/beacon/{AGENT_TYPE}",True,True,f"Register")

    print_debug(f"main(): System details - {get_system_details()}")

    try:
        provider = get_user_provider()
    except Exception as e:
        print_debug(f"CRITICAL: Failed to initialize User Management Provider: {e}")
        sys.exit(1)

    while True:

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
                send_message(f"agent/beacon/{AGENT_TYPE}",False,False,f"Agent moved into PAUSE status for {int(pausedEpochLocal - time.time())} seconds")
            else:
                send_message(f"agent/beacon/{AGENT_TYPE}",True,True,f"Agent moved into ACTIVE status (from PAUSE)")

        if not PAUSED:
            main_logic(provider)
            print_debug(f"main(): sleeping for {SLEEPTIME} seconds")
            print_debug(f"")
        else:
            if not suppressed_send:
                # Do not trigger alert
                send_message(f"agent/beacon/{AGENT_TYPE}",True,False,f"Agent still in PAUSE status for {int(pausedEpochLocal - time.time())} seconds remaining")
        
        time.sleep(SLEEPTIME)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    main()

#endregion###############