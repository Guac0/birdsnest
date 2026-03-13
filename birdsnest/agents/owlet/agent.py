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
import signal
import sys
from datetime import timedelta
try:
    import win32evtlog
    #import win32evtlogutil
    #import winreg
    #import win32serviceutil
    #import win32service
    #import win32event
    WINDOWS_LIBS_LOADED = True
except ImportError:
    WINDOWS_LIBS_LOADED = False
#import servicemanager
#import threading

#endregion###############
# Configuration Options #
#region##################

CONFIG_DEFAULTS = {
    "AGENT_NAME": "ssh",
    "AUTH_TOKEN": "testtoken",
    "AUTH_LOG_PATH": "",
    "AUTH_PARSER": "",
    "SLEEPTIME": 60,
    "SERVER_URL": "https://127.0.0.1:8000/",
    "SERVER_TIMEOUT": 5,
    "DEBUG_PRINT": True,
    "LOGFILE": "log.txt",
    "STATUSFILE": "status.txt",
    "STATE_FILE": "state.json",
    "AGENT_TYPE": "owlet"
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
AUTH_LOG_PATH = CONFIG["AUTH_LOG_PATH"]
AUTH_PARSER = CONFIG["AUTH_PARSER"]

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
    Unified getter for Linux (Debian, RHEL, Alpine) and FreeBSD.
    Uses shutil.which to locate binaries dynamically across different distributions.
    """
    system = platform.system()
    
    # 1. Try 'ip addr' first (Standard for modern Linux: Debian, RHEL, Alpine)
    # We check for the 'ip' binary regardless of the 'system' being Linux, 
    # but specifically skip for FreeBSD as 'ip' usually refers to something else there.
    if system == "Linux":
        ip_bin = shutil.which("ip")
        if ip_bin:
            try:
                output = subprocess.check_output([ip_bin, "-4", "addr"], text=True)
                iface = None
                for line in output.splitlines():
                    # Match interface headers: "2: eth0: <BROADCAST...>"
                    header_match = re.match(r"^\d+:\s+([^:@\s]+)", line.strip())
                    if header_match:
                        iface = header_match.group(1)
                    # Match the IP line associated with the above interface
                    if "inet " in line and ip in line:
                        return iface
            except Exception:
                pass

    # 2. Try 'ifconfig' (Primary for FreeBSD, fallback for Alpine/BusyBox)
    ifconfig_bin = shutil.which("ifconfig")
    if ifconfig_bin:
        try:
            output = subprocess.check_output([ifconfig_bin], text=True)
            iface = None
            
            for line in output.splitlines():
                # Headers start at the beginning of the line: "eth0: ..." or "em0: ..."
                # This regex works for both BSD-style and Linux-style ifconfig output.
                header_match = re.match(r"^([a-zA-Z0-9._-]+)[:\s]", line)
                if header_match:
                    iface = header_match.group(1)
                
                # Check for the IP in the indented lines following the header
                if "inet " in line and ip in line:
                    return iface
        except Exception:
            pass

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
        executable_path = shutil.which("bash")
        
        # Fallback to standard sh if bash isn't installed
        if not executable_path:
            executable_path = "/bin/sh"

        result = subprocess.run(
            cmd,
            shell=True,
            executable=executable_path,
            capture_output=True, 
            text=True,
            check=False # Do not raise a CalledProcessError on non-zero exit code
        )
    except FileNotFoundError:
        if noisy:
            print_debug("Error: The /bin/bash executable was not found.")
        return ""
    
    if result.returncode != 0:
        if noisy:
            # Errors usually go to stderr, but we can also print the exit code
            print_debug(f"Shell command failed with exit code {result.returncode}")
            if result.stderr:
                print_debug(f"Shell stderr: {result.stderr.strip()}")
        return ""
        
    return result.stdout.strip()

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

def send_message(endpoint,oldStatus=True,newStatus=True,message="",authInfo=None,systemInfo=get_system_details()):
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
                if endpoint == "agent/beacon/owlet":
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
# Parsers ##
#region##################

def get_native_parser():
    """Detects OS and returns the appropriate parser class."""
    if os.path.exists("/etc/debian_version"):
        return DebianAuthParser(), "/var/log/auth.log", JournalAuthWatcher()
    elif os.path.exists("/etc/redhat-release") or os.path.exists("/etc/rocky-release"):
        return RedHatParser(), "/var/log/secure", JournalAuthWatcher()
    elif os.path.exists("/etc/alpine-release"):
        return AlpineParser(), "/var/log/messages", AuthWatcher()
    elif os.uname().sysname == "FreeBSD":
        return FreeBSDParser(), "/var/log/auth.log", AuthWatcher()
    elif "windows" in platform.system().lower():
        if not WINDOWS_LIBS_LOADED:
            print_debug("CRITICAL: Windows detected but pywin32 not installed.")
            return None, None, None
        return WindowsAuthParser(), "N/A", WindowsAuthWatcher()
    else:
        # Fallback to a generic syslog parser
        return DebianAuthParser(), "/var/log/auth.log", AuthWatcher()
    
class BaseParser:
    """Interface for different log formats."""
    def parse_line(self, line):
        raise NotImplementedError("Each parser must implement parse_line")
    
    # Unified wrapper to separate timestamp from the message content
    # Works for ISO8601 (Modern) and Legacy Syslog
    TS_WRAPPER = re.compile(
        r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?|[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(.*)'
    )

    def _parse_timestamp(self, ts_str):
        """Standardized timestamp resolver for all child parsers."""
        now = datetime.now()
        if 'T' in ts_str: # Modern ISO
            try:
                return datetime.fromisoformat(ts_str.replace('Z', '+00:00')).timestamp()
            except ValueError: pass
        try: # Legacy Syslog
            dt = datetime.strptime(ts_str, "%b %d %H:%M:%S").replace(year=now.year)
            if dt > now + timedelta(days=1): dt = dt.replace(year=now.year - 1)
            return dt.timestamp()
        except ValueError: pass
        return None
    
    def _format_record(self, sig_type, match, epoch_or_line):
        """
        Standardized formatter shared by all OS-specific parsers.
        Works for Windows Events, Journald, and Syslog (FreeBSD/Alpine).
        """
        # 1. Handle Timestamp: Prioritize provided epoch from parser
        if isinstance(epoch_or_line, (int, float)):
            epoch = epoch_or_line
        else:
            # Fallback if parser didn't calculate epoch (deprecated behavior)
            epoch = int(time.time())
        
        # 2. Extract named groups from the regex match
        groups = match.groupdict()
        user = groups.get('user', 'unknown')
        ip = groups.get('ip', '127.0.0.1')
        
        # 3. Base Record Structure
        res = {
            "timestamp": epoch,
            "user": user,
            "srcip": ip,
            "login_type": sig_type,
            "successful": True  # Default to True, corrected by 'status' or sig_type
        }

        # 4. Success/Failure Logic (Unified for sshd, login, and Windows)
        # Checks for 'Accepted', 'success', 'opened', or Windows 'Success'
        if 'status' in groups:
            status_val = groups['status'].lower()
            res["successful"] = any(x in status_val for x in ["accept", "success", "open", "audit success"])
        
        # 5. Handle SSH Invalid Users (Always failure)
        if sig_type == "ssh_invalid":
            res["successful"] = False

        # 6. Unified Elevation Logic (Works for 'sudo' on Linux and 'su' on FreeBSD)
        # If the regex captured a source user, we format the transition: e.g., "su(alice->root)"
        if 'src_user' in groups:
            src = groups.get('src_user', 'unknown')
            # Extracts 'sudo' or 'su' from the sig_type and formats transition
            prefix = sig_type.split('_')[0] 
            res["login_type"] = f"{prefix}({src}->{user})"
            
        # 7. Windows Specific: Domain context (Optional)
        if 'domain' in groups and groups['domain'] not in ['NT AUTHORITY', '']:
            res["user"] = f"{groups['domain']}\\{user}"
            
        return res
    
    def __repr__(self):
        return f"NotImplemented Parser"

class DebianAuthParser(BaseParser):
    """
    Parses /var/log/auth.log for SSH attempts and Privilege Elevation.
    Supports ISO8601 (Modern Debian/RHEL) and RFC3339/Legacy Syslog (Alpine/FreeBSD).
    """
    def __init__(self):
        self.signatures = [
            # 1. SSH Password & Public Key
            {
                "type": "ssh_auth",
                "regex": re.compile(r"sshd\[\d+\]: (?P<status>Accepted|Failed) (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+)"),
            },
            # 2. Sudo Execution
            {
                "type": "sudo_elevation",
                "regex": re.compile(r"sudo:\s+(?P<src_user>\S+) : TTY=.* ; USER=(?P<user>\S+) ; COMMAND=(?P<cmd>.*)"),
            },
            # 3. Invalid User SSH Attempt
            {
                "type": "ssh_invalid",
                "regex": re.compile(r"sshd\[\d+\]: Invalid user (?P<user>\S+) from (?P<ip>\S+)"),
            }
        ]
        
        # Capture either:
        # Group 1 (ISO): 2026-03-13T02:59:42.123456+00:00
        # Group 2 (Legacy): Mar 13 02:11:41
        self.ts_wrapper_pattern = re.compile(
            r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?|[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(.*)'
        )

    def _parse_timestamp(self, ts_str):
        """
        Flexible timestamp parser for cross-platform log formats.
        """
        now = datetime.now()
        
        # Handle Modern ISO 8601 (Debian 12+, RHEL 9+)
        if 'T' in ts_str:
            try:
                # Replace Z with +00:00 for older Python 3.x compatibility
                clean_ts = ts_str.replace('Z', '+00:00')
                dt = datetime.fromisoformat(clean_ts)
                return dt.timestamp()
            except ValueError:
                pass

        # Handle Legacy Syslog (Alpine, FreeBSD, Debian 11-)
        try:
            # Format: Mar 13 02:11:41
            dt = datetime.strptime(ts_str, "%b %d %H:%M:%S")
            
            # Syslog is yearless; inject current year
            dt = dt.replace(year=now.year)
            
            # Handle the New Year's Eve rollover edge case
            if dt > now + timedelta(days=1):
                dt = dt.replace(year=now.year - 1)
                
            return dt.timestamp()
        except ValueError:
            pass

        return None

    def parse_line(self, line):
        match = self.ts_wrapper_pattern.match(line)
        if not match:
            return None
            
        ts_str = match.group(1)
        remaining_content = match.group(2)
        
        epoch = self._parse_timestamp(ts_str)
        if epoch is None:
            return None

        for sig in self.signatures:
            # We search the remaining_content to avoid regex overlap with the timestamp
            attr_match = sig['regex'].search(remaining_content)
            if attr_match:
                return self._format_record(sig['type'], attr_match, epoch)
        
        return None

    def __repr__(self):
        return f"DebianAuthParser"

class RedHatParser(BaseParser):
    def __init__(self):
        self.signatures = [
            {"type": "ssh_auth", "regex": re.compile(r"sshd\[\d+\]: (?P<status>Accepted|Failed) \S+ for (?P<user>\S+) from (?P<ip>\S+)")},
            {"type": "ssh_invalid", "regex": re.compile(r"sshd\[\d+\]: Invalid user (?P<user>\S+) from (?P<ip>\S+)")}
        ]

    def parse_line(self, line):
        m = self.TS_WRAPPER.match(line)
        if not m: return None
        epoch = self._parse_timestamp(m.group(1))
        if not epoch: return None
        
        content = m.group(2)
        for sig in self.signatures:
            match = sig['regex'].search(content)
            if match:
                return self._format_record(sig['type'], match, epoch)
        return None

    def __repr__(self):
        return f"RedHatParser"

class AlpineParser(BaseParser):
    """Parses /var/log/messages for Alpine (BusyBox)."""
    def __init__(self):
        self.signatures = [
            {"type": "ssh_auth", "regex": re.compile(r"(?:auth\.info )?sshd\[\d+\]: (?P<status>Accepted|Failed) \S+ for (?P<user>\S+) from (?P<ip>\S+)")},
            {"type": "sudo_elevation", "regex": re.compile(r"(?:auth\.info )?sudo:\s+(?P<src_user>\S+) :.*USER=(?P<user>\S+) ; COMMAND=(?P<cmd>.*)")}
        ]

    def parse_line(self, line):
        m = self.TS_WRAPPER.match(line)
        if not m: return None
        epoch = self._parse_timestamp(m.group(1))
        if not epoch: return None

        content = m.group(2)
        for sig in self.signatures:
            match = sig['regex'].search(content)
            if match:
                return self._format_record(sig['type'], match, epoch)
        return None

    def __repr__(self):
        return f"AlpineParser"

class FreeBSDParser(BaseParser):
    """
    Parses /var/log/auth.log for FreeBSD.
    Handles traditional BSD syslog format and local auth utilities like su and login.
    """
    def __init__(self):
        self.signatures = [
            # 1. SSH attempts (FreeBSD format includes 'port' detail)
            {
                "type": "ssh_auth", 
                "regex": re.compile(r"sshd\[\d+\]: (?P<status>Accepted|Failed) (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port")
            },
            # 2. su elevation (Captures source user and target user: "alice to root")
            {
                "type": "su_elevation", 
                "regex": re.compile(r"su\[\d+\]: (?P<src_user>\S+) to (?P<user>\S+) on (?P<tty>\S+)")
            },
            # 3. Console login failures
            {
                "type": "console_fail", 
                "regex": re.compile(r"login: FAIL on (?P<tty>\S+) for (?P<user>\S+), password incorrect")
            },
            # 4. Invalid User SSH Attempt
            {
                "type": "ssh_invalid",
                "regex": re.compile(r"sshd\[\d+\]: Invalid user (?P<user>\S+) from (?P<ip>\S+)")
            }
        ]

    def parse_line(self, line):
        # 1. Use the BaseParser wrapper to split timestamp from the rest of the line
        match = self.TS_WRAPPER.match(line)
        if not match:
            return None
            
        ts_str = match.group(1)
        remaining_content = match.group(2)
        
        # 2. Resolve the timestamp using the inherited logic (handles yearless BSD logs)
        epoch = self._parse_timestamp(ts_str)
        if epoch is None:
            return None

        # 3. Match against FreeBSD specific security signatures
        for sig in self.signatures:
            attr_match = sig['regex'].search(remaining_content)
            if attr_match:
                # _format_record handles the transition logic for su(src->target)
                return self._format_record(sig['type'], attr_match, epoch)
        
        return None

    def __repr__(self):
        return f"FreeBSDParser"

class WindowsAuthParser(BaseParser):
    """
    Parses Windows Security Event Logs.
    Optimized for 4624/4625 with LogonType filtering to reduce noise.
    """
    def __init__(self):
        self.log_type = "Security"
        self.event_ids = {4624: True, 4625: False}
        self.ignored_users = ["SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON"]
        # Only monitor Interactive (2), RDP (10), and Cached (11) logons
        self.interesting_logon_types = ["2", "10", "11"]

    def parse_event(self, event):
        event_id = event.EventID & 0xFFFF
        if event_id not in self.event_ids:
            return None

        inserts = event.StringInserts
        # Ensure we have the minimum required fields for a standard 4624/4625 event
        if not inserts or len(inserts) < 19:
            return None

        try:
            # Standard indices (Vista through Server 2022):
            user = inserts[5]
            domain = inserts[6]
            logon_type = inserts[8]
            ip = inserts[18]

            # 1. Filter out background system noise
            if user.upper() in self.ignored_users or user.endswith('$'):
                return None

            # 2. Filter by Logon Type (The 'Noise Filter')
            # If it's a success (4624), only care about interactive/RDP sessions.
            # We usually keep all failures (4625) to catch brute force attempts.
            if event_id == 4624 and logon_type not in self.interesting_logon_types:
                return None

            # 3. IP Normalization
            if ip in ["-", "::1", "127.0.0.1"]:
                ip = "127.0.0.1"

            # 4. Use your existing _format_record logic
            # Note: We pass the event.RecordNumber as part of the unique ID context
            class MockMatch:
                def __init__(self, data): self.data = data
                def groupdict(self): return self.data

            mock_match = MockMatch({
                "user": user,
                "domain": domain,
                "ip": ip,
                "logon_type_code": logon_type, # Useful for debugging
                "status": "success" if self.event_ids[event_id] else "failed"
            })

            # Get the epoch from the event object
            epoch = int(event.TimeGenerated.timestamp())
            
            return self._format_record("win_auth", mock_match, epoch)

        except Exception:
            return None

    def __repr__(self):
        return "WindowsAuthParser"
    
#endregion###############
###### Main Logic #######
#region##################

class AlertThrottler:
    def __init__(self, threshold=10, window=60, max_entries=1000):
        self.threshold = threshold
        self.window = window
        self.max_entries = max_entries  # Hard limit on unique IPs in memory
        self.history = {}
        self.suppressed = set()
        self.last_cleanup = time.time()

    def _cleanup_all(self):
        """
        Hybrid cleanup: 
        1. Time-based (Every 10 mins) to clear stale records.
        2. Size-based (Immediate) if memory exceeds max_entries.
        """
        now = time.time()
        
        # 1. Periodic Time-Based Cleanup
        if now - self.last_cleanup >= 600:
            expired_ips = []
            for ip, timestamps in self.history.items():
                # Prune old timestamps from the list
                self.history[ip] = [t for t in timestamps if now - t < self.window]
                if not self.history[ip]:
                    expired_ips.append(ip)
            
            for ip in expired_ips:
                self._purge_ip(ip)
            
            self.last_cleanup = now

        # 2. Urgent Size-Based Cleanup (LRU Eviction)
        if len(self.history) > self.max_entries:
            # Sort IPs by their most recent activity (the last timestamp in their list)
            # and remove the oldest ones until we are back under the limit.
            sorted_ips = sorted(self.history.keys(), key=lambda x: self.history[x][-1])
            excess_count = len(self.history) - self.max_entries
            
            for i in range(excess_count):
                self._purge_ip(sorted_ips[i])

    def _purge_ip(self, ip):
        """Helper to cleanly remove an IP from all tracking sets."""
        if ip in self.history:
            del self.history[ip]
        if ip in self.suppressed:
            self.suppressed.remove(ip)

    def should_throttle(self, ip):
        now = time.time()
        self._cleanup_all()

        if ip not in self.history:
            self.history[ip] = []
        
        # Clean current IP history to ensure 'attempt_count' is accurate for this window
        self.history[ip] = [t for t in self.history[ip] if now - t < self.window]
        
        currently_suppressed = ip in self.suppressed
        attempt_count = len(self.history[ip])

        # State: Moving from PROCEED -> THROTTLE
        if attempt_count >= self.threshold and not currently_suppressed:
            self.suppressed.add(ip)
            # Return immediately; the calling logic sends the START_THROTTLE alert
            return "START_THROTTLE"

        # State: Already suppressed
        if currently_suppressed:
            # Check for recovery: count has dropped significantly (hysteresis)
            if attempt_count < (self.threshold / 2):
                self.suppressed.remove(ip)
                self.history[ip].append(now)
                return "END_THROTTLE"
            
            # Still flooding: record attempt for window tracking but signal silence
            self.history[ip].append(now)
            return "SILENCE"

        # State: Normal operation
        self.history[ip].append(now)
        return "PROCEED"
    
class AuthWatcher:
    def __init__(self, parser, auth_log):
        self.parser = parser
        self.auth_log = auth_log
        self.config = self.fetch_config()
        self.last_scan_time = self.load_state()
        self.throttler = AlertThrottler(threshold=5, window=60)
        self.seen_signatures = set()

    def fetch_config(self):
        """
        Fetches both entity lists and global policy settings from the server.
        Merges them into a unified config dictionary.
        """
        base_config = {
            "users": {"legitimate": [], "malicious": []},
            "ips": {"legitimate": [], "malicious": []}
        }
        
        # 1. Fetch Entity Lists
        got_config = send_message("agent/list_authconfig_agent")
        if got_config:
            base_config.update(json.loads(got_config))
        else:
            print_debug(f"Error fetching entity lists")

        # 2. Fetch Global Policy Settings
        global_settings = send_message("agent/list_authconfigglobal")
        if global_settings:
            try:
                global_settings = json.loads(global_settings)
                # Convert string booleans from DB ("true"/"false") to Python bools
                for key, val in global_settings.items():
                    if isinstance(val, str):
                        if val.lower() == "true": val = True
                        elif val.lower() == "false": val = False
                    base_config[key] = val
            except Exception as E:
                print_debug(f"Error applying global config, using default fallbacks. error: {E}")
                # Default fallbacks if server is unreachable
                base_config.setdefault("strict_user", False)
                base_config.setdefault("strict_ip", False)
                base_config.setdefault("create_incident", False)
                base_config.setdefault("log_attempt_successful", True)
        else:
            print_debug(f"Error fetching global config, using default fallbacks")
            # Default fallbacks if server is unreachable
            base_config.setdefault("strict_user", False)
            base_config.setdefault("strict_ip", False)
            base_config.setdefault("create_incident", False)
            base_config.setdefault("log_attempt_successful", True)

        print_debug(f"fetch_config(): returning config - {base_config}")
        return base_config

    def load_state(self):
        if os.path.exists(STATE_FILE):
            with open(STATE_FILE, 'r') as f:
                return json.load(f).get("last_scan", time.time())
        return int(time.time())# - 3600 # Default to now if no state exists

    def save_state(self, timestamp):
        temp_file = f"{STATE_FILE}.tmp"
        try:
            with open(temp_file, 'w') as f:
                json.dump({"last_scan": int(timestamp)}, f)
                f.flush()
                os.fsync(f.fileno()) # Ensure data is physically on disk
            os.replace(temp_file, STATE_FILE) # Atomic swap
        except Exception as e:
            print_debug(f"save_state(): Failed to save state: {e}")

    def analyze_log(self):
        new_last_scan = self.load_state()
        self.last_scan_time = new_last_scan
        sent_msg = False
        records_to_process = []
        
        if not os.path.exists(self.auth_log):
            return sent_msg

        file_size = os.path.getsize(self.auth_log)
        if file_size == 0:
            return sent_msg

        with open(self.auth_log, 'rb') as f:
            f.seek(0, os.SEEK_END)
            pointer = f.tell()
            buffer = b""
            chunk_size = 4096
            reached_cutoff = False

            while pointer > 0 and not reached_cutoff:
                if pointer - chunk_size > 0:
                    pointer -= chunk_size
                    f.seek(pointer)
                    chunk = f.read(chunk_size)
                else:
                    f.seek(0)
                    chunk = f.read(pointer)
                    pointer = 0

                chunk += buffer
                lines = chunk.splitlines()

                if pointer > 0:
                    buffer = lines.pop(0)
                else:
                    # pointer is 0, so 'buffer' is no longer needed; 
                    # all lines in this final chunk are complete.
                    buffer = b""

                for line in reversed(lines):
                    decoded_line = line.decode('utf-8', errors='replace')
                    record = self.parser.parse_line(decoded_line)
                    if not record: continue

                    # Generate a unique hash for this log line
                    import hashlib
                    line_sig = hashlib.md5(line).hexdigest()

                    # CHANGE: Don't stop on equality, only stop if strictly OLDER
                    if record['timestamp'] < self.last_scan_time:
                        reached_cutoff = True
                        break
                    
                    # If the timestamp is the same as our cutoff, check if we've seen this exact line
                    if record['timestamp'] == self.last_scan_time:
                        if line_sig in self.seen_signatures:
                            continue
                            
                    records_to_process.append(record)
                    # Track signatures of logs that occurred at the NEW highest timestamp
                    if record['timestamp'] > new_last_scan:
                        new_last_scan = record['timestamp']
                        # Reset signatures for the new "current" second
                        self.temp_signatures = {line_sig}
                    elif record['timestamp'] == new_last_scan:
                        self.temp_signatures.add(line_sig)
            
            # FIX: Process the leftover buffer if we haven't reached the cutoff
            if not reached_cutoff and buffer:
                decoded_line = buffer.decode('utf-8', errors='replace')
                record = self.parser.parse_line(decoded_line)
                if record and record['timestamp'] > self.last_scan_time:
                    records_to_process.append(record)
                    if record['timestamp'] > new_last_scan:
                        new_last_scan = record['timestamp']

        records_to_process.reverse()
        for record in records_to_process:
            if self.evaluate_threat(record):
                sent_msg = True

        # Update state to the timestamp of the newest log we've seen
        self.seen_signatures = self.temp_signatures
        self.save_state(new_last_scan)
        return sent_msg

    def evaluate_threat(self, auth):
        """
        Processes a single auth event, applies flood protection, 
        and determines if a beacon should be sent.
        """
        ip = auth.get('srcip', '127.0.0.1')
        user = auth.get('user', 'unknown')
        
        # 1. Check Flood Protection status FIRST
        throttle_status = self.throttler.should_throttle(ip)
        
        if throttle_status == "SILENCE":
            print_debug(f"evaluate_threat(): IP {ip} is silenced. Ignoring log.")
            return False

        # 2. Determine Malicious Status (Policy Checks)
        strict_ip = self.config.get('strict_ip', False)
        strict_user = self.config.get('strict_user', False)
        
        is_mal_user = user in self.config['users']['malicious'] if not strict_user else user not in self.config['users']['legitimate']
        is_mal_ip = ip in self.config['ips']['malicious'] if not strict_ip else ip not in self.config['ips']['legitimate']
        is_malicious = is_mal_user or is_mal_ip

        # 3. Define Default Statuses
        # oldStatus: False = Potential threat detected
        # newStatus: False = Successful compromise (Malicious user + Successful login)
        old_status = not is_malicious
        new_status = not (is_malicious and auth['successful'])
        msg = None

        # 4. Message Construction Priority
        if throttle_status == "START_THROTTLE":
            msg = f"FLOOD CONTROL: IP {ip} is being throttled for excessive login attempts."
            old_status = False  # Force an 'Unhealthy' status so the dashboard flags it
            
        elif throttle_status == "END_THROTTLE":
            msg = f"FLOOD CONTROL: IP {ip} is no longer being throttled."
            old_status = True   # Mark as resolved/healthy
            new_status = True
            
        elif is_mal_user and is_mal_ip:
            msg = f"SECURITY ALERT: Known malicious user {user} from malicious IP {ip}"
        elif is_mal_user:
            msg = f"SECURITY ALERT: Malicious user access: {user}"
        elif is_mal_ip:
            msg = f"SECURITY ALERT: Access from malicious IP: {ip}"

        # 5. Final Dispatch
        if msg:
            print_debug(f"evaluate_threat(): Sending beacon - {msg}")
            send_message("agent/beacon/owlet", old_status, new_status, msg, authInfo=auth)
            return True

        # No threat, no throttle change, no alert needed
        return False

class JournalAuthWatcher(AuthWatcher):
    """
    A robust watcher that reads /var/log/auth.log (or secure) 
    but falls back to journalctl if the file is missing.
    """
    def get_journal_logs(self, since_timestamp):
        # Format: 2026-03-13 02:11:41
        since_str = datetime.fromtimestamp(since_timestamp).strftime('%Y-%m-%d %H:%M:%S')
    
        # CHANGE: Listen for both SSHD and general AUTH logs (sudo/su)
        cmd = [
            "journalctl", 
            "SYSLOG_FACILITY=4", # 4 is the 'auth' facility
            "SYSLOG_FACILITY=10", # 10 is 'authpriv'
            "--since", since_str, 
            "--output=short-iso", 
            "--no-pager"
        ]
        
        try:
            # Note: This requires the agent to run with sudo/root privileges to read the journal
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return result.stdout.splitlines()
        except Exception as e:
            print_debug(f"JournalAuthWatcher: Failed to query journalctl: {e}")
            return []

    def analyze_log(self):
        # If the physical file exists, use the high-speed binary backtracker
        if os.path.exists(self.auth_log) and os.path.getsize(self.auth_log) > 0:
            return super().analyze_log()
        
        # Fallback for Debian 12+ and RHEL 9+
        print_debug(f"JournalAuthWatcher: {self.auth_log} not found. Using journalctl fallback.")
        self.last_scan_time = self.load_state()
        lines = self.get_journal_logs(self.last_scan_time)
        
        records_to_process = []
        new_last_scan = self.last_scan_time
        sent_msg = False

        for line in lines:
            record = self.parser.parse_line(line)
            if record and record['timestamp'] > self.last_scan_time:
                records_to_process.append(record)
                if record['timestamp'] > new_last_scan:
                    new_last_scan = record['timestamp']

        for record in records_to_process:
            if self.evaluate_threat(record):
                sent_msg = True

        self.save_state(new_last_scan)
        return sent_msg

if WINDOWS_LIBS_LOADED:
    class WindowsAuthWatcher(AuthWatcher):
        def load_state(self):
            if os.path.exists(STATE_FILE):
                with open(STATE_FILE, 'r') as f:
                    state = json.load(f)
                    # Support both Linux (last_scan) and Windows (last_record)
                    return state.get("last_record", 0), state.get("last_scan", time.time())
            return 0, int(time.time())

        def analyze_log(self):
            """Overrides analyze_log to use Windows Event API."""
            last_record, last_timestamp = self.load_state()
            server = 'localhost'
            handle = win32evtlog.OpenEventLog(server, self.parser.log_type)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            sent_msg = False
            records_to_process = []
            reached_cutoff = False
            new_last_scan = self.last_scan_time

            while not reached_cutoff:
                events = win32evtlog.ReadEventLog(handle, flags, 0)
                if not events:
                    break
                
                for event in events:
                    # CHANGE: Use RecordNumber as the primary cutoff
                    if event.RecordNumber <= last_record:
                        reached_cutoff = True
                        break
                        
                    record = self.parser.parse_event(event)
                    if record:
                        records_to_process.append(record)
                        # Update state with the highest record number seen
                        if event.RecordNumber > new_last_record:
                            new_last_record = event.RecordNumber
                        
                        if reached_cutoff: break

            records_to_process.reverse()
            for record in records_to_process:
                # FIX: Capture the threat return value
                if self.evaluate_threat(record):
                    sent_msg = True

            self.save_state(new_last_scan)
            win32evtlog.CloseEventLog(handle)
            return sent_msg
else:
    # This prevents the program from crashing if WindowsAuthWatcher is referenced 
    # in an OS-generic loop or factory.
    class WindowsAuthWatcher:
        def __init__(self, *args, **kwargs):
            pass
        def analyze_log(self):
            # Log a debug message or just return False
            return False

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

    send_message("agent/beacon/owlet",True,True,f"Register")

    #oldStatus = True
    #newStatus = True
    #oldIssues = []
    #newIssues = []

    print_debug(f"main(): System details - {get_system_details()}")

    PARSER_MAP = {
        "debian": DebianAuthParser,
        "ubuntu": DebianAuthParser,
        "rhel": RedHatParser,
        "rocky": RedHatParser,
        "alpine": AlpineParser,
        "freebsd": FreeBSDParser
    }

    parser, log_path, watcherObj = get_native_parser()
    if AUTH_LOG_PATH:
        log_path = AUTH_LOG_PATH
    if AUTH_PARSER:
        parser = PARSER_MAP.get(AUTH_PARSER.lower(), parser)
    watcher = watcherObj(parser,log_path)
    print_debug(f"Selected parser {parser} and log path {log_path}")

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
                send_message("agent/beacon/owlet",False,False,f"Agent moved into PAUSE status for {int(pausedEpochLocal - time.time())} seconds")
            else:
                send_message("agent/beacon/owlet",True,True,f"Agent moved into ACTIVE status (from PAUSE)")

        if not PAUSED:

            # Files
            watcher.config = watcher.fetch_config()
            sent_msg = watcher.analyze_log()

            if not sent_msg:
                send_message("agent/beacon/owlet",True,True,"all good")

            # Finish up
            #print_debug(f"main(): oldStatus - {oldStatus}")
            #print_debug(f"main(): newStatus - {newStatus}")
            #for issue in issues:
                #print_debug(f"main(): issue - {issue}")
                #send_message("agent/beacon/owlet",oldStatus,newStatus,issue)
            
            print_debug(f"main(): sleeping for {SLEEPTIME} seconds")
            print_debug(f"")

            #oldIssues = newIssues
            #newIssues = []
        else:
            if not suppressed_send:
                # Do not trigger alert
                send_message("agent/beacon/owlet",True,False,f"Agent still in PAUSE status for {int(pausedEpochLocal - time.time())} seconds remaining")
        
        time.sleep(SLEEPTIME)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    main()

#endregion###############