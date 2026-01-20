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
    "AGENT_NAME": "ssh",
    "AUTH_TOKEN": "testtoken",
    "AUTH_LOG_PATH": "",
    "AUTH_PARSER": "",
    "SLEEPTIME": 60,
    "SERVER_URL": "https://127.0.0.1:8080/",
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
        result = subprocess.run(
            cmd,
            shell=True,
            executable="/bin/bash", # Explicitly use bash for consistency
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

def send_message(oldStatus,newStatus,message,authInfo=None,systemInfo=get_system_details()):
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
# Parsers ##
#region##################

def get_native_parser():
    """Detects OS and returns the appropriate parser class."""
    if os.path.exists("/etc/debian_version"):
        return DebianAuthParser(), "/var/log/auth.log"
    elif os.path.exists("/etc/redhat-release") or os.path.exists("/etc/rocky-release"):
        return RedHatParser(), "/var/log/secure"
    elif os.path.exists("/etc/alpine-release"):
        return AlpineParser(), "/var/log/messages"
    elif os.uname().sysname == "FreeBSD":
        return FreeBSDParser(), "/var/log/auth.log"
    else:
        # Fallback to a generic syslog parser
        return DebianAuthParser(), "/var/log/auth.log"
    
class BaseParser:
    """Interface for different log formats."""
    def parse_line(self, line):
        raise NotImplementedError("Each parser must implement parse_line")
    def __repr__(self):
        return f"NotImplemented Parser"

class DebianAuthParser(BaseParser):
    """
    Parses /var/log/auth.log for SSH attempts and Privilege Elevation.
    """
    def __init__(self):
        # We define a list of signatures to check against each line
        self.signatures = [
            # 1. SSH Password Success/Fail
            {
                "type": "ssh_auth",
                "regex": re.compile(r"sshd\[\d+\]: (?P<status>Accepted|Failed) password for (?P<user>\S+) from (?P<ip>\S+)"),
            },
            # 2. SSH Public Key Success
            {
                "type": "ssh_pubkey",
                "regex": re.compile(r"sshd\[\d+\]: Accepted publickey for (?P<user>\S+) from (?P<ip>\S+)"),
            },
            # 3. Sudo Execution (Elevation)
            {
                "type": "sudo_elevation",
                "regex": re.compile(r"sudo:\s+(?P<src_user>\S+) : TTY=.* ; USER=(?P<user>\S+) ; COMMAND=(?P<cmd>.*)"),
            },
            # 4. Invalid User SSH Attempt
            {
                "type": "ssh_invalid",
                "regex": re.compile(r"sshd\[\d+\]: Invalid user (?P<user>\S+) from (?P<ip>\S+)"),
            }
        ]
        
        # Base timestamp regex (Jan 18 12:00:01)
        #self.ts_pattern = re.compile(r"^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>[\d:]+)") #old
        self.ts_pattern = re.compile(r"^(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})T(?P<time>[\d:.]+)(?P<timezone>[+-]\d{2}:\d{2})")

    def parse_line(self, line):
        # First, extract timestamp
        ts_match = self.ts_pattern.match(line)
        if not ts_match:
            return None
            
        ts_str = f"{datetime.now().year} {ts_match.group('month')} {ts_match.group('day')} {ts_match.group('time')}"
        #epoch = int(time.mktime(time.strptime(ts_str, "%Y %b %d %H:%M:%S")))
        epoch = int(time.mktime(time.strptime(ts_str, "%Y %m %d %H:%M:%S.%f"))) #iso

        # Check against each signature
        for sig in self.signatures:
            match = sig['regex'].search(line)
            if match:
                return self._format_record(sig['type'], match, epoch)
        
        return None

    def _format_record(self, sig_type, match, epoch):
        # Default successful to False unless explicitly 'Accepted' or a Sudo command
        res = {
            "timestamp": epoch,
            "user": match.group('user'),
            "srcip": match.group('ip') if 'ip' in match.groupdict() else "127.0.0.1",
            "login_type": sig_type,
            "successful": True 
        }

        if sig_type == "ssh_auth":
            res["successful"] = (match.group('status') == "Accepted")
        elif sig_type == "ssh_invalid":
            res["successful"] = False
        elif sig_type == "sudo_elevation":
            # For sudo, we note the source user in the 'notes' or similar field
            res["login_type"] = f"sudo({match.group('src_user')}->{match.group('user')})"
            # We treat the execution itself as a 'success' event to log
            
        return res

    def __repr__(self):
        return f"DebianAuthParser"

class RedHatParser(BaseParser):
    """Parses /var/log/secure for RHEL/Rocky/CentOS."""
    def __init__(self):
        self.log_path = "/var/log/secure"
        self.signatures = [
            # SSH Auth (Password/Key/Invalid)
            {"type": "ssh", "regex": re.compile(r"sshd\[\d+\]: (?P<status>Accepted|Failed) (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+)")},
            {"type": "ssh_invalid", "regex": re.compile(r"sshd\[\d+\]: Invalid user (?P<user>\S+) from (?P<ip>\S+)")},
            # Sudo Elevation
            {"type": "sudo", "regex": re.compile(r"sudo:.* ; USER=(?P<user>\S+) ; COMMAND=(?P<cmd>.*)")},
            # Direct su to root
            {"type": "su_elevation", "regex": re.compile(r"su: pam_unix\(su-l:session\): session opened for user root by (?P<src_user>\S+)")}
        ]

    def parse_line(self, line):
        # RHEL/Rocky often use same MMM DD HH:MM:SS format as Debian
        for sig in self.signatures:
            match = sig['regex'].search(line)
            if match:
                return self._format_record(sig['type'], match, line)
        return None

    def __repr__(self):
        return f"RedHatParser"

class AlpineParser(BaseParser):
    """Parses /var/log/messages for Alpine (BusyBox)."""
    def __init__(self):
        self.log_path = "/var/log/messages"
        self.signatures = [
            # Alpine sshd logs are often simplified
            {"type": "ssh", "regex": re.compile(r"auth\.info sshd\[\d+\]: (?P<status>Accepted|Failed) (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+)")},
            # Alpine sudo (if installed)
            {"type": "sudo", "regex": re.compile(r"auth\.info sudo:.*USER=(?P<user>\S+); COMMAND=(?P<cmd>.*)")}
        ]

    def parse_line(self, line):
        for sig in self.signatures:
            match = sig['regex'].search(line)
            if match:
                return self._format_record(sig['type'], match, line)
        return None

    def __repr__(self):
        return f"AlpineParser"

class FreeBSDParser(BaseParser):
    """Parses /var/log/auth.log for FreeBSD."""
    def __init__(self):
        self.log_path = "/var/log/auth.log"
        self.signatures = [
            # SSH attempts
            {"type": "ssh", "regex": re.compile(r"sshd\[\d+\]: (?P<status>Accepted|Failed) (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port")},
            # FreeBSD 'su' is very common for elevation
            {"type": "su_elevation", "regex": re.compile(r"su\[\d+\]: (?P<src_user>\S+) to root on (?P<tty>\S+)")},
            # Login failures on tty/console
            {"type": "console_fail", "regex": re.compile(r"login: FAIL on (?P<tty>\S+) for (?P<user>\S+), password incorrect")}
        ]

    def parse_line(self, line):
        for sig in self.signatures:
            match = sig['regex'].search(line)
            if match:
                return self._format_record(sig['type'], match, line)
        return None

    def __repr__(self):
        return f"FreeBSDParser"
    
#endregion###############
###### Main Logic #######
#region##################

class AlertThrottler:
    def __init__(self, threshold=10, window=60):
        self.threshold = threshold  # Max alerts before suppression
        self.window = window        # Time window in seconds
        self.history = {}           # { ip: [timestamps] }
        self.suppressed = set()      # IPs currently being silenced

    def should_throttle(self, ip):
        now = time.time()
        if ip not in self.history:
            self.history[ip] = []
        
        # Clean old timestamps outside the window
        self.history[ip] = [t for t in self.history[ip] if now - t < self.window]
        self.history[ip].append(now)

        if len(self.history[ip]) > self.threshold:
            if ip not in self.suppressed:
                self.suppressed.add(ip)
                return "START_THROTTLE" # Signal to send one last warning
            return "SILENCE"
        
        if ip in self.suppressed and len(self.history[ip]) < (self.threshold / 2):
            self.suppressed.remove(ip)
            return "END_THROTTLE"
            
        return "PROCEED"
        
class AuthWatcher:
    def __init__(self, parser, auth_log):
        self.parser = parser
        self.auth_log = auth_log
        self.config = self.fetch_config()
        self.last_scan_time = self.load_state()
        self.throttler = AlertThrottler(threshold=5, window=60)

    def fetch_config(self):
        """
        Fetches both entity lists and global policy settings from the server.
        Merges them into a unified config dictionary.
        """
        base_config = {
            "users": {"legitimate": [], "malicious": []},
            "ips": {"legitimate": [], "malicious": []}
        }
        
        # 1. Fetch Entity Lists (GET)
        try:
            with urllib.request.urlopen(SERVER_URL + "list_authconfig_agent", timeout=SERVER_TIMEOUT, context=CTX) as r:
                base_config.update(json.loads(r.read().decode()))
        except Exception as e:
            print_debug(f"Error fetching entity lists: {e}")

        # 2. Fetch Global Policy Settings (POST)
        try:
            req = urllib.request.Request(
                SERVER_URL + "list_authconfigglobal", 
                data=json.dumps({}).encode(), # Sending empty JSON for POST
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=SERVER_TIMEOUT, context=CTX) as r:
                global_settings = json.loads(r.read().decode())
                # Convert string booleans from DB ("true"/"false") to Python bools
                for key, val in global_settings.items():
                    if isinstance(val, str):
                        if val.lower() == "true": val = True
                        elif val.lower() == "false": val = False
                    base_config[key] = val
        except Exception as e:
            print_debug(f"Error fetching global config: {e}")
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
        with open(STATE_FILE, 'w') as f:
            json.dump({"last_scan": int(timestamp)}, f)

    def analyze_log(self):
        new_last_scan = self.load_state()
        self.last_scan_time = new_last_scan
        sent_msg = False
        
        # List to hold new records (since we find them in reverse, we'll flip them later)
        records_to_process = []
        
        print_debug(f"analyze_log(): starting with last scan time of {datetime.fromtimestamp(new_last_scan).strftime('%Y-%m-%d %H:%M:%S')} ({new_last_scan})")
        
        if not os.path.exists(self.auth_log):
            print_debug(f"analyze_log(): auth_log does not exist! path: {self.auth_log}")
            return sent_msg

        file_size = os.path.getsize(self.auth_log)
        if file_size == 0:
            print_debug("analyze_log(): auth_log is empty.")
            return sent_msg

        with open(self.auth_log, 'rb') as f:
            # Move pointer to the very end of the file
            f.seek(0, os.SEEK_END)
            pointer = f.tell()
            buffer = b""
            chunk_size = 4096  # 4KB chunks are usually optimal for I/O
            reached_cutoff = False

            #print_debug(f"analyze_log(): seeking backward from end of file ({file_size} bytes)")

            while pointer > 0 and not reached_cutoff:
                # Determine how much to read (don't over-read past start of file)
                if pointer - chunk_size > 0:
                    pointer -= chunk_size
                    f.seek(pointer)
                    chunk = f.read(chunk_size)
                else:
                    # We are at the beginning of the file
                    f.seek(0)
                    chunk = f.read(pointer)
                    pointer = 0

                # Combine new chunk with leftover data from previous chunk
                chunk += buffer
                lines = chunk.splitlines()

                # The first line of a chunk might be partial; save it for the next loop
                if pointer > 0:
                    buffer = lines.pop(0)
                else:
                    buffer = b""

                # Process the lines in this chunk from bottom to top
                for line in reversed(lines):
                    decoded_line = line.decode('utf-8', errors='ignore')
                    print_debug(f"analyze_log(): sending line to parser: {decoded_line}")
                    record = self.parser.parse_line(decoded_line)

                    if record:
                        if record['timestamp'] > self.last_scan_time:
                            records_to_process.append(record)
                            # Keep track of the most recent timestamp seen
                            if record['timestamp'] > new_last_scan:
                                new_last_scan = record['timestamp']
                        else:
                            # Found a record older or equal to our last scan! Stop reading.
                            print_debug(f"analyze_log(): found cutoff at timestamp {record['timestamp']}. Stopping backtracker.")
                            reached_cutoff = True
                            break

        # Since we collected them backward, reverse them to process chronologically
        records_to_process.reverse()
        print_debug(f"analyze_log(): found {len(records_to_process)} new records to evaluate.")

        for record in records_to_process:
            if self.evaluate_threat(record):
                sent_msg = True

        new_last_scan = time.time()
        self.save_state(new_last_scan)
        print_debug(f"analyze_log(): exiting, saving state with timestamp {new_last_scan}")

        return sent_msg

    def evaluate_threat(self, auth):
        """
        Processes a single auth event, applies flood protection, 
        and determines if a beacon should be sent.
        """
        # 2. Determine Malicious Status based on Config + Policy
        # Pull flags from the config (handled during fetch_config)
        strict_ip = self.config.get('strict_ip', False)
        strict_user = self.config.get('strict_user', False)

        ip = auth.get('srcip', '127.0.0.1')
        user = auth.get('user', 'unknown')
        print_debug(f"evaluate_threat(): srcip: {ip}, user: {user}, strict_user: {strict_user}, strict_ip: {strict_ip}")
        
        # 1. Check Flood Protection status
        throttle_status = self.throttler.should_throttle(ip)
        
        if throttle_status == "SILENCE":
            # Log line ignored to prevent server flooding
            print_debug("evaluate_threat(): SILENCED")
            return False
        
        # User Evaluation
        is_mal_user = False
        if strict_user:
            # Strict: Malicious if NOT in legitimate list
            if user not in self.config['users']['legitimate']:
                is_mal_user = True
        else:
            # Permissive: Malicious only if in malicious list
            if user in self.config['users']['malicious']:
                is_mal_user = True

        # IP Evaluation
        is_mal_ip = False
        if strict_ip:
            # Strict: Malicious if NOT in legitimate list
            if ip not in self.config['ips']['legitimate']:
                is_mal_ip = True
        else:
            # Permissive: Malicious only if in malicious list
            if ip in self.config['ips']['malicious']:
                is_mal_ip = True

        # Aggregate Threat Status
        is_malicious = is_mal_user or is_mal_ip

        # 3. Construct Message and Statuses
        # oldStatus (False = Malicious activity detected)
        # newStatus (False = Malicious activity AND successful login)
        old_status = not is_malicious
        new_status = not (is_malicious and auth['successful'])

        if throttle_status == "START_THROTTLE":
            msg = f"FLOOD CONTROL: IP {ip} is being throttled for excessive login attempts."
        elif is_mal_user and is_mal_ip:
            msg = f"SECURITY ALERT: Known malicious user {user} from malicious IP {ip}"
        elif is_mal_user:
            msg = f"SECURITY ALERT: Malicious user access: {user}"
        elif is_mal_ip:
            msg = f"SECURITY ALERT: Access from malicious IP: {ip}"
        else:
            # If not malicious and not flooding, we do not send a beacon
            print_debug(f"evaluate_threat(): item is not malicious, ignoring. strict_user: {strict_user}, strict_ip: {strict_ip}")
            return False

        # 4. Final Beacon Dispatch
        self.send_message(old_status, new_status, msg, authInfo=auth)
        return True

#endregion###############
######### Main ##########
#region##################

def main(stop_event=None):
    global PAUSED

    send_message(True,True,f"Register")

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

    parser, log_path = get_native_parser()
    if AUTH_LOG_PATH:
        log_path = AUTH_LOG_PATH
    if AUTH_PARSER:
        parser = PARSER_MAP.get(AUTH_PARSER.lower(), parser)
    watcher = AuthWatcher(parser,log_path)
    print_debug(f"Selected parser {parser} and log path {log_path}")

    while True:

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

            # Files
            watcher.config = watcher.fetch_config()
            sent_msg = watcher.analyze_log()

            if not sent_msg:
                send_message(True,True,"all good")

            # Finish up
            #print_debug(f"main(): oldStatus - {oldStatus}")
            #print_debug(f"main(): newStatus - {newStatus}")
            #for issue in issues:
                #print_debug(f"main(): issue - {issue}")
                #send_message(oldStatus,newStatus,issue)
            
            print_debug(f"main(): sleeping for {SLEEPTIME} seconds")
            print_debug(f"")

            #oldIssues = newIssues
            #newIssues = []
        else:
            if not suppressed_send:
                # Do not trigger alert
                send_message(True,False,f"Agent still in PAUSE status for {int(pausedEpochLocal - time.time())} seconds remaining")
        
        time.sleep(SLEEPTIME)

if __name__ == "__main__":
    main()

#endregion###############