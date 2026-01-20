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
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    for key, value in config.items():
        if isinstance(value, str):
            config[key] = value.format(
                HOST=config.get("HOST"),
                PORT=config.get("PORT"),
                timestamp=timestamp
            )
    if badPath:
        print(f"[-] {timestamp} load_config(): config file path not found: {path}")
        with open(config.get("LOGFILE"), "a") as f: 
            f.write(f"[{timestamp}] CRITICAL - load_config(): config file path not found: {path}")
    return config
CONFIG = load_config("config.json") 
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
    if sys_platform == "Windows":
        release, version, csd, ptype = platform.win32_ver()
        return ("Windows", release, version)
    if sys_platform == "Linux":
        if hasattr(platform, 'freedesktop_os_release'):
            try:
                info = platform.freedesktop_os_release()
                return (info.get('ID', 'linux'), info.get('VERSION_ID', ''), info.get('NAME', ''))
            except OSError:
                pass
        if os.path.isfile("/etc/os-release"):
            info = {}
            with open("/etc/os-release") as f:
                for line in f:
                    match = re.match(r'^([A-Z_]+)="?([^"\n]+)"?$', line)
                    if match:
                        info[match.group(1)] = match.group(2)
            return (
                info.get('ID', 'linux'), 
                info.get('VERSION_ID', info.get('VERSION', '')), 
                info.get('PRETTY_NAME', '')
            )
    return (sys_platform, platform.release(), platform.version())
def get_os(simple=False):
    system = platform.system()
    if system == "Linux":
        if simple:
            return get_platform_dist()[1] 
        return ' '.join(get_platform_dist()) 
    if simple:
        return platform.system() 
    return f"{platform.system()} {platform.release()}" 
def get_perms():
    system = platform.system()
    if system == "Windows":
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            is_admin = False
        domain = os.environ.get("USERDOMAIN", None)
        user = getpass.getuser()
        if domain:
            runAsUser = f"{domain}\\{user}"
        else:
            runAsUser = user
        return is_admin, runAsUser
    if system in ("Linux", "FreeBSD"):
        is_root = (os.geteuid() == 0)
        sudo_user = os.environ.get("SUDO_USER")
        if sudo_user:
            runAsUser = sudo_user
        else:
            runAsUser = getpass.getuser()
        return is_root, runAsUser
    print_debug("get_perms(): reached unexpected unsupported OS block")
    return False, runAsUser
def get_primary_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80)) 
        ip_address = s.getsockname()[0]
    except Exception as E:
        ip_address = "0.0.0.0"
        print_debug(f"get_primary_ip(): {E}")
    finally:
        s.close()
    return ip_address
def interface_get_primary():
    system = platform.system()
    if system == "Windows":
        return interface_get_primary_windows(get_primary_ip())
    else:
        return interface_get_primary_linux(get_primary_ip())
def interface_get_primary_windows(ip):
    output = subprocess.check_output(["ipconfig"], text=True, encoding="utf-8", errors="ignore")
    current_iface = None
    for line in output.splitlines():
        line = line.strip()
        m = re.match(r"(.+?) adapter (.+?):", line, re.IGNORECASE)
        if m:
            current_iface = m.group(2)
            continue
        if "IPv4 Address" in line and ip in line:
            return current_iface
    return None
def interface_get_primary_linux(ip):
    try:
        output = subprocess.check_output(["ip", "-4", "addr"], text=True)
        iface = None
        for line in output.splitlines():
            line = line.strip()
            m = re.match(r"\d+:\s+([^:]+):", line)
            if m:
                iface = m.group(1)
                continue
            if line.startswith("inet ") and ip in line:
                return iface
    except Exception:
        pass
    try:
        output = subprocess.check_output(["ifconfig"], text=True)
        iface = None
        for line in output.splitlines():
            m = re.match(r"^([a-zA-Z0-9._-]+):\s", line)
            if m:
                iface = m.group(1)
                continue
            if "inet " in line and ip in line:
                return iface
    except Exception:
        pass
    return None
def get_system_details():
    sysInfo = {
        "os": get_os(),
        "executionUser": get_perms()[1],
        "executionAdmin": get_perms()[0],
        "hostname": socket.gethostname(), 
        "ipadd": get_primary_ip()
    }
    return sysInfo
def run_powershell(cmd,noisy=True):
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", cmd],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        if noisy:
            print_debug(f"PowerShell error: {result.stderr}")
        return "" 
    return result.stdout
def run_bash(cmd, noisy=True):
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            executable="/bin/bash", 
            capture_output=True, 
            text=True,
            check=False 
        )
    except FileNotFoundError:
        if noisy:
            print_debug("Error: The /bin/bash executable was not found.")
        return ""
    if result.returncode != 0:
        if noisy:
            print_debug(f"Shell command failed with exit code {result.returncode}")
            if result.stderr:
                print_debug(f"Shell stderr: {result.stderr.strip()}")
        return ""
    return result.stdout.strip()
def get_pause_status(file=STATUSFILE):
    try:
        with open(file,"r+") as f:
            firstline = f.readline().strip()
            if len(firstline) < 1:
                return False,False,0
            preferServer = firstline.lower() == "true"
            pausedUntilEpoch = float(f.readline().strip())
            if round(pausedUntilEpoch) != 0:
                if pausedUntilEpoch > time.time():
                    return preferServer, True, pausedUntilEpoch
                else:
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
        with open(file,"w") as f:
            f.write(f"false\n0\n")
        return False, False, 0
    except Exception as E:
        print_debug(f"get_pause_status(): unknown error - {E}")
        with open(file,"w") as f:
            f.write(f"false\n0\n")
        return False, False, 0
def send_message(oldStatus,newStatus,message,authInfo=None,systemInfo=get_system_details()):
    if not SERVER_URL:
        return True
    url = SERVER_URL + "beacon"
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
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=SERVER_TIMEOUT, context=CTX) as response:
            if response.getcode() == 200:
                print_debug(f"send_message(): sent msg to server: [{oldStatus,newStatus,message}]")
                return response.read()
            else:
                print_debug(f"send_message(): Server error: {response.getcode()}")
    except urllib.error.HTTPError as e:
        print_debug(f"[send_message(): HTTP error: {e.code} {e.reason}")
    except urllib.error.URLError as e:
        print_debug(f"send_message(): URL error: {e.reason}")
    except Exception as e:
        print_debug(f"send_message(): Beacon error: {e}")
    return False
def get_pause_state_server(systemInfo=get_system_details()):
    if not SERVER_URL:
        return True
    url = SERVER_URL + "get_pause"
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
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=SERVER_TIMEOUT, context=CTX) as response:
            if response.getcode() == 200:
                response_body = response.read().decode("utf-8")
                timeInt = float(response_body)
                print_debug(f"get_pause_state_server(): sent msg to server with response {response_body}")
                return timeInt
            else:
                print_debug(f"get_pause_state_server(): Server error: {response.getcode()}")
    except urllib.error.HTTPError as e:
        print_debug(f"get_pause_state_server(): HTTP error: {e.code} {e.reason}")
    except urllib.error.URLError as e:
        print_debug(f"get_pause_state_server(): URL error: {e.reason}")
    except ValueError:
        print_debug(f"get_pause_state_server(): could not convert received value to int")
    except Exception as e:
        print_debug(f"get_pause_state_server(): Beacon error: {e}")
    return -1
def get_native_parser():
    if os.path.exists("/etc/debian_version"):
        return DebianAuthParser(), "/var/log/auth.log", AuthWatcher()
    elif os.path.exists("/etc/redhat-release") or os.path.exists("/etc/rocky-release"):
        return RedHatParser(), "/var/log/secure", AuthWatcher()
    elif os.path.exists("/etc/alpine-release"):
        return AlpineParser(), "/var/log/messages", AuthWatcher()
    elif os.uname().sysname == "FreeBSD":
        return FreeBSDParser(), "/var/log/auth.log", AuthWatcher()
    elif "windows" in platform.system().lower():
        return WindowsAuthParser(), "N/A", WindowsAuthWatcher()
    else:
        return DebianAuthParser(), "/var/log/auth.log", AuthWatcher()
class BaseParser:
    def parse_line(self, line):
        raise NotImplementedError("Each parser must implement parse_line")
    def __repr__(self):
        return f"NotImplemented Parser"
class DebianAuthParser(BaseParser):
    def __init__(self):
        self.signatures = [
            {
                "type": "ssh_auth",
                "regex": re.compile(r"sshd\[\d+\]: (?P<status>Accepted|Failed) password for (?P<user>\S+) from (?P<ip>\S+)"),
            },
            {
                "type": "ssh_pubkey",
                "regex": re.compile(r"sshd\[\d+\]: Accepted publickey for (?P<user>\S+) from (?P<ip>\S+)"),
            },
            {
                "type": "sudo_elevation",
                "regex": re.compile(r"sudo:\s+(?P<src_user>\S+) : TTY=.* ; USER=(?P<user>\S+) ; COMMAND=(?P<cmd>.*)"),
            },
            {
                "type": "ssh_invalid",
                "regex": re.compile(r"sshd\[\d+\]: Invalid user (?P<user>\S+) from (?P<ip>\S+)"),
            }
        ]
        self.ts_pattern = re.compile(r"^(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})T(?P<time>[\d:.]+)(?P<timezone>[+-]\d{2}:\d{2})")
    def parse_line(self, line):
        ts_match = self.ts_pattern.match(line)
        if not ts_match:
            return None
        ts_str = f"{datetime.now().year} {ts_match.group('month')} {ts_match.group('day')} {ts_match.group('time')}"
        epoch = int(time.mktime(time.strptime(ts_str, "%Y %m %d %H:%M:%S.%f"))) 
        for sig in self.signatures:
            match = sig['regex'].search(line)
            if match:
                return self._format_record(sig['type'], match, epoch)
        return None
    def _format_record(self, sig_type, match, epoch):
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
            res["login_type"] = f"sudo({match.group('src_user')}->{match.group('user')})"
        return res
    def __repr__(self):
        return f"DebianAuthParser"
class RedHatParser(BaseParser):
    def __init__(self):
        self.log_path = "/var/log/secure"
        self.signatures = [
            {"type": "ssh", "regex": re.compile(r"sshd\[\d+\]: (?P<status>Accepted|Failed) (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+)")},
            {"type": "ssh_invalid", "regex": re.compile(r"sshd\[\d+\]: Invalid user (?P<user>\S+) from (?P<ip>\S+)")},
            {"type": "sudo", "regex": re.compile(r"sudo:.* ; USER=(?P<user>\S+) ; COMMAND=(?P<cmd>.*)")},
            {"type": "su_elevation", "regex": re.compile(r"su: pam_unix\(su-l:session\): session opened for user root by (?P<src_user>\S+)")}
        ]
    def parse_line(self, line):
        for sig in self.signatures:
            match = sig['regex'].search(line)
            if match:
                return self._format_record(sig['type'], match, line)
        return None
    def __repr__(self):
        return f"RedHatParser"
class AlpineParser(BaseParser):
    def __init__(self):
        self.log_path = "/var/log/messages"
        self.signatures = [
            {"type": "ssh", "regex": re.compile(r"auth\.info sshd\[\d+\]: (?P<status>Accepted|Failed) (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+)")},
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
    def __init__(self):
        self.log_path = "/var/log/auth.log"
        self.signatures = [
            {"type": "ssh", "regex": re.compile(r"sshd\[\d+\]: (?P<status>Accepted|Failed) (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port")},
            {"type": "su_elevation", "regex": re.compile(r"su\[\d+\]: (?P<src_user>\S+) to root on (?P<tty>\S+)")},
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
class WindowsAuthParser:
    def __init__(self):
        self.log_type = "Security"
        self.event_ids = {4624: True, 4625: False}
    def _get_timestamp(self, event):
        return int(event.TimeGenerated.timestamp())
    def parse_event(self, event):
        event_id = event.EventID & 0xFFFF 
        if event_id not in self.event_ids:
            return None
        try:
            user = event.StringInserts[5] if len(event.StringInserts) > 5 else "unknown"
            ip = event.StringInserts[18] if len(event.StringInserts) > 18 else "127.0.0.1"
            if ip == "-" or ip == "::1": ip = "127.0.0.1"
            return {
                "timestamp": self._get_timestamp(event),
                "user": user,
                "srcip": ip,
                "successful": self.event_ids[event_id],
                "type": "win_auth",
                "raw": f"WinEvent {event_id}: {user} from {ip}"
            }
        except Exception as e:
            print(f"Error parsing Windows Event: {e}")
            return None
    def __repr__(self):
        return "WindowsAuthParser"
class AlertThrottler:
    def __init__(self, threshold=10, window=60):
        self.threshold = threshold  
        self.window = window        
        self.history = {}           
        self.suppressed = set()      
    def should_throttle(self, ip):
        now = time.time()
        if ip not in self.history:
            self.history[ip] = []
        self.history[ip] = [t for t in self.history[ip] if now - t < self.window]
        self.history[ip].append(now)
        if len(self.history[ip]) > self.threshold:
            if ip not in self.suppressed:
                self.suppressed.add(ip)
                return "START_THROTTLE" 
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
        base_config = {
            "users": {"legitimate": [], "malicious": []},
            "ips": {"legitimate": [], "malicious": []}
        }
        try:
            with urllib.request.urlopen(SERVER_URL + "list_authconfig_agent", timeout=SERVER_TIMEOUT, context=CTX) as r:
                base_config.update(json.loads(r.read().decode()))
        except Exception as e:
            print_debug(f"Error fetching entity lists: {e}")
        try:
            req = urllib.request.Request(
                SERVER_URL + "list_authconfigglobal", 
                data=json.dumps({}).encode(), 
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=SERVER_TIMEOUT, context=CTX) as r:
                global_settings = json.loads(r.read().decode())
                for key, val in global_settings.items():
                    if isinstance(val, str):
                        if val.lower() == "true": val = True
                        elif val.lower() == "false": val = False
                    base_config[key] = val
        except Exception as e:
            print_debug(f"Error fetching global config: {e}")
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
        return int(time.time())
    def save_state(self, timestamp):
        with open(STATE_FILE, 'w') as f:
            json.dump({"last_scan": int(timestamp)}, f)
    def analyze_log(self):
        new_last_scan = self.load_state()
        self.last_scan_time = new_last_scan
        sent_msg = False
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
                    buffer = b""
                for line in reversed(lines):
                    decoded_line = line.decode('utf-8', errors='ignore')
                    print_debug(f"analyze_log(): sending line to parser: {decoded_line}")
                    record = self.parser.parse_line(decoded_line)
                    if record:
                        if record['timestamp'] > self.last_scan_time:
                            records_to_process.append(record)
                            if record['timestamp'] > new_last_scan:
                                new_last_scan = record['timestamp']
                        else:
                            print_debug(f"analyze_log(): found cutoff at timestamp {record['timestamp']}. Stopping backtracker.")
                            reached_cutoff = True
                            break
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
        strict_ip = self.config.get('strict_ip', False)
        strict_user = self.config.get('strict_user', False)
        ip = auth.get('srcip', '127.0.0.1')
        user = auth.get('user', 'unknown')
        print_debug(f"evaluate_threat(): srcip: {ip}, user: {user}, strict_user: {strict_user}, strict_ip: {strict_ip}")
        throttle_status = self.throttler.should_throttle(ip)
        if throttle_status == "SILENCE":
            print_debug("evaluate_threat(): SILENCED")
            return False
        is_mal_user = False
        if strict_user:
            if user not in self.config['users']['legitimate']:
                is_mal_user = True
        else:
            if user in self.config['users']['malicious']:
                is_mal_user = True
        is_mal_ip = False
        if strict_ip:
            if ip not in self.config['ips']['legitimate']:
                is_mal_ip = True
        else:
            if ip in self.config['ips']['malicious']:
                is_mal_ip = True
        is_malicious = is_mal_user or is_mal_ip
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
            print_debug(f"evaluate_threat(): item is not malicious, ignoring. strict_user: {strict_user}, strict_ip: {strict_ip}")
            return False
        self.send_message(old_status, new_status, msg, authInfo=auth)
        return True
class WindowsAuthWatcher(AuthWatcher):
    def analyze_log(self):
        server = 'localhost'
        handle = win32evtlog.OpenEventLog(server, self.parser.log_type)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        records_to_process = []
        reached_cutoff = False
        print_debug(f"Starting Windows Event Scan. Last scan: {self.last_scan_time}")
        while not reached_cutoff:
            events = win32evtlog.ReadEventLog(handle, flags, 0)
            if not events:
                break
            for event in events:
                record = self.parser.parse_event(event)
                if record:
                    if record['timestamp'] > self.last_scan_time:
                        records_to_process.append(record)
                    else:
                        reached_cutoff = True
                        break
            if reached_cutoff: break
        records_to_process.reverse() 
        for record in records_to_process:
            self.evaluate_threat(record)
        self.save_state(time.time())
        win32evtlog.CloseEventLog(handle)
def main(stop_event=None):
    global PAUSED
    send_message(True,True,f"Register")
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
        pausedEpochServer = get_pause_state_server()
        pausePreferServer, pausedStatus, pausedEpochLocal = get_pause_status()
        if pausedEpochServer != -1:
            if pausedEpochServer == 0:
                if pausePreferServer:
                    with open(STATUSFILE,"w") as f:
                        f.write(f"true\n0\n")
                    pausedStatus = False
                    pausedEpochLocal = 0
            else:
                if pausedEpochServer == 1:
                    with open(STATUSFILE,"w") as f:
                        f.write(f"{pausePreferServer}\n0\n")
                    pausedStatus = False
                    pausedEpochLocal = 0
                else:
                    with open(STATUSFILE,"w") as f:
                        f.write(f"{pausePreferServer}\n{pausedEpochServer}\n")
                    pausedStatus = True
                    pausedEpochLocal = pausedEpochServer
        sent_msg = False
        suppressed_send = False
        if PAUSED != pausedStatus:
            PAUSED = pausedStatus
            if PAUSED:
                suppressed_send = True
                send_message(False,False,f"Agent moved into PAUSE status for {int(pausedEpochLocal - time.time())} seconds")
            else:
                send_message(True,True,f"Agent moved into ACTIVE status (from PAUSE)")
        if not PAUSED:
            watcher.config = watcher.fetch_config()
            sent_msg = watcher.analyze_log()
            if not sent_msg:
                send_message(True,True,"all good")
            print_debug(f"main(): sleeping for {SLEEPTIME} seconds")
            print_debug(f"")
        else:
            if not suppressed_send:
                send_message(True,False,f"Agent still in PAUSE status for {int(pausedEpochLocal - time.time())} seconds remaining")
        time.sleep(SLEEPTIME)
if __name__ == "__main__":
    main()