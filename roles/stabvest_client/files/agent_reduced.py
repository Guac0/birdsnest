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
def get_system_details():
    sysInfo = {
        "os": get_os(),
        "executionUser": get_perms()[1],
        "executionAdmin": get_perms()[0],
        "hostname": socket.gethostname(), 
        "ipadd": get_primary_ip()
    }
    return sysInfo
def create_backup_primary(path,backupDir=BACKUPDIR):
    return True, ""
def hash_id(*args):
    combined = "|".join(map(str, args))
    encoded = base64.b64encode(combined.encode("utf-8")).decode("utf-8")
    return encoded
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
        if result.returncode != 0:
            if noisy:
                print_debug(f"Shell command failed with exit code {result.returncode}")
                if result.stderr:
                    print_debug(f"Shell stderr: {result.stderr.strip()}")
            return ""
        return result.stdout.strip()
    except FileNotFoundError:
        if noisy:
            print_debug("Error: The /bin/bash executable was not found.")
        return ""
def run_git(args, cwd):
    cmd = ["git", "-c", "http.sslVerify=false"] + args
    result = subprocess.run(
        cmd, 
        cwd=cwd, 
        capture_output=True, 
        text=True, 
        shell=(platform.system() == "Windows")
    )
    if result.returncode != 0:
        print_debug(f"Shell command failed with exit code {result.returncode}")
        if result.stderr:
            print_debug(f"Shell stderr: {result.stderr.strip()}")
    return result
def setup_git_agent(repo_dir,protected_folder,systemInfo=get_system_details()):
    try:
        if not os.path.exists(repo_dir):
            run_git(["clone", f"{SERVER_URL}git/{hash_id(AGENT_NAME, systemInfo["hostname"], systemInfo["ipadd"], systemInfo["os"])}.git",Path(repo_dir).name],os.path.dirname(Path(__file__).resolve()))
        run_git(["config", "user.name", "Agent"],repo_dir)
        run_git(["config", "user.email", f"agent@{systemInfo["hostname"]}.local"],repo_dir)
        run_git(["checkout", "-b", "good"], cwd=repo_dir)
        sync_protected_to_repo(repo_dir, protected_folder)
        run_git(["add", "."], cwd=repo_dir)
        run_git(["commit", "-m", "initialCommitGood"], cwd=repo_dir)
        run_git(["push", "-u", "origin", "good"], cwd=repo_dir)
        run_git(["checkout", "-b", "bad"], cwd=repo_dir)
        sync_protected_to_repo(repo_dir, protected_folder)
        run_git(["add", "."], cwd=repo_dir)
        run_git(["commit", "-m", "initialCommitBad"], cwd=repo_dir)
        run_git(["push", "-u", "origin", "bad"], cwd=repo_dir)
        run_git(["checkout", "good"], cwd=repo_dir)
        return True
    except Exception as E:
        print_debug(f"Critical error when running setup_git_agent: {E}")
        return False
def audit_command(command,package="",packageManager="apt"):
    return True, True
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
def send_message(oldStatus,newStatus,message,systemInfo=get_system_details()):
    if not SERVER_URL:
        return True
    url = SERVER_URL + "beacon"
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
def interface_address(interface,ip_address,subnet,gateway):
    system = platform.system()
    if system == "Windows":
        return interface_address_windows(interface,ip_address,subnet,gateway)
    else:
        return interface_address_linux(interface,ip_address,subnet,gateway)
def interface_address_windows(interface,ip_address,subnet,gateway):
    issues = []
    query_cmd = fr"""
        Get-NetIPConfiguration -InterfaceAlias '{interface}' |
        Select-Object IPv4Address, IPv4DefaultGateway | ConvertTo-Json
    """
    output = run_powershell(query_cmd)
    if not output:
        return False, False, [f"Failed to query interface {interface} due to PowerShell error."]
    try:
        data = json.loads(output)
    except json.JSONDecodeError as E:
        return False, False, [f"Failed to query interface {interface} due to PowerShell JSON parsing error."]
    has_address = bool(data.get("IPv4Address"))
    has_gateway = bool(data.get("IPv4DefaultGateway"))
    if has_address and has_gateway:
        return True, True, []
    statusFix = True
    if not has_address:
        set_ip_cmd = fr"""
            New-NetIPAddress -InterfaceAlias '{interface}' |
            -IPAddress {ip_address} -PrefixLength {subnet}
        """
        if DISARM:
            issues.append(f"Missing IPv4 Address for interface {interface}, DISARMED.")
            statusFix = False
        else:
            if not run_powershell(set_ip_cmd):
                statusFix = False
                issues.append(f"Missing IPv4 Address for interface {interface}, FAILED to restore {ip_address}/{subnet}.")
            else:
                issues.append(f"Missing IPv4 Address for interface {interface}, RESTORED {ip_address}/{subnet}.")
    if not has_gateway:
        set_gw_cmd = (
            f"New-NetRoute -InterfaceAlias '{interface}' "
            f"-DestinationPrefix '0.0.0.0/0' -NextHop {gateway}"
        )
        if DISARM:
            issues.append(f"Missing Gateway Address for interface {interface}, DISARMED.")
            statusFix = False
        else:
            if not run_powershell(set_gw_cmd):
                statusFix = False
                issues.append(f"Missing Gateway Address for interface {interface}, FAILED to restore {gateway}.")
            else:
                issues.append(f"Missing Gateway Address for interface {interface}, RESTORED {gateway}.")
    return False, statusFix, issues
def interface_address_linux(interface, ip_address, subnet, gateway):
    issues = []
    ip_addr_cmd = f"ip addr show dev {interface}"
    addr_output = run_bash(ip_addr_cmd, noisy=True)
    ip_route_cmd = "ip route show default"
    route_output = run_bash(ip_route_cmd, noisy=True)
    if not addr_output:
        print_debug(f"interface_address_linux({interface}): Failed to query interface IP (ip addr)")
        return False, False, [f"Failed to query interface {interface} (ip addr error)."]
    cidr = f"{ip_address}/{subnet}"
    has_address = bool(re.search(fr"inet\s+{re.escape(cidr)}\s+", addr_output))
    has_gateway = bool(re.search(fr"default\s+via\s+{re.escape(gateway)}\s+dev\s+{interface}\s+", route_output))
    old_status = has_address and has_gateway
    new_status = old_status
    if old_status:
        return True, True, []
    status_fix = True
    if not has_address:
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
    if not has_gateway:
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
    if status_fix:
        addr_output_new = run_bash(ip_addr_cmd, noisy=True)
        route_output_new = run_bash(ip_route_cmd, noisy=True)
        has_address_new = bool(re.search(fr"inet\s+{re.escape(cidr)}\s+", addr_output_new))
        has_gateway_new = bool(re.search(fr"default\s+via\s+{re.escape(gateway)}\s+dev\s+{interface}\s+", route_output_new))
        new_status = has_address_new and has_gateway_new
    else:
        new_status = False 
    return old_status, new_status, issues
def interface_mtu(interface=interface_get_primary(),mtu_minimum=MTU_MIN,mtu_maximum=MTU_MAX,mtu_default=MTU_DEFAULT):
    system = platform.system()
    if system == "Windows":
        return interface_mtu_windows(interface,mtu_minimum,mtu_maximum,mtu_default)
    else:
        return interface_mtu_linux(interface,mtu_minimum,mtu_maximum,mtu_default)
def interface_mtu_windows(interface=interface_get_primary(),mtu_minimum=MTU_MIN,mtu_maximum=MTU_MAX,mtu_default=MTU_DEFAULT):
    ps_get_mtu = fr"""
    Get-NetIPInterface -InterfaceAlias "{interface}" -AddressFamily IPv4 |
        Select-Object -ExpandProperty NlMtu
    """
    output = run_powershell(ps_get_mtu).strip()
    if not output:
        return False, False, [f"Failed to query MTU for interface '{interface}' due to PowerShell error."]
    if not output.isdigit():
        return False, False, [f"Failed to query MTU for interface '{interface}' due to invalid PowerShell output parsing."]
    old_mtu = int(output)
    if old_mtu < mtu_minimum or old_mtu > mtu_maximum:
        new_mtu = mtu_default
        ps_set_mtu = fr'''
        Set-NetIPInterface -InterfaceAlias "{interface}" -NlMtu {new_mtu}
        '''
        if DISARM:
            return False, False, [f"Interface {interface}'s MTU was set to {old_mtu}, DISARMED."]
        else:
            if run_powershell(ps_set_mtu):
                return False, True, [f"Interface {interface}'s MTU was set to {old_mtu}, RESTORED new mtu {new_mtu}."]
            else:
                return False, False, [f"Interface {interface}'s MTU was set to {old_mtu}, FAILED to restore new mtu {new_mtu}."]
    return True, True, []
def interface_mtu_linux(interface=interface_get_primary(), mtu_minimum=MTU_MIN, mtu_maximum=MTU_MAX, mtu_default=MTU_DEFAULT):
    ip_get_mtu = f"ip link show dev {interface}"
    output = run_bash(ip_get_mtu)
    if not output:
        return False, False, [f"Failed to query MTU for interface '{interface}' due to shell error."]
    match = re.search(r"mtu\s+(\d+)\s+", output)
    if not match:
        return False, False, [f"Failed to parse MTU for interface '{interface}'. Output: {output}"]
    old_mtu = int(match.group(1))
    if old_mtu < mtu_minimum or old_mtu > mtu_maximum:
        new_mtu = mtu_default
        ip_set_mtu = f"ip link set dev {interface} mtu {new_mtu}"
        if DISARM:
            print_debug(f"DISARMED, but told to update MTU for '{interface}' from {old_mtu} to {new_mtu}")
            return False, False, [f"Interface {interface}'s MTU was set to {old_mtu}, DISARMED."]
        else:
            print_debug(f"Updated MTU for '{interface}' from {old_mtu} to {new_mtu}")
            if run_bash(ip_set_mtu):
                output_new = run_bash(ip_get_mtu)
                match_new = re.search(r"mtu\s+(\d+)\s+", output_new)
                if match_new and int(match_new.group(1)) == new_mtu:
                    return False, True, [f"Interface {interface}'s MTU was set to {old_mtu}, RESTORED new mtu {new_mtu}."]
                else:
                    return False, False, [f"Interface {interface}'s MTU was set to {old_mtu}, FAILED to verify new mtu {new_mtu}."]
            else:
                return False, False, [f"Interface {interface}'s MTU was set to {old_mtu}, FAILED to restore new mtu {new_mtu}."]
    return True, True, []
def interface_ttl(interface=interface_get_primary()):
    system = platform.system()
    if system == "Windows":
        return interface_mtu_windows(interface)
    else:
        return interface_mtu_linux(interface)
def interface_ttl_windows():
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
            return False, False, [f"Bad system TTL set, DISARMED."]
        else:
            ps_result = run_powershell(delete_script).strip()
            if ps_result:
                return False, True, [f"Bad system TTL set, RESTORED default TTL."]
            return False, False, [f"Bad system TTL set, FAILED to restore default TTL."]
    return True, True, []
def interface_ttl_linux():
    issues = []
    IPV4_TTL_PARAM = "net.ipv4.ip_default_ttl"
    IPV6_HL_PARAM = "net.ipv6.conf.default.hop_limit" 
    ttl_query_cmd = f"sysctl -n {IPV4_TTL_PARAM}"
    current_ttl_output = run_bash(ttl_query_cmd, noisy=True)
    hl_query_cmd = f"sysctl -n {IPV6_HL_PARAM}"
    current_hl_output = run_bash(hl_query_cmd, noisy=True)
    try:
        current_ttl = int(current_ttl_output)
    except (ValueError, TypeError):
        current_ttl = LINUX_DEFAULT_TTL
    try:
        current_hl = int(current_hl_output)
    except (ValueError, TypeError):
        current_hl = LINUX_DEFAULT_TTL
    ttl_customized = current_ttl != LINUX_DEFAULT_TTL
    hl_customized = current_hl != LINUX_DEFAULT_TTL
    old_status = not (ttl_customized or hl_customized)
    if old_status:
        return True, True, []
    status_fix = True
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
    new_status = False
    if status_fix:
        new_ttl_output = run_bash(ttl_query_cmd, noisy=True)
        new_hl_output = run_bash(hl_query_cmd, noisy=True)
        try:
            new_ttl = int(new_ttl_output)
            new_hl = int(new_hl_output)
        except (ValueError, TypeError):
            return False, False, issues
        new_status = (new_ttl == LINUX_DEFAULT_TTL and new_hl == LINUX_DEFAULT_TTL)
    return old_status, new_status, issues
def interface_down(interface=interface_get_primary()):
    system = platform.system()
    if system == "Windows":
        return interface_down_windows(interface)
    else:
        return interface_down_linux(interface)
def interface_down_windows(interface=interface_get_primary()):
    ps_check = fr"""
    $iface = '{interface}'
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
    """
    status = run_powershell(ps_check).strip()
    if not status:
        return False, False, [f"Interface {interface}'s up/down status cannot be determined due to PowerShell error."]
    if status == "NotFound":
        return False, False, [f"Interface {interface}'s up/down status cannot be determined as it cannot be found."]
    if status == "Down":
        ps_enable = fr"""
        Enable-NetAdapter -Name '{interface}' -Confirm:$false
        """ 
        if DISARM:
            return False, False, [f"Interface {interface} was set to DOWN, DISARMED."]
        else:
            if run_powershell(ps_enable).strip():
                return False, True, [f"Interface {interface} was set to DOWN, RESTORED UP state."]
            return False, False, [f"Interface {interface} was set to DOWN, FAILED to restore UP state."]
    return True, True, []
def interface_down_linux(interface=interface_get_primary()):
    issues = []
    ip_check_cmd = f"ip link show dev {interface}"
    output = run_bash(ip_check_cmd)
    if not output:
        return False, False, [f"Interface {interface} cannot be queried (Not Found or shell error)."]
    status_match = re.search(r"<\S+>", output)
    if not status_match:
        return False, False, [f"Interface {interface}'s status flags could not be parsed."]
    flags = status_match.group(0)
    is_up = "UP" in flags
    old_status = is_up
    if not is_up:
        ip_set_up_cmd = f"ip link set dev {interface} up"
        if DISARM:
            print_debug(f"interface_down_linux({interface}): DISARMED, but told to enable interface")
            return False, False, [f"Interface {interface} was set to DOWN, DISARMED."]
        else:
            print_debug(f"interface_down_linux({interface}): Setting interface UP.")
            if run_bash(ip_set_up_cmd):
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
    return True, True, []
def interface_uninstall():
    return False, False, [f"interface_uninstall(): not implemented."]
    system = platform.system()
    if system == "Windows":
        return interface_uninstall_windows()
    else:
        return False, False, [f"interface_uninstall(): not implemented for system {system}."] 
def interface_uninstall_windows(interface_name,ipv4_address,prefix_length,gateway,dns_servers):
    ps_detect = r'''
    $int = Get-NetIPInterface -AddressFamily IPv4 -ErrorAction SilentlyContinue
    if ($int -eq $null -or $int.Count -eq 0) { "Missing" } else { "Present" }
    '''
    ipv4_state = run_powershell(ps_detect).strip()
    if ipv4_state == "Missing":
        print_debug("[+] IPv4 is not installed. Reinstalling...")
        ps_install = r'''
        netsh interface ipv4 install
        Write-Output "Installed"
        '''
        run_powershell(ps_install)
    else:
        print_debug("[+] IPv4 already installed.")
    print_debug(f"[+] Restoring IPv4 address on {interface_name}...")
    ps_set_ip = fr'''
    netsh interface ipv4 set address name="{interface_name}" static {ipv4_address} {prefix_length} {gateway}
    '''
    run_powershell(ps_set_ip)
    print_debug("[+] Restoring DNS servers...")
    ps_clear_dns = fr'''
    netsh interface ipv4 set dnsservers name="{interface_name}" source=static address={dns_servers[0]} register=primary
    '''
    run_powershell(ps_clear_dns)
    for dns in dns_servers[1:]:
        ps_add_dns = fr'''
        netsh interface ipv4 add dnsservers name="{interface_name}" address={dns} index=2
        '''
        run_powershell(ps_add_dns)
    print_debug("[+] IPv4 configuration restored successfully.")
    return True
def interface_main(interface,ip_address,subnet,gateway):
    oldStatus = True
    newStatus = True
    issues = []
    """
    result_oldStatus, result_newStatus, result_issues = interface_uninstall()
    if not result_oldStatus:
        oldStatus = False
    if not result_newStatus:
        newStatus = False
    for issue in result_issues:
        issues.append(issue)
    """
    """
    result_oldStatus, result_newStatus, result_issues = interface_address(interface,ip_address,subnet,gateway)
    if not result_oldStatus:
        oldStatus = False
    if not result_newStatus:
        newStatus = False
    for issue in result_issues:
        issues.append(issue)
    """
    result_oldStatus, result_newStatus, result_issues = interface_down()
    if not result_oldStatus:
        oldStatus = False
    if not result_newStatus:
        newStatus = False
    for issue in result_issues:
        issues.append(issue)
    result_oldStatus, result_newStatus, result_issues = interface_mtu(interface)
    if not result_oldStatus:
        oldStatus = False
    if not result_newStatus:
        newStatus = False
    for issue in result_issues:
        issues.append(issue)
    result_oldStatus, result_newStatus, result_issues = interface_ttl()
    if not result_oldStatus:
        oldStatus = False
    if not result_newStatus:
        newStatus = False
    for issue in result_issues:
        issues.append(issue)
    return oldStatus, newStatus, issues
def firewall_rules_audit(port,direction="in",action="block"):
    system = platform.system()
    if system == "Windows":
        return firewall_rules_audit_windows(port,direction,action)
    else:
        return firewall_rules_audit_linux(port,direction,action)
def firewall_rules_audit_windows(port,direction="in",action="block"):
    ps_query = fr"""
    $rules = Get-NetFirewallPortFilter |
        Where-Object { 
            $lp = $_.LocalPort
            if ($lp -like '*,*') { 
                return $lp.Split(',') -contains '{port}'
            } 
            if ($lp -like '*-*') { 
                $a, $b = $lp.Split('-')
                return ({port} -ge [int]$a -and {port} -le [int]$b)
            } 
            return $lp -eq '{port}'
        }  |
        Get-NetFirewallRule |
        Where-Object {  $_.Direction -eq '{direction}' -and $_.Action -eq '{action}' }  |
        Select-Object Name, DisplayName, Action, Direction, Profile
    if (-not $rules) { 
        "none found"
    }  else { 
        $rules | ConvertTo-Json
    } 
    """
    output = run_powershell(ps_query).strip()
    if not output:
        return [f"Could not get firewall rule information due to PowerShell error."], dict()
    if output.strip() == "none found":
        return [], dict()
    try:
        rules = json.loads(output)
    except json.JSONDecodeError:
        return [f"Could not get firewall rule information due to PowerShell JSON error."], dict()
    if isinstance(rules, dict):
        rules = [rules]
    return [], rules
def firewall_rules_audit_linux(port, direction="in", action="block"):
    issues = []
    matching_rules = []
    chain = "INPUT" if direction.lower() == "in" else "OUTPUT"
    targets = ["DROP", "REJECT"] if action.lower() == "block" else ["ACCEPT"]
    ip_query_cmd = f"{IPTABLES_PATH} -t filter -nL {chain} --line-numbers"
    output = run_bash(ip_query_cmd)
    if not output:
        return [f"Could not run '{ip_query_cmd}' or no rules found."], []
    rule_regex = re.compile(
        fr"^\s*(?P<index>\d+)\s+(?P<target>DROP|REJECT|ACCEPT)\s+"  
        fr"(?P<prot>[a-z]+|\*)\s+.*?"                               
        fr"(?P<spec>dpt|spt):(?P<port_spec>[\d,\-]+)\s*$"           
    )
    for line in output.splitlines():
        if not line.strip().startswith(('Chain', 'num', 'target', 'policy', 'pkts')):
            match = rule_regex.search(line)
            if match and match.group('target') in targets:
                protocol = match.group('prot')
                port_definition = match.group('port_spec')
                is_port_match = False
                if port_definition:
                    if ',' in port_definition and str(port) in port_definition.split(','):
                        is_port_match = True
                    elif '-' in port_definition:
                        try:
                            a, b = map(int, port_definition.split('-'))
                            target_port = int(port)
                            if a <= target_port <= b:
                                is_port_match = True
                        except ValueError:
                            issues.append(f"Warning: Could not parse port range in rule: {line}")
                    elif port_definition == str(port):
                        is_port_match = True
                    if is_port_match:
                        full_spec_line = line.strip()
                        rule_dict = {
                            "Chain": chain,
                            "Index": match.group('index'),
                            "Protocol": protocol,
                            "Action": match.group('target'),
                            "Direction": direction.upper(),
                            "DisplayName": full_spec_line, 
                            "Rule_Spec": full_spec_line 
                        }
                        matching_rules.append(rule_dict)
    return issues, matching_rules
def firewall_rules_delete(rules,port):
    system = platform.system()
    if system == "Windows":
        return firewall_rules_delete_windows(rules,port)
    else:
        return firewall_rules_delete_linux(rules)
def firewall_rules_delete_windows(rules,port):
    issues = []
    status = True
    for rule in rules:
        if (not DISARM):
            delete_cmd = f"Remove-NetFirewallRule -Name '{rule['Name']}'"
            output = run_powershell(delete_cmd)
            if output:
                issues.append(f"SUCCESSFULLY removed firewall rule: {rule['Name']}/{rule['DisplayName']}: {rule['Action']} {port} {rule['Direction']} on profile {rule['Profile']}.")
            else:
                issues.append(f"FAILED to remove firewall rule: {rule['Name']}/{rule['DisplayName']}: {rule['Action']} {port} {rule['Direction']} on profile {rule['Profile']}.")
                status = False
        else:
            status = False
            issues.append(f"DISARMED, but told to remove firewall rule: {rule['Name']}/{rule['DisplayName']}: {rule['Action']} {port} {rule['Direction']} on profile {rule['Profile']}.")
    return status, issues
def firewall_rules_delete_linux(rules):
    issues = []
    overall_status = True
    rules.sort(key=lambda r: int(r['Index']), reverse=True)
    for rule in rules:
        chain = rule.get('Chain')
        index = rule.get('Index')
        display_name = rule.get('DisplayName', 'N/A')
        if not (chain and index):
            issues.append(f"FAILED: Rule {display_name} is missing Chain or Index and cannot be deleted.")
            overall_status = False
            continue
        delete_cmd = f"{IPTABLES_PATH} -D {chain} {index}"
        if DISARM:
            issues.append(f"DISARMED, but told to remove firewall rule: {chain} rule #{index}")
            continue
        else:
            print_debug(f"Attempting delete: {delete_cmd} (Rule: {display_name})")
            if run_bash(delete_cmd) == "":
                issues.append(f"SUCCESSFULLY removed firewall rule from {chain} at index #{index}.")
            else:
                issues.append(f"FAILED to remove firewall rule from {chain} at index #{index}. Command failed.")
                overall_status = False
    if not DISARM:
        persist_cmd = f"/sbin/{IPTABLES_PATH}-save > /etc/sysconfig/iptables"
        if overall_status:
            print_debug("Attempting to persist iptables rules...")
            if run_bash(persist_cmd):
                issues.append("SUCCESS: Running iptables rules saved (persistent).")
            else:
                issues.append("WARNING: FAILED to persist iptables changes. Rule deletion is *NOT* permanent.")
                overall_status = False 
    return overall_status, issues
def firewall_rules_create(port,direction,action):
    system = platform.system()
    if system == "Windows":
        return firewall_rules_create_windows(port,direction,action)
    else:
        return firewall_rules_create_linux(port,direction,action)
def firewall_rules_create_windows(port,direction,action):
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
        return False, [f"DISARMED, but told to create firewall rule Stabvest_Rule_{port}_{direction}_{action}"] 
    if run_powershell(ps_cmd):
        return True, [f"SUCCESSFULLY created firewall rule Stabvest_Rule_{port}_{direction}_{action}"]
    else:
        return False, [f"FAILED to create firewall rule Stabvest_Rule_{port}_{direction}_{action}"]
def firewall_rules_create_linux(port, direction, action, protocol="tcp"):
    issues = []
    if direction.lower() == "inbound":
        chain = "INPUT"
        port_flag = "--dport" 
    elif direction.lower() == "outbound":
        chain = "OUTPUT"
        port_flag = "--sport" 
    else:
        return False, [f"FAILED: Invalid direction '{direction}'. Must be 'inbound' or 'outbound'."]
    if action.lower() == "allow":
        target = "ACCEPT"
    elif action.lower() == "block":
        target = "DROP"
    else:
        return False, [f"FAILED: Invalid action '{action}'. Must be 'allow' or 'block'."]
    if protocol.lower() == "tcp" or protocol.lower() == "udp":
        module_spec = f"-m {protocol.lower()}"
    else:
        module_spec = ""
        port_flag = "" 
    rule_spec = f"-p {protocol.lower()} {module_spec} {port_flag} {port} -j {target}"
    iptables_cmd = f"{IPTABLES_PATH} -A {chain} {rule_spec}"
    rule_description = f"{target} on port {port} ({protocol.upper()}) {direction.upper()}"
    if DISARM:
        print_debug(f"firewall_rules_create_linux(): DISARMED, but told to create rule: {iptables_cmd}")
        return False, [f"DISARMED, but told to create firewall rule: {rule_description}"]
    else:
        print_debug(f"Creating iptables rule: {iptables_cmd}")
        if run_bash(iptables_cmd) == "":
            issues.append(f"SUCCESSFULLY created firewall rule: {rule_description} (running kernel).")
            persist_cmd = f"/sbin/{IPTABLES_PATH}-save > /etc/sysconfig/iptables"
            print_debug("Attempting to persist iptables rules...")
            if run_bash(persist_cmd):
                issues.append("SUCCESS: Running iptables rules saved to disk (persistent).")
                return True, issues
            else:
                issues.append("FAILED to persist iptables changes. Rule is *NOT* permanent across reboots.")
                return False, issues
        else:
            return False, [f"FAILED to create firewall rule: {rule_description}. Check permissions/syntax."]
def firewall_policy_audit(direction):
    system = platform.system()
    if system == "Windows":
        return firewall_policy_audit_windows(direction)
    else:
        return firewall_policy_audit_linux(direction)
def firewall_policy_audit_windows(direction):
    ps_cmd = f"""
    Get-NetFirewallProfile |
        Select-Object Name, Default{direction}Action |
        ConvertTo-Json
    """
    output = run_powershell(ps_cmd)
    issues = []
    if not output:
        return False, False, [f"Failed to load firewall policy information due to PowerShell error."]
    try:
        profiles = json.loads(output)
    except json.JSONDecodeError:
        return False, False, [f"Failed to load firewall policy information due to could not decode PowerShell JSON output."]
    if isinstance(profiles, dict):
        profiles = [profiles]
    for p in profiles:
        if (p[f"Default{direction}Action"] == "Block"):
            issues.append([f"Default firewall policy on profile {p['Name']} for direction {direction} is set to BLOCK."])
    if issues:
        return True, False, issues
    return True, True, []
def firewall_policy_audit_linux(direction):
    issues = []
    if direction.lower() == "inbound":
        chain = "INPUT"
    elif direction.lower() == "outbound":
        chain = "OUTPUT"
    else:
        return False, False, [f"Failed: Invalid direction '{direction}'. Must be 'Inbound' or 'Outbound'."]
    ip_query_cmd = f"{IPTABLES_PATH} -t filter -S {chain}"
    output = run_bash(ip_query_cmd)
    if not output:
        return False, False, [f"Failed to load iptables policy for {chain} due to shell error."]
    policy_regex = re.compile(fr"^-P\s+{chain}\s+(?P<action>ACCEPT|DROP|REJECT)(?:\s+\[\d+:\d+\])?")
    match = policy_regex.search(output)
    if not match:
        return False, False, [f"Failed to parse iptables policy for {chain}. Unexpected output."]
    default_action = match.group('action')
    if default_action in ["DROP", "REJECT"]:
        issues.append(f"Default firewall policy for {chain} ({direction}) is set to BLOCK ({default_action}).")
        policy_status = False
    else:
        policy_status = True 
    return True, policy_status, issues
def firewall_main(protectedPorts):
    oldStatus = True
    newStatus = True
    issues = []
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
def sync_protected_to_repo(repo_dir,protected_folder):
    shutil.copytree(protected_folder, repo_dir, dirs_exist_ok=True)
    return repo_dir
def restore_protected_from_repo(repo_dir,protected_folder):
    shutil.copytree(repo_dir, protected_folder, dirs_exist_ok=True)
def get_latest_commit_stats(branch_name,repo_dir):
    result = run_git(["show", "--format=", "--name-status", branch_name],repo_dir)
    if result.returncode != 0 or not result.stdout.strip():
        return {"count": 0, "files": []}
    lines = result.stdout.strip().split('\n')
    files_info = []
    for line in lines:
        if not line: continue
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
def file_protect_main(repo_dir,protected_folder):
    try:
        run_git(["checkout", "good"],repo_dir)
        run_git(["pull", "origin", "good"],repo_dir)
        sync_protected_to_repo(repo_dir,protected_folder)
        run_git(["add", "."],repo_dir)
        diff_check = run_git(["diff", "--cached", "--quiet"],repo_dir)
        changes = {}
        if diff_check.returncode != 0:
            try:
                run_git(["stash"],repo_dir)
                run_git(["checkout", "bad"],repo_dir)
                run_git(["pull", "origin", "bad"],repo_dir)
                stash_apply = run_git(["stash", "pop"],repo_dir)
                if stash_apply.returncode != 0:
                    run_git(["checkout", "--theirs", "."],repo_dir)
                    run_git(["add", "."],repo_dir)
                    run_git(["commit", "-m", f"auto-resolveconflict"],repo_dir)
                run_git(["add", "."],repo_dir)
                run_git(["commit", "-m", f"auto-malicious{datetime.now().strftime("%Y-%m-%d_%H-%M-%S")}"],repo_dir)
                run_git(["push", "-u", "origin", "bad"],repo_dir)
                changes = get_latest_commit_stats("bad",repo_dir)
                run_git(["checkout", "good"],repo_dir)
                if not DISARM:
                    restore_protected_from_repo(repo_dir,protected_folder)
                    return False, True, [f"File changes occurred and were successfully restored. Affected files {changes["count"]}: {changes["files"]}"]
                else:
                    return False, False, [f"File changes occurred, DISARMED. Affected files {changes["count"]}: {changes["files"]}"]
            except Exception as E:
                return False, False, [f"File changes occurred and failed to restore known good state: {E}"]
        else:
            return True,True,[]
    except Exception as E:
        return False, False, [f"Unexpected error when attempting to check file integrity status: {E}"]
def service_audit(service):
    system = platform.system()
    if system == "Windows":
        return service_audit_windows(service)
    else:
        return service_audit_linux(service)
def service_audit_windows(service_name):
    ps_check = fr"""
    $svc = Get-Service -Name '{service_name}' -ErrorAction SilentlyContinue
    if ($svc -eq $null) { 
        Write-Output 'NotFound'
    }  else { 
        $obj = New-Object PSObject -Property @{ 
            Status = $svc.Status
            StartType = (Get-CimInstance Win32_Service -Filter "Name='{service_name}'").StartMode
        } 
        $obj | ConvertTo-Json
    } 
    """
    raw = run_powershell(ps_check).strip()
    if not raw:
        return False, False, [f"FAILED to get status information for service {service_name}, PowerShell error."]
    if raw == "NotFound" or raw == "":
        return False, False, [f"ServiceNotFound for service {service_name}."]
    try:
        data = json.loads(raw)
    except:
        return False, False, [f"FAILED to get status information for service {service_name}, PowerShell JSON parse error."]
    current_status  = data.get("Status", "")
    current_start   = data.get("StartType", "")
    oldStatus = True
    if (current_status == "Running") or (current_start not in ("Auto", "Automatic")):
        oldStatus = False
    newStatus = oldStatus
    issues = []
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
                newStatus = True 
            else:
                issues.append(f"Service {service_name} not running, FAILED to start service.")
    if current_start not in ("Auto", "Automatic"):
        issue_msg = issue_msg or "WrongStartType"
        ps_auto = fr"""
        Set-Service -Name '{service_name}' -StartupType Automatic
        """
        if DISARM:
            issues.append(f"Service {service_name} not set to automatic start, DISARMED.")
        else:
            if run_powershell(ps_auto):
                issues.append(f"Service {service_name} not set to automatic start, RESTORED to automatic start.")
                newStatus = True
            else:
                issues.append(f"Service {service_name} not set to automatic start, FAILED to set to automatic start.")
    return oldStatus, newStatus, issues
def service_audit_linux(service_name):
    issues = []
    systemctl_show_cmd = f"systemctl show --no-pager {service_name}"
    raw = run_bash(systemctl_show_cmd).strip()
    if not raw:
        systemctl_check = run_bash(f"systemctl status {service_name}", noisy=True)
        if "not-found" in systemctl_check.lower():
            return False, False, [f"ServiceNotFound for service {service_name}."]
        else:
            return False, False, [f"FAILED to get status information for service {service_name}, systemctl error."]
    data = {}
    for line in raw.splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            data[key] = value
    current_active_state = data.get("ActiveState", "").lower() 
    current_load_state = data.get("LoadState", "").lower()     
    current_enable_state = data.get("UnitFileState", "").lower() 
    is_running = current_active_state == "active"
    is_enabled = current_enable_state == "enabled" 
    oldStatus = is_running and is_enabled
    newStatus = oldStatus
    if not is_running:
        start_cmd = f"systemctl start {service_name}"
        if DISARM:
            issues.append(f"Service {service_name} is stopped, DISARMED.")
            newStatus = False
        else:
            if run_bash(start_cmd):
                time.sleep(1)
                verify_cmd = f"systemctl is-active {service_name}"
                if run_bash(verify_cmd).strip() == "active":
                    issues.append(f"Service {service_name} was stopped, RESTORED to START state.")
                    newStatus = True
                else:
                    issues.append(f"Service {service_name} was stopped, FAILED to verify START state.")
            else:
                issues.append(f"Service {service_name} was stopped, FAILED to execute start command.")
    if not is_enabled:
        enable_cmd = f"systemctl enable {service_name}"
        if DISARM:
            issues.append(f"Service {service_name} not set to automatic start (disabled), DISARMED.")
        else:
            if run_bash(enable_cmd):
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
    if (not service) and (not package):
        print_debug(f"service_uninstall({service},{package}): provided with empty args despite failsafes elsewhere?")
        return True, True, [] 
    system = platform.system()
    if system == "Windows":
        return service_uninstall_windows(service,package)
    else:
        return service_uninstall_linux(service,package)
def service_uninstall_windows(service,package):
    issues = []
    old_status = False
    new_status = False
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
            feature = {} 
        feature_state = feature.get("State", "")
        if feature_state == "Enabled":
            old_status = True
        else:
            if DISARM:
                issues.append(f"Missing required package {package} for service {service}, DISARMED.")
            else:
                enable_cmd = ( 
                    f"Enable-WindowsOptionalFeature -Online -FeatureName {package} -All -NoRestart"
                )
                if run_powershell(enable_cmd):
                    issues.append(f"Missing required package {package} for service {service}, FAILED to reinstall package due to PowerShell error.")
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
        new_status = True
        new_status = True
        return old_status, new_status, issues
    print_debug(f"service_uninstall_windows({service},{package}): reached end of func which is unexpected, possible logic error")
    return True, True, [] 
def service_uninstall_linux(service, package):
    issues = []
    package_present_initial = False
    service_present_initial = False
    if package:
        rpm_check_cmd = f"rpm -q {package}"
        rpm_output = run_bash(rpm_check_cmd, noisy=True)
        if "is not installed" not in rpm_output and rpm_output != "":
            package_present_initial = True
            print_debug(f"Package {package} is installed.")
        else:
            if not DISARM:
                install_cmd = f"dnf install -y {package}"
                print_debug(f"Attempting to install package {package}...")
                if run_bash(install_cmd):
                    issues.append(f"Missing required package {package}, RESTORED by installing package.")
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
        package_present_initial = True
        package_present_after = True
    if service:
        svc_check_cmd = f"systemctl show --no-pager {service}"
        svc_output = run_bash(svc_check_cmd, noisy=True)
        if "not-found" not in svc_output and svc_output != "":
            service_present_initial = True
            service_present_after = True 
        else:
            issues.append(f"Missing service unit file {service}.")
            service_present_after = False
            if not package_present_initial and package_present_after and service_present_initial == False:
                 if "not-found" not in run_bash(svc_check_cmd, noisy=True) and run_bash(svc_check_cmd, noisy=True) != "":
                    service_present_after = True
                    issues.append(f"Service {service} restored by package installation.")
    else:
        service_present_initial = True
        service_present_after = True
    old_status = package_present_initial and service_present_initial
    new_status = package_present_after and service_present_after
    if not old_status and not new_status and not DISARM:
        if not package_present_after:
             issues.append(f"Overall FAILED to restore missing service/package.")
        if not service_present_after:
             issues.append(f"Overall FAILED to find service {service} even after package install.")
    return old_status, new_status, issues
def service_integrity(service,backupDict):
    system = platform.system()
    if system == "Windows":
        return service_integrity_windows(service,backupDict)
    else:
        return True, True, []
def service_integrity_windows(service_name, backupDict):
    ps_check = fr"""
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
    """
    raw = run_powershell(ps_check).strip()
    if not raw:
        return False, False, [f"FAILED to get integrity information for service {service_name}, PowerShell error."]
    oldStatus = True
    newStatus = oldStatus
    issues = []
    if raw == "NotFound" or raw == "":
        oldStatus = False 
        expected_path_name = backupDict.get("PathName", "")
        expected_display_name = backupDict.get("DisplayName", service_name)
        expected_start_type = backupDict.get("StartType", "auto").lower()
        expected_start_name = backupDict.get("StartName", "LocalSystem")
        dependencies_str = "/".join(backupDict.get("Dependencies", []))
        if not expected_path_name:
            issues.append(f"Service {service_name} was MISSING, FAILED to create (PathName not in backupDict).")
            return oldStatus, False, issues
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
                return oldStatus, True, issues 
            else:
                issues.append(f"Service {service_name} was MISSING, FAILED to create service.")
                return oldStatus, False, issues 
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
    current_dependencies_sorted = sorted([d.lower() for d in current_dependencies])
    expected_dependencies_sorted = sorted([d.lower() for d in expected_dependencies])
    if (current_start_name != expected_start_name) or       (current_path_name.lower().strip() != expected_path_name.lower().strip()) or       (current_dependencies_sorted != expected_dependencies_sorted):
        oldStatus = False
    if current_path_name.lower().strip() != expected_path_name.lower().strip():
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
    if current_start_name != expected_start_name:
        ps_start_name_fix = None
        if expected_start_name in ("LocalSystem", "NT AUTHORITY\\LocalSystem"):
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
    if current_dependencies_sorted != expected_dependencies_sorted:
        dependency_list_str = "/".join(expected_dependencies)
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
    oldStatus = True
    newStatus = True
    issues = []
    show_cmd = f"systemctl show --no-pager {service_name}"
    raw = run_bash(show_cmd).strip()
    if "not-found" in raw.lower() or not raw:
        oldStatus = False
        newStatus = False
        issues.append(f"ServiceNotFound for service {service_name}.")
        return oldStatus, newStatus, issues
    current_attrs = {}
    for line in raw.splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            if key == "ExecStart":
                current_attrs["ExecStart"] = value.split('=', 1)[-1].strip() 
            elif key == "User":
                current_attrs["User"] = value
            elif key == "Requires":
                current_attrs["Requires"] = sorted([d.lower() for d in value.split()])
    expected_exec_start = backupDict.get("ExecStart", "").strip()
    expected_user = backupDict.get("User", "").strip()
    expected_dependencies = backupDict.get("Dependencies", [])
    if isinstance(expected_dependencies, str):
        expected_dependencies = ast.literal_eval(expected_dependencies)
    expected_dependencies = sorted([d.lower() for d in backupDict.get("Dependencies", [])])
    current_exec_start = current_attrs.get("ExecStart", "").strip()
    if current_exec_start.lower() != expected_exec_start.lower():
        oldStatus = False
        issue_msg = f"ExecStart (PathName) is incorrect. Current: '{current_exec_start}', Expected: '{expected_exec_start}'."
        issues.append(issue_msg)
        if not DISARM:
            issues.append("-> Remediation failed: Cannot automatically modify systemd unit file.")
            newStatus = False
    current_user = current_attrs.get("User", "").strip()
    if current_user.lower() != expected_user.lower():
        oldStatus = False
        issue_msg = f"User (StartName) is incorrect. Current: '{current_user}', Expected: '{expected_user}'."
        issues.append(issue_msg)
        if not DISARM:
            issues.append("-> Remediation failed: Cannot automatically modify systemd unit file for User.")
            newStatus = False
    current_dependencies = current_attrs.get("Requires", [])
    if current_dependencies != expected_dependencies:
        oldStatus = False
        issue_msg = f"Dependencies (Requires/After) are incorrect. Current: {current_dependencies}, Expected: {expected_dependencies}."
        issues.append(issue_msg)
        if not DISARM:
            issues.append("-> Remediation failed: Cannot automatically modify systemd unit file for Dependencies.")
            newStatus = False
    if DISARM and not oldStatus:
         issues.append("Integrity check failed, DISARMED. No restoration attempted.")
    return oldStatus, newStatus, issues
def service_backup(service):
    system = platform.system()
    if system == "Windows":
        return service_backup_windows(service)
    else:
        return {}
def service_backup_windows(service_name):
    ps_query = fr"""
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
    """
    raw = run_powershell(ps_query).strip()
    if not raw or raw == "NotFound":
        print(f"[ERROR] Service '{service_name}' not found or PowerShell error during query.")
        return None
    try:
        data = json.loads(raw)
        data['StartType'] = data['StartType'].lower()
        if data['Dependencies'] is None:
            data['Dependencies'] = []
        return data
    except Exception as e:
        print(f"[ERROR] Failed to parse JSON configuration for '{service_name}': {e}")
        return None
def service_backup_linux(service_name):
    systemctl_show_cmd = f"systemctl show --no-pager {service_name}"
    raw = run_bash(systemctl_show_cmd).strip()
    if not raw or "not-found" in raw.lower():
        print_debug(f"[ERROR] Service '{service_name}' not found or systemctl error during query.")
        return None
    systemd_attrs = {}
    for line in raw.splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            systemd_attrs[key] = value
    systemctl_enabled_cmd = f"systemctl is-enabled {service_name}"
    enable_state = run_bash(systemctl_enabled_cmd, noisy=True).strip().lower()
    exec_start_line = systemd_attrs.get("ExecStart", "")
    if exec_start_line:
        path_name = exec_start_line.split('=', 1)[-1].strip()
    else:
        path_name = ""
    requires_str = systemd_attrs.get("Requires", "")
    dependencies = [dep for dep in requires_str.split() if dep]
    start_name = systemd_attrs.get("User", "root") 
    display_name = systemd_attrs.get("Description", service_name)
    if enable_state == "enabled":
        start_type = "auto"
    elif enable_state in ["disabled", "static"]:
        start_type = "disabled"
    else:
        start_type = "manual" 
    backup_dict = {
        "PathName": path_name,                
        "StartName": start_name,              
        "Dependencies": dependencies,         
        "DisplayName": display_name,          
        "StartType": start_type.lower()       
    }
    return backup_dict
def service_lastrun(service):
    system = platform.system()
    if system == "Windows":
        return service_audit_windows(service)
    else:
        return service_audit_linux(service)
def service_lastrun_windows(service_name):
    oldStatus = True  
    newStatus = True  
    issues = []
    ps_check = fr"""
    $svc = Get-Service -Name '{service_name}' -ErrorAction SilentlyContinue
    if ($svc -eq $null) { 
        Write-Output 'NotFound'
    }  else { 
        $obj = New-Object PSObject -Property @{ 
            Status = $svc.Status
        } 
        $obj | ConvertTo-Json
    } 
    """
    raw = run_powershell(ps_check).strip()
    if not raw:
        oldStatus = False
        newStatus = False
        issues.append(f"FAILED to get status information for service {service_name}, PowerShell error.")
        return oldStatus, newStatus, issues
    if raw == "NotFound" or raw == "":
        oldStatus = False
        newStatus = False
        issues.append(f"Status Check: ServiceNotFound {service_name}.")
        return oldStatus, newStatus, issues
    try:
        data = json.loads(raw)
    except:
        oldStatus = False
        newStatus = False
        issues.append(f"FAILED to get status information for service {service_name}, PowerShell JSON parse error.")
        return oldStatus, newStatus, issues
    current_status = data.get("Status", "Unknown")
    if current_status == "Running":
        return oldStatus, newStatus, issues
    oldStatus = False
    newStatus = False 
    ps_exit_code_query = fr"sc.exe qc {service_name}"
    qc_output = run_powershell(ps_exit_code_query, noisy=True)
    if not qc_output:
        issues.append(f"Service Status: {current_status}. FAILED to query exit codes via sc.exe.")
        return oldStatus, newStatus, issues
    win32_match = re.search(r"WIN32_EXIT_CODE\s+:\s+(\d+)", qc_output, re.IGNORECASE)
    service_match = re.search(r"SERVICE_EXIT_CODE\s+:\s+(\d+)", qc_output, re.IGNORECASE)
    win32_code = int(win32_match.group(1)) if win32_match else -1
    service_code = int(service_match.group(1)) if service_match else -1
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
    oldStatus = True  
    newStatus = True  
    issues = []
    systemctl_active_cmd = f"systemctl is-active {service_name}"
    current_status = run_bash(systemctl_active_cmd, noisy=True).strip()
    systemctl_check = run_bash(f"systemctl status {service_name}", noisy=True)
    if "not-found" in systemctl_check.lower():
        oldStatus = False
        newStatus = False
        issues.append(f"Status Check: ServiceNotFound {service_name}.")
        return oldStatus, newStatus, issues
    if current_status == "active":
        return oldStatus, newStatus, issues
    oldStatus = False
    newStatus = False 
    show_cmd = f"systemctl show --no-pager {service_name}"
    show_output = run_bash(show_cmd, noisy=True)
    exit_code = "N/A"
    data = {}
    for line in show_output.splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            data[key] = value
    main_pid = data.get("MainPID", "0")
    if main_pid == "0":
        exit_code_raw = data.get("ExecMainCode", data.get("ExecStopCode", None))
        if exit_code_raw is not None:
             exit_code = exit_code_raw
    journal_cmd = f"journalctl -u {service_name} -n 5 --no-pager"
    journal_output = run_bash(journal_cmd, noisy=True).strip()
    analysis_message = f"Service {service_name} Status: {current_status}."
    if current_status == "failed":
        analysis_message += " Service transitioned to a FAILED state."
    analysis_message += f" Last known exit code: {exit_code}."
    issues.append(analysis_message)
    return oldStatus, newStatus, issues
def service_main(services,packages,service_backups):
    if len(services) != len(packages):
        return False, False, [f"service_main({services},{packages}): services and packages lists are not the same size."]
    oldStatus = True
    newStatus = True
    issues = []
    for service,package in zip(services,packages):
        if (not service) and (not package):
            continue
        """
        result_oldStatus, result_newStatus, result_issues = service_uninstall(service,package)
        if not result_oldStatus:
            oldStatus = False
        if not result_newStatus:
            newStatus = False
        for issue in result_issues:
            issues.append(issue)
        """
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
        result_oldStatus, result_newStatus, result_issues = service_audit(service)
        if not result_oldStatus:
            oldStatus = False
        if not result_newStatus:
            newStatus = False
        for issue in result_issues:
            issues.append(issue)
        result_oldStatus, result_newStatus, result_issues = service_lastrun(service)
        if not result_oldStatus:
            oldStatus = False
        if not result_newStatus:
            newStatus = False
        for issue in result_issues:
            issues.append(issue)
    return oldStatus, newStatus, issues
def pause_countdown(seconds=60):
    return resume(True)
def pause(seconds=60):
    send_message(True,True,f"pausing for seconds {seconds}")
    return True
def resume(scheduled=False):
    send_message(True,True,f"resuming - scheduled: {scheduled}")
    return True
def reregister():
    send_message(True,True,"reregister")
    return True
def init_int_vars(interface=interface_get_primary()):
    system = platform.system()
    if system == "Windows":
        return init_int_vars_windows(interface)
    else:
        return init_int_vars_linux(interface)
def init_int_vars_windows(interface=interface_get_primary()):
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
    ip_address = None
    prefix = None
    gateway = None
    try:
        cmd = ["ip", "-j", "addr", "show", interface]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        addr_data = json.loads(result.stdout)
        if addr_data:
            ipv4_infos = [addr for addr in addr_data[0].get("addr_info", []) if addr.get("family") == "inet"]
            if ipv4_infos:
                ip_address = ipv4_infos[0].get("local")
                prefix = ipv4_infos[0].get("prefixlen")
    except (subprocess.CalledProcessError, json.JSONDecodeError, IndexError) as e:
        print_debug(f"init_int_vars_linux({interface}): Failed to query IP address. Error: {e}")
    try:
        cmd = ["ip", "-j", "route", "show", "default", "dev", interface]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        route_data = json.loads(result.stdout)
        if route_data:
            gateway = route_data[0].get("gateway")
    except (subprocess.CalledProcessError, json.JSONDecodeError, IndexError) as e:
        print_debug(f"init_int_vars_linux({interface}): Failed to query gateway. Error: {e}")
    print_debug(f"init_int_vars_linux({interface}): {ip_address} {prefix} {gateway}")
    return ip_address, prefix, gateway
def test_network():
    interface = interface_get_primary() 
    ip_address,prefix,gateway = init_int_vars()
    print_debug(f"interface_get_primary(): {interface}")
    print_debug(f"interface_main({interface,ip_address,prefix,gateway}): {interface_main(interface,ip_address,prefix,gateway)}")
    print_debug(f"firewall_main(['81','82']): {firewall_main(['81','82'])}")
def test_service():
    service = "AxInstSV"
    print_debug(f"service_audit({service}): {service_audit(service)}")
def test_main():
    print_debug(f"get_system_details(): {get_system_details()}")
    test_service()
def main(stop_event=None):
    global PAUSED
    ip_address,prefix,gateway = init_int_vars() 
    systemInfo = get_system_details()
    agent_id = hash_id(AGENT_NAME, systemInfo["hostname"], systemInfo["ipadd"], systemInfo["os"])
    repo_url = os.path.join(f"{SERVER_URL}git",f"{agent_id}.git")
    repo_dir = f"{os.path.join(os.path.dirname(Path(__file__).resolve()),f"{agent_id}.git")}"
    send_message(True,True,f"Register")
    setup_git_agent(repo_dir,PROTECTED_FOLDERS[0]) 
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
            print_debug(f"main(): running file checks")
            result_issues_main = []
            for protected_folder in PROTECTED_FOLDERS:
                result_oldStatus, result_newStatus, result_issues = file_protect_main(repo_dir,protected_folder)
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
            print_debug(f"main(): oldStatus - {oldStatus}")
            print_debug(f"main(): newStatus - {newStatus}")
            print_debug(f"main(): sleeping for {SLEEPTIME} seconds")
            print_debug(f"")
            oldIssues = newIssues
            newIssues = []
        else:
            if not suppressed_send:
                send_message(True,False,f"Agent still in PAUSE status for {int(pausedEpochLocal - time.time())} seconds remaining")
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
    main()