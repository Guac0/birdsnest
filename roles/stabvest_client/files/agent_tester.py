# Implements unit testing for the stabvest agent
# Usage: run program with python and follow the prompts

import datetime
import os
import subprocess
import platform
#import ctypes
import re
import socket

DEBUG = True
LOGFILE = ""
LINE_SIZE = 75
SYSTEM = platform.system()
OPTIONS = {
    "- Firewall": f"{'-'*(round((LINE_SIZE - 13)/1))}",
    "w0": "Firewall test - run all",
    "w1": "Firewall test - run scored service block rule inbound",
    "w2": "Firewall test - run scored service block rule outbound",
    "w3": "Firewall test - run scored service block range inbound",
    "w4": "Firewall test - run scored service block range outbound",
    "w5": "Firewall test - block all inbound without allow for scored service",
    "w6": "Firewall test - block all outbound without allow for scored service",
    "w7": "Firewall test - block all inbound with allow for scored service",
    "w8": "Firewall test - block all outbound with allow for scored service",
    "- Interface": f"{'-'*(round((LINE_SIZE - 14)/1))}",
    "i0": "Interface test - run all",
    "i1": "Interface test - interface down",
    "i2": "Interface test - too low MTU",
    "i3": "Interface test - too high MTU",
    "i4": "Interface test - non-default TTL",
    "i5": "Interface test - non-default address",
    "i6": "Interface test - non-default subnet",
    "i7": "Interface test - non-default gateway",
    "i8": "Interface test - set to DHCP",
    "- Service": f"{'-'*(round((LINE_SIZE - 12)/1))}",
    "s0": "Service test - run all",
    "s1": "Service test - service stop",
    "s2": "Service test - service failed",
    "s3": "Service test - service integrity (dependencies (windows))",
    "s4": "Service test - service integrity (executable)",
    "s5": "Service test - service deleted",
    "s6": "Service test - package deleted",
    "- File": f"{'-'*(round((LINE_SIZE - 9)/1))}",
    "f0": "File test - run all",
    "f1": "File test - delete file/folder",
    "f2": "File test - modify file contents",
    "f3": "File test - modify file/folder permissions",
    "f4": "File test - modify file/folder last modified time",
    "f5": "File test - make file/folder immutable",
    "- Unique Service": f"{'-'*(round((LINE_SIZE - 19)/1))}",
    "u0": "Unique Service test - run all",
    "u1": "Unique Service test - mysql",
    "- Agent": f"{'-'*(round((LINE_SIZE - 10)/1))}",
    "a0": "Agent test - run all",
    "a1": "Agent test - re-register",
    "a2": "Agent test - pause",
    "a3": "Agent test - resume (early)",
    "": f"{'-'*(LINE_SIZE - 3)}"
}



def get_perms():
    """
    Gets the execution perm level (user and elevation level).
    Intentionally
    Returns: isRunAsElevated(bool), runAsUser(String)
    """

    system = platform.system()
    is_admin = False

    if system == "Windows":
        """
        try:
            # Windows admin check using IsUserAnAdmin
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            # Fallback if call fails
            is_admin = False
        return is_admin
        """
        try:
            test_path = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "temp_admin_test.tmp")
            with open(test_path, "w") as f:
                f.write("test")
            os.remove(test_path)
            return True
        except Exception:
            return False
    
    if system in ("Linux", "FreeBSD"):
        # euid 0 - root OR sudo
        is_admin = (os.geteuid() == 0)
        return is_admin
    
    # Unknown OS - shouldn't reach
    print_debug("get_perms(): reached unexpected unsupported OS block")
    return False

def print_debug(msg):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if (DEBUG):
        print(msg)
    if LOGFILE:
        if len(LOGFILE) > 0:
            with open(LOGFILE, "a") as f:
                f.write(f"{timestamp} {msg}\n")
    return

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

def test_service_stop(service):
    # Implements s1
    if SYSTEM == "Windows":
        run_powershell(f"Stop-Service -Name '{service}'")
        run_powershell(f"Set-Service -Name '{service}' -StartupType Disabled")
    else:
        run_bash(f"systemctl stop {service}")
        run_bash(f"systemctl disable {service}")
    return

def test_service_fail(service):
    # Implements s2
    if SYSTEM == "Windows":
        run_powershell(f"(Get-WmiObject -Class Win32_Service -Filter Name='{service}').PathName | ForEach-Object {{Rename-Item $_ (Join-Path (Split-Path $_) ((Split-Path $_ -Leaf) + '.old'))}}")
    else:
        run_bash(f"svc={service}; systemctl disable --now '$svc'; exe=$(systemctl show -p ExecStart --value '$svc' | awk '{{print $1}}'); mv '$exe;' '$exe.old'")
    return

def test_service_integrity(service,type):
    # Implements s3-4
    if SYSTEM == "Windows":
        if type == "dependency":
            run_powershell(f"$svc = Get-Service {service}; sc.exe config {service} depend= '$($svc.ServicesDependedOn.Name -join '/')/Tcpip'")
        elif type == "executable":
            run_powershell(f"sc.exe stop {service}; sc.exe config {service} binPath='C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'; sc.exe start {service}")
        else:
            print(f"test_service_integrity: unrecognized type {type}")
    else:
        if type == "dependency":
            print("dependency test is not applicable for non-windows")
            pass # not applicable
        elif type == "executable":
            run_bash(f"mkdir -p /etc/systemd/system/{service}.service.d && echo -e '[{service}]\\nExecStart=\\nExecStart=/bin/bash' | tee /etc/systemd/system/{service}.service.d/override.conf > /dev/null && systemctl daemon-reexec && systemctl restart {service}")
        else:
            print(f"test_service_integrity: unrecognized type {type}")
    return

def test_service_deleted(service):
    # Implements s5
    if SYSTEM == "Windows":
        run_powershell(f"Stop-Service -Name '{service}'")
        run_powershell(f"sc.exe delete '{service}'")
    else:
        run_bash(f"systemctl disable --now {service}")
        run_bash(f"rm /etc/systemd/system/{service}.service")
        run_bash(f"systemctl daemon-reload")
    return

def test_service_deleted_package(package):
    # Implements s6
    if SYSTEM == "Windows":
        run_powershell(f"Uninstall-WindowsFeature -Name '{package}'") # TODO pretty big limitation but not seeing a much better way
    else:
        run_bash(f"PKG={package}; command -v apt-get && sudo apt-get remove -y '$PKG'; command -v apt && sudo apt remove -y '$PKG'; command -v dnf && sudo dnf remove -y '$PKG'; command -v yum && sudo yum remove -y '$PKG'; command -v pacman && sudo pacman -Rns --noconfirm '$PKG'; command -v zypper && sudo zypper remove -y '$PKG'; command -v apk && sudo apk del '$PKG'; command -v emerge && sudo emerge -C '$PKG'; command -v snap && sudo snap remove '$PKG'; command -v flatpak && sudo flatpak uninstall -y '$PKG'; command -v nix-env && nix-env -e '$PKG'")
    return

def test_service_main(test,service):
    if test == 0: #there's no better way to do this? lame.
        test_service_stop(service)
        test_service_fail(service)
        test_service_integrity(service,"dependency")
        test_service_integrity(service,"executable")
        test_service_deleted(service)
        test_service_deleted_package(service)
    elif test == 1:
        test_service_stop(service)
    elif test == 2:
        test_service_fail(service)
    elif test == 3:
        test_service_integrity(service,"dependency")
    elif test == 4:
        test_service_integrity(service,"executable")
    elif test == 5:
        test_service_deleted(service)
    elif test == 6:
        test_service_deleted_package(service)
    else:
        print(f"No matching test found for test {test}")
    return

def test_interface_down():
    # Implements i1
    interfaceName = interface_get_primary()
    if SYSTEM == "Windows":
        run_powershell(f"Disable-NetAdapter -Name '{interfaceName}'")    
    else:
        run_bash(f"ip link set dev {interfaceName} down")
    return

def test_interface_mtu(newMtu=1100):
    # Implements i2, i3
    interfaceName = interface_get_primary()
    if SYSTEM == "Windows":
        run_powershell(f"Set-NetIPInterface -InterfaceAlias '{interfaceName}' -NlMtuBytes {newMtu}")    
    else:
        run_bash(f"ip link set dev {interfaceName} mtu {newMtu}")
        print(f"MTU set to {newMtu}, will reset on reboot!")
    return

def test_interface_ttl():
    # Implements i4
    if SYSTEM == "Windows":
        run_powershell(f"Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters' -Name DefaultTTL -Type DWord -Value 100")
        print("System TTL changed to 100, will likely need a reboot to take effect!")
    else:
        run_bash(f"sysctl -w net.ipv4.ip_default_ttl=100")
        print("System TTL changed to 100, will likely not persist past reboot!")
    return

def test_interface_config(type):
    # Implements i5-7
    interfaceName = interface_get_primary()
    if SYSTEM == "Windows":
        if type == "address":
            run_powershell(f"Set-NetIPAddress -InterfaceAlias {interfaceName} -IPAddress 192.168.99.99")
        elif type == "subnet":
            run_powershell(f"Set-NetIPAddress -InterfaceAlias {interfaceName} -PrefixLength 29")
        elif type == "gateway":
            run_powershell(f"Set-NetIPAddress -InterfaceAlias {interfaceName} -DefaultGateway 192.168.99.99")
        else:
            print(f"test_interface_config: unknown option {type}")
    else:
        if type == "address":
            run_bash(f"ip addr replace 192.168.99.99/24 dev {interfaceName}")
        elif type == "subnet":
            run_bash(f"ip addr replace 192.168.99.99/24 dev {interfaceName}") # same as above tbh
        elif type == "gateway":
            run_bash(f"ip route replace default via 192.168.99.99 dev {interfaceName}")
        else:
            print(f"test_interface_config: unknown option {type}")
    return

def test_interface_dhcp():
    # Implements i8
    interfaceName = interface_get_primary()
    if SYSTEM == "Windows":
        run_powershell(f"Set-NetIPInterface -InterfaceAlias '{interfaceName}' -Dhcp Enabled")
        run_powershell(f"Set-DnsClientServerAddress -InterfaceAlias '{interfaceName}' -ResetServerAddresses")
    else:
        run_bash(f"dhclient -v {interfaceName}")
    return 

def test_interface_main(test):
    if test == 0: #there's no better way to do this? lame.
        test_interface_down()
        test_interface_mtu(1200)
        test_interface_mtu(1514)
        test_interface_ttl()
        test_interface_config("address")
        test_interface_config("subnet")
        test_interface_config("gateway")
        test_interface_dhcp()
    elif test == 1:
        test_interface_down()
    elif test == 2:
        test_interface_mtu(1200)
    elif test == 3:
        test_interface_mtu(1514)
    elif test == 4:
        test_interface_ttl()
    elif test == 5:
        test_interface_config("address")
    elif test == 6:
        test_interface_config("subnet")
    elif test == 7:
        test_interface_config("gateway")
    elif test == 8:
        test_interface_dhcp()
    else:
        print(f"No matching test found for test {test}")
    return

def test_firewall_blockrule(port,dir):
    # implements w1-2
    if SYSTEM == "Windows":
        run_powershell(f"New-NetFirewallRule -DisplayName 'Block {dir} TCP PORT' -Direction {dir} -Protocol TCP -LocalPort {port} -Action Block")
        run_powershell(f"New-NetFirewallRule -DisplayName 'Block {dir} UDP PORT' -Direction {dir} -Protocol UDP -LocalPort {port} -Action Block")
    else:
        if dir == "Inbound":
            run_bash(f"iptables -A INPUT -p tcp --dport {port} -j DROP")
            run_bash(f"iptables -A INPUT -p udp --dport {port} -j DROP")
        else:
            run_bash(f"iptables -A OUTPUT -p tcp --sport {port} -j DROP")
            run_bash(f"iptables -A OUTPUT -p udp --sport {port} -j DROP")
    pass

def test_firewall_blockrange(port,dir):
    # implements w3-4
    if SYSTEM == "Windows":
        portrange=f"{port-10}-{port+10}"
        run_powershell(f"New-NetFirewallRule -DisplayName 'Block {dir} TCP PORT RANGE' -Direction {dir} -Protocol TCP -LocalPort {portrange} -Action Block")
        run_powershell(f"New-NetFirewallRule -DisplayName 'Block {dir} UDP PORT RANGE' -Direction {dir} -Protocol UDP -LocalPort {portrange} -Action Block")
    else:
        portrange=f"{port-10}:{port+10}"
        if dir == "Inbound":
            run_bash(f"iptables -A INPUT -p tcp --dport {portrange} -j DROP")
            run_bash(f"iptables -A INPUT -p udp --dport {portrange} -j DROP")
        else:
            run_bash(f"iptables -A OUTPUT -p tcp --sport {portrange} -j DROP")
            run_bash(f"iptables -A OUTPUT -p udp --sport {portrange} -j DROP")
    pass

def test_firewall_policy(port,dir,allow):
    # implements w5-8
    if SYSTEM == "Windows":
        if allow:
            run_powershell(f"New-NetFirewallRule -DisplayName 'Allow {dir} TCP PORT' -Direction {dir} -Protocol TCP -LocalPort {port} -Action Allow")
            run_powershell(f"New-NetFirewallRule -DisplayName 'Allow {dir} UDP PORT' -Direction {dir} -Protocol UDP -LocalPort {port} -Action Allow")
        run_powershell(f"Set-NetFirewallProfile -Profile Domain,Public,Private -Default{dir} -Action Block")
    else:
        if dir == "Inbound":
            if allow:
                run_bash(f"iptables -A INPUT -p tcp --dport {port} -j DROP")
            run_bash(f"iptables -P INPUT DROP")
            run_bash(f"iptables -A INPUT -i lo -j ACCEPT")
            run_bash(f"iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")
        else:
            if allow:
                run_bash(f"iptables -A OUTPUT -p tcp --dport {port} -j DROP")
            run_bash(f"iptables -P OUTPUT DROP")
            run_bash(f"iptables -A OUTPUT -i lo -j ACCEPT")
            run_bash(f"iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")
    pass

def test_firewall_main(test,port):
    if test == 0: #there's no better way to do this? lame.
        test_firewall_blockrule(port,"Inbound")
        test_firewall_blockrule(port,"Outbound")
        test_firewall_blockrange(port,"Inbound")
        test_firewall_blockrange(port,"Outbound")
        test_firewall_policy(port,"Inbound",False)
        test_firewall_policy(port,"Outbound",False)
        test_firewall_policy(port,"Inbound",True)
        test_firewall_policy(port,"Outbound",True)
    elif test == 1:
        test_firewall_blockrule(port,"Inbound")
    elif test == 2:
        test_firewall_blockrule(port,"Outbound")
    elif test == 3:
        test_firewall_blockrange(port,"Inbound")
    elif test == 4:
        test_firewall_blockrange(port,"Outbound")
    elif test == 5:
        test_firewall_policy(port,"Inbound",False)
    elif test == 6:
        test_firewall_policy(port,"Outbound",False)
    elif test == 7:
        test_firewall_policy(port,"Inbound",True)
    elif test == 8:
        test_firewall_policy(port,"Outbound",True)
    else:
        print(f"No matching test found for test {test}")
    return

def test_file_delete(path):
    # implements f1
    try:
        if os.path.exists(path):
            if os.path.isdir(path):
                os.rmdir(path)
            else:
                os.remove(path)
            print(f"Item '{path}' has been deleted successfully.")
        else:
            print(f"Item '{path}' does not exist.")
    except Exception as E:
        print(f"Issue when deleting {path}: {E}")
    return

def test_file_modify_contents(path):
    # implements f2
    try:
        if not os.path.exits(path):
            print(f"Item '{path}' does not exist.")
            return
        if os.path.isdir(path):
            print("test_file_modify_contents(): given directory but expected file!")
        else:
            with open(path, "a") as f:
                f.write("\nThis is a malicious change mwahahaha.")
    except Exception as E:
        print(f"Issue when appending to {path}: {E}")
    return

def test_file_modify_attribute(path,type):
    # implements f3-f5
    if not os.path.exits(path):
        print(f"Item '{path}' does not exist.")
        return
    if SYSTEM == "Windows":
        if type == "permissions":
            run_powershell(f"icacls '{path}' /inheritance:r")
            run_powershell(f"icacls '{path}' /grant:r '$env:USERNAME:(R)'")
        elif type == "lastmodified":
            run_powershell(f"(Get-Item {path}).CreationTime = Get-Date '2000-01-01 00:00:00'")
            run_powershell(f"(Get-Item {path}).LastAccessTime = Get-Date '2000-01-01 00:00:00'")
            run_powershell(f"(Get-Item {path}).LastWriteTime = Get-Date '2000-01-01 00:00:00'")
        elif type == "immutable":
            run_powershell(f"icacls '{path}' /inheritance:r")
            run_powershell(f"icacls '{path}' /deny Everyone:(WD,AD,DC)")
        else:
            print(f"test_file_attributes: unrecognized type {type}")
    else:
        if type == "permissions":
            run_bash(f"chmod 700 {path}")
        elif type == "lastmodified":
            run_bash(f"touch -a -m -t 200001010000 {path}")
        elif type == "immutable":
            run_bash(f"chattr +i {path}")
        else:
            print(f"test_file_attributes: unrecognized type {type}")
    return

def test_file_main(test,path):
    if test == 0: #there's no better way to do this? lame.
        test_file_delete(path)
        test_file_modify_attribute(path,"permissions")
        test_file_modify_attribute(path,"lastmodified")
        test_file_modify_attribute(path,"immutable")
    elif test == 1:
        test_file_delete(path)
    elif test == 2:
        test_file_modify_contents(path)
    elif test == 3:
        test_file_modify_attribute(path,"permissions")
    elif test == 4:
        test_file_modify_attribute(path,"lastmodified")
    elif test == 5:
        test_file_modify_attribute(path,"immutable")
    else:
        print(f"No matching test found for test {test}")
    return

def test_unqiue_mysql():
    # Implements u1
    return 

def test_unique_main(test,service):
    if test == 0:
        test_unqiue_mysql()
    elif test == 1:
        test_unqiue_mysql()
    else:
        print(f"No matching test found for test {test}")
    return

def test_agent_reregister():
    # Implements a1
    return 

def test_agent_pause():
    # Implements a2
    return 

def test_agent_resume():
    # Implements a3
    return 

def test_agent_main(test):
    if test == 0: #there's no better way to do this? lame.
        test_agent_reregister()
        test_agent_pause()
        test_agent_resume()
    elif test == 1:
        test_agent_reregister()
    elif test == 2:
        test_agent_pause()
    elif test == 3:
        test_agent_resume()
    else:
        print(f"No matching test found for test {test}")
    return

def main():
    if not get_perms():
        print("This program must be ran as admin")
        input("Press ENTER to exit")
        return

    while True:
        print("="*LINE_SIZE)
        print(f"={'':^{LINE_SIZE-2}}=")
        print(f"={'Stabvest Tester':^{LINE_SIZE-2}}=")
        print(f"={'':^{LINE_SIZE-2}}=")
        print("="*LINE_SIZE)
        print()
        print("Select a test to run:")
        for key, value in OPTIONS.items():
            print(f"{key} - {value}")
        test = input("> ").strip()
        if test in ["quit","stop","exit"]:
            return
        try:
            test, sep, after = test.partition(":")[0]
            if not sep:
                raise AssertionError("Failed to parse input - enter only the test name (such as 'f1')")
            if test not in OPTIONS:
                raise AssertionError(f"Unknown test name: {test}")
            category = test[0]
            test = int(test[1])
            if category == "s":
                service = input("Enter the service name: ")
                if SYSTEM == "Windows":
                    if not run_powershell(f"Get-Service -Name '{service}'"):
                        raise AssertionError(f"Service not found: {service}")
                else:
                    if not run_bash(f"systemctl status {service}"):
                        raise AssertionError(f"Service not found: {service}")
                test_service_main(test,service)
            elif category == "i":
                test_interface_main(test)
            elif category == "w":
                port = input("Enter the scored port number: ")
                if port != "icmp":
                    if port < 1 or port > 65535:
                        raise AssertionError(f"Invalid port value {port}: must be between 1-65535, or 'icmp'")
                test_firewall_main(test,port)
            elif category == "f":
                path = input("Enter the full protected file path: ")
                if not path.os.exists(path):
                    raise AssertionError(f"Path does not exist: {path}")
                test_file_main(test,path)
            elif category == "u":
                service = input("Enter the service name: ")
                if SYSTEM == "Windows":
                    if not run_powershell(f"Get-Service -Name '{service}'"):
                        raise AssertionError(f"Service not found: {service}")
                else:
                    if not run_bash(f"systemctl status {service}"):
                        raise AssertionError(f"Service not found: {service}")
                test_unique_main(test,service)
            elif category == "a":
                test_agent_main(test)
            else:
                raise AssertionError(f"Category not supported: {category}")
        except AssertionError as E:
            print(E)
        except Exception as E:
            print(f"Unexpected exception: {E}")
        print()
        input("Press Enter to Continue")
        print()

if __name__ == "__main__":
    main()
