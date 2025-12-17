import os
import shutil
import subprocess
import re
import platform

# -----------------------------
# CONFIGURATION
# -----------------------------
#BUILD_DIR = "build_assets"

TARGET_FILE = "agent.py"
NUITKA_ARGS = [
    #"--standalone",
    "--onefile",
    #"--include-package=encodings",
    #"--include-package=ctypes",
    #"--include-package=os", 
    #"--include-package=io",
    #"--include-package=win32timezone",
    #"--include-data-file=pythonservice.exe=pythonservice.exe",
    #"--include-package-data=python",
    #"--verbose",
    #"--report=nuitka_report.xml",
    #"--enable-plugin=anti-bloat", #pywin32
    #"--python-flag=no_docstrings", # breaks sqlalchemy
]

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

# -----------------------------
# MAIN BUILD PROCESS
# -----------------------------
def main():

    print("=== Running Nuitka ===")
    nuitka_cmd = [
        "python", "-m", "nuitka",
        TARGET_FILE,
        *NUITKA_ARGS,
    ]

    print("Running:", " ".join(nuitka_cmd))
    subprocess.run(nuitka_cmd, check=True)

    print("\n=== Build complete! ===")

    osname=""
    system = platform.system()
    simple=False
    if system == "Linux":
        if simple:
            osname = get_platform_dist()[1] # Ubuntu, debian, redhat
        else:
            osname = '_'.join(get_platform_dist()) # Ubuntu 10.04 lucid, debian 4.0 , fedora 17 Beefy Miracle, redhat 5.6 Tikanga, redhat 5.9 Final (<- centos)
    else:
        if simple:
            osname = platform.system() # Windows, FreeBSD
        else:
            osname = f"{platform.system()}_{platform.release()}"

    try:
        if platform.system() == "Windows":
            dest = f"{TARGET_FILE.split('.')[0]}_{osname}.exe"
            if os.path.exists(dest):
                os.remove(dest)
            os.rename(f"{TARGET_FILE.split('.')[0]}.exe",dest)
            print(f"Renamed output file to {dest}")
        else:
            dest = f"{TARGET_FILE.split('.')[0]}_{osname}.bin"
            if os.path.exists(dest):
                os.remove(dest)
            os.rename(f"{TARGET_FILE.split('.')[0]}.bin",dest)
            print(f"Renamed output file to {dest}")
    except FileNotFoundError as E:
        print("Attempted to rename output file but could not locate it (possible unexpected file exception or Nuitka error)")
        print(f"Full error: {E}")

if __name__ == "__main__":
    main()
