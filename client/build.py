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
            osname = platform.dist()[1] # Ubuntu, debian, redhat
        else:
            osname = '_'.join(platform.dist()) # Ubuntu 10.04 lucid, debian 4.0 , fedora 17 Beefy Miracle, redhat 5.6 Tikanga, redhat 5.9 Final (<- centos)
    else:
        if simple:
            osname = platform.system() # Windows, FreeBSD
        else:
            osname = f"{platform.system()}_{platform.release()}"

    try:
        if platform.system() == "Windows":
            os.rename(f"{TARGET_FILE.split(".")[0]}.exe",f"{TARGET_FILE.split(".")[0]}_{osname}.exe")
            print(f"Renamed output file to {TARGET_FILE.split(".")[0]}_{osname}.exe")
        else:
            os.rename(f"{TARGET_FILE.split(".")[0]}.bin",f"{TARGET_FILE.split(".")[0]}_{osname}.bin")
            print(f"Renamed output file to {TARGET_FILE.split(".")[0]}_{osname}.bin")
    except FileNotFoundError as E:
        print("Attempted to rename output file but could not locate it (possible unexpected file exception or Nuitka error)")
        print(f"Full error: {E}")

if __name__ == "__main__":
    main()
