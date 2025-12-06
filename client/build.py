import os
import shutil
import subprocess
import re

# -----------------------------
# CONFIGURATION
# -----------------------------
#BUILD_DIR = "build_assets"

SERVER_FILE = "agent.py"
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
        SERVER_FILE,
        *NUITKA_ARGS,
    ]

    print("Running:", " ".join(nuitka_cmd))
    subprocess.run(nuitka_cmd, check=True)

    print("\n=== Build complete! ===")


if __name__ == "__main__":
    main()
