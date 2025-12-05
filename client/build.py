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
        #"--plugin-enable=flask",
        #"--plugin-enable=sqlalchemy",
        #"--include-module=sqlalchemy.orm.dependency",
        #"--include-module=flask_sqlalchemy.dependency",
        #f"--include-data-dir={BUILD_DIR}/templates=templates",
        #f"--include-data-dir={BUILD_DIR}/static=static",
    ]

    print("Running:", " ".join(nuitka_cmd))
    subprocess.run(nuitka_cmd, check=True)

    print("\n=== Build complete! ===")


if __name__ == "__main__":
    main()
