import os
import shutil
import subprocess
import re
import platform
import tokenize,io

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


def minify_py(py_code):
    """
    Returns 'source' minus comments and docstrings.
    """
    io_obj = io.StringIO(py_code)
    out = ""
    prev_toktype = tokenize.INDENT
    last_lineno = -1
    last_col = 0
    for tok in tokenize.generate_tokens(io_obj.readline):
        token_type = tok[0]
        token_string = tok[1]
        start_line, start_col = tok[2]
        end_line, end_col = tok[3]
        ltext = tok[4]
        # The following two conditionals preserve indentation.
        # This is necessary because we're not using tokenize.untokenize()
        # (because it spits out code with copious amounts of oddly-placed
        # whitespace).
        if start_line > last_lineno:
            last_col = 0
        if start_col > last_col:
            out += (" " * (start_col - last_col))
        # Remove comments:
        if token_type == tokenize.COMMENT:
            pass
        # This series of conditionals removes docstrings:
        elif token_type == tokenize.STRING:
            if prev_toktype != tokenize.INDENT:
        # This is likely a docstring; double-check we're not inside an operator:
                if prev_toktype != tokenize.NEWLINE:
                    # Note regarding NEWLINE vs NL: The tokenize module
                    # differentiates between newlines that start a new statement
                    # and newlines inside of operators such as parens, brackes,
                    # and curly braces.  Newlines inside of operators are
                    # NEWLINE and newlines that start new code are NL.
                    # Catch whole-module docstrings:
                    if start_col > 0:
                        # Unlabelled indentation means we're inside an operator
                        out += token_string
                    # Note regarding the INDENT token: The tokenize module does
                    # not label indentation inside of an operator (parens,
                    # brackets, and curly braces) as actual indentation.
                    # For example:
                    # def foo():
                    #     "The spaces before this docstring are tokenize.INDENT"
                    #     test = [
                    #         "The spaces before this string do not get a token"
                    #     ]
        else:
            out += token_string
        prev_toktype = token_type
        last_col = end_col
        last_lineno = end_line
    return "\n".join([line for line in out.splitlines() if line.strip()])

def process_py_file(path):
    with open(path, "r", encoding="utf-8") as f:
        py = f.read()

    py = minify_py(py)

    with open(path, "w", encoding="utf-8") as f:
        f.write(py)

# -----------------------------
# MAIN BUILD PROCESS
# -----------------------------
def main():

    """
    print("=== Running Nuitka ===")
    nuitka_cmd = [
        "python", "-m", "nuitka",
        TARGET_FILE,
        *NUITKA_ARGS,
    ]

    print("Running:", " ".join(nuitka_cmd))
    subprocess.run(nuitka_cmd, check=True)
    """

    shutil.copy("agent.py", "agent_reduced.py")
    process_py_file("agent_reduced.py")

    print("\n=== Build complete! ===")

    """
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
    """

if __name__ == "__main__":
    main()
