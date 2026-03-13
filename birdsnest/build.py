import os
import shutil
import subprocess
from pathlib import Path
import re
import platform
import io,tokenize

from htmlmin import minify as html_minify
from jsmin import jsmin

# -----------------------------
# CONFIGURATION
# -----------------------------
SOURCE_ITEMS = [
                "agents\\owlet\\.gitignore","agents\\owlet\\agent.py","agents\\owlet\\requirements.txt","agents\\owlet\\nssm-2.24_win64.exe",
                "agents\\stabvest\\.gitignore","agents\\stabvest\\agent.py","agents\\stabvest\\agent_tester.py","agents\\stabvest\\requirements.txt","agents\\stabvest\\nssm-2.24_win64.exe",
                "templates","static","modules",
                "models.py","server.py","shared.py","utilities.py","worker.py"
                ]
BUILD_DIR = "build_assets"

#TARGET_FILE = "server.py"
#NUITKA_ARGS = [
#    #"--standalone",
#    "--onefile",
#    #"--python-flag=no_docstrings", # breaks sqlalchemy
#]


# -----------------------------
# UTILITIES
# -----------------------------
script_re = re.compile(
    r"(<script[^>]*>)(.*?)(</script>)",
    flags=re.DOTALL | re.IGNORECASE
)

style_re = re.compile(
    r"(<style[^>]*>)(.*?)(</style>)",
    flags=re.DOTALL | re.IGNORECASE
)

def ensure_clean_dir(path):
    if os.path.exists(path):
        shutil.rmtree(path)
    os.makedirs(path)

def copy_tree(src, dst):
    shutil.copytree(src, dst)


# -----------------------------
# MINIFICATION FUNCTIONS
# -----------------------------
def minify_css(css_code):
    """Remove CSS comments and extra whitespace."""
    css_code = re.sub(r"/\*.*?\*/", "", css_code, flags=re.DOTALL)  # remove /* ... */
    css_code = re.sub(r"\s+", " ", css_code)                        # collapse whitespace
    css_code = re.sub(r"\s*([{}:;,])\s*", r"\1", css_code)          # tighten punctuation spacing
    return css_code.strip()


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
        elif token_type == tokenize.STRING:
            # If the string follows an '=', it's an assignment, NOT a docstring
            if prev_toktype == tokenize.OP and token_string == '=':
                out += token_string
            elif prev_toktype != tokenize.INDENT and prev_toktype != tokenize.NEWLINE:
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
    return "\n".join([line for line in out.split('\n') if line.strip()])


def minify_inline_js(html):
    def replace_script(match):
        open_tag, js_code, close_tag = match.groups()

        if "src=" in open_tag.lower():
            return match.group(0)

        return open_tag + jsmin(js_code) + close_tag

    return script_re.sub(replace_script, html)


def minify_inline_css(html):
    def replace_style(match):
        open_tag, css_code, close_tag = match.groups()
        return open_tag + minify_css(css_code) + close_tag

    return style_re.sub(replace_style, html)


def process_html_file(path):
    with open(path, "r", encoding="utf-8") as f:
        html = f.read()

    html = html_minify(html, remove_comments=True)
    html = minify_inline_js(html)
    html = minify_inline_css(html)

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)


def process_js_file(path):
    with open(path, "r", encoding="utf-8") as f:
        js = f.read()

    js = jsmin(js)

    with open(path, "w", encoding="utf-8") as f:
        f.write(js)


def process_css_file(path):
    with open(path, "r", encoding="utf-8") as f:
        css = f.read()

    css = minify_css(css)

    with open(path, "w", encoding="utf-8") as f:
        f.write(css)


def process_py_file(path):
    with open(path, "r", encoding="utf-8") as f:
        py = f.read()

    py = minify_py(py)

    with open(path, "w", encoding="utf-8") as f:
        f.write(py)


def minify_directory(dir_path):
    for root, _, files in os.walk(dir_path):
        for file in files:
            full_path = os.path.join(root, file)

            if file.endswith(".html"):
                process_html_file(full_path)

            elif file.endswith(".js"):
                process_js_file(full_path)

            elif file.endswith(".css"):
                process_css_file(full_path)
            
            elif file.endswith(".py"):
                process_py_file(full_path)

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
    print("=== Cleaning build directory ===")
    ensure_clean_dir(BUILD_DIR)

    print("=== Copying asset directories ===")
    for f in SOURCE_ITEMS:
        dest_path = os.path.join(BUILD_DIR, f)
        if Path(f).is_dir():
            copy_tree(f, dest_path)
        else:
            dest_parent = os.path.dirname(dest_path)
            if not os.path.exists(dest_parent):
                os.makedirs(dest_parent)
            shutil.copy(f, dest_path)

    print("=== Minifying HTML, JS, and CSS assets ===")
    minify_directory(BUILD_DIR)

    """
    print("=== Running Nuitka ===")
    nuitka_cmd = [
        "python", "-m", "nuitka",
        TARGET_FILE,
        *NUITKA_ARGS,
        #"--plugin-enable=flask",
        #"--plugin-enable=sqlalchemy",
        #"--include-module=sqlalchemy.orm.dependency",
        #"--include-module=flask_sqlalchemy.dependency",
        "--include-package=OpenSSL",
        #"--include-package=pyopenssl",
        f"--include-data-dir={BUILD_DIR}/templates=templates",
        f"--include-data-dir={BUILD_DIR}/static=static",
    ]

    print("Running:", " ".join(nuitka_cmd))
    subprocess.run(nuitka_cmd, check=True)
    """

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
