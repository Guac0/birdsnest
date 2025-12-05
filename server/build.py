import os
import shutil
import subprocess
from pathlib import Path
import re

from htmlmin import minify as html_minify
from jsmin import jsmin

# -----------------------------
# CONFIGURATION
# -----------------------------
SOURCE_TEMPLATES = "templates"
SOURCE_STATIC = "static"
BUILD_DIR = "build_assets"

SERVER_FILE = "server.py"
NUITKA_ARGS = [
    #"--standalone",
    "--onefile",
    #"--python-flag=no_docstrings", # breaks sqlalchemy
]


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


# -----------------------------
# MAIN BUILD PROCESS
# -----------------------------
def main():
    print("=== Cleaning build directory ===")
    ensure_clean_dir(BUILD_DIR)

    print("=== Copying asset directories ===")
    copy_tree(SOURCE_TEMPLATES, os.path.join(BUILD_DIR, "templates"))
    copy_tree(SOURCE_STATIC, os.path.join(BUILD_DIR, "static"))

    print("=== Minifying HTML, JS, and CSS assets ===")
    minify_directory(BUILD_DIR)

    print("=== Running Nuitka ===")
    nuitka_cmd = [
        "python", "-m", "nuitka",
        SERVER_FILE,
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

    print("\n=== Build complete! ===")


if __name__ == "__main__":
    main()
