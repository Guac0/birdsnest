# Holds shared logic like configuration values and logging
import os, json, logging
from datetime import datetime, timedelta
from concurrent_log_handler import ConcurrentRotatingFileHandler
import platform
from pathlib import Path
from flask_login import UserMixin

#os.umask(0) # 666/777

CONFIG_DEFAULTS = {
    "HOST": "0.0.0.0",
    "PORT": 8080,
    "PUBLIC_URL": "https://{HOST}:{PORT}",
    "LOGFILE": "log_{timestamp}.txt",
    "SAVEFILE": "save_{timestamp}.db",
    "SECRET_KEY": "changemeplease",
    "SAVE_INTERVAL": 60,
    "STALE_TIME": 300,
    "DEFAULT_WEBHOOK_SLEEP_TIME": 0.25,
    "MAX_WEBHOOK_MSG_PER_MINUTE": 50,
    "WEBHOOK_URL": "",
    "CREATE_TEST_DATA": True,
    "AUTHCONFIG_STRICT_IP": False,
    "AUTHCONFIG_STRICT_USER": False,
    "AUTHCONFIG_CREATE_INCIDENT": False,
    "AUTHCONFIG_LOG_ATTEMPT_SUCCESSFUL": True,
    "AGENT_AUTH_TOKENS": {
        "testtoken": { 
            "added_by": "default"
        }
    },
    "WEBGUI_USERS": {
        "admin": {"password": "admin", "role": "admin"},
        "analyst": {"password": "analyst", "role": "analyst"},
        "guest": {"password": "guest", "role": "guest"}
    }
}

def load_config(path):
    config = CONFIG_DEFAULTS.copy()
    badPath = False

    if os.path.exists(path):
        with open(path, "r") as f:
            config.update(json.load(f))
    else:
        badPath = True

    # Generate timestamp once
    now = datetime.now()

    # 2. Round up to the start of the next minute
    # (Adds 1 minute and zeros out the seconds/microseconds)
    next_minute = (now + timedelta(minutes=1)).replace(second=0, microsecond=0)

    # 3. Generate the timestamp string
    timestamp = next_minute.strftime("%Y-%m-%d_%H-%M-00")

    # Replace placeholders in strings
    for key, value in config.items():
        if isinstance(value, str):
            config[key] = value.format(
                HOST=config.get("HOST"),
                PORT=config.get("PORT"),
                timestamp=timestamp
            )

    if badPath:
        print(f"[-] {timestamp} load_config(): config file path not found: {path}")
        with open(config.get("LOGFILE"), "a") as f: # intentionally not the correct logfile format
            f.write(f"[{timestamp}] CRITICAL - load_config(): config file path not found: {path}")

    #config["PUBLIC_URL"] = f"http://{config['HOST']}:{config['PORT']}"
    #config["LOGFILE"] = f"log_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt"
    #config["SAVEFILE"] = f"save_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.json"

    return config

CONFIG = load_config("config.json") # relative to cwd!
HOST = CONFIG["HOST"]
PORT = CONFIG["PORT"]
PUBLIC_URL = CONFIG["PUBLIC_URL"]
LOGFILE = CONFIG["LOGFILE"]
SAVEFILE = CONFIG["SAVEFILE"]
SAVE_INTERVAL = CONFIG["SAVE_INTERVAL"]
STALE_TIME = CONFIG["STALE_TIME"]
DEFAULT_WEBHOOK_SLEEP_TIME = CONFIG["DEFAULT_WEBHOOK_SLEEP_TIME"]
MAX_WEBHOOK_MSG_PER_MINUTE = CONFIG["MAX_WEBHOOK_MSG_PER_MINUTE"]
WEBHOOK_URL = CONFIG["WEBHOOK_URL"]
INITIAL_AGENT_AUTH_TOKENS = CONFIG["AGENT_AUTH_TOKENS"]
INITIAL_WEBGUI_USERS = CONFIG["WEBGUI_USERS"]
AUTHCONFIG_STRICT_IP = CONFIG["AUTHCONFIG_STRICT_IP"]
AUTHCONFIG_STRICT_USER = CONFIG["AUTHCONFIG_STRICT_USER"]
AUTHCONFIG_CREATE_INCIDENT = CONFIG["AUTHCONFIG_CREATE_INCIDENT"]
AUTHCONFIG_LOG_ATTEMPT_SUCCESSFUL = CONFIG["AUTHCONFIG_LOG_ATTEMPT_SUCCESSFUL"]
CREATE_TEST_DATA = CONFIG["CREATE_TEST_DATA"]
SECRET_KEY = CONFIG["SECRET_KEY"]

# Path to the git-http-backend executable
# On Linux: /usr/lib/git-core/git-http-backend
# On Windows: C:/Program Files/Git/mingw64/libexec/git-core/git-http-backend.exe
if "windows" in platform.system().lower():
    GIT_BACKEND = "C:/Program Files/Git/mingw64/libexec/git-core/git-http-backend.exe"
else:
    GIT_BACKEND = "/usr/lib/git-core/git-http-backend"
GIT_PROJECT_ROOT = os.path.join(os.path.dirname(Path(__file__).resolve()),"repos")
if not os.path.exists(GIT_PROJECT_ROOT):
    os.mkdir(GIT_PROJECT_ROOT)

def setup_logging(name="default"):
    # 1. Create a logger instance
    logger = logging.getLogger(name)
    
    # If the logger already has handlers, don't add more (prevents duplicate entries)
    if logger.handlers:
        logger.info(f"setup_logging(): logger already exists, returning existing logger")
        return logger

    logger.setLevel(logging.INFO)

    # 2. Use ConcurrentRotatingFileHandler
    # This handles multiple processes (Gunicorn workers + Worker.py) 
    # and manages the .lock file automatically to prevent rotation crashes.
    handler = ConcurrentRotatingFileHandler(
        LOGFILE,        # LOGFILE path
        "a",              # append mode
        10 * 1024 * 1024, # maxBytes: 10MB
        10,               # backupCount: keep 10 old logs
        encoding='utf-8'
    )
    
    # 3. Define the log format
    formatter = logging.Formatter(
        '[%(asctime)s] [%(name)s] [%(process)d] %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    # Note: Added [%(process)d] to the format above. 
    # This helps you identify which Gunicorn worker or background thread 
    # sent the message when debugging.
    
    handler.setFormatter(formatter)
    
    # 4. Add the handler to the logger
    logger.addHandler(handler)
    
    # Optional: Prevent logs from bubbling up to the root logger
    logger.propagate = False
    
    return logger

class User(UserMixin):
    def __init__(self, id, role):
        # Password is not saved here - use webgui_users.get(username)['password']
        self.id = id
        self.role = role