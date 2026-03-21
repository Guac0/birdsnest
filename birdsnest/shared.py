# Contains shared logic like configuration values and logging
# Does not contain shared functions and code apart from critical, first-run setup items

import os, json, logging
from datetime import datetime, timedelta
from concurrent_log_handler import ConcurrentRotatingFileHandler
import platform
from pathlib import Path
from flask_login import UserMixin
import sys

#os.umask(0) # 666/777

CONFIG_DEFAULTS = {
    "HOST": "0.0.0.0",
    "PORT": 8000,
    "PUBLIC_URL": "https://{HOST}:{PORT}",
    "LOGFILE": "log_{timestamp}.txt",
    "SECRET_KEY": "changemeplease",
    "STALE_TIME": 300,
    "DEFAULT_WEBHOOK_SLEEP_TIME": 0.25,
    "MAX_WEBHOOK_MSG_PER_MINUTE": 50,
    "WEBHOOK_URL": "",
    "CREATE_TEST_DATA": True,
    "DATABASE_CREDS": "birdsnest:birdsnestpwd",
    "DATABASE_LOCATION": "database:5432",
    "DATABASE_DB": "birdsnestdb",
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

    return config

CONFIG = load_config("config.json") # relative to cwd!
HOST = CONFIG["HOST"]
PORT = CONFIG["PORT"]
PUBLIC_URL = CONFIG["PUBLIC_URL"]
LOGFILE = CONFIG["LOGFILE"]
STALE_TIME = CONFIG["STALE_TIME"]
DEFAULT_WEBHOOK_SLEEP_TIME = CONFIG["DEFAULT_WEBHOOK_SLEEP_TIME"]
MAX_WEBHOOK_MSG_PER_MINUTE = CONFIG["MAX_WEBHOOK_MSG_PER_MINUTE"]
WEBHOOK_URL = CONFIG["WEBHOOK_URL"]
INITIAL_AGENT_AUTH_TOKENS = CONFIG["AGENT_AUTH_TOKENS"]
INITIAL_WEBGUI_USERS = CONFIG["WEBGUI_USERS"]
DATABASE_CREDS = CONFIG["DATABASE_CREDS"]
DATABASE_LOCATION = CONFIG["DATABASE_LOCATION"]
DATABASE_DB = CONFIG["DATABASE_DB"]
AUTHCONFIG_STRICT_IP = CONFIG["AUTHCONFIG_STRICT_IP"]
AUTHCONFIG_STRICT_USER = CONFIG["AUTHCONFIG_STRICT_USER"]
AUTHCONFIG_CREATE_INCIDENT = CONFIG["AUTHCONFIG_CREATE_INCIDENT"]
AUTHCONFIG_LOG_ATTEMPT_SUCCESSFUL = CONFIG["AUTHCONFIG_LOG_ATTEMPT_SUCCESSFUL"]
CREATE_TEST_DATA = CONFIG["CREATE_TEST_DATA"]
SECRET_KEY = CONFIG["SECRET_KEY"]

GIT_PROJECT_ROOT = os.path.join(os.path.dirname(Path(__file__).resolve()),"repos")
if not os.path.exists(GIT_PROJECT_ROOT):
    os.mkdir(GIT_PROJECT_ROOT)

def setup_logging(argname="default"): #note that argname is now unused
    context = os.environ.get("APP_CONTEXT", "DEFAULT")
    name = context
    logger = logging.getLogger(name)

    if logger.handlers:
        #logger.info(f"setup_logging(): logger already exists, returning existing logger")
        return logger

    logger.setLevel(logging.INFO)

    handler = ConcurrentRotatingFileHandler(
        LOGFILE,        # LOGFILE path
        "a",              # append mode
        10 * 1024 * 1024, # maxBytes: 10MB
        10,               # backupCount: keep 10 old logs
        encoding='utf-8'
    )
    stream_handler = logging.StreamHandler(sys.stdout)
    
    formatter = logging.Formatter(
        '[%(asctime)s] [%(name)s] [%(process)d] %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    handler.setFormatter(formatter)
    stream_handler.setFormatter(formatter)
    
    logger.addHandler(handler)
    logger.addHandler(stream_handler)
    
    # Optional: Prevent logs from bubbling up to the root logger
    logger.propagate = False

    if context == "SERVER":
        gunicorn_logger = logging.getLogger("gunicorn.error")
        gunicorn_logger.addHandler(handler)
    # Optional: Catch all other library logs (SQLAlchemy, etc.)
    logging.getLogger().addHandler(stream_handler)
    
    return logger

# Path to the git-http-backend executable
# On Linux: /usr/lib/git-core/git-http-backend
# On Windows: C:/Program Files/Git/mingw64/libexec/git-core/git-http-backend.exe
if "windows" in platform.system().lower():
    GIT_BACKEND = "C:/Program Files/Git/mingw64/libexec/git-core/git-http-backend.exe"
else:
    if Path("/usr/lib/git-core/git-http-backend").is_file():
        GIT_BACKEND = "/usr/lib/git-core/git-http-backend"
    else:
        if Path("/usr/libexec/git-core/git-http-backend").is_file():
            GIT_BACKEND = "/usr/libexec/git-core/git-http-backend"
        else:
            GIT_BACKEND = f"/no/backend/found/for/{platform.system().lower().split()}"
class User(UserMixin):
    def __init__(self, id, role):
        # Password is not saved here - use webgui_users.get(username)['password']
        self.id = id
        self.role = role