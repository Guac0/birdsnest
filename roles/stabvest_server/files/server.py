from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin, current_user
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, abort, send_from_directory, session
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta
import time
import re
import os
import random
import atexit, signal, sys
import threading, time
import json
from collections import deque
import base64
from urllib.parse import urlparse, unquote_plus
import urllib.request
import urllib.error
import math
import logging
from logging.handlers import RotatingFileHandler
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import class_mapper
import subprocess
from pathlib import Path
import platform

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

CONFIG_DEFAULTS = {
    "HOST": "0.0.0.0",
    "PORT": 8080,
    "PUBLIC_URL": "https://{HOST}:{PORT}",
    "LOGFILE": "log_{timestamp}.txt",
    "SAVEFILE": "save_{timestamp}.db",
    "SAVE_INTERVAL": 60,
    "STALE_TIME": 300,
    "DEFAULT_WEBHOOK_SLEEP_TIME": 0.25,
    "MAX_WEBHOOK_MSG_PER_MINUTE": 50,
    "WEBHOOK_URL": "",
    "AUTHCONFIG_STRICT_IP": False,
    "AUTHCONFIG_STRICT_USER": False,
    "AUTHCONFIG_CREATE_INCIDENT": False,
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
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

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

# =================================
# ======= START USER CONFIG =======
# =================================

# === WEBGUI CONFIG ===
#webgui_users    = {                     # Valid roles: admin or analyst or guest
#    "admin": {"password": "admin", "role": "admin"},
#    "analyst": {"password": "analyst", "role": "analyst"},
#    "guest": {"password": "guest", "role": "guest"}
#}
# === SERVER CONFIG ===
#HOST            = "127.0.0.1"           # Listen IP
#PORT            = 8080                  # Listen Port
#PUBLIC_URL      = f"http://{HOST}:{PORT}"
#LOGFILE         = f"log_{datetime.now().strftime("%Y-%m-%d_%H-%M-%S")}.txt"   # File to write logs to
#SAVEFILE        = f"save_{datetime.now().strftime("%Y-%m-%d_%H-%M-%S")}.json"#f"save_testing2.json" # Savefile to save/load data from. Default f"save_{datetime.now().strftime("%Y-%m-%d_%H-%M-%S")}.json"
#SAVE_INTERVAL   = 60                    # Seconds between autosaves
#STALE_TIME      = 300                   # If agent has not checked in for this time period in seconds, mark them as stale
#DEFAULT_WEBHOOK_SLEEP_TIME = 0.25       # Seconds between webhook uploads. Mostly just used as a fallback value in case auto rate limiting fails
#MAX_WEBHOOK_MSG_PER_MINUTE = 50         # max 30 as of december 2025 for discord. this is shared between all webhooks in a single channel
#WEBHOOK_URL = ""
# test
#WEBHOOK_URL     = "https://discord.com/api/webhooks/1445146908808188065/1xkiXfsL7ie8i04rGxdMu6nnnzJsVtj188VbHtZT5oBNJIoOYV5VP8lpI-mJhzeNYuYD"
# ccdc
#
# === BEACON CONFIG ===
#agent_auth_tokens   = {
#    "testtoken": { # Change this per engagement. Allows beacons to authenticate to the server
#        "timestamp": time.time(),
#        "added_by": "default"
#    }
#}

# =================================
# ======== END USER CONFIG ========
# =================================

# =================================
# ==== INITIALIZE VARS/SETTINGS ===
# =================================

# === Set Flask Config ===
SQLALCHEMY_DATABASE_URI = f'sqlite:///{SAVEFILE}'
app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.urandom(32), # Randomize the key every startup to avoid cookie reuse
    SESSION_COOKIE_SECURE=True, # Forces the session cookie to be sent only over HTTPS.
    SESSION_COOKIE_HTTPONLY=True, # Prevents JavaScript from accessing the session cookie
    SESSION_COOKIE_SAMESITE="Strict", # "Strict": the cookie is only sent for requests from the same site (no subdomains)
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=2),
    SESSION_REFRESH_EACH_REQUEST=True # Automatic refreshes mean that lifetime is effectively infinite! This means that users actively on the site won't get signed out, but people who close the site but not the browser and keep it closed for 1 min will have to sign in again
)
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
# Silence the deprecation warning
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# === Initialize Misc Vars ===
start_time = time.time()
last_save_time=0
webhook_queue = deque()
webhook_queue_cond = threading.Condition()
ansible_queue = deque()
ansible_queue_cond = threading.Condition()
db = SQLAlchemy(app) # Initialize SQLAlchemy
TTYD_PROCESS = None
class User(UserMixin):
    def __init__(self, id, role):
        # Password is not saved here - use webgui_users.get(username)['password']
        self.id = id
        self.role = role
# See load_user() for the following
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # redirect to login page if not authenticated

# === DATA STRUCTURES ===
# Note: all timestamps are logged in unix time
# Note: all ids are created via joining the stated fields with "|" characters and base64ing the resulting string
#agents              = {}    # agent_id (name, hostname, ip, os): {agent_name(str),hostname(str),ip(str),os(str),executionUser(str),executionAdmin(bool),lastSeenTime(int, epoch time),lastStatus(bool),stale(bool),pausedUntil(int, epoch time)}
#messages            = {}    # message_id (timestamp,agent_id): {timestamp(int),agent_id(str),oldStatus(bool),newStatus(bool),message(str)}
#incidents           = {}    # incident_id (increments with each incident): {timestamp(int),agent_id(str),tag(str),oldStatus(bool),newStatus(bool),message(str),assignee(str),sla(int, epoch time)}. TAG can be "New", "Active", or "Closed". TODO: consider refactoring this using a reference to messages

# === DATABASE SETUP ===

# --- 1. AGENT Model ---
# Maps to the 'agents' dictionary structure. The primary key will be agent_name.
class Agent(db.Model):
    __tablename__ = 'agents'

    # Primary Key
    agent_id = db.Column(db.String(128), primary_key=True, nullable=False)

    # Agent details
    agent_name = db.Column(db.String(128))
    agent_type = db.Column(db.String(24))
    hostname = db.Column(db.String(128))
    ip = db.Column(db.String(45)) # IPv4 or IPv6
    os = db.Column(db.String(64))
    executionUser = db.Column(db.String(128))
    executionAdmin = db.Column(db.Boolean, default=False)
    
    # Status and Time
    lastSeenTime = db.Column(db.Integer, default=lambda: int(time.time())) # Epoch time (int)
    lastStatus = db.Column(db.Boolean, default=True) # True for OK, False for issue
    stale = db.Column(db.Boolean, default=False)
    pausedUntil = db.Column(db.String(32), default=0) # Epoch time in python style (str). 0 for default/natural expiry, 1 for manual resume

    messages = db.relationship('Message', backref='agent', lazy='dynamic', primaryjoin="Agent.agent_id == Message.agent_id")
    incidents = db.relationship('Incident', backref='agent', lazy='dynamic', primaryjoin="Agent.agent_id == Incident.agent_id")

    def __repr__(self):
        return f"<Agent {self.agent_name} ({'Online' if self.lastStatus else 'Down'})>"

# --- 2. MESSAGE Model ---
# Maps to the 'messages' dictionary structure.
# Uses a composite primary key of (timestamp, agent_id) for uniqueness and ordering.
class Message(db.Model):
    __tablename__ = 'messages'

    message_id = db.Column(db.String(128), primary_key=True, nullable=False)
    agent_id = db.Column(db.String(128), db.ForeignKey('agents.agent_id'), nullable=False)
    
    # Message-specific fields
    timestamp = db.Column(db.Integer, default=lambda: int(time.time()), nullable=False)
    oldStatus = db.Column(db.Boolean, nullable=False)
    newStatus = db.Column(db.Boolean, nullable=False)
    message = db.Column(db.Text, nullable=False) # Use Text for potentially long messages

    def __repr__(self):
        return f"<Message {self.timestamp} from {self.agent_id}>"

# --- 3. INCIDENT Model ---
# Maps to the 'incidents' dictionary structure. Refactored TAG to use a more standard field name.
class Incident(db.Model):
    __tablename__ = 'incidents'

    # Primary Key - using an auto-incrementing integer is standard for SQL primary keys
    incident_id = db.Column(db.Integer, primary_key=True)
    
    # Incident fields
    timestamp = db.Column(db.Integer, default=lambda: int(time.time()), nullable=False)
    agent_id = db.Column(db.String(128), db.ForeignKey('agents.agent_id'), nullable=False)
    
    tag = db.Column(db.String(10), default="New", nullable=False) # "New", "Active", "Closed"
    oldStatus = db.Column(db.Boolean, nullable=False)
    newStatus = db.Column(db.Boolean, nullable=False)
    message = db.Column(db.Text, nullable=False)
    assignee = db.Column(db.String(128))
    sla = db.Column(db.Integer) # Epoch time (int)

    def __repr__(self):
        return f"<Incident {self.incident_id} for {self.agent_id} (Tag: {self.tag})>"

# --- 4. AGENT_AUTH_TOKEN Model ---
# Maps to 'agent_auth_tokens'. Token is the primary key.
class AuthToken(db.Model):
    __tablename__ = 'auth_tokens'
    
    token = db.Column(db.String(128), primary_key=True, nullable=False) # The token string itself
    timestamp = db.Column(db.Integer, default=lambda: int(time.time()), nullable=False)
    added_by = db.Column(db.String(128))

    def __repr__(self):
        return f"<AuthToken {self.token[:8]}...>"

# --- 5. WEBGUI_USERS Model ---
# Maps to 'webgui_users'. Username is the primary key.
class WebUser(db.Model):
    __tablename__ = 'web_users'
    
    username = db.Column(db.String(64), primary_key=True, nullable=False)
    
    password = db.Column(db.String(128), nullable=False) 
    role = db.Column(db.String(20), nullable=False) # "admin", "analyst", or "guest"

    def __repr__(self):
        return f"<WebUser {self.username} (Role: {self.role})>"

class AnsibleResult(db.Model):
    __tablename__ = 'ansible_results'
    
    task = db.Column(db.Integer, primary_key=True, nullable=False)
    
    returncode = db.Column(db.Integer, nullable=False)
    result = db.Column(db.String(4096), nullable=False) 
    def __repr__(self):
        return f"<Ansible Task {self.task} (ReturnCode: {self.returncode}, Result: {self.result})>"
    def to_dict(self):
        """
        Converts the ORM object into a dictionary, making it ready for JSON serialization.
        """
        data = {
            'task': self.task,
            'returncode': self.returncode,
            'result': self.result,
        }
        return data

class AnsibleVars(db.Model):
    __tablename__ = 'ansiblevars'
    
    id = db.Column(db.String(32),primary_key=True, nullable=False)
    
    dest_ip = db.Column(db.String(64), default="192.168.1.1", nullable=False)
    ansible_folder = db.Column(db.String(256), default="~/ansible/", nullable=False)
    ansible_playbook = db.Column(db.String(64), default="playbook.yaml", nullable=False)
    ansible_inventory = db.Column(db.String(64), default="inventory.yaml", nullable=False)
    ansible_venv = db.Column(db.String(256), default="", nullable=False)
    ansible_user = db.Column(db.String(64), default="", nullable=False)
    ansible_port = db.Column(db.Integer, default=22, nullable=False)
    ansible_password = db.Column(db.String(256), default="", nullable=False)
    ansible_become_password = db.Column(db.String(256), default="", nullable=False)

    stabvest_deploy_dir_win = db.Column(db.String(16), default="C:\\stabvest", nullable=False)
    stabvest_deploy_dir_unix = db.Column(db.String(16), default="/stabvest", nullable=False)
    stabvest_agent_executable = db.Column(db.String(16), default="agent_Windows_10.exe", nullable=False)
    stabvest_tester_executable = db.Column(db.String(16), default="agent_tester_Windows_10.exe", nullable=False)
    stabvest_task_name = db.Column(db.String(16), default="stabvest", nullable=False)
    stabvest_task_interval = db.Column(db.Integer, default=60, nullable=False)
    stabvest_task_create = db.Column(db.Boolean, default=True, nullable=False)
    stabvest_include_tester = db.Column(db.Boolean, default=True, nullable=False)

    stabvest_agent_name = db.Column(db.String(16), default="", nullable=False)
    stabvest_auth_token = db.Column(db.String(128), default="testtoken", nullable=False)
    stabvest_agent_type = db.Column(db.String(32), default="stabvest", nullable=False)
    stabvest_server_url = db.Column(db.String(128), default="https://127.0.0.1:8080/", nullable=False)
    stabvest_server_timeout = db.Column(db.Integer, default=5, nullable=False)
    stabvest_sleeptime = db.Column(db.Integer, default=60, nullable=False)
    stabvest_disarm = db.Column(db.Boolean, default=True, nullable=False)
    stabvest_debug_print = db.Column(db.Boolean, default=True, nullable=False)
    stabvest_logfile = db.Column(db.String(256), default="log.txt", nullable=False)
    stabvest_backupdir = db.Column(db.String(256), default="", nullable=False)

    stabvest_mtu_min = db.Column(db.Integer, default=1200, nullable=False)
    stabvest_mtu_default = db.Column(db.Integer, default=1300, nullable=False)
    stabvest_mtu_max = db.Column(db.Integer, default=1514, nullable=False)
    stabvest_linux_default_ttl = db.Column(db.Integer, default=64, nullable=False)

    stabvest_ports = db.Column(db.String(256), default="[81]", nullable=False)
    stabvest_services = db.Column(db.String(256), default='["AxInstSV"]', nullable=False)
    stabvest_packages = db.Column(db.String(256), default='[""]', nullable=False)
    stabvest_service_backups = db.Column(db.String(1024), default='{"PathName":"C:\\Windows\\system32\\svchost.exe -k AxInstSVGroup", "StartName":"LocalSystem", "Dependencies":null, "DisplayName":"ActiveX Installer (AxInstSV)", "StartType": "Manual"}', nullable=False)

    def __repr__(self):
        return f"<Ansible Defaults for Profile {self.id}>"
    
    def to_dict(self):
        return {column.name: getattr(self, column.name) for column in self.__table__.columns}

class AuthConfig(db.Model):
    __tablename__ = 'authconfigs'
    
    id = db.Column(db.Integer, primary_key=True)
    entity_value = db.Column(db.String(100), nullable=False, unique=True)
    entity_type = db.Column(db.String(10), nullable=False) # 'IP' or 'USER'
    disposition = db.Column(db.String(10), nullable=False) # 'LEGITIMATE' or 'MALICIOUS'

    def to_dict(self):
        return {
            "value": self.entity_value,
            "type": self.entity_type,
            "status": self.disposition
        }
    
    def __repr__(self):
        return f"<AuthConfig {self.id}: {self.entity_type} {self.entity_value} is classified as {self.disposition}.>"
    
    def to_dict(self):
        return {column.name: getattr(self, column.name) for column in self.__table__.columns}

class AuthConfigGlobal(db.Model):
    __tablename__ = 'authconfigglobals'
    id = db.Column(db.Integer, primary_key=True)
    # The setting name (e.g., 'strict_ip', 'strict_user')
    key = db.Column(db.String(50), unique=True, nullable=False)
    # Boolean value stored as integer 0/1 for SQLite compatibility
    value = db.Column(db.Boolean, default=False)

class AuthRecord(db.Model):
    __tablename__ = 'authrecords'
    
    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.String(128), db.ForeignKey('messages.message_id'), nullable=False)
    agent_id = db.Column(db.String(128), db.ForeignKey('agents.agent_id'), nullable=False)

    user = db.Column(db.String(100), nullable=False)
    login_type = db.Column(db.String(32), nullable=False)
    srcip = db.Column(db.String(45), default="", nullable=False) # Increased for IPv6 support
    successful = db.Column(db.Boolean, nullable=False)
    timestamp = db.Column(db.Integer, nullable=False) # Helpful for sorting logs
    notes = db.Column(db.String(1024))

    def __repr__(self):
        status = "Success" if self.successful else "Failed"
        if self.notes:
            return f"<AuthRecord {self.id}: {self.login_type} login attempt on user {self.user} from {self.srcip} ({status}). Notes: {self.notes}>"
        return f"<AuthRecord {self.id}: {self.login_type} login attempt on user {self.user} from {self.srcip} ({status}).>"
    
    def to_dict(self):
        # This version is excellent as it handles all columns automatically
        return {column.name: getattr(self, column.name) for column in self.__table__.columns}

# =================================
# ======= UTILITY FUNCTIONS =======
# =================================

# === DATABASE ====

def insert_initial_data():
    """
    Inserts initial configuration data (auth tokens and users) into the database.
    This should only be run after the tables have been created via db.create_all().
    """
    try:
        # --- Insert Auth Tokens ---
        for token_value, data in INITIAL_AGENT_AUTH_TOKENS.items():
            # In a real app, you would first check if the token already exists 
            # to prevent duplicates, but for a first run, direct insert is fine.
            new_token = AuthToken(
                token=token_value,
                timestamp=time.time(),
                added_by=data["added_by"]
            )
            db.session.add(new_token)

        # --- Insert Web Users ---
        for username, data in INITIAL_WEBGUI_USERS.items():
            hashed_password = generate_password_hash(data["password"])
            new_user = WebUser(
                username=username,
                password=hashed_password, # WARNING: Hash passwords in production!
                role=data["role"]
            )
            db.session.add(new_user)
        
        db.session.commit()
        logger.info("Successfully inserted initial Auth Tokens and Web Users.")

    except Exception as e:
        db.session.rollback()
        logger.error(f"FATAL: Failed to insert initial data into DB: {e}")

def create_db_tables():

    db_exists = os.path.exists(os.path.join("instances",SAVEFILE))
    # Use the application context to ensure Flask extensions are configured
    with app.app_context():
        # This checks the database file defined in SQLALCHEMY_DATABASE_URI.
        # If the file (server.db) doesn't exist, it creates it.
        # If the tables defined in your models don't exist, it creates them.
        db.create_all()
        if not db_exists:
            insert_initial_data()
            logger.info(f"Initialized database with initial data at {SAVEFILE}")
        else:
            logger.info(f"Initialized database at {SAVEFILE}")

def serialize_model(instance):
    """
    Generic function to convert any SQLAlchemy model instance into a dictionary.
    It iterates over the columns defined in the model's mapping and extracts their values.
    
    NOTE: This only serializes direct columns and ignores relationships.
    """
    
    # Use class_mapper to get the mapped properties of the class
    mapper = class_mapper(instance.__class__)
    
    # Dictionary comprehension to build the serialized data
    serialized_data = {}
    for column in mapper.columns:
        # Get the value using the attribute name (column.key)
        value = getattr(instance, column.key)
        
        # NOTE ON NAMING CONVENTION:
        # If your clients expect camelCase/PascalCase (e.g., "executionUser", "lastSeenTime")
        # but your model uses snake_case (e.g., "execution_user", "last_seen_time"), 
        # you would need an extra mapping layer here. 
        # For simplicity, we are using the column key (snake_case) as the final key name. 
        # If needed, you can add a dictionary lookup here to map snake_case to the old 
        # client-expected casing if it differs.
        
        serialized_data[column.key] = value

    return serialized_data

# === BEACON SUPPORT ===

def run_git(args, cwd=GIT_PROJECT_ROOT):
    """Executes git commands with SSL verification disabled."""
    # -c http.sslVerify=false disables SSL checks for the specific command
    cmd = ["git", "-c", "http.sslVerify=false"] + args
    result = subprocess.run(
        cmd, 
        cwd=cwd, 
        capture_output=True, 
        text=True, 
        shell=(platform.system() == "Windows")
    )
    return result

def setup_logging():
    # 1. Create a logger instance
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO) # Set the minimum logging level

    # 2. Create a file handler
    # Use RotatingFileHandler to automatically manage file size and rotation
    # maxBytes: 10MB, backupCount: keep 10 old log files
    handler = RotatingFileHandler(
        LOGFILE,
        maxBytes=10 * 1024 * 1024,
        backupCount=10,
        encoding='utf-8'
    )
    
    # 3. Define the log format
    formatter = logging.Formatter(
        '[%(asctime)s] %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    handler.setFormatter(formatter)
    
    # 4. Add the handler to the logger
    logger.addHandler(handler)
    
    # 5. Disable default handlers (often necessary in Flask/Werkzeug)
    if logger.hasHandlers():
        logger.handlers.clear()
    logger.addHandler(handler)
    
    return logger

def hash_id(*args):
    # hash any number of args so that we have a single value to use as the id that remains unique if multiple items have similar fields
    # Does not need to be secure
    combined = "|".join(map(str, args))
    encoded = base64.b64encode(combined.encode("utf-8")).decode("utf-8")
    return encoded
    #return hashlib.sha256(f"{ip}|{hostname}".encode()).hexdigest() #sha256 hash - too complex to use on frontend

def matches_pattern(value, pattern):
    return pattern is None or re.fullmatch(pattern, value) is not None

def create_incident(messageDict,tag="New",assignee="",createAlert=True):
    """
    Creates a new incident record in the database and handles agent pause status.
    
    Args:
        messageDict (dict): Dictionary containing data derived from a Message (e.g., 
                            timestamp, agent_id, statuses, message, sla).
        tag (str): Incident status tag ("New", "Active", "Closed").
        assignee (str): Assigned analyst username.
        createAlert (bool): Whether to queue a webhook alert.
    """

    # --- 1. Create and Persist the Incident Record ---
    try:
        new_incident = Incident(
            # incident_id is auto-incremented by the database
            timestamp=messageDict["timestamp"],
            agent_id=messageDict["agent_id"],
            tag=tag,
            # Note: Changed to snake_case for consistency with model definitions
            oldStatus=messageDict["oldStatus"],
            newStatus=messageDict["newStatus"],
            message=messageDict["message"],
            assignee=assignee,
            sla=messageDict["sla"]
        )

        #if incident_id in incidents:
        #    logger.warning(f"/create_incident - incidents hash collision. Old incident: {incidents[incident_id]}. New incident: {incidentDict}")
        
        db.session.add(new_incident)
        db.session.commit()
        
        incident_id = new_incident.incident_id
        # incident_id is now available after the commit
        
    except Exception as e:
        # In a real app, use logger.error(f"Error creating incident: {e}")
        logger.error(f"create_incident(): Error creating incident: {e}")
        db.session.rollback() # Important: rollback the session on error
        return

    # --- 2. Handle Paused Status (Agent State Update) ---
    agent_id = new_incident.agent_id
    
    """
    try:
        # Check if the incident message indicates a pause
        
        if new_incident.message.lower().split(" - ")[1].split(" ")[0] == "paused":
            
            # Retrieve the Agent record using the primary key
            agent = db.session.get(Agent,agent_id)
            
            if agent:
                pattern = r'(\\d+)\\s*(?=seconds\\b)' # remove extra slashes if this is uncommented
                match = re.search(pattern, new_incident.message)
                
                if match:
                    seconds = int(match.group(1))
                    
                    # Update the database record directly
                    agent.pausedUntil = int(time.time()) + seconds
                    db.session.commit()
                else:
                    # logger.error(f"/create_incident - cannot parse seconds attribute...")
                    print(f"create_incident(): Cannot parse seconds in pause incident for Agent {agent_id}.")         
    except Exception as E:
        # This catches errors during the pause update, often due to 
        # messages not following the expected format.
        db.session.rollback() 
        # logger.debug(f"Non-standard incident message. Skipping pause update: {E}")
        pass 
    """

    # --- 3. Handle Alerts ---
    if createAlert:
        # This part remains mostly the same, but uses the committed incident_id
        # and the SQLAlchemy object attributes for the dictionary payload.
        
        # We assume webhook_queue_cond and webhook_queue are available globals.
        try:
            # We create a dictionary representation for the webhook handler if needed
            incident_payload = {
                "timestamp": new_incident.timestamp,
                "agent_id": new_incident.agent_id,
                "oldStatus": new_incident.oldStatus,
                "tag": new_incident.tag,
                "newStatus": new_incident.newStatus,
                "message": new_incident.message,
                "assignee": new_incident.assignee,
                "sla": new_incident.sla
            }
            
            #discord_webhook(incident_id,incidentDict)
            with webhook_queue_cond: # Might lead to minor sleep but nothing major
                webhook_queue.append({"incident_id": incident_id, "incident":incident_payload})
                webhook_queue_cond.notify() 
            # TODO trigger web alert?
            
        except Exception as E:
            # logger.error(f"Error queueing webhook: {E}")
            print(f"create_incident(): Could not queue webhook: {E}")

    return

def webhook_main():
    """Dedicated rate-limited sender thread with dynamic rate limiting."""
    if not WEBHOOK_URL:
        return

    last_60_seconds = [] # list of sent times as epoch time
    
    while True:
        # -----------------------------
        # BLOCKING dequeue (popleft)
        # -----------------------------
        with webhook_queue_cond:
            while not webhook_queue:
                webhook_queue_cond.wait()
            payload = webhook_queue.popleft()

        # Send the webhook and get the response/body
        with app.app_context():
            resp, body = discord_webhook(payload["incident_id"], payload["incident"])

        sleep_time = 0  # default unless rate limited

        try:
            if resp.code == 429:
                # Rate limited by Discord
                bodyDict = json.loads(body)
                sleep_time = float(bodyDict["retry_after"])

                # Requeue at TOP
                with webhook_queue_cond:
                    webhook_queue.appendleft(payload)
                    webhook_queue_cond.notify()

                logger.warning(f"/webhook_main - Retry_After succeeded, re-queued incident and sleeping for {sleep_time}.")

            else:
                # Maybe rate-limit headers present
                remaining = resp.getheader("X-RateLimit-Remaining")
                reset_after = resp.getheader("X-RateLimit-Reset-After")

                if remaining is not None and reset_after is not None:
                    try:
                        remaining_int = int(remaining)
                        reset_after_float = float(reset_after)

                        if remaining_int == 0:
                            sleep_time = reset_after_float
                            logger.info(f"/webhook_main - incident {payload['incident_id']}: 0 responses remaining, sleeping for {sleep_time}.")
                    except ValueError:
                        sleep_time = DEFAULT_WEBHOOK_SLEEP_TIME
                        logger.warning(f"/webhook_main - incident {payload['incident_id']}: failed to parse headers, sleeping {sleep_time}.")
                else:
                    sleep_time = DEFAULT_WEBHOOK_SLEEP_TIME
                    logger.warning(f"/webhook_main - Missing rate limit headers, sleeping {sleep_time}.")

        except Exception as e:
            sleep_time = DEFAULT_WEBHOOK_SLEEP_TIME
            logger.error(f"/webhook_main - caught unknown error from discord_webhook - {e}.")

        last_60_seconds.append(time.time())

        for incTime in last_60_seconds:
            if (time.time() - incTime) > 60:
                last_60_seconds.remove(incTime)
        
        if len(last_60_seconds) >= MAX_WEBHOOK_MSG_PER_MINUTE - 1:
            new_sleep_time = 60 - (time.time() - last_60_seconds[0]) # how long until first message is out of the 60 second window
            if new_sleep_time < sleep_time: # dont go below existing ratelimit if any
                new_sleep_time = sleep_time
            new_sleep_time = math.ceil(new_sleep_time * 100) / 100 # round to 2 decimals
            if new_sleep_time > (60 / MAX_WEBHOOK_MSG_PER_MINUTE): # reduce noise in normal operation
                logger.info(f"/webhook_main - client side ratelimiting enabled: sleeping for {new_sleep_time} seconds. Old sleep_time: {sleep_time}. len(last_60_seconds): {len(last_60_seconds)}. MAX_WEBHOOK_MSG_PER_MINUTE: {MAX_WEBHOOK_MSG_PER_MINUTE}.") 
            sleep_time = new_sleep_time # If we are client side ratelimited, set extra time to compensate for discord channel ratelimiting (wait until oldest message drops off)

        # Rate limit enforcement
        time.sleep(sleep_time)

def discord_webhook(incident_id,incident,url=WEBHOOK_URL):
    #compare rules level to set colors of the alert
    if not url:
        return
    
    color = "5e5e5e" # unknown
    
    try:
        if (incident["message"].lower().split(' ')[0]  == "firewall"):
            color = "641f1a"
        elif (incident["message"].lower().split(' ')[0]  == "interface"):
            color = "91251e"
        elif (incident["message"].lower().split(' ')[0]  == "service"):
            color = "8C573A"
        elif (incident["message"].lower().split(' ')[0]  == "servicecustom"):
            color = "a37526"
        elif (incident["message"].lower().split(' ')[0] == "agent"):
            color = "404C24"
        elif (incident["message"].lower().split(' ')[0] == "server"):
            color = "6d39cf"
        elif (incident["message"].lower().split(' ')[0] == "ir"):
            color = "4e08aa"
        elif (incident["message"].lower().split(' ')[0] == "inject"):
            color = "036995"
        elif (incident["message"].lower().split(' ')[0] == "uptime"):
            color = "380a8e"
    except Exception as E:
        # weird format, fallback to generic color
        pass

    #data that the webhook will receive and use to display the alert in discord chat
    try:
        incident_record = db.session.get(Incident,incident_id)
        agent = db.session.get(Agent,incident_record.agent_id)
        if not agent:
            #logger.warning(f"Could not find agent {incident_obj.agent_id} for incident {incident_obj.incident_id}.")
            raise KeyError
        
        payload = json.dumps({
        "embeds": [
            {
            "title": "Alert - {} Incident Created on {} for {}".format(incident["message"].split('-')[0].strip(),agent.hostname,agent.agent_name),
            "color": int(color,16),
            "description": "{}".format(incident["message"]),
            #"description": "{}\n\n[Open Dashboard]({}/incidents)".format(incident["message"],PUBLIC_URL),
            "url": f"{PUBLIC_URL}/incidents?incident_id={incident_id}",
            "fields": [
                {
                "name": "Incident #",
                "value": "{}".format(incident_id),
                "inline": True
                },
                {
                "name": "Timestamp",
                "value": "{}".format(datetime.fromtimestamp(incident["timestamp"])),
                "inline": True
                },
                {
                "name": "Autofix Status",
                "value": "{}".format(incident["newStatus"]),
                "inline": True
                },
                {
                "name": "Agent Name",
                "value": "{}".format(agent.agent_name),
                "inline": True
                },
                {
                "name": "Hostname",
                "value": "{}".format(agent.hostname),
                "inline": True
                },
                {
                "name": "IP Address",
                "value": "{}".format(agent.ip),
                "inline": True
                }
            ]
            }
        ]
        })
    except KeyError as E:
        payload = json.dumps({
        "embeds": [
            {
            "title": "Alert - Custom {} Incident Created".format(incident["message"].split('-')[0].strip()),
            "color": int(color,16),
            "description": "{}".format(incident["message"]),
            #"description": "{}\n\n[Open Dashboard]({}/incidents)".format(incident["message"],PUBLIC_URL),
            "url": f"{PUBLIC_URL}/incidents?incident_id={incident_id}",
            "fields": [
                {
                "name": "Incident #",
                "value": "{}".format(incident_id),
                "inline": True
                },
                {
                "name": "Timestamp",
                "value": "{}".format(datetime.fromtimestamp(incident["timestamp"])),
                "inline": True
                },
                {
                "name": "Autofix Status",
                "value": "{}".format(incident["newStatus"]),
                "inline": True
                }
            ]
            }
        ]
        })
    except IndexError as E:
        # weird data type with very short msg. should only happen with custom incidents, if any
        # Actually this probably will never get hit lol as split()[0] should always work
        payload = json.dumps({
        "embeds": [
            {
            "title": "Alert - Custom Generic Incident Created",
            "color": int(color,16),
            "description": "{}".format(incident["message"]),
            #"description": "{}\n\n[Open Dashboard]({}/incidents)".format(incident["message"],PUBLIC_URL),
            "url": f"{PUBLIC_URL}/incidents?incident_id={incident_id}",
            "fields": [
                {
                "name": "Incident #",
                "value": "{}".format(incident_id),
                "inline": True
                },
                {
                "name": "Timestamp",
                "value": "{}".format(datetime.fromtimestamp(incident["timestamp"])),
                "inline": True
                },
                {
                "name": "Autofix Status",
                "value": "{}".format(incident["newStatus"]),
                "inline": True
                }
            ]
            }
        ]
        })

    headers = {
        'content-type': 'application/json',
        'Accept-Charset': 'UTF-8',
        'User-Agent': 'python-urllib/3' # Required for urllib, automatic with requests
    }
    data = payload.encode("utf-8") if isinstance(payload, str) else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers=headers,
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            logger.info(f"/discord_webhook - sent message for incident {incident_id}.")

            #status_code = resp.getcode()
            #status_text = resp.read().decode("utf-8")
            #response_headers = resp.getheaders()   # <-- tuple list of headers

            #print("Status Code:", status_code)
            #print("Headers:")
            #for k, v in response_headers:
            #    print(f"  {k}: {v}")
            #print("Body:")
            #print(status_text)

            body = resp.read().decode('utf-8') if resp.fp else ''  # consume body
            return resp, body  # return the response for headers inspection
    except urllib.error.HTTPError as err: #error is actually the full comm object
        body = err.read().decode('utf-8') if err.fp else ''
        logger.error(f"/discord_webhook - failed to send message for incident {incident_id}. StatusCode: {err.code}. Body: {body}.") # Headers: {err.headers}. 
        return err,body

def periodic_stale(interval=60):
    """
    Checks agents' lastSeenTime against STALE_TIME and updates the 'stale' status.
    Generates a new incident if an agent moves into the stale state.
    Closes the relevant incident if an agent moves out of the stale state.
    """
    while True:
        time.sleep(interval)

        with app.app_context():
    
            # 1. Retrieve all agent records directly
            agents_records = Agent.query.all()
            
            agents_updated = False

            for agent in agents_records:

                if agent.agent_name == "custom":
                    continue
                    
                time_since_seen = time.time() - agent.lastSeenTime
                
                # --- Check for state change ---

                if agent.stale:
                    # Scenario A: Agent was STALE, checking if it has recovered
                    if time_since_seen < STALE_TIME:
                        # Agent is NO LONGER STALE (checked in recently)
                        agent.stale = False

                        criteria = {
                            "agent_id": agent.agent_id,
                            "tag": ('New', 'Active'),
                            "message": f"Agent - Agent {agent.agent_name} on {agent.hostname} moved to Stale state. Last seen {datetime.fromtimestamp(agent.lastSeenTime).strftime('%Y-%m-%d_%H-%M-%S')}."
                        }

                        incident_id = find_incident_db(criteria, newest=True)
        
                        if incident_id:
                            try:
                                incident = db.session.get(Incident,incident_id)
                                if incident:
                                    incident.tag = "Closed"
                                    logger.info(f"periodic_stale(): Stale incident {incident_id} CLOSED for {agent.agent_id}.")
                                    return True
                            except Exception as e:
                                logger.warning(f"periodic_stale(): Failed to close incident {incident_id}: {e}")
                                return False
                        
                        else:
                            logger.warning(f"periodic_stale(): Did not find incident for agent {agent.agent_id} recovering from Stale state.")

                        logger.info(f"periodic_stale(): Agent {agent.agent_id} recovered from stale state.")
                        agents_updated = True
                    # else: Agent is STILL STALE, continue checking others (no DB update)
                
                else:
                    # Scenario B: Agent was NOT STALE, checking if it is now stale
                    if time_since_seen > STALE_TIME:
                        # Agent is NOW STALE (missed check-in)
                        agent.stale = True
                        
                        # Generate a new incident
                        incident_data = {
                            "timestamp": time.time(),
                            "agent_id": agent.agent_id,
                            "oldStatus": agent.lastStatus,
                            "newStatus": False,
                            "message": f"Agent - Agent {agent.agent_name} on {agent.hostname} moved to Stale state. Last seen {datetime.fromtimestamp(agent.lastSeenTime).strftime('%Y-%m-%d_%H-%M-%S')}.",
                            "sla": 0
                        }
                        create_incident(incident_data)
                        logger.info(f"periodic_stale(): Agent {agent.agent_id} moved to stale state. Incident created.")
                        agents_updated = True

            # 2. Commit all accumulated changes at the end for efficiency
            if agents_updated:
                try:
                    db.session.commit()
                    logger.info("periodic_stale(): Database commit successful for stale status updates.")
                except Exception as e:
                    db.session.rollback()
                    logger.info(f"periodic_stale(): Database error during stale update: {e}")
            else:
                logger.info("periodic_stale(): No changes.")

def periodic_ansible(interval=5):
    # Handles the ansible queue
    # We could further unblock this by moving the subprocess execution to another worker, but it's not really intended for multiple agents to be deployed at once for now. As such, this is fine.

    while True:
        # -----------------------------
        # BLOCKING dequeue (popleft)
        # -----------------------------
        with ansible_queue_cond:
            while not ansible_queue:
                ansible_queue_cond.wait()
            item = ansible_queue.popleft()

        task = item["task"]
        dest_ip = item["data"]["dest_ip"]
        ansible_folder = item["data"]["ansible_folder"]
        extra_vars = item["data"]["extra_vars"]
        ansible_playbook = item["data"]["ansible_playbook"]
        ansible_inventory = item["data"]["ansible_inventory"]
        ansible_venv = item["data"]["ansible_venv"]
        if ansible_venv:
            command = f"source {ansible_venv} && cd {ansible_folder} && ansible-playbook {ansible_playbook} -i {ansible_inventory} -l {dest_ip} -t stabvest_client_auto {extra_vars}"
        else:
            command = f"cd {ansible_folder} && ansible-playbook {ansible_playbook} -i {ansible_inventory} -l {dest_ip} -t stabvest_client_auto {extra_vars}"

        logger.info(f"periodic_ansible(): starting subprocess for task {task}. command: {command}")
        
        result = subprocess.run(
            command,
            #"whoami",
            shell=True,
            capture_output=True, 
            text=True, 
            check=False
        )

        logger.info(f"periodic_ansible(): finished subprocess for task {task} and logging result to database. Returncode: {result.returncode}")

        with app.app_context():
            newResult = AnsibleResult(
                task = task,
                returncode = result.returncode,
                result = f"STDOUT: {result.stdout.strip()} ||| STDERR: {result.stderr.strip()}"
            )

            db.session.add(newResult)
            db.session.commit()
        
        time.sleep(interval) # interval isnt really needed i think

def find_incident(incidents, criteria, newest=False):
    """
    incidents: dict of incident_id -> incident_data
    criteria: dict of field -> expected_value
              (value may be tuple/list for OR-match)
    newest: False = return oldest match (default)
            True  = return newest match
    
    returns single matching incident id
    """
    def matches(incident):
        for key, required in criteria.items():
            value = incident.get(key)

            # allow tuple/list for (A OR B)
            if isinstance(required, (tuple, list)):
                if value not in required:
                    return False
            else:
                if value != required:
                    return False

        return True

    candidates = [
        (iid, data)
        for iid, data in incidents.items()
        if matches(data)
    ]

    if not candidates:
        return None

    # pick oldest or newest based on timestamp
    key_fn = (lambda x: -x[1]["timestamp"]) if newest else (lambda x: x[1]["timestamp"])

    selected_iid, _ = min(candidates, key=key_fn)
    return selected_iid

def find_incident_db(criteria, newest=False):
    """
    Finds a single incident record in the database based on criteria.

    NOTE: Criteria keys (e.g., 'oldStatus', 'agent_id') must match the 
    SQLAlchemy Incident model attributes (snake_case).

    Args:
        criteria (dict): dict of field -> expected_value.
                         (value may be tuple/list for OR-match using SQL IN operator)
        newest (bool): False = return oldest match (default: timestamp ASC)
                       True = return newest match (timestamp DESC)

    returns: single matching incident_id (int) or None
    """
    
    # Start the base query against the Incident model
    query = Incident.query
    
    # 1. Apply Filters based on criteria
    for key, required_value in criteria.items():
        # Get the corresponding column attribute from the Incident class
        column = getattr(Incident, key, None)
        
        if column is None:
            # If a criteria key doesn't match an attribute, we stop the query or skip the filter.
            # Choosing to stop and return None for strictness.
            logger.warning(f"find_incident_db(): Warning: Criteria key '{key}' does not match a column in Incident model.")
            return None 

        if isinstance(required_value, (tuple, list)):
            # Use the SQL 'IN' operator for OR-match (e.g., tag IN ('New', 'Active'))
            query = query.filter(column.in_(required_value))
        else:
            # Use standard equality filtering (e.g., agent_id == 'XYZ')
            query = query.filter(column == required_value)

    # 2. Apply Ordering
    if newest:
        # Sort by timestamp descending to get the newest first
        query = query.order_by(Incident.timestamp.desc())
    else:
        # Sort by timestamp ascending to get the oldest first (default)
        query = query.order_by(Incident.timestamp.asc())
        
    # 3. Execute Query and Retrieve Result
    # .first() retrieves the first result according to the ordering
    selected_incident = query.first()

    if selected_incident:
        return selected_incident.incident_id
    else:
        return None

def clean_and_join_path(path_string):
    # 1. Split the string by either forward (/) or backward (\) slashes
    # We use a regex character class [\\/] to match both.
    path_parts = re.split(r'[\\/]', path_string)
    
    # 2. Filter out empty strings (caused by leading/trailing or double slashes)
    path_parts = [part for part in path_parts if part]
    
    # 3. Join the parts using the current operating system's separator
    return os.path.join(*path_parts)

def get_git_stats(db,repos_root=os.path.join(GIT_PROJECT_ROOT,"")):
    results = []
    
    # Iterate through each folder in the repos directory
    for repo_folder in os.listdir(repos_root):
        repo_path = os.path.join(repos_root, repo_folder)
        logger.info(f"handling repo folder {repo_folder} at {repo_path}")
        
        # Only process directories
        if not os.path.isdir(repo_path):
            continue

        # Extract agent_id from repo name (e.g., "123.git" -> 123)
        agent_id_str = repo_folder.replace(".git", "")
        
        # Query DB for agent metadata
        agent = db.session.query(Agent).filter_by(agent_id=agent_id_str).first()

        # Data points for both required branches
        for branch in ["good", "bad"]:
            try:
                # 1. Get Commit Name (Subject) and Time
                # %s = subject, %at = author date (unix timestamp)
                
                commit_raw = run_git(["show", "-s", "--format=%s|%at", branch],os.path.join(GIT_PROJECT_ROOT,repo_folder))
                name, timestamp = commit_raw.split('|')

                # 2. Get Diff Stats
                # --summary provides "create mode", "delete mode"
                # --numstat provides added/deleted line counts
                diff_cmd = run_git(["diff", f"{branch}^!", "--summary"],os.path.join(GIT_PROJECT_ROOT,repo_folder))
                diff_output = subprocess.check_output(diff_cmd, cwd=repo_path, text=True)
                
                # Parse types of changes
                added = diff_output.count("create mode")
                deleted = diff_output.count("delete mode")
                # Modified is everything else in the diff that isn't a create/delete
                total_files_cmd = run_git(["diff", f"{branch}^!", "--name-only"],os.path.join(GIT_PROJECT_ROOT,repo_folder))
                total_files = len(subprocess.check_output(total_files_cmd, cwd=repo_path, text=True).splitlines())
                modified = total_files - (added + deleted)

                # Build the data point
                if agent:
                    results.append({
                        "repo_name": repo_folder,
                        "branch": branch,
                        "agent_name": agent.agent_name,
                        "hostname": agent.hostname,
                        "ip": agent.ip,
                        "latest_commit_name": name,
                        "latest_commit_time": datetime.fromtimestamp(int(timestamp)).strftime('%Y-%m-%d %H:%M:%S'),
                        "diffs": {
                            "files_added": added,
                            "files_deleted": deleted,
                            "files_modified": modified
                        }
                    })
                else:
                    results.append({
                        "repo_name": repo_folder,
                        "branch": branch,
                        "agent_name": "UNK",
                        "hostname": "UNK",
                        "ip": "UNK",
                        "latest_commit_name": name,
                        "latest_commit_time": datetime.fromtimestamp(int(timestamp)).strftime('%Y-%m-%d %H:%M:%S'),
                        "diffs": {
                            "files_added": added,
                            "files_deleted": deleted,
                            "files_modified": modified
                        }
                    })

            except subprocess.CalledProcessError as E:
                # Handle cases where a branch might not exist yet
                logger.warning(f"subprocess info {E}")
                continue

    logger.info(f"returning {results}")
    return results

# === SAVE AND LOAD ===
def save_state(filepath=SAVEFILE):
    return False
    """
    global last_save_time

    def prepare(data):
        if isinstance(data, set):
            return list(data)
        elif isinstance(data, dict):
            return {k: prepare(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [prepare(item) for item in data]
        else:
            return data

    state = {
        "webgui_users": webgui_users,
        "agent_auth_tokens": agent_auth_tokens,
        "agents": agents,
        "messages": messages,
        "incidents": incidents
    }

    with open(filepath, "w") as f:
        json.dump(state, f, indent=2)

    last_save_time=time.time()

    logger.info(f"save_state - saved current database to {SAVEFILE}")
    """

def signal_handler(signum, frame):
    save_state()
    sys.exit(0)

def periodic_autosave(interval=SAVE_INTERVAL):
    while True:
        time.sleep(interval)
        save_state()

def load_state(filepath=SAVEFILE):
    return False
    """
    global webgui_users, agents, messages, incidents, agent_auth_tokens

    try:
        with open(filepath, "r") as f:
            state = json.load(f)

        # Rehydrate any sets
        def restore(data):
            if isinstance(data, dict):
                return {k: restore(v) for k, v in data.items()}
            elif isinstance(data, list):
                return [restore(item) for item in data]
            return data

        agent_auth_tokens = state["agent_auth_tokens"]
        webgui_users = state["webgui_users"]
        agents = state["agents"]
        messages = state["messages"]
        incidents = state["incidents"]

        logger.info(f"load_state - {filepath} loaded!")

    except FileNotFoundError:
        logger.error(f"load_state - {filepath} not found, starting fresh!")
    """

# === LOGIN AND MISC ===

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != "admin":
            abort(403)  # Forbidden
        return f(*args, **kwargs)
    return decorated_function

def analyst_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or (current_user.role != "analyst" and current_user.role != "admin" ):
            abort(403)  # Forbidden
        return f(*args, **kwargs)
    return decorated_function

@login_manager.user_loader
def load_user(id):
    user_record = WebUser.query.filter(WebUser.username == id).first()
    if user_record:
        return User(id, user_record.role)
    return None

def is_safe_path(next_url: str) -> bool:
    if not next_url:
        return False
    # percent-decoded already by Flask for request.args/form, but be safe:
    next_url = unquote_plus(next_url)
    parsed = urlparse(next_url)
    # allow only relative paths (no scheme/netloc)
    return (parsed.scheme == "" and parsed.netloc == "" and next_url.startswith("/"))

# === TEST DATA ===
def get_random_time_offset_epoch(minutes_offset=30, direction="either"):
    """
    Returns a random timestamp in seconds since the epoch,
    within a specified minute offset from the current time.

    Args:
        minutes_offset (int): The maximum number of minutes for the offset.
        direction (str): "past", "future", or "either".

    Returns:
        float: A random timestamp in seconds since the epoch.
    """
    current_epoch_time = time.time()
    seconds_offset = minutes_offset * 60

    if direction == "past":
        random_offset = -random.uniform(0, seconds_offset)
    elif direction == "future":
        random_offset = random.uniform(0, seconds_offset)
    elif direction == "either":
        random_offset = random.uniform(-seconds_offset, seconds_offset)
    else:
        raise ValueError("direction must be 'past', 'future', or 'either'")

    return current_epoch_time + random_offset

def add_test_data_agents(num=5):
    # agent_id (name, hostname, ip, os): {agent_name(str),hostname(str),ip(str),os(str),executionUser(str),executionAdmin(bool),lastSeenTime(int),lastStatus(bool),stale(bool)}
    try:
        for i in range(1,num + 1):
            #agent_name = random.choice(["apache2","iis","smb","mysql","vsftpd"])
            agent_name = ["apache2","iis","smb","mysql","vsftpd"][i-1]
            agent_type = random.choice(["stabvest","owlet"])
            possible_hostnames = ["webserver1","webserver2","fileshare1","fileshare2","dc01"]
            #hostname = random.choice(possible_hostnames)
            hostname = possible_hostnames[i-1]
            possible_ips = ["10.1.1.1","10.1.1.2","10.1.1.3","10.1.1.4","10.1.1.5"]
            #ip = random.choice(possible_ips)
            ip = possible_ips[i-1]
            possible_oses = ["Windows 10","Windows 2016Server","Ubuntu 16.03 Bookworm","RHEL 9.3","Rocky 8"]
            #os = random.choice(possible_oses)
            os = possible_oses[i-1]

            # The agent_id is computed but we use a unique prefix for test data to avoid collisions
            #computed_agent_id = hash_id(f"test_agent_{i}", hostname, ip, os)
            computed_agent_id = hash_id(agent_name, hostname, ip, os)

            new_agent = Agent(
                agent_id=computed_agent_id,
                agent_name=agent_name,
                agent_type=agent_type,
                hostname=hostname,
                ip=ip,
                os=os,
                executionUser=random.choice(["root", "admin", ".\\administrator", "domain\\dadmin", "user"]),
                executionAdmin=random.choice([True, False]),
                lastSeenTime=time.time() - ((num - i) * 100),
                lastStatus=random.choice([True, False]),
                stale=random.choice([True, False]),
                pausedUntil=random.choice([str(0),str(0),str(1),str(time.time()),str(time.time() + 180), str(time.time() + 600)])
            )
            db.session.add(new_agent)
        db.session.commit()
        logger.info(f"Successfully added {num} test agents to the database.")
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to add test agent data: {e}")

def add_test_data_messages(num=15):
    try:
        all_agents = Agent.query.all()
        for i in range(1, num + 1):
            timestamp = time.time() - ((num - i) * 100)
            #agent_id = f"agent_{random.randint(1, 5)}" # Uses the agent_id naming pattern from the original code
            agent_id = random.choice(all_agents).agent_id

            message_id = hash_id(timestamp, agent_id)
            new_message = Message(
                message_id = message_id,
                timestamp=timestamp,
                agent_id=agent_id,
                oldStatus=random.choice([False, True]),
                newStatus=random.choice([False, True]),
                message=random.choice([
                    "Service - Missing required package {package} for service {service}, DISARMED.",
                    "Service - Service {service_name} not running, RESTORED service to START state.",
                    "Service - Service {service_name} not set to automatic start, FAILED to set to automatic start.",
                    "Firewall - Default {direction} policy is deny_all and no specific {direction.lower()} allow rule for port {port} exists. SUCCESSFULLY created firewall rule Stabvest_Rule_{port}_{direction}_{action}.",
                    "Firewall - Default {direction} policy is deny_all and no specific {direction.lower()} allow rule for port {port} exists. DISARMED, but told to create firewall rule Stabvest_Rule_{port}_{direction}_{action}.",
                    "Firewall - SUCCESSFULLY removed firewall rule: {rule['Name']}/{rule['DisplayName']}: {rule['Action']} {port} {rule['Direction']} on profile {rule['Profile']}.",
                    "Firewall - Could not get firewall rule information due to PowerShell error.",
                    "Interface - Interface {interface} was set to DOWN, RESTORED UP state.",
                    "Interface - Bad system TTL set, DISARMED.",
                    "Interface - Interface {interface}'s MTU was set to {old_mtu}, RESTORED new mtu {new_mtu}.",
                    "Agent - Paused for 60 seconds.",
                    "Agent - Resumed after sleeping for 60 seconds.",
                    "Agent - Resumed after sleeping for 60 seconds, EARLY EXIT.",
                    "Agent - Agent re-registered.",
                    "ServiceCustom - MySQL users changed.",
                    "ServiceCustom - MySQL data changed.",
                    "ServiceCustom - IIS Site Config changed.",
                    "ServiceCustom - IIS Application Pool changed.",
                    "all good",
                    "all good",
                    "all good",
                    "all good",
                    "all good",
                    "all good"#,
                    #"Generic - Test Test Test.",
                    #"Generic - Test Test Test."
                ])
            )
            db.session.add(new_message)
            
        db.session.commit()
        logger.info(f"Successfully added {num} test messages to the database.")
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to add test message data: {e}")

def add_test_data_incidents(num=15,createAlert=True):
    all_agents = Agent.query.all()
    for i in range(1, num + 1):
        ranagent = random.choice(all_agents)
        #agent_id = f"agent_{random.randint(1,5)}"
        agent_id = ranagent.agent_id
        agent_name = ranagent.agent_name
        #agent_name = f"agent_{random.randint(1,5)}"
        hostname = "exampleHost"
        lastSeenTime = time.time() - ((num - i) * 100)
        incident_data = {
            "timestamp": lastSeenTime,
            "agent_id": agent_id,
            "oldStatus": random.choice([False,True]),
            "newStatus": random.choice([False,True]),
            "message": random.choice([
                "Service - Missing required package {package} for service {service}, DISARMED.",
                "Service - Service {service_name} not running, RESTORED service to START state.",
                "Service - Service {service_name} not set to automatic start, FAILED to set to automatic start.",
                "Firewall - Default {direction} policy is deny_all and no specific {direction.lower()} allow rule for port {port} exists. SUCCESSFULLY created firewall rule Stabvest_Rule_{port}_{direction}_{action}.",
                "Firewall - Default {direction} policy is deny_all and no specific {direction.lower()} allow rule for port {port} exists. DISARMED, but told to create firewall rule Stabvest_Rule_{port}_{direction}_{action}.",
                "Firewall - SUCCESSFULLY removed firewall rule: {rule['Name']}/{rule['DisplayName']}: {rule['Action']} {port} {rule['Direction']} on profile {rule['Profile']}.",
                "Firewall - Could not get firewall rule information due to PowerShell error.",
                "Interface - Interface {interface} was set to DOWN, RESTORED UP state.",
                "Interface - Bad system TTL set, DISARMED.",
                "Interface - Interface {interface}'s MTU was set to {old_mtu}, RESTORED new mtu {new_mtu}.",
                f"Agent - Agent {agent_name} on {hostname} moved to Stale state. Last seen {datetime.fromtimestamp(lastSeenTime).strftime('%Y-%m-%d_%H-%M-%S')}",
                "Agent - Paused for 60 seconds.",
                "Agent - Resumed after sleeping for 60 seconds.",
                "Agent - Resumed after sleeping for 60 seconds, EARLY EXIT.",
                "Agent - Agent re-registered.",
                "ServiceCustom - MySQL users changed.",
                "ServiceCustom - MySQL data changed.",
                "ServiceCustom - IIS Site Config changed.",
                "ServiceCustom - IIS Application Pool changed.",
                "Generic - Test Test Test.",
                "Generic - Test Test Test.",
                "Genericshort",
                "Genericshort"
            ]),
            "sla": random.choice([0,get_random_time_offset_epoch(90)])
        }
        create_incident(
            incident_data,
            tag=random.choice(["New", "Active", "Closed"]),
            assignee=random.choice(["Andrew", "James", "Max", "Windows", "Windows", "Linux", "Linux", "", "", "", ""]),
            createAlert=createAlert
        )
    logger.info(f"Successfully added {num} test incidents to the database.")

def add_test_data_incidents_custom(num=5,createAlert=True):
    for i in range(1, num + 1):
        incident_data = {
            "timestamp": time.time() - ((num - i) * 100),
            "agent_id":f"custom",
            "oldStatus": random.choice([False,True]),
            "newStatus": random.choice([False,True]),
            "message": random.choice([
                "IR - Investigate suspicious sign-in activity on {hostname} / {ipaddress}.",
                "IR - Write report on Doubletap scheduled task.",
                "Inject - Implement HTTPS for {check} scorecheck on {hostname} / {ipaddress} by {time}.",
                "Uptime - Fix failed {check} scorecheck on {hostname} / {ipaddress}.",
                "Server - Save Exported by User {user}",
                "Server - User Added With Username {username} and Role {role} by User {current_user.id}"
            ]),
            "sla": random.choice([0,get_random_time_offset_epoch(90)])
        }
        create_incident(
            incident_data,
            tag=random.choice(["New", "Active", "Closed"]),
            assignee=random.choice(["Andrew", "James", "Max", "Windows", "Windows", "Linux", "Linux", "", "", "", ""]),
            createAlert=createAlert
        )
    logger.info(f"Successfully added {num} test custom incidents to the database.")

def add_test_data_auth_records(num=10):
    try:
        # Fetch existing agents and messages to use as foreign keys
        all_agents = Agent.query.all()
        all_messages = Message.query.all()

        if not all_agents or not all_messages:
            logger.error("Cannot add AuthRecords: Agents or Messages tables are empty.")
            return

        for i in range(1, num + 1):
            # Pick a random parent message and its associated agent
            parent_message = random.choice(all_messages)
            parent_agent_id = parent_message.agent_id
            
            # Setup realistic data variations
            user = random.choice(["root", "admin", "nobody", "www-data", "db_user", "malicious_actor", "service_acct"])
            login_type = random.choice(["ssh-password", "ssh-key", "tty", "sudo-attempt"])
            srcip = random.choice([
                "192.168.1.50", "10.0.0.15", "172.16.5.22", # Local
                "45.33.22.11", "185.22.33.44",              # Remote/Malicious
                "2001:db8:3333:4444:5555:6666:7777:8888"    # IPv6
            ])
            successful = random.choice([True, False, False, False]) # Weight toward failure for 'notable' logs
            
            # Use the parent message's timestamp for consistency
            timestamp = parent_message.timestamp + random.randint(1, 10) 
            
            # Generate appropriate notes based on success
            possible_notes = [
                "User in malicious_users list.",
                "Multiple failed attempts from this IP detected.",
                "Successful login from unauthorized subnet.",
                "Source IP matches known botnet signature.",
                "Unusual login time for this user account.",
                None
            ]

            new_record = AuthRecord(
                message_id=parent_message.message_id,
                agent_id=parent_agent_id,
                user=user,
                login_type=login_type,
                srcip=srcip,
                successful=successful,
                timestamp=timestamp,
                notes=random.choice(possible_notes) if not successful else "Successful login audit."
            )
            
            db.session.add(new_record)

        db.session.commit()
        logger.info(f"Successfully added {num} test auth records to the database.")
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to add test auth record data: {e}")

def add_test_data_auth_config():
    """
    Populates the AuthConfig table with sample IPs and Usernames.
    Matches the data pool used in add_test_data_auth_records.
    """
    try:
        # Define the pool of test entities
        test_ips = [
            ("192.168.1.50", "LEGITIMATE"),
            ("10.0.0.15", "LEGITIMATE"),
            ("172.16.5.22", "LEGITIMATE"),
            ("45.33.22.11", "MALICIOUS"),
            ("185.22.33.44", "MALICIOUS"),
            ("2001:db8:3333:4444:5555:6666:7777:8888", "MALICIOUS")
        ]

        test_users = [
            ("root", "MALICIOUS"),
            ("admin", "LEGITIMATE"),
            ("nobody", "LEGITIMATE"),
            ("www-data", "LEGITIMATE"),
            ("db_user", "LEGITIMATE"),
            ("malicious_actor", "MALICIOUS"),
            ("service_acct", "LEGITIMATE")
        ]

        # Combine them into a processing list
        config_items = []
        for val, disp in test_ips:
            config_items.append({'val': val, 'type': 'IP', 'disp': disp})
        for val, disp in test_users:
            config_items.append({'val': val, 'type': 'USER', 'disp': disp})

        added_count = 0
        for item in config_items:
            # Check if entry already exists to avoid Unique Constraint errors
            exists = AuthConfig.query.filter_by(entity_value=item['val']).first()
            if not exists:
                new_entry = AuthConfig(
                    entity_value=item['val'],
                    entity_type=item['type'],
                    disposition=item['disp']
                )
                db.session.add(new_entry)
                added_count += 1

        db.session.commit()
        logger.info(f"Successfully added {added_count} entries to AuthConfig.")
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to populate AuthConfig test data: {e}")

# =================================
# ========= API ENDPOINTS =========
# =================================

# === BASIC WEBSITE FUNCTIONALITY ===

@app.route("/")
@app.route("/dashboard")
@login_required
def page_dashboard():
    logger.info(f"/dashboard - Successful connection from {current_user.id} at {request.remote_addr}")
    return render_template("dashboard.html")

@app.route("/agents")
@login_required
def page_agents():
    logger.info(f"/agents - Successful connection from {current_user.id} at {request.remote_addr}")
    return render_template("agents.html")

@app.route("/messages")
@login_required
def page_messages():
    logger.info(f"/messages - Successful connection from {current_user.id} at {request.remote_addr}")
    return render_template("messages.html")

@app.route("/configmgmt")
@login_required
def page_configmgmt():
    logger.info(f"/configmgmt - Successful connection from {current_user.id} at {request.remote_addr}")
    return render_template("configmgmt.html")

@app.route("/deployment")
@login_required
@analyst_required
def page_deployment():
    logger.info(f"deployment - Successful connection from {current_user.id} at {request.remote_addr}")
    return render_template("deployment.html")

@app.route("/incidents")
@login_required
def page_incidents():
    logger.info(f"/incidents - Successful connection from {current_user.id} at {request.remote_addr}")
    return render_template("incidents.html")

@app.route("/management")
@login_required
@admin_required
def page_management():
    logger.info(f"management - Successful connection from {current_user.id} at {request.remote_addr}")
    return render_template("management.html")

@app.route("/authrecords")
@login_required
def page_authrecords():
    logger.info(f"/authrecords - Successful connection from {current_user.id} at {request.remote_addr}")
    return render_template("authrecords.html")

@app.route("/authconfig")
@login_required
@analyst_required
def page_authconfig():
    logger.info(f"/authconfig - Successful connection from {current_user.id} at {request.remote_addr}")
    return render_template("authconfig.html")

@app.route('/favicon.ico')
def favicon():
    logger.info(f"favicon.ico - Successful connection at {request.remote_addr}")
    return send_from_directory(os.path.join(app.root_path, 'static'),'favicon.ico',mimetype='image/vnd.microsoft.icon')

@app.route('/background.jpg')
def background():
    logger.info(f"/background.jpg - Successful connection at {request.remote_addr}")
    return send_from_directory(os.path.join(app.root_path, 'static'),'background.jpg',mimetype='image/vnd.microsoft.icon')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # For GET render pass the next param to template so the form includes it
    if request.method == 'GET':
        next_param = request.args.get('next', '')
        logger.info(f"/login - Successful connection at {request.remote_addr}")
        return render_template('login.html', next=next_param)

    # POST
    username = request.form.get('username')
    password = request.form.get('password')
    next_param = request.form.get('next') or request.args.get('next') or ''

    user_record = WebUser.query.filter(WebUser.username == username).first()
    if user_record and check_password_hash(user_record.password, password):
        user_obj = User(username, user_record.role)
        login_user(user_obj)
        session.permanent = True
        logger.info(f"/login - Successful authentication for {username} from {request.remote_addr}")

        # Validate next and redirect safely
        if is_safe_path(next_param):
            return redirect(unquote_plus(next_param))
        return redirect(url_for('page_dashboard'))

    flash('Invalid username or password', 'danger')
    logger.error(f"/login - Unsuccessful connection for {username} with password {password} from {request.remote_addr}")
    return render_template('login.html', next=next_param)

@app.route('/logout')
@login_required
def logout():
    logger.info(f"/logout - Logging out user {current_user.id} at {request.remote_addr}")

    logout_user()
    return redirect(url_for('login'))

@app.route('/whoami')
@login_required
def whoami():
    logger.info(f"/whoami - Successful connection for {current_user.id} at {request.remote_addr}")
    return jsonify({"username": current_user.id, "role": current_user.role})

# === BEACONS ===

@app.route("/ping", methods=["POST"])
def ping():
    # Provides an endpoint for the client to check that they can reach the server fine. Does not check auth.
    logger.info(f"/ping - Successful connection from {request.remote_addr}")
    return "ok", 200

@app.route("/beacon", methods=["POST"])
def handle_beacon():
    data = request.json

    agent_name = data.get("name","")
    agent_type = data.get("agent_type","")
    hostname = data.get("hostname","")
    ip = data.get("ip","")
    os_name = data.get("os","")
    executionUser = data.get("executionUser","")
    executionAdmin = data.get("executionAdmin","")
    auth = data.get("auth","")
    oldStatus = data.get("oldStatus","")
    newStatus = data.get("newStatus","")
    message = data.get("message","")
    #owlet only
    timestamp = data.get("timestamp","")
    user = data.get("user","")
    srcip = data.get("srcip","")
    login_type = data.get("login_type","")
    successful = data.get("successful",False)
    
    #if not all([agent_name, hostname, ip, os_name, executionUser, executionAdmin, auth, beacon_type, oldStatus, newStatus, message]):
    # intentionally no check for owlet perms
    if not all([agent_name, agent_type, hostname, ip, os_name, auth, message]): # required data only
        logger.warning(f"/beacon - Failed connection from {request.remote_addr} - missing data. Full details: {[agent_name, hostname, ip, os_name, executionUser, executionAdmin, auth, oldStatus, newStatus, message]}")
        return "Missing data", 400
    
    # Auth check
    auth_token_record = AuthToken.query.filter_by(token=auth).first()
    if not auth_token_record:
        logger.warning(f"/beacon - Failed connection from {request.remote_addr} - invalid auth token. Full details: {[agent_name, hostname, ip, os_name, executionUser, executionAdmin, auth, oldStatus, newStatus, message]}")
        return "Unauthorized", 403

    # Register client if new, or update agent fields if not
    agent_id = hash_id(agent_name, hostname, ip, os_name)

    try:
        agent = db.session.get(Agent,agent_id)
        is_reregister_request = message.split(" ")[0].lower() == "reregister"
    except Exception:
        # Avoid crashing if message format is unexpected
        is_reregister_request = False

    try:
        # Reregistration logic
        if is_reregister_request and agent:
            # Delete existing agent record
            db.session.delete(agent)
            agent = None # Set to None so it gets re-created in the next block
            logger.info(f"/beacon - Reregistering and deleting old agent record for agent {agent_id} with details: {[agent_name, hostname, ip, os_name, executionUser, executionAdmin, auth, oldStatus, newStatus, message]}")
            
        # Register or update client
        if not agent:
            # CREATE NEW AGENT
            new_agent = Agent(
                agent_id=agent_id,
                agent_name=agent_name,
                hostname=hostname,
                ip=ip,
                os=os_name,
                executionUser=executionUser,
                executionAdmin=executionAdmin,
                lastSeenTime=time.time(),
                lastStatus=newStatus,
                # stale field is typically derived, but if stored: stale=False,
                pausedUntil=str(0)
            )
            db.session.add(new_agent)
            if not os.path.exists(os.path.join(GIT_PROJECT_ROOT,f"{agent_id}.git")):
                try:
                    run_git(["init", "--bare", f"{agent_id}.git"],GIT_PROJECT_ROOT)
                    logger.info(f"/beacon: created repo {os.path.join(GIT_PROJECT_ROOT,f"{agent_id}.git")}")
                except subprocess.CalledProcessError as e:
                    logger.error(f"/beacon: Error occurred when creating {os.path.join(GIT_PROJECT_ROOT,f"{agent_id}.git")} - {e.stderr}")
            
        else:
            # UPDATE EXISTING AGENT
            agent.lastSeenTime = time.time()
            agent.lastStatus = newStatus
            
        db.session.commit()
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"/beacon - Failed to register or update agent {agent_id}: {e}")
        return "Database error during agent update", 500
    
    # 4. Update Messages (DB Write)
    message_id = hash_id(time.time(), agent_id)
    message_data = {
        "timestamp": time.time(),
        "agent_id": agent_id,
        "oldStatus": oldStatus,
        "newStatus": newStatus,
        "message": message
    }
    
    try:
        new_message = Message(
            message_id = message_id,
            timestamp=message_data["timestamp"],
            agent_id=message_data["agent_id"],
            oldStatus=message_data["oldStatus"],
            newStatus=message_data["newStatus"],
            message=message_data["message"]
        )
        db.session.add(new_message)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"/beacon - Failed to create message for agent {agent_id}: {e}")
        # Not returning an error, as this is secondary to agent update/auth
        pass

    """
    # 5. Handle RESUME Logic (DB Read/Write)
    try:
        # Check for RESUME message pattern
        if message.lower().split(" - ")[1].split(" ")[0] == "resumed":
            # 5a. Update Agent Status
            # We already have the agent record (or the new one was created)
            current_agent = db.session.get(Agent,agent_id)
            if current_agent:
                current_agent.pausedUntil = 0
                db.session.commit()

            # 5b. Find and Close Incident
            pattern = r'(\\d+)\\s*seconds\\b' # remove extra slashes if this is uncommented
            match = re.search(pattern, message)
            
            if match:
                seconds = int(match.group(1))
                
                # Search for the corresponding PAUSE incident that is still open
                incident_to_close = Incident.query.filter(
                    Incident.agent_id == agent_id,
                    Incident.tag.in_(["New", "Active"]),
                    # Match either the full message or the 'EARLY EXIT' message
                    or_(
                        Incident.message.like(f"%Resumed after sleeping for {seconds} seconds%"),
                        Incident.message.like(f"%Resumed after sleeping for {seconds} seconds, EARLY EXIT%")
                    )
                ).first()
                
                if incident_to_close:
                    incident_to_close.tag = "Closed"
                    db.session.commit()
                else:
                    logger.warning(f"/beacon - RESUME message received but no open incident found to close for agent {agent_id}.")
            else:
                logger.error(f"/beacon - cannot parse seconds attribute in resume incident. Full message: {message}.")
                
    except Exception as e:
        # Catches exceptions from message parsing or DB operations within the RESUME block
        db.session.rollback() 
        logger.error(f"/beacon - Error processing RESUME logic for agent {agent_id}: {e}")
    """
    doIncident = True

    if agent_type.lower() == "owlet":
        try:
            new_authrecord = AuthRecord(
                agent_id = agent_id,
                message_id = message_id,
                timestamp=timestamp,
                user=user,
                srcip=srcip,
                login_type=login_type,
                successful=successful,
                notes=message
            )
            db.session.add(new_authrecord)
            db.session.commit()
            message = str(new_authrecord)
        except Exception as e:
            db.session.rollback()
            logger.error(f"/beacon - Failed to create authrecord for agent {agent_id}: {e}")
            # Not returning an error, as this is secondary to agent update/auth
            if message:
                message = f"owlet fallback msg: {login_type} login attempt from user {user} from {srcip} attempted login with status {successful}, notes: {message}"
            else:
                message = f"owlet fallback msg: {login_type} login attempt from user {user} from {srcip} attempted login with status {successful}."
            pass
        doIncidentDb = db.session.get(AuthConfigGlobal,"create_incident")
        if doIncidentDb != None:
            doIncident = doIncidentDb

    # 6. Trigger Incident if Status Change is Critical
    if oldStatus == False:
        # The original code just passed the messageDict, which is okay since it contains all necessary info.
        if doIncident:
            incident_data = {
                "timestamp": time.time(),
                "agent_id": agent_id,
                "oldStatus": oldStatus,
                "newStatus": newStatus,
                "message": message,
                "sla": 0
            }
            create_incident(incident_data)

    return "ok", 200

@app.route("/get_pause", methods=["POST"])
def get_pause():
    data = request.json

    agent_name = data.get("name","")
    agent_type = data.get("agent_type","")
    hostname = data.get("hostname","")
    ip = data.get("ip","")
    os_name = data.get("os","")
    executionUser = data.get("executionUser","")
    executionAdmin = data.get("executionAdmin","")
    auth = data.get("auth","")
    
    #if not all([agent_name, hostname, ip, os_name, executionUser, executionAdmin, auth, beacon_type, oldStatus, newStatus, message]):
    if not all([agent_name, agent_type, hostname, ip, os_name, auth]): # required data only
        logger.warning(f"/beacon - Failed connection from {request.remote_addr} - missing data. Full details: {[agent_name, agent_type, hostname, ip, os_name, executionUser, executionAdmin, auth]}")
        return "Missing data", 400
    
    # Auth check
    auth_token_record = AuthToken.query.filter_by(token=auth).first()
    if not auth_token_record:
        logger.warning(f"/beacon - Failed connection from {request.remote_addr} - invalid auth token. Full details: {[agent_name, agent_type, hostname, ip, os_name, executionUser, executionAdmin, auth]}")
        return "Unauthorized", 403

    # Get agent identity
    agent_id = hash_id(agent_name, hostname, ip, os_name)

    agent = db.session.get(Agent,agent_id)

    if not agent:
        return "Unauthorized", 403
    
    return str(float(agent.pausedUntil)), 200

@app.route('/git/<repo_name>.git/<path:git_path>', methods=['GET', 'POST', 'PROPFIND'])
@app.route('/git/<repo_name>.git/', defaults={'git_path': ''}, methods=['GET', 'POST', 'PROPFIND'])
def git_backend(repo_name, git_path):
    # Log IMMEDIATELY with all inputs
    logger.info(f"/git: START git_backend: repo={repo_name}, path={git_path}, method={request.method}")

    try:
        # Check if the cleaning function is the culprit
        try:
            # If this function crashes, it usually happens here
            git_path = clean_and_join_path(git_path)
        except Exception as e:
            logger.info(f"/git: CRASH in clean_and_join_path: {str(e)}")
            return f"Path cleaning failed: {str(e)}", 500

        # Construct path info safely
        path_info = f"{repo_name}.git/{git_path}"
        
        # Build Environment
        env = {
            'REQUEST_METHOD': request.method,
            'GIT_PROJECT_ROOT': GIT_PROJECT_ROOT,
            'GIT_HTTP_EXPORT_ALL': '1',
            'PATH_INFO': path_info,
            'QUERY_STRING': request.query_string.decode('utf-8') if request.query_string else '',
            'CONTENT_TYPE': request.headers.get('Content-Type', ''),
            'CONTENT_LENGTH': request.headers.get('Content-Length', ''),
            'REMOTE_ADDR': request.remote_addr,
        }

        # Validate GIT_BACKEND exists before trying to run it
        if not os.path.exists(GIT_BACKEND):
            logger.info(f"/git: CRITICAL: GIT_BACKEND binary not found at {GIT_BACKEND}")
            return "Backend binary missing", 500

        # Subprocess execution
        process = subprocess.Popen(
            [GIT_BACKEND],
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        stdout, stderr = process.communicate(input=request.data)

        if process.returncode != 0:
            logger.info(f"/git: Git binary returned {process.returncode}. Stderr: {stderr.decode('utf-8')}")

        # Header parsing
        header_end = stdout.find(b'\r\n\r\n')
        if header_end == -1:
            header_end = stdout.find(b'\n\n')
            sep_len = 2
        else:
            sep_len = 4

        if header_end == -1:
            # If no headers found, the binary likely produced an error on stdout
            logger.info(f"/git: CGI ERROR: No header separator. Raw Output: {stdout[:200]}")
            return "Invalid response from Git backend", 500

        header_section = stdout[:header_end].decode('utf-8')
        response_body = stdout[header_end + sep_len:]

        # 3. Attempt to parse headers
        header_end = stdout.find(b'\r\n\r\n')
        sep_len = 4
        if header_end == -1:
            header_end = stdout.find(b'\n\n')
            sep_len = 2

        if header_end == -1:
            logger.info(f"/git: CGI Header Parse Error: No header separator found in binary output. Raw output start: {stdout[:50]}")
            return "Internal Server Error: Invalid CGI Response", 500

        header_section = stdout[:header_end].decode('utf-8')
        response_body = stdout[header_end + sep_len:]

        headers_dict = {}
        status_code = 200
        for line in header_section.splitlines():
            if ':' in line:
                key, value = line.split(':', 1)
                k = key.strip().lower()
                v = value.strip()
                if k == 'status':
                    try:
                        status_code = int(v.split(' ')[0])
                    except ValueError:
                        logger.info(f"/git: Malformed Status header: {v}")
                else:
                    headers_dict[key.strip()] = v

        return response_body, status_code, headers_dict

    except FileNotFoundError:
        logger.info(f"/git: GIT_BACKEND binary not found at: {GIT_BACKEND}")
        return "Internal Server Error: Backend Binary Missing", 500
    except PermissionError:
        logger.info(f"/git: Permission denied when executing GIT_BACKEND: {GIT_BACKEND}")
        return "Internal Server Error: Backend Permission Denied", 500
    except Exception as e:
        logger.info(f"/git: Unexpected error in git_backend: {str(e)}")
        return "Internal Server Error", 500

@app.route('/list_authconfig_agent', methods=['GET'])
def get_config():
    entries = AuthConfig.query.all()
    
    # Structure the data so the agent can easily parse it
    config = {
        "users": {"legitimate": [], "malicious": []},
        "ips": {"legitimate": [], "malicious": []}
    }
    
    for entry in entries:
        category = "users" if entry.entity_type == 'USER' else "ips"
        status = entry.disposition.lower()
        config[category][status].append(entry.entity_value)
        
    return jsonify(config)

# === FRONTEND DISPLAY ===

@login_required
@app.route('/list_authconfigglobal', methods=['POST'])
def get_global_config():
    configs = AuthConfigGlobal.query.all()
    return jsonify({c.key: c.value for c in configs})

@login_required
@analyst_required
@app.route('/list_authconfig', methods=['POST'])
def list_authconfig():
    entries = AuthConfig.query.all()
    # Return as a list of dictionaries for the frontend to map
    return jsonify([entry.to_dict() for entry in entries])

@login_required
@app.route('/list_auth_records', methods=['POST'])
def list_auth_records():
    results = db.session.query(AuthRecord, Agent).\
        join(Agent, AuthRecord.agent_id == Agent.agent_id).\
        order_by(AuthRecord.timestamp.desc()).all()
    
    data = {}
    for record, agent in results:
        # Get the base dictionary from the record
        entry = record.to_dict()
        
        # 1. Detach/Remove the agent_id field
        entry.pop('agent_id', None)
        
        # 2. Attach the foreign keyed agent details
        entry['hostname'] = agent.hostname
        entry['agent_ip'] = agent.ip  # Renamed to agent_ip to avoid confusion with srcip
        entry['os'] = agent.os
        
        # Store in the ID-keyed dictionary format required by your frontend
        data[str(record.id)] = entry
    
    return jsonify(data)

@login_required
@app.route("/list_git_overall", methods=["POST"])
def list_git_overall():
    try:
        returned_info = get_git_stats(db)
        logger.info(f"/list_git_overall - Successful connection from {current_user.id} at {request.remote_addr}. returning info {returned_info}")
        return jsonify(returned_info), 200
    except Exception as E:
        logger.warning(f"/list_git_overall - Failed connection from {current_user.id} at {request.remote_addr}. Exception: {E}")
        return "",500

@login_required
@app.route("/ping_login", methods=["POST"])
def ping_login():
    # Provides an endpoint for the client to check that they can reach the server fine. Does not check auth.
    logger.info(f"/ping_login - Successful connection from {current_user.id} at {request.remote_addr}")
    return "ok", 200

@app.route("/list_users", methods=["POST"])
@login_required
@admin_required
def list_users():
    try:
        logger.info(f"/list_users - Successful connection from {current_user.id} at {request.remote_addr}")
        users = WebUser.query.all()
        user_dict = {user.username: serialize_model(user) for user in users}
        return jsonify(user_dict)
    except Exception as e:
        logger.error(f"/list_users - Database or serialization error: {e}")
        return jsonify({"error": "Failed to retrieve user list"}), 500

@app.route("/list_users_simple", methods=["POST"])
@login_required
def list_users_simple():
    """
    Retrieves a simple dictionary of all users and their roles from the database.
    """
    try:
        logger.info(f"/list_users_simple - Successful connection from {current_user.id} at {request.remote_addr}")
        
        users = WebUser.query.all()
        user_roles = {user.username: user.role for user in users}

        return jsonify(user_roles)

    except Exception as e:
        logger.error(f"/list_users_simple - Database error: {e}")
        return jsonify({"error": "Failed to retrieve simple user list"}), 500

@app.route("/list_tokens", methods=["POST"])
@login_required
@admin_required
def list_tokens():
    try:
        logger.info(f"/list_tokens - Successful connection from {current_user.id} at {request.remote_addr}")
        tokens = AuthToken.query.all()
        token_dict = {token.token: serialize_model(token) for token in tokens}
        return jsonify(token_dict)
    except Exception as e:
        logger.error(f"/list_tokens - Database or serialization error: {e}")
        return jsonify({"error": "Failed to retrieve token list"}), 500

@app.route("/list_tokens_number", methods=["POST"])
@login_required
def list_tokens_number():
    """
    Returns the count of authentication tokens in the database.
    """
    try:
        logger.info(f"/list_tokens_number - Successful connection from {current_user.id} at {request.remote_addr}")
        
        token_count = AuthToken.query.count()
        
        return jsonify({"number": token_count})
    
    except Exception as e:
        logger.error(f"/list_tokens_number - Database error: {e}")
        return jsonify({"error": "Failed to retrieve token count"}), 500

@app.route("/list_agents", methods=["POST"])
@login_required
def list_agents():
    try:
        logger.info(f"/list_agents - Successful connection from {current_user.id} at {request.remote_addr}")
        
        agents = Agent.query.all()
        
        agent_dict = {
            agent.agent_id: serialize_model(agent)
            for agent in agents
        }
        
        return jsonify(agent_dict)
        
    except Exception as e:
        logger.error(f"/list_agents - Database or serialization error: {e}")
        return jsonify({"error": "Failed to retrieve agent list"}), 500

@app.route("/list_messages", methods=["POST"])
@login_required
def list_messages():
    try:
        logger.info(f"/list_messages - Successful connection from {current_user.id} at {request.remote_addr}")
        
        messages = Message.query.all()
        
        message_dict = {
            message.message_id: serialize_model(message)
            for message in messages
        }
        
        return jsonify(message_dict)

    except Exception as e:
        logger.error(f"/list_messages - Database or serialization error: {e}")
        return jsonify({"error": "Failed to retrieve message list"}), 500

@app.route("/list_incidents", methods=["POST"])
@login_required
def list_incidents():
    try:
        logger.info(f"/list_incidents - Successful connection from {current_user.id} at {request.remote_addr}")
        
        incidents = Incident.query.all()
        
        incident_dict = {
            incident.incident_id: serialize_model(incident)
            for incident in incidents
        }
        
        return jsonify(incident_dict)
        
    except Exception as e:
        logger.error(f"/list_incidents - Database or serialization error: {e}")
        return jsonify({"error": "Failed to retrieve incident list"}), 500

@app.route("/list_ansiblevars", methods=["GET"]) # TODO standardize on POST
@login_required
def list_ansiblevars():
    try:
        logger.info(f"/list_ansiblevars - Successful connection from {current_user.id} at {request.remote_addr}")
        
        vars = AnsibleVars.query.filter_by(id="main").first() 

        if not vars:
            return jsonify({"status":"no ansiblevars database instance available"}), 200
                
        return jsonify(vars.to_dict()), 200
        
    except Exception as e:
        logger.error(f"/list_ansiblevars - Database or serialization error: {e}")
        return jsonify({"error": "Failed to retrieve ansiblevars list"}), 500

@app.route("/set_ansiblevars", methods=["POST"])
@login_required
@analyst_required
def set_ansiblevars():
    try:
        logger.info(f"/set_ansiblevars - Successful connection from {current_user.id} at {request.remote_addr}")
        
        vars = AnsibleVars.query.filter_by(id="main").first() 

        if not vars:
            return jsonify({"status":"no ansiblevars database instance available"}), 200
                
        return jsonify(vars.to_dict()), 200
        
    except Exception as e:
        logger.error(f"/set_ansiblevars - Database or serialization error: {e}")
        return jsonify({"error": "Failed to retrieve ansiblevars list"}), 500
    
@app.route("/list_logfile", methods=["POST"])
@login_required
@admin_required
def list_logfile(filepath=LOGFILE,lines=50):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            # Use deque to keep only the last 50 lines in memory
            last_lines = deque(f, maxlen=lines)
        logger.info(f"/list_logfile - Successful connection from {current_user.id} at {request.remote_addr}")
        return list(last_lines)

    except FileNotFoundError:
        logger.error(f"/list_logfile - Successful connection from {current_user.id} at {request.remote_addr}")
        return f"FileNotFound {filepath}", 400

@app.route("/list_ansibleresult", methods=["POST"])
@login_required
@analyst_required
def list_ansibleresult():
    try:
        data = request.json
        taskID = data.get("taskID")
        if not all([taskID]): # just the required string
            logger.warning(f"/list_ansibleresult - Failed connection from {current_user.id} at {request.remote_addr} - missing data. Full details: {[taskID]}")
            return "Missing data", 400
        
        taskResult_obj = AnsibleResult.query.filter_by(task=taskID).one_or_none() 
        
        if taskResult_obj is None:
            # Task not found in the database. 
            # This is the expected behavior if the task is running or the ID is invalid.
            logger.info(f"/list_ansibleresult - Failed connection from {current_user.id} at {request.remote_addr} - taskID is not available (not found/is pending). Full details: {[taskID]}")
            
            # Return a non-OK status code (e.g., 404 or 202) to signal "not ready/not found"
            return jsonify({"status": "pending", "message": "Task not complete or ID invalid"}), 404
        
        # Task was found and result object exists
        # NOTE: You will need a .to_dict() or Marshmallow serializer to correctly
        # convert the ORM object (taskResult_obj) to a dictionary for jsonify.
        
        # Assuming you have a .to_dict() method on your AnsibleResult model:
        task_data = taskResult_obj.to_dict() 
        
        logger.info(f"/list_ansibleresult - Successful connection from {current_user.id} at {request.remote_addr} for taskID {taskID}")
        return jsonify(task_data), 200
        
    except Exception as e:
        logger.error(f"/list_ansibleresult - Database or serialization error: {e}")
        return jsonify({"error": "Failed to retrieve result details"}), 500

@app.route("/save_export", methods=["POST"])
@login_required
@admin_required
def save_export(filepath=SAVEFILE):
    return jsonify({"error": "Deprecated"}), 500

    logger.info(f"/save_export - Successful connection from {current_user.id} at {request.remote_addr}")
    
    try:
        with open(filepath, "r") as f:
            state = json.load(f)

        incident = {
            "timestamp": time.time(),
            "agent_id":f"custom",
            "oldStatus": False,
            "newStatus": False,
            "message": f"Server - Save Exported by User {current_user.id}",
            "sla": 0
        }
        create_incident(incident)

        return state
    except FileNotFoundError:
        logger.error(f"/save_export - Successful connection from {current_user.id} at {request.remote_addr}")
        return f"FileNotFound {filepath}", 400

# === FRONTEND INTERACTION ===

@app.route('/update_authconfigglobal', methods=['POST'])
@login_required
@analyst_required
def update_global_config():
    data = request.get_json()
    key = data.get('key')
    
    config = AuthConfigGlobal.query.filter_by(key=key).first()
    if not config:
        config = AuthConfigGlobal(key=key, value=data.get('value'))
        db.session.add(config)
    else:
        config.value = data.get('value')
    
    db.session.commit()
    return jsonify({"status": "success", "key": key, "new_value": config.value})

@app.route('/add_authconfig', methods=['POST'])
@login_required
@analyst_required
def add_authconfig():
    data = request.get_json()
    val = data.get('entity_value', '').strip()
    e_type = data.get('entity_type') # 'IP' or 'USER'
    disp = data.get('disposition')   # 'LEGITIMATE' or 'MALICIOUS'

    if not val or not e_type or not disp:
        return jsonify({"status": "error", "message": "Missing fields"}), 400

    # Prevent duplicates
    if AuthConfig.query.filter_by(entity_value=val).first():
        return jsonify({"status": "error", "message": "Entry already exists"}), 409

    new_entry = AuthConfig(entity_value=val, entity_type=e_type, disposition=disp)
    db.session.add(new_entry)
    db.session.commit()
    return jsonify({"status": "success", "id": new_entry.id})

@app.route('/update_authconfig_status', methods=['POST'])
@login_required
@analyst_required
def update_authconfig_status():
    data = request.get_json()
    entry = AuthConfig.query.get(data.get('id'))
    if not entry:
        return jsonify({"status": "error", "message": "Not found"}), 404
    
    # Toggle logic
    entry.disposition = "MALICIOUS" if entry.disposition == "LEGITIMATE" else "LEGITIMATE"
    db.session.commit()
    return jsonify({"status": "success", "new_disposition": entry.disposition})

@app.route('/delete_authconfig', methods=['POST'])
@login_required
@analyst_required
def delete_authconfig():
    data = request.get_json()
    entry_id = data.get('id')
    entry = AuthConfig.query.get(entry_id)
    
    if entry:
        db.session.delete(entry)
        db.session.commit()
        return jsonify({"status": "success"})
    return jsonify({"status": "error", "message": "Entry not found"}), 404

@app.route('/authrecord_update_notes', methods=['POST'])
@login_required
@analyst_required
def authrecord_update_notes():
    data = request.get_json()
    record_id = data.get('id')
    new_notes = data.get('notes')

    try:
        record = AuthRecord.query.get(record_id)
        if not record:
            logger.warning(f"/authrecord_update_notes - failed request from {current_user.id} at {request.remote_addr} - record not found for id {record_id} and new_notes {new_notes}.")
            return jsonify({"status": "error", "message": "Record not found"}), 404
        
        record.notes = new_notes
        db.session.commit()
        logger.info(f"/authrecord_update_notes - successful request from {current_user.id} at {request.remote_addr} - updating notes for incident {record_id} to {new_notes}.")
        return jsonify({"status": "success", "message": "Notes updated"})
    except Exception as E:
        db.session.rollback()
        logger.error(f"/authrecord_update_notes - failed request from {current_user.id} at {request.remote_addr} - Database error: {E}")
        return jsonify({"error": "Database error"}), 500

@app.route('/bulk_authconfig', methods=['POST'])
@login_required
@analyst_required
def bulk_authconfig():
    data = request.get_json()
    action = data.get('action') # 'import' or 'export'
    
    if action == 'export':
        entries = AuthConfig.query.all()
        return jsonify([entry.to_dict() for entry in entries])
    
    if action == 'import':
        raw_list = data.get('data', [])
        added_count = 0
        for item in raw_list:
            # Check for existing to prevent unique constraint errors
            if not AuthConfig.query.filter_by(entity_value=item['entity_value']).first():
                new_entry = AuthConfig(
                    entity_value=item['entity_value'],
                    entity_type=item['entity_type'],
                    disposition=item['disposition']
                )
                db.session.add(new_entry)
                added_count += 1
        db.session.commit()
        return jsonify({"status": "success", "added": added_count})

@app.route('/bulk_auth_records', methods=['POST'])
@login_required
@analyst_required
def bulk_auth_records():
    data = request.get_json()
    action = data.get('action') # 'import' or 'export'
    
    if action == 'export':
        records = AuthRecord.query.all()
        return jsonify([r.to_dict() for r in records])
    
    if action == 'import':
        raw_list = data.get('data', [])
        added_count = 0
        for item in raw_list:
            # Basic deduplication check: check if record with same timestamp/user/ip exists
            exists = AuthRecord.query.filter_by(
                timestamp=item.get('timestamp'),
                user=item.get('user'),
                srcip=item.get('srcip')
            ).first()
            
            if not exists:
                new_rec = AuthRecord(
                    timestamp=item.get('timestamp'),
                    agent_id=item.get('agent_id'),
                    user=item.get('user'),
                    srcip=item.get('srcip'),
                    successful=item.get('successful'),
                    notes=item.get('notes', '')
                )
                db.session.add(new_rec)
                added_count += 1
        db.session.commit()
        return jsonify({"status": "success", "added": added_count})
    
@app.route("/agent_pause", methods=["POST"])
@login_required
@analyst_required
def agent_pause():
    data = request.json
    agent_id = data.get("agent_id")
    seconds = data.get("seconds")
    if not all([agent_id,seconds]):
        logger.warning(f"/agent_pause - Failed connection from {current_user.id} at {request.remote_addr} - missing data. Full details: {[agent_id,seconds]}")
        return "Missing data", 400
    agent = Agent.query.filter_by(agent_id=agent_id).first()
    if not agent:
        logger.warning(f"/agent_pause - Failed connection from {current_user.id} at {request.remote_addr} - bad agent_id value, agent_id does not exist. Full details: {[agent_id,seconds]}")
        return "Agent with specified ID does not exist", 400
    try:
        # Allow pausing for longer so don't error check that
        agent.pausedUntil = str(time.time() + seconds)
        db.session.commit()
        logger.info(f"/agent_pause - Successful connection from {current_user.id} at {request.remote_addr}. Pausing agent {agent_id} for {seconds} seconds.")
        return jsonify({"status": "ok"})
    except Exception as e:
        db.session.rollback()
        logger.error(f"/agent_pause - Database error: {e}")
        return jsonify({"error": f"Database error: {e}"}), 500

@app.route("/agent_resume", methods=["POST"])
@login_required
@analyst_required
def agent_resume():
    data = request.json
    agent_id = data.get("agent_id")
    if not all([agent_id]):
        logger.warning(f"/agent_resume - Failed connection from {current_user.id} at {request.remote_addr} - missing data. Full details: {[agent_id]}")
        return "Missing data", 400
    agent = Agent.query.filter_by(agent_id=agent_id).first()
    if not agent:
        logger.warning(f"/agent_resume - Failed connection from {current_user.id} at {request.remote_addr} - bad agent_id value, agent_id does not exist. Full details: {[agent_id]}")
        return "Agent with specified ID ", 400
    try:
        if (int(agent.pausedUntil) == 0) or (int(agent.pausedUntil) == 1):
            return "Agent is already in ACTIVE state", 400
        agent.pausedUntil = str(1)
        db.session.commit()
        logger.info(f"/agent_resume - Successful connection from {current_user.id} at {request.remote_addr}. Resuming agent {agent_id}.")
        return jsonify({"status": "ok"})
    except Exception as e:
        db.session.rollback()
        logger.error(f"/agent_resume - Database error: {e}")
        return jsonify({"error": f"Database error: {e}"}), 500
    
@app.route("/add_incident", methods=["POST"])
@login_required
@analyst_required
def add_incident():
    data = request.json
    newStatus = data.get("newStatus")
    message = data.get("message")
    assignee = data.get("assignee","")
    createAlert = data.get("createAlert")
    sla = data.get("sla",0)
    if not sla:
        sla = 0

    if not all([message]): # just the required string
        logger.warning(f"/add_incident - Failed connection from {current_user.id} at {request.remote_addr} - missing data. Full details: {[newStatus,message,assignee,createAlert,sla]}")
        return "Missing data", 400
    
    try:
        # epoch
        sla = float(sla)
    except:
        logger.warning(f"/add_incident - Failed connection from {current_user.id} at {request.remote_addr} - bad sla value. Full details: {[newStatus,message,assignee,createAlert,sla]}")
        return "Bad SLA value", 400
    
    # not verifying data as I don't want to. TODO
    
    messageDict = {
        "timestamp": time.time(),
        "agent_id": "custom",
        "oldStatus": True,
        "newStatus": newStatus,
        "message": message,
        "sla": sla
    }

    create_incident(messageDict,tag="New",assignee=assignee,createAlert=createAlert)

    logger.info(f"/add_incident - Successful connection from {current_user.id} at {request.remote_addr}. Creating incident with details {[newStatus,message,assignee,createAlert,sla]}.")
    return jsonify({"status": "ok"})

@app.route("/add_user", methods=["POST"])
@login_required
@admin_required
def add_user():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    role = data.get("role")

    if not all([username, password, role]):
        logger.warning(f"/add_user - Failed connection from {current_user.id} at {request.remote_addr} - missing data. Full details: {[username, password, role]}")
        return "Missing data", 400
    
    if role not in ["guest","analyst","admin"]:
        logger.warning(f"/add_user - Failed connection from {current_user.id} at {request.remote_addr} - bad role value. Full details: {[username, password, role]}")
        return "Bad role value", 400

    existing_user = WebUser.query.filter_by(username=username).first()
    if existing_user:
        logger.warning(f"/add_user - Failed connection from {current_user.id} at {request.remote_addr} - bad username value, conflicts with existing user. Full details: {[username, password, role]}")
        return "New user overlaps with existing user", 400

    try:
       
        hashed_password = generate_password_hash(password)

        new_user = WebUser(
            username=username,
            password=hashed_password,
            role=role
        )

        db.session.add(new_user)
        db.session.commit()

        incident_data = {
            "timestamp": time.time(),
            "agent_id": "custom",
            "oldStatus": False,
            "newStatus": False,
            "message": f"Server - User Added With Username {username} and Role {role} by User {current_user.id}",
            "sla": 0
        }
        create_incident(incident_data)

        logger.info(f"/add_user - Successful connection from {current_user.id} at {request.remote_addr}. Adding user {username} with role {role}")
        return jsonify({"status": "ok"})
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"/add_user - Database error: {e}")
        return jsonify({"error": "Database error while adding user"}), 500
    
@app.route("/delete_user", methods=["POST"])
@login_required
@admin_required
def delete_user():
    data = request.json
    username = data.get("username")

    if not all([username]):
        logger.warning(f"/delete_user - Failed connection from {current_user.id} at {request.remote_addr} - missing data. Full details: {[username]}")
        return "Missing data", 400
    
    if username == current_user.id:
        logger.warning(f"/delete_user - Failed connection from {current_user.id} at {request.remote_addr} - cannot delete own user. Full details: {[username]}")
        return "Target username cannot be the same as current username", 400
    
    user_to_delete = WebUser.query.filter_by(username=username).first()
    
    if not user_to_delete:
        logger.warning(f"/delete_user - Failed connection from {current_user.id} at {request.remote_addr} - username not found. Full details: {[username]}")
        return "Bad role value", 400

    try:
        user_role = user_to_delete.role
        
        incident_data = {
            "timestamp": time.time(),
            "agent_id": "custom",
            "oldStatus": False,
            "newStatus": False,
            "message": f"Server - User Deleted With Username {username} and Role {user_role} by User {current_user.id}",
            "sla": 0
        }
        create_incident(incident_data)

        db.session.delete(user_to_delete)
        db.session.commit()
        
        logger.info(f"/delete_user - Successful connection from {current_user.id} at {request.remote_addr}. Deleting user {username} with role {user_role}")
        return jsonify({"status": "ok"})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"/delete_user - Database error: {e}")
        return jsonify({"error": "Database error while deleting user"}), 500

@app.route("/add_token", methods=["POST"])
@login_required
@admin_required
def add_token():
    data = request.json
    token = data.get("token")

    if not all([token]):
        logger.warning(f"/add_token - Failed connection from {current_user.id} at {request.remote_addr} - missing data. Full details: {[token]}")
        return "Missing data", 400
    
    token_record = AuthToken.query.filter_by(token=token).first()
    if token_record:
        logger.warning(f"/add_token - Failed connection from {current_user.id} at {request.remote_addr} - bad token value, conflicts with existing token. Full details: {[token]}")
        return "New token overlaps with existing token", 400
    
    try:
        new_token = AuthToken(
            token=token,
            timestamp=time.time(),
            added_by=current_user.id
        )
        
        db.session.add(new_token)
        db.session.commit()
        
        incident_data = {
            "timestamp": time.time(),
            "agent_id": "custom",
            "oldStatus": False,
            "newStatus": False,
            "message": f"Server - Token Added by User {current_user.id}",
            "sla": 0
        }
        create_incident(incident_data)

        logger.info(f"/add_token - Successful connection from {current_user.id} at {request.remote_addr}. Adding token {token}")
        return jsonify({"status": "ok"})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"/add_token - Database error: {e}")
        return jsonify({"error": "Database error while adding token"}), 500

@app.route("/delete_token", methods=["POST"])
@login_required
@admin_required
def delete_token():
    data = request.json
    token = data.get("token")

    if not all([token]):
        logger.warning(f"/delete_token - Failed connection from {current_user.id} at {request.remote_addr} - missing data. Full details: {[token]}")
        return "Missing data", 400
    
    token_to_delete = AuthToken.query.filter_by(token=token).first()
    
    if not token_to_delete:
        logger.warning(f"/delete_token - Failed connection from {current_user.id} at {request.remote_addr} - username not found. Full details: {[token]}")
        return "Bad role value", 400

    try:
        added_by = token_to_delete.added_by
        timestamp = datetime.fromtimestamp(token_to_delete.timestamp)
        
        incident_data = {
            "timestamp": time.time(),
            "agent_id": "custom",
            "oldStatus": False,
            "newStatus": False,
            "message": f"Server - Token Deleted by User {current_user.id}",
            "sla": 0
        }
        create_incident(incident_data)
        
        db.session.delete(token_to_delete)
        db.session.commit()

        logger.info(f"/delete_token - Successful connection from {current_user.id} at {request.remote_addr}. Deleting token {token} that was added by {added_by} at {timestamp}")
        return jsonify({"status": "ok"})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"/delete_token - Database error: {e}")
        return jsonify({"error": "Database error while deleting token"}), 500

@app.route("/update_incident_tag", methods=["POST"])
@login_required
@analyst_required
def update_incident_tag():
    data = request.json
    incident_id = data.get("incident_id")
    tag = data.get("tag")

    if not all([incident_id, tag]):
        logger.warning(f"/update_incident_tag - Failed connection from {current_user.id} at {request.remote_addr} - missing data. Full details: {[incident_id, tag]}")
        return "Missing data", 400
    
    try:
        incident_id = int(incident_id)
    except:
        logger.warning(f"/update_incident_tag - Failed connection from {current_user.id} at {request.remote_addr} - Invalid incident ID {incident_id} (failed to parse to int). Full details: {[incident_id, tag]}")
        return "Bad incident value", 400
    
    if tag not in ["New","Active","Closed"]:
        logger.info(f"/update_incident_tag - Successful connection from {current_user.id} at {request.remote_addr}. Invalid tag {tag}")
        return "Bad tag value", 400
    
    incident = db.session.get(Incident,incident_id)
    
    if incident:
        try:
            incident.tag = tag
            db.session.commit()
            logger.info(f"update_incident_tag - Successful connection from {current_user.id} at {request.remote_addr}. Updating tag for incident {incident_id} to {tag}")
            return jsonify({"status": "ok"}), 200
        except Exception as e:
            db.session.rollback()
            logger.error(f"/update_incident_tag - Database update error: {e}")
            return jsonify({"error": "Database error during update"}), 500
    else:
        logger.warning(f"/update_incident_tag - Successful connection from {current_user.id} at {request.remote_addr}. No incident found with id {incident_id}")
        return "Invalid incident ID", 400

@app.route("/update_incident_assignee", methods=["POST"])
@login_required
@analyst_required
def update_incident_assignee():
    data = request.json
    incident_id = data.get("incident_id")
    assignee = data.get("assignee")

    if not all([incident_id, assignee]):
        logger.warning(f"/update_incident_assignee - Failed connection from {current_user.id} at {request.remote_addr} - missing data. Full details: {[incident_id, assignee]}")
        return "Missing data", 400
    
    try:
        incident_id = int(incident_id)
    except:
        logger.warning(f"/update_incident_assignee - Failed connection from {current_user.id} at {request.remote_addr} - Invalid incident ID {incident_id} (failed to parse to int). Full details: {[incident_id, assignee]}")
        return "Bad incident value", 400
    
    incident = db.session.get(Incident,incident_id)
    
    if incident:
        try:
            incident.assignee = assignee
            db.session.commit()
            logger.info(f"/update_incident_assignee - Successful connection from {current_user.id} at {request.remote_addr}. Updating assignee for incident {incident_id} to {assignee}")
            return jsonify({"status": "ok"}), 200
        except Exception as e:
            db.session.rollback()
            logger.error(f"/update_incident_assignee - Database update error: {e}")
            return jsonify({"error": "Database error during update"}), 500
    else:
        logger.warning(f"/update_incident_assignee - Successful connection from {current_user.id} at {request.remote_addr}. No incident found with id {incident_id}")
        return "Invalid incident ID", 400

@app.route("/update_incident_sla", methods=["POST"])
@login_required
@analyst_required
def update_incident_sla():
    data = request.json
    incident_id = data.get("incident_id")
    sla = data.get("sla")

    if not all([incident_id, sla]):
        logger.warning(f"/update_incident_sla - Failed connection from {current_user.id} at {request.remote_addr} - missing data. Full details: {[incident_id, sla]}")
        return "Missing data", 400
    
    try:
        incident_id = int(incident_id)
    except:
        logger.warning(f"/update_incident_sla - Failed connection from {current_user.id} at {request.remote_addr} - Invalid incident ID {incident_id} (failed to parse to int). Full details: {[incident_id, sla]}")
        return "Bad incident value", 400
    
    try:
        sla = int(sla)
    except Exception as E:
        logger.warning(f"/update_incident_sla - Successful connection from {current_user.id} at {request.remote_addr}. Cannot cast SLA of {sla} to int.")
        return "Bad sla value", 400
    
    incident = db.session.get(Incident,incident_id)

    if incident:
        try:
            incident.sla = sla
            db.session.commit()
            logger.info(f"/update_incident_sla - Successful connection from {current_user.id} at {request.remote_addr}. Updating sla for incident {incident_id} to {sla}")
            return jsonify({"status": "ok"}), 200
        except Exception as e:
            db.session.rollback()
            logger.error(f"/update_incident_sla - Database update error: {e}")
            return jsonify({"error": "Database error during update"}), 500
    else:
        logger.warning(f"/update_incident_sla - Successful connection from {current_user.id} at {request.remote_addr}. No incident found with id {incident_id}")
        return "Invalid incident ID", 400

@app.route("/add_ansible", methods=["POST"])
@login_required
@analyst_required
def add_ansible():
    data = request.json
    ansible_folder = data.get("ansible_folder")
    ansible_playbook = data.get("ansible_playbook")
    ansible_inventory = data.get("ansible_inventory")
    dest_ip = data.get("dest_ip")
    ansible_venv = data.get("ansible_venv","")
    extra_vars = data.get("extra_vars")

    if not all([ansible_folder,ansible_playbook,ansible_inventory,dest_ip,extra_vars]):
        logger.warning(f"/add_ansible - Failed connection from {current_user.id} at {request.remote_addr} - missing data. Full details: {[ansible_folder,ansible_playbook,ansible_inventory,dest_ip,extra_vars]}")
        return jsonify({"status":"Missing data"}), 400
    
    logger.warning(f"/add_ansible - Successful connection from {current_user.id} at {request.remote_addr}. Waiting for ansible_queue_cond. Full details: {[ansible_folder,ansible_playbook,ansible_inventory,dest_ip,extra_vars]}")
    
    record_count = db.session.query(AnsibleResult).count()
    taskID = record_count + 1
    
    with ansible_queue_cond: # Might lead to minor sleep but nothing major
        ansible_queue.append(
            {
                "task": taskID,
                "data": {
                    "ansible_folder": ansible_folder, "extra_vars": extra_vars,"ansible_playbook":ansible_playbook,"ansible_inventory":ansible_inventory,"dest_ip":dest_ip,"ansible_venv":ansible_venv
                }
            }
        )
        ansible_queue_cond.notify() 

    logger.info(f"/add_ansible - Successful connection from {current_user.id} at {request.remote_addr}. Full details: {[ansible_folder,ansible_playbook,ansible_inventory,dest_ip,extra_vars]}")
    
    return jsonify({"status": "ok","task": taskID}), 200

@app.route("/save_manual", methods=["POST"])
@login_required
@analyst_required
def save_manual():
    return jsonify({"error": "Deprecated"}), 500

    logger.info(f"/save_manual - Successful connection from {current_user.id} at {request.remote_addr}")
    
    try:
        save_state()
        return f"Successfully saved state to {SAVEFILE}", 200
    except Exception as e:
        return f"Failed to save state: {e}", 500

# =================================
# ============= MAIN ==============
# =================================

if __name__ == "__main__":

    logger = setup_logging()

    logger.info(f"Starting server on {HOST}:{PORT}")

    create_db_tables()

    # Load previous state if available
    #load_state()

    # Save on exit setup - see signal_handler() and save_state()
    # Registering both signal and atexit may cause saves to happen twice, but oh well. Not like it's a ton of work anyways.
    #signal.signal(signal.SIGINT, signal_handler)
    #signal.signal(signal.SIGTERM, signal_handler)
    #atexit.register(save_state)

    # Start threads before test data to avoid delays
    threading.Thread(target=periodic_autosave, daemon=True).start()
    threading.Thread(target=webhook_main, daemon=True).start()
    threading.Thread(target=periodic_stale, daemon=True).start()
    threading.Thread(target=periodic_ansible, daemon=True).start()

    # Test data
    with app.app_context():
        try:
            add_test_data_agents(5)
            add_test_data_messages(10)
            add_test_data_incidents_custom(5)
            add_test_data_incidents(10)
            #add_test_data_comp(0)
            #add_test_data_cmds()
            add_test_data_auth_records(20)
            add_test_data_auth_config()

            if not db.session.get(AuthConfigGlobal,"strict_user"):
                config = AuthConfigGlobal(key="strict_user", value=AUTHCONFIG_STRICT_USER)
                db.session.add(config)
                logger.info(f"Initialized default strict_user={AUTHCONFIG_STRICT_USER}.")
            if not db.session.get(AuthConfigGlobal,"strict_ip"):
                config = AuthConfigGlobal(key="strict_ip", value=AUTHCONFIG_STRICT_IP)
                db.session.add(config)
                logger.info(f"Initialized default strict_ip={AUTHCONFIG_STRICT_IP}.")
            if not db.session.get(AuthConfigGlobal,"create_incident"):
                config = AuthConfigGlobal(key="create_incident", value=AUTHCONFIG_CREATE_INCIDENT)
                db.session.add(config)
                logger.info(f"Initialized default create_incident={AUTHCONFIG_CREATE_INCIDENT}.")

            existing_vars = db.session.get(AnsibleVars,"main")
            if not existing_vars:
                new_ansiblevars = AnsibleVars(id="main")
                db.session.add(new_ansiblevars)
                db.session.commit()
                logger.info(f"Initialized default AnsibleVars.")
            else:
                logger.info("AnsibleVars 'main' already exists, skipping initialization.")
        except Exception as E:
            db.session.rollback()
            logger.error(f"FATAL: Failed to insert initial data into DB at main(): {E}")

    # Start main app. Do not put any code below this line
    app.run(host=HOST, port=PORT, ssl_context='adhoc', use_reloader=False, debug=False)