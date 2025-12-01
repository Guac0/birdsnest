from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin, current_user
from flask import Flask, Response, request, jsonify, render_template, redirect, url_for, flash, abort, send_from_directory, session
from functools import wraps
from datetime import datetime, timedelta
import hashlib
import time
import re
import os
import random
import string
import subprocess
import requests
import atexit, signal, sys
import threading, time
import json
from collections import Counter
import base64

# =================================
# ======= START USER CONFIG =======
# =================================

# === WEBGUI CONFIG ===
webgui_users    = {                     # Valid roles: admin or guest
    "admin": {"password": "admin", "role": "admin"},  # TODO: use hashed passwords
    "guest": {"password": "guest", "role": "guest"}
}
# === SERVER CONFIG ===
HOST            = "127.0.0.1"           # Listen IP
PORT            = 8080                  # Listen Port
LOGFILE         = f"log_{datetime.now().strftime("%Y-%m-%d_%H-%M-%S")}.txt"   # File to write logs to
SAVEFILE        = f"save_{datetime.now().strftime("%Y-%m-%d_%H-%M-%S")}.json"#f"save_testing2.json" # Savefile to save/load data from. Default f"save_{datetime.now().strftime("%Y-%m-%d_%H-%M-%S")}.json"
SAVE_INTERVAL   = 60                    # Seconds between autosaves
# === BEACON CONFIG ===
AUTH_TOKEN              = "testtoken" # Change this per engagement. Allows beacons to authenticate to the server

# =================================
# ======== END USER CONFIG ========
# =================================

# =================================
# ==== INITIALIZE VARS/SETTINGS ===
# =================================

# === Set Flask Config ===
app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.urandom(32), # Randomize the key every startup to avoid cookie reuse
    #SESSION_COOKIE_SECURE=True, # Forces the session cookie to be sent only over HTTPS. TODO
    SESSION_COOKIE_HTTPONLY=True, # Prevents JavaScript from accessing the session cookie
    SESSION_COOKIE_SAMESITE="Strict", # "Strict": the cookie is only sent for requests from the same site (no subdomains)
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=1),
    SESSION_REFRESH_EACH_REQUEST=True # Automatic refreshes mean that lifetime is effectively infinite! This means that users actively on the site won't get signed out, but people who close the site but not the browser and keep it closed for 1 min will have to sign in again
)

# === Initialize Misc Vars ===
start_time = time.time()
last_save_time=0
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
agents              = {}    # agent_id (name, hostname, ip, os): {agent_name(str),hostname(str),ip(str),os(str),executionUser(str),executionAdmin(bool),lastSeenTime(int),lastStatus(bool)}
messages            = {}    # message_id (timestamp,agent_id): {timestamp(int),agent_id(str),oldStatus(bool),newStatus(bool),message(str)}
incidents           = {}    # incident_id (increments with each incident): {timestamp(int),agent_id(str),tag(str),oldStatus(bool),newStatus(bool),message(str)}. TAG can be "New", "Active", or "Closed". TODO: consider refactoring this using a reference to messages

# =================================
# ======= UTILITY FUNCTIONS =======
# =================================

# === BEACON SUPPORT ===

def hash_id(*args):
    # hash any number of args so that we have a single value to use as the id that remains unique if multiple items have similar fields
    # Does not need to be secure
    combined = "|".join(map(str, args))
    encoded = base64.b64encode(combined.encode("utf-8")).decode("utf-8")
    return encoded
    #return hashlib.sha256(f"{ip}|{hostname}".encode()).hexdigest() #sha256 hash - too complex to use on frontend

def matches_pattern(value, pattern):
    return pattern is None or re.fullmatch(pattern, value) is not None

# === SAVE AND LOAD ===
def save_state(filepath=SAVEFILE):
    global last_save_time
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

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
        "agents": agents,
        "messages": messages,
        "incidents": incidents
    }

    with open(filepath, "w") as f:
        json.dump(state, f, indent=2)

    last_save_time=time.time()

    with open(LOGFILE, "a") as f:
        f.write(f"[+] {timestamp} save_state - saved current database to {LOGFILE}\n")

def signal_handler(signum, frame):
    save_state()
    sys.exit(0)

def periodic_autosave(interval=SAVE_INTERVAL):
    while True:
        time.sleep(interval)
        save_state()

def load_state(filepath=SAVEFILE):
    global webgui_users, agents, messages, incidents
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

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

        webgui_users = state["webgui_users"]
        agents = state["agents"]
        messages = state["messages"]
        incidents = state["incidents"]

        with open(LOGFILE, "a") as f:
            f.write(f"[+] {timestamp} load_state - {filepath} loaded!\n")

    except FileNotFoundError:
        with open(LOGFILE, "a") as f:
            f.write(f"[+] {timestamp} load_state - {filepath} not found, starting fresh\n")

# === LOGIN AND MISC ===

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != "admin":
            abort(403)  # Forbidden
        return f(*args, **kwargs)
    return decorated_function

@login_manager.user_loader
def load_user(id):
    user = webgui_users.get(id)
    if user:
        return User(id, user['role'])
    return None

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

def add_test_data_incidents(num=11):
    for i in range(1,num):
        incidents[i] = {
            "timestamp": time.time() - ((num - i) * 100),
            "agent_id":f"agent_{random.randint(1,5)}",
            "tag": random.choice(["New","Active","Closed"]),
            "oldStatus": random.choice([False,True]),
            "newStatus": random.choice([False,True]),
            "message": random.choice([
                "Service Issue - Missing required package {package} for service {service}, DISARMED.",
                "Service Issue - Service {service_name} not running, RESTORED service to START state.",
                "Service Issue - Service {service_name} not set to automatic start, FAILED to set to automatic start.",
                "Firewall Issue - Default {direction} policy is deny_all and no specific {direction.lower()} allow rule for port {port} exists. SUCCESSFULLY created firewall rule Stabvest_Rule_{port}_{direction}_{action}",
                "Firewall Issue - Default {direction} policy is deny_all and no specific {direction.lower()} allow rule for port {port} exists. DISARMED, but told to create firewall rule Stabvest_Rule_{port}_{direction}_{action}",
                "Firewall Issue - SUCCESSFULLY removed firewall rule: {rule['Name']}/{rule['DisplayName']}: {rule['Action']} {port} {rule['Direction']} on profile {rule['Profile']}.",
                "Firewall Issue - Could not get firewall rule information due to PowerShell error.",
                "Interface Issue - Interface {interface} was set to DOWN, RESTORED UP state.",
                "Interface Issue - Bad system TTL set, DISARMED.",
                "Interface Issue - Interface {interface}'s MTU was set to {old_mtu}, RESTORED new mtu {new_mtu}.",
                "Interface Issue - Missing IPv4 Address for interface {interface}, FAILED to restore {ip_address}/{subnet}."
            ])
        }

# =================================
# ========= API ENDPOINTS =========
# =================================

# === BASIC WEBSITE FUNCTIONALITY ===

@app.route("/")
@app.route("/dashboard")
@login_required
def page_dashboard():
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOGFILE, "a") as f:
        f.write(f"[+] {timestamp} /dashboard - Successful connection from {current_user.id} at {request.remote_addr}\n")
    return render_template("dashboard.html")

@app.route("/incidents")
@login_required
def page_incidents():
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOGFILE, "a") as f:
        f.write(f"[+] {timestamp} /dashboard - Successful connection from {current_user.id} at {request.remote_addr}\n")
    return render_template("incidents.html")

@app.route('/favicon.ico')
def favicon():
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOGFILE, "a") as f:
        f.write(f"[+] {timestamp} /favicon.ico - Successful connection at {request.remote_addr}\n")
    return send_from_directory(os.path.join(app.root_path, 'static'),'favicon.ico',mimetype='image/vnd.microsoft.icon')

@app.route('/background.jpg')
def background():
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOGFILE, "a") as f:
        f.write(f"[+] {timestamp} /background.jpg - Successful connection at {request.remote_addr}\n")
    return send_from_directory(os.path.join(app.root_path, 'static'),'background.jpg',mimetype='image/vnd.microsoft.icon')

@app.route('/login', methods=['GET', 'POST'])
def login():
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Very basic password check (TODO: replace with hashing & salting!)
        user = webgui_users.get(username)
        if user and password == user['password']:
            user_obj = User(username, user['role'])
            login_user(user_obj)
            session.permanent = True # Without session.permanent = True, Flask sets a session that expires when the browser closes - so not compatible with timeouts
            with open(LOGFILE, "a") as f:
                f.write(f"[+] {timestamp} /login - Successful authentication for {username} from {request.remote_addr}\n")
            return redirect(url_for('page_dashboard'))
        else:
            flash('Invalid username or password', 'danger')
            with open(LOGFILE, "a") as f:
                f.write(f"[-] {timestamp} /login - Unsuccessful connection for {username} with password {password} from {request.remote_addr}\n")
    else:
        with open(LOGFILE, "a") as f:
            f.write(f"[+] {timestamp} /login - Successful connection at {request.remote_addr}\n")

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOGFILE, "a") as f:
        f.write(f"[+] {timestamp} /logout - Logging out user {current_user.id} at {request.remote_addr}\n")

    logout_user()
    return redirect(url_for('login'))

@app.route('/whoami')
@login_required
def whoami():
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOGFILE, "a") as f:
        f.write(f"[+] {timestamp} /whoami - Successful connection for {current_user.id} at {request.remote_addr}\n")
    return jsonify({"username": current_user.id, "role": current_user.role})

# === BEACONS ===

@app.route("/ping", methods=["POST"])
def ping():
    # Provides an endpoint for the client to check that they can reach the server fine. Does not check auth.
    with open(LOGFILE, "a") as f:
        f.write(f"[+] {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} /ping - Successful connection from {request.remote_addr}\n")
    return "ok", 200

@app.route("/beacon", methods=["POST"])
def handle_beacon():
    data = request.json

    agent_name = data.get("name")
    hostname = data.get("hostname")
    ip = data.get("ip")
    os_name = data.get("os")
    executionUser = data.get("executionUser")
    executionAdmin = data.get("executionAdmin")
    auth = data.get("auth")
    beacon_type = data.get("beacon_type")
    oldStatus = data.get("oldStatus")
    newStatus = data.get("newStatus")
    message = data.get("message")

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Auth check
    if auth != AUTH_TOKEN:
        with open(LOGFILE, "a") as f:
            f.write(f"[-] {timestamp} /beacon - Failed connection from {request.remote_addr} - invalid auth token. Full details: {[hostname, ip, os_name, auth, output]}\n")
        return "Unauthorized", 403
    
    if not all([agent_name, hostname, ip, os_name, executionUser, executionAdmin, auth, beacon_type, oldStatus, newStatus, message]):
        with open(LOGFILE, "a") as f:
            f.write(f"[-] {timestamp} /beacon - Failed connection from {request.remote_addr} - missing data. Full details: {[agent_name, hostname, ip, os_name, executionUser, executionAdmin, auth, beacon_type, oldStatus, newStatus, message]}\n")
        return "Missing data", 400

    # Register client if new, or update agent fields if not
    # TODO re-register stale agents or registration agents
    agent_id = hash_id(agent_name, hostname, ip, os_name)

    if agent_id not in agents:
        agents[agent_id] = {
            "agent_name": agent_name,
            "hostname": hostname,
            "ip": ip,
            "os": os_name,
            "executionUser": executionUser,
            "executionAdmin": executionAdmin,
            "lastSeenTime": time.time(),
            "lastStatus": newStatus
        }
    else:
        agents[agent_id]["last_seen"] = time.time()
        agents[agent_id]["lastStatus"] = newStatus
    
    # Update messages{}
    message_id = hash_id(timestamp, agent_id)
    messageDict = {
        "timestamp": timestamp,
        "agent_id": agent_id,
        "oldStatus": oldStatus,
        "newStatus": newStatus,
        "message": message
    }

    if message_id in messages:
        with open(LOGFILE, "a") as f:
            f.write(f"[-] {timestamp} /beacon - messages hash collision. Old message: {messages[message_id]}. New message: {messageDict}\n")
    messages[message_id] = messageDict

    # Trigger incident if needed. Incident means that oldStatus is FALSE (malicious action or critical error detected)
    if oldStatus == False:
        incident_id = len(incidents) + 1
        incidentDict = {
            "timestamp": timestamp,
            "agent_id": agent_id,
            "oldStatus": oldStatus,
            "tag": "New",
            "newStatus": newStatus,
            "message": message
        }

        if incident_id in incidents:
            with open(LOGFILE, "a") as f:
                f.write(f"[-] {timestamp} /beacon - incidents hash collision. Old incident: {incidents[incident_id]}. New incident: {incidentDict}\n")
        incidents[incident_id] = incidentDict
        # TODO trigger incident alert

    # Return
    return "ok", 200

# === FRONTEND DISPLAY ===

@app.route("/list_agents", methods=["POST"])
@login_required
def list_agents():
    # TODO add filtering

    data = request.json
    #auth = data.get("auth")

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    #if auth != OPERATOR_TOKEN:
    #    with open(LOGFILE, "a") as f:
    #        f.write(f"[-] {timestamp} /list_agents - Failed connection from {request.remote_addr} - invalid auth token. Full details: {[auth]}\n")
    #    return "Unauthorized", 403
    
    with open(LOGFILE, "a") as f:
        f.write(f"[+] {timestamp} /list_agents - Successful connection from {current_user.id} at {request.remote_addr}\n")
    
    return jsonify(agents)

@app.route("/list_messages", methods=["POST"])
@login_required
def list_messages():
    # TODO add filtering

    data = request.json
    #auth = data.get("auth")

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    #if auth != OPERATOR_TOKEN:
    #    with open(LOGFILE, "a") as f:
    #        f.write(f"[-] {timestamp} /list_messages - Failed connection from {request.remote_addr} - invalid auth token. Full details: {[auth]}\n")
    #    return "Unauthorized", 403
    
    with open(LOGFILE, "a") as f:
        f.write(f"[+] {timestamp} /list_messages - Successful connection from {current_user.id} at {request.remote_addr}\n")
    
    return jsonify(messages)

@app.route("/list_incidents", methods=["POST"])
@login_required
def list_incidents():
    # TODO add filtering for only active incidents
    
    data = request.json
    #auth = data.get("auth")

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    #if auth != OPERATOR_TOKEN:
    #    with open(LOGFILE, "a") as f:
    #        f.write(f"[-] {timestamp} /list_incidents - Failed connection from {request.remote_addr} - invalid auth token. Full details: {[auth]}\n")
    #    return "Unauthorized", 403
    
    with open(LOGFILE, "a") as f:
        f.write(f"[+] {timestamp} /list_incidents - Successful connection from {current_user.id} at {request.remote_addr}\n")
    
    return jsonify(incidents)

# === FRONTEND INTERACTION ===

@app.route("/add_user", methods=["POST"])
@login_required
@admin_required
def add_user():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    if not all([username, password]):
        with open(LOGFILE, "a") as f:
            f.write(f"[-] {timestamp} /add_user - Failed connection from {current_user.id} at {request.remote_addr} - missing data. Full details: {[username, password]}\n")
        return "Missing data", 400

    epoch_time = time.time()

    webgui_users[username] = {"password": password, "role": "guest"} # TODO hash

    with open(LOGFILE, "a") as f:
        f.write(f"[+] {timestamp} /add_user - Successful connection from {current_user.id} at {request.remote_addr}. Adding user {username}\n")
    return jsonify({"status": "ok"})

@app.route("/update_incident_tag", methods=["POST"])
@login_required
@admin_required
def update_incident_tag():
    data = request.json
    incident_id = data.get("incident_id")
    tag = data.get("tag")

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    if not all([incident_id, tag]):
        with open(LOGFILE, "a") as f:
            f.write(f"[-] {timestamp} /update_incident_tag - Failed connection from {current_user.id} at {request.remote_addr} - missing data. Full details: {[incident_id, tag]}\n")
        return "Missing data", 400
    
    try:
        incident_id = int(incident_id)
    except:
        with open(LOGFILE, "a") as f:
            f.write(f"[-] {timestamp} /update_incident_tag - Failed connection from {current_user.id} at {request.remote_addr} - Invalid incident ID {incident_id} (failed to parse to int). Full details: {[incident_id, tag]}\n")
        return "Bad incident value", 400
    
    if tag not in ["New","Active","Closed"]:
        with open(LOGFILE, "a") as f:
            f.write(f"[+] {timestamp} /update_incident_tag - Successful connection from {current_user.id} at {request.remote_addr}. Invalid tag {tag}\n")
        return "Bad tag value", 400
    
    if incident_id in incidents:
        incidents[incident_id]["tag"] = tag
        with open(LOGFILE, "a") as f:
            f.write(f"[+] {timestamp} /update_incident_tag - Successful connection from {current_user.id} at {request.remote_addr}. Updating tag for incident {incident_id} to {tag}\n")
        return "ok", 200
    else:
        with open(LOGFILE, "a") as f:
            f.write(f"[+] {timestamp} /update_incident_tag - Successful connection from {current_user.id} at {request.remote_addr}. No incident found with id {incident_id}\n")
        return "Invalid incident ID", 400

# =================================
# ============= MAIN ==============
# =================================

if __name__ == "__main__":
    
    with open(LOGFILE, "a") as f:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[+] {timestamp} Starting server on {HOST}:{PORT}\n")

    # Load previous state if available
    load_state()

    # Test data
    add_test_data_incidents()
    #add_test_data_comp(0)
    #add_test_data_cmds()

    # Save on exit setup - see signal_handler() and save_state()
        # Registering both signal and atexit may cause saves to happen twice, but oh well. Not like it's a ton of work anyways.
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    atexit.register(save_state)

    # Start
    threading.Thread(target=periodic_autosave, daemon=True).start()
    app.run(host=HOST, port=PORT)