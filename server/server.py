from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin, current_user
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, abort, send_from_directory, session
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

# TODO synch

# =================================
# ======= START USER CONFIG =======
# =================================

# === WEBGUI CONFIG ===
webgui_users    = {                     # Valid roles: admin or analyst or guest
    "admin": {"password": "admin", "role": "admin"},  # TODO: use hashed passwords
    "analyst": {"password": "analyst", "role": "analyst"},
    "guest": {"password": "guest", "role": "guest"}
}
# === SERVER CONFIG ===
HOST            = "127.0.0.1"           # Listen IP
PORT            = 8080                  # Listen Port
PUBLIC_URL      = f"http://{HOST}:{PORT}"
LOGFILE         = f"log_{datetime.now().strftime("%Y-%m-%d_%H-%M-%S")}.txt"   # File to write logs to
SAVEFILE        = f"save_{datetime.now().strftime("%Y-%m-%d_%H-%M-%S")}.json"#f"save_testing2.json" # Savefile to save/load data from. Default f"save_{datetime.now().strftime("%Y-%m-%d_%H-%M-%S")}.json"
SAVE_INTERVAL   = 60                    # Seconds between autosaves
STALE_TIME      = 300                   # If agent has not checked in for this time period in seconds, mark them as stale
DEFAULT_WEBHOOK_SLEEP_TIME = 0.25       # Seconds between webhook uploads. Mostly just used as a fallback value in case auto rate limiting fails
MAX_WEBHOOK_MSG_PER_MINUTE = 30         # max 30 as of december 2025 for discord. this is shared between all webhooks in a single channel
#WEBHOOK_URL = ""
# test
WEBHOOK_URL     = "https://discord.com/api/webhooks/1445146908808188065/1xkiXfsL7ie8i04rGxdMu6nnnzJsVtj188VbHtZT5oBNJIoOYV5VP8lpI-mJhzeNYuYD"
# ccdc
#WEBHOOK_URL     = "https://discord.com/api/webhooks/1445154855214780459/N1mBMKjo2mvzCdGuRa6sH92UG394rFVr8PR9ZXuapcvLWDsGCYji47LN-GRQ5L2NTRzY"
# === BEACON CONFIG ===
agent_auth_tokens   = {
    "testtoken": { # Change this per engagement. Allows beacons to authenticate to the server
        "timestamp": time.time(),
        "added_by": "default"
    }
}

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
webhook_queue = deque()
webhook_queue_cond = threading.Condition()
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
agents              = {}    # agent_id (name, hostname, ip, os): {agent_name(str),hostname(str),ip(str),os(str),executionUser(str),executionAdmin(bool),lastSeenTime(int),lastStatus(bool),stale(bool)}
messages            = {}    # message_id (timestamp,agent_id): {timestamp(int),agent_id(str),oldStatus(bool),newStatus(bool),message(str)}
incidents           = {}    # incident_id (increments with each incident): {timestamp(int),agent_id(str),tag(str),oldStatus(bool),newStatus(bool),message(str),assignee(str)}. TAG can be "New", "Active", or "Closed". TODO: consider refactoring this using a reference to messages

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

def create_incident(messageDict,tag="New",assignee="",createAlert=True):
    """
    Creates an incident and sends alerts
    """
    global incidents

    incident_id = len(incidents) + 1
    incidentDict = {
        "timestamp": messageDict["timestamp"],
        "agent_id": messageDict["agent_id"],
        "oldStatus": messageDict["oldStatus"],
        "tag": tag,
        "newStatus": messageDict["newStatus"],
        "message": messageDict["message"],
        "assignee": assignee
    }

    if incident_id in incidents:
        with open(LOGFILE, "a") as f:
            f.write(f"[-] {timestamp} /create_incident - incidents hash collision. Old incident: {incidents[incident_id]}. New incident: {incidentDict}\n")
    incidents[incident_id] = incidentDict

    if createAlert:
        #discord_webhook(incident_id,incidentDict)
        with webhook_queue_cond: # Might lead to minor sleep but nothing major
            webhook_queue.append({"incident_id": incident_id, "incident":incidentDict})
            webhook_queue_cond.notify() 
        # TODO trigger web alert?
    
    return

def webhook_main():
    """Dedicated rate-limited sender thread with dynamic rate limiting."""

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

                with open(LOGFILE, "a") as f:
                    f.write(f"[-] {timestamp} /webhook_main - Retry_After succeeded, re-queued incident and sleeping for {sleep_time}.\n")

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
                            with open(LOGFILE, "a") as f:
                                f.write(f"[-] {timestamp} /webhook_main - incident {payload['incident_id']}: 0 responses remaining, sleeping for {sleep_time}.\n")
                    except ValueError:
                        sleep_time = DEFAULT_WEBHOOK_SLEEP_TIME
                        with open(LOGFILE, "a") as f:
                            f.write(f"[-] {timestamp} /webhook_main - incident {payload['incident_id']}: failed to parse headers, sleeping {sleep_time}.\n")
                else:
                    sleep_time = DEFAULT_WEBHOOK_SLEEP_TIME
                    with open(LOGFILE, "a") as f:
                        f.write(f"[-] {timestamp} /webhook_main - Missing rate limit headers, sleeping {sleep_time}.\n")

        except Exception as e:
            sleep_time = DEFAULT_WEBHOOK_SLEEP_TIME
            with open(LOGFILE, "a") as f:
                f.write(f"[-] {timestamp} /webhook_main - caught unknown error from discord_webhook - {e}.\n")

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
                with open(LOGFILE, "a") as f:
                    f.write(f"[-] {timestamp} /webhook_main - client side ratelimiting enabled: sleeping for {new_sleep_time} seconds. Old sleep_time: {sleep_time}. len(last_60_seconds): {len(last_60_seconds)}. MAX_WEBHOOK_MSG_PER_MINUTE: {MAX_WEBHOOK_MSG_PER_MINUTE}.\n") 
            sleep_time = new_sleep_time # If we are client side ratelimited, set extra time to compensate for discord channel ratelimiting (wait until oldest message drops off)

        # Rate limit enforcement
        time.sleep(sleep_time)

def discord_webhook(incident_id,incident,url=WEBHOOK_URL):
    #compare rules level to set colors of the alert
    if not url:
        return
    
    if (incident["message"].lower().split(' ')[0]  == "firewall"):
        color = "3b9102"
    elif (incident["message"].lower().split(' ')[0]  == "interface"):
        color = "01410b"
    elif (incident["message"].lower().split(' ')[0]  == "service"):
        color = "b87700"
    elif (incident["message"].lower().split(' ')[0]  == "servicecustom"):
        color = "5e4902"
    elif (incident["message"].lower().split(' ')[0] == "agent"):
        color = "04459b"
    elif (incident["message"].lower().split(' ')[0] == "ir"):
        color = "a81106"
    elif (incident["message"].lower().split(' ')[0] == "inject"):
        color = "430477"
    elif (incident["message"].lower().split(' ')[0] == "uptime"):
        color = "5a0b05"
    else:
        color = "6184542" # unknown

    #data that the webhook will receive and use to display the alert in discord chat
    # TODO: proper agent name
    try:
        payload = json.dumps({
        "embeds": [
            {
            "title": "Stabvest Alert - {} Incident Created on {} for {}".format(incident["message"].split('-')[0].strip(),agents[incident["agent_id"]]["hostname"],agents[incident["agent_id"]]["agent_name"]),
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
                "value": "{}".format(agents[incident["agent_id"]]["agent_name"]),
                "inline": True
                },
                {
                "name": "Hostname",
                "value": "{}".format(agents[incident["agent_id"]]["hostname"]),
                "inline": True
                },
                {
                "name": "IP Address",
                "value": "{}".format(agents[incident["agent_id"]]["ip"]),
                "inline": True
                }
            ]
            }
        ]
        })
    except KeyError:
        payload = json.dumps({
        "embeds": [
            {
            "title": "Stabvest Alert - Custom {} Incident Created".format(incident["message"].split('-')[0].strip()),
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
            with open(LOGFILE, "a") as f:
                f.write(f"[-] {timestamp} /discord_webhook - sent message for incident {incident_id}.\n")

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
        with open(LOGFILE, "a") as f:
            f.write(f"[-] {timestamp} /discord_webhook - failed to send message for incident {incident_id}. StatusCode: {err.code}. Body: {body}.\n") # Headers: {err.headers}. 
        return err,body

def check_stale(agents,incidents):
    """
    Given an agents dict, check their lastSeenTime and stale values and update stale if required.
    If agent moves in to stale state, generate an incident.
    If an agent moves out of stale state, close the relevant incident
    """
    for agent_id in agents:
        if agents[agent_id]["stale"]:
            # If agent was previously stale, see if they've checked in recently
            if (time.time() - agents[agent_id]["lastSeenTime"]) < STALE_TIME:
                # No longer stale, so close the relevant incident
                agents[agent_id]["stale"] = False
                
            else:
                # Still stale - update incident time
                continue
        else:
            # Agent not previously stale - check if they have not checked in recently
            if (time.time() - agents[agent_id]["lastSeenTime"]) > STALE_TIME:
                # Stale
                agents[agent_id]["stale"] = True

    return agents

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
        "agent_auth_tokens": agent_auth_tokens,
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
    global webgui_users, agents, messages, incidents, agent_auth_tokens
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

        agent_auth_tokens = state["agent_auth_tokens"]
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

def analyst_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or (current_user.role != "analyst" and current_user.role != "admin" ):
            abort(403)  # Forbidden
        return f(*args, **kwargs)
    return decorated_function

@login_manager.user_loader
def load_user(id):
    user = webgui_users.get(id)
    if user:
        return User(id, user['role'])
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
    global agents
    for i in range(1,num + 1):
        agent = {
            "agent_name": random.choice(["apache2","iis","smb","mysql","vsftpd"]),
            "hostname": random.choice(["webserver1","webserver2","fileshare1","fileshare2","dc01"]),
            "ip": random.choice(["10.1.1.1","10.1.1.2","10.1.1.3","10.1.1.4","10.1.1.5"]),
            "os": random.choice(["Windows 10","Windows 2016Server","Ubuntu 16.03 Name","RHEL 9.3","Rocky 8"]),
            "executionUser": random.choice(["root","admin",".\\administrator","domain\\dadmin","user"]),
            "executionAdmin": random.choice([True,False]),
            "lastSeenTime": time.time() - ((num - i) * 100),
            "lastStatus": random.choice([True,False]),
            "stale": False
        }
        agents[f"agent_{i}"] = agent

def add_test_data_incidents(num=15,createAlert=True):
    for i in range(1,num + 1):
        incident = {
            "timestamp": time.time() - ((num - i) * 100),
            "agent_id":f"agent_{random.randint(1,5)}",
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
                "Agent - No logs from agent in {minutes} minutes.",
                "Agent - Agent paused for {seconds} seconds.",
                "Agent - Agent re-registered.",
                "ServiceCustom - MySQL users changed.",
                "ServiceCustom - MySQL data changed.",
                "ServiceCustom - IIS Site Config changed.",
                "ServiceCustom - IIS Application Pool changed."#,
                #"Generic - Test Test Test.",
                #"Generic - Test Test Test."
            ])
        }
        create_incident(incident,random.choice(["New","Active","Closed"]),random.choice(["Andrew","James","Max","Windows","Windows","Linux","Linux","","","",""]),createAlert)

def add_test_data_incidents_custom(num=5,createAlert=True):
    for i in range(1,num + 1):
        incident = {
            "timestamp": time.time() - ((num - i) * 100),
            "agent_id":f"custom",
            "oldStatus": random.choice([False,True]),
            "newStatus": random.choice([False,True]),
            "message": random.choice([
                "IR - Investigate suspicious sign-in activity on {hostname} / {ipaddress}.",
                "IR - Write report on Doubletap scheduled task.",
                "Inject - Implement HTTPS for {check} scorecheck on {hostname} / {ipaddress} by {time}.",
                "Uptime - Fix failed {check} scorecheck on {hostname} / {ipaddress}."
            ])
        }
        create_incident(incident,random.choice(["New","Active","Closed"]),random.choice(["Andrew","James","Max","Windows","Windows","Linux","Linux","","","",""]),createAlert)

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

@app.route("/management")
@login_required
@admin_required
def page_management():
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOGFILE, "a") as f:
        f.write(f"[+] {timestamp} /management - Successful connection from {current_user.id} at {request.remote_addr}\n")
    return render_template("management.html")

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

    # For GET render pass the next param to template so the form includes it
    if request.method == 'GET':
        next_param = request.args.get('next', '')
        with open(LOGFILE, "a") as f:
            f.write(f"[+] {timestamp} /login - Successful connection at {request.remote_addr}\n")
        return render_template('login.html', next=next_param)

    # POST
    username = request.form.get('username')
    password = request.form.get('password')
    next_param = request.form.get('next') or request.args.get('next') or ''

    user = webgui_users.get(username)
    if user and password == user['password']:
        user_obj = User(username, user['role'])
        login_user(user_obj)
        session.permanent = True
        with open(LOGFILE, "a") as f:
            f.write(f"[+] {timestamp} /login - Successful authentication for {username} from {request.remote_addr}\n")

        # Validate next and redirect safely
        if is_safe_path(next_param):
            return redirect(unquote_plus(next_param))
        return redirect(url_for('page_dashboard'))

    flash('Invalid username or password', 'danger')
    with open(LOGFILE, "a") as f:
        f.write(f"[-] {timestamp} /login - Unsuccessful connection for {username} with password {password} from {request.remote_addr}\n")
    return render_template('login.html', next=next_param)

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
    if not auth in agent_auth_tokens:
        with open(LOGFILE, "a") as f:
            f.write(f"[-] {timestamp} /beacon - Failed connection from {request.remote_addr} - invalid auth token. Full details: {[hostname, ip, os_name, auth]}\n")
        return "Unauthorized", 403
    
    if not all([agent_name, hostname, ip, os_name, executionUser, executionAdmin, auth, beacon_type, oldStatus, newStatus, message]):
        with open(LOGFILE, "a") as f:
            f.write(f"[-] {timestamp} /beacon - Failed connection from {request.remote_addr} - missing data. Full details: {[agent_name, hostname, ip, os_name, executionUser, executionAdmin, auth, beacon_type, oldStatus, newStatus, message]}\n")
        return "Missing data", 400

    # Register client if new, or update agent fields if not
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
            "lastStatus": newStatus,
            "stale": False
        }
    else:
        # TODO re-register agents might need a refresh on hostname and etc
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
        create_incident(messageDict)

    # Return
    return "ok", 200

# === FRONTEND DISPLAY ===

@app.route("/list_users", methods=["POST"])
@login_required
@admin_required
def list_users():
    data = request.json
    #auth = data.get("auth")

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    #if auth != OPERATOR_TOKEN:
    #    with open(LOGFILE, "a") as f:
    #        f.write(f"[-] {timestamp} /list_agents - Failed connection from {request.remote_addr} - invalid auth token. Full details: {[auth]}\n")
    #    return "Unauthorized", 403
    
    with open(LOGFILE, "a") as f:
        f.write(f"[+] {timestamp} /list_users - Successful connection from {current_user.id} at {request.remote_addr}\n")
    
    return jsonify(webgui_users)

@app.route("/list_users_simple", methods=["POST"])
@login_required
@analyst_required
def list_users_simple():
    data = request.json
    #auth = data.get("auth")

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    #if auth != OPERATOR_TOKEN:
    #    with open(LOGFILE, "a") as f:
    #        f.write(f"[-] {timestamp} /list_agents - Failed connection from {request.remote_addr} - invalid auth token. Full details: {[auth]}\n")
    #    return "Unauthorized", 403
    
    with open(LOGFILE, "a") as f:
        f.write(f"[+] {timestamp} /list_users_simple - Successful connection from {current_user.id} at {request.remote_addr}\n")
    
    users = []
    for user in webgui_users:
        users.append(user)

    return users

@app.route("/list_tokens", methods=["POST"])
@login_required
@admin_required
def list_tokens():
    data = request.json
    #auth = data.get("auth")

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    #if auth != OPERATOR_TOKEN:
    #    with open(LOGFILE, "a") as f:
    #        f.write(f"[-] {timestamp} /list_agents - Failed connection from {request.remote_addr} - invalid auth token. Full details: {[auth]}\n")
    #    return "Unauthorized", 403
    
    with open(LOGFILE, "a") as f:
        f.write(f"[+] {timestamp} /list_tokens - Successful connection from {current_user.id} at {request.remote_addr}\n")
    
    return jsonify(agent_auth_tokens)

@app.route("/list_agents", methods=["POST"])
@login_required
def list_agents():

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

@app.route("/list_logfile", methods=["POST"])
@login_required
@admin_required
def list_logfile(filepath=LOGFILE,lines=50):

    data = request.json
    #auth = data.get("auth")

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    #if auth != OPERATOR_TOKEN:
    #    with open(LOGFILE, "a") as f:
    #        f.write(f"[-] {timestamp} /list_incidents - Failed connection from {request.remote_addr} - invalid auth token. Full details: {[auth]}\n")
    #    return "Unauthorized", 403
    
    with open(LOGFILE, "a") as f:
        f.write(f"[+] {timestamp} /list_logfile - Successful connection from {current_user.id} at {request.remote_addr}\n")
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            # Use deque to keep only the last 50 lines in memory
            last_lines = deque(f, maxlen=lines)
        return list(last_lines)

    except FileNotFoundError:
        with open(LOGFILE, "a") as f:
            f.write(f"[+] /list_logfile - Successful connection from {current_user.id} at {request.remote_addr}\n")
            return f"FileNotFound {filepath}", 400

@app.route("/save_export", methods=["POST"])
@login_required
@admin_required
def save_export(filepath=SAVEFILE):

    data = request.json
    #auth = data.get("auth")

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    #if auth != OPERATOR_TOKEN:
    #    with open(LOGFILE, "a") as f:
    #        f.write(f"[-] {timestamp} /list_incidents - Failed connection from {request.remote_addr} - invalid auth token. Full details: {[auth]}\n")
    #    return "Unauthorized", 403
    
    with open(LOGFILE, "a") as f:
        f.write(f"[+] {timestamp} /save_export - Successful connection from {current_user.id} at {request.remote_addr}\n")
    
    try:
        with open(filepath, "r") as f:
            state = json.load(f)

        return state
    except FileNotFoundError:
        with open(LOGFILE, "a") as f:
            f.write(f"[+] /save_export - Successful connection from {current_user.id} at {request.remote_addr}\n")
            return f"FileNotFound {filepath}", 400

# === FRONTEND INTERACTION ===

@app.route("/add_incident", methods=["POST"])
@login_required
@analyst_required
def add_incident():
    data = request.json
    newStatus = data.get("newStatus")
    message = data.get("message")
    assignee = data.get("assignee","")
    createAlert = data.get("createAlert")

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    if not all([message]): # just the required string
        with open(LOGFILE, "a") as f:
            f.write(f"[-] {timestamp} /add_incident - Failed connection from {current_user.id} at {request.remote_addr} - missing data. Full details: {[newStatus,message,assignee,createAlert]}\n")
        return "Missing data", 400
    
    # not verifying data as I don't want to. TODO
    
    messageDict = {
        "timestamp": time.time(),
        "agent_id": "custom",
        "oldStatus": True,
        "newStatus": newStatus,
        "message": message
    }

    create_incident(messageDict,tag="New",assignee=assignee,createAlert=createAlert)

    with open(LOGFILE, "a") as f:
        f.write(f"[+] {timestamp} /add_incident - Successful connection from {current_user.id} at {request.remote_addr}. Creating incident with details [newStatus,message,assignee,createAlert].\n")
    return jsonify({"status": "ok"})

@app.route("/add_user", methods=["POST"])
@login_required
@admin_required
def add_user():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    role = data.get("role")

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    if not all([username, password, role]):
        with open(LOGFILE, "a") as f:
            f.write(f"[-] {timestamp} /add_user - Failed connection from {current_user.id} at {request.remote_addr} - missing data. Full details: {[username, password, role]}\n")
        return "Missing data", 400
    
    if role != "guest" and role != "analyst":
        with open(LOGFILE, "a") as f:
            f.write(f"[-] {timestamp} /add_user - Failed connection from {current_user.id} at {request.remote_addr} - bad role value. Full details: {[username, password, role]}\n")
        return "Bad role value", 400

    if username in webgui_users:
        with open(LOGFILE, "a") as f:
            f.write(f"[-] {timestamp} /add_user - Failed connection from {current_user.id} at {request.remote_addr} - bad username value, conflicts with existing user. Full details: {[username, password, role]}\n")
        return "New user overlaps with existing user", 400

    webgui_users[username] = {"password": password, "role": role} # TODO hash

    with open(LOGFILE, "a") as f:
        f.write(f"[+] {timestamp} /add_user - Successful connection from {current_user.id} at {request.remote_addr}. Adding user {username} with role {role}\n")
    return jsonify({"status": "ok"})

@app.route("/delete_user", methods=["POST"])
@login_required
@admin_required
def delete_user():
    data = request.json
    username = data.get("username")

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    if not all([username]):
        with open(LOGFILE, "a") as f:
            f.write(f"[-] {timestamp} /delete_user - Failed connection from {current_user.id} at {request.remote_addr} - missing data. Full details: {[username]}\n")
        return "Missing data", 400
    
    if not webgui_users[username]:
        with open(LOGFILE, "a") as f:
            f.write(f"[-] {timestamp} /delete_user - Failed connection from {current_user.id} at {request.remote_addr} - username not found. Full details: {[username]}\n")
        return "Bad role value", 400
    
    if username == current_user.id:
        with open(LOGFILE, "a") as f:
            f.write(f"[-] {timestamp} /delete_user - Failed connection from {current_user.id} at {request.remote_addr} - cannot delete own user. Full details: {[username]}\n")
        return "Target username cannot be the same as current username", 400

    with open(LOGFILE, "a") as f:
        f.write(f"[+] {timestamp} /delete_user - Successful connection from {current_user.id} at {request.remote_addr}. Deleting user {username} with role {webgui_users[username]["role"]}\n")
    
    webgui_users.pop(username)

    return jsonify({"status": "ok"})

@app.route("/add_token", methods=["POST"])
@login_required
@admin_required
def add_token():
    data = request.json
    token = data.get("token")

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    if not all([token]):
        with open(LOGFILE, "a") as f:
            f.write(f"[-] {timestamp} /add_token - Failed connection from {current_user.id} at {request.remote_addr} - missing data. Full details: {[token]}\n")
        return "Missing data", 400
    
    if token in agent_auth_tokens:
        with open(LOGFILE, "a") as f:
            f.write(f"[-] {timestamp} /add_token - Failed connection from {current_user.id} at {request.remote_addr} - bad token value, conflicts with existing token. Full details: {[token]}\n")
        return "New user overlaps with existing user", 400

    agent_auth_tokens[token] = {"timestamp": time.time(), "added_by": current_user.id}

    with open(LOGFILE, "a") as f:
        f.write(f"[+] {timestamp} /add_token - Successful connection from {current_user.id} at {request.remote_addr}. Adding token {token}\n")
    return jsonify({"status": "ok"})

@app.route("/delete_token", methods=["POST"])
@login_required
@admin_required
def delete_token():
    data = request.json
    token = data.get("token")

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    if not all([token]):
        with open(LOGFILE, "a") as f:
            f.write(f"[-] {timestamp} /delete_token - Failed connection from {current_user.id} at {request.remote_addr} - missing data. Full details: {[token]}\n")
        return "Missing data", 400
    
    if not agent_auth_tokens[token]:
        with open(LOGFILE, "a") as f:
            f.write(f"[-] {timestamp} /delete_token - Failed connection from {current_user.id} at {request.remote_addr} - username not found. Full details: {[token]}\n")
        return "Bad role value", 400

    with open(LOGFILE, "a") as f:
        f.write(f"[+] {timestamp} /delete_token - Successful connection from {current_user.id} at {request.remote_addr}. Deleting token {token} that was added by {agent_auth_tokens[token]["added_by"]} at {datetime.fromtimestamp(agent_auth_tokens[token]["timestamp"])}\n")
    
    agent_auth_tokens.pop(token)

    return jsonify({"status": "ok"})

@app.route("/update_incident_tag", methods=["POST"])
@login_required
@analyst_required
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

@app.route("/update_incident_assignee", methods=["POST"])
@login_required
@analyst_required
def update_incident_assignee():
    data = request.json
    incident_id = data.get("incident_id")
    assignee = data.get("assignee")

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    if not all([incident_id, assignee]):
        with open(LOGFILE, "a") as f:
            f.write(f"[-] {timestamp} /update_incident_assignee - Failed connection from {current_user.id} at {request.remote_addr} - missing data. Full details: {[incident_id, assignee]}\n")
        return "Missing data", 400
    
    try:
        incident_id = int(incident_id)
    except:
        with open(LOGFILE, "a") as f:
            f.write(f"[-] {timestamp} /update_incident_assignee - Failed connection from {current_user.id} at {request.remote_addr} - Invalid incident ID {incident_id} (failed to parse to int). Full details: {[incident_id, assignee]}\n")
        return "Bad incident value", 400
    
    if incident_id in incidents:
        incidents[incident_id]["assignee"] = assignee
        with open(LOGFILE, "a") as f:
            f.write(f"[+] {timestamp} /update_incident_assignee - Successful connection from {current_user.id} at {request.remote_addr}. Updating assignee for incident {incident_id} to {assignee}\n")
        return "ok", 200
    else:
        with open(LOGFILE, "a") as f:
            f.write(f"[+] {timestamp} /update_incident_assignee - Successful connection from {current_user.id} at {request.remote_addr}. No incident found with id {incident_id}\n")
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

    # Save on exit setup - see signal_handler() and save_state()
    # Registering both signal and atexit may cause saves to happen twice, but oh well. Not like it's a ton of work anyways.
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    atexit.register(save_state)

    # Start threads before test data to avoid delays
    threading.Thread(target=periodic_autosave, daemon=True).start()
    threading.Thread(target=webhook_main, daemon=True).start()

    # Test data
    add_test_data_agents()
    add_test_data_incidents_custom(30)
    add_test_data_incidents(70)
    #add_test_data_comp(0)
    #add_test_data_cmds()

    # Start main app. Do not put any code below this line
    app.run(host=HOST, port=PORT)