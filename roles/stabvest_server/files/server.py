from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin, current_user
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, abort, send_from_directory, session
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta
import time
import os
from collections import deque
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
import subprocess

from models import (
db,
Agent, Message, Incident, AuthToken, WebUser, AnsibleResult, AnsibleVars,
AuthConfig, AuthConfigGlobal, AuthRecord, WebhookQueue, AnsibleQueue
)
from shared import (
setup_logging, User, CONFIG, HOST, PORT, PUBLIC_URL, LOGFILE, SAVEFILE, SAVE_INTERVAL, STALE_TIME, DEFAULT_WEBHOOK_SLEEP_TIME,
MAX_WEBHOOK_MSG_PER_MINUTE, WEBHOOK_URL, INITIAL_AGENT_AUTH_TOKENS, INITIAL_WEBGUI_USERS, AUTHCONFIG_STRICT_IP,
AUTHCONFIG_STRICT_USER, AUTHCONFIG_CREATE_INCIDENT, AUTHCONFIG_LOG_ATTEMPT_SUCCESSFUL, CREATE_TEST_DATA, SECRET_KEY,
GIT_PROJECT_ROOT, GIT_BACKEND
)
from utilities import (
insert_initial_data, create_db_tables, serialize_model, is_safe_path,
get_random_time_offset_epoch, add_test_data_agents, add_test_data_messages, add_test_data_incidents,
add_test_data_incidents_custom, add_test_data_auth_records, add_test_data_auth_config,
run_git, hash_id, create_incident, clean_and_join_path, get_git_stats, find_incident, find_incident_db
)
from web import (
    login,
    dashboard_summary, get_repo_history, get_commit_diff, 
    list_authconfig, list_auth_records, list_git_overall, 
    ping_login, list_users, list_users_simple, list_tokens, 
    list_tokens_number, list_agents, list_messages, 
    list_incidents, list_ansiblevars, 
    list_logfile, list_ansibleresult, save_export, 
    set_ansiblevars, save_git_note, set_good_branch, update_global_config, 
    add_authconfig, update_authconfig_status, delete_authconfig, 
    authrecord_update_notes, bulk_authconfig, bulk_auth_records, 
    agent_pause, agent_resume, add_incident, add_user,
    delete_token, update_incident_tag, update_incident_assignee,
    update_incident_sla, add_ansible, add_token, delete_user
)

# === Set Flask Config ===
SQLALCHEMY_DATABASE_URI = f'sqlite:///{SAVEFILE}'
app = Flask(__name__)
app.config['SECRET_KEY'] = CONFIG["SECRET_KEY"]
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False # Silence the deprecation warning
app.config.update(
    SESSION_COOKIE_SECURE=True, # Forces the session cookie to be sent only over HTTPS.
    SESSION_COOKIE_HTTPONLY=True, # Prevents JavaScript from accessing the session cookie
    SESSION_COOKIE_SAMESITE="Strict", # "Strict": the cookie is only sent for requests from the same site (no subdomains)
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=3),
    SESSION_REFRESH_EACH_REQUEST=True, # Automatic refreshes mean that lifetime is effectively infinite! This means that users actively on the site won't get signed out, but people who close the site but not the browser and keep it closed for 1 min will have to sign in again
    
    # --- Server-Side Session Config ---
    SESSION_TYPE='sqlalchemy',
    SESSION_SQLALCHEMY=db,  # Tell it to use your existing SQLAlchemy instance
    SESSION_SQLALCHEMY_TABLE='flask_sessions', # It will create this table automatically
    SESSION_PERMANENT=True,
    SESSION_USE_SIGNER=True # Protects the session cookie from tampering
)
db.init_app(app)

# === Initialize Misc Vars ===
# See load_user() for the following
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # redirect to login page if not authenticated

create_db_tables(app)

logger = setup_logging("web")
logger.info(f"Starting server on {HOST}:{PORT}")

# =================================
# ======= UTILITY FUNCTIONS =======
# =================================

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
def login_redirect():
    return login()

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

    agent_name = data.get("name","") # Agent name. Should be unique per agent_type per host. Ex: apache2 (for a stabvest agent protecting apache2)
    agent_type = data.get("agent_type","") # Agent type. Ex: stabvest
    hostname = data.get("hostname","") # Client machine hostname
    ip = data.get("ip","") # Client machine ip WITHOUT subnet mask
    os_name = data.get("os","") # Client machine OS string in format Ubuntu 10.04 lucid, debian 4.0 , fedora 17 Beefy Miracle, redhat 5.6 Tikanga, redhat 5.9 Final, Windows 10, Windows 2016Server, FreeBSD format
    executionUser = data.get("executionUser","") # The user the client program is executing as
    executionAdmin = data.get("executionAdmin",False) # Whether the client program is executing in a superuser context
    auth = data.get("auth","") # Client auth token
    oldStatus = data.get("oldStatus",False) # Client old status. ex: false if client has detected malicious activity or has had an internal error, true if nothing has been detected
    newStatus = data.get("newStatus",False) # Client new status. Always TRUE if oldStatus is TRUE. Otherwise, serves as an indicator if the issue in oldStatus has been automatically remediated successfully.
    message = data.get("message","") # Custom string message. Used for incident descriptions.
    #owlet only
    timestamp = data.get("timestamp",0) # Special - OWLET usage only. Represents timestamp of the analyzed event in epoch time.
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
                    run_git(["config", "-f", f"{agent_id}.git/config", "http.receivepack", "true"],GIT_PROJECT_ROOT)
                    logger.info(f"/beacon: created repo {os.path.join(GIT_PROJECT_ROOT,f'{agent_id}.git')}")
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
        if (message.lower().strip() != "all good") and (message.lower().strip() != "register") and (message.lower().strip() != "reregister") and (message.lower().strip() != "agent moved into pause status for") and (message.lower().strip() != "agent still in pase status for"):
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
    #logger.info(f"/git: START git_backend: repo={repo_name}, path={git_path}, method={request.method}")

    try:
        # Check if the cleaning function is the culprit
        try:
            # If this function crashes, it usually happens here
            git_path = clean_and_join_path(git_path)
        except Exception as e:
            logger.eoor(f"/git: CRASH in clean_and_join_path: {str(e)}")
            return f"Path cleaning failed: {str(e)}", 500

        # Build Environment
        env = {
            'REQUEST_METHOD': request.method,
            'GIT_PROJECT_ROOT': GIT_PROJECT_ROOT,
            'GIT_HTTP_EXPORT_ALL': '1',
            #'PATH_INFO': f"{repo_name}.git/{git_path}",
            'PATH_INFO': f"/{repo_name}.git/{git_path}" if git_path else f"/{repo_name}.git/",
            #'PATH_TRANSLATED': os.path.join(GIT_PROJECT_ROOT, repo_name + ".git", git_path),
            'QUERY_STRING': request.query_string.decode('utf-8') if request.query_string else '',
            'CONTENT_TYPE': request.headers.get('Content-Type', ''),
            'CONTENT_LENGTH': request.headers.get('Content-Length', ''),
            'REMOTE_ADDR': request.remote_addr,
            'REMOTE_USER': 'git_user',
        }

        #logger.info(f"/git: GIT_BACKEND - {GIT_BACKEND}, env - {env}.")

        # Validate GIT_BACKEND exists before trying to run it
        if not os.path.exists(GIT_BACKEND):
            logger.critical(f"/git: CRITICAL: GIT_BACKEND binary not found at {GIT_BACKEND}")
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
            logger.warning(f"/git: Git binary returned {process.returncode}. Stderr: {stderr.decode('utf-8')}")

        # Header parsing
        header_end = stdout.find(b'\r\n\r\n')
        if header_end == -1:
            header_end = stdout.find(b'\n\n')
            sep_len = 2
        else:
            sep_len = 4

        if header_end == -1:
            # If no headers found, the binary likely produced an error on stdout
            logger.warning(f"/git: CGI ERROR: No header separator. Raw Output: {stdout[:200]}")
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
            logger.warning(f"/git: CGI Header Parse Error: No header separator found in binary output. Raw output start: {stdout[:50]}")
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
                        logger.warning(f"/git: Malformed Status header: {v}")
                else:
                    headers_dict[key.strip()] = v
        #logger.info(f"/git: returning response_body {response_body}, status_code {status_code}, headers_dict {headers_dict}.")
        logger.info(f"/git - Successful connection from {request.remote_addr}.")
        return response_body, status_code, headers_dict

    except FileNotFoundError:
        logger.error(f"/git: GIT_BACKEND binary not found at: {GIT_BACKEND}")
        return "Internal Server Error: Backend Binary Missing", 500
    except PermissionError:
        logger.error(f"/git: Permission denied when executing GIT_BACKEND: {GIT_BACKEND}")
        return "Internal Server Error: Backend Permission Denied", 500
    except Exception as e:
        logger.error(f"/git: Unexpected error in git_backend: {str(e)}")
        return "Internal Server Error", 500

@app.route('/list_authconfig_agent', methods=['GET'])
def get_config():
    logger.info(f"/list_authconfig_agent - Successful connection from {request.remote_addr}.")
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

# Also used for frontend
@app.route('/list_authconfigglobal', methods=['POST'])
def get_global_config():
    logger.info(f"/list_authconfigglobal - Successful connection from {request.remote_addr}.")
    configs = AuthConfigGlobal.query.all()
    return jsonify({c.key: c.value for c in configs})

# === FRONTEND DISPLAY ===

@app.route("/dashboard_summary", methods=["POST"])
@login_required
def dashboard_summary_redirect():
    return dashboard_summary()

@app.route("/get_repo_history", methods=["POST"])
@login_required
def get_repo_history_redirect():
    return get_repo_history()

@app.route("/get_commit_diff", methods=["POST"])
@login_required
def get_commit_diff_redirect():
    return get_commit_diff()

@login_required
@app.route('/list_authconfig', methods=['POST'])
def list_authconfig_redirect():
    return list_authconfig()

@login_required
@app.route('/list_auth_records', methods=['POST'])
def list_auth_records_redirect():
    return list_auth_records()

@login_required
@app.route("/list_git_overall", methods=["POST"])
def list_git_overall_redirect():
    return list_git_overall()

@login_required
@app.route("/ping_login", methods=["POST"])
def ping_login_redirect():
    return ping_login()

@app.route("/list_users", methods=["POST"])
@login_required
@admin_required
def list_users_redirect():
    return list_users()

@app.route("/list_users_simple", methods=["POST"])
@login_required
def list_users_simple_redirect():
    return list_users_simple()

@app.route("/list_tokens", methods=["POST"])
@login_required
@admin_required
def list_tokens_redirect():
    return list_tokens()

@app.route("/list_tokens_number", methods=["POST"])
@login_required
def list_tokens_number_redirect():
    return list_tokens_number()

@app.route("/list_agents", methods=["POST"])
@login_required
def list_agents_redirect():
    return list_agents()

@app.route("/list_messages", methods=["POST"])
@login_required
def list_messages_redirect():
    return list_messages()

@app.route("/list_incidents", methods=["POST"])
@login_required
def list_incidents_redirect():
    return list_incidents()

@app.route("/list_ansiblevars", methods=["GET"]) # TODO standardize on POST
@login_required
def list_ansiblevars_redirect():
    return list_ansiblevars()

@app.route("/list_logfile", methods=["POST"])
@login_required
@admin_required
def list_logfile_redirect(filepath=LOGFILE, lines=50):
    return list_logfile(filepath, lines)

@app.route("/list_ansibleresult", methods=["POST"])
@login_required
@analyst_required
def list_ansibleresult_redirect():
    return list_ansibleresult()

@app.route("/save_export", methods=["POST"])
@login_required
@admin_required
def save_export_redirect(filepath=SAVEFILE):
    return save_export(filepath)

# === FRONTEND INTERACTION ===

@app.route("/set_ansiblevars", methods=["POST"])
@login_required
@analyst_required
def set_ansiblevars_redirect():
    return set_ansiblevars()

@app.route("/save_git_note", methods=["POST"])
@login_required
@analyst_required
def save_git_note_redirect():
    return save_git_note()

@app.route("/set_good_branch", methods=["POST"])
@login_required
@analyst_required
def set_good_branch_redirect():
    return set_good_branch()

@app.route('/update_authconfigglobal', methods=['POST'])
@login_required
@analyst_required
def update_global_config_redirect():
    return update_global_config()

@app.route('/add_authconfig', methods=['POST'])
@login_required
@analyst_required
def add_authconfig_redirect():
    return add_authconfig()

@app.route('/update_authconfig_status', methods=['POST'])
@login_required
@analyst_required
def update_authconfig_status_redirect():
    return update_authconfig_status()

@app.route('/delete_authconfig', methods=['POST'])
@login_required
@analyst_required
def delete_authconfig_redirect():
    return delete_authconfig()

@app.route('/authrecord_update_notes', methods=['POST'])
@login_required
@analyst_required
def authrecord_update_notes_redirect():
    return authrecord_update_notes()

@app.route('/bulk_authconfig', methods=['POST'])
@login_required
@analyst_required
def bulk_authconfig_redirect():
    return bulk_authconfig()

@app.route('/bulk_auth_records', methods=['POST'])
@login_required
@analyst_required
def bulk_auth_records_redirect():
    return bulk_auth_records()

@app.route("/agent_pause", methods=["POST"])
@login_required
@analyst_required
def agent_pause_redirect():
    return agent_pause()

@app.route("/agent_resume", methods=["POST"])
@login_required
@analyst_required
def agent_resume_redirect():
    return agent_resume()

@app.route("/add_incident", methods=["POST"])
@login_required
@analyst_required
def add_incident_redirect():
    return add_incident()

@app.route("/add_user", methods=["POST"])
@login_required
@admin_required
def add_user_redirect():
    return add_user()

@app.route("/delete_user", methods=["POST"])
@login_required
@admin_required
def delete_user_redirect():
    return delete_user()

@app.route("/add_token", methods=["POST"])
@login_required
@admin_required
def add_token_redirect():
    return add_token()

@app.route("/delete_token", methods=["POST"])
@login_required
@admin_required
def delete_token_redirect():
    return delete_token()

@app.route("/update_incident_tag", methods=["POST"])
@login_required
@analyst_required
def update_incident_tag_redirect():
    return update_incident_tag()

@app.route("/update_incident_assignee", methods=["POST"])
@login_required
@analyst_required
def update_incident_assignee_redirect():
    return update_incident_assignee()

@app.route("/update_incident_sla", methods=["POST"])
@login_required
@analyst_required
def update_incident_sla_redirect():
    return update_incident_sla()

@app.route("/add_ansible", methods=["POST"])
@login_required
@analyst_required
def add_ansible_redirect():
    return add_ansible()

@app.route("/save_manual", methods=["POST"])
@login_required
@analyst_required
def save_manual():
    return jsonify({"error": "Deprecated"}), 500

# =================================
# ============= MAIN ==============
# =================================

def start_server():
    app.run(host=HOST, port=PORT, ssl_context='adhoc', use_reloader=False, debug=False)

if __name__ == "__main__":
    # Not used in production (gunicorn)

    # Start main app. Do not put any code below this line
    start_server()