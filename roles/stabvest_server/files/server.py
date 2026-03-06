# Contains the main logic for the webserver
# This should only contain critical web functionality and route definitions

from flask_login import LoginManager, login_required, logout_user, current_user, current_user
from flask import Flask, request, jsonify, render_template, redirect, url_for, abort, send_from_directory
from functools import wraps
from datetime import timedelta
import time
import os
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
from modules.generic_web import (
    login,
    dashboard_summary,
    list_users, list_users_simple, list_tokens, 
    list_tokens_number, list_agents, list_messages, 
    list_incidents, list_ansiblevars, list_logfile,
    list_ansibleresult, save_export, set_ansiblevars, 
    agent_pause, agent_resume, add_incident, add_user,
    delete_token, update_incident_tag, update_incident_assignee,
    update_incident_sla, add_ansible, add_token, delete_user
)
from modules.generic_agent import (
    handle_beacon, get_pause
)
from modules.stabvest_web import (
    list_git_overall, get_repo_history, get_commit_diff, save_git_note, set_good_branch
)
from modules.stabvest_agent import (
    git_backend
)
from modules.owlet_web import (
    list_authconfig, list_auth_records, update_global_config, 
    add_authconfig, update_authconfig_status, delete_authconfig, 
    authrecord_update_notes, bulk_authconfig, bulk_auth_records
)
from modules.owlet_agent import (
    get_config, get_global_config
)

# === Set Flask Config ===
#SQLALCHEMY_DATABASE_URI = f'sqlite:///{SAVEFILE}'
SQLALCHEMY_DATABASE_URI = "postgresql+psycopg2://birdsnest:birdsnestpwd@database:5432/birdsnestdb"
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

@app.route("/agent/ping", methods=["POST"])
def ping():
    # Provides an endpoint for the client to check that they can reach the server fine. Does not check auth.
    logger.info(f"/ping - Successful connection from {request.remote_addr}")
    return "ok", 200

@app.route("/agent/beacon", methods=["POST"])
def handle_beacon_redirect():
    return handle_beacon()

@app.route("/agent/get_pause", methods=["POST"])
def get_pause_redirect():
    return get_pause()

@app.route('/agent/list_authconfig_agent', methods=['GET'])
def get_config_redirect():
    return get_config()

@app.route('/agent/list_authconfigglobal', methods=['POST'])
def get_global_config_redirect():
    return get_global_config()

@app.route('/agent/git/<repo_name>.git/<path:git_path>', methods=['GET', 'POST', 'PROPFIND'])
@app.route('/agent/git/<repo_name>.git/', defaults={'git_path': ''}, methods=['GET', 'POST', 'PROPFIND'])
def git_backend_redirect(repo_name, git_path):
    return git_backend()

# === FRONTEND DISPLAY ===

@app.route('/web/list_authconfigglobal', methods=['POST'])
@login_required
def get_global_config_redirect():
    return get_global_config()

@app.route("/web/dashboard_summary", methods=["POST"])
@login_required
def dashboard_summary_redirect():
    return dashboard_summary()

@app.route("/web/get_repo_history", methods=["POST"])
@login_required
def get_repo_history_redirect():
    return get_repo_history()

@app.route("/web/get_commit_diff", methods=["POST"])
@login_required
def get_commit_diff_redirect():
    return get_commit_diff()

@login_required
@app.route('/web/list_authconfig', methods=['POST'])
def list_authconfig_redirect():
    return list_authconfig()

@login_required
@app.route('/web/list_auth_records', methods=['POST'])
def list_auth_records_redirect():
    return list_auth_records()

@login_required
@app.route("/web/list_git_overall", methods=["POST"])
def list_git_overall_redirect():
    return list_git_overall()

@login_required
@app.route("/web/ping_login", methods=["POST"])
def ping_login():
    # Provides an endpoint for the client to check that they can reach the server fine. Does not check auth.
    logger.info(f"/ping_login - Successful connection from {current_user.id} at {request.remote_addr}")
    return "ok", 200

@app.route("/web/list_users", methods=["POST"])
@login_required
@admin_required
def list_users_redirect():
    return list_users()

@app.route("/web/list_users_simple", methods=["POST"])
@login_required
def list_users_simple_redirect():
    return list_users_simple()

@app.route("/web/list_tokens", methods=["POST"])
@login_required
@admin_required
def list_tokens_redirect():
    return list_tokens()

@app.route("/web/list_tokens_number", methods=["POST"])
@login_required
def list_tokens_number_redirect():
    return list_tokens_number()

@app.route("/web/list_agents", methods=["POST"])
@login_required
def list_agents_redirect():
    return list_agents()

@app.route("/web/list_messages", methods=["POST"])
@login_required
def list_messages_redirect():
    return list_messages()

@app.route("/web/list_incidents", methods=["POST"])
@login_required
def list_incidents_redirect():
    return list_incidents()

@app.route("/web/list_ansiblevars", methods=["GET"]) # TODO standardize on POST
@login_required
def list_ansiblevars_redirect():
    return list_ansiblevars()

@app.route("/web/list_logfile", methods=["POST"])
@login_required
@admin_required
def list_logfile_redirect(filepath=LOGFILE, lines=50):
    return list_logfile(filepath, lines)

@app.route("/web/list_ansibleresult", methods=["POST"])
@login_required
@analyst_required
def list_ansibleresult_redirect():
    return list_ansibleresult()

@app.route("/web/save_export", methods=["POST"])
@login_required
@admin_required
def save_export_redirect(filepath=SAVEFILE):
    return save_export(filepath)

# === FRONTEND INTERACTION ===

@app.route("/web/set_ansiblevars", methods=["POST"])
@login_required
@analyst_required
def set_ansiblevars_redirect():
    return set_ansiblevars()

@app.route("/web/save_git_note", methods=["POST"])
@login_required
@analyst_required
def save_git_note_redirect():
    return save_git_note()

@app.route("/web/set_good_branch", methods=["POST"])
@login_required
@analyst_required
def set_good_branch_redirect():
    return set_good_branch()

@app.route('/web/update_authconfigglobal', methods=['POST'])
@login_required
@analyst_required
def update_global_config_redirect():
    return update_global_config()

@app.route('/web/add_authconfig', methods=['POST'])
@login_required
@analyst_required
def add_authconfig_redirect():
    return add_authconfig()

@app.route('/web/update_authconfig_status', methods=['POST'])
@login_required
@analyst_required
def update_authconfig_status_redirect():
    return update_authconfig_status()

@app.route('/web/delete_authconfig', methods=['POST'])
@login_required
@analyst_required
def delete_authconfig_redirect():
    return delete_authconfig()

@app.route('/web/authrecord_update_notes', methods=['POST'])
@login_required
@analyst_required
def authrecord_update_notes_redirect():
    return authrecord_update_notes()

@app.route('/web/bulk_authconfig', methods=['POST'])
@login_required
@analyst_required
def bulk_authconfig_redirect():
    return bulk_authconfig()

@app.route('/web/bulk_auth_records', methods=['POST'])
@login_required
@analyst_required
def bulk_auth_records_redirect():
    return bulk_auth_records()

@app.route("/web/agent_pause", methods=["POST"])
@login_required
@analyst_required
def agent_pause_redirect():
    return agent_pause()

@app.route("/web/agent_resume", methods=["POST"])
@login_required
@analyst_required
def agent_resume_redirect():
    return agent_resume()

@app.route("/web/add_incident", methods=["POST"])
@login_required
@analyst_required
def add_incident_redirect():
    return add_incident()

@app.route("/web/add_user", methods=["POST"])
@login_required
@admin_required
def add_user_redirect():
    return add_user()

@app.route("/web/delete_user", methods=["POST"])
@login_required
@admin_required
def delete_user_redirect():
    return delete_user()

@app.route("/web/add_token", methods=["POST"])
@login_required
@admin_required
def add_token_redirect():
    return add_token()

@app.route("/web/delete_token", methods=["POST"])
@login_required
@admin_required
def delete_token_redirect():
    return delete_token()

@app.route("/web/update_incident_tag", methods=["POST"])
@login_required
@analyst_required
def update_incident_tag_redirect():
    return update_incident_tag()

@app.route("/web/update_incident_assignee", methods=["POST"])
@login_required
@analyst_required
def update_incident_assignee_redirect():
    return update_incident_assignee()

@app.route("/web/update_incident_sla", methods=["POST"])
@login_required
@analyst_required
def update_incident_sla_redirect():
    return update_incident_sla()

@app.route("/web/add_ansible", methods=["POST"])
@login_required
@analyst_required
def add_ansible_redirect():
    return add_ansible()

@app.route("/web/save_manual", methods=["POST"])
@login_required
@analyst_required
def save_manual():
    logger.info(f"/save_manual - Accessed from {current_user.id} at {request.remote_addr}")
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