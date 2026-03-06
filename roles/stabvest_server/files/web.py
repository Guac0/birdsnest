# Endpoints and support functions for the web frontend
from flask_login import current_app, LoginManager, login_user, login_required, logout_user, current_user, UserMixin, current_user
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, abort, send_from_directory, session
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta
import time
import os
from collections import deque
from urllib.parse import urlparse, unquote_plus
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
import subprocess
from flask_session import Session

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

logger = setup_logging("web")

#######################################
# === BASIC WEBSITE FUNCTIONALITY === #
#######################################

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

#######################################
# ======== Frontend Display ========= #
#######################################

def dashboard_summary():
    try:
        now = int(time.time())
        one_hour_ago = now - 900 # 3600 seconds = 1 hour (your code had 900)

        # Execution logic: Wrap subqueries to ensure they return lists
        # .all() returns a list of Row objects which work like tuples
        auth_config_raw = db.session.query(AuthConfig.entity_type, func.count(AuthConfig.id)).group_by(AuthConfig.entity_type).all()
        auth_record_raw = db.session.query(AuthRecord.login_type, func.count(AuthRecord.id)).group_by(AuthRecord.login_type).all()
        user_roles_raw = db.session.query(WebUser.role, func.count(WebUser.role)).group_by(WebUser.role).all()

        stats = {
            "agents": {
                "total": Agent.query.count() or 0,
                "active": Agent.query.filter_by(lastStatus=True).count() or 0,
                "stale": Agent.query.filter_by(stale=True).count() or 0,
                "paused": Agent.query.filter(Agent.pausedUntil != "0").count() or 0
            },
            "webhooks": {
                "queue_count": WebhookQueue.query.count() or 0,
                "ansible_count": AnsibleQueue.query.count() or 0
            },
            "auth_globals": {str(c.key): bool(c.value) for c in AuthConfigGlobal.query.all()},
            "auth_configs": {str(t): count for t, count in auth_config_raw},
            "auth_records": {
                "total": AuthRecord.query.count() or 0,
                "by_type": {str(t): count for t, count in auth_record_raw},
                "recent_failed": AuthRecord.query.filter(AuthRecord.successful == False, AuthRecord.timestamp >= one_hour_ago).count() or 0,
                "recent_success": AuthRecord.query.filter(AuthRecord.successful == True, AuthRecord.timestamp >= one_hour_ago).count() or 0
            },
            "incidents": {
                "total": Incident.query.count() or 0,
                "new": Incident.query.filter_by(tag="New").count() or 0,
                "active": Incident.query.filter_by(tag="Active").count() or 0,
                "closed": Incident.query.filter_by(tag="Closed").count() or 0
            },
            "messages": {
                "total": Message.query.count(),
                "recent": Message.query.filter(Message.timestamp >= one_hour_ago).count()
            },
            "users": {
                "total": WebUser.query.count() or 0,
                "roles": {str(r): count for r, count in user_roles_raw}
            },
            # Hardcode these to 0 if the tables don't exist yet to prevent Frontend 'undefined' errors
            "tokens": AuthToken.query.count() if 'AuthToken' in globals() else 0
        }

        # Debug print to terminal (Optional - remove for production)
        # print(f"DEBUG: Returning Stats Keys: {stats.keys()}")

        logger.info(f"/dashboard_summary - Successful connection from {current_user.id} at {request.remote_addr}")
        return jsonify(stats)

    except Exception as e:
        # This is critical: if this returns a 500, the frontend 'data' variable becomes undefined
        logger.error(f"/dashboard_summary Error: {str(e)}")
        return jsonify({"error": "Internal Server Error", "details": str(e)}), 500
    
def get_repo_history():
    data = request.json
    repo_path = os.path.join(current_app.root_path, 'repos', data.get("repo_name"))
    try:
        # Use a unique delimiter ( is the ASCII Record Separator) to prevent parser breaks
        # We use --topo-order to ensure a readable chronological history
        fmt = "%H|%at|%s|%D|%N"
        cmd = ["log", "--all", f"--pretty=format:{fmt}", "--name-status", "--topo-order"]
        result = run_git(cmd, cwd=repo_path)
        
        history = []
        # Split by the Record Separator instead of just newlines
        blocks = result.stdout.split('')
        
        for block in blocks:
            if not block.strip(): continue
            lines = block.strip().split('\n')
            header = lines[0].split('|')
            
            if len(header) >= 4:
                h, t, s, d = header[0], header[1], header[2], header[3]
                n = header[4] if len(header) > 4 else ""
                branch = "good" if "good" in d else ("bad" if "bad" in d else "")
                
                commit_item = {
                    "hash": h, 
                    "time": datetime.fromtimestamp(int(t)).strftime('%Y-%m-%d %H:%M:%S'),
                    "name": s, "branch": branch, "notes": n.strip(), "changes": []
                }
                
                # Parse the name-status lines that follow the header in this block
                for line in lines[1:]:
                    p = line.split('\t')
                    if len(p) == 2:
                        commit_item["changes"].append({"type": p[0], "file": p[1]})
                history.append(commit_item)
        
        logger.info(f"/get_repo_history - Successful connection from {current_user.id} at {request.remote_addr}")
        return jsonify(history), 200
    except Exception as e:
        logger.warning(f"/get_repo_history - Failed connection from {current_user.id} at {request.remote_addr}. Git error: {str(e)}")
        return jsonify({"error": str(e)}), 500

def get_commit_diff():
    data = request.json
    repo_path = os.path.join(current_app.root_path, 'repos', data.get("repo_name"))
    # Diff current commit against the tip of 'good'
    cmd = ["diff", "good", data.get("hash")]
    try:
        result = run_git(cmd, cwd=repo_path)
        logger.info(f"/get_commit_diff - Successful connection from {current_user.id} at {request.remote_addr}")
        return jsonify({"diff": result.stdout}), 200
    except Exception as E:
        logger.warning(f"/get_commit_diff - Failed connection from {current_user.id} at {request.remote_addr}. Git error: {str(E)}")

def list_authconfig():
    logger.info(f"/list_authconfig - Successful connection from {current_user.id} at {request.remote_addr}.")
    entries = AuthConfig.query.all()
    # Return as a list of dictionaries for the frontend to map
    return jsonify([entry.to_dict() for entry in entries])

def list_auth_records():
    logger.info(f"/list_auth_records - Successful connection from {current_user.id} at {request.remote_addr}.")
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

def list_git_overall():
    try:
        returned_info = get_git_stats(db)
        logger.info(f"/list_git_overall - Successful connection from {current_user.id} at {request.remote_addr}.")
        return jsonify(returned_info), 200
    except Exception as E:
        logger.warning(f"/list_git_overall - Failed connection from {current_user.id} at {request.remote_addr}. Exception: {E}")
        return "",500

def ping_login():
    # Provides an endpoint for the client to check that they can reach the server fine. Does not check auth.
    logger.info(f"/ping_login - Successful connection from {current_user.id} at {request.remote_addr}")
    return "ok", 200

def list_users():
    try:
        logger.info(f"/list_users - Successful connection from {current_user.id} at {request.remote_addr}")
        users = WebUser.query.all()
        user_dict = {user.username: serialize_model(user) for user in users}
        return jsonify(user_dict)
    except Exception as e:
        logger.error(f"/list_users - Database or serialization error: {e}")
        return jsonify({"error": "Failed to retrieve user list"}), 500

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

def list_tokens():
    try:
        logger.info(f"/list_tokens - Successful connection from {current_user.id} at {request.remote_addr}")
        tokens = AuthToken.query.all()
        token_dict = {token.token: serialize_model(token) for token in tokens}
        return jsonify(token_dict)
    except Exception as e:
        logger.error(f"/list_tokens - Database or serialization error: {e}")
        return jsonify({"error": "Failed to retrieve token list"}), 500

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

def list_messages():
    try:

        # Join Message -> Agent
        results = (
            db.session.query(Message, Agent)
            .join(Agent, Agent.agent_id == Message.agent_id)
            .all()
        )

        message_dict = {}

        for message, agent in results:
            msg_data = serialize_model(message)

            # Add agent context
            msg_data.update({
                "agent_name": agent.agent_name,
                "agent_type": agent.agent_type,
                "hostname": agent.hostname,
                "ip": agent.ip,
            })

            message_dict[message.message_id] = msg_data

        logger.info(
            f"/list_messages - Successful connection from {current_user.id} at {request.remote_addr}"
        )
        return jsonify(message_dict)

    except Exception as e:
        logger.error(f"/list_messages - Database or serialization error: {e}")
        return jsonify({"error": "Failed to retrieve message list"}), 500

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
        
        # Assuming you have a .to_dict() method on your AnsibleResult model:
        task_data = taskResult_obj.to_dict() 
        
        logger.info(f"/list_ansibleresult - Successful connection from {current_user.id} at {request.remote_addr} for taskID {taskID}")
        return jsonify(task_data), 200
        
    except Exception as e:
        logger.error(f"/list_ansibleresult - Database or serialization error: {e}")
        return jsonify({"error": "Failed to retrieve result details"}), 

#######################################
# ====== Frontend Interaction ======= #
#######################################

def save_git_note():
    data = request.json
    repo_path = os.path.join(current_app.root_path, 'repos', data.get("repo_name"))
    
    # Minimal change: Ensure git identity is set so the note commit can be created
    run_git(["config", "user.name", "Dashboard-Operator"], cwd=repo_path)
    run_git(["config", "user.email", f"operator@server.local"], cwd=repo_path)
    
    cmd = ["notes", "add", "-f", "-m", data.get("note"), data.get("hash")]
    result = run_git(cmd, cwd=repo_path)
    
    if result.returncode == 0:
        logger.info(f"/save_git_note - Successful connection from {current_user.id} at {request.remote_addr}")
        return jsonify({"status": "success"}), 200
    logger.warning(f"/save_git_note - Failed connection from {current_user.id} at {request.remote_addr}. Failed to execute git: {result.stderr}")
    return jsonify({"error": result.stderr}), 500

def set_good_branch():
    data = request.json
    repo_path = os.path.join(current_app.root_path, 'repos', data.get("repo_name"))
    target_hash = data.get("hash")
    
    try:
        # 1. Ensure we are on the good branch
        for branch in ["good","bad"]:
            run_git(["checkout", branch], cwd=repo_path)
            # 2. Extract the state of the target commit into the current index/worktree
            run_git(["checkout", target_hash, "--", "."], cwd=repo_path)
            # 3. Create the RESTORE commit
            run_git(["commit", "-m", f"RESTORE to {target_hash[:8]}"], cwd=repo_path)
            # 4. Point 'bad' to match the new 'good' state so they are synchronized
            #run_git(["update-ref", "refs/heads/bad", "refs/heads/good"], cwd=repo_path)
        
        logger.info(f"/set_good_branch - Successful connection from {current_user.id} at {request.remote_addr}")
        return jsonify({"status": "success"}), 200
    except Exception as e:
        logger.info(f"/set_good_branch - Successful connection from {current_user.id} at {request.remote_addr}. Failed to execute git: {str(e)}")
        return jsonify({"error": str(e)}), 500

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
    logger.info(f"/update_global_config - Successful connection from {current_user.id} at {request.remote_addr}. Config change: {key}:{config.value}")
    return jsonify({"status": "success", "key": key, "new_value": config.value})

def add_authconfig():
    data = request.get_json()
    val = data.get('entity_value', '').strip()
    e_type = data.get('entity_type') # 'IP' or 'USER'
    disp = data.get('disposition')   # 'LEGITIMATE' or 'MALICIOUS'

    if not val or not e_type or not disp:
        return jsonify({"status": "error", "message": "Missing fields"}), 400

    # Prevent duplicates
    if AuthConfig.query.filter_by(entity_value=val).first():
        logger.info(f"/add_authconfig - Successful connection from {current_user.id} at {request.remote_addr}. New val already exists: {val}, e_type: {e_type}, disp: {disp}")
        return jsonify({"status": "error", "message": "Entry already exists"}), 409

    new_entry = AuthConfig(entity_value=val, entity_type=e_type, disposition=disp)
    db.session.add(new_entry)
    db.session.commit()
    logger.info(f"/add_authconfig - Successful connection from {current_user.id} at {request.remote_addr}. New val: {val}, e_type: {e_type}, disp: {disp}")
    return jsonify({"status": "success", "id": new_entry.id})

def update_authconfig_status():
    data = request.get_json()
    entry = AuthConfig.query.get(data.get('id'))
    if not entry:
        logger.warning(f"/update_authconfig_status - Failed connection from {current_user.id} at {request.remote_addr}. No value with id {data.get('id')} found")
        return jsonify({"status": "error", "message": "Not found"}), 404
    
    # Toggle logic
    entry.disposition = "MALICIOUS" if entry.disposition == "LEGITIMATE" else "LEGITIMATE"
    db.session.commit()
    logger.info(f"/update_authconfig_status - Successful connection from {current_user.id} at {request.remote_addr}. Entity: {entry.entity_value}, disposition: {entry.disposition}")
    return jsonify({"status": "success", "new_disposition": entry.disposition})

def delete_authconfig():
    data = request.get_json()
    entry_id = data.get('id')
    entry = AuthConfig.query.get(entry_id)
    
    if entry:
        logger.info(f"/delete_authconfig - Successful connection from {current_user.id} at {request.remote_addr}. Deleting entry {entry.entity_value}")
        db.session.delete(entry)
        db.session.commit()
        return jsonify({"status": "success"})
    logger.warning(f"/delete_authconfig - Failed connection from {current_user.id} at {request.remote_addr}. Entry with id {data.get('id')} not found.")
    return jsonify({"status": "error", "message": "Entry not found"}), 404

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

def bulk_authconfig():
    data = request.get_json()
    action = data.get('action') # 'import' or 'export'
    
    if action == 'export':
        entries = AuthConfig.query.all()
        logger.info(f"/bulk_authconfig - Successful connection from {current_user.id} at {request.remote_addr}. Exporting config.")
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
        logger.info(f"/bulk_authconfig - Successful connection from {current_user.id} at {request.remote_addr}. Importing config of size {added_count}.")
        return jsonify({"status": "success", "added": added_count})

def bulk_auth_records():
    data = request.get_json()
    action = data.get('action') # 'import' or 'export'
    
    if action == 'export':
        records = AuthRecord.query.all()
        logger.info(f"/bulk_authconfig - Successful connection from {current_user.id} at {request.remote_addr}. Exporting records.")
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
        logger.info(f"/bulk_authconfig - Successful connection from {current_user.id} at {request.remote_addr}. Importing records of size {added_count}.")
        return jsonify({"status": "success", "added": added_count})
    
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

def agent_resume():
    data = request.json
    agent_id = data.get("agent_id")
    logger.info(f"/agent_resume - {data}")
    if not all([agent_id]):
        logger.warning(f"/agent_resume - Failed connection from {current_user.id} at {request.remote_addr} - missing data. Full details: {[agent_id]}")
        return "Missing data", 400
    agent = Agent.query.filter_by(agent_id=agent_id).first()
    if not agent:
        logger.warning(f"/agent_resume - Failed connection from {current_user.id} at {request.remote_addr} - bad agent_id value, agent_id does not exist. Full details: {[agent_id]}")
        return f"Agent with specified ID {agent_id} does not exist", 400
    try:
        logger.info(f"/agent_resume - 1")
        pausedUntilInt = int(agent.pausedUntil)
        logger.info(f"/agent_resume - ")
        if (pausedUntilInt == 0) or (pausedUntilInt == 1):
            return "Agent is already in ACTIVE state", 400
        logger.info(f"/agent_resume - 3")
        agent.pausedUntil = "1"
        logger.info(f"/agent_resume - 4")
        db.session.commit()
        logger.info(f"/agent_resume - 5")
        logger.info(f"/agent_resume - Successful connection from {current_user.id} at {request.remote_addr}. Resuming agent {agent_id}.")
        return jsonify({"status": "ok"})
    except Exception as e:
        db.session.rollback()
        logger.error(f"/agent_resume - Database error: {e}")
        return jsonify({"error": f"Database error: {e}"}), 500
    
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
    
    #logger.warning(f"/add_ansible - Successful connection from {current_user.id} at {request.remote_addr}. Waiting for ansible_queue_cond. Full details: {[ansible_folder,ansible_playbook,ansible_inventory,dest_ip,extra_vars]}")
    
    # Instead of counting records for a taskID, we'll let the DB handle it
    new_task = AnsibleQueue(
        ansible_folder=ansible_folder,
        ansible_playbook=ansible_playbook,
        ansible_inventory=ansible_inventory,
        dest_ip=dest_ip,
        ansible_venv=ansible_venv,
        extra_vars=extra_vars
    )
    
    db.session.add(new_task)
    db.session.commit()
    
    # We use the auto-increment ID as the taskID
    taskID = new_task.id
    
    logger.info(f"/add_ansible - Task {taskID} queued via DB for IP {dest_ip}")
    return jsonify({"status": "ok", "task": taskID}), 200