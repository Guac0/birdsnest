# Endpoints and support functions for agent interaction

from flask import request, jsonify
import subprocess
import time
import os

from models import (
db,
Agent, Message, Incident, AuthToken, WebUser, AnsibleResult, AnsibleVars,
AuthConfig, AuthConfigGlobal, AuthRecord, WebhookQueue, AnsibleQueue
)
from shared import (
setup_logging, User, CONFIG, HOST, PORT, PUBLIC_URL, LOGFILE, STALE_TIME, DEFAULT_WEBHOOK_SLEEP_TIME,
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
from modules.generic_agent import beacon_generic

logger = setup_logging("web")

def beacon_owlet():
    data = request.json

    oldStatus = data.get("oldStatus",False) # Client old status. ex: false if client has detected malicious activity or has had an internal error, true if nothing has been detected
    newStatus = data.get("newStatus",False) # Client new status. Always TRUE if oldStatus is TRUE. Otherwise, serves as an indicator if the issue in oldStatus has been automatically remediated successfully.
    message = data.get("message","") # Custom string message. Used for incident descriptions.
    #owlet only
    timestamp = data.get("timestamp",0) # Special - OWLET usage only. Represents timestamp of the analyzed event in epoch time.
    user = data.get("user","")
    srcip = data.get("srcip","")
    login_type = data.get("login_type","")
    successful = data.get("successful",False)
    
    returnMsg, returnCode, registered, agent_id, current_time = beacon_generic("/agent/beacon/owlet")
    if returnCode != 200:
        return returnMsg, returnCode
    
    # update messages table
    try:
        message_id = hash_id(current_time, agent_id)
        new_message = Message(
            message_id = message_id,
            timestamp=current_time,
            agent_id=agent_id,
            oldStatus=oldStatus,
            newStatus=newStatus,
            message=message
        )
        db.session.add(new_message)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"/beacon_owlet - Failed to create message for agent {agent_id}: {e}")
        # Not returning an error, as this is secondary / recoverable (hopefully...)

    doIncident = True

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

    # Trigger Incident if Status Change is Critical
    if oldStatus == False:
        if doIncident:
            incident_data = {
                "timestamp": current_time,
                "agent_id": agent_id,
                "oldStatus": oldStatus,
                "newStatus": newStatus,
                "message": message,
                "sla": 0
            }
            create_incident(incident_data)

    return "ok", 200

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

# Also used for frontend btw
def get_global_config():
    logger.info(f"/list_authconfigglobal - Successful connection from {request.remote_addr}.")
    configs = AuthConfigGlobal.query.all()
    return jsonify({c.key: c.value for c in configs})
