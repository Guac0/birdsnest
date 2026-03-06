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
