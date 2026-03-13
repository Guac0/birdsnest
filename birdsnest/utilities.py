# Contains various helper functions that must be referenced by multiple other files

from datetime import datetime
import re
import os
import base64
import subprocess
import platform
import time
import random
from sqlalchemy.orm import class_mapper
from werkzeug.security import generate_password_hash
from urllib.parse import urlparse, unquote_plus
import hashlib

from models import (
db,
Agent, Message, Incident, AuthToken, AuthTokenAgent, WebUser, AnsibleResult, AnsibleVars,
AuthConfig, AuthConfigGlobal, AuthRecord, WebhookQueue, AnsibleQueue
)
from shared import (
setup_logging, User, CONFIG, HOST, PORT, PUBLIC_URL, LOGFILE, STALE_TIME, DEFAULT_WEBHOOK_SLEEP_TIME,
MAX_WEBHOOK_MSG_PER_MINUTE, WEBHOOK_URL, INITIAL_AGENT_AUTH_TOKENS, INITIAL_WEBGUI_USERS, AUTHCONFIG_STRICT_IP,
AUTHCONFIG_STRICT_USER, AUTHCONFIG_CREATE_INCIDENT, AUTHCONFIG_LOG_ATTEMPT_SUCCESSFUL, CREATE_TEST_DATA, SECRET_KEY,
GIT_PROJECT_ROOT, GIT_BACKEND, DATABASE_CREDS, DATABASE_LOCATION, DATABASE_DB
)

logger = setup_logging()

##########################
# === DATABASE FUNCS === #
##########################


def insert_initial_data():
    """
    Inserts initial configuration data (auth tokens and users) into the database.
    This should only be run after the tables have been created via db.create_all().
    """
    try:
        new_agent = Agent(
            agent_id="custom",
            agent_name="custom",
            agent_type="custom",
            hostname="N/A",
            ip="255.255.255.255",
            os="N/A",
            executionUser="N/A",
            executionAdmin=True,
            lastSeenTime=0,
            lastStatus=True,
            stale=True,
            pausedUntil=0
        )
        db.session.add(new_agent)
        
        if CREATE_TEST_DATA:
            add_test_data_agents(5)
            add_test_data_messages(10)
            add_test_data_incidents_custom(5)
            add_test_data_incidents(10)
            #add_test_data_comp(0)
            #add_test_data_cmds()
            add_test_data_auth_records(20)
            add_test_data_auth_config()

        #if not db.session.get(AuthConfigGlobal,"strict_user"):
        if not db.session.execute(db.select(AuthConfigGlobal).filter_by(key="strict_user")).scalar_one_or_none():
            config = AuthConfigGlobal(key="strict_user", value=AUTHCONFIG_STRICT_USER)
            db.session.add(config)
            logger.info(f"Initialized default strict_user={AUTHCONFIG_STRICT_USER}.")
        #if not db.session.get(AuthConfigGlobal,"strict_ip"):
        if not db.session.execute(db.select(AuthConfigGlobal).filter_by(key="strict_ip")).scalar_one_or_none():
            config = AuthConfigGlobal(key="strict_ip", value=AUTHCONFIG_STRICT_IP)
            db.session.add(config)
            logger.info(f"Initialized default strict_ip={AUTHCONFIG_STRICT_IP}.")
        #if not db.session.get(AuthConfigGlobal,"create_incident"):
        if not db.session.execute(db.select(AuthConfigGlobal).filter_by(key="create_incident")).scalar_one_or_none():
            config = AuthConfigGlobal(key="create_incident", value=AUTHCONFIG_CREATE_INCIDENT)
            db.session.add(config)
            logger.info(f"Initialized default create_incident={AUTHCONFIG_CREATE_INCIDENT}.")
        #if not db.session.get(AuthConfigGlobal,"log_attempt_successful"):
        if not db.session.execute(db.select(AuthConfigGlobal).filter_by(key="log_attempt_successful")).scalar_one_or_none():
            config = AuthConfigGlobal(key="log_attempt_successful", value=AUTHCONFIG_LOG_ATTEMPT_SUCCESSFUL)
            db.session.add(config)
            logger.info(f"Initialized default log_attempt_successful={AUTHCONFIG_LOG_ATTEMPT_SUCCESSFUL}.")
            

        existing_vars = db.session.get(AnsibleVars,"main")
        if not existing_vars:
            new_ansiblevars = AnsibleVars(id="main")
            db.session.add(new_ansiblevars)
            db.session.commit()
            logger.info(f"Initialized default AnsibleVars.")
        else:
            logger.info("AnsibleVars 'main' already exists, skipping initialization.")


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

def create_db_tables(app):

    # Use the application context to ensure Flask extensions are configured
    with app.app_context():
        # This checks the database defined in SQLALCHEMY_DATABASE_URI.
        # If the tables defined in your models don't exist, it creates them.
        db.create_all()
        context = os.environ.get("APP_CONTEXT", "DEFAULT")
        if context == "WORKER":
            db_exists = WebUser.query.first()
            if not db_exists:
                insert_initial_data()
                logger.info(f"Initialized database with initial data inserted.")
            else:
                logger.info(f"Initialized database.")

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


##########################
# ===== TEST DATA ====== #
##########################


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
            os_name = possible_oses[i-1]

            # The agent_id is computed but we use a unique prefix for test data to avoid collisions
            #computed_agent_id = hash_id(f"test_agent_{i}", hostname, ip, os)
            computed_agent_id = hash_id(agent_name, hostname, ip, os)

            new_agent = Agent(
                agent_id=computed_agent_id,
                agent_name=agent_name,
                agent_type=agent_type,
                hostname=hostname,
                ip=ip,
                os=os_name,
                executionUser=random.choice(["root", "admin", ".\\administrator", "domain\\dadmin", "user"]),
                executionAdmin=random.choice([True, False]),
                lastSeenTime=time.time() - ((num - i) * 100),
                lastStatus=random.choice([True, False]),
                stale=random.choice([True, False]),
                pausedUntil=random.choice([str(0),str(0),str(1),str(time.time()),str(time.time() + 180), str(time.time() + 600)])
            )
            db.session.add(new_agent)
            new_token = AuthTokenAgent(
                agent_id=computed_agent_id,
                added_by="test data",
                token=os.urandom(6).hex()
            )
            db.session.add(new_token)
        db.session.commit()
        logger.info(f"Successfully added {num} test agents to the database.")
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to add test agent data: {e}")

def add_test_data_messages(num=15):
    try:
        all_agents = Agent.query.filter(Agent.agent_id != 'custom').all()
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
    all_agents = Agent.query.filter(Agent.agent_id != 'custom').all()
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
    all_agents = Agent.query.filter(Agent.agent_id != 'custom').all()
    for i in range(1, num + 1):
        agent_id = random.choice(all_agents).agent_id
        incident_data = {
            "timestamp": time.time() - ((num - i) * 100),
            "agent_id":agent_id,
            "oldStatus": random.choice([False,True]),
            "newStatus": random.choice([False,True]),
            "message": random.choice([
                "IR - Investigate suspicious sign-in activity on {hostname} / {ipaddress}.",
                "IR - Write report on Doubletap scheduled task.",
                "Inject - Implement HTTPS for {check} scorecheck on {hostname} / {ipaddress} by {time}.",
                "Uptime - Fix failed {check} scorecheck on {hostname} / {ipaddress}.",
                #"Server - Save Exported by User {user}",
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
        all_agents = Agent.query.filter(Agent.agent_id != 'custom').all()
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

##########################
# === MISC UTILITIES === #
##########################

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

def hash_id(*args):
    # Hash any number of args so that we have a single value to use as the id that remains unique if multiple items have similar fields. Does not need to be secure
    combined = "|".join(map(str, args))
    return hashlib.sha256(combined.encode("utf-8")).hexdigest() # hex digest returns a fixed-length 64-char string regardless of input size
    #return base64.b64encode(combined.encode("utf-8")).decode("utf-8")

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
        try:
            # Instead of a memory deque, we insert into the DB queue
            new_task = WebhookQueue(incident_id=new_incident.incident_id)
            db.session.add(new_task)
            db.session.commit()
            # No need for notify() anymore; the worker will poll the DB
        except Exception as E:
            logger.error(f"create_incident(): Could not queue webhook in DB: {E}")
    return

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
        #logger.info(f"handling repo folder {repo_folder} at {repo_path}")
        
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
                repo_path = os.path.join(GIT_PROJECT_ROOT, repo_folder)

                # 1. Get Commit Name (Subject) and Time
                # Access .stdout and strip() to get the actual string
                cp_commit = run_git(["show", "-s", "--format=%s|%at", branch], repo_path)
                commit_raw = cp_commit.stdout.strip() 
                
                if not commit_raw:
                    continue
                    
                name, timestamp = commit_raw.split('|')

                # 2. Get Diff Stats
                # Use your run_git wrapper consistently instead of mixing with check_output
                cp_diff = run_git(["diff", f"{branch}^!", "--summary"], repo_path)
                diff_output = cp_diff.stdout

                # Parse types of changes
                added = diff_output.count("create mode")
                deleted = diff_output.count("delete mode")

                # 3. Get Modified Count
                cp_total = run_git(["diff", f"{branch}^!", "--name-only"], repo_path)
                total_files = len(cp_total.stdout.splitlines())
                modified = total_files - (added + deleted)

                # Build the data point
                entry = {
                    "repo_name": repo_folder,
                    "branch": branch,
                    "agent_name": agent.agent_name if agent else "UNK",
                    "hostname": agent.hostname if agent else "UNK",
                    "ip": agent.ip if agent else "UNK",
                    "latest_commit_name": name,
                    "latest_commit_time": datetime.fromtimestamp(int(timestamp)).strftime('%Y-%m-%d %H:%M:%S'),
                    "diffs": {
                        "files_added": added,
                        "files_deleted": deleted,
                        "files_modified": modified
                    }
                }
                results.append(entry)

            except (subprocess.CalledProcessError, ValueError, AttributeError) as e:
                logger.warning(f"Failed to process branch {branch} in {repo_folder}: {e}")
                continue

    #logger.info(f"returning {results}")
    return results

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

def is_safe_path(next_url: str) -> bool:
    if not next_url:
        return False
    # percent-decoded already by Flask for request.args/form, but be safe:
    next_url = unquote_plus(next_url)
    parsed = urlparse(next_url)
    # allow only relative paths (no scheme/netloc)
    return (parsed.scheme == "" and parsed.netloc == "" and next_url.startswith("/"))
