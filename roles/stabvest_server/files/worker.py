# Implements the background worker due periodic polling tasks
# Note: initializes a Flask app for code similarity, but does not expose any routes

import threading
import time
import sdnotify
from datetime import datetime
import math
import urllib.request
import urllib.error
import json
import subprocess
from flask import Flask

from shared import (
setup_logging, User, CONFIG, HOST, PORT, PUBLIC_URL, LOGFILE, STALE_TIME, DEFAULT_WEBHOOK_SLEEP_TIME,
MAX_WEBHOOK_MSG_PER_MINUTE, WEBHOOK_URL, INITIAL_AGENT_AUTH_TOKENS, INITIAL_WEBGUI_USERS, AUTHCONFIG_STRICT_IP,
AUTHCONFIG_STRICT_USER, AUTHCONFIG_CREATE_INCIDENT, AUTHCONFIG_LOG_ATTEMPT_SUCCESSFUL, CREATE_TEST_DATA, SECRET_KEY,
GIT_PROJECT_ROOT, GIT_BACKEND
)
from models import (
db,
Agent, Message, Incident, AuthToken, WebUser, AnsibleResult, AnsibleVars,
AuthConfig, AuthConfigGlobal, AuthRecord, WebhookQueue, AnsibleQueue
)
from utilities import (
insert_initial_data, create_db_tables, serialize_model, is_safe_path,
get_random_time_offset_epoch, add_test_data_agents, add_test_data_messages, add_test_data_incidents,
add_test_data_incidents_custom, add_test_data_auth_records, add_test_data_auth_config,
run_git, hash_id, create_incident, clean_and_join_path, get_git_stats, find_incident, find_incident_db
)

#SQLALCHEMY_DATABASE_URI = f'sqlite:///save.db'
SQLALCHEMY_DATABASE_URI = "postgresql+psycopg2://birdsnest:birdsnestpwd@database:5432/birdsnestdb"
app = Flask(__name__)
app.config['SECRET_KEY'] = CONFIG["SECRET_KEY"]
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False # Silence the deprecation warning
db.init_app(app)

def webhook_main():
    """Dedicated rate-limited sender thread with dynamic rate limiting."""
    if not WEBHOOK_URL:
        return

    last_60_seconds = []
    
    while True:
        sleep_time = 0
        with app.app_context():
            # Find the oldest unprocessed task
            task = WebhookQueue.query.order_by(WebhookQueue.created_at.asc()).first()
            
            if not task:
                time.sleep(2) # Wait a bit before checking for new tasks again
                continue

            # Fetch incident data needed for the webhook
            incident = Incident.query.get(task.incident_id)
            if not incident:
                # Cleanup if incident was deleted
                db.session.delete(task)
                db.session.commit()
                continue

            # Prepare the payload like your original code did
            incident_payload = {
                "timestamp": incident.timestamp,
                "agent_id": incident.agent_id,
                "oldStatus": incident.oldStatus,
                "tag": incident.tag,
                "newStatus": incident.newStatus,
                "message": incident.message,
                "assignee": incident.assignee,
                "sla": incident.sla
            }

            # Send the webhook
            resp, body = discord_webhook(task.incident_id, incident_payload)

            try:
                if resp.code == 429:
                    # Rate limited by Discord
                    bodyDict = json.loads(body)
                    sleep_time = float(bodyDict["retry_after"])

                    logger.warning(f"/webhook_main - Retry_After succeeded, re-queued incident and sleeping for {sleep_time}.")
                else:
                    db.session.delete(task)
                    db.session.commit()

                    # Maybe rate-limit headers present
                    remaining = resp.getheader("X-RateLimit-Remaining")
                    reset_after = resp.getheader("X-RateLimit-Reset-After")

                    if remaining is not None and reset_after is not None:
                        try:
                            remaining_int = int(remaining)
                            reset_after_float = float(reset_after)

                            if remaining_int == 0:
                                sleep_time = reset_after_float
                                logger.info(f"/webhook_main - incident {incident.incident_id}: 0 responses remaining, sleeping for {sleep_time}.")
                        except ValueError:
                            sleep_time = DEFAULT_WEBHOOK_SLEEP_TIME
                            logger.warning(f"/webhook_main - incident {incident.incident_id}: failed to parse headers, sleeping {sleep_time}.")
                    else:
                        sleep_time = DEFAULT_WEBHOOK_SLEEP_TIME
                        logger.warning(f"/webhook_main - Missing rate limit headers, sleeping {sleep_time}.")

            except Exception as e:
                sleep_time = DEFAULT_WEBHOOK_SLEEP_TIME
                db.session.delete(task)
                db.session.commit()
                logger.error(f"/webhook_main - caught unknown error from discord_webhook, deleting incident {task.incident_id} from webhook queue - {e}.")

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
        #time.sleep(max(sleep_time,0.2))
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
        elif (incident["message"].lower().split(' ')[0]  == "file"):
            color = "b11226"

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
    logger.info("periodic_stale() started.")
    
    while True:
        # Sleep at the START of the loop to allow the system to initialize
        time.sleep(interval)

        with app.app_context():
            try:
                agents_records = Agent.query.all()
                agents_updated = False

                for agent in agents_records:
                    if agent.agent_name == "custom":
                        continue
                        
                    time_since_seen = time.time() - agent.lastSeenTime
                    
                    # --- Scenario A: Recovering from Stale ---
                    if agent.stale and time_since_seen < STALE_TIME:
                        agent.stale = False
                        agents_updated = True

                        criteria = {
                            "agent_id": agent.agent_id,
                            "tag": ('New', 'Active'),
                            "message": f"Agent - Agent {agent.agent_name} on {agent.hostname} moved to Stale state. Last seen {datetime.fromtimestamp(agent.lastSeenTime).strftime('%Y-%m-%d_%H-%M-%S')}."
                        }

                        incident_id = find_incident_db(criteria, newest=True)
                        if incident_id:
                            incident = db.session.get(Incident, incident_id)
                            if incident:
                                incident.tag = "Closed"
                                logger.info(f"periodic_stale(): Stale incident {incident_id} CLOSED for {agent.agent_id}.")
                        
                        logger.info(f"periodic_stale(): Agent {agent.agent_id} recovered.")

                    # --- Scenario B: Becoming Stale ---
                    elif not agent.stale and time_since_seen > STALE_TIME:
                        agent.stale = True
                        agents_updated = True
                        
                        incident_data = {
                            "timestamp": time.time(),
                            "agent_id": agent.agent_id,
                            "oldStatus": agent.lastStatus,
                            "newStatus": False,
                            "message": f"Agent - Agent {agent.agent_name} on {agent.hostname} moved to Stale state. Last seen {datetime.fromtimestamp(agent.lastSeenTime).strftime('%Y-%m-%d_%H-%M-%S')}.",
                            "sla": 0
                        }
                        # This will now trigger the DB-backed WebhookQueue
                        create_incident(incident_data)
                        logger.info(f"periodic_stale(): Agent {agent.agent_id} moved to stale state.")

                if agents_updated:
                    db.session.commit()
                    logger.info("periodic_stale(): Database updated.")
                else:
                    logger.info("periodic_stale(): No changes.")

            except Exception as e:
                db.session.rollback()
                logger.error(f"periodic_stale(): Loop encountered error: {e}")
            
            #finally:
                # Explicitly remove the session to prevent connection leaking
                # in long-running background processes.
                #db.session.remove()

def periodic_ansible(interval=5):
    """Polls DB for Ansible tasks, executes them, and logs results."""
    logger.info("periodic_ansible(): started.")
    
    while True:
        with app.app_context():
            # 1. Fetch the oldest queued task
            item = AnsibleQueue.query.order_by(AnsibleQueue.created_at.asc()).first()
            
            if not item:
                time.sleep(interval)
                continue

            # 2. Build the command (Using data from the DB record)
            if item.ansible_venv:
                command = f"source {item.ansible_venv} && cd {item.ansible_folder} && ansible-playbook {item.ansible_playbook} -i {item.ansible_inventory} -l {item.dest_ip} -t stabvest_client_auto {item.extra_vars}"
            else:
                command = f"cd {item.ansible_folder} && ansible-playbook {item.ansible_playbook} -i {item.ansible_inventory} -l {item.dest_ip} -t stabvest_client_auto {item.extra_vars}"

            logger.info(f"periodic_ansible(): starting subprocess for task {item.id}")
            
            # 3. Execute Subprocess
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True, 
                text=True, 
                check=False
            )

            # 4. Log Result to Database
            newResult = AnsibleResult(
                task=item.id,
                returncode=result.returncode,
                result=f"STDOUT: {result.stdout.strip()} ||| STDERR: {result.stderr.strip()}"
            )
            db.session.add(newResult)
            
            # 5. REMOVE from queue and commit everything
            db.session.delete(item)
            db.session.commit()
            
            logger.info(f"periodic_ansible(): finished task {newResult.task}. Returncode: {result.returncode}")
            
        # Optional: small rest between back-to-back tasks
        time.sleep(1)

if __name__ == "__main__":
    logger = setup_logging("worker")
    logger.info("Starting background worker threads...")
    #notifier = sdnotify.SystemdNotifier()

    create_db_tables(app)

    # Start the same threads you had before
    threads = [
        threading.Thread(target=webhook_main, daemon=True),
        threading.Thread(target=periodic_stale, daemon=True),
        threading.Thread(target=periodic_ansible, daemon=True)#,
        # all in one testing only!
        #threading.Thread(target=start_server, daemon=True)
        #gunicorn --certfile=cert.pem --keyfile=key.pem --workers 4 --bind 0.0.0.0:8000 server:app 
    ]

    for t in threads:
        t.start()
    
    #notifier.notify("READY=1")
    logger.info("Started background worker threads.")

    # Keep the main process alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Worker shutting down...")