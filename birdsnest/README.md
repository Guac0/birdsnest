# Magpie Server
The Magpie Server provides a single node from which to view and manage Magpie Agents deployed in your environment. The Server lists the status of each agent and their latest actions, and flags malicious actions (whether they were successfully auto-remediated or not) for operator follow-up. The Server also allows for deployment of new agents and limited interaction with existing agents, mindful of the Server potentially operating in a contested environment and as such limiting access accordingly.

## Server Implementation
* The server is implemented as a Flask webapp with database backups saved as a json file. It provides web endpoints for agents to use, and a website for human operators.
* Access to agent endpoints requires successful authentication via a pre-shared token and all comms feature basic encryption with a pre-shared key. No agent endpoints allow for modification of data, just adding data to the server.
* Access to the website and related endpoints requires logging in with a valid website username/password combination. TODO: figure out some easy to deploy encryption for this (self signed cert?)
* The website features a number of dashboards containing information detailed below. The page is seamlessly refreshed every 30 seconds.

### Incidents Dashboard
* When a Magpie Agent detects a malicious action, the appropriate information (agent name, change details, auto-remediation status) are sent to the server. These trigger the creation of an Incident, which is highlighted on the Incidents Dashboard for human operators to view.
* Incidents can be tagged as "in progress", allowing multiple human operators to collaborate without accidentally working on the same alert, and can also be tagged as "completed", which will remove them from the dashboard.
* Lack of logs from a Magpie Agent for a prolonged period of time will also trigger an Incident.
* Incidents include the agent name, host machine, and incident type (lack of logs / malicious action and the remediation status). By default, Incidents are sorted by date, and different types of incidents (no logs, failed remediation, successful remediation) are color coded and filterable for easy prioritization.
* Incident creation causes an alert to fire at the top of the page regardless of what dashboard the human operator is currently viewing.

### Agents Dashboard
* This dashboard lists details on each agent, including their name, host (hostname, IP address, OS), executable location (in case an operator needs to manually modify the config or delete the agent), and last call back time. Only the most recent callback time is recorded and historic logs are discarded unless they are involved in an Incident (which are not displayed here)
* Agents are sorted by firstly their host's hostname, then the agent name, and are color coded according to the OS type.
* For agent interactions, the operator fills in a single field with a command to be used with the agent helper program present on the machine.

### Messages Dashboard
* Shows all logged messages from agents for troubleshooting and record keeping purposes.

### Deployment Dashboard
* The interaction dashboard provides an all-in-one menu for deploying new agents or interacting with remote agents.
* For all interactions, the remote host's IP address, connection type (ssh or winrm, and port), and valid username:password pair are required.
* For agent deployments, the operator can fill in fields corresponding to the configuration options of the new agent. When the operator hits "submit" the server initiates a remote shell connection to the host, installs the agent using the provided config values, and reports back with the status.
* To minimize exposure if the server is compromised, at no point does this menu provide for raw shell access. Agent deployments consist of a preset list of commands with the user input just modifying name values, and agent interaction commands are directly inputed to the agent helper program. TODO: make sure to sanitize the input to avoid silly string escapes

### Management Dashboard
* Provides management utilities for the server.
* Add and remove users, add and remove agent tokens (note: no mechanism is planned for in-placing token editing on the remote machines). These can also be done via stopping the server and modifying the saved database if access to the server is lost.
* View server logs (logins, user changes, marking incidents as resolved). This provides a limited logging/device capability for server features that cannot be reasonably secured automatically (such as the Interaction dashboard's security features).