# Stabvest Agent
The Stabvest v2 Agent provides a local agent for assessing and maintaining file integrity on a system, and communicating status updates back to a central visualizer. Each agent provides full service coverage for a core function of the system, such as a Apache2 webserver, by protecting its config files, execution binaries, service, and networking stack.

## Applications / configuration:
* Operator modifies the config section to list a series of files/directories, services, and ports to protect.
* Automated deployment helper installs the program as an always-running executable that uses a service to restart on failure
* Multiple agents may be deployed onto a single box to protect multiple services/other custom items. It is intended that each agent act as a self contained executable that protects only one designated suite (such as one for Apache2, another for mysql, etc)
* Additionally, a helper program is also provided for interactions with the Stabvest agent(s)
* Written in Python for cross-platform comaptibility

## Helper Program
* Provides a command-line utility for temporarily pausing the stabvest agent and re-registering the current state of protected items (for config changes to the core service). Full assisted agent deletion is not implemented for live deployments for security purposes.
* Written in Python for cross-platform compatibility
* Supported commands: add, pause, reregister, delete (only in testing environment; code removed from live deployment)
* Each command must be paired with the name of the agent to modify. The "add" command is used to locally register a new agent to the helper, which consists of the agent's name, service, and executable file location (not the full config details of the client). A list command is intentionally not implemented for security reasons; agents on a machine will call back their details to the central server. TODO: figure out how to protect the agent details at rest in the helper program
* The helper program does not participate in any client to server communication. However, the server may remotely interact with the helper program (through a standard shell session) to interact with individual agents.

## Main Agent Program
* Uses Python Watchdog for live protection of protected files, and polling on a protected interval to protect features that do not have live monitors (firewall rules, services)
* Checks the protected items for malicious changes - any modifications to protected files or service details will be restored from backup, and program will seek and remediate common service breaks and firewall breaks.
* Legitimate system changes can be accomplished by pausing the agent, making the changes, and re-registering the agent to register the changed files.
* In addition to protecting the uptime or existence of a service or file, the Agent can also be ran in inverted mode to keep designated malware deployment locations secured.
* The Agent provides limited auto-remediation for breaks performed due important system binaries that it relies on to function, such as re-installing iptables if it is not found or unmasking it if it has been hidden.
* The Agent performs (basic encryption, just a XOR using a pre-shared key) callbacks to the central monitoring server when important events occur - agent registration, pausing, re-registration, auto remediation successes, and auto remediation failures. A periodic callback is also implemented as a way to inform the server that the agent is still running without difficulties.
* The Agent does not expose any methods for remote interaction; all interaction with it must use a normal shell on the system to use the helper program to interact with the main agent.
* The Agent exposes the following methods for local interaction: pause (optional: specified time period, defaults to 60 seconds. A time period is mandatory to avoid forgeting to resume the agent), resume, and re-register.

### Supported File Protection Methods
* On initial run or during re-registration, the protected files/folders are zipped up to compressed zip folders, timestomped, and stored in a random location. This applies to explicitly configured protected files, as well as the configuration file for the specified protected service(s)
* Features with live protection support (files) will instantly respond to file modification by restoring the modified file(s) from the zipped backup. The appropriate service will be reloaded if necessary.

### Supported Service Protection Methods
* The Agent automatically detects if the protected service is in a "stopped" state, and will attempt to restart it and set it to auto-restart on failure
* In the event of a protected service exiting with a failure code, the Stabvest agent will attempt to restart it once (after performing emergency file/serivce/network integrity checks). If this results in another failure, the protection system de-activates until the service correctly comes online again, as this requires manual intervention to remediate.
* If the protected service is installed through a package manager, the Agent can re-install it. This is not needed for the config file and main binary as those are typically protected, but may fix missing dependencies that arise from uninstalling the full package. (Linux only)

### Supported Network Protection Methods
* The Agent provides for limited network protection for the protected service. It automatically detects and deletes any firewall rules that block traffic on the protected port(s) (TODO: add support for port ranges)
* Additionally, it provides limited automatic troubleshooting and remediation support for broader network breaks. It provides auto-remediation for the main network interface being set to the DOWN state, and offers error logging (but not automatic remediation) for breaks such as MTU changes, missing IP address assignment, missing default gateway, and overall internet connectivity (pinging 8.8.8.8).