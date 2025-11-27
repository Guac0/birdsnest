Note: \ means written but not tested, X means fully working

## Primary Application
[\] Detect OS {tested on Win10}
[\] Get system details (IP address, hostname) {tested on Win10}
[ ] Config variables
[ ] Separate threads for interaction / polling / watchdog

## Interaction
[ ] Pause
[ ] Restart
[ ] Re-register

## Network comms
[ ] Initial registration
[ ] Paused
[ ] Resume
[ ] Re-registration
[ ] Remediation - Service Stop
[ ] Remediation - Service Error 1
[ ] Remediation - Service Error Multiple
[ ] Remediation - Network Firewall
[ ] Remediation - Network Other
[ ] Remediation - File
[ ] Remediation - Service File
[ ] Encryption

## Functionality - Windows
[ ] Detect service stopped and restart/re-enable it
[ ] Detect service in failed state and restart it
[ ] Detect service in failed state multiple times and ignore
[ ] Detect service in failed state multiple times and ignore
[ ] Detect service - works for multiple services
[\] Detect network - detect and remediate deny port rule {tested detection on Win10, wrote remediation}
[\] Detect network - detect and remediate deny all rule without allow {written but not tested}
[\] Detect network - detect and remediate deny port range rule {tested detection on Win10, wrote remediation}
[ ] Detect network - detect and report general network comms (8.8.8.8)
[ ] Detect network - detect and remediate interface down
[\] Detect network - works for multiple ports {tested on Win10}
[ ] Create backup
[ ] Detect protected file change and restore from backup
[ ] Detect protected file change for service and restore from backup
[ ] Detect protected file change and restore from backup - works for multiple files/dirs
[ ] Detect protected file change for service and restore from backup - works for multiple services
[ ] Restart service if file changes
[ ] Specific functionality for mysql

## Functionality - Debian
[ ] Detect service stopped and restart/re-enable it
[ ] Detect service in failed state and restart it
[ ] Detect service in failed state multiple times and ignore
[ ] Detect service in failed state multiple times and ignore
[ ] Detect service - works for multiple services
[ ] Detect network - detect and remediate deny port rule
[ ] Detect network - detect and remediate deny all rule without allow
[ ] Detect network - detect and remediate deny port range rule
[ ] Detect network - detect and report general network comms (8.8.8.8)
[ ] Detect network - detect and remediate interface down
[ ] Detect network - works for multiple ports
[ ] Create backup
[ ] Detect protected file change and restore from backup
[ ] Detect protected file change for service and restore from backup
[ ] Detect protected file change and restore from backup - works for multiple files/dirs
[ ] Detect protected file change for service and restore from backup - works for multiple services
[ ] Restart service if file changes