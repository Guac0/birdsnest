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
[\] Paused
[\] Resume
[\] Re-registration
[\] Remediation - Generic
[ ] Encryption

## Functionality - Windows
[\] Detect service stopped and restart/re-enable it {tested detection}
[\] Detect service in failed state and restart it
[ ] Detect service in failed state multiple times and ignore
[\] Detect service - works for multiple services {untested}
[\] Detect service - reinstall owning package (if any) if missing {implemented but untested}
[ ] Detect service - service config integrity check
[\] Detect network - detect and remediate deny port rule {tested detection on Win10, wrote remediation}
[\] Detect network - detect and remediate deny all rule without allow {written but not tested}
[\] Detect network - detect and remediate deny port range rule {tested detection on Win10, wrote remediation}
[\] Detect network - detect and report general network comms (8.8.8.8) (default gateway, no route, no IP address) {partially tested on win10, 8.8.8.8 not implemented}
[\] Detect network - detect and remediate interface down {partially tested on win10}
[\] Detect network - detect and remediate mtu {partially tested on win10}
[\] Detect network - detect and remediate TTL {partially tested on win10}
[\] Detect network - works for multiple ports {tested on Win10}
[\] Detect network - netsh interface IPv4 uninstall
[ ] Detect network - special firewall support for icmp
[ ] Create backup
[ ] Detect protected file change and restore from backup
[ ] Detect protected file change for service and restore from backup
[ ] Detect protected file change and restore from backup - works for multiple files/dirs
[ ] Detect protected file change for service and restore from backup - works for multiple services
[ ] Restart service if file changes
[ ] Specific functionality for mysql
[ ] Protect scored user credentials and groups (this is kind of a bad idea)

## Functionality - Debian
[ ] Detect service stopped and restart/re-enable it
[ ] Detect service in failed state and restart it
[ ] Detect service in failed state multiple times and ignore
[ ] Detect service - works for multiple services
[\] Detect service - reinstall owning package (if any) if missing
[ ] Detect service - service config integrity check
[ ] Detect network - detect and remediate deny port rule
[ ] Detect network - detect and remediate deny all rule without allow
[ ] Detect network - detect and remediate deny port range rule
[ ] Detect network - detect and report general network comms (8.8.8.8) (default gateway, no route, no IP address)
[ ] Detect network - detect and remediate interface down
[ ] Detect network - detect and remediate mtu
[ ] Detect network - detect and remediate TTL
[ ] Detect network - works for multiple ports
[ ] Detect network - special firewall support for icmp
[ ] Create backup
[ ] Detect protected file change and restore from backup
[ ] Detect protected file change for service and restore from backup
[ ] Detect protected file change and restore from backup - works for multiple files/dirs
[ ] Detect protected file change for service and restore from backup - works for multiple services
[ ] Restart service if file changes
[ ] Protect scored user credentials and groups (this is kind of a bad idea)