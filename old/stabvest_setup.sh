#!/bin/bash

: '
Name: StabVest_Setup.sh
Author: Guac0 / Andrew Niebur
Shoot me a message if you yoink stuff from this, I like seeing my stuff used :D
'

# Make sure these have the same values as the ansible deploy script uses!
# You should change these from the defaults since this script repo is probably public and red team can see...
deploydir="/bin"
deployservicename="man-database"
timestomp_start_year=2018
timestomp_end_year=2023

# check for root and exit if not found
if  [ "$EUID" -ne 0 ];
then
    echo "User is not root. Skill issue."
    exit 1
fi

generate_random_date() {
    # Generate a random year between given values
    local year=$(printf "%02d" $(( RANDOM % ($timestomp_end_year - $timestomp_start_year + 1) + $timestomp_start_year )))
    local year_short=$(printf "%02d" $(( year % 100 )))  # Get last two digits for YY
    local century=$(printf "%02d" $(( year / 100 )))    # Get first two digits for CC
    # Generate a random month (01 to 12)
    local month=$(printf "%02d" $(( RANDOM % 12 + 1 ))) 
    # Generate a random day (01 to 28)
    local day=$(printf "%02d" $(( RANDOM % 28 + 1 ))) 
    # Generate a random hour (00 to 23), minute (00 to 59), and second (00 to 59)
    local hour=$(printf "%02d" $(( RANDOM % 24 )))
    local minute=$(printf "%02d" $(( RANDOM % 60 )))
    local second=$(printf "%02d" $(( RANDOM % 60 )))
    local random_date="${year_short}${month}${day}${hour}${minute}.${second}"
    echo "$random_date"
}

if [ "$1" = "local" ]; then
    mv stabvest.sh "$deploydir/$deployservicename"
    chown root:root "$deploydir/$deployservicename"
    chmod 750 "$deploydir/$deployservicename"
    random_date=$(generate_random_date)
    touch -t "$random_date" "$deploydir/$deployservicename"
    mv stabvest_setup.sh "$deploydir/$deployservicename-helper"
    chown root:root "$deploydir/$deployservicename-helper"
    chmod 750 "$deploydir/$deployservicename-helper"
    random_date=$(generate_random_date)
    touch -t "$random_date" "$deploydir/$deployservicename-helper"
fi

# Create the systemd service file
cat << EOF > /etc/systemd/system/$deployservicename.service
[Unit]
Description=Helper daemon
After=network.target

[Service]
Type=simple
ExecStart=$deploydir/$deployservicename
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
EOF

# Timestomp the service file
random_date=$(generate_random_date)
touch -t "$random_date" /etc/systemd/system/$deployservicename.service

# Reload systemd daemon
systemctl daemon-reload

# Enable the service
systemctl enable $deployservicename.service

# Start the service
systemctl start $deployservicename.service
