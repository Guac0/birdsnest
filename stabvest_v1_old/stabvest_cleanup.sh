#!/bin/bash

: '
Name: StabVest_cleanup.sh
Author: Guac0
Shoot me a message if you yoink stuff from this, I like seeing my stuff used :D
'

#Options
name="man-database"
servicepath="/etc/systemd/system/$name.service"
setuppath="/bin/$name-helper"
binarypath="/bin/$name-database"
backupdir="/usr/share/fonts/stab-mono/"

# check for root and exit if not found
if  [ "$EUID" -ne 0 ];
then
    echo "User is not root. Skill issue."
    exit 1
fi

#delete service
systemctl stop $(basename $servicepath)
rm -rf $servicepath
systemctl daemon-reload

#delete scripts
rm -rf $setuppath
rm -rf $binarypath

# delete backups
rm -rf $backupdir