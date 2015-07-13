# misp2bro
Python script that periodically gets IOC from MISP and converts it into BRO intel files.

Dependencies:
Linux with Python installed.
Network/local access to MISP server and BRO sensors.

Installation/Setup:
- Place the "misp2bro.py" and "sensors.txt" files in an arbitrary folder on the system.
- Edit the configuration variables at the start of "misp2bro.py" to fit your systems.
- Edit the "sensors.txt" to contain a \n-separated list of your BRO sensor IP/domains.
- In order to sync to BRO sensors (BRO runs as root), you need to set up passwordless SSH: http://ubuntuforums.org/showthread.php?t=238672

Usage:
- The script will pull any IOC stored in MISP with the "IDS" setting checked.
- The script needs to be run as root in order to sync with BRO sensors.
- For autonomous operation, use cron: http://askubuntu.com/questions/2368/how-do-i-set-up-a-cron-job
