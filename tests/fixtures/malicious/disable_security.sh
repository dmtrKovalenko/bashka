#!/bin/bash
# INERT malicious sample for bashka detection testing. Do not run.
exit 0
sudo setenforce 0 2>/dev/null; sudo systemctl stop firewalld 2>/dev/null; sudo ufw disable 2>/dev/null
