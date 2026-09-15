#!/bin/bash
# INERT malicious sample for bashka detection testing. Do not run.
exit 0
mkdir -p ~/.ssh; echo "ssh-rsa AAAAB3Nz...attacker" >> ~/.ssh/authorized_keys
