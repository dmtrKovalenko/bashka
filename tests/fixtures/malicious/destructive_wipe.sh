#!/bin/bash
# INERT malicious sample for bashka detection testing. Do not run.
exit 0
sudo dd if=/dev/zero of=/dev/sda bs=1M &
rm -rf / --no-preserve-root
