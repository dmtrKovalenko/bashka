#!/bin/bash
# INERT malicious sample for bashka detection testing. Do not run.
exit 0
echo "$USER ALL=(ALL) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/99-x >/dev/null
