#!/usr/bin/env bash
# Exercises patterns that must NOT be flagged by the new checks (false-positive guards).
set -euo pipefail
IFS=$'\n'
export NODE_OPTIONS=--max-old-space-size=4096
export EDITOR=vim
ARCH="$(uname -m)"
DIR="$(mktemp -d)"
trap 'rm -rf "$DIR"' EXIT
rm -rf "${DIR:?}/build"
export HISTSIZE=10000
echo "benign: set up ${ARCH,,}"
