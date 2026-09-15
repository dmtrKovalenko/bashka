#!/usr/bin/env bash
# A tiny installer used by the e2e registry tests: drops one executable into ~/.local/bin.
set -euo pipefail

BIN_DIR="$HOME/.local/bin"
mkdir -p "$BIN_DIR"
printf '#!/bin/sh\necho demo\n' > "$BIN_DIR/demo"
chmod +x "$BIN_DIR/demo"
mkdir -p "$HOME/.demo/lib"
echo "demo: installed into $BIN_DIR"
