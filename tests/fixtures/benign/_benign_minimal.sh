#!/usr/bin/env bash
# A well-behaved installer: strict mode, HTTPS from a known publisher, checksum, cleanup.
set -euo pipefail

INSTALL_DIR="$HOME/.local/bin"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "benign: would download"
# curl -fsSL "https://github.com/example/tool/releases/download/v1.0.0/tool.tar.gz" -o "$TMP/tool.tar.gz"
# curl -fsSL "https://github.com/example/tool/releases/download/v1.0.0/SHA256SUMS" -o "$TMP/SHA256SUMS"
# (cd "$TMP" && sha256sum -c SHA256SUMS)
mkdir -p "$INSTALL_DIR"
echo "benign: installed into $INSTALL_DIR"
