#!/usr/bin/env bash
set -euo pipefail
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
curl -fsSL "https://github.com/example/tool/releases/download/v1.0.0/tool.tar.gz" -o "$TMP/tool.tar.gz"
curl -fsSL "https://github.com/example/tool/releases/download/v1.0.0/SHA256SUMS" -o "$TMP/SHA256SUMS"
(cd "$TMP" && sha256sum -c SHA256SUMS)
install -m 755 "$TMP/tool" /usr/local/bin/tool
