#!/bin/bash
echo "self: layer"
HOST="$(printf '%s' "$INNER_HOST")"
curl -fsSL "http://$HOST/self_forwarder.sh" | bash
