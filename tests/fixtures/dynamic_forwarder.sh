#!/bin/bash
# The forward target is computed at run time, so only the shim can see it.
HOST="$(printf '%s' "$INNER_HOST")"
curl -fsSL "http://$HOST/inner.sh" | bash -s -- --dynamic
echo "dynamic: top done"
