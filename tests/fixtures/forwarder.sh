#!/bin/bash
# pyenv.run-style bootstrap: the real payload is one layer down, hidden in a function.
set -e

index_main() {
  echo "forwarder: bootstrapping"
  curl -s -S -L "$INNER_URL" | bash -s -- --from-forwarder
}

index_main
