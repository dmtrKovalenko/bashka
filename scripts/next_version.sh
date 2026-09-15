#!/usr/bin/env bash
# Prints the next release version: the highest `v*` tag with its minor bumped and patch reset.
# With no tags yet, the version in Cargo.toml is used as-is.
set -euo pipefail

latest="$(git tag -l 'v*' --sort=-v:refname | head -n 1)"
if [ -z "$latest" ]; then
    next="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)"
else
    IFS=. read -r major minor _ <<<"${latest#v}"
    next="$major.$((minor + 1)).0"
fi
echo "$next"
if [ -n "${GITHUB_OUTPUT:-}" ]; then
    {
        echo "version=$next"
        echo "tag=v$next"
    } >>"$GITHUB_OUTPUT"
fi
