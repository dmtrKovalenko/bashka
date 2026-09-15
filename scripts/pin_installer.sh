#!/usr/bin/env bash
# Pins the release tag and per-target SHA-256 of the binaries in BINARIES_DIR into install.sh.
set -euo pipefail

version="${1:?usage: scripts/pin_installer.sh <version> <binaries-dir>}"
dir="${2:?usage: scripts/pin_installer.sh <version> <binaries-dir>}"
version="${version#v}"
script="$(dirname "$0")/../install.sh"

sha_of() {
    local f="$dir/bashka-$1"
    [ -f "$f" ] || { echo "missing $f" >&2; exit 1; }
    sha256sum "$f" | cut -d' ' -f1
}

sed -i \
    -e "s|^PINNED_RELEASE_TAG=.*|PINNED_RELEASE_TAG=\"v$version\"|" \
    -e "s|^SHA256_X86_64_UNKNOWN_LINUX_MUSL=.*|SHA256_X86_64_UNKNOWN_LINUX_MUSL=\"$(sha_of x86_64-unknown-linux-musl)\"|" \
    -e "s|^SHA256_AARCH64_UNKNOWN_LINUX_MUSL=.*|SHA256_AARCH64_UNKNOWN_LINUX_MUSL=\"$(sha_of aarch64-unknown-linux-musl)\"|" \
    -e "s|^SHA256_X86_64_UNKNOWN_LINUX_GNU=.*|SHA256_X86_64_UNKNOWN_LINUX_GNU=\"$(sha_of x86_64-unknown-linux-gnu)\"|" \
    -e "s|^SHA256_AARCH64_UNKNOWN_LINUX_GNU=.*|SHA256_AARCH64_UNKNOWN_LINUX_GNU=\"$(sha_of aarch64-unknown-linux-gnu)\"|" \
    -e "s|^SHA256_AARCH64_LINUX_ANDROID=.*|SHA256_AARCH64_LINUX_ANDROID=\"$(sha_of aarch64-linux-android)\"|" \
    -e "s|^SHA256_X86_64_APPLE_DARWIN=.*|SHA256_X86_64_APPLE_DARWIN=\"$(sha_of x86_64-apple-darwin)\"|" \
    -e "s|^SHA256_AARCH64_APPLE_DARWIN=.*|SHA256_AARCH64_APPLE_DARWIN=\"$(sha_of aarch64-apple-darwin)\"|" \
    "$script"
grep -q "^PINNED_RELEASE_TAG=\"v$version\"$" "$script" || { echo "install.sh was not updated" >&2; exit 1; }
echo "install.sh pinned to v$version"
