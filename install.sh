#!/usr/bin/env bash
# Bashka own 100% safe bash installation script
# curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/dmtrKovalenko/bashka/main/install.sh | bash
set -euo pipefail

REPO="dmtrKovalenko/bashka"
APP_NAME="bashka"
INSTALL_DIR="${BASHKA_INSTALL_DIR:-$HOME/.local/bin}"
if [ -z "${BASHKA_INSTALL_DIR:-}" ] && [ -n "${TERMUX_VERSION:-}" ] && [ -n "${PREFIX:-}" ]; then
    INSTALL_DIR="$PREFIX/bin"
fi

# Pinned by CI on every release (see .github/workflows/release.yml).
PINNED_RELEASE_TAG="v0.2.0"
SHA256_X86_64_UNKNOWN_LINUX_GNU="3e8f7e9ccd1e25772a4c51a458a307824ef535ae936a2c3f49c3cd250599d03e"
SHA256_AARCH64_UNKNOWN_LINUX_GNU="4fb280ceb5e942d6e8a05e0ec8cac2611e4cd949eb6d71bf18ee07474eef23e5"
SHA256_X86_64_UNKNOWN_LINUX_MUSL="ec101f02a95fc9c2cd95efdfc8db0b2776aecc84b886e869d1c0d01900247f61"
SHA256_AARCH64_UNKNOWN_LINUX_MUSL="b4ea8177abbe7408d7745dbf04c5b371418b155a27581accd1c49d6ef7b6a0f1"
SHA256_AARCH64_LINUX_ANDROID="02ffe39990c093f9a36de88213f26bf3623be676dbab45527a44ce78fab4789d"
SHA256_X86_64_APPLE_DARWIN="ab9c7969f4594a24f3e595e1efa94b4f9091e80453a8e803699916b54450da0f"
SHA256_AARCH64_APPLE_DARWIN="082067b795f10d941603565f031402605ff4fe9fae01bf7e04f222027f821765"

info() { printf '\033[1;34m%s\033[0m\n' "$*"; }
fail() { printf '\033[1;31merror: %s\033[0m\n' "$*" >&2; exit 1; }

# Termux (Android) has its own libc; glibc systems get the dynamic build, everything else
# (Alpine, NixOS, unknown) gets the static musl one.
linux_libc() {
    if [ -n "${TERMUX_VERSION:-}" ] || [ "$(uname -o 2>/dev/null || true)" = "Android" ]; then
        echo "android"
    elif ldd --version 2>&1 | grep -qi glibc; then
        echo "gnu"
    else
        echo "musl"
    fi
}

detect_target() {
    local os arch libc
    os="$(uname -s)"
    arch="$(uname -m)"
    case "$os" in
        Linux)
            libc="$(linux_libc)"
            case "$arch:$libc" in
                x86_64:gnu) echo "x86_64-unknown-linux-gnu" ;;
                x86_64:*) echo "x86_64-unknown-linux-musl" ;;
                aarch64:android | arm64:android) echo "aarch64-linux-android" ;;
                aarch64:gnu | arm64:gnu) echo "aarch64-unknown-linux-gnu" ;;
                aarch64:* | arm64:*) echo "aarch64-unknown-linux-musl" ;;
                *) fail "unsupported architecture: $arch" ;;
            esac
            ;;
        Darwin)
            case "$arch" in
                x86_64) echo "x86_64-apple-darwin" ;;
                arm64) echo "aarch64-apple-darwin" ;;
                *) fail "unsupported architecture: $arch" ;;
            esac
            ;;
        *) fail "unsupported OS: $os (bashka runs on Linux and macOS)" ;;
    esac
}

pinned_sha() {
    case "$1" in
        x86_64-unknown-linux-gnu) echo "$SHA256_X86_64_UNKNOWN_LINUX_GNU" ;;
        aarch64-unknown-linux-gnu) echo "$SHA256_AARCH64_UNKNOWN_LINUX_GNU" ;;
        x86_64-unknown-linux-musl) echo "$SHA256_X86_64_UNKNOWN_LINUX_MUSL" ;;
        aarch64-unknown-linux-musl) echo "$SHA256_AARCH64_UNKNOWN_LINUX_MUSL" ;;
        aarch64-linux-android) echo "$SHA256_AARCH64_LINUX_ANDROID" ;;
        x86_64-apple-darwin) echo "$SHA256_X86_64_APPLE_DARWIN" ;;
        aarch64-apple-darwin) echo "$SHA256_AARCH64_APPLE_DARWIN" ;;
    esac
}

# `sha256sum -c` on Linux, `shasum -a 256 -c` on macOS.
check_sha256() {
    local file="$1" expected="$2"
    if command -v sha256sum >/dev/null 2>&1; then
        echo "$expected  $file" | sha256sum -c - >/dev/null
    elif command -v shasum >/dev/null 2>&1; then
        echo "$expected  $file" | shasum -a 256 -c - >/dev/null
    else
        fail "neither sha256sum nor shasum is available to verify the download"
    fi
}

main() {
    local target tag expected asset url
    # Not local: the EXIT trap runs after main returns and must still see it under set -u.
    target="$(detect_target)"
    tag="$PINNED_RELEASE_TAG"
    expected="$(pinned_sha "$target")"
    [ -n "$expected" ] || fail "no pinned checksum for $target in this copy of install.sh"

    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT

    asset="$APP_NAME-$target"
    url="https://github.com/$REPO/releases/download/$tag/$asset"
    info "downloading $APP_NAME $tag for $target"
    curl --proto '=https' --tlsv1.2 -fsSL -o "$tmp/$APP_NAME" "$url" \
        || fail "download failed: $url"

    info "verifying sha256"
    check_sha256 "$tmp/$APP_NAME" "$expected" || fail "checksum mismatch for $asset; refusing to install"

    mkdir -p "$INSTALL_DIR"
    install -m 755 "$tmp/$APP_NAME" "$INSTALL_DIR/$APP_NAME"
    info "installed $INSTALL_DIR/$APP_NAME ($tag)"

    case ":$PATH:" in
        *":$INSTALL_DIR:"*) ;;
        *)
            echo
            echo "$INSTALL_DIR is not on your PATH. Add it in your shell profile, e.g.:"
            echo "  export PATH=\"$INSTALL_DIR:\$PATH\""
            ;;
    esac
    echo
    echo "next time, make the bash installation safer by adding ka, e.g."
    printf '  curl -fsSL https://dmtrkovalenko.dev/install-fff-mcp.sh | bash\033[1;35mka\033[0m\n'
}

main
