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
PINNED_RELEASE_TAG="v0.10.0"
SHA256_X86_64_UNKNOWN_LINUX_GNU="bb66502f413f01bd0cc2e8bcae904a5e20f8ebe5fa9d300597444c4218b9f983"
SHA256_AARCH64_UNKNOWN_LINUX_GNU="29578d5df68cb8521a901145abf7f050492691d2fb1bb7d266ad9f4d6f33ca54"
SHA256_X86_64_UNKNOWN_LINUX_MUSL="5f9742759a6d8581de2c34d9424af162c87e42de0357e0a46e7ae36f1bfcf019"
SHA256_AARCH64_UNKNOWN_LINUX_MUSL="74e0d5cbd3822e7a522cde71c59d360ac25ebbf26b665f086b23f423aebb88c0"
SHA256_AARCH64_LINUX_ANDROID="d49a43d102ac0c4d19293f585261ca49f058f2f98c7677fbe8b722438c7e92d4"
SHA256_X86_64_APPLE_DARWIN="8cc3036869bb8bc9a3e5ec0441ea00178c7b03620a7fe018f9fbaf8a05ec20a2"
SHA256_AARCH64_APPLE_DARWIN="6d126a6acd7b6403af7c1efcdc3ea77731f4d60d1c00496e809021df4ba3edfc"

info() { printf '\033[1;34m%s\033[0m\n' "$*"; }
fail() { printf '\033[1;31merror: %s\033[0m\n' "$*" >&2; exit 1; }

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

# `sha256sum -c` on Linux, `shasum -a 256 -c` on mac
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
