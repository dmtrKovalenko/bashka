#!/bin/sh

# This script installs the Nix package manager on your system by
# downloading a binary distribution and running its installer script
# (which in turn creates and populates /nix).

{ # Prevent execution if this script was only partially downloaded
oops() {
    echo "$0:" "$@" >&2
    exit 1
}

umask 0022

tmpDir="$(mktemp -d -t nix-binary-tarball-unpack.XXXXXXXXXX || \
          oops "Can't create temporary directory for downloading the Nix binary tarball")"
cleanup() {
    rm -rf "$tmpDir"
}
trap cleanup EXIT INT QUIT TERM

require_util() {
    command -v "$1" > /dev/null 2>&1 ||
        oops "you do not have '$1' installed, which I need to $2"
}

case "$(uname -s).$(uname -m)" in
    Linux.x86_64)
        hash=0c3960a9792331a22081c3c7a5d8465db9b17c50b3acdf18587fa4c6f2cb1158
        path=3d229fmjbbhn74zwp21z6rfx2a35ryy8/nix-2.35.2-x86_64-linux.tar.xz
        system=x86_64-linux
        ;;
    Linux.i?86)
        hash=55363adb55f1447be49298c671f5beb539526f2f3181e8e11eab669af6d5990b
        path=bzfrrx38n5qc3kj6id18zqbysk48vykz/nix-2.35.2-i686-linux.tar.xz
        system=i686-linux
        ;;
    Linux.aarch64)
        hash=4d0302a2910f5eec1c33b8deef634f04899a75737e7001ec49908d003ae5efda
        path=f8vsr7dbkb5slmwiv6s2cc5bjw73xqwn/nix-2.35.2-aarch64-linux.tar.xz
        system=aarch64-linux
        ;;
    Linux.armv6l)
        hash=2f79330820e2de68279d1c796827d4d6269396c3cbb22bacf6c238639db9b306
        path=j3i097mi5gf31qqcfimgmdqmdrncpvnc/nix-2.35.2-armv6l-linux.tar.xz
        system=armv6l-linux
        ;;
    Linux.armv7l)
        hash=e4a68bd13f20b10f67b551178116655520323f5a29a7e82a2db24a6b2a166e89
        path=jq9dyz2q83d4z6rhfgfzbaqgcar7ss82/nix-2.35.2-armv7l-linux.tar.xz
        system=armv7l-linux
        ;;
    Linux.riscv64)
        hash=98ee79540d4b9ccfe733655ea049a67af24f15860fbf92103bc1911bbd905a53
        path=1slh67389ncg34nqsz1a0ampcwzlcxq8/nix-2.35.2-riscv64-linux.tar.xz
        system=riscv64-linux
        ;;
    Darwin.x86_64)
        hash=d725518d89f3b0b8d4af702a9d38d519814014cbe125afb3ed0545c9d755f6a5
        path=q89r761wxaykz2zhb2l8j0rsljm9k9ak/nix-2.35.2-x86_64-darwin.tar.xz
        system=x86_64-darwin
        ;;
    Darwin.arm64|Darwin.aarch64)
        hash=1695c13aba5afa7c2ecd6dc4a9393f602e7bbc440ed45e81602c831546580ec3
        path=hl0qj2xiq7npi3xxk1byan3nc75kx0q1/nix-2.35.2-aarch64-darwin.tar.xz
        system=aarch64-darwin
        ;;
    FreeBSD.amd64|FreeBSD.x86_64)
        hash=e944893995e82989a13df992e6f636f1050a2498f7792f9cef3cb2e1d18ba692
        path=j9ll2y5d3mh1ichmkrfnjfrjc64z18gf/nix-2.35.2-x86_64-freebsd.tar.xz
        system=x86_64-freebsd
        ;;
    *) oops "sorry, there is no binary distribution of Nix for your platform";;
esac

# Use this command-line option to fetch the tarballs using nar-serve or Cachix
if [ "${1:-}" = "--tarball-url-prefix" ]; then
    if [ -z "${2:-}" ]; then
        oops "missing argument for --tarball-url-prefix"
    fi
    url=${2}/${path}
    shift 2
else
    url=https://releases.nixos.org/nix/nix-2.35.2/nix-2.35.2-$system.tar.xz
fi

tarball=$tmpDir/nix-2.35.2-$system.tar.xz

require_util tar "unpack the binary tarball"
if [ "$(uname -s)" != "Darwin" ]; then
    require_util xz "unpack the binary tarball"
fi

if command -v curl > /dev/null 2>&1; then
    fetch() { curl --fail -L "$1" -o "$2"; }
elif command -v wget > /dev/null 2>&1; then
    fetch() { wget "$1" -O "$2"; }
else
    oops "you don't have wget or curl installed, which I need to download the binary tarball"
fi

echo "downloading Nix 2.35.2 binary tarball for $system from '$url' to '$tmpDir'..."
fetch "$url" "$tarball" || oops "failed to download '$url'"

if command -v sha256sum > /dev/null 2>&1; then
    hash2="$(sha256sum -b "$tarball" | cut -c1-64)"
elif command -v shasum > /dev/null 2>&1; then
    hash2="$(shasum -a 256 -b "$tarball" | cut -c1-64)"
elif command -v openssl > /dev/null 2>&1; then
    hash2="$(openssl dgst -r -sha256 "$tarball" | cut -c1-64)"
else
    oops "cannot verify the SHA-256 hash of '$url'; you need one of 'shasum', 'sha256sum', or 'openssl'"
fi

if [ "$hash" != "$hash2" ]; then
    oops "SHA-256 hash mismatch in '$url'; expected $hash, got $hash2"
fi

unpack=$tmpDir/unpack
mkdir -p "$unpack"
tar -xJf "$tarball" -C "$unpack" || oops "failed to unpack '$url'"

script=$(echo "$unpack"/*/install)

[ -e "$script" ] || oops "installation script is missing from the binary tarball!"
export INVOKED_FROM_INSTALL_IN=1
"$script" "$@"

} # End of wrapping
