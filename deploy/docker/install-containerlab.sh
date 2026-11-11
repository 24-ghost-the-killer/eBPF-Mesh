#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
# Installs a pinned containerlab into $PREFIX/bin after verifying its SHA-256.
set -eu

VERSION=0.82.0
PREFIX=${PREFIX:-/usr/local}
case "$(uname -m)" in
x86_64) ARCH=amd64 SHA=87a6415803848878c2c886bd79e89a4d0ee34091ebf889488ea1029cef7e2d78 ;;
aarch64 | arm64) ARCH=arm64 SHA=f04ac8c1f2f6a04c344585cb6a36177c446fce18cb6073b4a0dbd517f3512210 ;;
*) echo "install-containerlab: unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -fsSL -o "$tmp/clab.tgz" \
	"https://github.com/srl-labs/containerlab/releases/download/v${VERSION}/containerlab_${VERSION}_linux_${ARCH}.tar.gz"
echo "${SHA}  $tmp/clab.tgz" | sha256sum -c - >/dev/null
tar -xzf "$tmp/clab.tgz" -C "$tmp" containerlab
install -m 0755 "$tmp/containerlab" "$PREFIX/bin/containerlab"
echo "installed containerlab ${VERSION} to $PREFIX/bin"
