#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
# Installs a pinned Node.js LTS into $PREFIX after verifying its SHA-256, and
# pnpm at the version package.json pins. Used by the web test image.
set -eu

NODE_VERSION=24.22.1
PNPM_VERSION=12.4.1
PREFIX=${PREFIX:-/usr/local}

case "$(uname -m)" in
x86_64)
	ARCH=x64
	SHA=6c172a9ab6718f7b801fb5a7bd486af2ee5e32758086a04b84fcce2aa77095e6
	;;
aarch64 | arm64)
	ARCH=arm64
	SHA=dbabf7a1cbf947e6059ffad2c27b80041db97dea1e553b62afdee7f13fca336e
	;;
*)
	echo "install-node: unsupported architecture $(uname -m)" >&2
	exit 1
	;;
esac

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
name=node-v${NODE_VERSION}-linux-${ARCH}
curl -fsSL -o "$tmp/node.tar.xz" "https://nodejs.org/dist/v${NODE_VERSION}/${name}.tar.xz"
echo "${SHA}  $tmp/node.tar.xz" | sha256sum -c - >/dev/null
tar -xJf "$tmp/node.tar.xz" -C "$tmp"
cp -R "$tmp/$name/bin" "$tmp/$name/lib" "$tmp/$name/include" "$tmp/$name/share" "$PREFIX/"
npm install -g --no-fund --no-audit "pnpm@${PNPM_VERSION}" >/dev/null
node --version
pnpm --version
