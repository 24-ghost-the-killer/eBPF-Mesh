#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
# Installs a pinned Node.js LTS into its own directory ($NODE_DIR, default
# /opt/node) after verifying its SHA-256, plus pnpm at the version
# package.json pins, and links node/npm/npx/pnpm into $PREFIX/bin. Never
# mixes files with another Node installation (CI runners ship one in
# /usr/local). Used by the web test image and CI.
set -eu

NODE_VERSION=24.22.1
PNPM_VERSION=12.4.1
PREFIX=${PREFIX:-/usr/local}
NODE_DIR=${NODE_DIR:-/opt/node}

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
mkdir "$tmp/node"
tar -xJf "$tmp/node.tar.xz" -C "$tmp/node" --strip-components=1
rm -rf "$NODE_DIR"
mkdir -p "$(dirname "$NODE_DIR")" "$PREFIX/bin"
mv "$tmp/node" "$NODE_DIR"
# Use exactly this Node and npm from here on.
PATH="$NODE_DIR/bin:$PATH"
"$NODE_DIR/bin/npm" install -g --prefix "$NODE_DIR" --no-fund --no-audit "pnpm@${PNPM_VERSION}" >/dev/null
for b in node npm npx pnpm; do ln -sf "$NODE_DIR/bin/$b" "$PREFIX/bin/$b"; done
"$PREFIX/bin/node" --version
"$PREFIX/bin/pnpm" --version
