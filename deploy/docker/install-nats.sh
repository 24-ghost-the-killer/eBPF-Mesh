#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
# Installs pinned nats-server and nats (CLI) binaries into $PREFIX/bin after
# verifying their SHA-256. Used by the dev image and CI.
set -eu

NATS_SERVER_VERSION=2.15.2
NATS_CLI_VERSION=0.5.1
PREFIX=${PREFIX:-/usr/local}

case "$(uname -m)" in
x86_64)
	ARCH=amd64
	SERVER_SHA=67cb8e10bc6f0c4b47f75a728529a20953dbae2a4f9a4a52ae8517d65ae303ff
	CLI_SHA=f8a3e106deebed7afe736b7090359bda3aa62a04b310440bedc1d11a93c0ab4f
	;;
aarch64 | arm64)
	ARCH=arm64
	SERVER_SHA=bc2c788dcbf2849af749564e06a0d48c19bced851f2d68a2e21c54d078949b28
	CLI_SHA=91c661f1173ee9bfe07514eef55a29d25ac7757a0868c179e825eba976073adc
	;;
*)
	echo "install-nats: unsupported architecture $(uname -m)" >&2
	exit 1
	;;
esac

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

srv=nats-server-v${NATS_SERVER_VERSION}-linux-${ARCH}
curl -fsSL -o "$tmp/srv.tgz" \
	"https://github.com/nats-io/nats-server/releases/download/v${NATS_SERVER_VERSION}/${srv}.tar.gz"
echo "${SERVER_SHA}  $tmp/srv.tgz" | sha256sum -c - >/dev/null
tar -xzf "$tmp/srv.tgz" -C "$tmp"
install -m 0755 "$tmp/${srv}/nats-server" "$PREFIX/bin/nats-server"

cli=nats-${NATS_CLI_VERSION}-linux-${ARCH}
curl -fsSL -o "$tmp/cli.zip" \
	"https://github.com/nats-io/natscli/releases/download/v${NATS_CLI_VERSION}/${cli}.zip"
echo "${CLI_SHA}  $tmp/cli.zip" | sha256sum -c - >/dev/null
python3 -c 'import sys, zipfile; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])' "$tmp/cli.zip" "$tmp"
install -m 0755 "$tmp/${cli}/nats" "$PREFIX/bin/nats"

echo "installed nats-server ${NATS_SERVER_VERSION} and nats ${NATS_CLI_VERSION} to $PREFIX/bin"
