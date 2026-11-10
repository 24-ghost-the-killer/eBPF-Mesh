#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Prepare a Debian 12+/Ubuntu 22.04+ VM (e.g. on Proxmox) to build and test
# eBPF Mesh: compilers, libbpf, iproute2 and the pinned Rust toolchain.
#
#   scripts/setup-dev-vm.sh          run as your normal user (uses sudo for apt)
#
# Idempotent. Does not change network configuration, does not attach anything.
set -euo pipefail

if [[ $EUID -eq 0 ]]; then
	echo "run as your normal user; the script calls sudo where needed" >&2
	exit 1
fi
if ! command -v apt-get >/dev/null; then
	echo "this script supports Debian/Ubuntu (apt) only" >&2
	exit 1
fi

KVER=$(uname -r)
KMAJ=${KVER%%.*}
KMIN=$(echo "$KVER" | cut -d. -f2)
if (( KMAJ < 6 || (KMAJ == 6 && KMIN < 1) )); then
	echo "warning: kernel $KVER is older than 6.1; BPF tests may fail" >&2
fi

sudo apt-get update
sudo apt-get install -y --no-install-recommends \
	ca-certificates curl git make gcc libc6-dev \
	clang llvm libbpf-dev libelf-dev zlib1g-dev pkg-config linux-libc-dev \
	iproute2 iputils-ping procps python3

# Rust: rustup reads rust-toolchain.toml in the repo and installs the pinned
# toolchain on first use.
if ! command -v rustup >/dev/null; then
	curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain none
	# shellcheck disable=SC1091
	source "$HOME/.cargo/env"
fi

mountpoint -q /sys/fs/bpf || echo "note: /sys/fs/bpf is not mounted; the tests mount it when run as root"

cat <<EOF

ready. kernel $KVER, $(clang --version | head -1)
next, from the repo root:
  make                         # build (as this user)
  make test                    # unprivileged tests
  sudo make test-bpf           # verifier + BPF_PROG_TEST_RUN
  sudo make test-integration   # veth/netns end-to-end
EOF
