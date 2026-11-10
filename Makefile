# SPDX-License-Identifier: MIT OR Apache-2.0
# Sentinel-Edge top-level build.
#
#   make                    build the XDP object (Linux) and the Rust workspace
#   make test               fmt + clippy + Rust unit tests (any OS)
#   sudo make test-bpf      BPF_PROG_TEST_RUN parser tests (Linux, root)
#   sudo make test-integration  veth/netns end-to-end test (Linux, root)
#   make docker-test        everything above inside a privileged container
#                           (use this on macOS)
#
# The repo path may contain spaces: only relative paths are used in targets.

CARGO      ?= cargo
TARGET_DIR ?= $(or $(CARGO_TARGET_DIR),target)
BUILD      := build
BPF_OBJ    := $(BUILD)/ebpf/xdp_main.o
CTL        := $(TARGET_DIR)/debug/sentinelctl
TEST_XDP   := $(BUILD)/tests/test_xdp
UNAME_S    := $(shell uname -s)

DOCKER_IMAGE ?= sentinel-dev
DOCKER_RUN    = docker run --rm --privileged \
	-v "$(CURDIR)":/src \
	-v sentinel-cargo:/usr/local/cargo/registry \
	-v sentinel-target:/target -e CARGO_TARGET_DIR=/target \
	$(DOCKER_IMAGE)

.PHONY: all build bpf rust test lint test-bpf test-integration test-all \
	docker-image docker-test docker-shell lab-up clean help

all: build

build: bpf rust

bpf:
ifeq ($(UNAME_S),Linux)
	$(MAKE) -C ebpf
else
	@echo "bpf: skipped on $(UNAME_S); the XDP object needs Linux (try: make docker-test)"
endif

rust:
	$(CARGO) build --workspace

lint:
	$(CARGO) fmt --all --check
	$(CARGO) clippy --workspace --all-targets -- -D warnings

test: lint
	$(CARGO) test --workspace

$(TEST_XDP): tests/bpf/test_xdp.c tests/bpf/cases.h tests/common/pktbuild.h ebpf/include/abi.h
	@mkdir -p $(@D)
	$(CC) -O2 -g -std=gnu11 -Wall -Wextra -Werror $< -o $@ $$(pkg-config --cflags --libs libbpf)

test-bpf: bpf $(TEST_XDP)
	./$(TEST_XDP) $(BPF_OBJ)

# Does not build the CLI itself: under sudo, cargo is usually not on PATH.
test-integration: bpf
	@test -x "$(CTL)" || { echo "missing $(CTL): run 'make rust' first (as your normal user)"; exit 1; }
	CTL="$(abspath $(CTL))" BPF_OBJ="$(abspath $(BPF_OBJ))" tests/integration/veth_counts.sh

# Everything, in order. Must run as root on Linux (used by docker-test).
test-all: build test test-bpf test-integration

docker-image:
	docker build -q -t $(DOCKER_IMAGE) -f deploy/docker/Dockerfile.dev deploy/docker

docker-test: docker-image
	$(DOCKER_RUN) make test-all

docker-shell: docker-image
	docker run --rm -it --privileged -v "$(CURDIR)":/src \
		-v sentinel-cargo:/usr/local/cargo/registry \
		-v sentinel-target:/target -e CARGO_TARGET_DIR=/target \
		$(DOCKER_IMAGE) bash

lab-up:
	@echo "lab-up: the containerlab anycast lab arrives in phase 8"; exit 1

clean:
	$(MAKE) -C ebpf clean
	rm -rf $(BUILD)
	$(CARGO) clean

help:
	@sed -n '2,12p' Makefile
