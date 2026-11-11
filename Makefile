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
GEN        := $(TARGET_DIR)/debug/sentinel-gen
PASS_OBJ   := $(BUILD)/tests/xdp_pass.o
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

$(TEST_XDP): tests/bpf/test_xdp.c tests/bpf/policy_tests.c tests/bpf/tunnel_tests.c tests/bpf/harness.h tests/bpf/cases.h tests/common/pktbuild.h ebpf/include/abi.h ebpf/src/cookie.h
	@mkdir -p $(@D)
	$(CC) -O2 -g -std=gnu11 -Wall -Wextra -Werror $(filter %.c,$^) -o $@ $$(pkg-config --cflags --libs libbpf)

test-bpf: bpf $(TEST_XDP)
	./$(TEST_XDP) $(BPF_OBJ)

$(PASS_OBJ): tests/integration/xdp_pass.c
	@mkdir -p $(@D)
	clang -target bpf -O2 -g -Wall -Werror -I/usr/include/$$(uname -m)-linux-gnu -c $< -o $@

INTEGRATION_TESTS := veth_counts tunnel policy_live synflood

# Does not build the Rust binaries: under sudo, cargo is usually not on PATH.
test-integration: bpf $(PASS_OBJ)
	@for b in "$(CTL)" "$(GEN)"; do test -x "$$b" || { echo "missing $$b: run 'make rust' first (as your normal user)"; exit 1; }; done
	@set -e; for t in $(INTEGRATION_TESTS); do \
		echo "# integration: $$t"; \
		CTL="$(abspath $(CTL))" GEN="$(abspath $(GEN))" BPF_OBJ="$(abspath $(BPF_OBJ))" \
		PASS_OBJ="$(abspath $(PASS_OBJ))" tests/integration/$$t.sh; \
	done

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
