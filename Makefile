# eBPF Mesh - top-level build and test entry points.
#
#   make                        build the XDP object, the Rust workspace and the
#                               root-only test binaries (Linux; on macOS only
#                               the Rust workspace is built)
#   make test                   unprivileged tests: host dataplane tests + cargo test
#                               (Linux and macOS)
#   sudo make test-bpf          verifier + BPF_PROG_TEST_RUN corpus (Linux, root)
#   sudo make test-integration  veth/netns end-to-end test (Linux, root)
#   make lint                   rustfmt --check + clippy -D warnings
#   make docker-test            everything above in a privileged Linux container
#
# Run `make` as your user before the sudo targets: they only depend on built
# files, so root never needs cargo or rustup on its PATH.

UNAME_S := $(shell uname -s)
PLATFORM := $(shell uname -s | tr A-Z a-z)-$(shell uname -m)

# Per-platform output dirs, so a macOS checkout mounted into a Linux container
# never mixes host and container artefacts.
BUILD            ?= build/$(PLATFORM)
CARGO            ?= cargo
CARGO_TARGET_DIR ?= target/$(PLATFORM)
export CARGO_TARGET_DIR

OBJ := $(BUILD)/em_xdp.bpf.o
CTL := $(CARGO_TARGET_DIR)/release/meshctl

HOST_CC     ?= cc
TEST_CFLAGS := -std=gnu11 -O1 -g -Wall -Wextra -Werror -Wno-missing-field-initializers -Wno-unknown-pragmas \
	-I ebpf/src -I tests/common
SAN_FLAGS   := -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer

RUST_SRCS  := Cargo.toml Cargo.lock $(shell find userspace -name '*.rs' -o -name Cargo.toml)
EBPF_SRCS  := $(wildcard ebpf/src/*.c ebpf/src/*.h)
TEST_HDRS  := $(wildcard tests/common/*.h) $(wildcard ebpf/src/*.h)

.PHONY: all ebpf userspace test test-host test-rust test-bpf test-integration \
	lint fmt clean docker-image docker-test docker-shell

ifeq ($(UNAME_S),Linux)
all: ebpf userspace $(BUILD)/tests/test_xdp
else
all: userspace
	@echo "note: the XDP object and root-only tests build on Linux only;"
	@echo "      use 'make docker-test' or a Linux VM (docs/running.md)."
endif

ebpf: $(OBJ)

$(OBJ): $(EBPF_SRCS) ebpf/Makefile
	$(MAKE) -C ebpf OUT=$(abspath $(BUILD))

userspace: $(CTL)

$(CTL): $(RUST_SRCS)
	$(CARGO) build --release --workspace --locked

# ---------------- unprivileged tests ----------------

test: test-host test-rust

$(BUILD)/tests/parser_host: tests/bpf/parser_host.c $(TEST_HDRS)
	@mkdir -p $(@D)
	$(HOST_CC) $(TEST_CFLAGS) $(SAN_FLAGS) $< -o $@

test-host: $(BUILD)/tests/parser_host
	./$(BUILD)/tests/parser_host

test-rust:
	$(CARGO) test --workspace --locked

lint:
	$(CARGO) fmt --all -- --check
	$(CARGO) clippy --workspace --all-targets --locked -- -D warnings

fmt:
	$(CARGO) fmt --all

# ---------------- root-only tests (Linux, BPF-capable kernel) ----------------

$(BUILD)/tests/test_xdp: tests/bpf/test_xdp.c $(TEST_HDRS)
	@mkdir -p $(@D)
	$(HOST_CC) $(TEST_CFLAGS) $< -o $@ -lbpf -lelf -lz

test-bpf: $(OBJ) $(BUILD)/tests/test_xdp
	./$(BUILD)/tests/test_xdp $(OBJ)

test-integration: $(OBJ) $(CTL)
	CTL=$(abspath $(CTL)) OBJ=$(abspath $(OBJ)) tests/integration/veth.sh

# ---------------- containerised Linux toolchain ----------------

DOCKER       ?= docker
DOCKER_IMAGE ?= ebpf-mesh-dev
DOCKER_RUN   := $(DOCKER) run --rm --privileged \
	-v "$(CURDIR)":/src -w /src \
	-v ebpf-mesh-cargo:/usr/local/cargo/registry \
	$(DOCKER_IMAGE)

docker-image:
	$(DOCKER) build -t $(DOCKER_IMAGE) -f scripts/docker/Dockerfile.dev scripts/docker

docker-test: docker-image
	$(DOCKER_RUN) sh -c 'make all lint test test-bpf test-integration'

docker-shell: docker-image
	$(DOCKER) run --rm -it --privileged -v "$(CURDIR)":/src -w /src \
		-v ebpf-mesh-cargo:/usr/local/cargo/registry $(DOCKER_IMAGE) bash

clean:
	rm -rf build target
