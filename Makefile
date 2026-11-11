# SPDX-License-Identifier: MIT OR Apache-2.0
# Sentinel-Edge top-level build.
#
#   make                    build the XDP object (Linux) and the Rust workspace
#   make test               fmt + clippy + Rust unit tests (any OS)
#   sudo make test-bpf      BPF_PROG_TEST_RUN parser tests (Linux, root)
#   sudo make test-integration  veth/netns end-to-end test (Linux, root)
#   make test-web           web app: API client drift, typecheck, Vitest, build
#   sudo make test-e2e      Playwright onboarding/isolation tests against the lab
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
AGENT      := $(TARGET_DIR)/debug/sentinel-agent
API        := $(TARGET_DIR)/debug/sentinel-api
WORKER     := $(TARGET_DIR)/debug/sentinel-worker
PASS_OBJ   := $(BUILD)/tests/xdp_pass.o
TEST_XDP   := $(BUILD)/tests/test_xdp
UNAME_S    := $(shell uname -s)

DOCKER_BASE  ?= sentinel-dev
DOCKER_IMAGE ?= sentinel-web
# Linux node_modules and .next live in volumes, not in the (macOS) checkout.
DOCKER_VOLS   = -v "$(CURDIR)":/src \
	-v sentinel-cargo:/usr/local/cargo/registry \
	-v sentinel-target:/target -e CARGO_TARGET_DIR=/target \
	-v sentinel-nm-root:/src/node_modules -v sentinel-nm-web:/src/web/node_modules \
	-v sentinel-nm-e2e:/src/tests/e2e/node_modules -v sentinel-next:/src/web/.next \
	-v sentinel-pnpm:/pnpm-store -v sentinel-playwright:/ms-playwright \
	-e PNPM_STORE_DIR=/pnpm-store -e E2E_ARTIFACTS=/src/build/e2e-artifacts
DOCKER_RUN    = docker run --rm --privileged $(DOCKER_VOLS) $(DOCKER_IMAGE)

.PHONY: all build bpf rust test lint test-api test-bpf test-integration test-all \
	web-install test-web test-e2e docker-image docker-test docker-shell lab-up clean help

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

# API integration tests against a throwaway PostgreSQL (initdb with a unix
# socket in a temp dir: bind mounts may not support sockets; as root the
# cluster runs as nobody).
test-api:
	@dir=$$(mktemp -d /tmp/sentinel-pg.XXXXXX) && url=$$(tests/api/pg.sh start "$$dir") && \
	  SENTINEL_TEST_PG="$$url" $(CARGO) test -p sentinel-api --test api -- --ignored --test-threads 4; \
	  rc=$$?; tests/api/pg.sh stop "$$dir"; rm -rf "$$dir"; exit $$rc

$(TEST_XDP): tests/bpf/test_xdp.c tests/bpf/policy_tests.c tests/bpf/tunnel_tests.c tests/bpf/sample_tests.c tests/bpf/harness.h tests/bpf/cases.h tests/common/pktbuild.h ebpf/include/abi.h ebpf/src/cookie.h
	@mkdir -p $(@D)
	$(CC) -O2 -g -std=gnu11 -Wall -Wextra -Werror $(filter %.c,$^) -o $@ $$(pkg-config --cflags --libs libbpf)

test-bpf: bpf $(TEST_XDP)
	./$(TEST_XDP) $(BPF_OBJ)

$(PASS_OBJ): tests/integration/xdp_pass.c
	@mkdir -p $(@D)
	clang -target bpf -O2 -g -Wall -Werror -I/usr/include/$$(uname -m)-linux-gnu -c $< -o $@

INTEGRATION_TESTS := veth_counts tunnel policy_live synflood agent_kv decisions api_e2e

# Does not build the Rust binaries: under sudo, cargo is usually not on PATH.
test-integration: bpf $(PASS_OBJ)
	@for b in "$(CTL)" "$(GEN)" "$(AGENT)" "$(API)" "$(WORKER)"; do test -x "$$b" || { echo "missing $$b: run 'make rust' first (as your normal user)"; exit 1; }; done
	@set -e; for t in $(INTEGRATION_TESTS); do \
		echo "# integration: $$t"; \
		CTL="$(abspath $(CTL))" GEN="$(abspath $(GEN))" AGENT="$(abspath $(AGENT))" \
		API="$(abspath $(API))" WORKER="$(abspath $(WORKER))" PGSH="$(abspath tests/api/pg.sh)" \
		RENDER="$(abspath deploy/nats/render-config.py)" BPF_OBJ="$(abspath $(BPF_OBJ))" \
		PASS_OBJ="$(abspath $(PASS_OBJ))" tests/integration/$$t.sh; \
	done

web-install:
	pnpm install --frozen-lockfile $(if $(PNPM_STORE_DIR),--store-dir $(PNPM_STORE_DIR))

# Web app: generated API client matches docs/openapi.json, types, Vitest, build.
test-web: web-install
	pnpm --filter web check
	pnpm --filter e2e exec tsc --noEmit -p .
	pnpm --filter web build

# Playwright against the full lab (root: namespaces, XDP). Needs node + pnpm.
test-e2e: bpf $(PASS_OBJ)
	@for b in "$(CTL)" "$(GEN)" "$(AGENT)" "$(API)" "$(WORKER)"; do test -x "$$b" || { echo "missing $$b: run 'make rust' first (as your normal user)"; exit 1; }; done
	CTL="$(abspath $(CTL))" GEN="$(abspath $(GEN))" AGENT="$(abspath $(AGENT))" \
	API="$(abspath $(API))" WORKER="$(abspath $(WORKER))" PGSH="$(abspath tests/api/pg.sh)" \
	RENDER="$(abspath deploy/nats/render-config.py)" BPF_OBJ="$(abspath $(BPF_OBJ))" \
	PASS_OBJ="$(abspath $(PASS_OBJ))" tests/integration/portal_e2e.sh

# Everything, in order. Must run as root on Linux (used by docker-test).
test-all: build test test-api test-bpf test-integration test-web test-e2e

docker-image:
	docker build -q -t $(DOCKER_BASE) -f deploy/docker/Dockerfile.dev deploy/docker
	docker build -q -t $(DOCKER_IMAGE) --build-arg BASE=$(DOCKER_BASE) -f deploy/docker/Dockerfile.web deploy/docker

docker-test: docker-image
	$(DOCKER_RUN) make test-all

docker-shell: docker-image
	docker run --rm -it --privileged $(DOCKER_VOLS) $(DOCKER_IMAGE) bash

lab-up:
	@echo "lab-up: the containerlab anycast lab arrives in phase 8"; exit 1

clean:
	$(MAKE) -C ebpf clean
	rm -rf $(BUILD)
	$(CARGO) clean

help:
	@sed -n '2,14p' Makefile
