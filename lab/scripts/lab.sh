#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Drives the anycast lab. Runs inside the test image (make lab-up / lab-test /
# lab-down start it with the host's Docker socket, host network and PID
# namespace, and the repository mounted at the same path as on the host, so
# containerlab's bind mounts resolve on the host).
#
#   lab.sh up      build, generate state, deploy, initialise NATS/ClickHouse
#   lab.sh test    up + acceptance test (+ down unless KEEP=1)
#   lab.sh down    destroy the lab
set -euo pipefail
LAB="$(cd "$(dirname "$0")/.." && pwd)"
REPO="$(cd "$LAB/.." && pwd)"
TARGET=${CARGO_TARGET_DIR:-$REPO/target}
TOPO="$LAB/topology.clab.yml"
export AGENT="$TARGET/debug/sentinel-agent" WORKER="$TARGET/debug/sentinel-worker"
export RENDER="$REPO/deploy/nats/render-config.py"
cd "$REPO"

dexec() { local n=$1; shift; docker exec "clab-sentinel-$n" "$@"; }

files() {
	make -s build >/dev/null
	make -s build/tests/xdp_pass.o >/dev/null
	rm -rf build/lab && mkdir -p build/lab/bin
	for b in sentinel-agent sentinel-api sentinel-worker sentinel-gen sentinelctl; do
		cp "$TARGET/debug/$b" build/lab/bin/
	done
	cp build/ebpf/xdp_main.o build/tests/xdp_pass.o deploy/health/sentinel-health.sh build/lab/
	echo "binaries and XDP objects in build/lab"
}

image() {
	rm -rf build/lab-image && mkdir -p build/lab-image
	cp lab/Dockerfile deploy/docker/install-nats.sh build/lab-image/
	docker build -q -t sentinel-lab:latest build/lab-image >/dev/null
	docker image inspect clickhouse/clickhouse-server:25.8.33.6 >/dev/null 2>&1 ||
		docker pull -q clickhouse/clickhouse-server:25.8.33.6 >/dev/null
	echo "images ready"
}

wait_cmd() { # wait_cmd <seconds> <description> cmd...
	local t=$1 what=$2
	shift 2
	for _ in $(seq $((t * 2))); do "$@" >/dev/null 2>&1 && return 0; sleep 0.5; done
	echo "timed out waiting for $what" >&2
	return 1
}

init_services() {
	local admin=("nats" "--server" "tls://172.31.250.10:4222" "--tlsca" "/lab/state/nats/ca.pem"
		"--nkey" "/lab/state/nats/admin.nk")
	wait_cmd 60 "NATS" dexec nats "${admin[@]}" server check connection
	for b in tenants services rules platform keys; do
		dexec nats "${admin[@]}" kv add "$b" --history 5 >/dev/null 2>&1 || true
	done
	wait_cmd 120 "ClickHouse" dexec clickhouse clickhouse-client -q "SELECT 1"
	dexec clickhouse sh -c 'clickhouse-client --multiquery < /migrations/0001_flows.sql'
	docker exec -i clab-sentinel-clickhouse clickhouse-client --multiquery <lab/state/clickhouse-users.sql
	wait_cmd 180 "the API" curl -sf http://172.31.250.13:8080/api/v1/status
	echo "NATS buckets, ClickHouse schema and users, API ready"
}

up() {
	files
	image
	"$LAB/scripts/setup.sh"
	containerlab deploy --reconfigure -t "$TOPO" >/dev/null
	init_services
	echo "lab up: containerlab inspect -t $TOPO"
}

down() {
	containerlab destroy --cleanup -t "$TOPO" >/dev/null 2>&1 || true
	echo "lab down"
}

case "${1:-}" in
files) files ;;
image) image ;;
up) up ;;
down) down ;;
test)
	up
	rc=0
	"$LAB/scripts/acceptance.sh" || rc=$?
	if [ "${KEEP:-0}" != 1 ]; then down; else echo "KEEP=1: lab left running"; fi
	exit $rc
	;;
*)
	echo "usage: lab.sh up|test|down|files|image" >&2
	exit 2
	;;
esac
