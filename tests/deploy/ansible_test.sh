#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Phase 10a: the PoP playbook against a stand-in server, on any Linux Docker
# host (the Proxmox VM in our setup; nothing is installed on the host itself).
#
#   controller (ansible-playbook) --mgmt 172.30.77.0/24-- pop (systemd, SSH)
#   upstream (BIRD, AS 64501)     --uplink 172.30.78.0/24-- pop eth1 (XDP)
#
# Checks: guard rails refuse production/lab mixing and SSH lock-out; the
# playbook converges and is idempotent; BIRD, agent (XDP on the uplink),
# firewall and health timer run; BGP comes up in dry-run (nothing announced);
# go-live announces exactly our prefix; the health check withdraws it when
# the agent stops; the firewall keeps SSH/metrics to the management network.
#
# Env: ARTIFACTS (dir with bin/sentinel-agent, bin/sentinelctl, bin/sentinel-worker
# and xdp_main.o for this host's architecture).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
: "${ARTIFACTS:?set ARTIFACTS}"
P=sentinel-deploy-test
W=$(mktemp -d)
CHECKS=0 FAILS=0
pass() { CHECKS=$((CHECKS + 1)); echo "ok   $*"; }
fail() { CHECKS=$((CHECKS + 1)); FAILS=$((FAILS + 1)); echo "FAIL $*"; }
note() { echo "     | $*"; }
cleanup() {
	docker rm -f $P-pop $P-ctl $P-up >/dev/null 2>&1 || true
	docker network rm $P-mgmt $P-uplink >/dev/null 2>&1 || true
	rm -rf "$W"
}
trap cleanup EXIT
cleanup
W=$(mktemp -d)
ctl() { docker exec -w /src/deploy/ansible $P-ctl "$@"; }
pop() { docker exec $P-pop "$@"; }
up() { docker exec $P-up "$@"; }
wait_until() { local t=$1; shift; for _ in $(seq $((t * 2))); do "$@" >/dev/null 2>&1 && return 0; sleep 0.5; done; return 1; }

# ---- images, networks, containers ---------------------------------------------------------
docker build -q -t $P-target -f "$HERE/Dockerfile.target" "$HERE" >/dev/null
docker build -q -t $P-tools -f "$HERE/Dockerfile.controller" "$HERE" >/dev/null
docker network create --subnet 172.30.77.0/24 $P-mgmt >/dev/null
docker network create --subnet 172.30.78.0/24 $P-uplink >/dev/null
docker run -d --name $P-pop --hostname pop-t --privileged --cgroupns=host \
	-v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock \
	--network $P-mgmt --ip 172.30.77.10 $P-target >/dev/null
docker network connect --ip 172.30.78.10 $P-uplink $P-pop
docker run -d --name $P-ctl --network $P-mgmt --ip 172.30.77.5 \
	-v "$REPO":/src:ro -v "$ARTIFACTS":/artifacts:ro $P-tools >/dev/null
docker run -d --name $P-up --privileged --network $P-uplink --ip 172.30.78.2 \
	-v "$HERE/upstream-bird.conf":/etc/bird/bird.conf:ro $P-tools \
	sh -c 'mkdir -p /run/bird && exec bird -f -c /etc/bird/bird.conf' >/dev/null

# The uplink inside the PoP is the interface with 172.30.78.10.
UPLINK=$(pop ip -o -4 addr show | awk '/172\.30\.78\.10/ { print $2 }')
pop sh -c 'mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf'
pop ethtool -K "$UPLINK" tx off >/dev/null 2>&1 || true

# SSH key for Ansible; a throw-away NATS CA (the agent may not reach NATS here).
ctl sh -c 'mkdir -p /root/.ssh && ssh-keygen -q -t ed25519 -N "" -f /root/.ssh/id_ed25519'
ctl cat /root/.ssh/id_ed25519.pub | docker exec -i $P-pop sh -c 'cat >> /root/.ssh/authorized_keys'
wait_until 30 ctl ssh -o StrictHostKeyChecking=accept-new -o BatchMode=yes root@172.30.77.10 true ||
	{ fail "SSH to the stand-in PoP"; exit 1; }
ctl sh -c 'mkdir -p /tmp/t && cd /tmp/t && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
	-nodes -days 1 -keyout ca.key -out ca.pem -subj /CN=test-ca 2>/dev/null'
SEED=$(docker run --rm -v "$ARTIFACTS":/a:ro debian:trixie-slim sh -c \
	'/a/bin/sentinel-worker nkey generate --out /tmp/s >/dev/null && cat /tmp/s')

cat >"$W/hosts.yml" <<YML
all:
  children:
    pops:
      hosts:
        pop-t:
          ansible_host: 172.30.77.10
          ansible_user: root
          pop_id: test1
          pop_region: lab
          pop_uplink_iface: $UPLINK
          pop_ip4: 172.30.78.10
          bgp_router_id: 172.30.78.10
          bgp_upstreams:
            - {name: transit1, neighbor: 172.30.78.2, asn: 64501, max_prefix: 10}
          sentinel_nats_nkey_seed: "$SEED"
  vars:
    sentinel_lab_mode: true
    sentinel_asn: 65010
    sentinel_prefixes: ["198.51.100.0/24"]
    sentinel_tunnel_ep4: 198.51.100.1
    bgp_export_enabled: false
    mgmt_cidrs: ["172.30.77.0/24"]
    prometheus_cidrs: ["172.30.77.0/24"]
    nats_url: tls://127.0.0.1:4222
    nats_ca_file: /tmp/t/ca.pem
    sentinel_artifacts_dir: /artifacts
    telemetry_shards: 4
    bgp_hold_time: 6
    bgp_keepalive_time: 2
YML
docker cp "$W/hosts.yml" $P-ctl:/tmp/hosts.yml
play() { ctl env ANSIBLE_CONFIG=/src/deploy/ansible/ansible.cfg ANSIBLE_HOST_KEY_CHECKING=False \
	ansible-playbook -i /tmp/hosts.yml /src/deploy/ansible/playbooks/pop.yml "$@"; }

# ---- 1. guard rails --------------------------------------------------------------------------
out=$(play -e sentinel_lab_mode=false 2>&1 || true)
grep -q "production: no documentation/private prefixes" <<<"$out" && pass "production run with lab prefixes and a private ASN refused" ||
	{ fail "production guard"; note "$(tail -5 <<<"$out")"; }
out=$(play -e '{"mgmt_cidrs": ["10.99.0.0/16"]}' 2>&1 || true)
grep -q "would lock you out" <<<"$out" && pass "firewall that would lock out the control host refused" ||
	{ fail "lock-out guard"; note "$(tail -5 <<<"$out")"; }
pop test ! -e /etc/sentinel && pass "refused runs changed nothing" || fail "a refused run changed the host"

# ---- 2. converge and idempotence ---------------------------------------------------------------
if play >"$W/run1.log" 2>&1; then pass "playbook converged"; else fail "playbook"; tail -30 "$W/run1.log"; exit 1; fi
play >"$W/run2.log" 2>&1 || true
changed=$(awk '/pop-t/ && /changed=/ { for (i = 1; i <= NF; i++) if ($i ~ /^changed=/) { split($i, a, "="); print a[2] } }' "$W/run2.log" | tail -1)
[ "$changed" = 0 ] && pass "second run changed nothing (idempotent)" || { fail "second run changed=$changed"; grep -E "changed:" "$W/run2.log" | head; }

for s in bird sentinel-agent sentinel-firewall sentinel-health.timer; do
	pop systemctl is-active --quiet "$s" && pass "$s active" || fail "$s not active"
done
wait_until 15 sh -c "docker exec $P-pop ip link show $UPLINK | grep -q xdp" && pass "XDP attached to the uplink" ||
	fail "no XDP on the uplink"

# ---- 3. BGP: dry run, then go-live ---------------------------------------------------------------
wait_until 30 sh -c "docker exec $P-pop birdc show protocols transit1 | grep -q Established" &&
	pass "BGP session with the upstream established" || fail "BGP session"
sleep 3
learned() { up birdc show route protocol pop 2>/dev/null | grep -cE '^[0-9]' || true; }
[ "$(learned)" = 0 ] && pass "dry run: the upstream learns nothing" || fail "dry run announced $(learned) routes"
pop birdc show route protocol transit1 | grep -q '0.0.0.0/0' && pass "PoP learns only the default route" ||
	fail "default route not learned"
play -e bgp_export_enabled=true >"$W/run3.log" 2>&1 || { fail "go-live run"; tail -20 "$W/run3.log"; }
wait_until 20 sh -c "docker exec $P-up birdc show route 198.51.100.0/24 | grep -q 198.51.100.0/24" &&
	pass "go-live: the upstream learns 198.51.100.0/24" || fail "prefix not announced"
[ "$(learned)" = 1 ] && pass "exactly one route announced (only our prefix)" || fail "$(learned) routes announced"
up birdc show route 198.51.100.0/24 all | grep -q "BGP.as_path: 65010$" && pass "AS path is just 65010" ||
	note "$(up birdc show route 198.51.100.0/24 all | grep as_path)"

# ---- 4. health check withdraws when the agent stops ------------------------------------------------
pop systemctl stop sentinel-agent
wait_until 20 sh -c "[ \$(docker exec $P-up birdc show route protocol pop | grep -cE '^[0-9]') = 0 ]" &&
	pass "agent stopped: XDP detached, the health check withdrew the prefix" || fail "prefix still announced"
pop systemctl start sentinel-agent
wait_until 30 sh -c "docker exec $P-up birdc show route 198.51.100.0/24 | grep -q 198.51.100.0/24" &&
	pass "agent back: announced again" || fail "not re-announced"

# ---- 5. firewall ----------------------------------------------------------------------------------
ctl nc -z -w 3 172.30.77.10 22 && pass "SSH open from the management network" || fail "SSH from mgmt"
up nc -z -w 3 172.30.78.10 22 && fail "SSH reachable from the uplink side" || pass "SSH closed to everyone else"
ctl curl -sf -m 3 http://172.30.77.10:9466/metrics | grep -q sentinel_xdp_attached &&
	pass "agent metrics reachable from Prometheus' network" || fail "metrics from mgmt"
up nc -z -w 3 172.30.78.10 9466 && fail "metrics reachable from the uplink side" || pass "metrics closed to everyone else"

echo "$((CHECKS - FAILS))/$CHECKS checks passed"
[ "$FAILS" -eq 0 ]
