#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# End-to-end test of the Phase 0 dataplane and meshctl on a veth pair.
#
#   root netns: em0 (10.99.0.1, fd00::1)   <-- XDP attached here
#   netns em-ns-<pid>: em1 (10.99.0.2, fd00::2) --> sends traffic to em0
#
# Lab-only addresses (10.0.0.0/8, fd00::/8); nothing leaves the veth pair.
# Requires root, iproute2, ping, python3, a bpffs, and the built artefacts
# (passed by `make test-integration` as $CTL and $OBJ).
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
CTL=${CTL:?set CTL to the meshctl binary (make test-integration does this)}
OBJ=${OBJ:?set OBJ to em_xdp.bpf.o (make test-integration does this)}
PIN_ROOT=${PIN_ROOT:-/sys/fs/bpf/ebpf-mesh-test-$$}
NS=em-ns-$$
IF=em0
PEER=em1
PASS=0
FAIL=0

mctl() { "$CTL" --pin-root "$PIN_ROOT" "$@"; }
send() { ip netns exec "$NS" python3 "$ROOT/tests/integration/send_frames.py" "$PEER" "$MAC" "$@"; }

cleanup() {
	mctl detach -i "$IF" >/dev/null 2>&1 || true
	ip link set dev "$IF" xdpgeneric off 2>/dev/null || true
	ip link set dev "$IF" xdpdrv off 2>/dev/null || true
	ip netns del "$NS" 2>/dev/null || true
	ip link del "$IF" 2>/dev/null || true
	rm -rf "$PIN_ROOT"
}
trap cleanup EXIT

check() { # description, condition (arithmetic expression)
	if (( $2 )); then
		echo "ok   - $1"
		PASS=$((PASS + 1))
	else
		echo "FAIL - $1  [$2]"
		FAIL=$((FAIL + 1))
	fi
}

stats() { mctl stats -i "$IF" --json; }
counter() { # json, name -> packets
	python3 -c 'import json,sys; print(json.loads(sys.argv[1])["counters"][sys.argv[2]]["packets"])' "$1" "$2"
}
parse_sum() { # json -> sum of parse_* packets
	python3 -c 'import json,sys; c=json.loads(sys.argv[1])["counters"]; print(sum(v["packets"] for k,v in c.items() if k.startswith("parse_")))' "$1"
}
xdp_mode() { # -> "native" | "generic" | "none" (from the kernel, not from meshctl)
	ip -j link show dev "$IF" | python3 -c '
import json,sys
x=json.load(sys.stdin)[0].get("xdp",{})
print({1:"native",2:"generic"}.get(x.get("mode"),"none"))'
}
xdp_prog_id() {
	ip -j link show dev "$IF" | python3 -c '
import json,sys
x=json.load(sys.stdin)[0].get("xdp",{})
print(x.get("prog",{}).get("id",0))'
}
ping_ok() { ip netns exec "$NS" ping -c "$1" -i 0.2 -W 1 10.99.0.1 >/dev/null 2>&1 && echo 1 || echo 0; }

mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf

ip netns add "$NS"
ip link add "$IF" type veth peer name "$PEER"
ip link set "$PEER" netns "$NS"
ip addr add 10.99.0.1/24 dev "$IF"
ip -6 addr add fd00::1/64 dev "$IF" nodad
ip link set "$IF" up
ip netns exec "$NS" ip addr add 10.99.0.2/24 dev "$PEER"
ip netns exec "$NS" ip -6 addr add fd00::2/64 dev "$PEER" nodad
ip netns exec "$NS" ip link set "$PEER" up
ip netns exec "$NS" ip link set lo up
MAC=$(cat /sys/class/net/$IF/address)

echo "# attach (native mode)"
mctl attach -i "$IF" --obj "$OBJ" --mode native
check "kernel reports native XDP on $IF" "$(xdp_mode | grep -c '^native$') == 1"
check "program and stats map are pinned" "$(ls "$PIN_ROOT/$IF" | grep -cE '^(em_xdp_main|em_stats)$') == 2"

echo "# legitimate traffic passes"
check "ping succeeds through XDP" "$(ping_ok 5) == 1"
S=$(stats)
check "ICMP echo counted (>= 5)" "$(counter "$S" l4_icmp) >= 5"
check "nothing dropped" "$(counter "$S" verdict_drop) == 0"

echo "# malformed and anomalous frames are classified, still passed"
B=$(stats)
send syn 6
send xmas 10
send tcp_trunc 7
send udp_len_bad 5
send ipv6_frag_later 3
sleep 0.3
S=$(stats)
d() { echo $(( $(counter "$S" "$1") - $(counter "$B" "$1") )); }
check "SYNs counted (6)" "$(d tcp_syn) == 6"
check "XMAS scans counted as bad TCP flags (10)" "$(d anom_tcp_bad_flags) == 10"
check "truncated TCP counted (7)" "$(d parse_err_tcp_trunc) == 7"
check "bad UDP length counted (5)" "$(d parse_err_udp_len) == 5"
check "IPv6 non-first fragments counted (3)" "$(d frag_later) == 3"
check "still nothing dropped" "$(counter "$S" verdict_drop) == 0"

echo "# counter invariants"
RX=$(counter "$S" rx)
V=$(( $(counter "$S" verdict_pass) + $(counter "$S" verdict_drop) + $(counter "$S" verdict_tx) + $(counter "$S" verdict_redirect) ))
check "rx ($RX) == sum of verdicts ($V)" "$RX == $V"
check "rx ($RX) == sum of parse outcomes" "$RX == $(parse_sum "$S")"

echo "# attach is not idempotent by accident"
if mctl attach -i "$IF" --obj "$OBJ" --mode native 2>/dev/null; then R=0; else R=1; fi
check "second attach without --replace is refused" "$R == 1"
if mctl attach -i "$IF" --obj "$OBJ" --mode generic --replace 2>/dev/null; then R=0; else R=1; fi
check "replace into a different mode is refused" "$R == 1"

echo "# atomic replace keeps pinned counters"
OLD_ID=$(xdp_prog_id)
mctl attach -i "$IF" --obj "$OBJ" --mode native --replace
S=$(stats)
check "new program id after replace" "$(xdp_prog_id) != $OLD_ID && $(xdp_prog_id) != 0"
check "still native after replace" "$(xdp_mode | grep -c '^native$') == 1"
check "counters survived replace" "$(counter "$S" rx) >= $RX"

echo "# detach"
mctl detach -i "$IF"
check "no XDP program left on $IF" "$(xdp_mode | grep -c '^none$') == 1"
check "pins removed" "$(ls "$PIN_ROOT" 2>/dev/null | wc -l) == 0"

echo "# generic mode"
mctl attach -i "$IF" --obj "$OBJ" --mode generic
check "kernel reports generic XDP on $IF" "$(xdp_mode | grep -c '^generic$') == 1"
check "ping succeeds in generic mode" "$(ping_ok 3) == 1"
check "generic mode counts traffic" "$(counter "$(stats)" l4_icmp) >= 3"
mctl detach -i "$IF"
check "generic program detached" "$(xdp_mode | grep -c '^none$') == 1"

echo "# never touches a program it did not attach"
if ip link set dev "$IF" xdpgeneric obj "$OBJ" sec xdp 2>/dev/null; then
	if mctl attach -i "$IF" --obj "$OBJ" --mode generic 2>/dev/null; then R=0; else R=1; fi
	check "attach refuses to replace a foreign program" "$R == 1"
	if mctl detach -i "$IF" 2>/dev/null; then R=0; else R=1; fi
	check "detach refuses to remove a foreign program" "$R == 1"
	check "foreign program still attached" "$(xdp_mode | grep -c '^generic$') == 1"
	ip link set dev "$IF" xdpgeneric off
else
	echo "skip - iproute2 cannot load BTF-defined maps here; foreign-program checks skipped"
fi

echo
echo "veth integration: $PASS passed, $FAIL failed"
exit $(( FAIL > 0 ))
