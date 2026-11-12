#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Phase 1 "done when": XDP counts packets on a veth.
#
# Topology (two network namespaces, one veth pair, native XDP on the B side):
#
#   [ns A] va 192.0.2.1  <---- veth ---->  vb 192.0.2.2 [ns B]  <- sentinelctl attach
#
# IPv6 is disabled and neighbours are static in both namespaces so the only
# frames reaching vb are the ones this test sends; the counters can therefore
# be checked for exact values.
#
# Env: CTL (sentinelctl binary), BPF_OBJ (xdp_main.o). Needs root.
set -euo pipefail

: "${CTL:?set CTL to the sentinelctl binary}"
: "${BPF_OBJ:?set BPF_OBJ to xdp_main.o}"
[ "$(id -u)" -eq 0 ] || { echo "veth_counts: needs root" >&2; exit 1; }
for tool in ip jq nsenter ping python3; do
	command -v "$tool" >/dev/null || { echo "veth_counts: missing $tool" >&2; exit 1; }
done

HERE="$(cd "$(dirname "$0")" && pwd)"
ID=$$
NS_A="xs-a-$ID"
NS_B="xs-b-$ID"
VA="xsa$ID"
VB="xsb$ID"
MAC_A=02:00:00:00:00:01
MAC_B=02:00:00:00:00:02
IP_A=192.0.2.1
IP_B=192.0.2.2
export SENTINEL_PIN_DIR="/sys/fs/bpf/sentinel-test-$ID"

FAILS=0
CHECKS=0
pass() { CHECKS=$((CHECKS + 1)); echo "ok   $*"; }
fail() { CHECKS=$((CHECKS + 1)); FAILS=$((FAILS + 1)); echo "FAIL $*"; }
inb() { ip netns exec "$NS_B" "$@"; }
# sentinelctl in ns B. Not `ip netns exec`: it remounts /sys in a private
# mount namespace, which hides bpffs at /sys/fs/bpf. nsenter only switches netns.
ctl() { nsenter --net="/run/netns/$NS_B" "$CTL" "$@"; }
ina() { ip netns exec "$NS_A" "$@"; }

cleanup() {
	set +e
	ctl detach --iface "$VB" >/dev/null 2>&1
	ip netns del "$NS_A" 2>/dev/null
	ip netns del "$NS_B" 2>/dev/null
	rm -rf "$SENTINEL_PIN_DIR" 2>/dev/null
}
trap cleanup EXIT

# ---- setup ---------------------------------------------------------------
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf

ip netns add "$NS_A"
ip netns add "$NS_B"
for ns in "$NS_A" "$NS_B"; do
	ip netns exec "$ns" sysctl -qw net.ipv6.conf.all.disable_ipv6=1
	ip netns exec "$ns" sysctl -qw net.ipv6.conf.default.disable_ipv6=1
	ip -n "$ns" link set lo up
done
ip link add "$VA" netns "$NS_A" address "$MAC_A" type veth \
	peer name "$VB" netns "$NS_B" address "$MAC_B"
ina sysctl -qw "net.ipv6.conf.$VA.disable_ipv6=1"
inb sysctl -qw "net.ipv6.conf.$VB.disable_ipv6=1"
ip -n "$NS_A" addr add "$IP_A/24" dev "$VA"
ip -n "$NS_B" addr add "$IP_B/24" dev "$VB"
ip -n "$NS_A" neigh add "$IP_B" lladdr "$MAC_B" dev "$VA" nud permanent
ip -n "$NS_B" neigh add "$IP_A" lladdr "$MAC_A" dev "$VB" nud permanent
ip -n "$NS_A" link set "$VA" up
ip -n "$NS_B" link set "$VB" up

xdp_mode() { # prints the XDP attach mode of vb: 1 = native (driver), none = detached
	ip -n "$NS_B" -j link show dev "$VB" | jq -r '.[0].xdp.mode // "none"'
}
count() { # count <stats-json> <verdict>
	jq -r --arg v "$2" '[.entries[] | select(.verdict == $v) | .pkts] | add // 0' <<<"$1"
}
send() { # send <kind> <count>
	ina python3 "$HERE/send_frames.py" --iface "$VA" --src-mac "$MAC_A" \
		--dst-mac "$MAC_B" --kind "$1" --count "$2" >/dev/null
}

# ---- attach --------------------------------------------------------------
if ctl attach --iface "$VB" --obj "$BPF_OBJ" --mode generic >/dev/null 2>&1; then
	fail "generic mode accepted without --allow-generic"
else
	pass "generic mode refused without --allow-generic"
fi
[ "$(xdp_mode)" = none ] && pass "nothing attached after refusal" \
	|| fail "XDP attached after refused generic attach"

# B's own address is the PoP IP: pings to it are pass_local. Nothing is
# protected here, so frames to 198.51.100.10 count as drop_no_tenant.
ctl attach --iface "$VB" --obj "$BPF_OBJ" --pop-ip4 "$IP_B" >/dev/null
[ "$(xdp_mode)" = 1 ] && pass "attached in native mode" \
	|| fail "expected native XDP (mode 1), got $(xdp_mode)"

if ctl attach --iface "$VB" --obj "$BPF_OBJ" >/dev/null 2>&1; then
	fail "second attach on the same interface accepted"
else
	pass "second attach refused"
fi

before=$(ctl stats --json)
[ "$(jq '.entries | length' <<<"$before")" -eq 0 ] && pass "counters start empty" \
	|| fail "counters not empty at start: $before"

# ---- traffic -------------------------------------------------------------
PINGS=20
if ina ping -q -c "$PINGS" -i 0.01 -W 2 "$IP_B" >/dev/null; then
	pass "$PINGS pings answered through XDP"
else
	fail "ping through XDP failed"
fi

N_VALID4=5 N_VALID6=4 N_VLAN4=3 N_QINQ6=2
N_FRAG4=4 N_FRAG6=3 N_NONIP=3 N_MALFORMED=14
send valid4 "$N_VALID4"
send valid6 "$N_VALID6"
send vlan4 "$N_VLAN4"
send qinq6 "$N_QINQ6"
send frag4 "$N_FRAG4"
send frag6 "$N_FRAG6"
send nonip "$N_NONIP"
send malformed "$N_MALFORMED"
sleep 0.5 # veth XDP runs in NAPI; let it drain

stats=$(ctl stats --json)
want_no_tenant=$((N_VALID4 + N_VALID6 + N_VLAN4 + N_QINQ6 + N_FRAG4 + N_FRAG6))
check() { # check <verdict> <want>
	local got
	got=$(count "$stats" "$1")
	[ "$got" -eq "$2" ] && pass "counter $1 = $2" || fail "counter $1 = $got, want $2"
}
check pass_local "$PINGS"
check drop_no_tenant "$want_no_tenant"
check pass_non_ip "$N_NONIP"
check drop_malformed "$N_MALFORMED"
total_bytes=$(jq '[.entries[].bytes] | add' <<<"$stats")
[ "$total_bytes" -gt 0 ] && pass "byte counters populated ($total_bytes bytes)" \
	|| fail "byte counters empty"

ctl stats | sed 's/^/     | /'

# ---- lab-range guard of the generator -------------------------------------
if ina python3 "$HERE/send_frames.py" --iface "$VA" --kind valid4 --dst4 8.8.8.8 \
	--count 1 >/dev/null 2>&1; then
	fail "frame sender accepted a non-lab destination"
else
	pass "frame sender refuses non-lab destination"
fi

# ---- detach --------------------------------------------------------------
ctl detach --iface "$VB" >/dev/null
[ "$(xdp_mode)" = none ] && pass "detached: no XDP program on $VB" \
	|| fail "XDP still attached after detach"
[ ! -e "$SENTINEL_PIN_DIR" ] && pass "pins removed after last detach" \
	|| fail "pin dir left behind: $(ls "$SENTINEL_PIN_DIR")"
if ctl stats >/dev/null 2>&1; then
	fail "stats succeeded with nothing attached"
else
	pass "stats reports 'not attached' after detach"
fi
ina ping -q -c 3 -i 0.01 -W 2 "$IP_B" >/dev/null && pass "traffic flows after detach" \
	|| fail "ping failed after detach"

echo "$((CHECKS - FAILS))/$CHECKS checks passed"
[ "$FAILS" -eq 0 ]
