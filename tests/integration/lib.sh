# SPDX-License-Identifier: MIT OR Apache-2.0
# Shared helpers for the integration tests (source it; needs bash and root).
#
# Topology built by lab_up:
#
#   [ns A "internet"]                               [ns B "pop + origin"]
#   va 203.0.113.1/25  <-------- veth -------->  vb 10.10.1.1/24 (PoP unicast)
#   (clients, sentinel-gen)                       lo 198.51.100.10/32 (protected IP)
#   xdp_pass on va (veth XDP_TX needs             sentinel XDP (native) on vb
#   a program on the peer)                        HTTP server on 198.51.100.10:80
#
# Spoofed flood sources come from 203.0.113.128/25, which ns A does not own,
# so challenge SYN-ACKs to them die in ns A (forwarding is off).
#
# Env: CTL, GEN, BPF_OBJ, PASS_OBJ.

: "${CTL:?set CTL}" "${GEN:?set GEN}" "${BPF_OBJ:?set BPF_OBJ}" "${PASS_OBJ:?set PASS_OBJ}"
[ "$(id -u)" -eq 0 ] || { echo "needs root" >&2; exit 1; }
for tool in ip jq nsenter curl python3 ss; do
	command -v "$tool" >/dev/null || { echo "missing $tool" >&2; exit 1; }
done

ID=$$
NS_A="xs-a-$ID"
NS_B="xs-b-$ID"
VA="xsa$ID"
VB="xsb$ID"
MAC_A=02:00:00:00:00:01
MAC_B=02:00:00:00:00:02
CLIENT=203.0.113.1
POP_IP=10.10.1.1
PROTECTED=198.51.100.10
FLOOD_SRC=203.0.113.128/25
export SENTINEL_PIN_DIR="/sys/fs/bpf/sentinel-test-$ID"
WORK="$(mktemp -d)"

FAILS=0
CHECKS=0
pass() { CHECKS=$((CHECKS + 1)); echo "ok   $*"; }
fail() { CHECKS=$((CHECKS + 1)); FAILS=$((FAILS + 1)); echo "FAIL $*"; }
ina() { ip netns exec "$NS_A" "$@"; }
inb() { ip netns exec "$NS_B" "$@"; }
# sentinelctl in ns B. Not `ip netns exec`: it remounts /sys in a private
# mount namespace, which hides bpffs at /sys/fs/bpf. nsenter only switches netns.
ctl() { nsenter --net="/run/netns/$NS_B" "$CTL" "$@"; }
gen() { ina "$GEN" "$@"; }

lab_down() {
	set +e
	[ -n "${HTTP_PID:-}" ] && kill "$HTTP_PID" 2>/dev/null
	ctl detach --iface "$VB" >/dev/null 2>&1
	ip netns del "$NS_A" 2>/dev/null
	ip netns del "$NS_B" 2>/dev/null
	rm -rf "$SENTINEL_PIN_DIR" "$WORK" 2>/dev/null
}

lab_up() {
	trap lab_down EXIT
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
	ip -n "$NS_A" link set "$VA" up
	ip -n "$NS_B" link set "$VB" up
	ip -n "$NS_A" addr add "$CLIENT/25" dev "$VA"
	ip -n "$NS_A" route add 198.51.100.0/24 dev "$VA"
	ip -n "$NS_A" neigh add "$PROTECTED" lladdr "$MAC_B" dev "$VA" nud permanent
	ip -n "$NS_B" addr add "$POP_IP/24" dev "$VB"
	ip -n "$NS_B" addr add "$PROTECTED/32" dev lo
	ip -n "$NS_B" route add 203.0.113.0/24 dev "$VB"
	ip -n "$NS_B" neigh add "$CLIENT" lladdr "$MAC_A" dev "$VB" nud permanent
	ip -n "$NS_A" link set dev "$VA" xdpdrv obj "$PASS_OBJ" sec xdp

	ctl attach --iface "$VB" --obj "$BPF_OBJ" --pop-ip4 "$POP_IP" >/dev/null

	mkdir -p "$WORK/www"
	echo sentinel-ok >"$WORK/www/index.html"
	inb python3 -m http.server 80 --bind "$PROTECTED" --directory "$WORK/www" \
		>"$WORK/http.log" 2>&1 &
	HTTP_PID=$!
	for _ in $(seq 50); do
		inb ss -Hltn "sport = :80" | grep -q . && return 0
		sleep 0.1
	done
	echo "HTTP server did not start" >&2
	exit 1
}

# Packets counted for a verdict.
count() {
	ctl stats --json | jq -r --arg v "$1" \
		'[.entries[] | select(.verdict == $v) | .pkts] | add // 0'
}

# A field of the "Tcp:" line in ns B's /proc/net/snmp (e.g. InSegs).
tcp_snmp() {
	inb awk -v f="$1" '/^Tcp:/ { if (!n) { for (i = 1; i <= NF; i++) if ($i == f) c = i; n = 1 } else print $c }' /proc/net/snmp
}

# HTTP GET from the client; prints the body. $1 = max seconds.
http_get() {
	ina curl -sS --max-time "${1:-3}" "http://$PROTECTED/" 2>/dev/null
}

http_ok() { [ "$(http_get "${1:-3}")" = sentinel-ok ]; }

finish() {
	echo "$((CHECKS - FAILS))/$CHECKS checks passed"
	[ "$FAILS" -eq 0 ]
}
