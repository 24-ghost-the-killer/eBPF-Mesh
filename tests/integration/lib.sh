# SPDX-License-Identifier: MIT OR Apache-2.0
# Shared helpers for the integration tests (source it; needs bash and root).
#
# Topology built by lab_up:
#
#   [ns C "origin"]                [ns A "internet"]                [ns B "PoP"]
#   xso 192.0.2.10/24 <--veth--> xsc 192.0.2.1/24
#   runs the generated            client 203.0.113.1 (lo)
#   customer tunnel script;       xsa 10.10.1.254/24 <-----veth-----> xsb 10.10.1.1/24
#   HTTP origin on                routes 198.51.100.0/24 via the PoP  sentinel XDP (native)
#   198.51.100.10:80              xdp_pass on xsa (veth XDP_TX needs  asset 1: 198.51.100.10/32
#                                 a program on the peer)              -> origin 192.0.2.10
#
# Forward: client -> A -> B (XDP: filter, IPIP to 192.0.2.10, XDP_TX) -> A -> C.
# Return (tunnel mode): C -> IPIP to 198.51.100.1 -> A -> B (XDP: validate,
# decapsulate, XDP_TX) -> A -> client. DSR mode: C -> A -> client directly.
#
# Spoofed flood sources come from 203.0.113.128/25, which nobody owns; replies
# to them die in A (no route).
#
# Env: CTL, GEN, BPF_OBJ, PASS_OBJ. Optional: SENTINEL_TEST_TUNNEL_DEV (default:
# tunl0 on Docker Desktop's linuxkit kernel, where creating an IPIP device
# inside a namespace has crashed the VM; otherwise the script creates one).

: "${CTL:?set CTL}" "${GEN:?set GEN}" "${BPF_OBJ:?set BPF_OBJ}" "${PASS_OBJ:?set PASS_OBJ}"
[ "$(id -u)" -eq 0 ] || { echo "needs root" >&2; exit 1; }
for tool in ip jq nsenter curl python3 ss ethtool; do
	command -v "$tool" >/dev/null || { echo "missing $tool" >&2; exit 1; }
done

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ID=$$
NS_A="xs-a-$ID"
NS_B="xs-b-$ID"
NS_C="xs-c-$ID"
VA="xsa$ID"
VB="xsb$ID"
VC="xsc$ID"
VO="xso$ID"
MAC_A=02:00:00:00:00:01
MAC_B=02:00:00:00:00:02
CLIENT=203.0.113.1
ROUTER_IP=10.10.1.254
POP_IP=10.10.1.1
TUNNEL_EP=198.51.100.1
PROTECTED=198.51.100.10
ORIGIN=192.0.2.10
FLOOD_SRC=203.0.113.128/25
ASSET=1
export SENTINEL_PIN_DIR="/sys/fs/bpf/sentinel-test-$ID"
WORK="$(mktemp -d)"
if [ -z "${SENTINEL_TEST_TUNNEL_DEV:-}" ] && uname -r | grep -q linuxkit; then
	SENTINEL_TEST_TUNNEL_DEV=tunl0
fi
TUNNEL_DEV_ARGS=()
[ -n "${SENTINEL_TEST_TUNNEL_DEV:-}" ] && TUNNEL_DEV_ARGS=(--tunnel-dev "$SENTINEL_TEST_TUNNEL_DEV")

FAILS=0
CHECKS=0
pass() { CHECKS=$((CHECKS + 1)); echo "ok   $*"; }
fail() { CHECKS=$((CHECKS + 1)); FAILS=$((FAILS + 1)); echo "FAIL $*"; }
ina() { ip netns exec "$NS_A" "$@"; }
inb() { ip netns exec "$NS_B" "$@"; }
inc() { ip netns exec "$NS_C" "$@"; }
# sentinelctl in ns B. Not `ip netns exec`: it remounts /sys in a private
# mount namespace, which hides bpffs at /sys/fs/bpf. nsenter only switches netns.
ctl() { nsenter --net="/run/netns/$NS_B" "$CTL" "$@"; }
gen() { ina "$GEN" "$@"; }

lab_down() {
	set +e
	[ -n "${HTTP_PID:-}" ] && kill "$HTTP_PID" 2>/dev/null
	ctl detach --iface "$VB" >/dev/null 2>&1
	for ns in "$NS_A" "$NS_B" "$NS_C"; do ip netns del "$ns" 2>/dev/null; done
	rm -rf "$SENTINEL_PIN_DIR" "$WORK" 2>/dev/null
}

sysctls() { # sysctls <ns> key=value...
	local ns=$1
	shift
	for kv in "$@"; do ip netns exec "$ns" sysctl -qw "$kv"; done
}

# Runs the customer tunnel script for the asset in ns C. $1 = tunnel | dsr.
origin_tunnel() {
	ctl asset script "$ASSET" --return "$1" "${TUNNEL_DEV_ARGS[@]}" >"$WORK/tunnel-$1.sh"
	inc sh "$WORK/tunnel-$1.sh" "${2:-up}" >/dev/null
}

lab_up() { # lab_up [tunnel|dsr]
	trap lab_down EXIT
	mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
	for ns in "$NS_A" "$NS_B" "$NS_C"; do
		ip netns add "$ns"
		sysctls "$ns" net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1
		ip -n "$ns" link set lo up
	done
	sysctls "$NS_A" net.ipv4.ip_forward=1 net.ipv4.conf.all.rp_filter=0 \
		net.ipv4.conf.default.rp_filter=0

	ip link add "$VA" netns "$NS_A" address "$MAC_A" type veth \
		peer name "$VB" netns "$NS_B" address "$MAC_B"
	ip link add "$VC" netns "$NS_A" type veth peer name "$VO" netns "$NS_C"
	for pair in "$NS_A:$VA" "$NS_A:$VC" "$NS_B:$VB" "$NS_C:$VO"; do
		ip -n "${pair%%:*}" link set "${pair#*:}" up
		# veth leaves TCP/UDP checksums to "hardware" (CHECKSUM_PARTIAL);
		# XDP_TX sends the raw bytes on, so the receiver would see a
		# half-computed checksum. Real NICs deliver complete checksums.
		ip netns exec "${pair%%:*}" ethtool -K "${pair#*:}" tx off >/dev/null
	done
	ip -n "$NS_A" addr add "$ROUTER_IP/24" dev "$VA"
	ip -n "$NS_A" addr add 192.0.2.1/24 dev "$VC"
	ip -n "$NS_A" addr add "$CLIENT/32" dev lo
	ip -n "$NS_A" route add 198.51.100.0/24 via "$POP_IP"
	ip -n "$NS_B" addr add "$POP_IP/24" dev "$VB"
	ip -n "$NS_C" addr add "$ORIGIN/24" dev "$VO"
	ip -n "$NS_C" route add default via 192.0.2.1
	ip -n "$NS_A" link set dev "$VA" xdpdrv obj "$PASS_OBJ" sec xdp

	ctl attach --iface "$VB" --obj "$BPF_OBJ" --pop-ip4 "$POP_IP" >/dev/null
	ctl config set --tunnel-ep4 "$TUNNEL_EP" --nexthop-mac "$MAC_A" >/dev/null
	ctl asset add "$PROTECTED/32" --tenant 1 --origin "$ORIGIN" >/dev/null

	origin_tunnel "${1:-tunnel}"
	inc python3 "$HERE/http_origin.py" "$PROTECTED" 80 >"$WORK/http.log" 2>&1 &
	HTTP_PID=$!
	for _ in $(seq 50); do
		inc ss -Hltn "sport = :80" | grep -q . && return 0
		sleep 0.1
	done
	echo "HTTP origin did not start" >&2
	exit 1
}

# Packets counted for a verdict (all tenants).
count() {
	ctl --json stats | jq -r --arg v "$1" \
		'[.entries[] | select(.verdict == $v) | .pkts] | add // 0'
}

# A field of the "Tcp:" line in the origin's /proc/net/snmp (e.g. InSegs).
tcp_snmp() {
	inc awk -v f="$1" '/^Tcp:/ { if (!n) { for (i = 1; i <= NF; i++) if ($i == f) c = i; n = 1 } else print $c }' /proc/net/snmp
}

# HTTP request from the client; prints the body. $1 = max seconds, $2 = path.
http_get() {
	ina curl -sS --interface "$CLIENT" --max-time "${1:-3}" "http://$PROTECTED${2:-/}" 2>/dev/null
}

http_ok() { [ "$(http_get "${1:-3}")" = sentinel-ok ]; }

# Uploads $1 bytes; prints what the origin received.
http_upload() {
	head -c "$1" /dev/zero >"$WORK/upload.bin"
	ina curl -sS --interface "$CLIENT" --max-time "${2:-10}" --data-binary @"$WORK/upload.bin" \
		-H 'Content-Type: application/octet-stream' "http://$PROTECTED/upload" 2>/dev/null
}

finish() {
	echo "$((CHECKS - FAILS))/$CHECKS checks passed"
	[ "$FAILS" -eq 0 ]
}
