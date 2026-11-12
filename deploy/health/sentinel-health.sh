#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
# PoP health check (spec 11.3, ADR 0023): announce the anycast prefixes only
# while XDP is attached to the uplink and the agent's heartbeat is fresh.
# Run every 2 seconds (sentinel-health.timer). Changes BIRD only when the
# state flips, and logs the transition.
#
# Env: XS_IFACE (uplink), XS_HEARTBEAT (default /run/sentinel/heartbeat),
#      XS_MAX_AGE (seconds, default 10), BIRDC (default birdc),
#      XS_PROTOCOLS (default "anycast4 anycast6").
set -u
: "${XS_IFACE:?set XS_IFACE}"
HB=${XS_HEARTBEAT:-/run/sentinel/heartbeat}
MAX=${XS_MAX_AGE:-10}
BIRDC=${BIRDC:-birdc}
PROTOS=${XS_PROTOCOLS:-anycast4 anycast6}

healthy() {
	ip -j link show dev "$XS_IFACE" 2>/dev/null | grep -q '"xdp"' || return 1
	[ -r "$HB" ] || return 1
	age=$(( $(date +%s) - $(cat "$HB" 2>/dev/null || echo 0) ))
	[ "$age" -lt "$MAX" ]
}

if healthy; then want=enable; else want=disable; fi
for p in $PROTOS; do
	state=$($BIRDC show protocols "$p" 2>/dev/null | awk -v p="$p" '$1 == p { print $4 }')
	case "$want:$state" in
	enable:down) $BIRDC enable "$p" >/dev/null && logger -t sentinel-health "$p enabled (healthy)" 2>/dev/null ;;
	disable:up) $BIRDC disable "$p" >/dev/null && logger -t sentinel-health "$p withdrawn (XDP or agent unhealthy)" 2>/dev/null ;;
	esac
done
exit 0
