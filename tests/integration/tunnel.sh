#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Phase 3 "done when": a test customer namespace receives the packet through
# the tunnel and sees the real client IP.
#
# Also: replies through the tunnel and with DSR, MTU/MSS end to end (1 MiB in
# both directions), oversize packets counted, MSS clamping rescuing a customer
# whose tunnel MTU is wrong.
set -euo pipefail
source "$(dirname "$0")/lib.sh"

lab_up tunnel
echo "     | origin tunnel device: ${SENTINEL_TEST_TUNNEL_DEV:-created by the script}"

# ---- delivery and the real client IP ----------------------------------------
before_ret=$(count tx_return)
body=$(http_get 5 || true)
[ "$body" = sentinel-ok ] && pass "client reaches the origin through the PoP" \
	|| fail "HTTP through the tunnel failed (got '$body')"
grep -q "^$CLIENT " "$WORK/http.log" && pass "origin sees the real client IP $CLIENT" \
	|| fail "origin log: $(cat "$WORK/http.log")"
[ "$(count pass)" -ge 1 ] && pass "PoP tunnelled the request (pass counted)" || fail "no pass verdicts"
[ "$(count tx_return)" -gt "$before_ret" ] && pass "replies came back through the PoP (tx_return)" \
	|| fail "no tx_return: replies did not use the tunnel"

# ---- MTU / MSS ------------------------------------------------------------------
size=$(http_get 10 /blob | wc -c)
[ "$size" -eq 1048576 ] && pass "1 MiB download (origin -> client)" || fail "download got $size bytes"
got=$(http_upload 1048576 || true)
[ "$got" = 1048576 ] && pass "1 MiB upload (client -> origin, full-size segments fit the tunnel)" \
	|| fail "upload: origin received '${got}'"
big=$(count drop_too_big)
[ "$big" -eq 0 ] && pass "no packet exceeded the uplink MTU" || fail "$big packets too big"

ina ping -q -c 2 -W 2 -I "$CLIENT" -M do -s 1452 "$PROTECTED" >/dev/null \
	&& pass "1480-byte packet (DF) delivered and answered" || fail "1480-byte ping failed"
before=$(count drop_too_big)
ina ping -q -c 2 -W 1 -I "$CLIENT" -M do -s 1472 "$PROTECTED" >/dev/null 2>&1 \
	&& fail "1500-byte packet got through a 1500 uplink with tunnel overhead" \
	|| pass "1500-byte packet does not fit the tunnel"
[ $(($(count drop_too_big) - before)) -eq 2 ] && pass "counted as drop_too_big" \
	|| fail "drop_too_big did not count the oversize pings"

# Customer forgot the tunnel MTU: the origin advertises MSS 1460. The PoP
# clamps the SYN-ACK to 1440 on the way back, so uploads still fit.
dev="${SENTINEL_TEST_TUNNEL_DEV:-sentinel0}"
inc ip link set "$dev" mtu 1500
before=$(count drop_too_big)
got=$(http_upload 1048576 || true)
[ "$got" = 1048576 ] && pass "wrong customer MTU: upload still works (PoP clamped the MSS)" \
	|| fail "wrong customer MTU: upload got '${got}'"
[ "$(count drop_too_big)" -eq "$before" ] && pass "wrong customer MTU: nothing too big" \
	|| fail "wrong customer MTU: packets too big"
inc ip link set "$dev" mtu 1480

# ---- direct server return ---------------------------------------------------------
origin_tunnel tunnel down
origin_tunnel dsr
before_ret=$(count tx_return)
http_ok 5 && pass "DSR: HTTP works" || fail "DSR: HTTP failed"
got=$(http_upload 1048576 || true)
[ "$got" = 1048576 ] && pass "DSR: 1 MiB upload (origin lowered its MSS)" || fail "DSR: upload got '${got}'"
[ "$(count tx_return)" -eq "$before_ret" ] && pass "DSR: replies bypassed the PoP" \
	|| fail "DSR: replies still went through the PoP"

ctl stats | sed 's/^/     | /'
finish
