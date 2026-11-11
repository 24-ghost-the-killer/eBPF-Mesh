#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Phase 2 "done when": a SYN flood from a test generator is stopped while a
# normal HTTP request still succeeds.
#
# 1. Mitigate: spoofed SYN flood (sentinel-gen) + a real HTTP request with
#    curl. The flood must never reach the server's TCP stack; curl must get
#    the page (after one SYN-cookie round trip).
# 2. Control: the same flood in observe mode does reach the server, which
#    proves step 1 measured something real.
set -euo pipefail
source "$(dirname "$0")/lib.sh"

lab_up
ctl service add --proto tcp --port 80 >/dev/null
ctl policy set --mitigate on --syncookies on --enforce-services on >/dev/null

# ---- 1. mitigate ------------------------------------------------------------
segs0=$(tcp_snmp InSegs)
opens0=$(tcp_snmp PassiveOpens)
chal0=$(count tx_syn_challenge)

gen syn --dst "$PROTECTED" --dport 80 --src "$FLOOD_SRC" --duration 4s \
	--pps 20000 >"$WORK/gen.log" 2>&1 &
GEN_PID=$!
sleep 1

t0=$(date +%s%N)
body=$(http_get 5 || true)
t1=$(date +%s%N)
ms=$(((t1 - t0) / 1000000))
[ "$body" = sentinel-ok ] && pass "HTTP request during the flood succeeded (${ms} ms)" \
	|| fail "HTTP request during the flood failed (got '${body}')"
[ "$ms" -lt 3000 ] && pass "first connection delayed only by the cookie round trip" \
	|| fail "HTTP request took ${ms} ms"
wait "$GEN_PID"
sed 's/^/     | /' "$WORK/gen.log"

sent=$(grep -o 'sent [0-9]*' "$WORK/gen.log" | awk '{print $2}')
chal=$(($(count tx_syn_challenge) - chal0))
segs=$(($(tcp_snmp InSegs) - segs0))
opens=$(($(tcp_snmp PassiveOpens) - opens0))
synrecv=$(inb ss -Htn state syn-recv | wc -l)

[ "$chal" -ge $((sent / 2)) ] && pass "flood SYNs answered by XDP challenges ($chal of $sent sent)" \
	|| fail "only $chal challenges for $sent flood SYNs"
[ "$(count syn_verified)" -ge 1 ] && pass "the real client was verified by its RST" \
	|| fail "client never verified"
[ "$segs" -lt 100 ] && pass "server TCP stack saw $segs segments (flood: $sent)" \
	|| fail "server TCP stack saw $segs segments during the flood"
[ "$opens" -eq 1 ] && pass "exactly one connection accepted (the real client)" \
	|| fail "server accepted $opens connections"
[ "$synrecv" -eq 0 ] && pass "no half-open connections on the server" \
	|| fail "$synrecv half-open connections on the server"

ctl stats | sed 's/^/     | /'

# ---- 2. control: observe mode lets the flood through -------------------------
ctl policy set --mitigate off >/dev/null
segs0=$(tcp_snmp InSegs)
gen syn --dst "$PROTECTED" --dport 80 --src "$FLOOD_SRC" --count 5000 >"$WORK/gen2.log" 2>&1
sleep 0.5
sent=$(grep -o 'sent [0-9]*' "$WORK/gen2.log" | awk '{print $2}')
segs=$(($(tcp_snmp InSegs) - segs0))
[ "$segs" -ge $((sent / 2)) ] && pass "control: in observe mode the server saw $segs of $sent flood SYNs" \
	|| fail "control: observe-mode flood did not reach the server ($segs of $sent)"
http_ok 5 && pass "observe mode: HTTP still works" || fail "observe mode: HTTP failed"

finish
