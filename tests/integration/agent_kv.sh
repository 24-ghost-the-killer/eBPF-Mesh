#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Phase 4 "done when": a tenant added with `nats kv put` works without
# restarting anything.
#
# The PoP is driven only by the agent: NATS (TLS, nkeys, per-PoP
# permissions) runs on the PoP namespace's loopback; the agent attaches XDP,
# applies the KV buckets and publishes acks, stats, telemetry and health.
#
# Env: see lib.sh and nats_lab.sh.
set -euo pipefail
source "$(dirname "$0")/lib.sh"
source "$(dirname "$0")/nats_lab.sh"

nats_prepare
lab_net
nats_start
pass "NATS up with TLS, nkeys and the KV buckets"
nats_record config.ack.lab1 stats.lab1 health.lab1 'telemetry.lab1.>'
agent_config
start_agent
wait_for "$N/sub-health.lab1.log" '"xdp_attached":true' 10 \
	&& pass "agent attached XDP and reports health" || { fail "no health"; cat "$WORK/agent.log"; }

# ---- nothing configured yet ---------------------------------------------------------
http_ok 2 && fail "traffic delivered without any asset" || pass "no asset yet: dropped"
[ "$(count drop_no_tenant)" -ge 1 ] && pass "counted as drop_no_tenant" || fail "no drop_no_tenant"

# ---- the done-when step: add a tenant with nats kv put ----------------------------
ASSET1='{"v":1,"version":1,"asset":1,"tenant":1,"prefix":"198.51.100.10/32","origin":"192.0.2.10"}'
admin kv put tenants asset.1 "$ASSET1" >/dev/null
wait_for "$N/sub-config.ack.lab1.log" '"key":"asset.1".*"version":1,"ok":true' 5 \
	&& pass "agent acknowledged asset.1 version 1" || fail "no ack for asset.1"
origin_start tunnel
http_ok 5 && pass "nats kv put -> traffic flows, nothing restarted" || fail "HTTP failed after kv put"
grep -q "^$CLIENT " "$WORK/http.log" && pass "origin sees the real client IP" || fail "client IP not seen"

# ---- policy, services, rules through KV ------------------------------------------
admin kv put services asset.1 '{"v":1,"version":2,"services":[{"proto":"tcp","port":80}]}' >/dev/null
admin kv put tenants asset.1 '{"v":1,"version":3,"asset":1,"tenant":1,"prefix":"198.51.100.10/32","origin":"192.0.2.10","policy":{"mode":"mitigate","enforce_services":true}}' >/dev/null
wait_for "$N/sub-config.ack.lab1.log" '"key":"asset.1".*"version":3,"ok":true' 5 \
	&& pass "policy update acknowledged (version 3)" || fail "no ack for version 3"
http_ok 3 && pass "tcp/80 allowed by the KV service list" || fail "tcp/80 blocked"
before=$(count drop_service)
gen udp --dst "$PROTECTED" --dport 53 --src 203.0.113.60/32 --count 50 >/dev/null
sleep 0.3
[ $(($(count drop_service) - before)) -ge 25 ] && pass "udp/53 dropped (mitigate + services from KV)" \
	|| fail "udp/53 not dropped"

admin kv put rules tenant.1 "{\"v\":1,\"version\":4,\"block\":[{\"prefix\":\"$CLIENT/32\",\"expires_at\":$(($(now_ms) + 60000))}]}" >/dev/null
wait_for "$N/sub-config.ack.lab1.log" '"key":"tenant.1".*"ok":true' 5 && pass "block rule acknowledged" \
	|| fail "no ack for tenant.1"
http_ok 2 && fail "blocked client still connects" || pass "block rule from KV enforced"
admin kv del rules tenant.1 --force >/dev/null
wait_for "$N/sub-config.ack.lab1.log" '"key":"tenant.1","op":"delete"' 5 \
	&& pass "rule deletion acknowledged" || fail "no delete ack"
http_ok 3 && pass "deleting the KV key lifts the block" || fail "still blocked after delete"

# A bad document is rejected and changes nothing.
admin kv put tenants asset.1 '{"v":1,"version":5,"asset":1,"tenant":0,"prefix":"198.51.100.10/32","origin":"192.0.2.10"}' >/dev/null
wait_for "$N/sub-config.ack.lab1.log" '"version":5,"ok":false,"error":"tenant 0' 5 \
	&& pass "invalid document rejected with a reason" || fail "no rejection ack"
http_ok 3 && pass "rejected update kept the previous state" || fail "rejected update broke traffic"

# ---- published data ---------------------------------------------------------------------
sleep 2
wait_for "$N/sub-stats.lab1.log" '"tenant":1,"verdict":"pass"' 3 && pass "stats.lab1 counts the tenant's traffic" \
	|| fail "stats.lab1 missing tenant 1"
wait_for "$N/sub-telemetry.lab1.log" "\"src\":\"$CLIENT\".*\"dport\":80" 3 \
	&& pass "telemetry.lab1.* carries the client's flow" || fail "no telemetry flow for the client"
wait_for "$N/sub-health.lab1.log" '"config_version":[3-9]' 3 && pass "health reports the applied config version" \
	|| fail "health config_version"
[ $(( $(date +%s) - $(cat "$WORK/heartbeat") )) -lt 5 ] && pass "heartbeat file is fresh" || fail "stale heartbeat"
inb curl -s http://127.0.0.1:9466/metrics | grep -q 'sentinel_packets_total{tenant="1",verdict="pass"}' \
	&& pass "Prometheus endpoint exports per-tenant counters" || fail "metrics missing"

# ---- NATS security ---------------------------------------------------------------------------
natsc "$N/lab1.nk" kv put tenants asset.9 '{}' >/dev/null 2>&1 && fail "a PoP could write to KV" \
	|| pass "PoP credentials cannot write KV"
out=$(natsc "$N/lab1.nk" pub stats.lab2 spoofed 2>&1 || true)
echo "$out" | grep -qi "permission" && pass "PoP cannot publish another PoP's stats" \
	|| fail "no permission error publishing stats.lab2: $out"
# A plaintext client: the server demands TLS and never answers PING.
plain=$(inb python3 - <<'PY'
import socket
s = socket.create_connection(("127.0.0.1", 4222), timeout=2)
info = s.recv(4096).decode()
s.sendall(b'CONNECT {"verbose":false}\r\nPING\r\n')
try:
    reply = s.recv(4096).decode()
except Exception as e:
    reply = f"error: {e}"
print("tls_required" if '"tls_required":true' in info else "no-tls", "PONG" if "PONG" in reply else "no-pong")
PY
)
[ "$plain" = "tls_required no-pong" ] && pass "connections without TLS are refused" \
	|| fail "plaintext client: $plain"

# ---- restarts ----------------------------------------------------------------------------------
kill -9 "$AGENT_PID"
wait "$AGENT_PID" 2>/dev/null || true
kill -0 "$AGENT_PID" 2>/dev/null && fail "agent survived kill -9" || pass "agent process is gone"
http_ok 3 && pass "agent killed: XDP keeps protecting with the last state" || fail "traffic stopped after agent crash"
admin kv del tenants asset.1 --force >/dev/null # change while the agent is down
: >"$N/sub-config.ack.lab1.log"
start_agent
wait_for "$N/sub-config.ack.lab1.log" '"key":"asset.1","op":"delete"' 10 \
	&& pass "restarted agent resynced (missed delete applied)" || fail "no resync after restart"
http_ok 2 && fail "deleted asset still served" || pass "deleted asset no longer delivered"
grep -q "adopting existing XDP attachment" "$WORK/agent.log" && pass "restart adopted the attachment" \
	|| fail "restart re-attached instead of adopting"

kill -TERM "$AGENT_PID"
for _ in $(seq 50); do kill -0 "$AGENT_PID" 2>/dev/null || break; sleep 0.1; done
[ "$(ip -n "$NS_B" -j link show dev "$VB" | jq -r '.[0].xdp.mode // "none"')" = none ] \
	&& pass "SIGTERM detached XDP cleanly" || fail "XDP still attached after SIGTERM"

if [ "$FAILS" -gt 0 ]; then
	echo "---- agent log"; tail -40 "$WORK/agent.log"
	echo "---- nats server log"; grep -i -E "violation|error" "$N/server.log" | tail -20
fi
finish
