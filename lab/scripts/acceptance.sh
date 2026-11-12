#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Phase 8 "done when": bots in three regions hit three different PoPs, and
# draining or killing a PoP moves its traffic without loss of service.
#
# Runs against the deployed lab (lab.sh test): a customer protects a server
# through the API, clients in all three regions request it continuously,
# bots send traffic from each region. Then:
#   1. each bot's traffic arrives at its own region's PoP (ClickHouse flows)
#   2. drain pop-2 from the admin API: region 2 moves, no request fails
#   3. kill pop-3's agent: the health check withdraws the route, no request fails
#   4. crash pop-1 (container killed): BGP fails over; the outage is measured
#      and service must be back within seconds
set -euo pipefail
LAB="$(cd "$(dirname "$0")/.." && pwd)"
REPO="$(cd "$LAB/.." && pwd)"
S="$LAB/state"
API=http://172.31.250.13:8080/api/v1
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT

CHECKS=0 FAILS=0
pass() { CHECKS=$((CHECKS + 1)); echo "ok   $*"; }
fail() { CHECKS=$((CHECKS + 1)); FAILS=$((FAILS + 1)); echo "FAIL $*"; }
note() { echo "     | $*"; }
dexec() { local n=$1; shift; docker exec "clab-sentinel-$n" "$@"; }
birdc() { local n=$1; shift; dexec "$n" birdc -s /run/bird/bird.ctl "$@"; }

# ---- API sessions (cookie jar + CSRF per user) ---------------------------------------
api() { # api <who> METHOD PATH [JSON] -> body; status in $W/<who>.status
	local who=$1 m=$2 p=$3
	local args=(-s -o "$W/$who.body" -w '%{http_code}' -X "$m" -b "$W/$who.jar" -c "$W/$who.jar"
		-H "content-type: application/json")
	[ -f "$W/$who.csrf" ] && args+=(-H "x-csrf-token: $(cat "$W/$who.csrf")")
	[ $# -ge 4 ] && args+=(--data "$4")
	curl "${args[@]}" "$API$p" >"$W/$who.status"
	cat "$W/$who.body"
}
code() { cat "$W/$1.status"; }
totp() {
	python3 - "$@" <<'PY'
import base64, hashlib, hmac, struct, sys, time
s = sys.argv[1]; k = base64.b32decode(s + "=" * (-len(s) % 8))
c = int(time.time()) // 30 + (int(sys.argv[2]) if len(sys.argv) > 2 else 0)
h = hmac.new(k, struct.pack(">Q", c), hashlib.sha1).digest(); o = h[-1] & 15
print("%06d" % ((struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 1000000))
PY
}
login() { # login <who> <email> <password>
	api "$1" POST /auth/login "{\"email\":\"$2\",\"password\":\"$3\"}" | jq -r .csrf_token >"$W/$1.csrf"
	[ "$(code "$1")" = 200 ]
}
enable_2fa() { # enable_2fa <who>
	local s
	s=$(api "$1" POST /auth/2fa/setup | jq -r .secret)
	api "$1" POST /auth/2fa/enable "{\"code\":\"$(totp "$s")\"}" >/dev/null
	[ "$(code "$1")" = 200 ]
}
wait_until() { # wait_until <seconds> cmd...
	local t=$1
	shift
	for _ in $(seq $((t * 2))); do "$@" >/dev/null 2>&1 && return 0; sleep 0.5; done
	return 1
}

# ---- routing and traffic helpers -------------------------------------------------------
# The next hop region-N uses for the anycast prefix.
anycast_via() { birdc "region-$1" show route 198.51.100.0/24 primary | awk '$1 == "via" { print $2; exit }'; }
served_by_own_pop() { [ "$(anycast_via "$1")" = "10.10.$1.2" ]; }
served_elsewhere() { local v; v=$(anycast_via "$1"); [ -n "$v" ] && [ "$v" != "10.10.$1.2" ]; }

CH() { dexec clickhouse clickhouse-client -q "$1"; }
# The PoP that saw most of bot-N's packets in the last $2 seconds.
bot_ip() { echo "203.0.113.$((32 * $1 + 18))"; }
bot_pop() {
	CH "SELECT pop FROM sentinel.flows WHERE src = toIPv6('::ffff:$(bot_ip "$1")') \
	    AND ts > now64(3) - INTERVAL ${2:-6} SECOND GROUP BY pop ORDER BY sum(pkts) DESC LIMIT 1"
}

client_failures() { dexec "client-$1" sh -c 'grep -cv "^200$" /tmp/http.log 2>/dev/null || true'; }
client_total() { dexec "client-$1" sh -c 'wc -l </tmp/http.log 2>/dev/null || echo 0'; }
reset_clients() { for c in 1 2 3; do dexec "client-$c" sh -c ': >/tmp/http.log'; done; }
no_failures() { # no_failures <what>: every client request succeeded since the last reset
	local bad=0 tot=0 c f
	for c in 1 2 3; do
		f=$(client_failures "$c")
		tot=$((tot + $(client_total "$c")))
		bad=$((bad + f))
		[ "$f" -gt 0 ] && note "client-$c: $f failed requests"
	done
	[ "$bad" -eq 0 ] && pass "$1: all $tot client requests succeeded" || fail "$1: $bad of $tot requests failed"
}

# ---- 0. the lab is up ----------------------------------------------------------------------
for n in 1 2 3; do
	wait_until 60 sh -c "docker exec clab-sentinel-pop-$n birdc -s /run/bird/bird.ctl show protocols upstream4 | grep -q Established" ||
		fail "pop-$n BGP session"
done
for n in 1 2 3; do wait_until 30 served_by_own_pop "$n" || fail "region-$n does not prefer pop-$n"; done
[ "$FAILS" = 0 ] && pass "BGP up: each region routes the anycast prefix to its own PoP"

# ---- 1. a customer and a protected IP, through the API ----------------------------------
ADMIN_PW="admin $(head -c 9 /dev/urandom | base64)"
dexec api sh -c ". /lab/state/api.env; export SENTINEL_DATABASE_URL; SENTINEL_ADMIN_PASSWORD='$ADMIN_PW' \
	/opt/sentinel/bin/sentinel-api create-admin --config /lab/state/api.toml --email ops@lab.test" >/dev/null
login admin ops@lab.test "$ADMIN_PW" && enable_2fa admin && pass "platform admin with 2FA" || fail "admin login"

PW="correct horse battery"
api cust POST /auth/signup '{"email":"customer@lab.test","password":"correct horse battery","tenant_name":"Lab customer"}' >/dev/null
TOKEN=$(jq -r .body "$(ls "$S"/mail/*.json | sort | tail -1)" | sed 's/.*token=\([^ ]*\).*/\1/')
api cust POST /auth/verify-email "{\"token\":\"$TOKEN\"}" >/dev/null
login cust customer@lab.test "$PW" || fail "customer login"
TID=$(api cust GET /me | jq -r '.tenants[0].id')
asset=$(api cust POST "/tenants/$TID/assets" '{"origin_ip":"192.0.2.10","services":[]}')
AID=$(jq -r .id <<<"$asset")
IP=$(jq -r .protected_prefix <<<"$asset" | cut -d/ -f1)
note "protected IP $IP for origin-1 (asset $AID)"
applied_everywhere() {
	local st
	st=$(api cust GET "/tenants/$TID/assets/$AID/status")
	[ "$(jq -r '"\(.pops_applied)/\(.pops_total)"' <<<"$st")" = 3/3 ]
}
wait_until 30 applied_everywhere && pass "asset active on 3 of 3 PoPs" || fail "asset not on all PoPs"

dev=""
uname -r | grep -q linuxkit && dev="&device=tunl0" # Docker Desktop: see ADR 0012 tests
api cust GET "/tenants/$TID/assets/$AID/tunnel?return=tunnel$dev" >"$W/tunnel.sh"
docker exec -i clab-sentinel-origin-1 sh -s up <"$W/tunnel.sh" >/dev/null
docker cp "$REPO/tests/integration/http_origin.py" clab-sentinel-origin-1:/tmp/http_origin.py >/dev/null
docker exec -d clab-sentinel-origin-1 sh -c "python3 /tmp/http_origin.py $IP 80 >/tmp/http.log 2>&1"
sleep 1
tt=$(api cust POST "/tenants/$TID/assets/$AID/tunnel-test")
[ "$(jq -r '.ok' <<<"$tt")" = true ] && [ "$(jq '.pops | length' <<<"$tt")" = 3 ] &&
	pass "tunnel test passes from all 3 PoPs" || { fail "tunnel test"; note "$tt"; }

for c in 1 2 3; do
	wait_until 15 sh -c "docker exec clab-sentinel-client-$c curl -s --max-time 2 http://$IP/ | grep -q sentinel-ok" ||
		fail "client-$c cannot reach the protected IP"
	docker exec -d "clab-sentinel-client-$c" sh -c "while true; do
		curl -s -o /dev/null -w '%{http_code}\n' --max-time 2 http://$IP/ >>/tmp/http.log; sleep 0.2; done"
done
pass "clients in all three regions reach the customer's server through the PoPs"

# ---- 2. bots in three regions hit three different PoPs --------------------------------------
for b in 1 2 3; do
	docker exec -d "clab-sentinel-bot-$b" sentinel-gen udp --dst "$IP" --dport 9 --src "$(bot_ip "$b")/32" \
		--pps 300 --payload 200 --duration 900s
done
sleep 10
for b in 1 2 3; do
	p=$(bot_pop "$b")
	[ "$p" = "pop-$b" ] && pass "bot-$b (region $b) hits pop-$b" || fail "bot-$b hits ${p:-nothing}, not pop-$b"
done
sleep 50 # let traffic_1m fill a minute
tr=$(api cust GET "/tenants/$TID/traffic?step=60")
pops=$(jq -r '[.pops[] | select(any(.points[]; .in_pps > 0)) | .pop] | sort | join(",")' <<<"$tr")
[ "$pops" = "pop-1,pop-2,pop-3" ] && pass "traffic history (ClickHouse traffic_1m) per PoP: $pops" ||
	{ fail "traffic per PoP: '$pops'"; note "$(head -c 300 <<<"$tr")"; }
no_failures "steady state"

# ---- 3. drain pop-2 from the admin API ----------------------------------------------------------
reset_clients
api admin POST /admin/pops/pop-2/drain '{"drain":true}' >/dev/null
[ "$(code admin)" = 200 ] && pass "drain pop-2 accepted (admin API)" || fail "drain: $(code admin)"
wait_until 20 served_elsewhere 2 && pass "region 2 now routes to $(anycast_via 2) (AS path prepended)" ||
	fail "region 2 still uses pop-2"
sleep 8
p=$(bot_pop 2 5)
[ -n "$p" ] && [ "$p" != pop-2 ] && pass "bot-2's traffic moved to $p" || fail "bot-2 still at ${p:-?}"
[ "$(api admin GET /admin/pops | jq -r '.[] | select(.id == "pop-2") | .status')" = draining ] &&
	pass "admin view shows pop-2 draining" || fail "pop-2 status"
no_failures "drain"
reset_clients
api admin POST /admin/pops/pop-2/drain '{"drain":false}' >/dev/null
wait_until 20 served_by_own_pop 2 && pass "undrain: region 2 back on pop-2" || fail "undrain"
sleep 5
no_failures "undrain"

# ---- 4. kill pop-3's agent: the health check withdraws the route ----------------------------
reset_clients
dexec pop-3 pkill -9 -f sentinel-agent || true
wait_until 30 served_elsewhere 3 && pass "agent killed: heartbeat went stale, pop-3 withdrew (region 3 -> $(anycast_via 3))" ||
	fail "pop-3 still announced"
sleep 8
p=$(bot_pop 3 5)
[ -n "$p" ] && [ "$p" != pop-3 ] && pass "bot-3's traffic moved to $p" || fail "bot-3 still at ${p:-?}"
no_failures "agent killed"
reset_clients
dexec pop-3 sh /lab/scripts/node.sh start-agent 3
wait_until 30 served_by_own_pop 3 && pass "agent restarted: pop-3 announces again" || fail "pop-3 not back"
sleep 5
no_failures "agent restarted"

# ---- 5. crash pop-1 (the whole node) ---------------------------------------------------------
reset_clients
sleep 3
docker kill clab-sentinel-pop-1 >/dev/null
t0=$(date +%s)
wait_until 20 served_elsewhere 1 && pass "pop-1 crashed: region 1 failed over to $(anycast_via 1) in $(($(date +%s) - t0)) s" ||
	fail "region 1 still routes to pop-1"
sleep 10
p=$(bot_pop 1 5)
[ -n "$p" ] && [ "$p" != pop-1 ] && pass "bot-1's traffic moved to $p" || fail "bot-1 still at ${p:-?}"
bad=0 tot=0
for c in 1 2 3; do bad=$((bad + $(client_failures "$c"))); tot=$((tot + $(client_total "$c"))); done
note "requests failed during the crash: $bad of $tot (outage bounded by link-down detection)"
recent_ok() { for c in 1 2 3; do dexec "client-$c" sh -c 'tail -n 10 /tmp/http.log | grep -cv "^200$" | grep -qx 0' || return 1; done; }
recent_ok && pass "service fully restored after the crash (last 10 requests of every client OK)" ||
	fail "requests still failing after the crash"
[ "$bad" -le 30 ] && pass "crash outage short ($bad failed requests, about 5 per client-second)" ||
	fail "crash outage too long: $bad failed requests"

echo "$((CHECKS - FAILS))/$CHECKS checks passed"
if [ "$FAILS" -gt 0 ]; then
	for f in "$S"/logs/*.log; do echo "---- $(basename "$f")"; tail -5 "$f"; done
fi
[ "$FAILS" -eq 0 ]
