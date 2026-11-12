#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# The whole platform without the web app: a customer signs up through the
# API, gets a protected IP, runs the generated tunnel script, and real
# traffic reaches their server through the PoP. Policy and rules changed
# through the API reach the PoP via PostgreSQL -> outbox -> NATS KV -> agent,
# and the API reports "active on 1 of 1 PoPs" from the agent's acks.
#
# Env: see lib.sh and nats_lab.sh, plus API (sentinel-api), PGSH (tests/api/pg.sh).
set -euo pipefail
source "$(dirname "$0")/lib.sh"
source "$(dirname "$0")/nats_lab.sh"
: "${API:?set API}" "${PGSH:?set PGSH}"

EMAIL=customer@e2e.test
PW="correct horse battery"

# ---- infrastructure: lab, NATS, agent, PostgreSQL, API ----------------------------
nats_prepare
lab_net
nats_start
nats_record config.ack.lab1
agent_config
start_agent
wait_for "$WORK/agent.log" "in sync" 10 || { fail "agent not in sync"; cat "$WORK/agent.log"; }

PGD=$(mktemp -d /tmp/sentinel-pg.XXXXXX)
PGURL=$("$PGSH" start "$PGD")
CLEANUP_CMDS+=("'$PGSH' stop '$PGD'; rm -rf '$PGD'")
cat >"$WORK/api.toml" <<CFG
[server]
listen = "127.0.0.1:8080"
public_url = "http://portal.lab"
cookie_secure = false
[anycast]
prefix4 = "198.51.100.0/24"
tunnel_ep4 = "$TUNNEL_EP"
[mail]
mode = "file"
dir = "$WORK/mail"
from = "noreply@lab"
[nats]
url = "$URL"
ca = "$N/ca.pem"
nkey_seed_file = "$N/api.nk"
CFG
SENTINEL_DATABASE_OWNER_URL="$PGURL" "$API" migrate --config "$WORK/api.toml" >/dev/null
"$PGSH" sql "$PGD" "ALTER ROLE sentinel_api LOGIN"
SENTINEL_DATABASE_URL=${PGURL/postgres@/sentinel_api@} \
SENTINEL_DATA_KEY=$(head -c 32 /dev/urandom | base64) \
	ip netns exec "$NS_B" "$API" serve --config "$WORK/api.toml" >"$WORK/api.log" 2>&1 &
BG_PIDS+=($!)
for _ in $(seq 50); do inb ss -Hltn "sport = :8080" | grep -q . && break; sleep 0.1; done
pass "PostgreSQL, API, NATS and agent running"

# ---- API client (curl in the PoP namespace, cookie jar + CSRF) ----------------------
CSRF=""
api() { # api METHOD PATH [JSON] -> body on stdout, HTTP status in $WORK/status
	local args=(-s -o "$WORK/body" -w '%{http_code}' -X "$1" -b "$WORK/jar" -c "$WORK/jar"
		-H "content-type: application/json")
	[ -n "$CSRF" ] && args+=(-H "x-csrf-token: $CSRF")
	[ $# -ge 3 ] && args+=(--data "$3")
	inb curl "${args[@]}" "http://127.0.0.1:8080/api/v1$2" >"$WORK/status"
	cat "$WORK/body"
}
code() { cat "$WORK/status"; }
mail_token() { jq -r .body "$(ls "$WORK"/mail/*.json | sort | tail -1)" | sed 's/.*token=\([^ ]*\).*/\1/'; }
totp() { # totp <base32 secret> [steps ahead]
	python3 - "$@" <<'PY'
import base64, hashlib, hmac, struct, sys, time
s = sys.argv[1]; k = base64.b32decode(s + "=" * (-len(s) % 8))
c = int(time.time()) // 30 + (int(sys.argv[2]) if len(sys.argv) > 2 else 0)
h = hmac.new(k, struct.pack(">Q", c), hashlib.sha1).digest(); o = h[-1] & 15
print("%06d" % ((struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 1000000))
PY
}
# wait_applied <tid> <aid> <min version>: the agent acked it
wait_applied() {
	local i st
	for i in $(seq 50); do
		st=$(api GET "/tenants/$1/assets/$2/status")
		if [ "$(jq -r '.pops_applied' <<<"$st")" = 1 ] &&
			[ "$(jq -r '.pops[0].version // 0' <<<"$st")" -ge "$3" ]; then
			return 0
		fi
		sleep 0.2
	done
	echo "     | status: $st"
	return 1
}

# ---- onboarding through the API --------------------------------------------------------
api POST /auth/signup "{\"email\":\"$EMAIL\",\"password\":\"$PW\",\"tenant_name\":\"Example\"}" >/dev/null
[ "$(code)" = 202 ] && pass "signup accepted" || fail "signup: $(code)"
api POST /auth/verify-email "{\"token\":\"$(mail_token)\"}" >/dev/null
[ "$(code)" = 200 ] && pass "email verified with the mailed token" || fail "verify: $(code)"
CSRF=$(api POST /auth/login "{\"email\":\"$EMAIL\",\"password\":\"$PW\"}" | jq -r .csrf_token)
[ "$(code)" = 200 ] && pass "logged in" || fail "login: $(code)"
TID=$(api GET /me | jq -r '.tenants[0].id')

asset=$(api POST "/tenants/$TID/assets" '{"origin_ip":"192.0.2.10","services":[{"proto":"tcp","port":80}]}')
[ "$(code)" = 201 ] && pass "asset created" || fail "create asset: $(code) $asset"
AID=$(jq -r .id <<<"$asset")
PROTECTED=$(jq -r .protected_prefix <<<"$asset" | cut -d/ -f1)
V1=$(jq -r .config_version <<<"$asset")
echo "     | protected IP $PROTECTED (asset $AID, version $V1)"
wait_applied "$TID" "$AID" "$V1" && pass "status: active on 1 of 1 PoPs (from the agent's ack)" \
	|| fail "asset not applied on the PoP"

# The customer runs the generated script (tunl0 on Docker Desktop).
dev=${SENTINEL_TEST_TUNNEL_DEV:+&device=$SENTINEL_TEST_TUNNEL_DEV}
api GET "/tenants/$TID/assets/$AID/tunnel?return=tunnel$dev" >"$WORK/tunnel.sh"
[ "$(code)" = 200 ] && pass "tunnel script from the API" || fail "tunnel script: $(code)"
inc sh "$WORK/tunnel.sh" up >/dev/null
ip netns exec "$NS_C" python3 "$HERE/http_origin.py" "$PROTECTED" 80 >"$WORK/http.log" 2>&1 &
HTTP_PID=$!
for _ in $(seq 50); do inc ss -Hltn "sport = :80" | grep -q . && break; sleep 0.1; done
http_ok 5 && pass "client reaches the customer's server through the PoP" || fail "HTTP failed"
grep -q "^$CLIENT " "$WORK/http.log" && pass "the origin sees the real client IP" || fail "client IP not seen"

# ---- policy through the API: 2FA, then mitigate + services --------------------------------
SECRET=$(api POST /auth/2fa/setup | jq -r .secret)
api POST /auth/2fa/enable "{\"code\":\"$(totp "$SECRET")\"}" >/dev/null
[ "$(code)" = 200 ] && pass "2FA enabled" || fail "2FA enable: $(code)"
pol='{"mode":"mitigate","syncookies":false,"enforce_services":true,"fragments":"drop","pps_per_src":0,"burst":0,"services":[{"proto":"tcp","port":80}]}'
V2=$(api PUT "/tenants/$TID/assets/$AID/policy" "$pol" | jq -r .config_version)
[ "$(code)" = 200 ] && pass "mitigate enabled through the API" || fail "policy: $(code)"
wait_applied "$TID" "$AID" "$V2" && pass "new policy version applied on the PoP" || fail "policy not applied"
http_ok 3 && pass "tcp/80 still served" || fail "tcp/80 broken after policy"
before=$(count drop_service)
gen udp --dst "$PROTECTED" --dport 53 --src 203.0.113.60/32 --count 50 >/dev/null
sleep 0.3
[ $(($(count drop_service) - before)) -ge 25 ] && pass "udp/53 dropped at the PoP" || fail "udp/53 not dropped"

# ---- rules through the API ---------------------------------------------------------------
rule=$(api POST "/tenants/$TID/rules" "{\"kind\":\"block\",\"prefix\":\"$CLIENT/32\",\"ttl_seconds\":600}")
[ "$(code)" = 201 ] && pass "block rule created" || fail "rule: $(code) $rule"
wait_for "$N/sub-config.ack.lab1.log" "\"key\":\"tenant.$TID\".*\"ok\":true" 10 \
	&& pass "the PoP acknowledged the rule" || fail "no rule ack"
http_ok 2 && fail "blocked client still connects" || pass "block rule enforced at the PoP"
api DELETE "/tenants/$TID/rules/$(jq -r .id <<<"$rule")" >/dev/null
for _ in $(seq 30); do http_ok 1 && break; sleep 0.2; done
http_ok 3 && pass "deleting the rule lifts the block" || fail "still blocked"

st=$(inb curl -s http://127.0.0.1:8080/api/v1/status)
[ "$(jq -r '.pops[0].id + "/" + .pops[0].status' <<<"$st")" = lab1/up ] \
	&& pass "public status shows the PoP up" || fail "status: $st"

if [ "$FAILS" -gt 0 ]; then
	echo "---- api log"; tail -20 "$WORK/api.log"
	echo "---- agent log"; tail -20 "$WORK/agent.log"
fi
finish
