#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Signed decisions at the PoP (ADR 0021): the agent applies a decision only
# from a trusted, unrevoked issuer with a valid signature, a fresh timestamp
# and an unseen id; never over an allowlist; the block expires inside XDP;
# KV rule changes leave decision blocks alone; NATS permissions keep PoPs
# from issuing decisions.
#
# Env: see lib.sh and nats_lab.sh, plus WORKER (sentinel-worker: key
# generation and signing).
set -euo pipefail
source "$(dirname "$0")/lib.sh"
source "$(dirname "$0")/nats_lab.sh"
: "${WORKER:?set WORKER}"

nats_prepare
lab_net
nats_start
nats_record decision.global config.ack.lab1
agent_config
start_agent
wait_for "$WORK/agent.log" "in sync" 10 || { fail "agent not in sync"; cat "$WORK/agent.log"; }
admin kv put tenants asset.1 '{"v":1,"version":1,"asset":1,"tenant":1,"prefix":"198.51.100.10/32","origin":"192.0.2.10","policy":{"mode":"mitigate"}}' >/dev/null
wait_for "$N/sub-config.ack.lab1.log" '"key":"asset.1".*"ok":true' 5 || fail "asset.1 not applied"
origin_start tunnel
http_ok 5 && pass "PoP, agent and customer server up (mitigate mode)" || fail "HTTP failed"

PUB=$("$WORKER" key generate --out "$N/worker-1.key")
sign() { # sign <src> <ttl> [extra args]
	local src=$1 ttl=$2
	shift 2
	"$WORKER" sign --key "$N/worker-1.key" --issuer worker-1 --tenant 1 --src "$src" --ttl "$ttl" \
		--reason udp_flood "$@"
}
publish() { admin pub decision.global "$1" >/dev/null 2>&1; sleep 0.5; }
metric() { # metric <result>: sentinel_decisions_total for that outcome
	inb curl -s http://127.0.0.1:9466/metrics |
		awk -v r="result=\"$1\"" 'index($0, "sentinel_decisions_total{") == 1 && index($0, r) { print $2 }' |
		tail -1
}
keydoc() { # keydoc <revoked> <version>
	admin kv put keys issuer.worker-1 \
		"{\"v\":1,\"version\":$2,\"issuer\":\"worker-1\",\"public_key\":\"$PUB\",\"revoked\":$1}" >/dev/null
	sleep 0.5
}

# ---- trust --------------------------------------------------------------------------------
publish "$(sign "$CLIENT/32" 30)"
[ "$(metric unknown_issuer)" = 1 ] && pass "decision from an unknown issuer refused" \
	|| fail "unknown issuer: $(metric unknown_issuer)"
http_ok 2 && pass "nothing blocked" || fail "blocked by an untrusted decision"

keydoc false 1
D=$(sign "$CLIENT/32" 4)
publish "$D"
[ "$(metric applied)" = 1 ] && pass "signed decision from a trusted issuer applied" \
	|| { fail "not applied: $(metric applied)"; tail -5 "$WORK/agent.log"; }
http_ok 1 && fail "blocked client still connects" || pass "block enforced at the PoP"
ctl --json block list | jq -e '.[] | select(.reason == "decision")' >/dev/null \
	&& pass "xs_block entry carries reason decision" || fail "no decision entry in xs_block"

# KV reconcile (any change to the rules bucket) keeps the decision's block.
admin kv put rules tenant.1 '{"v":1,"version":2,"allow":[{"prefix":"192.0.2.0/24"}]}' >/dev/null
sleep 0.5
http_ok 1 && fail "KV reconcile removed the decision block" || pass "KV reconcile leaves decision blocks alone"

publish "$D"
[ "$(metric replay)" = 1 ] && pass "replayed decision refused" || fail "replay: $(metric replay)"

sleep 4
http_ok 3 && pass "block expired after its TTL (inside XDP)" || fail "still blocked after the TTL"

# ---- refusals -----------------------------------------------------------------------------
publish "$(sign "$CLIENT/32" 30 --ts $(($(now_ms) - 120000)))"
[ "$(metric stale)" = 1 ] && pass "stale decision refused" || fail "stale: $(metric stale)"
publish "$(sign "$CLIENT/32" 30 | sed 's|203.0.113.1/32|203.0.113.2/32|')"
[ "$(metric bad_signature)" = 1 ] && pass "tampered decision refused (bad signature)" \
	|| fail "tampered: $(metric bad_signature)"
publish "$(sign "$CLIENT/32" 30 | sed 's|"ttl_s":30|"ttl_s":0|')"
[ "$(metric invalid)" = 1 ] && pass "invalid decision refused" || fail "invalid: $(metric invalid)"
http_ok 2 && pass "no refused decision blocked anything" || fail "blocked after refusals"

admin kv put rules tenant.1 "{\"v\":1,\"version\":3,\"allow\":[{\"prefix\":\"$CLIENT/32\"}]}" >/dev/null
sleep 0.5
publish "$(sign 203.0.113.0/24 30)"
[ "$(metric skipped_allowlisted)" = 1 ] && pass "decision overlapping an allowlist skipped" \
	|| fail "allowlist: $(metric skipped_allowlisted)"
admin kv del rules tenant.1 --force >/dev/null
sleep 0.5
http_ok 2 && pass "allowlisted client unaffected" || fail "allowlisted client blocked"

keydoc true 4
publish "$(sign "$CLIENT/32" 30)"
[ "$(metric revoked_issuer)" = 1 ] && pass "decision from a revoked issuer refused" \
	|| fail "revoked: $(metric revoked_issuer)"
http_ok 2 && pass "revoked issuer blocked nothing" || fail "revoked issuer blocked"

# ---- NATS permissions ------------------------------------------------------------------------
# A publish without permission is dropped by the server: look for markers.
natsc "$N/lab1.nk" pub decision.global '{"marker":"from-pop"}' >/dev/null 2>&1 || true
natsc "$N/worker-1.nk" pub decision.global '{"marker":"from-worker"}' >/dev/null 2>&1 || true
wait_for "$N/sub-decision.global.log" 'from-worker' 3 && pass "the worker may publish decisions" \
	|| fail "worker cannot publish decisions"
grep -q 'from-pop' "$N/sub-decision.global.log" && fail "a PoP could publish decisions" \
	|| pass "PoP credentials cannot publish decisions"
natsc "$N/worker-1.nk" kv put keys issuer.evil '{}' >/dev/null 2>&1 \
	&& fail "a worker could write the keys bucket" || pass "worker credentials cannot write KV"

[ "$FAILS" -gt 0 ] && tail -20 "$WORK/agent.log"
finish
