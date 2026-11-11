#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Live policy changes with real traffic: rate limit, block/allow rules with
# TTL and gc, observe vs mitigate, allowed services, the global kill switch.
set -euo pipefail
source "$(dirname "$0")/lib.sh"

lab_up tunnel

# ---- rate limit -------------------------------------------------------------
ctl policy set --asset "$ASSET" --mitigate on --pps-per-src 100 --burst 100 >/dev/null
gen udp --dst "$PROTECTED" --dport 53 --src 203.0.113.50/32 --count 3000 >/dev/null
sleep 0.3
rl=$(count drop_ratelimit)
ok=$(count pass) # includes a few ICMP errors the origin and router send back
[ "$rl" -ge 2000 ] && pass "single-source flood rate limited ($rl dropped)" \
	|| fail "only $rl packets rate limited"
[ "$ok" -le 400 ] && pass "rate limit let through about the burst ($ok passed)" \
	|| fail "$ok packets passed the rate limit"
ctl policy set --asset "$ASSET" --pps-per-src 0 >/dev/null
http_ok && pass "other source unaffected by the rate limit" || fail "HTTP failed"

# ---- block / allow ------------------------------------------------------------
ctl block add "$CLIENT/32" --ttl 1m >/dev/null
http_ok 2 && fail "HTTP worked although the client is blocked" \
	|| pass "blocked client cannot connect"
[ "$(count drop_block)" -ge 1 ] && pass "drop_block counted" || fail "no drop_block"
[ "$(ctl --json block list | jq -r '.[0].active')" = true ] && pass "block list shows the rule active" \
	|| fail "block list: $(ctl --json block list)"

ctl allow add "$CLIENT" >/dev/null
http_ok && pass "allowlist beats blocklist" || fail "allowlisted client blocked"
ctl allow del "$CLIENT" >/dev/null
http_ok 2 && fail "still allowed after allow del" || pass "allow del takes effect"
ctl block del "$CLIENT/32" >/dev/null
http_ok && pass "block del takes effect" || fail "still blocked after block del"

# ---- observe vs mitigate ------------------------------------------------------
ctl block add "$CLIENT/32" --ttl 1m >/dev/null
ctl policy set --asset "$ASSET" --mitigate off >/dev/null
before=$(count drop_block)
http_ok && pass "observe mode: blocked client still connects" || fail "observe mode dropped"
[ "$(count drop_block)" -gt "$before" ] && pass "observe mode: block verdicts still counted" \
	|| fail "observe mode: no block verdicts counted"
ctl policy set --asset "$ASSET" --mitigate on >/dev/null
ctl observe on >/dev/null
http_ok && pass "kill switch: mitigation suspended" || fail "kill switch did not suspend drops"
ctl observe off >/dev/null
http_ok 2 && fail "kill switch off: block not enforced" || pass "kill switch off: block enforced again"
ctl block del "$CLIENT/32" >/dev/null

# ---- TTL expiry inside XDP, then gc --------------------------------------------
ctl block add "$CLIENT/32" --ttl 2s >/dev/null
http_ok 1 && fail "2s block not enforced" || pass "short block enforced"
sleep 2.5
http_ok && pass "block expired inside XDP without userspace" || fail "expired block still dropping"
[ "$(ctl --json gc | jq .block)" -eq 1 ] && pass "gc removed the expired block" || fail "gc did not remove it"
[ "$(ctl --json block list | jq length)" -eq 0 ] && pass "block list empty after gc" || fail "rules left after gc"

# ---- allowed services -------------------------------------------------------------
ctl service add --asset "$ASSET" --proto tcp --port 80 >/dev/null
ctl policy set --asset "$ASSET" --enforce-services on >/dev/null
http_ok && pass "tcp/80 allowed" || fail "tcp/80 blocked"
before=$(count drop_service)
gen udp --dst "$PROTECTED" --dport 53 --src 203.0.113.60/32 --count 100 >/dev/null
sleep 0.3
[ $(($(count drop_service) - before)) -ge 50 ] && pass "udp/53 dropped (not an allowed service)" \
	|| fail "udp/53 not dropped"
[ "$(ctl --json service list | jq -r '.[0].proto + "/" + (.[0].port|tostring)')" = tcp/80 ] \
	&& pass "service list" || fail "service list: $(ctl --json service list)"

# ---- traffic to the PoP itself bypasses policy ------------------------------------
before=$(count pass_local)
ina ping -c 3 -i 0.05 -W 2 "$POP_IP" >/dev/null && pass "PoP unicast IP reachable despite services" \
	|| fail "ping to the PoP unicast IP failed"
[ $(($(count pass_local) - before)) -eq 3 ] && pass "counted as pass_local" || fail "pass_local not counted"

finish
