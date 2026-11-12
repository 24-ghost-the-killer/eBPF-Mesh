#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Phase 6 "done when": the whole onboarding flow works in the browser. This
# brings up the full lab (PoP with XDP + agent, NATS, PostgreSQL, API), the
# web app behind the same-origin edge proxy, and runs the Playwright tests in
# tests/e2e with Chromium in the PoP namespace. The tests act on the lab
# (run the tunnel script on the customer server, send client traffic) through
# a hook script written below; it only touches this lab's namespaces.
#
# Env: see lib.sh and nats_lab.sh, plus API, PGSH, and optionally
# E2E_GREP (Playwright --grep).
set -euo pipefail
source "$(dirname "$0")/lib.sh"
source "$(dirname "$0")/nats_lab.sh"
: "${API:?set API}" "${PGSH:?set PGSH}" "${WORKER:?set WORKER}"
for tool in node pnpm; do
	command -v "$tool" >/dev/null || { echo "missing $tool (use make docker-test-web)" >&2; exit 1; }
done
REPO="$(cd "$HERE/../.." && pwd)"
PORTAL=http://localhost:3000

# ---- lab, NATS, agent ---------------------------------------------------------------------
nats_prepare
lab_net
# A PoP has a default route; the agent's tunnel probes need it to reach origins.
ip -n "$NS_B" route add default via "$ROUTER_IP"
nats_start
agent_config
worker_config
# Lab bots share a /24 with the test client: never aggregate to /24 here.
printf 'aggregate_min_sources = 64\n' >>"$WORK/worker.toml"
start_agent
wait_for "$WORK/agent.log" "in sync" 10 || { fail "agent not in sync"; cat "$WORK/agent.log"; }

# ---- PostgreSQL + API -------------------------------------------------------------------------
PGD=$(mktemp -d /tmp/sentinel-pg.XXXXXX)
PGURL=$("$PGSH" start "$PGD")
CLEANUP_CMDS+=("'$PGSH' stop '$PGD'; rm -rf '$PGD'")
mkdir -p "$WORK/mail"
chmod 755 "$WORK" "$WORK/mail"
cat >"$WORK/api.toml" <<CFG
[server]
listen = "127.0.0.1:8080"
public_url = "$PORTAL"
cookie_secure = true          # browsers treat http://localhost as secure
trust_proxy = true            # behind the edge proxy
status_page_origins = ["http://localhost:3100"]
[webhooks]
allow_http = true             # lab: the webhook sink is plain HTTP on loopback
allow_private_targets = true
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
SENTINEL_DECISION_KEY=$(head -c 32 /dev/urandom | base64) \
	ip netns exec "$NS_B" "$API" serve --config "$WORK/api.toml" >"$WORK/api.log" 2>&1 &
BG_PIDS+=($!)
for _ in $(seq 50); do inb ss -Hltn "sport = :8080" | grep -q . && break; sleep 0.1; done
# Trust the worker's decisions (the API publishes the key to the PoPs).
SENTINEL_DATABASE_URL=${PGURL/postgres@/sentinel_api@} \
	"$API" signing-key --config "$WORK/api.toml" add --issuer worker-1 --public-key "$WORKER_PUB" >/dev/null
start_worker
ip netns exec "$NS_B" python3 "$HERE/webhook_sink.py" 127.0.0.1 9999 "$WORK/webhooks.log" &
BG_PIDS+=($!)

# ---- web app + edge proxy (in the PoP namespace, next to the API) -----------------------------
(cd "$REPO" && pnpm install --frozen-lockfile ${PNPM_STORE_DIR:+--store-dir "$PNPM_STORE_DIR"} >"$WORK/pnpm.log" 2>&1) || { cat "$WORK/pnpm.log"; exit 1; }
(cd "$REPO/web" && pnpm build >"$WORK/web-build.log" 2>&1) || { tail -40 "$WORK/web-build.log"; exit 1; }
(cd "$REPO/tests/e2e" && pnpm exec playwright install chromium >"$WORK/pw-install.log" 2>&1) ||
	{ tail -20 "$WORK/pw-install.log"; exit 1; }
cd "$REPO/web"
nsenter --net="/run/netns/$NS_B" pnpm exec next start --hostname 127.0.0.1 --port 3001 >"$WORK/web.log" 2>&1 &
BG_PIDS+=($!)
EDGE_LISTEN=127.0.0.1:3000 API_ORIGIN=http://127.0.0.1:8080 WEB_ORIGIN=http://127.0.0.1:3001 \
	nsenter --net="/run/netns/$NS_B" node scripts/edge.mjs >"$WORK/edge.log" 2>&1 &
BG_PIDS+=($!)
cd "$REPO"
for _ in $(seq 100); do
	inb curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:3000/login 2>/dev/null | grep -q 200 && break
	sleep 0.2
done
inb curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:3000/login | grep -q 200 &&
	pass "PostgreSQL, API, NATS, agent, web app and edge proxy running" ||
	{ fail "web app not reachable"; tail -20 "$WORK/web.log" "$WORK/edge.log"; finish; }

# ---- the separately hosted status page (static files on another origin) ------------------
cp -R "$REPO/status-page" "$WORK/status-page"
cat >"$WORK/status-page/config.js" <<JS
window.SENTINEL_STATUS = { api: "$PORTAL/api/v1/status", portal: "$PORTAL", refreshSeconds: 5 };
JS
cat >"$WORK/status-page/incidents.json" <<JSON
[{"date": "2026-01-01", "title": "Lab maintenance", "status": "resolved", "text": "Example incident for the tests."}]
JSON
nsenter --net="/run/netns/$NS_B" python3 -m http.server 3100 --bind 127.0.0.1 \
	--directory "$WORK/status-page" >"$WORK/status-page.log" 2>&1 &
BG_PIDS+=($!)

# ---- hook for the browser tests -------------------------------------------------------------
HOOK="$WORK/lab-hook.sh"
cat >"$HOOK" <<HOOK
#!/usr/bin/env bash
# Lab actions for tests/e2e (generated by portal_e2e.sh for this lab only).
set -euo pipefail
case "\$1" in
origin-up) # <tunnel script> <protected ip>: the customer runs the script, starts a web server
	ip netns exec "$NS_C" sh "\$2" up >/dev/null
	ip netns exec "$NS_C" python3 "$HERE/http_origin.py" "\$3" 80 >>"$WORK/http.log" 2>&1 &
	echo \$! >>"$WORK/hook.pids"
	for _ in \$(seq 50); do ip netns exec "$NS_C" ss -Hltn "sport = :80" | grep -q . && exit 0; sleep 0.1; done
	exit 1 ;;
http-ok) # <protected ip>: a client request through the PoP succeeds
	[ "\$(ip netns exec "$NS_A" curl -sS --interface "$CLIENT" --max-time 2 "http://\$2/" 2>/dev/null)" = sentinel-ok ] ;;
flood) # <protected ip> <udp port> <seconds>: UDP flood from 8 lab bots (203.0.113.64/29)
	ip netns exec "$NS_A" "$GEN" udp --dst "\$2" --dport "\$3" --src 203.0.113.64/29 --pps 4000 \
		--payload 400 --duration "\$4s" >/dev/null 2>&1 </dev/null &
	echo \$! >>"$WORK/hook.pids" ;;
drops) # packets dropped by block rules at the PoP so far
	SENTINEL_PIN_DIR="$SENTINEL_PIN_DIR" nsenter --net="/run/netns/$NS_B" "$CTL" --json stats |
		jq -r '[.entries[] | select(.verdict == "drop_block") | .pkts] | add // 0' ;;
udp-rx) # UDP datagrams that reached the customer server (delivered or no port)
	ip netns exec "$NS_C" awk '/^Udp:/ { if (!n) { for (i = 1; i <= NF; i++) { if (\$i == "InDatagrams") a = i; if (\$i == "NoPorts") b = i }; n = 1 } else print \$a + \$b }' /proc/net/snmp ;;
operator) # <email>: a platform administrator without any tenant (as on a fresh install)
	SENTINEL_DATABASE_URL="${PGURL/postgres@/sentinel_api@}" SENTINEL_ADMIN_PASSWORD="\$3" \
		"$API" create-admin --config "$WORK/api.toml" --email "\$2" >/dev/null ;;
promote) # <email>: make the user a platform administrator
	"$PGSH" sql "$PGD" "UPDATE users SET is_platform_admin = true WHERE email = '\$2'" >/dev/null ;;
webhooks) # what the webhook sink received (JSON lines)
	cat "$WORK/webhooks.log" 2>/dev/null || true ;;
traffic) # <protected ip> <seconds>: background client requests
	(end=\$((SECONDS + \$3)); while [ \$SECONDS -lt \$end ]; do
		ip netns exec "$NS_A" curl -s --interface "$CLIENT" --max-time 1 "http://\$2/" >/dev/null 2>&1 || true
		sleep 0.05
	done) >/dev/null 2>&1 </dev/null &
	echo \$! >>"$WORK/hook.pids" ;;
*) echo "unknown action \$1" >&2; exit 2 ;;
esac
HOOK
chmod +x "$HOOK"
CLEANUP_CMDS+=("[ -f '$WORK/hook.pids' ] && xargs -r kill <'$WORK/hook.pids' 2>/dev/null")

# ---- Playwright -----------------------------------------------------------------------------------
E2E_OUT="$WORK/e2e-results"
set +e
(cd "$REPO/tests/e2e" &&
	PORTAL_URL="$PORTAL" STATUS_PAGE_URL=http://localhost:3100 MAIL_DIR="$WORK/mail" LAB_HOOK="$HOOK" E2E_OUT="$E2E_OUT" \
	LAB_ORIGIN="$ORIGIN" LAB_CLIENT="$CLIENT" TUNNEL_DEV="${SENTINEL_TEST_TUNNEL_DEV:-}" \
	nsenter --net="/run/netns/$NS_B" pnpm exec playwright test ${E2E_GREP:+--grep "$E2E_GREP"} 2>&1 |
	tee "$WORK/playwright.log")
rc=${PIPESTATUS[0]}
set -e
summary=$(grep -E "^\s+[0-9]+ (passed|failed|flaky|skipped)" "$WORK/playwright.log" | tr -s ' ' | xargs || true)
[ "$rc" -eq 0 ] && pass "Playwright: $summary" || fail "Playwright: ${summary:-exit $rc}"

if [ "$FAILS" -gt 0 ]; then
	echo "---- api log"; tail -30 "$WORK/api.log"
	echo "---- agent log"; tail -20 "$WORK/agent.log"
	echo "---- web log"; tail -20 "$WORK/web.log"
	echo "---- worker log"; tail -20 "$WORK/worker.log"
	if [ -n "${E2E_ARTIFACTS:-}" ] && [ -d "$E2E_OUT" ]; then
		mkdir -p "$E2E_ARTIFACTS" && cp -R "$E2E_OUT"/. "$E2E_ARTIFACTS"/ &&
			echo "     | traces and screenshots in $E2E_ARTIFACTS"
	fi
fi
finish
