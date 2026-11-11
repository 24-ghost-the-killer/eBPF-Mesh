#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Phase 10a: the control-plane stack (deploy/compose) from scratch on a
# Docker host: secrets generated, images built, everything started, then:
# TLS + security headers, portal and API through Caddy, CORS for the status
# page, signup through the API (database + RLS), NATS buckets, workers,
# ClickHouse users, Prometheus and Grafana (dashboard provisioned), backups.
# Uses its own state and ports; refuses to run if deploy/compose/state exists.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
C="$REPO/deploy/compose"
S="$C/state"
[ -e "$S" ] && { echo "deploy/compose/state exists: refusing (it may hold real secrets)" >&2; exit 1; }
CHECKS=0 FAILS=0
pass() { CHECKS=$((CHECKS + 1)); echo "ok   $*"; }
fail() { CHECKS=$((CHECKS + 1)); FAILS=$((FAILS + 1)); echo "FAIL $*"; }
dc() { docker compose -f "$C/docker-compose.yml" --env-file "$S/.env" "$@"; }
cleanup() { dc down -v --remove-orphans >/dev/null 2>&1 || true; rm -rf "$S"; }
trap cleanup EXIT
wait_until() { local t=$1; shift; for _ in $(seq $((t * 2))); do "$@" >/dev/null 2>&1 && return 0; sleep 0.5; done; return 1; }
B=https://localhost:18443

mkdir -p "$S"
sed -e 's/^PORTAL_DOMAIN=.*/PORTAL_DOMAIN=localhost/' -e 's/^TLS_ISSUER=.*/TLS_ISSUER=internal/' \
	-e 's/^HTTPS_PORT=.*/HTTPS_PORT=18443/' -e 's/^NATS_PORT=.*/NATS_PORT=14222/' \
	-e 's/^SENTINEL_POPS=.*/SENTINEL_POPS=smoke1/' -e 's|^STATUS_PAGE_ORIGIN=.*|STATUS_PAGE_ORIGIN=https://status.test|' \
	"$C/.env.example" >"$S/.env"
echo "HTTP_PORT=18080" >>"$S/.env"
"$C/scripts/init.sh" >/dev/null && pass "secrets and configs generated" || { fail "init.sh"; exit 1; }
[ "$(stat -c %a "$S" 2>/dev/null || stat -f %Lp "$S")" = 700 ] && pass "state directory is private (700)" || fail "state permissions"
"$C/scripts/init.sh" >/dev/null 2>&1 && fail "init.sh overwrote existing secrets" || pass "init.sh refuses to overwrite secrets"

dc up -d --build >/dev/null 2>&1 || { fail "compose up"; dc logs --tail 20; exit 1; }
wait_until 240 curl -skf "$B/api/v1/status" && pass "API answers through Caddy (TLS)" || { fail "API via Caddy"; dc logs --tail 30 api caddy bootstrap; }
[ "$(dc ps -a --format '{{.Service}} {{.ExitCode}}' | awk '$1 == "bootstrap" { print $2 }')" = 0 ] &&
	pass "bootstrap: migrations and worker keys" || fail "bootstrap"
wait_until 60 sh -c "docker compose -f '$C/docker-compose.yml' --env-file '$S/.env' logs nats-init | grep -q 'KV buckets ready'" &&
	pass "NATS KV buckets created" || fail "nats-init"

h=$(curl -sk -D - -o "$S/home.html" "$B/")
grep -q "DDoS protection" "$S/home.html" && pass "public site served" || fail "home page"
grep -qi "^strict-transport-security: max-age=" <<<"$h" && pass "HSTS on HTTPS" || fail "no HSTS"
grep -qi "^content-security-policy: .*'nonce-" <<<"$h" && pass "CSP with nonce" || fail "no CSP"
grep -qi "^x-frame-options: DENY" <<<"$h" && pass "X-Frame-Options" || fail "no X-Frame-Options"
curl -sk -o /dev/null -w '%{http_code}' -H 'content-type: application/json' \
	--data '{"email":"smoke@example.org","password":"correct horse battery","tenant_name":"Smoke"}' \
	"$B/api/v1/auth/signup" | grep -q 202 && pass "signup through the API (database, RLS)" || fail "signup"
curl -sk -D - -o /dev/null -H "Origin: https://status.test" "$B/api/v1/status" |
	grep -qi "^access-control-allow-origin: https://status.test" && pass "status page origin may read /status" || fail "CORS"

wait_until 60 sh -c "docker compose -f '$C/docker-compose.yml' --env-file '$S/.env' logs worker-1 worker-2 | grep -c 'worker running' | grep -qx 2" &&
	pass "both workers running" || fail "workers"
wait_until 60 sh -c "docker compose -f '$C/docker-compose.yml' --env-file '$S/.env' logs api | grep -q 'nats: connected'" &&
	pass "API connected to NATS (TLS, own user)" || fail "API NATS"
CH_ADMIN=$(grep ^CLICKHOUSE_PASSWORD= "$S/clickhouse.env" | cut -d= -f2)
users=$(dc exec -T clickhouse clickhouse-client --user admin --password "$CH_ADMIN" -q "SHOW USERS" 2>/dev/null | tr '\n' ' ')
grep -q sentinel_worker <<<"$users" && grep -q sentinel_api <<<"$users" && pass "ClickHouse least-privilege users" || fail "ClickHouse users: $users"

wait_until 60 dc exec -T prometheus wget -qO- http://localhost:9090/-/ready && pass "Prometheus ready" || fail "Prometheus"
wait_until 60 sh -c "docker compose -f '$C/docker-compose.yml' --env-file '$S/.env' exec -T prometheus wget -qO- 'http://localhost:9090/api/v1/targets' | grep -q '\"job\":\"caddy\".*\"health\":\"up\"\|\"health\":\"up\".*\"job\":\"caddy\"'" &&
	pass "Prometheus scrapes Caddy" || fail "Caddy target"
GF=$(grep ^GF_SECURITY_ADMIN_PASSWORD= "$S/grafana.env" | cut -d= -f2)
wait_until 90 curl -sf "http://admin:$GF@127.0.0.1:3001/api/search?query=Sentinel" &&
	curl -sf "http://admin:$GF@127.0.0.1:3001/api/search?query=Sentinel" | grep -q sentinel-pops &&
	pass "Grafana with the provisioned PoP dashboard" || fail "Grafana dashboard"
curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:3001/api/search" | grep -q 401 && pass "Grafana requires login" || fail "Grafana anonymous"

dump=$("$C/scripts/backup.sh" 2>/dev/null | head -1)
[ -s "$dump" ] && pass "PostgreSQL backup written" || fail "backup"
n=$("$C/scripts/backup.sh" --check "$dump" 2>/dev/null | tail -1)
[ "${n:-0}" -gt 5 ] 2>/dev/null && pass "backup restorable ($n tables listed by pg_restore)" || fail "backup check: $n"

echo "$((CHECKS - FAILS))/$CHECKS checks passed"
[ "$FAILS" -eq 0 ]
