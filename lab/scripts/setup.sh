#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Generates the lab's secrets and configuration into lab/state (git-ignored):
# NATS CA, certificate and nkeys (one user per component), worker signing
# keys, database and ClickHouse passwords, and the configs of the agents,
# the API and the workers. Paths are as the lab nodes see them (/lab/state).
#
# Env: AGENT, WORKER (binaries, for key generation), RENDER (render-config.py).
set -euo pipefail
: "${AGENT:?set AGENT}" "${WORKER:?set WORKER}" "${RENDER:?set RENDER}"
LAB="$(cd "$(dirname "$0")/.." && pwd)"
S="$LAB/state"
IN=/lab/state                   # the same directory inside the nodes
NATS_IP=172.31.250.10 PG_IP=172.31.250.11 CH_IP=172.31.250.12 API_IP=172.31.250.13

rm -rf "$S"
mkdir -p "$S"/{nats,agents,workers,logs,mail}
chmod 777 "$S/logs" "$S/mail"
secret() { head -c 24 /dev/urandom | base64 | tr -d '/+=' | head -c 32; }

# ---- NATS: CA, server certificate, nkeys, server config ------------------------------------
N="$S/nats"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 7 \
	-keyout "$N/ca.key" -out "$N/ca.pem" -subj "/CN=sentinel-lab-ca" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
	-keyout "$N/server.key" -out "$N/server.csr" -subj "/CN=nats" 2>/dev/null
printf 'subjectAltName=IP:%s,DNS:nats\n' "$NATS_IP" >"$N/san.ext"
openssl x509 -req -in "$N/server.csr" -CA "$N/ca.pem" -CAkey "$N/ca.key" -CAcreateserial \
	-days 7 -extfile "$N/san.ext" -out "$N/server.pem" 2>/dev/null
chmod 644 "$N"/*.key
args=()
for u in admin api; do
	pub=$("$AGENT" nkey generate --out "$N/$u.nk")
	case $u in admin) args+=(--admin "$pub") ;; api) args+=(--api "$pub") ;; esac
done
for p in 1 2 3; do args+=(--pop "pop-$p=$("$AGENT" nkey generate --out "$N/pop-$p.nk")"); done
for w in 1 2; do args+=(--worker "worker-$w=$("$WORKER" nkey generate --out "$N/worker-$w.nk")"); done
chmod 644 "$N"/*.nk
python3 "$RENDER" --listen 0.0.0.0:4222 --cert "$IN/nats/server.pem" --key "$IN/nats/server.key" \
	--store /var/lib/nats "${args[@]}" >"$N/server.json"

# ---- passwords -----------------------------------------------------------------------------
secret >"$S/postgres.password"
secret >"$S/api-db.password"
CH_ADMIN=$(secret) CH_WORKER=$(secret) CH_API=$(secret)
printf 'CLICKHOUSE_USER=admin\nCLICKHOUSE_PASSWORD=%s\nCLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1\n' \
	"$CH_ADMIN" >"$S/clickhouse.env"
printf '%s\n%s\n' "$CH_WORKER" "$CH_API" >"$S/clickhouse.users"
cat >"$S/clickhouse-users.sql" <<SQL
CREATE USER IF NOT EXISTS sentinel_worker IDENTIFIED WITH sha256_password BY '$CH_WORKER';
-- The view traffic_1m_mv runs with the inserting user's rights: the worker
-- also reads the rows it inserts (SELECT on flows) and writes traffic_1m.
GRANT SELECT, INSERT ON sentinel.flows TO sentinel_worker;
GRANT INSERT ON sentinel.traffic_1m TO sentinel_worker;
CREATE USER IF NOT EXISTS sentinel_api IDENTIFIED WITH sha256_password BY '$CH_API' SETTINGS readonly = 1;
GRANT SELECT ON sentinel.traffic_1m TO sentinel_api;
SQL

# ---- PoP agents -----------------------------------------------------------------------------
for p in 1 2 3; do
	cat >"$S/agents/pop-$p.toml" <<CFG
[pop]
id = "pop-$p"
region = "region-$p"
iface = "eth1"
pop_ip4 = "10.10.$p.2"
tunnel_ep4 = "198.51.100.1"
[xdp]
object = "/opt/sentinel/xdp_main.o"
pin_dir = "/sys/fs/bpf/sentinel"
[nats]
url = "tls://$NATS_IP:4222"
ca = "$IN/nats/ca.pem"
nkey_seed_file = "$IN/nats/pop-$p.nk"
[telemetry]
shards = 4
sample_base = 1
target_events_per_sec = 50000
[agent]
heartbeat_file = "/run/sentinel/heartbeat"
metrics_listen = "127.0.0.1:9466"
health_interval_s = 2
gc_interval_s = 5
[bird]
drain_file = "/etc/bird/drain.conf"
birdc = "birdc"
socket = "/run/bird/bird.ctl"
CFG
done

# ---- workers ----------------------------------------------------------------------------------
for w in 1 2; do
	"$WORKER" key generate --out "$S/workers/worker-$w.key" >"$S/workers/worker-$w.pub"
	cat >"$S/workers/worker-$w.toml" <<CFG
[worker]
id = "worker-$w"
signing_key_file = "$IN/workers/worker-$w.key"
shards = 4
[nats]
url = "tls://$NATS_IP:4222"
ca = "$IN/nats/ca.pem"
nkey_seed_file = "$IN/nats/worker-$w.nk"
[clickhouse]
url = "http://$CH_IP:8123"
user = "sentinel_worker"
batch_rows = 2000
CFG
done
chmod 644 "$S"/workers/*.key
printf 'SENTINEL_CLICKHOUSE_PASSWORD=%s\n' "$CH_WORKER" >"$S/worker.env"

# ---- API ----------------------------------------------------------------------------------------
cat >"$S/api.toml" <<CFG
[server]
listen = "0.0.0.0:8080"
public_url = "http://$API_IP:8080"
cookie_secure = false         # plain HTTP inside the lab only
[anycast]
prefix4 = "198.51.100.0/24"
tunnel_ep4 = "198.51.100.1"
[mail]
mode = "file"
dir = "$IN/mail"
from = "noreply@lab"
[webhooks]
allow_http = true
allow_private_targets = true
[clickhouse]
url = "http://$CH_IP:8123"
user = "sentinel_api"
[nats]
url = "tls://$NATS_IP:4222"
ca = "$IN/nats/ca.pem"
nkey_seed_file = "$IN/nats/api.nk"
CFG
PG=$(cat "$S/postgres.password")
API_DB=$(cat "$S/api-db.password")
cat >"$S/api.env" <<ENV
SENTINEL_DATABASE_OWNER_URL=postgres://postgres:$PG@$PG_IP/sentinel
SENTINEL_DATABASE_URL=postgres://sentinel_api:$API_DB@$PG_IP/sentinel
SENTINEL_DATA_KEY=$(head -c 32 /dev/urandom | base64)
SENTINEL_CLICKHOUSE_PASSWORD=$CH_API
SENTINEL_DECISION_KEY=$(head -c 32 /dev/urandom | base64)
ENV
chmod -R a+rX "$S"
echo "lab state in $S"
