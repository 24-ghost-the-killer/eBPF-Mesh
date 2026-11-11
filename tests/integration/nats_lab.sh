# SPDX-License-Identifier: MIT OR Apache-2.0
# NATS + agent on top of lib.sh (source after lib.sh). NATS runs on the PoP
# namespace's loopback with TLS (lab CA) and one nkey user per component.
#
# Env: AGENT (sentinel-agent), RENDER (deploy/nats/render-config.py).

: "${AGENT:?set AGENT}" "${RENDER:?set RENDER}"
for tool in nats nats-server openssl; do
	command -v "$tool" >/dev/null || { echo "missing $tool" >&2; exit 1; }
done

N="$WORK/nats"
URL=tls://127.0.0.1:4222
mkdir -p "$N"
natsc() { # natsc <seed file> args...: nats CLI in the PoP namespace
	local seed=$1
	shift
	inb nats --server "$URL" --tlsca "$N/ca.pem" --nkey "$seed" "$@"
}
admin() { natsc "$N/admin.nk" "$@"; }
now_ms() { date +%s%3N; }

# CA, server certificate, nkeys (admin, api, lab1, lab2) and server config.
nats_prepare() {
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 \
		-keyout "$N/ca.key" -out "$N/ca.pem" -subj "/CN=sentinel-lab-ca" 2>/dev/null
	openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
		-keyout "$N/server.key" -out "$N/server.csr" -subj "/CN=nats" 2>/dev/null
	printf 'subjectAltName=IP:127.0.0.1,DNS:localhost\n' >"$N/san.ext"
	openssl x509 -req -in "$N/server.csr" -CA "$N/ca.pem" -CAkey "$N/ca.key" -CAcreateserial \
		-days 2 -extfile "$N/san.ext" -out "$N/server.pem" 2>/dev/null
	local admin_pub api_pub pop_pub lab2_pub
	admin_pub=$("$AGENT" nkey generate --out "$N/admin.nk")
	api_pub=$("$AGENT" nkey generate --out "$N/api.nk")
	pop_pub=$("$AGENT" nkey generate --out "$N/lab1.nk")
	lab2_pub=$("$AGENT" nkey generate --out "$N/lab2.nk")
	python3 "$RENDER" --listen 127.0.0.1:4222 --cert "$N/server.pem" --key "$N/server.key" \
		--store "$N/js" --admin "$admin_pub" --api "$api_pub" \
		--pop "lab1=$pop_pub" --pop "lab2=$lab2_pub" >"$N/server.json"
}

# Server in ns B plus the four KV buckets. Call after lab_net.
nats_start() {
	# Background processes are started directly, not through a shell
	# function: otherwise $! is a subshell and signals never reach them.
	ip netns exec "$NS_B" nats-server -c "$N/server.json" >"$N/server.log" 2>&1 &
	BG_PIDS+=($!)
	for _ in $(seq 50); do inb ss -Hltn "sport = :4222" | grep -q . && break; sleep 0.1; done
	for b in tenants services rules platform; do
		admin kv add "$b" --history 5 >/dev/null
	done
}

# nats_record <subject>...: log each subject to $N/sub-<subject without .>>.log
nats_record() {
	local subj f
	for subj in "$@"; do
		f="$N/sub-${subj%%.>}.log"
		ip netns exec "$NS_B" nats --server "$URL" --tlsca "$N/ca.pem" --nkey "$N/admin.nk" \
			sub "$subj" --raw >"$f" 2>&1 &
		BG_PIDS+=($!)
	done
	sleep 0.5
}

agent_config() {
	cat >"$WORK/agent.toml" <<CFG
[pop]
id = "lab1"
region = "lab"
iface = "$VB"
pop_ip4 = "$POP_IP"
tunnel_ep4 = "$TUNNEL_EP"
nexthop_mac = "$MAC_A"
[xdp]
object = "$BPF_OBJ"
pin_dir = "$SENTINEL_PIN_DIR"
[nats]
url = "$URL"
ca = "$N/ca.pem"
nkey_seed_file = "$N/lab1.nk"
[telemetry]
shards = 4
sample_base = 1
target_events_per_sec = 100000
[agent]
heartbeat_file = "$WORK/heartbeat"
metrics_listen = "127.0.0.1:9466"
health_interval_s = 1
gc_interval_s = 2
CFG
}

start_agent() {
	# nsenter (not ip netns exec) keeps bpffs visible; it execs the agent,
	# so $! is the agent's PID.
	nsenter --net="/run/netns/$NS_B" "$AGENT" run --config "$WORK/agent.toml" \
		>>"$WORK/agent.log" 2>&1 &
	AGENT_PID=$!
	BG_PIDS+=("$AGENT_PID")
}
