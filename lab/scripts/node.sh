#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
# Starts one lab node's role (containerlab `exec`, after the links exist).
# Daemons are started in the background with setsid; logs go to
# /lab/state/logs/<node>.<daemon>.log.
#
#   node.sh region|pop|origin|client|bot N
#   node.sh nats|postgres|api
#   node.sh worker N
#   node.sh start-agent N      (restart the agent on pop-N)
set -eu
ROLE=$1
N=${2:-}
S=/lab/state
LOG=$S/logs
mkdir -p "$LOG"
NAME=$(hostname)

bg() { # bg <log name> cmd...: start a daemon in its own session
	name=$1
	shift
	setsid "$@" >>"$LOG/$NAME.$name.log" 2>&1 </dev/null &
}

data_link() { # data_link <iface> <addr/len>: address, no TX checksum offload
	ip link set "$1" up
	ip addr replace "$2" dev "$1"
	# veth leaves checksums to "hardware"; XDP_TX would forward them half done.
	ethtool -K "$1" tx off >/dev/null 2>&1 || true
}

wait_iface() {
	for _ in $(seq 100); do ip link show "$1" >/dev/null 2>&1 && return 0; sleep 0.1; done
	echo "no $1" >&2
	return 1
}

lan_host() { # lan_host <addr/len> <gateway>: hosts behind a region use it as default route
	wait_iface eth1
	data_link eth1 "$1"
	ip route replace default via "$2" dev eth1
}

start_agent() {
	mkdir -p /run/sentinel
	bg agent /opt/sentinel/bin/sentinel-agent run --config "$S/agents/pop-$N.toml"
}

case "$ROLE" in
region)
	for i in 1 2 3 4 5; do wait_iface "eth$i"; done
	sysctl -qw net.ipv4.ip_forward=1 net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0
	data_link eth1 "10.10.$N.1/24"
	case $N in
	1) data_link eth2 10.1.12.1/30; data_link eth3 10.1.13.1/30 ;;
	2) data_link eth2 10.1.12.2/30; data_link eth3 10.1.23.1/30 ;;
	3) data_link eth2 10.1.13.2/30; data_link eth3 10.1.23.2/30 ;;
	esac
	data_link eth4 "203.0.113.$((32 * N + 1))/28"
	data_link eth5 "203.0.113.$((32 * N + 17))/28"
	if [ "$N" = 1 ]; then wait_iface eth6; data_link eth6 192.0.2.1/24; fi
	for i in eth1 eth2 eth3 eth4 eth5 eth6; do
		sysctl -qw "net.ipv4.conf.$i.rp_filter=0" 2>/dev/null || true
	done
	# veth XDP_TX (the PoP sending back to us) needs a program on this end.
	ip link set dev eth1 xdpdrv obj /opt/sentinel/xdp_pass.o sec xdp
	mkdir -p /run/bird
	bg bird bird -f -c "/lab/bird/region-$N.conf" -s /run/bird/bird.ctl
	;;
pop)
	wait_iface eth1
	data_link eth1 "10.10.$N.2/24"
	sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.eth1.rp_filter=0
	mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
	mkdir -p /etc/bird /run/bird /run/sentinel
	[ -f /etc/bird/drain.conf ] || printf 'define DRAIN = 0;\n' >/etc/bird/drain.conf
	bg bird bird -f -c "/lab/bird/pop-$N.conf" -s /run/bird/bird.ctl
	start_agent
	# The health check (a systemd timer on real PoPs) every 2 seconds.
	bg health sh -c 'while sleep 2; do XS_IFACE=eth1 XS_PROTOCOLS=anycast4 \
		BIRDC="birdc -s /run/bird/bird.ctl" /opt/sentinel/sentinel-health.sh; done'
	;;
start-agent) start_agent ;;
origin)
	lan_host 192.0.2.10/24 192.0.2.1
	;;
client)
	lan_host "203.0.113.$((32 * N + 2))/28" "203.0.113.$((32 * N + 1))"
	;;
bot)
	lan_host "203.0.113.$((32 * N + 18))/28" "203.0.113.$((32 * N + 17))"
	;;
nats)
	bg nats nats-server -c "$S/nats/server.json"
	;;
postgres)
	export PGDATA=/var/lib/sentinel-pg
	if [ ! -d "$PGDATA" ]; then
		mkdir -p "$PGDATA" /run/postgresql
		chown postgres "$PGDATA" /run/postgresql
		printf '%s\n' "$(cat "$S/postgres.password")" >/tmp/pw
		chown postgres /tmp/pw
		su postgres -c "initdb -D $PGDATA -U postgres --pwfile=/tmp/pw -A scram-sha-256" >/dev/null
		rm -f /tmp/pw
		echo "host all all 172.31.250.0/24 scram-sha-256" >>"$PGDATA/pg_hba.conf"
	fi
	su postgres -c "pg_ctl -D $PGDATA -l $LOG/$NAME.postgres.log -o \"-c listen_addresses=*\" -w start" >/dev/null
	PGPASSWORD=$(cat "$S/postgres.password") psql -h 127.0.0.1 -U postgres -tAc \
		"SELECT 1 FROM pg_database WHERE datname = 'sentinel'" | grep -q 1 ||
		PGPASSWORD=$(cat "$S/postgres.password") psql -h 127.0.0.1 -U postgres -qc "CREATE DATABASE sentinel"
	;;
api)
	# shellcheck disable=SC1091
	. "$S/api.env"
	export SENTINEL_DATABASE_URL SENTINEL_DATABASE_OWNER_URL SENTINEL_DATA_KEY \
		SENTINEL_CLICKHOUSE_PASSWORD SENTINEL_DECISION_KEY
	for _ in $(seq 120); do
		/opt/sentinel/bin/sentinel-api migrate --config "$S/api.toml" >>"$LOG/$NAME.migrate.log" 2>&1 && break
		sleep 1
	done
	PGPASSWORD=$(cat "$S/postgres.password") psql -h 172.31.250.11 -U postgres -d sentinel -qc \
		"ALTER ROLE sentinel_api LOGIN PASSWORD '$(cat "$S/api-db.password")'"
	for w in 1 2; do
		/opt/sentinel/bin/sentinel-api signing-key --config "$S/api.toml" add --issuer "worker-$w" \
			--public-key "$(cat "$S/workers/worker-$w.pub")" >>"$LOG/$NAME.keys.log" 2>&1
	done
	bg api /opt/sentinel/bin/sentinel-api serve --config "$S/api.toml"
	;;
worker)
	# shellcheck disable=SC1091
	. "$S/worker.env"
	export SENTINEL_CLICKHOUSE_PASSWORD
	bg worker /opt/sentinel/bin/sentinel-worker run --config "$S/workers/worker-$N.toml"
	;;
*)
	echo "unknown role $ROLE" >&2
	exit 2
	;;
esac
