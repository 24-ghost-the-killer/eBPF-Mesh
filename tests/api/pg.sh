#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Throwaway PostgreSQL for tests: pg.sh start|stop <dir>, pg.sh sql <dir> <stmt>.
# Prints the superuser connection URL on start. Unix socket only (no TCP).
# PostgreSQL refuses to run as root; as root the cluster runs as nobody.
set -euo pipefail
cmd=$1 dir=$2
bin=${SENTINEL_PG_BIN:-$(ls -d /usr/lib/postgresql/*/bin 2>/dev/null | sort -V | tail -1)}
[ -x "$bin/initdb" ] || bin=$(dirname "$(command -v initdb)")
as_pg() {
	if [ "$(id -u)" -eq 0 ]; then
		setpriv --reuid=nobody --regid=nogroup --clear-groups "$@"
	else
		"$@"
	fi
}
case "$cmd" in
start)
	mkdir -p "$dir"
	[ "$(id -u)" -eq 0 ] && chown nobody "$dir"
	as_pg "$bin/initdb" -D "$dir/data" -U postgres --auth=trust >/dev/null
	as_pg "$bin/pg_ctl" -D "$dir/data" -l "$dir/log" -w \
		-o "-k $dir -c listen_addresses= -p 5439 -c fsync=off" start >/dev/null
	echo "postgres://postgres@localhost/postgres?host=$dir&port=5439"
	;;
stop)
	as_pg "$bin/pg_ctl" -D "$dir/data" -m fast -w stop >/dev/null 2>&1 || true
	;;
sql) # pg.sh sql <dir> <statement>: run as the superuser
	"$bin/psql" -h "$dir" -p 5439 -U postgres -d postgres -v ON_ERROR_STOP=1 -qc "$3"
	;;
*)
	echo "usage: $0 start|stop <dir>" >&2
	exit 2
	;;
esac
