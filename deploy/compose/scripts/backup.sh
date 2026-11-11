#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# PostgreSQL backup (the source of truth; ClickHouse history and Prometheus
# can be rebuilt). Keeps the newest $KEEP dumps (default 14) in state/backups.
# Run daily from cron or a systemd timer on the control-plane host.
#
#   scripts/backup.sh               # dump
#   scripts/backup.sh --check FILE  # list a dump's contents (restore test)
# Restore: docker compose exec -T postgres pg_restore -U sentinel_owner -d sentinel --clean < FILE
set -euo pipefail
C="$(cd "$(dirname "$0")/.." && pwd)"
dc() { docker compose -f "$C/docker-compose.yml" --env-file "$C/state/.env" "$@"; }
if [ "${1:-}" = --check ]; then
	dc exec -T postgres pg_restore --list <"$2" | grep -c "TABLE DATA"
	exit 0
fi
mkdir -p "$C/state/backups"
chmod 700 "$C/state/backups"
out="$C/state/backups/sentinel-$(date -u +%Y%m%dT%H%M%SZ).dump"
dc exec -T postgres pg_dump -U sentinel_owner -d sentinel -Fc >"$out.tmp"
mv "$out.tmp" "$out"
chmod 600 "$out"
# Retention (file names have no spaces; the directory may).
(cd "$C/state/backups" && ls -1t sentinel-*.dump | tail -n +$((${KEEP:-14} + 1)) | while read -r f; do rm -f "$f"; done)
echo "$out"
echo "$(wc -c <"$out" | tr -d ' ') bytes" >&2
