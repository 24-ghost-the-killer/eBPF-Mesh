#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
# First start only: the API's role with its password (the migrations grant
# its privileges and set up Row Level Security).
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
	-v pw="$SENTINEL_API_DB_PASSWORD" <<'SQL'
CREATE ROLE sentinel_api LOGIN PASSWORD :'pw';
SQL
