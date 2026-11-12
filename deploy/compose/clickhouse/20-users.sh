#!/bin/bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# First start only: least-privilege users (ADR 0024).
set -eu
clickhouse client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --multiquery <<SQL
CREATE USER IF NOT EXISTS sentinel_worker IDENTIFIED WITH sha256_password BY '${CH_WORKER_PASSWORD}';
GRANT SELECT, INSERT ON sentinel.flows TO sentinel_worker;
GRANT INSERT ON sentinel.traffic_1m TO sentinel_worker;
CREATE USER IF NOT EXISTS sentinel_api IDENTIFIED WITH sha256_password BY '${CH_API_PASSWORD}' SETTINGS readonly = 1;
GRANT SELECT ON sentinel.traffic_1m TO sentinel_api;
SQL
