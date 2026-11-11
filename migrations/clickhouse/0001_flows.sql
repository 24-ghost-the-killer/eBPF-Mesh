-- SPDX-License-Identifier: MIT OR Apache-2.0
-- Traffic history (spec 12.2, ADR 0024). Apply as a ClickHouse admin:
--   clickhouse-client --multiquery < 0001_flows.sql
-- Users and grants are deployment-specific; see 0002_users.example.sql.

CREATE DATABASE IF NOT EXISTS sentinel;

CREATE TABLE IF NOT EXISTS sentinel.flows (
  ts       DateTime64(3, 'UTC'),
  pop      LowCardinality(String),
  tenant   UInt32,
  src      IPv6,                 -- IPv4 stored as ::ffff:a.b.c.d
  dst      IPv6,
  proto    UInt8,
  dport    UInt16,
  pkts     UInt64,               -- scaled by the sampling rate
  bytes    UInt64,
  verdict  LowCardinality(String)
) ENGINE = MergeTree
PARTITION BY toDate(ts)
ORDER BY (tenant, ts)
TTL toDateTime(ts) + INTERVAL 30 DAY;

-- Portal graphs read traffic_1m, never flows. A real table filled by a
-- materialized view, so readers need SELECT on traffic_1m only.
CREATE TABLE IF NOT EXISTS sentinel.traffic_1m (
  tenant   UInt32,
  pop      LowCardinality(String),
  verdict  LowCardinality(String),
  minute   DateTime('UTC'),
  pkts     UInt64,
  bytes    UInt64
) ENGINE = SummingMergeTree
ORDER BY (tenant, pop, verdict, minute)
TTL minute + INTERVAL 400 DAY;

CREATE MATERIALIZED VIEW IF NOT EXISTS sentinel.traffic_1m_mv TO sentinel.traffic_1m AS
SELECT tenant, pop, verdict, toStartOfMinute(ts) AS minute,
       sum(pkts) AS pkts, sum(bytes) AS bytes
FROM sentinel.flows GROUP BY tenant, pop, verdict, minute;
