# 0024 Traffic history in ClickHouse

**Status:** Accepted (phase 8)

- **Who writes:** the workers. Each already receives the telemetry of its
  shards, so together they insert every flow once (HTTP interface,
  JSONEachRow, batches of up to `batch_rows` every second). A bounded queue
  drops (and counts) batches when ClickHouse is slow or down: detection
  never waits for storage.
- **Schema** (`migrations/clickhouse/0001_flows.sql`): the spec's `flows`
  table (timestamps in UTC; counts are scaled by the sampling rate, so they
  are estimates). `traffic_1m` is an explicit SummingMergeTree table filled
  by the materialised view `traffic_1m_mv`, so readers need SELECT on
  `traffic_1m` only.
- **Users:** `sentinel_worker` may INSERT into `flows` and `traffic_1m` and
  SELECT `flows` (the view runs with the inserting user's rights);
  `sentinel_api` is read-only with SELECT on `traffic_1m`. Passwords come
  from environment variables.
- **Reading:** `GET /tenants/{id}/traffic?from&to&step` (viewer+) queries
  `traffic_1m` with typed query parameters (the tenant from the authorised
  path, never spliced into SQL), at most 2000 points and 31 days, and
  returns in / filtered / clean rates per PoP. Without `[clickhouse]` it
  answers 503 and the portal says history is not available.
