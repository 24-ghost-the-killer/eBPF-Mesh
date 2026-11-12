-- SPDX-License-Identifier: MIT OR Apache-2.0
-- Least-privilege users (example; passwords come from your secret store).
CREATE USER IF NOT EXISTS sentinel_worker IDENTIFIED WITH sha256_password BY '<worker password>';
-- The view traffic_1m_mv runs with the inserting user's rights: the worker
-- also reads the rows it inserts (SELECT on flows) and writes traffic_1m.
GRANT SELECT, INSERT ON sentinel.flows TO sentinel_worker;
GRANT INSERT ON sentinel.traffic_1m TO sentinel_worker;
CREATE USER IF NOT EXISTS sentinel_api IDENTIFIED WITH sha256_password BY '<api password>'
  SETTINGS readonly = 1;
GRANT SELECT ON sentinel.traffic_1m TO sentinel_api;
