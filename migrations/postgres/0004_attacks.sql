-- SPDX-License-Identifier: MIT OR Apache-2.0
-- Phase 7: attacks reported by workers, decisions, webhooks, signing keys
-- (ADR 0021, ADR 0022).

-- One attack per tenant and vector at a time; several workers may report
-- it. reporters: {"<issuer>": {"id": "...", "ended": false, "ts": ms}}.
ALTER TABLE attacks
  ADD COLUMN status         TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'ended')),
  ADD COLUMN reporters      JSONB NOT NULL DEFAULT '{}',
  ADD COLUMN pps            DOUBLE PRECISION NOT NULL DEFAULT 0,
  ADD COLUMN bps            DOUBLE PRECISION NOT NULL DEFAULT 0,
  ADD COLUMN dropped_ratio  DOUBLE PRECISION NOT NULL DEFAULT 0,
  ADD COLUMN targets        TEXT[] NOT NULL DEFAULT '{}',
  ADD COLUMN top_sources    JSONB NOT NULL DEFAULT '[]',
  ADD COLUMN decisions      INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN updated_at     TIMESTAMPTZ NOT NULL DEFAULT now();
CREATE INDEX attacks_tenant ON attacks (tenant_id, started_at DESC);
CREATE UNIQUE INDEX attacks_one_active ON attacks (tenant_id, vector) WHERE status = 'active';

-- Rates over time, for the attack graph.
CREATE TABLE attack_samples (
  attack_id      BIGINT NOT NULL REFERENCES attacks(id) ON DELETE CASCADE,
  tenant_id      BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  ts             TIMESTAMPTZ NOT NULL,
  pps            DOUBLE PRECISION NOT NULL,
  bps            DOUBLE PRECISION NOT NULL,
  dropped_ratio  DOUBLE PRECISION NOT NULL,
  PRIMARY KEY (attack_id, ts)
);
ALTER TABLE attack_samples ENABLE ROW LEVEL SECURITY;
CREATE POLICY attack_samples_access ON attack_samples TO sentinel_api
  USING ((tenant_id = app_tenant() AND app_tenant_ok()) OR app_admin())
  WITH CHECK ((tenant_id = app_tenant() AND app_tenant_ok()) OR app_admin());

-- Every verified decision seen on decision.global. tenant_id NULL = global.
CREATE TABLE decisions (
  issuer      TEXT NOT NULL,
  id          TEXT NOT NULL,
  tenant_id   BIGINT REFERENCES tenants(id) ON DELETE CASCADE,
  src         CIDR NOT NULL,
  action      TEXT NOT NULL,
  ttl_s       INTEGER NOT NULL,
  reason      TEXT NOT NULL,
  ts          TIMESTAMPTZ NOT NULL,
  expires_at  TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (issuer, id)
);
CREATE INDEX decisions_tenant ON decisions (tenant_id, ts DESC);
ALTER TABLE decisions ENABLE ROW LEVEL SECURITY;
-- Tenants see their own decisions; global ones only platform admins.
CREATE POLICY decisions_access ON decisions TO sentinel_api
  USING ((tenant_id = app_tenant() AND app_tenant_ok()) OR app_admin())
  WITH CHECK (app_admin());

ALTER TABLE webhooks
  ADD COLUMN name         TEXT NOT NULL DEFAULT '' CHECK (length(name) <= 64),
  ADD COLUMN created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  ADD COLUMN last_at      TIMESTAMPTZ,
  ADD COLUMN last_status  TEXT,
  ADD CONSTRAINT webhooks_kind CHECK (kind IN ('discord', 'slack', 'http', 'email'));
CREATE INDEX webhooks_tenant ON webhooks (tenant_id);

ALTER TABLE signing_keys ADD COLUMN revoked_at TIMESTAMPTZ;

GRANT SELECT, INSERT, UPDATE, DELETE ON attack_samples, decisions TO sentinel_api;
