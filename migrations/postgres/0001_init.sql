-- SPDX-License-Identifier: MIT OR Apache-2.0
-- Sentinel-Edge control plane: schema (spec section 12.1, with the additions
-- recorded in ADR 0016/0017). Run as the owner role (`sentinel-api migrate`).

CREATE EXTENSION IF NOT EXISTS citext;

-- Every KV document carries a version taken from this sequence; agents
-- acknowledge it (config_acks).
CREATE SEQUENCE config_version_seq;

CREATE TABLE tenants (
  id          BIGSERIAL PRIMARY KEY,
  name        TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
  plan        TEXT NOT NULL DEFAULT 'free',
  status      TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE users (
  id                 BIGSERIAL PRIMARY KEY,
  email              CITEXT UNIQUE NOT NULL,
  email_verified     BOOLEAN NOT NULL DEFAULT false,
  password_hash      TEXT NOT NULL,                     -- argon2id (PHC string)
  totp_secret        BYTEA,                             -- AES-256-GCM encrypted; NULL = no 2FA
  totp_pending       BYTEA,                             -- encrypted secret during setup
  totp_last_step     BIGINT NOT NULL DEFAULT 0,         -- replay protection
  is_platform_admin  BOOLEAN NOT NULL DEFAULT false,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE webauthn_credentials (                     -- used from phase 6
  id          BYTEA PRIMARY KEY,
  user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  public_key  BYTEA NOT NULL,
  sign_count  BIGINT NOT NULL DEFAULT 0,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE sessions (
  token_hash  TEXT PRIMARY KEY,                         -- sha256 hex of the cookie value
  user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  mfa_done    BOOLEAN NOT NULL DEFAULT false,
  csrf_token  TEXT NOT NULL,
  expires_at  TIMESTAMPTZ NOT NULL,                     -- absolute lifetime
  last_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),       -- idle timeout
  ip          INET,
  user_agent  TEXT
);
CREATE INDEX sessions_user ON sessions (user_id);

CREATE TABLE email_tokens (
  token_hash  TEXT PRIMARY KEY,
  user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  purpose     TEXT NOT NULL CHECK (purpose IN ('verify', 'reset')),
  expires_at  TIMESTAMPTZ NOT NULL,
  used_at     TIMESTAMPTZ
);

CREATE TABLE auth_failures (                            -- login rate limiting
  id     BIGSERIAL PRIMARY KEY,
  email  CITEXT,
  ip     INET,
  ts     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX auth_failures_email ON auth_failures (email, ts);
CREATE INDEX auth_failures_ip ON auth_failures (ip, ts);

CREATE TABLE memberships (
  user_id    BIGINT REFERENCES users(id) ON DELETE CASCADE,
  tenant_id  BIGINT REFERENCES tenants(id) ON DELETE CASCADE,
  role       TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'viewer')),
  PRIMARY KEY (user_id, tenant_id)
);
CREATE INDEX memberships_tenant ON memberships (tenant_id);

CREATE TABLE assets (                                   -- protected IPs
  id                BIGSERIAL PRIMARY KEY,
  tenant_id         BIGINT NOT NULL REFERENCES tenants(id),
  protected_prefix  CIDR NOT NULL UNIQUE,
  origin_ip         INET NOT NULL,
  tunnel            TEXT NOT NULL DEFAULT 'ipip' CHECK (tunnel IN ('ipip', 'gre')),
  mode              TEXT NOT NULL DEFAULT 'observe' CHECK (mode IN ('observe', 'mitigate')),
  config_version    BIGINT NOT NULL DEFAULT nextval('config_version_seq'),
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX assets_tenant ON assets (tenant_id);

CREATE TABLE policies (                                 -- one per asset (ADR 0004/0017)
  asset_id          BIGINT PRIMARY KEY REFERENCES assets(id) ON DELETE CASCADE,
  services          JSONB NOT NULL DEFAULT '[]',        -- [{"proto":"tcp","port":443}]
  pps_per_src       INT NOT NULL DEFAULT 0 CHECK (pps_per_src >= 0),
  burst             INT NOT NULL DEFAULT 0 CHECK (burst >= 0),
  syncookies        BOOLEAN NOT NULL DEFAULT false,
  enforce_services  BOOLEAN NOT NULL DEFAULT false,
  fragments         TEXT NOT NULL DEFAULT 'drop' CHECK (fragments IN ('allow', 'drop'))
);

CREATE TABLE rules (
  id          BIGSERIAL PRIMARY KEY,
  tenant_id   BIGINT REFERENCES tenants(id) ON DELETE CASCADE,  -- NULL = global
  kind        TEXT NOT NULL CHECK (kind IN ('allow', 'block')),
  prefix      CIDR NOT NULL,
  expires_at  TIMESTAMPTZ,                              -- NULL = permanent (allow only)
  reason      TEXT,
  created_by  BIGINT REFERENCES users(id) ON DELETE SET NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (kind = 'allow' OR expires_at IS NOT NULL)
);
CREATE INDEX rules_tenant ON rules (tenant_id);

-- Version of each tenant's rules document (KV rules/tenant.<id>; 0 = global).
CREATE TABLE tenant_rules_version (
  tenant_id  BIGINT PRIMARY KEY,                        -- 0 = global
  version    BIGINT NOT NULL
);

CREATE TABLE pops (                                     -- filled from health.<pop>
  id                      TEXT PRIMARY KEY,
  region                  TEXT NOT NULL,
  unicast_ip              INET,
  status                  TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'draining', 'down')),
  last_seen               TIMESTAMPTZ,
  config_version_applied  BIGINT
);

CREATE TABLE config_acks (                              -- filled from config.ack.<pop>
  pop      TEXT NOT NULL,
  bucket   TEXT NOT NULL,
  key      TEXT NOT NULL,
  version  BIGINT,
  ok       BOOLEAN NOT NULL,
  error    TEXT,
  ts       TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (pop, bucket, key)
);

-- Transactional outbox: written with the change, published to NATS KV by
-- the API's publisher (ADR 0016). value NULL = delete the key.
CREATE TABLE kv_outbox (
  id       BIGSERIAL PRIMARY KEY,
  bucket   TEXT NOT NULL,
  key      TEXT NOT NULL,
  value    JSONB,
  created  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE attacks (                                  -- used from phase 7
  id          BIGSERIAL PRIMARY KEY,
  tenant_id   BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  asset_id    BIGINT REFERENCES assets(id) ON DELETE SET NULL,
  vector      TEXT NOT NULL,
  started_at  TIMESTAMPTZ NOT NULL,
  ended_at    TIMESTAMPTZ,
  peak_pps    BIGINT, peak_bps BIGINT,
  pops        TEXT[]
);

CREATE TABLE api_keys (
  id          BIGSERIAL PRIMARY KEY,
  tenant_id   BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name        TEXT NOT NULL DEFAULT '',
  key_hash    TEXT NOT NULL UNIQUE,                     -- sha256 hex; the key is shown once
  scopes      TEXT[] NOT NULL CHECK (scopes <@ ARRAY['read', 'write']),
  created_by  BIGINT REFERENCES users(id) ON DELETE SET NULL,
  last_used   TIMESTAMPTZ,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE webhooks (                                 -- used from phase 7
  id          BIGSERIAL PRIMARY KEY,
  tenant_id   BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  kind        TEXT NOT NULL,
  target      TEXT NOT NULL,
  secret      BYTEA
);

CREATE TABLE audit_log (
  id         BIGSERIAL PRIMARY KEY,
  actor      BIGINT, tenant_id BIGINT,
  action     TEXT NOT NULL, payload JSONB,
  ip         INET,
  ts         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX audit_log_tenant ON audit_log (tenant_id, id);

CREATE TABLE signing_keys (                             -- used from phase 7
  issuer      TEXT PRIMARY KEY,
  public_key  BYTEA NOT NULL,
  revoked     BOOLEAN NOT NULL DEFAULT false,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
