-- SPDX-License-Identifier: MIT OR Apache-2.0
-- Phase 6: passkeys (WebAuthn) as a second factor next to TOTP (ADR 0019).

-- The placeholder table from 0001 was never used; webauthn-rs keeps the whole
-- credential (public key, counter, backup flags) in one serialised value.
DROP TABLE webauthn_credentials;

CREATE TABLE webauthn_credentials (
  id            BIGSERIAL PRIMARY KEY,
  user_id       BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  cred_id       BYTEA NOT NULL UNIQUE,                  -- the authenticator's credential ID
  name          TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
  passkey       JSONB NOT NULL,                         -- webauthn_rs::Passkey (public data only)
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_used_at  TIMESTAMPTZ
);
CREATE INDEX webauthn_credentials_user ON webauthn_credentials (user_id);

-- Random, stable WebAuthn user handle: no e-mail or database id goes to the
-- authenticator.
ALTER TABLE users ADD COLUMN webauthn_handle UUID NOT NULL DEFAULT gen_random_uuid();

-- Ceremony state between /start and /finish, bound to the session. It holds
-- the challenge, so it is encrypted with the data key like TOTP secrets.
CREATE TABLE webauthn_challenges (
  token_hash  TEXT NOT NULL REFERENCES sessions(token_hash) ON DELETE CASCADE,
  kind        TEXT NOT NULL CHECK (kind IN ('register', 'login')),
  state       BYTEA NOT NULL,
  expires_at  TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (token_hash, kind)
);

-- 2FA is on when the user has a TOTP secret or at least one passkey.
CREATE FUNCTION user_mfa_enabled(uid BIGINT) RETURNS BOOLEAN
LANGUAGE sql STABLE AS $$
  SELECT EXISTS (SELECT 1 FROM users WHERE id = uid AND totp_secret IS NOT NULL)
      OR EXISTS (SELECT 1 FROM webauthn_credentials WHERE user_id = uid)
$$;

GRANT SELECT, INSERT, UPDATE, DELETE ON webauthn_credentials, webauthn_challenges TO sentinel_api;
GRANT USAGE, SELECT ON SEQUENCE webauthn_credentials_id_seq TO sentinel_api;
GRANT EXECUTE ON FUNCTION user_mfa_enabled(BIGINT) TO sentinel_api;
