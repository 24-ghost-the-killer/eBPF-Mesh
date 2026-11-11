# 0019 Passkeys as a second factor

**Status:** Accepted (phase 6)

**Context.** The spec requires 2FA before protection can be enabled, "TOTP or
passkeys (WebAuthn)". Phase 5 implemented TOTP.

**Decision.**
- Passkeys are a **second factor** next to TOTP: login is always
  email + password, then a passkey *or* a TOTP code. 2FA is on when the user
  has a TOTP secret or at least one passkey (`user_mfa_enabled()` in SQL).
  Passwordless login is a later option; keeping one login flow keeps the
  rate limits and audit in one place.
- Library: **webauthn-rs 0.6** (pure Rust crypto, MPL-2.0, used unmodified).
  User verification is required. The relying party ID is the host of
  `server.public_url`, the allowed origin is that URL's origin.
- The WebAuthn **user handle is a random UUID** per user
  (`users.webauthn_handle`), never the email or database id.
- **Ceremony state** (the challenge) is stored server-side in
  `webauthn_challenges`, keyed by the session and the ceremony kind,
  encrypted with the data key, single use, valid for 5 minutes, and deleted
  with the session. Starting a new ceremony replaces the old one.
- Registering a passkey needs a fully authenticated session. The first
  second factor (passkey or TOTP) marks the current session as verified and
  logs out every other session of the user.
- Failed passkey assertions count as login failures (same per-account
  limit as wrong TOTP codes). Signature counters and backup flags are
  updated after every successful login.
- At most 10 passkeys per user; the last remaining second factor cannot be
  removed.
- Endpoints: `POST /auth/webauthn/{register,login}/{start,finish}`,
  `GET /auth/webauthn/credentials`, `DELETE /auth/webauthn/credentials/{id}`.

**Testing.** API tests cover option contents, encrypted single-use state,
forged credentials, and the session binding. The real ceremony is tested in
Chromium with a virtual authenticator (DevTools WebAuthn domain) in the
Playwright onboarding test: register, then log in with it.
