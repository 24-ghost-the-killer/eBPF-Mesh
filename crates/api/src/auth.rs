// SPDX-License-Identifier: MIT OR Apache-2.0
//! Authentication and authorisation (spec section 10, ADR 0016).
//!
//! - Passwords: argon2id (PHC strings), verified on a blocking thread.
//! - Sessions: 256-bit random token in an HttpOnly, Secure, SameSite=Strict
//!   cookie; only its SHA-256 is stored. Absolute and idle expiry; revocable.
//! - CSRF: a per-session token that state-changing requests must echo in
//!   X-CSRF-Token (the web app gets it from /me and the login response).
//! - 2FA: TOTP; with 2FA enabled, a fresh session can only complete 2FA or
//!   log out until a code was verified.
//! - API keys: `Authorization: Bearer xs_...`, stored hashed, tenant-bound,
//!   scopes read (viewer) / write (admin). Never owner.
//! - Roles come from the membership row, never from the URL alone.

use std::net::{IpAddr, SocketAddr};
use std::sync::OnceLock;

use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::{header, request::Parts, Method, StatusCode};
use sqlx::{FromRow, PgPool};

use crate::crypto::{ct_eq, sha256_hex, token};
use crate::db::{self, Scope};
use crate::error::{ApiError, ApiResult};
use crate::AppState;

pub const SESSION_COOKIE: &str = "xs_session";
pub const CSRF_HEADER: &str = "x-csrf-token";
pub const API_KEY_PREFIX: &str = "xs_";

// ---- passwords ------------------------------------------------------------------

pub async fn hash_password(password: String) -> anyhow::Result<String> {
    tokio::task::spawn_blocking(move || {
        Argon2::default()
            .hash_password(password.as_bytes())
            .map(|h| h.to_string())
            .map_err(|e| anyhow::anyhow!("hashing password: {e}"))
    })
    .await?
}

/// Verifies against `hash`, or against a dummy hash when the user does not
/// exist, so both cases take the same time (no user enumeration by timing).
pub async fn verify_password(password: String, hash: Option<String>) -> bool {
    static DUMMY: OnceLock<String> = OnceLock::new();
    let hash = match hash {
        Some(h) => h,
        None => DUMMY
            .get_or_init(|| {
                Argon2::default()
                    .hash_password(token().as_bytes())
                    .expect("hashing a random password")
                    .to_string()
            })
            .clone(),
    };
    tokio::task::spawn_blocking(move || {
        Argon2::default()
            .verify_password(password.as_bytes(), hash.as_str())
            .is_ok()
    })
    .await
    .unwrap_or(false)
}

pub fn check_password_policy(pw: &str, min_len: usize) -> ApiResult<()> {
    if pw.chars().count() < min_len {
        return Err(ApiError::bad_request(
            "weak_password",
            format!("passwords need at least {min_len} characters"),
        ));
    }
    if pw.len() > 1024 {
        return Err(ApiError::bad_request("weak_password", "password too long"));
    }
    Ok(())
}

pub fn check_email(email: &str) -> ApiResult<()> {
    let ok = email.len() <= 254
        && email.split_once('@').is_some_and(|(l, d)| {
            !l.is_empty() && d.contains('.') && !d.starts_with('.') && !d.ends_with('.')
        })
        && !email.chars().any(|c| c.is_whitespace() || c.is_control());
    if ok {
        Ok(())
    } else {
        Err(ApiError::bad_request(
            "invalid_email",
            "not a valid email address",
        ))
    }
}

// ---- roles -----------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    Viewer,
    Admin,
    Owner,
}

impl Role {
    pub fn parse(s: &str) -> Option<Role> {
        match s {
            "viewer" => Some(Role::Viewer),
            "admin" => Some(Role::Admin),
            "owner" => Some(Role::Owner),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Viewer => "viewer",
            Role::Admin => "admin",
            Role::Owner => "owner",
        }
    }
}

pub fn require(role: Role, min: Role) -> ApiResult<()> {
    if role >= min {
        Ok(())
    } else {
        Err(ApiError::forbidden(format!(
            "this needs the {} role",
            min.as_str()
        )))
    }
}

// ---- callers ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct SessionInfo {
    pub hash: String,
    pub mfa_done: bool,
    pub csrf: String,
}

#[derive(Clone, Debug)]
pub struct KeyInfo {
    pub id: i64,
    pub tenant_id: i64,
    pub scopes: Vec<String>,
}

/// Who is making the request.
#[derive(Clone, Debug)]
pub struct Caller {
    /// The user (for API keys: the user who created the key).
    pub user_id: Option<i64>,
    pub is_admin: bool,
    pub mfa_enabled: bool,
    pub session: Option<SessionInfo>,
    pub key: Option<KeyInfo>,
    pub ip: Option<IpAddr>,
}

impl Caller {
    pub fn scope(&self, tenant: Option<i64>) -> Scope {
        match &self.key {
            // A key acts for its own tenant only; its creator's other
            // memberships do not apply.
            Some(k) => Scope {
                user: None,
                tenant,
                key_tenant: Some(k.tenant_id),
                admin: false,
            },
            None => Scope {
                user: self.user_id,
                tenant,
                key_tenant: None,
                admin: false,
            },
        }
    }

    /// The caller's role in `tenant`; 404 when it has none (never reveal
    /// that another tenant exists).
    pub async fn role(&self, pool: &PgPool, tenant: i64) -> ApiResult<Role> {
        if let Some(k) = &self.key {
            if k.tenant_id != tenant {
                return Err(ApiError::not_found());
            }
            return Ok(if k.scopes.iter().any(|s| s == "write") {
                Role::Admin
            } else {
                Role::Viewer
            });
        }
        let user = self.user_id.ok_or_else(ApiError::unauthorized)?;
        let mut tx = db::begin(
            pool,
            Scope {
                user: Some(user),
                ..Default::default()
            },
        )
        .await?;
        let role: Option<String> = sqlx::query_scalar(
            "SELECT role FROM memberships WHERE user_id = $1 AND tenant_id = $2",
        )
        .bind(user)
        .bind(tenant)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        role.as_deref()
            .and_then(Role::parse)
            .ok_or_else(ApiError::not_found)
    }

    pub fn require_platform_admin(&self) -> ApiResult<()> {
        if self.is_admin && self.session.is_some() && self.mfa_enabled {
            Ok(())
        } else {
            Err(ApiError::forbidden(
                "platform administrators only (with 2FA)",
            ))
        }
    }

    pub fn require_mfa(&self) -> ApiResult<()> {
        if self.mfa_enabled {
            Ok(())
        } else {
            Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "mfa_required",
                "enable two-factor authentication first",
            ))
        }
    }
}

fn client_ip(parts: &Parts, state: &AppState) -> Option<IpAddr> {
    if state.cfg.server.trust_proxy {
        if let Some(ip) = parts
            .headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .and_then(|v| v.trim().parse().ok())
        {
            return Some(ip);
        }
    }
    parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip())
}

pub fn cookie_value(parts: &Parts, name: &str) -> Option<String> {
    parts
        .headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.to_string())
}

#[derive(FromRow)]
struct SessionRow {
    user_id: i64,
    mfa_done: bool,
    csrf_token: String,
    is_platform_admin: bool,
    mfa_enabled: bool,
    stale: bool,
}

async fn authenticate(
    parts: &Parts,
    state: &AppState,
    allow_pending_mfa: bool,
) -> ApiResult<Caller> {
    let ip = client_ip(parts, state);
    let pool = &state.pool;

    if let Some(auth) = parts
        .headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        let key = auth
            .strip_prefix("Bearer ")
            .ok_or_else(ApiError::unauthorized)?
            .trim();
        if !key.starts_with(API_KEY_PREFIX) {
            return Err(ApiError::unauthorized());
        }
        let row: Option<(i64, i64, Vec<String>, Option<i64>)> =
            sqlx::query_as("SELECT id, tenant_id, scopes, created_by FROM api_key_lookup($1)")
                .bind(sha256_hex(key))
                .fetch_optional(pool)
                .await?;
        let (id, tenant_id, scopes, created_by) = row.ok_or_else(ApiError::unauthorized)?;
        return Ok(Caller {
            user_id: created_by,
            is_admin: false,
            mfa_enabled: true, // only users with 2FA can create keys
            session: None,
            key: Some(KeyInfo {
                id,
                tenant_id,
                scopes,
            }),
            ip,
        });
    }

    let token = cookie_value(parts, SESSION_COOKIE).ok_or_else(ApiError::unauthorized)?;
    let hash = sha256_hex(&token);
    let row: Option<SessionRow> = sqlx::query_as(
        "SELECT s.user_id, s.mfa_done, s.csrf_token, u.is_platform_admin, \
                user_mfa_enabled(u.id) AS mfa_enabled, \
                (s.last_seen < now() - interval '1 minute') AS stale \
         FROM sessions s JOIN users u ON u.id = s.user_id \
         WHERE s.token_hash = $1 AND s.expires_at > now() \
           AND s.last_seen > now() - make_interval(mins => $2)",
    )
    .bind(&hash)
    .bind(state.cfg.sessions.idle_minutes as i32)
    .fetch_optional(pool)
    .await?;
    let r = row.ok_or_else(ApiError::unauthorized)?;
    if r.stale {
        sqlx::query("UPDATE sessions SET last_seen = now() WHERE token_hash = $1")
            .bind(&hash)
            .execute(pool)
            .await?;
    }
    if r.mfa_enabled && !r.mfa_done && !allow_pending_mfa {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "mfa_required",
            "complete two-factor authentication",
        ));
    }
    let safe = matches!(parts.method, Method::GET | Method::HEAD | Method::OPTIONS);
    if !safe {
        let sent = parts
            .headers
            .get(CSRF_HEADER)
            .map(|v| v.as_bytes())
            .unwrap_or_default();
        if !ct_eq(sent, r.csrf_token.as_bytes()) {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "csrf",
                "missing or wrong CSRF token",
            ));
        }
    }
    Ok(Caller {
        user_id: Some(r.user_id),
        is_admin: r.is_platform_admin,
        mfa_enabled: r.mfa_enabled,
        session: Some(SessionInfo {
            hash,
            mfa_done: r.mfa_done,
            csrf: r.csrf_token,
        }),
        key: None,
        ip,
    })
}

impl FromRequestParts<AppState> for Caller {
    type Rejection = ApiError;
    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> ApiResult<Self> {
        authenticate(parts, state, false).await
    }
}

/// A session that may still be waiting for its 2FA code.
pub struct PendingMfa(pub Caller);

impl FromRequestParts<AppState> for PendingMfa {
    type Rejection = ApiError;
    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> ApiResult<Self> {
        let c = authenticate(parts, state, true).await?;
        if c.session.is_none() {
            return Err(ApiError::unauthorized());
        }
        Ok(PendingMfa(c))
    }
}

/// The client IP, for unauthenticated endpoints (rate limits, audit).
pub struct ClientIp(pub Option<IpAddr>);

impl FromRequestParts<AppState> for ClientIp {
    type Rejection = ApiError;
    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> ApiResult<Self> {
        Ok(ClientIp(client_ip(parts, state)))
    }
}

// ---- sessions -----------------------------------------------------------------------

pub struct NewSession {
    pub token: String,
    pub csrf: String,
}

pub async fn create_session(
    state: &AppState,
    user_id: i64,
    mfa_done: bool,
    ip: Option<IpAddr>,
    user_agent: Option<&str>,
) -> ApiResult<NewSession> {
    let (tok, csrf) = (token(), token());
    sqlx::query(
        "INSERT INTO sessions (token_hash, user_id, mfa_done, csrf_token, expires_at, ip, user_agent) \
         VALUES ($1, $2, $3, $4, now() + make_interval(hours => $5), $6::inet, $7)",
    )
    .bind(sha256_hex(&tok))
    .bind(user_id)
    .bind(mfa_done)
    .bind(&csrf)
    .bind(state.cfg.sessions.absolute_hours as i32)
    .bind(ip.map(|i| i.to_string()))
    .bind(user_agent.map(|u| u.chars().take(256).collect::<String>()))
    .execute(&state.pool)
    .await?;
    Ok(NewSession { token: tok, csrf })
}

pub fn session_cookie(state: &AppState, token: &str) -> String {
    format!(
        "{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}{}",
        state.cfg.sessions.absolute_hours * 3600,
        if state.cfg.server.cookie_secure {
            "; Secure"
        } else {
            ""
        }
    )
}

pub fn clear_cookie(state: &AppState) -> String {
    format!(
        "{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{}",
        if state.cfg.server.cookie_secure {
            "; Secure"
        } else {
            ""
        }
    )
}

// ---- TOTP ---------------------------------------------------------------------------------

pub mod totp {
    use totp_rs::{Builder, Totp};

    pub const ISSUER: &str = "Sentinel-Edge";

    fn build(secret: &[u8], account: &str) -> anyhow::Result<Totp> {
        Builder::new()
            .with_secret(secret.to_vec())
            .with_account_name(account)
            .with_issuer(Some(ISSUER))
            .build()
            .map_err(|e| anyhow::anyhow!("TOTP: {e:?}"))
    }

    /// (base32 secret, otpauth:// URL) for authenticator apps.
    pub fn describe(secret: &[u8], account: &str) -> anyhow::Result<(String, String)> {
        let t = build(secret, account)?;
        let url = t.to_url().map_err(|e| anyhow::anyhow!("TOTP URL: {e:?}"))?;
        Ok((t.secret().to_base32(), url))
    }

    /// The time step of a valid code (±1 step), only if it is newer than
    /// `last_step` (RFC 6238 section 5.2: a code is accepted once).
    pub fn check(secret: &[u8], account: &str, code: &str, last_step: i64) -> Option<i64> {
        let t = build(secret, account).ok()?;
        let step = t.check_current(code.trim())? as i64;
        (step > last_step).then_some(step)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn codes_are_accepted_once() {
            let secret = [42u8; 20];
            let t = build(&secret, "a@example.org").unwrap();
            let code = t.generate_current().to_string();
            let step = check(&secret, "a@example.org", &code, 0).unwrap();
            assert!(
                check(&secret, "a@example.org", &code, step).is_none(),
                "replay"
            );
            assert!(check(&secret, "a@example.org", "000000x", 0).is_none());
            let (b32, url) = describe(&secret, "a@example.org").unwrap();
            assert!(url.starts_with("otpauth://totp/"), "{url}");
            assert!(url.contains(&b32));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn passwords_are_argon2id() {
        let h = hash_password("correct horse battery staple".into())
            .await
            .unwrap();
        assert!(h.starts_with("$argon2id$"), "{h}");
        assert!(verify_password("correct horse battery staple".into(), Some(h.clone())).await);
        assert!(!verify_password("wrong".into(), Some(h)).await);
        assert!(!verify_password("anything".into(), None).await);
    }

    #[test]
    fn roles_order() {
        assert!(Role::Owner > Role::Admin && Role::Admin > Role::Viewer);
        assert!(require(Role::Admin, Role::Viewer).is_ok());
        assert!(require(Role::Viewer, Role::Admin).is_err());
        assert_eq!(Role::parse("owner"), Some(Role::Owner));
        assert_eq!(Role::parse("root"), None);
    }

    #[test]
    fn email_and_password_policy() {
        assert!(check_email("a@example.org").is_ok());
        for bad in [
            "",
            "a",
            "@example.org",
            "a@b",
            "a b@example.org",
            "a@.org",
            "a@example.",
        ] {
            assert!(check_email(bad).is_err(), "{bad}");
        }
        assert!(check_password_policy("short", 12).is_err());
        assert!(check_password_policy("twelve chars", 12).is_ok());
    }
}
