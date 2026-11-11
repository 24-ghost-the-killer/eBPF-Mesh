// SPDX-License-Identifier: MIT OR Apache-2.0
//! /auth/webauthn: passkeys as a second factor (ADR 0019).
//!
//! Registration needs a fully authenticated session; the login ceremony runs
//! on a session that passed the password step and is waiting for 2FA, like
//! /auth/2fa/verify. Ceremony state lives in webauthn_challenges, bound to
//! the session, encrypted, single use and valid for five minutes.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::FromRow;
use utoipa::ToSchema;
use webauthn_rs::prelude::{
    Passkey, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, Uuid,
};

use crate::auth::{Caller, PendingMfa};
use crate::db;
use crate::error::{ApiError, ApiResult, ErrorBody};
use crate::routes::auth::StatusResp;
use crate::AppState;

const CEREMONY_SECONDS: i32 = 300;
pub const MAX_PASSKEYS: i64 = 10;

fn session_of(c: &Caller) -> ApiResult<(i64, String)> {
    match (&c.session, c.user_id) {
        (Some(s), Some(u)) => Ok((u, s.hash.clone())),
        _ => Err(ApiError::unauthorized()),
    }
}

async fn save_state<T: Serialize>(
    state: &AppState,
    session: &str,
    kind: &str,
    value: &T,
) -> ApiResult<()> {
    let plain = serde_json::to_vec(value).map_err(anyhow::Error::from)?;
    sqlx::query(
        "INSERT INTO webauthn_challenges (token_hash, kind, state, expires_at) \
         VALUES ($1, $2, $3, now() + make_interval(secs => $4)) \
         ON CONFLICT (token_hash, kind) DO UPDATE SET state = EXCLUDED.state, expires_at = EXCLUDED.expires_at",
    )
    .bind(session)
    .bind(kind)
    .bind(state.data_key.encrypt(&plain))
    .bind(CEREMONY_SECONDS as f64)
    .execute(&state.pool)
    .await?;
    Ok(())
}

/// Takes the ceremony state (single use).
async fn take_state<T: for<'de> Deserialize<'de>>(
    state: &AppState,
    session: &str,
    kind: &str,
) -> ApiResult<T> {
    let enc: Option<Vec<u8>> = sqlx::query_scalar(
        "DELETE FROM webauthn_challenges WHERE token_hash = $1 AND kind = $2 \
         RETURNING CASE WHEN expires_at > now() THEN state END",
    )
    .bind(session)
    .bind(kind)
    .fetch_optional(&state.pool)
    .await?
    .flatten();
    let enc = enc
        .ok_or_else(|| ApiError::bad_request("no_challenge", "start the passkey ceremony again"))?;
    let plain = state.data_key.decrypt(&enc)?;
    Ok(serde_json::from_slice(&plain).map_err(anyhow::Error::from)?)
}

#[derive(FromRow)]
struct CredRow {
    id: i64,
    passkey: Value,
}

async fn passkeys_of(state: &AppState, user: i64) -> ApiResult<Vec<(i64, Passkey)>> {
    let rows: Vec<CredRow> = sqlx::query_as(
        "SELECT id, passkey FROM webauthn_credentials WHERE user_id = $1 ORDER BY id",
    )
    .bind(user)
    .fetch_all(&state.pool)
    .await?;
    rows.into_iter()
        .map(|r| {
            serde_json::from_value::<Passkey>(r.passkey)
                .map(|p| (r.id, p))
                .map_err(|e| ApiError::from(anyhow::Error::from(e)))
        })
        .collect()
}

fn webauthn(state: &AppState) -> ApiResult<&webauthn_rs::Webauthn> {
    state.webauthn.as_deref().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "passkeys_unavailable",
            "passkeys need the portal to have a domain name",
        )
    })
}

fn webauthn_err(e: impl std::fmt::Display) -> ApiError {
    tracing::info!("webauthn: {e}");
    ApiError::bad_request("passkey_rejected", "the passkey could not be verified")
}

// ---- registration ---------------------------------------------------------------------

/// Start adding a passkey. Returns the PublicKeyCredentialCreationOptions
/// (`{"publicKey": {...}}`) for navigator.credentials.create().
#[utoipa::path(post, path = "/api/v1/auth/webauthn/register/start", tag = "auth",
    responses((status = 200, body = serde_json::Value), (status = 409, body = ErrorBody)),
    security(("session" = [])))]
pub async fn register_start(State(state): State<AppState>, c: Caller) -> ApiResult<Json<Value>> {
    let (user, session) = session_of(&c)?;
    let existing = passkeys_of(&state, user).await?;
    if existing.len() as i64 >= MAX_PASSKEYS {
        return Err(ApiError::conflict(
            "too_many",
            "at most 10 passkeys per account",
        ));
    }
    let (email, handle): (String, String) =
        sqlx::query_as("SELECT email::text, webauthn_handle::text FROM users WHERE id = $1")
            .bind(user)
            .fetch_one(&state.pool)
            .await?;
    let handle = Uuid::parse_str(&handle).map_err(anyhow::Error::from)?;
    let exclude = existing.iter().map(|(_, p)| p.cred_id().clone()).collect();
    let (ccr, reg) = webauthn(&state)?
        .start_passkey_registration(handle, &email, &email, Some(exclude))
        .map_err(webauthn_err)?;
    save_state::<PasskeyRegistration>(&state, &session, "register", &reg).await?;
    Ok(Json(
        serde_json::to_value(ccr).map_err(anyhow::Error::from)?,
    ))
}

#[derive(Deserialize, ToSchema)]
pub struct RegisterFinish {
    /// A label for the passkey, e.g. "Laptop".
    pub name: String,
    /// The PublicKeyCredential from navigator.credentials.create(), as JSON.
    #[schema(value_type = serde_json::Value)]
    pub credential: RegisterPublicKeyCredential,
}

#[derive(Serialize, ToSchema, FromRow)]
pub struct PasskeyView {
    pub id: i64,
    pub name: String,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

/// Finish adding a passkey. The first passkey (with no authenticator app)
/// turns 2FA on: every other session of the user is logged out.
#[utoipa::path(post, path = "/api/v1/auth/webauthn/register/finish", tag = "auth",
    request_body = RegisterFinish,
    responses((status = 201, body = PasskeyView), (status = 400, body = ErrorBody)),
    security(("session" = [])))]
pub async fn register_finish(
    State(state): State<AppState>,
    c: Caller,
    Json(req): Json<RegisterFinish>,
) -> ApiResult<(StatusCode, Json<PasskeyView>)> {
    let (user, session) = session_of(&c)?;
    let name = req.name.trim();
    if name.is_empty() || name.chars().count() > 64 {
        return Err(ApiError::bad_request(
            "invalid_name",
            "name: 1 to 64 characters",
        ));
    }
    let reg: PasskeyRegistration = take_state(&state, &session, "register").await?;
    let pk = webauthn(&state)?
        .finish_passkey_registration(&req.credential, &reg)
        .map_err(webauthn_err)?;
    let mut tx = db::begin(&state.pool, c.scope(None)).await?;
    let was_enabled: bool = sqlx::query_scalar("SELECT user_mfa_enabled($1)")
        .bind(user)
        .fetch_one(&mut *tx)
        .await?;
    let view: PasskeyView = sqlx::query_as(
        "INSERT INTO webauthn_credentials (user_id, cred_id, name, passkey) VALUES ($1, $2, $3, $4) \
         RETURNING id, name, (extract(epoch FROM created_at) * 1000)::bigint AS created_at, \
                   NULL::bigint AS last_used_at",
    )
    .bind(user)
    .bind(AsRef::<[u8]>::as_ref(pk.cred_id()))
    .bind(name)
    .bind(serde_json::to_value(&pk).map_err(anyhow::Error::from)?)
    .fetch_one(&mut *tx)
    .await?;
    if !was_enabled {
        // Same as enabling TOTP: this session proved the factor; every
        // other session must log in again.
        sqlx::query("UPDATE sessions SET mfa_done = true WHERE token_hash = $1")
            .bind(&session)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM sessions WHERE user_id = $1 AND token_hash <> $2")
            .bind(user)
            .bind(&session)
            .execute(&mut *tx)
            .await?;
    }
    db::audit(
        &mut tx,
        Some(user),
        None,
        "passkey.add",
        serde_json::json!({"passkey": view.id, "name": view.name, "mfa_enabled_now": !was_enabled}),
        c.ip,
    )
    .await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(view)))
}

// ---- login (second factor) ----------------------------------------------------------------

/// Start the passkey step of a login. Returns the
/// PublicKeyCredentialRequestOptions for navigator.credentials.get().
#[utoipa::path(post, path = "/api/v1/auth/webauthn/login/start", tag = "auth",
    responses((status = 200, body = serde_json::Value), (status = 400, body = ErrorBody)),
    security(("session" = [])))]
pub async fn login_start(
    State(state): State<AppState>,
    PendingMfa(c): PendingMfa,
) -> ApiResult<Json<Value>> {
    let (user, session) = session_of(&c)?;
    let keys: Vec<Passkey> = passkeys_of(&state, user)
        .await?
        .into_iter()
        .map(|(_, p)| p)
        .collect();
    if keys.is_empty() {
        return Err(ApiError::bad_request(
            "no_passkeys",
            "this account has no passkeys",
        ));
    }
    let (rcr, auth) = webauthn(&state)?
        .start_passkey_authentication(&keys)
        .map_err(webauthn_err)?;
    save_state::<PasskeyAuthentication>(&state, &session, "login", &auth).await?;
    Ok(Json(
        serde_json::to_value(rcr).map_err(anyhow::Error::from)?,
    ))
}

#[derive(Deserialize, ToSchema)]
pub struct LoginFinish {
    /// The PublicKeyCredential from navigator.credentials.get(), as JSON.
    #[schema(value_type = serde_json::Value)]
    pub credential: PublicKeyCredential,
}

/// Finish the passkey step: the session counts as 2FA-verified.
#[utoipa::path(post, path = "/api/v1/auth/webauthn/login/finish", tag = "auth",
    request_body = LoginFinish,
    responses((status = 200, body = StatusResp), (status = 400, body = ErrorBody),
        (status = 429, body = ErrorBody)), security(("session" = [])))]
pub async fn login_finish(
    State(state): State<AppState>,
    PendingMfa(c): PendingMfa,
    Json(req): Json<LoginFinish>,
) -> ApiResult<Json<StatusResp>> {
    let (user, session) = session_of(&c)?;
    let email: String = sqlx::query_scalar("SELECT email::text FROM users WHERE id = $1")
        .bind(user)
        .fetch_one(&state.pool)
        .await?;
    let failures: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM auth_failures WHERE email = $1 AND ts > now() - make_interval(mins => $2)",
    )
    .bind(&email)
    .bind(state.cfg.auth.window_minutes as i32)
    .fetch_one(&state.pool)
    .await?;
    if failures >= state.cfg.auth.login_max_failures {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "too many failed attempts",
        ));
    }
    let auth: PasskeyAuthentication = take_state(&state, &session, "login").await?;
    let result = match webauthn(&state)?.finish_passkey_authentication(&req.credential, &auth) {
        Ok(r) => r,
        Err(e) => {
            sqlx::query("INSERT INTO auth_failures (email, ip) VALUES ($1, $2::inet)")
                .bind(&email)
                .bind(c.ip.map(|i| i.to_string()))
                .execute(&state.pool)
                .await?;
            return Err(webauthn_err(e));
        }
    };
    // Store the new signature counter / backup state.
    for (id, mut pk) in passkeys_of(&state, user).await? {
        if pk.cred_id() == result.cred_id() {
            pk.update_credential(&result);
            sqlx::query(
                "UPDATE webauthn_credentials SET passkey = $1, last_used_at = now() WHERE id = $2",
            )
            .bind(serde_json::to_value(&pk).map_err(anyhow::Error::from)?)
            .bind(id)
            .execute(&state.pool)
            .await?;
        }
    }
    sqlx::query("UPDATE sessions SET mfa_done = true WHERE token_hash = $1")
        .bind(&session)
        .execute(&state.pool)
        .await?;
    Ok(Json(StatusResp {
        status: "ok".into(),
    }))
}

// ---- management --------------------------------------------------------------------------

#[utoipa::path(get, path = "/api/v1/auth/webauthn/credentials", tag = "auth",
    responses((status = 200, body = Vec<PasskeyView>)), security(("session" = [])))]
pub async fn list(State(state): State<AppState>, c: Caller) -> ApiResult<Json<Vec<PasskeyView>>> {
    let (user, _) = session_of(&c)?;
    Ok(Json(
        sqlx::query_as(
            "SELECT id, name, (extract(epoch FROM created_at) * 1000)::bigint AS created_at, \
                    (extract(epoch FROM last_used_at) * 1000)::bigint AS last_used_at \
             FROM webauthn_credentials WHERE user_id = $1 ORDER BY id",
        )
        .bind(user)
        .fetch_all(&state.pool)
        .await?,
    ))
}

/// Remove a passkey. The last remaining second factor cannot be removed.
#[utoipa::path(delete, path = "/api/v1/auth/webauthn/credentials/{id}", tag = "auth",
    params(("id" = i64, Path)),
    responses((status = 204), (status = 404, body = ErrorBody), (status = 409, body = ErrorBody)),
    security(("session" = [])))]
pub async fn remove(
    State(state): State<AppState>,
    c: Caller,
    Path(id): Path<i64>,
) -> ApiResult<StatusCode> {
    let (user, _) = session_of(&c)?;
    let mut tx = db::begin(&state.pool, c.scope(None)).await?;
    let (has_totp, count): (bool, i64) = sqlx::query_as(
        "SELECT (SELECT totp_secret IS NOT NULL FROM users WHERE id = $1), \
                (SELECT count(*) FROM webauthn_credentials WHERE user_id = $1)",
    )
    .bind(user)
    .fetch_one(&mut *tx)
    .await?;
    let gone = sqlx::query("DELETE FROM webauthn_credentials WHERE id = $1 AND user_id = $2")
        .bind(id)
        .bind(user)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if gone == 0 {
        return Err(ApiError::not_found());
    }
    if !has_totp && count <= 1 {
        return Err(ApiError::conflict(
            "last_factor",
            "add another passkey or an authenticator app first",
        ));
    }
    db::audit(
        &mut tx,
        Some(user),
        None,
        "passkey.remove",
        serde_json::json!({"passkey": id}),
        c.ip,
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
