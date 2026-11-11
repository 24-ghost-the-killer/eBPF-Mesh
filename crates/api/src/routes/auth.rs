// SPDX-License-Identifier: MIT OR Apache-2.0
//! /auth: signup, email verification, login/logout, TOTP, password reset.

use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use utoipa::ToSchema;

use crate::auth::{
    self, check_email, check_password_policy, clear_cookie, create_session, session_cookie, totp,
    Caller, ClientIp, PendingMfa,
};
use crate::crypto::{random_bytes, sha256_hex, token};
use crate::db::{self, Scope};
use crate::error::{ApiError, ApiResult, ErrorBody};
use crate::mail::Mail;
use crate::routes::me::UserView;
use crate::AppState;

#[derive(Deserialize, ToSchema)]
pub struct SignupReq {
    pub email: String,
    pub password: String,
    /// Name of the customer account (tenant) created with the user.
    pub tenant_name: String,
}

#[derive(Serialize, ToSchema)]
pub struct StatusResp {
    pub status: String,
}

fn status(s: &str) -> Json<StatusResp> {
    Json(StatusResp { status: s.into() })
}

#[derive(Deserialize, ToSchema)]
pub struct TokenReq {
    pub token: String,
}

#[derive(Deserialize, ToSchema)]
pub struct LoginReq {
    pub email: String,
    pub password: String,
}

#[derive(Serialize, ToSchema)]
pub struct LoginResp {
    pub user: UserView,
    /// Send back in X-CSRF-Token on every state-changing request.
    pub csrf_token: String,
    /// true: call /auth/2fa/verify before anything else.
    pub mfa_required: bool,
}

#[derive(Deserialize, ToSchema)]
pub struct CodeReq {
    pub code: String,
}

#[derive(Serialize, ToSchema)]
pub struct TotpSetupResp {
    /// Base32 secret for manual entry.
    pub secret: String,
    /// otpauth:// URL for QR codes.
    pub otpauth_url: String,
}

#[derive(Deserialize, ToSchema)]
pub struct EmailReq {
    pub email: String,
}

#[derive(Deserialize, ToSchema)]
pub struct ResetReq {
    pub token: String,
    pub password: String,
}

fn send(state: &AppState, to: &str, subject: &str, body: String) -> ApiResult<()> {
    state
        .mailer
        .send(Mail {
            to: to.into(),
            from: state.cfg.mail.from.clone(),
            subject: subject.into(),
            body,
        })
        .map_err(ApiError::from)
}

async fn new_email_token(
    state: &AppState,
    user: i64,
    purpose: &str,
    hours: i32,
) -> ApiResult<String> {
    let t = token();
    sqlx::query(
        "INSERT INTO email_tokens (token_hash, user_id, purpose, expires_at) \
         VALUES ($1, $2, $3, now() + make_interval(hours => $4))",
    )
    .bind(sha256_hex(&t))
    .bind(user)
    .bind(purpose)
    .bind(hours)
    .execute(&state.pool)
    .await?;
    Ok(t)
}

/// Consumes a one-time email token; returns its user.
async fn use_email_token(state: &AppState, t: &str, purpose: &str) -> ApiResult<i64> {
    sqlx::query_scalar(
        "UPDATE email_tokens SET used_at = now() \
         WHERE token_hash = $1 AND purpose = $2 AND used_at IS NULL AND expires_at > now() \
         RETURNING user_id",
    )
    .bind(sha256_hex(t))
    .bind(purpose)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| ApiError::bad_request("invalid_token", "the link is invalid or has expired"))
}

/// Create an account. Always answers 202 so the endpoint does not reveal
/// which addresses are registered; an existing address gets a notice mail.
#[utoipa::path(post, path = "/api/v1/auth/signup", tag = "auth", request_body = SignupReq,
    responses((status = 202, body = StatusResp), (status = 400, body = ErrorBody)))]
pub async fn signup(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<SignupReq>,
) -> ApiResult<(StatusCode, Json<StatusResp>)> {
    let email = req.email.trim().to_lowercase();
    check_email(&email)?;
    check_password_policy(&req.password, state.cfg.auth.min_password_len)?;
    let name = req.tenant_name.trim();
    if name.is_empty() || name.chars().count() > 100 {
        return Err(ApiError::bad_request(
            "invalid_name",
            "tenant name must be 1-100 characters",
        ));
    }
    let existing: Option<i64> = sqlx::query_scalar("SELECT id FROM users WHERE email = $1")
        .bind(&email)
        .fetch_optional(&state.pool)
        .await?;
    if existing.is_some() {
        send(
            &state,
            &email,
            "Sentinel-Edge sign-up attempt",
            "Someone tried to create an account with this address, which already has one. \
             If it was you, log in or reset your password."
                .into(),
        )?;
        return Ok((StatusCode::ACCEPTED, status("check_email")));
    }
    let hash = auth::hash_password(req.password).await?;
    let mut tx = db::begin(&state.pool, Scope::default()).await?;
    let user: i64 =
        sqlx::query_scalar("INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id")
            .bind(&email)
            .bind(&hash)
            .fetch_one(&mut *tx)
            .await?;
    // Take the id first and scope the transaction to it: under RLS an
    // INSERT ... RETURNING is only allowed for rows the caller may see.
    let tenant: i64 = sqlx::query_scalar("SELECT nextval(pg_get_serial_sequence('tenants', 'id'))")
        .fetch_one(&mut *tx)
        .await?;
    sqlx::query(
        "SELECT set_config('app.tenant_id', $1, true), set_config('app.user_id', $2, true)",
    )
    .bind(tenant.to_string())
    .bind(user.to_string())
    .execute(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO tenants (id, name) VALUES ($1, $2)")
        .bind(tenant)
        .bind(name)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO memberships (user_id, tenant_id, role) VALUES ($1, $2, 'owner')")
        .bind(user)
        .bind(tenant)
        .execute(&mut *tx)
        .await?;
    db::audit(
        &mut tx,
        Some(user),
        Some(tenant),
        "signup",
        serde_json::json!({"email": email}),
        ip,
    )
    .await?;
    tx.commit().await?;
    let t = new_email_token(&state, user, "verify", 48).await?;
    send(
        &state,
        &email,
        "Verify your Sentinel-Edge account",
        format!(
            "Open {}/verify-email?token={t} to verify your address.",
            state.cfg.server.public_url
        ),
    )?;
    Ok((StatusCode::ACCEPTED, status("check_email")))
}

#[utoipa::path(post, path = "/api/v1/auth/verify-email", tag = "auth", request_body = TokenReq,
    responses((status = 200, body = StatusResp), (status = 400, body = ErrorBody)))]
pub async fn verify_email(
    State(state): State<AppState>,
    Json(req): Json<TokenReq>,
) -> ApiResult<Json<StatusResp>> {
    let user = use_email_token(&state, &req.token, "verify").await?;
    sqlx::query("UPDATE users SET email_verified = true WHERE id = $1")
        .bind(user)
        .execute(&state.pool)
        .await?;
    Ok(status("verified"))
}

#[derive(FromRow)]
struct LoginRow {
    id: i64,
    password_hash: String,
    email_verified: bool,
    mfa_enabled: bool,
}

#[utoipa::path(post, path = "/api/v1/auth/login", tag = "auth", request_body = LoginReq,
    responses((status = 200, body = LoginResp), (status = 401, body = ErrorBody),
        (status = 403, body = ErrorBody), (status = 429, body = ErrorBody)))]
pub async fn login(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Json(req): Json<LoginReq>,
) -> ApiResult<Response> {
    let email = req.email.trim().to_lowercase();
    let a = &state.cfg.auth;
    let (by_email, by_ip): (i64, i64) = sqlx::query_as(
        "SELECT count(*) FILTER (WHERE email = $1), count(*) FILTER (WHERE ip = $2::inet) \
         FROM auth_failures WHERE ts > now() - make_interval(mins => $3)",
    )
    .bind(&email)
    .bind(ip.map(|i| i.to_string()))
    .bind(a.window_minutes as i32)
    .fetch_one(&state.pool)
    .await?;
    if by_email >= a.login_max_failures || by_ip >= a.login_ip_max_failures {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "too many failed logins; try again later",
        ));
    }
    let row: Option<LoginRow> = sqlx::query_as(
        "SELECT id, password_hash, email_verified, (totp_secret IS NOT NULL) AS mfa_enabled \
         FROM users WHERE email = $1",
    )
    .bind(&email)
    .fetch_optional(&state.pool)
    .await?;
    let ok =
        auth::verify_password(req.password, row.as_ref().map(|r| r.password_hash.clone())).await;
    let Some(user) = row.filter(|_| ok) else {
        sqlx::query("INSERT INTO auth_failures (email, ip) VALUES ($1, $2::inet)")
            .bind(&email)
            .bind(ip.map(|i| i.to_string()))
            .execute(&state.pool)
            .await?;
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
            "wrong email or password",
        ));
    };
    if !user.email_verified {
        return Err(
            ApiError::forbidden("verify your email address first").with_code("email_unverified")
        );
    }
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok());
    let s = create_session(&state, user.id, !user.mfa_enabled, ip, ua).await?;
    let me = crate::routes::me::user_view(&state, user.id).await?;
    let mut tx = db::begin(
        &state.pool,
        Scope {
            user: Some(user.id),
            ..Default::default()
        },
    )
    .await?;
    db::audit(
        &mut tx,
        Some(user.id),
        None,
        "login",
        serde_json::json!({}),
        ip,
    )
    .await?;
    tx.commit().await?;
    let body = LoginResp {
        user: me,
        csrf_token: s.csrf,
        mfa_required: user.mfa_enabled,
    };
    Ok((
        [(header::SET_COOKIE, session_cookie(&state, &s.token))],
        Json(body),
    )
        .into_response())
}

#[utoipa::path(post, path = "/api/v1/auth/logout", tag = "auth",
    responses((status = 204), (status = 401, body = ErrorBody)), security(("session" = [])))]
pub async fn logout(
    State(state): State<AppState>,
    PendingMfa(c): PendingMfa,
) -> ApiResult<Response> {
    if let Some(s) = &c.session {
        sqlx::query("DELETE FROM sessions WHERE token_hash = $1")
            .bind(&s.hash)
            .execute(&state.pool)
            .await?;
    }
    Ok((
        StatusCode::NO_CONTENT,
        [(header::SET_COOKIE, clear_cookie(&state))],
    )
        .into_response())
}

async fn user_email(state: &AppState, user: i64) -> ApiResult<String> {
    Ok(
        sqlx::query_scalar("SELECT email::text FROM users WHERE id = $1")
            .bind(user)
            .fetch_one(&state.pool)
            .await?,
    )
}

/// Start TOTP enrolment: returns a new secret (stored encrypted until enabled).
#[utoipa::path(post, path = "/api/v1/auth/2fa/setup", tag = "auth",
    responses((status = 200, body = TotpSetupResp), (status = 409, body = ErrorBody)),
    security(("session" = [])))]
pub async fn totp_setup(
    State(state): State<AppState>,
    c: Caller,
) -> ApiResult<Json<TotpSetupResp>> {
    let user = c
        .session
        .as_ref()
        .and(c.user_id)
        .ok_or_else(ApiError::unauthorized)?;
    if c.mfa_enabled {
        return Err(ApiError::conflict(
            "mfa_enabled",
            "two-factor authentication is already on",
        ));
    }
    let secret = random_bytes::<20>();
    let email = user_email(&state, user).await?;
    let (b32, url) = totp::describe(&secret, &email)?;
    sqlx::query("UPDATE users SET totp_pending = $1 WHERE id = $2")
        .bind(state.data_key.encrypt(&secret))
        .bind(user)
        .execute(&state.pool)
        .await?;
    Ok(Json(TotpSetupResp {
        secret: b32,
        otpauth_url: url,
    }))
}

/// Finish enrolment with a code from the app; 2FA is then required at login.
#[utoipa::path(post, path = "/api/v1/auth/2fa/enable", tag = "auth", request_body = CodeReq,
    responses((status = 200, body = StatusResp), (status = 400, body = ErrorBody)),
    security(("session" = [])))]
pub async fn totp_enable(
    State(state): State<AppState>,
    c: Caller,
    Json(req): Json<CodeReq>,
) -> ApiResult<Json<StatusResp>> {
    let user = c
        .session
        .as_ref()
        .and(c.user_id)
        .ok_or_else(ApiError::unauthorized)?;
    let (pending, email): (Option<Vec<u8>>, String) =
        sqlx::query_as("SELECT totp_pending, email::text FROM users WHERE id = $1")
            .bind(user)
            .fetch_one(&state.pool)
            .await?;
    let pending =
        pending.ok_or_else(|| ApiError::bad_request("no_setup", "call /auth/2fa/setup first"))?;
    let secret = state.data_key.decrypt(&pending)?;
    let step = totp::check(&secret, &email, &req.code, 0)
        .ok_or_else(|| ApiError::bad_request("invalid_code", "wrong or expired code"))?;
    let mut tx = db::begin(&state.pool, c.scope(None)).await?;
    sqlx::query(
        "UPDATE users SET totp_secret = totp_pending, totp_pending = NULL, totp_last_step = $1 WHERE id = $2",
    )
    .bind(step)
    .bind(user)
    .execute(&mut *tx)
    .await?;
    // This session proved the code; every other session must log in again.
    let current = c
        .session
        .as_ref()
        .map(|s| s.hash.clone())
        .unwrap_or_default();
    sqlx::query("UPDATE sessions SET mfa_done = true WHERE token_hash = $1")
        .bind(&current)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM sessions WHERE user_id = $1 AND token_hash <> $2")
        .bind(user)
        .bind(&current)
        .execute(&mut *tx)
        .await?;
    db::audit(
        &mut tx,
        Some(user),
        None,
        "mfa.enable",
        serde_json::json!({}),
        c.ip,
    )
    .await?;
    tx.commit().await?;
    Ok(status("enabled"))
}

/// Second login step for users with 2FA.
#[utoipa::path(post, path = "/api/v1/auth/2fa/verify", tag = "auth", request_body = CodeReq,
    responses((status = 200, body = StatusResp), (status = 400, body = ErrorBody),
        (status = 429, body = ErrorBody)), security(("session" = [])))]
pub async fn totp_verify(
    State(state): State<AppState>,
    PendingMfa(c): PendingMfa,
    Json(req): Json<CodeReq>,
) -> ApiResult<Json<StatusResp>> {
    let user = c.user_id.ok_or_else(ApiError::unauthorized)?;
    let session = c.session.clone().ok_or_else(ApiError::unauthorized)?;
    let (secret, last, email): (Option<Vec<u8>>, i64, String) =
        sqlx::query_as("SELECT totp_secret, totp_last_step, email::text FROM users WHERE id = $1")
            .bind(user)
            .fetch_one(&state.pool)
            .await?;
    let Some(secret) = secret else {
        return Ok(status("ok")); // no 2FA on this account
    };
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
    let secret = state.data_key.decrypt(&secret)?;
    let Some(step) = totp::check(&secret, &email, &req.code, last) else {
        sqlx::query("INSERT INTO auth_failures (email, ip) VALUES ($1, $2::inet)")
            .bind(&email)
            .bind(c.ip.map(|i| i.to_string()))
            .execute(&state.pool)
            .await?;
        return Err(ApiError::bad_request(
            "invalid_code",
            "wrong or already used code",
        ));
    };
    sqlx::query("UPDATE users SET totp_last_step = $1 WHERE id = $2 AND totp_last_step < $1")
        .bind(step)
        .bind(user)
        .execute(&state.pool)
        .await?;
    sqlx::query("UPDATE sessions SET mfa_done = true WHERE token_hash = $1")
        .bind(&session.hash)
        .execute(&state.pool)
        .await?;
    Ok(status("ok"))
}

/// Request a password reset link. Always 202.
#[utoipa::path(post, path = "/api/v1/auth/reset-password", tag = "auth", request_body = EmailReq,
    responses((status = 202, body = StatusResp)))]
pub async fn reset_request(
    State(state): State<AppState>,
    Json(req): Json<EmailReq>,
) -> ApiResult<(StatusCode, Json<StatusResp>)> {
    let email = req.email.trim().to_lowercase();
    let user: Option<i64> = sqlx::query_scalar("SELECT id FROM users WHERE email = $1")
        .bind(&email)
        .fetch_optional(&state.pool)
        .await?;
    if let Some(user) = user {
        let t = new_email_token(&state, user, "reset", 1).await?;
        send(
            &state,
            &email,
            "Reset your Sentinel-Edge password",
            format!(
                "Open {}/reset-password?token={t} within one hour.",
                state.cfg.server.public_url
            ),
        )?;
    }
    Ok((StatusCode::ACCEPTED, status("check_email")))
}

/// Set a new password with the emailed token. Ends every session.
#[utoipa::path(post, path = "/api/v1/auth/reset-password/confirm", tag = "auth", request_body = ResetReq,
    responses((status = 200, body = StatusResp), (status = 400, body = ErrorBody)))]
pub async fn reset_confirm(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<ResetReq>,
) -> ApiResult<Json<StatusResp>> {
    check_password_policy(&req.password, state.cfg.auth.min_password_len)?;
    let user = use_email_token(&state, &req.token, "reset").await?;
    let hash = auth::hash_password(req.password).await?;
    let mut tx = db::begin(
        &state.pool,
        Scope {
            user: Some(user),
            ..Default::default()
        },
    )
    .await?;
    sqlx::query("UPDATE users SET password_hash = $1, email_verified = true WHERE id = $2")
        .bind(&hash)
        .bind(user)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM sessions WHERE user_id = $1")
        .bind(user)
        .execute(&mut *tx)
        .await?;
    db::audit(
        &mut tx,
        Some(user),
        None,
        "password.reset",
        serde_json::json!({}),
        ip,
    )
    .await?;
    tx.commit().await?;
    Ok(status("password_changed"))
}
