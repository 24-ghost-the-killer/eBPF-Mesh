// SPDX-License-Identifier: MIT OR Apache-2.0
//! Public status and the platform-admin endpoints.

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use utoipa::ToSchema;

use crate::auth::Caller;
use crate::db::{self, Scope};
use crate::error::{ApiResult, ErrorBody};
use crate::kvsync;
use crate::AppState;

#[derive(Serialize, ToSchema, FromRow)]
pub struct PopStatus {
    pub id: String,
    pub region: String,
    /// up, down or draining
    pub status: String,
    pub last_seen: Option<i64>,
}

#[derive(Serialize, ToSchema)]
pub struct PublicStatus {
    pub pops: Vec<PopStatus>,
}

const POP_STATUS: &str = "SELECT id, region, \
    CASE WHEN status = 'draining' THEN 'draining' \
         WHEN last_seen > now() - interval '15 seconds' THEN 'up' ELSE 'down' END AS status, \
    (extract(epoch FROM last_seen) * 1000)::bigint AS last_seen FROM pops ORDER BY id";

/// Public PoP status (no authentication).
#[utoipa::path(get, path = "/api/v1/status", tag = "public", responses((status = 200, body = PublicStatus)))]
pub async fn status(State(state): State<AppState>) -> ApiResult<Json<PublicStatus>> {
    let pops: Vec<PopStatus> = sqlx::query_as(POP_STATUS).fetch_all(&state.pool).await?;
    Ok(Json(PublicStatus { pops }))
}

#[derive(Serialize, ToSchema, FromRow)]
pub struct AdminPop {
    pub id: String,
    pub region: String,
    pub unicast_ip: Option<String>,
    pub status: String,
    pub last_seen: Option<i64>,
    pub config_version_applied: Option<i64>,
}

#[utoipa::path(get, path = "/api/v1/admin/pops", tag = "admin",
    responses((status = 200, body = Vec<AdminPop>), (status = 403, body = ErrorBody)),
    security(("session" = [])))]
pub async fn admin_pops(
    State(state): State<AppState>,
    c: Caller,
) -> ApiResult<Json<Vec<AdminPop>>> {
    c.require_platform_admin()?;
    let rows: Vec<AdminPop> = sqlx::query_as(
        "SELECT id, region, host(unicast_ip) AS unicast_ip, \
         CASE WHEN status = 'draining' THEN 'draining' \
              WHEN last_seen > now() - interval '15 seconds' THEN 'up' ELSE 'down' END AS status, \
         (extract(epoch FROM last_seen) * 1000)::bigint AS last_seen, config_version_applied \
         FROM pops ORDER BY id",
    )
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(rows))
}

#[derive(Serialize, ToSchema, FromRow)]
pub struct AdminTenant {
    pub id: i64,
    pub name: String,
    pub plan: String,
    pub status: String,
    pub assets: i64,
    pub members: i64,
}

#[utoipa::path(get, path = "/api/v1/admin/tenants", tag = "admin",
    responses((status = 200, body = Vec<AdminTenant>), (status = 403, body = ErrorBody)),
    security(("session" = [])))]
pub async fn admin_tenants(
    State(state): State<AppState>,
    c: Caller,
) -> ApiResult<Json<Vec<AdminTenant>>> {
    c.require_platform_admin()?;
    let mut tx = db::begin(
        &state.pool,
        Scope {
            user: c.user_id,
            admin: true,
            ..Default::default()
        },
    )
    .await?;
    let rows: Vec<AdminTenant> = sqlx::query_as(
        "SELECT t.id, t.name, t.plan, t.status, \
         (SELECT count(*) FROM assets a WHERE a.tenant_id = t.id) AS assets, \
         (SELECT count(*) FROM memberships m WHERE m.tenant_id = t.id) AS members \
         FROM tenants t ORDER BY t.id",
    )
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(rows))
}

#[derive(Deserialize, Serialize, ToSchema)]
pub struct KillSwitch {
    /// true: every PoP counts verdicts but drops nothing.
    pub observe: bool,
}

#[derive(Serialize, ToSchema)]
pub struct KillSwitchResp {
    pub observe: bool,
    pub version: u64,
}

/// All PoPs to observe mode (or back).
#[utoipa::path(post, path = "/api/v1/admin/killswitch", tag = "admin", request_body = KillSwitch,
    responses((status = 200, body = KillSwitchResp), (status = 403, body = ErrorBody)),
    security(("session" = [])))]
pub async fn killswitch(
    State(state): State<AppState>,
    c: Caller,
    Json(k): Json<KillSwitch>,
) -> ApiResult<Json<KillSwitchResp>> {
    c.require_platform_admin()?;
    let mut tx = db::begin(
        &state.pool,
        Scope {
            user: c.user_id,
            admin: true,
            ..Default::default()
        },
    )
    .await?;
    let version = kvsync::enqueue_platform(&mut tx, k.observe).await?;
    db::audit(
        &mut tx,
        c.user_id,
        None,
        "killswitch",
        serde_json::json!({"observe": k.observe}),
        c.ip,
    )
    .await?;
    tx.commit().await?;
    state.outbox.notify_one();
    Ok(Json(KillSwitchResp {
        observe: k.observe,
        version,
    }))
}

// ---- decisions and signing keys (ADR 0021) ---------------------------------------------------

fn admin_scope(c: &Caller) -> Scope {
    Scope {
        user: c.user_id,
        admin: true,
        ..Default::default()
    }
}

#[derive(Serialize, ToSchema, FromRow)]
pub struct AdminDecision {
    pub issuer: String,
    pub id: String,
    /// null = global
    pub tenant_id: Option<i64>,
    pub src: String,
    pub action: String,
    pub ttl_s: i32,
    pub reason: String,
    pub ts: i64,
    pub expires_at: i64,
    pub active: bool,
}

/// Recent decisions from every issuer (workers and the API), newest first.
#[utoipa::path(get, path = "/api/v1/admin/decisions", tag = "admin",
    responses((status = 200, body = Vec<AdminDecision>), (status = 403, body = ErrorBody)),
    security(("session" = [])))]
pub async fn admin_decisions(
    State(state): State<AppState>,
    c: Caller,
) -> ApiResult<Json<Vec<AdminDecision>>> {
    c.require_platform_admin()?;
    let mut tx = db::begin(&state.pool, admin_scope(&c)).await?;
    let rows = sqlx::query_as(
        "SELECT issuer, id, tenant_id, src::text AS src, action, ttl_s, reason, \
                (extract(epoch FROM ts) * 1000)::bigint AS ts, \
                (extract(epoch FROM expires_at) * 1000)::bigint AS expires_at, \
                expires_at > now() AS active \
         FROM decisions ORDER BY ts DESC LIMIT 500",
    )
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(rows))
}

#[derive(Deserialize, ToSchema)]
pub struct NewDecision {
    /// 0 = every tenant (global block).
    pub tenant: u32,
    /// Source address or prefix to block.
    pub src: String,
    pub ttl_s: u32,
    /// Lower-case word, e.g. "manual" or "abuse_report".
    pub reason: String,
}

/// Block a source everywhere now: a decision signed with the API's key and
/// published to every PoP. Always expires.
#[utoipa::path(post, path = "/api/v1/admin/decisions", tag = "admin", request_body = NewDecision,
    responses((status = 202, body = AdminDecision), (status = 400, body = ErrorBody),
        (status = 403, body = ErrorBody), (status = 503, body = ErrorBody)),
    security(("session" = [])))]
pub async fn create_decision(
    State(state): State<AppState>,
    c: Caller,
    Json(req): Json<NewDecision>,
) -> ApiResult<(axum::http::StatusCode, Json<AdminDecision>)> {
    use sentinel_common::decision::{Decision, SUBJECT_DECISIONS};
    c.require_platform_admin()?;
    let unavailable = |m: &str| {
        crate::error::ApiError::new(
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            m,
        )
    };
    let key = state
        .decision_key
        .clone()
        .ok_or_else(|| unavailable("the API has no decision signing key"))?;
    let nats = state
        .nats
        .get()
        .cloned()
        .ok_or_else(|| unavailable("NATS is not connected"))?;
    let src: sentinel_common::prefix::Prefix = req
        .src
        .trim()
        .parse()
        .map_err(|e| crate::error::ApiError::bad_request("invalid_src", format!("{e}")))?;
    let now = sentinel_common::units::now_unix_ms();
    let mut d = Decision {
        kind: "decision".into(),
        v: 1,
        id: uuid::Uuid::now_v7().to_string(),
        issuer: state.cfg.decisions.issuer.clone(),
        tenant: req.tenant,
        src: src.to_string(),
        action: "block".into(),
        ttl_s: req.ttl_s,
        reason: req.reason.trim().to_string(),
        ts: now,
        sig: String::new(),
    };
    d.validate()
        .map_err(|e| crate::error::ApiError::bad_request("invalid_decision", e))?;
    if req.tenant != 0 {
        let mut tx = db::begin(&state.pool, admin_scope(&c)).await?;
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM tenants WHERE id = $1)")
                .bind(i64::from(req.tenant))
                .fetch_one(&mut *tx)
                .await?;
        tx.commit().await?;
        if !exists {
            return Err(crate::error::ApiError::not_found());
        }
    }
    d.sign(&key);
    let mut tx = db::begin(&state.pool, admin_scope(&c)).await?;
    db::audit(
        &mut tx,
        c.user_id,
        (req.tenant != 0).then_some(i64::from(req.tenant)),
        "decision.create",
        serde_json::json!({"id": d.id, "src": d.src, "ttl_s": d.ttl_s, "reason": d.reason}),
        c.ip,
    )
    .await?;
    tx.commit().await?;
    let body = serde_json::to_vec(&d).map_err(anyhow::Error::from)?;
    nats.publish(SUBJECT_DECISIONS, body.into())
        .await
        .map_err(|e| anyhow::anyhow!("publishing decision: {e}"))?;
    Ok((
        axum::http::StatusCode::ACCEPTED,
        Json(AdminDecision {
            issuer: d.issuer,
            id: d.id,
            tenant_id: (req.tenant != 0).then_some(i64::from(req.tenant)),
            src: d.src,
            action: d.action,
            ttl_s: d.ttl_s as i32,
            reason: d.reason,
            ts: now as i64,
            expires_at: (now + u64::from(req.ttl_s) * 1000) as i64,
            active: true,
        }),
    ))
}

#[derive(Serialize, ToSchema, FromRow)]
pub struct SigningKeyView {
    pub issuer: String,
    /// Base64 Ed25519 public key.
    pub public_key: String,
    pub revoked: bool,
    pub created_at: i64,
    pub revoked_at: Option<i64>,
}

#[utoipa::path(get, path = "/api/v1/admin/signing-keys", tag = "admin",
    responses((status = 200, body = Vec<SigningKeyView>), (status = 403, body = ErrorBody)),
    security(("session" = [])))]
pub async fn list_signing_keys(
    State(state): State<AppState>,
    c: Caller,
) -> ApiResult<Json<Vec<SigningKeyView>>> {
    c.require_platform_admin()?;
    let rows = sqlx::query_as(
        "SELECT issuer, encode(public_key, 'base64') AS public_key, revoked, \
                (extract(epoch FROM created_at) * 1000)::bigint AS created_at, \
                (extract(epoch FROM revoked_at) * 1000)::bigint AS revoked_at \
         FROM signing_keys ORDER BY issuer",
    )
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(rows))
}

#[derive(Deserialize, ToSchema)]
pub struct NewSigningKey {
    /// Worker or PoP name (a-z, 0-9, '-').
    pub issuer: String,
    /// Base64 Ed25519 public key (`sentinel-worker key generate`).
    pub public_key: String,
}

/// Trust a worker's decisions (published to every PoP through KV).
#[utoipa::path(post, path = "/api/v1/admin/signing-keys", tag = "admin", request_body = NewSigningKey,
    responses((status = 204), (status = 400, body = ErrorBody), (status = 403, body = ErrorBody)),
    security(("session" = [])))]
pub async fn add_signing_key(
    State(state): State<AppState>,
    c: Caller,
    Json(req): Json<NewSigningKey>,
) -> ApiResult<axum::http::StatusCode> {
    c.require_platform_admin()?;
    let mut tx = db::begin(&state.pool, admin_scope(&c)).await?;
    crate::attacks::add_signing_key(&mut tx, req.issuer.trim(), &req.public_key)
        .await
        .map_err(|e| crate::error::ApiError::bad_request("invalid_key", format!("{e:#}")))?;
    db::audit(
        &mut tx,
        c.user_id,
        None,
        "signing_key.add",
        serde_json::json!({"issuer": req.issuer.trim()}),
        c.ip,
    )
    .await?;
    tx.commit().await?;
    state.outbox.notify_one();
    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// Revoke an issuer: every PoP refuses its decisions from then on.
#[utoipa::path(post, path = "/api/v1/admin/signing-keys/{issuer}/revoke", tag = "admin",
    params(("issuer" = String, Path)),
    responses((status = 204), (status = 403, body = ErrorBody), (status = 404, body = ErrorBody)),
    security(("session" = [])))]
pub async fn revoke_signing_key(
    State(state): State<AppState>,
    c: Caller,
    axum::extract::Path(issuer): axum::extract::Path<String>,
) -> ApiResult<axum::http::StatusCode> {
    c.require_platform_admin()?;
    let mut tx = db::begin(&state.pool, admin_scope(&c)).await?;
    if !crate::attacks::revoke_signing_key(&mut tx, &issuer).await? {
        return Err(crate::error::ApiError::not_found());
    }
    db::audit(
        &mut tx,
        c.user_id,
        None,
        "signing_key.revoke",
        serde_json::json!({"issuer": issuer}),
        c.ip,
    )
    .await?;
    tx.commit().await?;
    state.outbox.notify_one();
    Ok(axum::http::StatusCode::NO_CONTENT)
}
