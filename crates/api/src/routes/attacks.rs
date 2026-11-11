// SPDX-License-Identifier: MIT OR Apache-2.0
//! /tenants/{tid}/attacks and /tenants/{tid}/webhooks.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use utoipa::{IntoParams, ToSchema};

use crate::auth::{require, Caller, Role};
use crate::db::{self, Tx};
use crate::error::{ApiError, ApiResult, ErrorBody};
use crate::webhook;
use crate::AppState;

async fn enter(state: &AppState, c: &Caller, tid: i64, min: Role) -> ApiResult<Tx> {
    let role = c.role(&state.pool, tid).await?;
    require(role, min)?;
    Ok(db::begin(&state.pool, c.scope(Some(tid))).await?)
}

// ---- attacks --------------------------------------------------------------------------

#[derive(Serialize, ToSchema, FromRow)]
pub struct AttackView {
    pub id: i64,
    pub asset_id: Option<i64>,
    /// syn_flood, udp_flood, icmp_flood, ack_flood, volumetric
    pub vector: String,
    /// active or ended
    pub status: String,
    /// Unix ms.
    pub started_at: i64,
    pub ended_at: Option<i64>,
    pub peak_pps: i64,
    pub peak_bps: i64,
    /// Latest rates (0 once ended).
    pub pps: f64,
    pub bps: f64,
    /// Share of the attack traffic dropped at the PoPs (0..1).
    pub dropped_ratio: f64,
    pub pops: Vec<String>,
    /// Most targeted protected IPs.
    pub targets: Vec<String>,
    /// Sources blocked by signed decisions.
    pub decisions: i32,
}

macro_rules! attack_select {
    () => {
        "SELECT id, asset_id, vector, status, (extract(epoch FROM started_at) * 1000)::bigint AS started_at, \
         (extract(epoch FROM ended_at) * 1000)::bigint AS ended_at, coalesce(peak_pps, 0) AS peak_pps, \
         coalesce(peak_bps, 0) AS peak_bps, pps, bps, dropped_ratio, coalesce(pops, '{}') AS pops, \
         targets, decisions FROM attacks"
    };
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ListQuery {
    /// 1-200, default 50
    #[param(required = false)]
    pub limit: Option<i64>,
}

/// Attacks, newest first.
#[utoipa::path(get, path = "/api/v1/tenants/{tid}/attacks", tag = "attacks",
    params(("tid" = i64, Path), ListQuery),
    responses((status = 200, body = Vec<AttackView>), (status = 404, body = ErrorBody)),
    security(("session" = []), ("api_key" = [])))]
pub async fn list_attacks(
    State(state): State<AppState>,
    c: Caller,
    Path(tid): Path<i64>,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<Vec<AttackView>>> {
    let mut tx = enter(&state, &c, tid, Role::Viewer).await?;
    let rows: Vec<AttackView> = sqlx::query_as(concat!(
        attack_select!(),
        " WHERE tenant_id = $1 ORDER BY started_at DESC LIMIT $2"
    ))
    .bind(tid)
    .bind(q.limit.unwrap_or(50).clamp(1, 200))
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(rows))
}

#[derive(Serialize, ToSchema, FromRow)]
pub struct AttackSample {
    pub ts: i64,
    pub pps: f64,
    pub bps: f64,
    pub dropped_ratio: f64,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct SourceView {
    pub src: String,
    pub pps: f64,
}

#[derive(Serialize, ToSchema, FromRow)]
pub struct DecisionView {
    pub id: String,
    pub issuer: String,
    /// Blocked source prefix.
    pub src: String,
    pub reason: String,
    pub ttl_s: i32,
    pub ts: i64,
    pub expires_at: i64,
}

#[derive(Serialize, ToSchema)]
pub struct AttackDetail {
    pub attack: AttackView,
    /// Rates over time (one sample per worker report).
    pub samples: Vec<AttackSample>,
    pub top_sources: Vec<SourceView>,
    /// Blocks issued during the attack.
    pub decisions: Vec<DecisionView>,
}

#[utoipa::path(get, path = "/api/v1/tenants/{tid}/attacks/{aid}", tag = "attacks",
    params(("tid" = i64, Path), ("aid" = i64, Path)),
    responses((status = 200, body = AttackDetail), (status = 404, body = ErrorBody)),
    security(("session" = []), ("api_key" = [])))]
pub async fn get_attack(
    State(state): State<AppState>,
    c: Caller,
    Path((tid, aid)): Path<(i64, i64)>,
) -> ApiResult<Json<AttackDetail>> {
    let mut tx = enter(&state, &c, tid, Role::Viewer).await?;
    let attack: AttackView = sqlx::query_as(concat!(
        attack_select!(),
        " WHERE id = $1 AND tenant_id = $2"
    ))
    .bind(aid)
    .bind(tid)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(ApiError::not_found)?;
    let samples: Vec<AttackSample> = sqlx::query_as(
        "SELECT (extract(epoch FROM ts) * 1000)::bigint AS ts, pps, bps, dropped_ratio \
         FROM attack_samples WHERE attack_id = $1 AND tenant_id = $2 ORDER BY ts LIMIT 5000",
    )
    .bind(aid)
    .bind(tid)
    .fetch_all(&mut *tx)
    .await?;
    let top: serde_json::Value =
        sqlx::query_scalar("SELECT top_sources FROM attacks WHERE id = $1 AND tenant_id = $2")
            .bind(aid)
            .bind(tid)
            .fetch_one(&mut *tx)
            .await?;
    let decisions: Vec<DecisionView> = sqlx::query_as(
        "SELECT id, issuer, src::text AS src, reason, ttl_s, \
                (extract(epoch FROM ts) * 1000)::bigint AS ts, \
                (extract(epoch FROM expires_at) * 1000)::bigint AS expires_at \
         FROM decisions WHERE tenant_id = $1 \
           AND ts >= to_timestamp($2 / 1000.0) - interval '10 seconds' \
           AND ($3::bigint IS NULL OR ts <= to_timestamp($3 / 1000.0) + interval '10 seconds') \
         ORDER BY ts LIMIT 500",
    )
    .bind(tid)
    .bind(attack.started_at)
    .bind(attack.ended_at)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(AttackDetail {
        attack,
        samples,
        top_sources: serde_json::from_value(top).unwrap_or_default(),
        decisions,
    }))
}

// ---- webhooks -----------------------------------------------------------------------------

#[derive(Serialize, ToSchema, FromRow)]
pub struct WebhookView {
    pub id: i64,
    /// discord, slack, http or email
    pub kind: String,
    pub name: String,
    pub target: String,
    pub created_at: i64,
    pub last_at: Option<i64>,
    pub last_status: Option<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct CreateWebhook {
    pub kind: String,
    #[serde(default)]
    pub name: String,
    /// URL (discord, slack, http) or email address.
    pub target: String,
}

#[derive(Serialize, ToSchema)]
pub struct CreatedWebhook {
    pub webhook: WebhookView,
    /// HTTP webhooks only, shown once: verify X-Sentinel-Signature with it.
    pub secret: Option<String>,
}

macro_rules! webhook_select {
    () => {
        "SELECT id, kind, name, target, (extract(epoch FROM created_at) * 1000)::bigint AS created_at, \
         (extract(epoch FROM last_at) * 1000)::bigint AS last_at, last_status FROM webhooks"
    };
}

#[utoipa::path(get, path = "/api/v1/tenants/{tid}/webhooks", tag = "webhooks",
    params(("tid" = i64, Path)),
    responses((status = 200, body = Vec<WebhookView>), (status = 404, body = ErrorBody)),
    security(("session" = []), ("api_key" = [])))]
pub async fn list_webhooks(
    State(state): State<AppState>,
    c: Caller,
    Path(tid): Path<i64>,
) -> ApiResult<Json<Vec<WebhookView>>> {
    let mut tx = enter(&state, &c, tid, Role::Admin).await?;
    let rows = sqlx::query_as(concat!(
        webhook_select!(),
        " WHERE tenant_id = $1 ORDER BY id"
    ))
    .bind(tid)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(rows))
}

/// Notify a Discord or Slack channel, an HTTP endpoint (signed) or an email
/// address when attacks start and end.
#[utoipa::path(post, path = "/api/v1/tenants/{tid}/webhooks", tag = "webhooks",
    params(("tid" = i64, Path)), request_body = CreateWebhook,
    responses((status = 201, body = CreatedWebhook), (status = 400, body = ErrorBody),
        (status = 404, body = ErrorBody), (status = 409, body = ErrorBody)),
    security(("session" = []), ("api_key" = [])))]
pub async fn create_webhook(
    State(state): State<AppState>,
    c: Caller,
    Path(tid): Path<i64>,
    Json(req): Json<CreateWebhook>,
) -> ApiResult<(StatusCode, Json<CreatedWebhook>)> {
    let kind = req.kind.trim().to_lowercase();
    let target = req.target.trim().to_string();
    let name = req.name.trim().to_string();
    if name.chars().count() > 64 {
        return Err(ApiError::bad_request(
            "invalid_name",
            "name: at most 64 characters",
        ));
    }
    webhook::check_target(&state.cfg.webhooks, &kind, &target)
        .map_err(|e| ApiError::bad_request("invalid_target", e))?;
    let mut tx = enter(&state, &c, tid, Role::Admin).await?;
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM webhooks WHERE tenant_id = $1")
        .bind(tid)
        .fetch_one(&mut *tx)
        .await?;
    if n >= state.cfg.webhooks.max_per_tenant {
        return Err(ApiError::conflict("too_many", "webhook limit reached"));
    }
    let secret = (kind == "http").then(|| format!("whsec_{}", crate::crypto::token()));
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO webhooks (tenant_id, kind, name, target, secret) VALUES ($1, $2, $3, $4, $5) RETURNING id",
    )
    .bind(tid)
    .bind(&kind)
    .bind(&name)
    .bind(&target)
    .bind(secret.as_ref().map(|s| state.data_key.encrypt(s.as_bytes())))
    .fetch_one(&mut *tx)
    .await?;
    let view: WebhookView = sqlx::query_as(concat!(webhook_select!(), " WHERE id = $1"))
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    db::audit(
        &mut tx,
        c.user_id,
        Some(tid),
        "webhook.create",
        serde_json::json!({"webhook": id, "kind": kind, "target": target}),
        c.ip,
    )
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(CreatedWebhook {
            webhook: view,
            secret,
        }),
    ))
}

#[utoipa::path(delete, path = "/api/v1/tenants/{tid}/webhooks/{wid}", tag = "webhooks",
    params(("tid" = i64, Path), ("wid" = i64, Path)),
    responses((status = 204), (status = 404, body = ErrorBody)),
    security(("session" = []), ("api_key" = [])))]
pub async fn delete_webhook(
    State(state): State<AppState>,
    c: Caller,
    Path((tid, wid)): Path<(i64, i64)>,
) -> ApiResult<StatusCode> {
    let mut tx = enter(&state, &c, tid, Role::Admin).await?;
    let n = sqlx::query("DELETE FROM webhooks WHERE id = $1 AND tenant_id = $2")
        .bind(wid)
        .bind(tid)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(ApiError::not_found());
    }
    db::audit(
        &mut tx,
        c.user_id,
        Some(tid),
        "webhook.delete",
        serde_json::json!({"webhook": wid}),
        c.ip,
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize, ToSchema)]
pub struct WebhookTestResult {
    pub ok: bool,
    /// "HTTP 200", "sent", or the error.
    pub status: String,
}

/// Sends a test notification now.
#[utoipa::path(post, path = "/api/v1/tenants/{tid}/webhooks/{wid}/test", tag = "webhooks",
    params(("tid" = i64, Path), ("wid" = i64, Path)),
    responses((status = 200, body = WebhookTestResult), (status = 404, body = ErrorBody)),
    security(("session" = []), ("api_key" = [])))]
pub async fn test_webhook(
    State(state): State<AppState>,
    c: Caller,
    Path((tid, wid)): Path<(i64, i64)>,
) -> ApiResult<Json<WebhookTestResult>> {
    // Role and existence through the tenant-scoped transaction first.
    let mut tx = enter(&state, &c, tid, Role::Admin).await?;
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM webhooks WHERE id = $1 AND tenant_id = $2)",
    )
    .bind(wid)
    .bind(tid)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    if !exists {
        return Err(ApiError::not_found());
    }
    let r = webhook::test(&state, tid, wid).await?;
    Ok(Json(match r {
        Ok(s) => WebhookTestResult {
            ok: true,
            status: s,
        },
        Err(e) => WebhookTestResult {
            ok: false,
            status: e,
        },
    }))
}
