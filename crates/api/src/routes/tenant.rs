// SPDX-License-Identifier: MIT OR Apache-2.0
//! /tenants/{tid}/...: assets (protected IPs), policy, tunnel script, status,
//! rules, members, API keys, audit log.
//!
//! Every handler resolves the caller's role in the tenant from the
//! membership row (or the API key) first, then works inside a transaction
//! scoped to that tenant, so RLS enforces the same boundary again.

use std::net::{IpAddr, Ipv4Addr};

use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use utoipa::{IntoParams, ToSchema};

use sentinel_common::msg::{
    subject_probe, FragDoc, ModeDoc, ProbeReq, ProbeResp, ServiceDoc, ServicesDoc, SCHEMA_V,
};
use sentinel_common::prefix::Prefix;
use sentinel_common::tunnel::{ReturnMode, TunnelScript};

use crate::alloc::{pick_free, used_hosts};
use crate::asset_select;
use crate::auth::{require, Caller, Role};
use crate::crypto::{sha256_hex, token};
use crate::db::{self, Tx};
use crate::error::{ApiError, ApiResult, ErrorBody};
use crate::kvsync::{self, AssetRow};
use crate::AppState;

async fn enter(state: &AppState, c: &Caller, tid: i64, min: Role) -> ApiResult<(Role, Tx)> {
    let role = c.role(&state.pool, tid).await?;
    require(role, min)?;
    let tx = db::begin(&state.pool, c.scope(Some(tid))).await?;
    Ok((role, tx))
}

fn wake(state: &AppState) {
    state.outbox.notify_one();
}

// ---- assets -------------------------------------------------------------------------

/// An allowed service (OpenAPI shape of `ServiceDoc`).
#[derive(ToSchema)]
#[allow(dead_code)]
pub struct Service {
    /// "tcp", "udp", "icmp", "icmpv6" or a protocol number.
    pub proto: String,
    /// TCP/UDP destination port; omit for every port of the protocol.
    pub port: Option<u16>,
}

#[derive(Serialize, Deserialize, ToSchema, Clone, Debug, PartialEq)]
pub struct PolicyView {
    /// observe (count only) or mitigate (drop). Mitigate needs 2FA.
    #[schema(value_type = String, example = "observe")]
    pub mode: ModeDoc,
    pub syncookies: bool,
    pub enforce_services: bool,
    #[schema(value_type = String, example = "drop")]
    pub fragments: FragDoc,
    pub pps_per_src: u32,
    pub burst: u32,
    #[schema(value_type = Vec<Service>, example = json!([{"proto": "tcp", "port": 443}]))]
    pub services: Vec<ServiceDoc>,
}

#[derive(Serialize, ToSchema)]
pub struct AssetView {
    pub id: i64,
    pub tenant_id: i64,
    /// The protected IP (allocated from the anycast prefix).
    pub protected_prefix: String,
    pub origin_ip: String,
    pub tunnel: String,
    pub config_version: i64,
    pub created_at: i64,
    pub policy: PolicyView,
}

fn view(a: &AssetRow) -> AssetView {
    let p = a.policy();
    AssetView {
        id: a.id,
        tenant_id: a.tenant_id,
        protected_prefix: a.prefix.clone(),
        origin_ip: a.origin.clone(),
        tunnel: a.tunnel.clone(),
        config_version: a.config_version,
        created_at: a.created_ms,
        policy: PolicyView {
            mode: p.mode,
            syncookies: p.syncookies,
            enforce_services: p.enforce_services,
            fragments: p.fragments,
            pps_per_src: p.pps_per_src,
            burst: p.burst,
            services: a.services(),
        },
    }
}

async fn load_asset(tx: &mut Tx, tid: i64, aid: i64) -> ApiResult<AssetRow> {
    sqlx::query_as::<_, AssetRow>(concat!(
        asset_select!(),
        " WHERE a.id = $1 AND a.tenant_id = $2"
    ))
    .bind(aid)
    .bind(tid)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(ApiError::not_found)
}

fn check_services(services: &[ServiceDoc]) -> ApiResult<()> {
    ServicesDoc {
        v: SCHEMA_V,
        version: 0,
        services: services.to_vec(),
    }
    .keys("asset.1")
    .map(|_| ())
    .map_err(|e| ApiError::bad_request("invalid_services", e))
}

#[utoipa::path(get, path = "/api/v1/tenants/{tid}/assets", tag = "assets",
    params(("tid" = i64, Path)), responses((status = 200, body = Vec<AssetView>),
        (status = 404, body = ErrorBody)), security(("session" = []), ("api_key" = [])))]
pub async fn list_assets(
    State(state): State<AppState>,
    c: Caller,
    Path(tid): Path<i64>,
) -> ApiResult<Json<Vec<AssetView>>> {
    let (_, mut tx) = enter(&state, &c, tid, Role::Viewer).await?;
    let rows: Vec<AssetRow> = sqlx::query_as(concat!(
        asset_select!(),
        " WHERE a.tenant_id = $1 ORDER BY a.id"
    ))
    .bind(tid)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(rows.iter().map(view).collect()))
}

#[utoipa::path(get, path = "/api/v1/tenants/{tid}/assets/{aid}", tag = "assets",
    params(("tid" = i64, Path), ("aid" = i64, Path)),
    responses((status = 200, body = AssetView), (status = 404, body = ErrorBody)),
    security(("session" = []), ("api_key" = [])))]
pub async fn get_asset(
    State(state): State<AppState>,
    c: Caller,
    Path((tid, aid)): Path<(i64, i64)>,
) -> ApiResult<Json<AssetView>> {
    let (_, mut tx) = enter(&state, &c, tid, Role::Viewer).await?;
    let a = load_asset(&mut tx, tid, aid).await?;
    tx.commit().await?;
    Ok(Json(view(&a)))
}

#[derive(Deserialize, ToSchema)]
pub struct CreateAsset {
    /// The customer's own server: tunnel destination.
    #[schema(value_type = String, example = "192.0.2.10")]
    pub origin_ip: Ipv4Addr,
    /// Ports to allow (only enforced once enforce_services is on).
    #[serde(default)]
    #[schema(value_type = Vec<Service>)]
    pub services: Vec<ServiceDoc>,
}

/// Protect a server: allocates a protected IP and starts in observe mode.
#[utoipa::path(post, path = "/api/v1/tenants/{tid}/assets", tag = "assets",
    params(("tid" = i64, Path)), request_body = CreateAsset,
    responses((status = 201, body = AssetView), (status = 400, body = ErrorBody),
        (status = 403, body = ErrorBody), (status = 409, body = ErrorBody)),
    security(("session" = []), ("api_key" = [])))]
pub async fn create_asset(
    State(state): State<AppState>,
    c: Caller,
    Path(tid): Path<i64>,
    Json(req): Json<CreateAsset>,
) -> ApiResult<(StatusCode, Json<AssetView>)> {
    let o = req.origin_ip;
    let ac = &state.cfg.anycast;
    if o.is_unspecified()
        || o.is_loopback()
        || o.is_multicast()
        || o.is_broadcast()
        || o.is_link_local()
        || ac.prefix4.contains(IpAddr::V4(o))
    {
        return Err(ApiError::bad_request(
            "invalid_origin",
            "the origin must be your server's public address",
        ));
    }
    check_services(&req.services)?;
    let (_, mut tx) = enter(&state, &c, tid, Role::Admin).await?;
    // One allocation at a time across all API instances.
    sqlx::query("SELECT pg_advisory_xact_lock(7001)")
        .execute(&mut *tx)
        .await?;
    let used: Vec<String> = sqlx::query_scalar("SELECT p::text FROM used_protected_prefixes() p")
        .fetch_all(&mut *tx)
        .await?;
    let used: Vec<Prefix> = used.iter().filter_map(|p| p.parse().ok()).collect();
    let mut reserved = ac.reserved4.clone();
    reserved.push(ac.tunnel_ep4);
    let ip = pick_free(&ac.prefix4, &reserved, &used_hosts(&used, &ac.prefix4))
        .ok_or_else(|| ApiError::conflict("pool_exhausted", "no protected IPs left"))?;
    let aid: i64 = sqlx::query_scalar(
        "INSERT INTO assets (tenant_id, protected_prefix, origin_ip) VALUES ($1, $2::cidr, $3::inet) RETURNING id",
    )
    .bind(tid)
    .bind(format!("{ip}/32"))
    .bind(o.to_string())
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO policies (asset_id, services) VALUES ($1, $2)")
        .bind(aid)
        .bind(serde_json::to_value(&req.services).map_err(anyhow::Error::from)?)
        .execute(&mut *tx)
        .await?;
    let a = load_asset(&mut tx, tid, aid).await?;
    kvsync::enqueue_asset(&mut tx, &a).await?;
    db::audit(&mut tx, c.user_id, Some(tid), "asset.create",
        serde_json::json!({"asset": aid, "prefix": a.prefix, "origin": a.origin, "api_key": c.key.as_ref().map(|k| k.id)}), c.ip).await?;
    tx.commit().await?;
    wake(&state);
    Ok((StatusCode::CREATED, Json(view(&a))))
}

#[utoipa::path(delete, path = "/api/v1/tenants/{tid}/assets/{aid}", tag = "assets",
    params(("tid" = i64, Path), ("aid" = i64, Path)),
    responses((status = 204), (status = 403, body = ErrorBody), (status = 404, body = ErrorBody)),
    security(("session" = [])))]
pub async fn delete_asset(
    State(state): State<AppState>,
    c: Caller,
    Path((tid, aid)): Path<(i64, i64)>,
) -> ApiResult<StatusCode> {
    let (_, mut tx) = enter(&state, &c, tid, Role::Owner).await?;
    let a = load_asset(&mut tx, tid, aid).await?;
    sqlx::query("DELETE FROM assets WHERE id = $1")
        .bind(aid)
        .execute(&mut *tx)
        .await?;
    kvsync::enqueue_asset_delete(&mut tx, aid).await?;
    db::audit(
        &mut tx,
        c.user_id,
        Some(tid),
        "asset.delete",
        serde_json::json!({"asset": aid, "prefix": a.prefix}),
        c.ip,
    )
    .await?;
    tx.commit().await?;
    wake(&state);
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(get, path = "/api/v1/tenants/{tid}/assets/{aid}/policy", tag = "assets",
    params(("tid" = i64, Path), ("aid" = i64, Path)),
    responses((status = 200, body = PolicyView), (status = 404, body = ErrorBody)),
    security(("session" = []), ("api_key" = [])))]
pub async fn get_policy(
    State(state): State<AppState>,
    c: Caller,
    Path((tid, aid)): Path<(i64, i64)>,
) -> ApiResult<Json<PolicyView>> {
    let (_, mut tx) = enter(&state, &c, tid, Role::Viewer).await?;
    let a = load_asset(&mut tx, tid, aid).await?;
    tx.commit().await?;
    Ok(Json(view(&a).policy))
}

/// Replace the asset's policy (ADR 0017: policy is per protected IP).
#[utoipa::path(put, path = "/api/v1/tenants/{tid}/assets/{aid}/policy", tag = "assets",
    params(("tid" = i64, Path), ("aid" = i64, Path)), request_body = PolicyView,
    responses((status = 200, body = AssetView), (status = 400, body = ErrorBody),
        (status = 403, body = ErrorBody), (status = 404, body = ErrorBody)),
    security(("session" = []), ("api_key" = [])))]
pub async fn put_policy(
    State(state): State<AppState>,
    c: Caller,
    Path((tid, aid)): Path<(i64, i64)>,
    Json(p): Json<PolicyView>,
) -> ApiResult<Json<AssetView>> {
    if p.mode == ModeDoc::Mitigate {
        c.require_mfa()?; // spec: 2FA before protection can be enabled
    }
    check_services(&p.services)?;
    if p.pps_per_src > i32::MAX as u32 || p.burst > i32::MAX as u32 {
        return Err(ApiError::bad_request("invalid_policy", "rate too large"));
    }
    let (_, mut tx) = enter(&state, &c, tid, Role::Admin).await?;
    load_asset(&mut tx, tid, aid).await?;
    sqlx::query(
        "UPDATE assets SET mode = $1, config_version = nextval('config_version_seq') WHERE id = $2",
    )
    .bind(if p.mode == ModeDoc::Mitigate {
        "mitigate"
    } else {
        "observe"
    })
    .bind(aid)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE policies SET services = $1, pps_per_src = $2, burst = $3, syncookies = $4, \
         enforce_services = $5, fragments = $6 WHERE asset_id = $7",
    )
    .bind(serde_json::to_value(&p.services).map_err(anyhow::Error::from)?)
    .bind(p.pps_per_src as i32)
    .bind(p.burst as i32)
    .bind(p.syncookies)
    .bind(p.enforce_services)
    .bind(if p.fragments == FragDoc::Allow {
        "allow"
    } else {
        "drop"
    })
    .bind(aid)
    .execute(&mut *tx)
    .await?;
    let a = load_asset(&mut tx, tid, aid).await?;
    kvsync::enqueue_asset(&mut tx, &a).await?;
    db::audit(
        &mut tx,
        c.user_id,
        Some(tid),
        "policy.update",
        serde_json::json!({"asset": aid, "policy": p}),
        c.ip,
    )
    .await?;
    tx.commit().await?;
    wake(&state);
    Ok(Json(view(&a)))
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct TunnelQuery {
    /// tunnel (default) or dsr
    #[serde(rename = "return")]
    #[param(required = false)]
    pub return_mode: Option<String>,
    /// Use an existing tunnel device (e.g. tunl0) instead of creating one.
    #[param(required = false)]
    pub device: Option<String>,
}

/// The script the customer runs on the origin (spec section 11.6).
#[utoipa::path(get, path = "/api/v1/tenants/{tid}/assets/{aid}/tunnel", tag = "assets",
    params(("tid" = i64, Path), ("aid" = i64, Path), TunnelQuery),
    responses((status = 200, body = String, content_type = "text/x-shellscript"),
        (status = 404, body = ErrorBody)),
    security(("session" = []), ("api_key" = [])))]
pub async fn tunnel_script(
    State(state): State<AppState>,
    c: Caller,
    Path((tid, aid)): Path<(i64, i64)>,
    Query(q): Query<TunnelQuery>,
) -> ApiResult<Response> {
    let (_, mut tx) = enter(&state, &c, tid, Role::Admin).await?;
    let a = load_asset(&mut tx, tid, aid).await?;
    tx.commit().await?;
    let mode = match q.return_mode.as_deref() {
        None | Some("tunnel") => ReturnMode::Tunnel,
        Some("dsr") => ReturnMode::Dsr,
        Some(_) => {
            return Err(ApiError::bad_request(
                "invalid_return",
                "return must be tunnel or dsr",
            ))
        }
    };
    if let Some(d) = &q.device {
        sentinel_common::pin::validate_ifname(d)
            .map_err(|e| ApiError::bad_request("invalid_device", e.to_string()))?;
    }
    let doc = a.asset_doc()?;
    let script = TunnelScript {
        asset_id: doc.asset,
        prefix: doc.prefix,
        origin: doc.origin,
        tunnel_ep: Some(state.cfg.anycast.tunnel_ep4),
        pop_mtu: state.cfg.anycast.pop_mtu,
        return_mode: mode,
        device: q.device.as_deref(),
    }
    .render()
    .map_err(|e| ApiError::bad_request("script", e))?;
    Ok((
        [(header::CONTENT_TYPE, "text/x-shellscript; charset=utf-8")],
        script,
    )
        .into_response())
}

#[derive(Serialize, ToSchema, FromRow)]
pub struct PopApplied {
    pub pop: String,
    pub version: Option<i64>,
    pub ok: bool,
    pub error: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct AssetStatus {
    pub config_version: i64,
    /// PoPs seen in the last 30 seconds.
    pub pops_total: i64,
    /// PoPs that acknowledged this version of the asset and its services.
    pub pops_applied: i64,
    pub pops: Vec<PopApplied>,
}

/// "Active on X of Y PoPs", from the agents' acknowledgements.
#[utoipa::path(get, path = "/api/v1/tenants/{tid}/assets/{aid}/status", tag = "assets",
    params(("tid" = i64, Path), ("aid" = i64, Path)),
    responses((status = 200, body = AssetStatus), (status = 404, body = ErrorBody)),
    security(("session" = []), ("api_key" = [])))]
pub async fn asset_status(
    State(state): State<AppState>,
    c: Caller,
    Path((tid, aid)): Path<(i64, i64)>,
) -> ApiResult<Json<AssetStatus>> {
    let (_, mut tx) = enter(&state, &c, tid, Role::Viewer).await?;
    let a = load_asset(&mut tx, tid, aid).await?;
    tx.commit().await?;
    let key = kvsync::asset_key(aid);
    let pops: Vec<PopApplied> = sqlx::query_as(
        "SELECT p.id AS pop, t.version, \
                coalesce(t.ok AND s.ok AND t.version >= $2 AND s.version >= $2, false) AS ok, \
                coalesce(t.error, s.error) AS error \
         FROM pops p \
         LEFT JOIN config_acks t ON t.pop = p.id AND t.bucket = 'tenants' AND t.key = $1 \
         LEFT JOIN config_acks s ON s.pop = p.id AND s.bucket = 'services' AND s.key = $1 \
         WHERE p.last_seen > now() - interval '30 seconds' ORDER BY p.id",
    )
    .bind(&key)
    .bind(a.config_version)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(AssetStatus {
        config_version: a.config_version,
        pops_total: pops.len() as i64,
        pops_applied: pops.iter().filter(|p| p.ok).count() as i64,
        pops,
    }))
}

#[derive(Serialize, ToSchema)]
pub struct TunnelTestPop {
    pub pop: String,
    /// At least one probe came back through the tunnel.
    pub ok: bool,
    pub sent: u8,
    pub received: u8,
    pub rtt_ms: Option<f64>,
    pub error: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct TunnelTest {
    /// Every live PoP reached the protected IP through the tunnel (and at
    /// least one PoP is live).
    pub ok: bool,
    pub pops: Vec<TunnelTestPop>,
}

/// Probe timeout per PoP (the agent waits up to 0.8 s per echo).
const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(6);

/// Tunnel test (ADR 0020): every live PoP pings the protected IP through
/// the tunnel; a reply proves delivery and the return tunnel.
#[utoipa::path(post, path = "/api/v1/tenants/{tid}/assets/{aid}/tunnel-test", tag = "assets",
    params(("tid" = i64, Path), ("aid" = i64, Path)),
    responses((status = 200, body = TunnelTest), (status = 404, body = ErrorBody),
        (status = 429, body = ErrorBody), (status = 503, body = ErrorBody)),
    security(("session" = []), ("api_key" = [])))]
pub async fn tunnel_test(
    State(state): State<AppState>,
    c: Caller,
    Path((tid, aid)): Path<(i64, i64)>,
) -> ApiResult<Json<TunnelTest>> {
    let (_, mut tx) = enter(&state, &c, tid, Role::Admin).await?;
    let a = load_asset(&mut tx, tid, aid).await?;
    // At most one test per asset every 5 seconds.
    let recent: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_log WHERE tenant_id = $1 AND action = 'asset.tunnel_test' \
         AND (payload->>'asset')::bigint = $2 AND ts > now() - interval '5 seconds'",
    )
    .bind(tid)
    .bind(aid)
    .fetch_one(&mut *tx)
    .await?;
    if recent > 0 {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "wait a few seconds between tunnel tests",
        ));
    }
    db::audit(
        &mut tx,
        c.user_id,
        Some(tid),
        "asset.tunnel_test",
        serde_json::json!({"asset": aid}),
        c.ip,
    )
    .await?;
    tx.commit().await?;
    let nats = state.nats.get().cloned().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            "the PoPs cannot be reached right now",
        )
    })?;
    let asset = u32::try_from(a.id).map_err(|_| ApiError::internal())?;
    let pops: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM pops WHERE last_seen > now() - interval '30 seconds' ORDER BY id",
    )
    .fetch_all(&state.pool)
    .await?;
    let body = serde_json::to_vec(&ProbeReq {
        v: SCHEMA_V,
        asset,
        count: 3,
    })
    .map_err(anyhow::Error::from)?;
    let results = futures::future::join_all(pops.iter().map(|pop| {
        let (nats, body) = (nats.clone(), body.clone());
        async move {
            let r =
                tokio::time::timeout(PROBE_TIMEOUT, nats.request(subject_probe(pop), body.into()))
                    .await;
            let resp = match r {
                Ok(Ok(m)) => serde_json::from_slice::<ProbeResp>(&m.payload)
                    .map_err(|e| format!("bad reply: {e}")),
                Ok(Err(e)) => Err(format!("no answer from the PoP: {e}")),
                Err(_) => Err("the PoP did not answer in time".to_string()),
            };
            match resp {
                Ok(p) => TunnelTestPop {
                    pop: pop.clone(),
                    ok: p.received > 0,
                    sent: p.sent,
                    received: p.received,
                    rtt_ms: p.rtt_ms,
                    error: p.error,
                },
                Err(e) => TunnelTestPop {
                    pop: pop.clone(),
                    ok: false,
                    sent: 0,
                    received: 0,
                    rtt_ms: None,
                    error: Some(e),
                },
            }
        }
    }))
    .await;
    Ok(Json(TunnelTest {
        ok: !results.is_empty() && results.iter().all(|p| p.ok),
        pops: results,
    }))
}

// ---- rules ------------------------------------------------------------------------------

#[derive(Serialize, ToSchema, FromRow)]
pub struct RuleView {
    pub id: i64,
    /// allow or block
    pub kind: String,
    pub prefix: String,
    /// Unix ms; null = permanent (allow only)
    pub expires_at: Option<i64>,
    pub reason: Option<String>,
    pub created_at: i64,
}

#[derive(Deserialize, ToSchema)]
pub struct CreateRule {
    /// allow or block
    pub kind: String,
    /// Source address or prefix.
    pub prefix: String,
    /// Required for blocks.
    pub ttl_seconds: Option<u64>,
    pub reason: Option<String>,
}

macro_rules! rule_select {
    () => {
        "SELECT id, kind, prefix::text AS prefix, \
         (extract(epoch FROM expires_at) * 1000)::bigint AS expires_at, reason, \
         (extract(epoch FROM created_at) * 1000)::bigint AS created_at FROM rules"
    };
}

#[utoipa::path(get, path = "/api/v1/tenants/{tid}/rules", tag = "rules",
    params(("tid" = i64, Path)), responses((status = 200, body = Vec<RuleView>)),
    security(("session" = []), ("api_key" = [])))]
pub async fn list_rules(
    State(state): State<AppState>,
    c: Caller,
    Path(tid): Path<i64>,
) -> ApiResult<Json<Vec<RuleView>>> {
    let (_, mut tx) = enter(&state, &c, tid, Role::Viewer).await?;
    let rows: Vec<RuleView> =
        sqlx::query_as(concat!(rule_select!(), " WHERE tenant_id = $1 ORDER BY id"))
            .bind(tid)
            .fetch_all(&mut *tx)
            .await?;
    tx.commit().await?;
    Ok(Json(rows))
}

/// Allow or block sources for this tenant's protected IPs. Customers can
/// never create global rules; prefixes wider than the configured limit and
/// /0 are refused.
#[utoipa::path(post, path = "/api/v1/tenants/{tid}/rules", tag = "rules",
    params(("tid" = i64, Path)), request_body = CreateRule,
    responses((status = 201, body = RuleView), (status = 400, body = ErrorBody)),
    security(("session" = []), ("api_key" = [])))]
pub async fn create_rule(
    State(state): State<AppState>,
    c: Caller,
    Path(tid): Path<i64>,
    Json(r): Json<CreateRule>,
) -> ApiResult<(StatusCode, Json<RuleView>)> {
    let rc = &state.cfg.rules;
    let prefix: Prefix =
        r.prefix
            .trim()
            .parse()
            .map_err(|e: sentinel_common::prefix::PrefixError| {
                ApiError::bad_request("invalid_prefix", e.0)
            })?;
    prefix
        .check_rule(rc.min_prefix_v4, rc.min_prefix_v6)
        .map_err(|e| ApiError::bad_request("prefix_too_wide", e.0))?;
    let ttl = match (r.kind.as_str(), r.ttl_seconds) {
        ("block", None) => return Err(ApiError::bad_request("ttl_required", "blocks must expire")),
        ("allow" | "block", Some(0)) => {
            return Err(ApiError::bad_request("invalid_ttl", "ttl must be positive"))
        }
        ("allow" | "block", t) => t,
        _ => {
            return Err(ApiError::bad_request(
                "invalid_kind",
                "kind must be allow or block",
            ))
        }
    };
    if ttl.is_some_and(|t| t > rc.max_block_ttl_days * 86400) {
        return Err(ApiError::bad_request(
            "invalid_ttl",
            format!("at most {} days", rc.max_block_ttl_days),
        ));
    }
    let reason = r.reason.map(|s| s.chars().take(200).collect::<String>());
    let (_, mut tx) = enter(&state, &c, tid, Role::Admin).await?;
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM rules WHERE tenant_id = $1")
        .bind(tid)
        .fetch_one(&mut *tx)
        .await?;
    if n >= rc.max_per_tenant {
        return Err(ApiError::conflict("too_many_rules", "rule limit reached"));
    }
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO rules (tenant_id, kind, prefix, expires_at, reason, created_by) \
         VALUES ($1, $2, $3::cidr, now() + make_interval(secs => $4), $5, $6) RETURNING id",
    )
    .bind(tid)
    .bind(&r.kind)
    .bind(prefix.to_string())
    .bind(ttl.map(|t| t as f64))
    .bind(&reason)
    .bind(c.user_id)
    .fetch_one(&mut *tx)
    .await?;
    kvsync::enqueue_rules(&mut tx, tid).await?;
    db::audit(
        &mut tx,
        c.user_id,
        Some(tid),
        "rule.create",
        serde_json::json!({"rule": id, "kind": r.kind, "prefix": prefix.to_string(), "ttl": ttl}),
        c.ip,
    )
    .await?;
    let row: RuleView = sqlx::query_as(concat!(rule_select!(), " WHERE id = $1"))
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    tx.commit().await?;
    wake(&state);
    Ok((StatusCode::CREATED, Json(row)))
}

#[utoipa::path(delete, path = "/api/v1/tenants/{tid}/rules/{rid}", tag = "rules",
    params(("tid" = i64, Path), ("rid" = i64, Path)),
    responses((status = 204), (status = 404, body = ErrorBody)),
    security(("session" = []), ("api_key" = [])))]
pub async fn delete_rule(
    State(state): State<AppState>,
    c: Caller,
    Path((tid, rid)): Path<(i64, i64)>,
) -> ApiResult<StatusCode> {
    let (_, mut tx) = enter(&state, &c, tid, Role::Admin).await?;
    let gone = sqlx::query("DELETE FROM rules WHERE id = $1 AND tenant_id = $2")
        .bind(rid)
        .bind(tid)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if gone == 0 {
        return Err(ApiError::not_found());
    }
    kvsync::enqueue_rules(&mut tx, tid).await?;
    db::audit(
        &mut tx,
        c.user_id,
        Some(tid),
        "rule.delete",
        serde_json::json!({"rule": rid}),
        c.ip,
    )
    .await?;
    tx.commit().await?;
    wake(&state);
    Ok(StatusCode::NO_CONTENT)
}

// ---- members -------------------------------------------------------------------------------

#[derive(Serialize, ToSchema, FromRow)]
pub struct MemberView {
    pub user_id: i64,
    pub email: String,
    pub role: String,
}

#[derive(Deserialize, ToSchema)]
pub struct AddMember {
    pub email: String,
    /// owner, admin or viewer
    pub role: String,
}

#[utoipa::path(get, path = "/api/v1/tenants/{tid}/users", tag = "members",
    params(("tid" = i64, Path)), responses((status = 200, body = Vec<MemberView>)),
    security(("session" = [])))]
pub async fn list_members(
    State(state): State<AppState>,
    c: Caller,
    Path(tid): Path<i64>,
) -> ApiResult<Json<Vec<MemberView>>> {
    let (_, mut tx) = enter(&state, &c, tid, Role::Owner).await?;
    let rows: Vec<MemberView> = sqlx::query_as(
        "SELECT m.user_id, u.email::text AS email, m.role FROM memberships m \
         JOIN users u ON u.id = m.user_id WHERE m.tenant_id = $1 ORDER BY m.user_id",
    )
    .bind(tid)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(rows))
}

/// Add an existing, verified user to the tenant.
#[utoipa::path(post, path = "/api/v1/tenants/{tid}/users", tag = "members",
    params(("tid" = i64, Path)), request_body = AddMember,
    responses((status = 201, body = MemberView), (status = 404, body = ErrorBody),
        (status = 409, body = ErrorBody)), security(("session" = [])))]
pub async fn add_member(
    State(state): State<AppState>,
    c: Caller,
    Path(tid): Path<i64>,
    Json(m): Json<AddMember>,
) -> ApiResult<(StatusCode, Json<MemberView>)> {
    let role = Role::parse(&m.role)
        .ok_or_else(|| ApiError::bad_request("invalid_role", "owner, admin or viewer"))?;
    let (_, mut tx) = enter(&state, &c, tid, Role::Owner).await?;
    let user: Option<(i64, String)> =
        sqlx::query_as("SELECT id, email::text FROM users WHERE email = $1 AND email_verified")
            .bind(m.email.trim().to_lowercase())
            .fetch_optional(&mut *tx)
            .await?;
    let (uid, email) = user.ok_or_else(|| ApiError::not_found().with_code("user_not_found"))?;
    sqlx::query("INSERT INTO memberships (user_id, tenant_id, role) VALUES ($1, $2, $3)")
        .bind(uid)
        .bind(tid)
        .bind(role.as_str())
        .execute(&mut *tx)
        .await?;
    db::audit(
        &mut tx,
        c.user_id,
        Some(tid),
        "member.add",
        serde_json::json!({"user": uid, "role": role.as_str()}),
        c.ip,
    )
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(MemberView {
            user_id: uid,
            email,
            role: role.as_str().into(),
        }),
    ))
}

#[utoipa::path(delete, path = "/api/v1/tenants/{tid}/users/{uid}", tag = "members",
    params(("tid" = i64, Path), ("uid" = i64, Path)),
    responses((status = 204), (status = 404, body = ErrorBody), (status = 409, body = ErrorBody)),
    security(("session" = [])))]
pub async fn remove_member(
    State(state): State<AppState>,
    c: Caller,
    Path((tid, uid)): Path<(i64, i64)>,
) -> ApiResult<StatusCode> {
    let (_, mut tx) = enter(&state, &c, tid, Role::Owner).await?;
    let owners: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM memberships WHERE tenant_id = $1 AND role = 'owner' AND user_id <> $2",
    )
    .bind(tid)
    .bind(uid)
    .fetch_one(&mut *tx)
    .await?;
    if owners == 0 {
        return Err(ApiError::conflict(
            "last_owner",
            "a tenant needs at least one owner",
        ));
    }
    let gone = sqlx::query("DELETE FROM memberships WHERE tenant_id = $1 AND user_id = $2")
        .bind(tid)
        .bind(uid)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if gone == 0 {
        return Err(ApiError::not_found());
    }
    db::audit(
        &mut tx,
        c.user_id,
        Some(tid),
        "member.remove",
        serde_json::json!({"user": uid}),
        c.ip,
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---- API keys ------------------------------------------------------------------------------

#[derive(Serialize, ToSchema, FromRow)]
pub struct KeyView {
    pub id: i64,
    pub name: String,
    pub scopes: Vec<String>,
    pub created_at: i64,
    pub last_used: Option<i64>,
}

#[derive(Deserialize, ToSchema)]
pub struct CreateKey {
    #[serde(default)]
    pub name: String,
    /// read and/or write
    pub scopes: Vec<String>,
}

#[derive(Serialize, ToSchema)]
pub struct NewKey {
    pub id: i64,
    /// Shown once; only its hash is stored.
    pub key: String,
    pub scopes: Vec<String>,
}

#[utoipa::path(get, path = "/api/v1/tenants/{tid}/api-keys", tag = "api-keys",
    params(("tid" = i64, Path)), responses((status = 200, body = Vec<KeyView>)),
    security(("session" = [])))]
pub async fn list_keys(
    State(state): State<AppState>,
    c: Caller,
    Path(tid): Path<i64>,
) -> ApiResult<Json<Vec<KeyView>>> {
    let (_, mut tx) = enter(&state, &c, tid, Role::Owner).await?;
    let rows: Vec<KeyView> = sqlx::query_as(
        "SELECT id, name, scopes, (extract(epoch FROM created_at) * 1000)::bigint AS created_at, \
         (extract(epoch FROM last_used) * 1000)::bigint AS last_used FROM api_keys \
         WHERE tenant_id = $1 ORDER BY id",
    )
    .bind(tid)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(rows))
}

/// Create an API key (owners with 2FA). The key is returned once.
#[utoipa::path(post, path = "/api/v1/tenants/{tid}/api-keys", tag = "api-keys",
    params(("tid" = i64, Path)), request_body = CreateKey,
    responses((status = 201, body = NewKey), (status = 403, body = ErrorBody)),
    security(("session" = [])))]
pub async fn create_key(
    State(state): State<AppState>,
    c: Caller,
    Path(tid): Path<i64>,
    Json(k): Json<CreateKey>,
) -> ApiResult<(StatusCode, Json<NewKey>)> {
    if c.key.is_some() {
        return Err(ApiError::forbidden("API keys cannot create API keys"));
    }
    c.require_mfa()?;
    let mut scopes: Vec<String> = k.scopes.clone();
    scopes.sort();
    scopes.dedup();
    if scopes.is_empty() || scopes.iter().any(|s| s != "read" && s != "write") {
        return Err(ApiError::bad_request(
            "invalid_scopes",
            "scopes: read and/or write",
        ));
    }
    let (_, mut tx) = enter(&state, &c, tid, Role::Owner).await?;
    let key = format!("{}{}", crate::auth::API_KEY_PREFIX, token());
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO api_keys (tenant_id, name, key_hash, scopes, created_by) VALUES ($1, $2, $3, $4, $5) RETURNING id",
    )
    .bind(tid)
    .bind(k.name.chars().take(100).collect::<String>())
    .bind(sha256_hex(&key))
    .bind(&scopes)
    .bind(c.user_id)
    .fetch_one(&mut *tx)
    .await?;
    db::audit(
        &mut tx,
        c.user_id,
        Some(tid),
        "api_key.create",
        serde_json::json!({"key": id, "scopes": scopes}),
        c.ip,
    )
    .await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(NewKey { id, key, scopes })))
}

#[utoipa::path(delete, path = "/api/v1/tenants/{tid}/api-keys/{kid}", tag = "api-keys",
    params(("tid" = i64, Path), ("kid" = i64, Path)),
    responses((status = 204), (status = 404, body = ErrorBody)), security(("session" = [])))]
pub async fn delete_key(
    State(state): State<AppState>,
    c: Caller,
    Path((tid, kid)): Path<(i64, i64)>,
) -> ApiResult<StatusCode> {
    let (_, mut tx) = enter(&state, &c, tid, Role::Owner).await?;
    let gone = sqlx::query("DELETE FROM api_keys WHERE id = $1 AND tenant_id = $2")
        .bind(kid)
        .bind(tid)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if gone == 0 {
        return Err(ApiError::not_found());
    }
    db::audit(
        &mut tx,
        c.user_id,
        Some(tid),
        "api_key.delete",
        serde_json::json!({"key": kid}),
        c.ip,
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---- audit ------------------------------------------------------------------------------------

#[derive(Serialize, ToSchema, FromRow)]
pub struct AuditView {
    pub id: i64,
    pub actor: Option<i64>,
    pub action: String,
    #[schema(value_type = Option<serde_json::Value>)]
    pub payload: Option<serde_json::Value>,
    pub ip: Option<String>,
    pub ts: i64,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct AuditQuery {
    /// Entries older than this id (paging).
    #[param(required = false)]
    pub before: Option<i64>,
    /// 1-500, default 100
    #[param(required = false)]
    pub limit: Option<i64>,
}

#[utoipa::path(get, path = "/api/v1/tenants/{tid}/audit", tag = "audit",
    params(("tid" = i64, Path), AuditQuery), responses((status = 200, body = Vec<AuditView>)),
    security(("session" = [])))]
pub async fn audit_log(
    State(state): State<AppState>,
    c: Caller,
    Path(tid): Path<i64>,
    Query(q): Query<AuditQuery>,
) -> ApiResult<Json<Vec<AuditView>>> {
    let (_, mut tx) = enter(&state, &c, tid, Role::Owner).await?;
    let rows: Vec<AuditView> = sqlx::query_as(
        "SELECT id, actor, action, payload, host(ip) AS ip, \
         (extract(epoch FROM ts) * 1000)::bigint AS ts FROM audit_log \
         WHERE tenant_id = $1 AND id < $2 ORDER BY id DESC LIMIT $3",
    )
    .bind(tid)
    .bind(q.before.unwrap_or(i64::MAX))
    .bind(q.limit.unwrap_or(100).clamp(1, 500))
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(rows))
}
