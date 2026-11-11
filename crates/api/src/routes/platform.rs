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
