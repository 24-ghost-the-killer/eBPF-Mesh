// SPDX-License-Identifier: MIT OR Apache-2.0
//! GET /me: the user, their tenants and roles, and the CSRF token.

use axum::extract::State;
use axum::Json;
use serde::Serialize;
use sqlx::FromRow;
use utoipa::ToSchema;

use crate::auth::Caller;
use crate::db::{self, Scope};
use crate::error::{ApiError, ApiResult, ErrorBody};
use crate::AppState;

#[derive(Serialize, ToSchema, FromRow)]
pub struct UserView {
    pub id: i64,
    pub email: String,
    pub email_verified: bool,
    pub mfa_enabled: bool,
    pub is_platform_admin: bool,
}

#[derive(Serialize, ToSchema, FromRow)]
pub struct TenantRole {
    pub id: i64,
    pub name: String,
    /// owner, admin or viewer
    pub role: String,
}

#[derive(Serialize, ToSchema)]
pub struct MeResp {
    pub user: UserView,
    pub tenants: Vec<TenantRole>,
    /// Echo in X-CSRF-Token (sessions only).
    pub csrf_token: Option<String>,
}

pub async fn user_view(state: &AppState, user: i64) -> ApiResult<UserView> {
    Ok(sqlx::query_as(
        "SELECT id, email::text AS email, email_verified, (totp_secret IS NOT NULL) AS mfa_enabled, \
         is_platform_admin FROM users WHERE id = $1",
    )
    .bind(user)
    .fetch_one(&state.pool)
    .await?)
}

#[utoipa::path(get, path = "/api/v1/me", tag = "account",
    responses((status = 200, body = MeResp), (status = 401, body = ErrorBody)),
    security(("session" = [])))]
pub async fn me(State(state): State<AppState>, c: Caller) -> ApiResult<Json<MeResp>> {
    let user = c
        .session
        .as_ref()
        .and(c.user_id)
        .ok_or_else(ApiError::unauthorized)?;
    let mut tx = db::begin(
        &state.pool,
        Scope {
            user: Some(user),
            ..Default::default()
        },
    )
    .await?;
    let tenants: Vec<TenantRole> = sqlx::query_as(
        "SELECT t.id, t.name, m.role FROM memberships m JOIN tenants t ON t.id = m.tenant_id \
         WHERE m.user_id = $1 ORDER BY t.id",
    )
    .bind(user)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(MeResp {
        user: user_view(&state, user).await?,
        tenants,
        csrf_token: c.session.map(|s| s.csrf),
    }))
}
