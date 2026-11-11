// SPDX-License-Identifier: MIT OR Apache-2.0
//! Every request runs in a transaction that tells PostgreSQL who is asking,
//! so Row Level Security (migrations/postgres/0002) applies (ADR 0016).

use sqlx::{PgPool, Postgres, Transaction};

pub type Tx = Transaction<'static, Postgres>;

#[derive(Clone, Copy, Debug, Default)]
pub struct Scope {
    pub user: Option<i64>,
    pub tenant: Option<i64>,
    /// Tenant of a database-verified API key (never from the URL).
    pub key_tenant: Option<i64>,
    pub admin: bool,
}

/// Begins a transaction with app.user_id / app.tenant_id / app.key_tenant /
/// app.is_admin set for its duration (set_config(..., true) = SET LOCAL).
pub async fn begin(pool: &PgPool, scope: Scope) -> Result<Tx, sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        "SELECT set_config('app.user_id', $1, true), set_config('app.tenant_id', $2, true), \
         set_config('app.key_tenant', $3, true), set_config('app.is_admin', $4, true)",
    )
    .bind(scope.user.map(|u| u.to_string()).unwrap_or_default())
    .bind(scope.tenant.map(|t| t.to_string()).unwrap_or_default())
    .bind(scope.key_tenant.map(|t| t.to_string()).unwrap_or_default())
    .bind(if scope.admin { "on" } else { "off" })
    .execute(&mut *tx)
    .await?;
    Ok(tx)
}

/// Appends to the audit log inside the change's transaction.
pub async fn audit(
    tx: &mut Tx,
    actor: Option<i64>,
    tenant: Option<i64>,
    action: &str,
    payload: serde_json::Value,
    ip: Option<std::net::IpAddr>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO audit_log (actor, tenant_id, action, payload, ip) VALUES ($1, $2, $3, $4, $5::inet)",
    )
    .bind(actor)
    .bind(tenant)
    .bind(action)
    .bind(payload)
    .bind(ip.map(|i| i.to_string()))
    .execute(&mut **tx)
    .await?;
    Ok(())
}
