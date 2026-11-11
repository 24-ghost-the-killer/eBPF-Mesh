// SPDX-License-Identifier: MIT OR Apache-2.0
//! PostgreSQL -> NATS KV through a transactional outbox, and NATS -> PostgreSQL
//! for agent acknowledgements and health (ADR 0016).
//!
//! Every change writes its KV documents to `kv_outbox` in the same
//! transaction as the data. The publisher drains the outbox in order and
//! deletes rows only after NATS confirmed the write, so a NATS outage
//! delays configuration but never loses it. Documents are built from the
//! shared types in `sentinel_common::msg`, the same ones the agent parses.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use futures::StreamExt;
use serde_json::Value;
use sqlx::{FromRow, PgPool};
use tokio::sync::Notify;
use tracing::{info, warn};

use sentinel_common::msg::{
    AssetDoc, ConfigAck, FragDoc, HealthMsg, ModeDoc, PlatformDoc, PolicyDoc, RuleDoc, RulesDoc,
    ServiceDoc, ServicesDoc, BUCKET_PLATFORM, BUCKET_RULES, BUCKET_SERVICES, BUCKET_TENANTS,
    PLATFORM_KEY, SCHEMA_V,
};
use sentinel_common::prefix::Prefix;

use crate::config::NatsCfg;
use crate::db::Tx;

/// Everything about an asset the API and its KV documents need.
#[derive(Clone, Debug, FromRow)]
pub struct AssetRow {
    pub id: i64,
    pub tenant_id: i64,
    pub prefix: String,
    pub origin: String,
    pub tunnel: String,
    pub mode: String,
    pub config_version: i64,
    pub created_ms: i64,
    pub services: Value,
    pub pps_per_src: i32,
    pub burst: i32,
    pub syncookies: bool,
    pub enforce_services: bool,
    pub fragments: String,
}

/// The asset SELECT, as a macro so queries stay compile-time literals
/// (`concat!(asset_select!(), " WHERE ...")`): sqlx refuses runtime SQL.
#[macro_export]
macro_rules! asset_select {
    () => {
        "SELECT a.id, a.tenant_id, a.protected_prefix::text AS prefix, \
         host(a.origin_ip) AS origin, a.tunnel, a.mode, a.config_version, \
         (extract(epoch FROM a.created_at) * 1000)::bigint AS created_ms, \
         p.services, p.pps_per_src, p.burst, p.syncookies, p.enforce_services, p.fragments \
         FROM assets a JOIN policies p ON p.asset_id = a.id"
    };
}

impl AssetRow {
    pub fn services(&self) -> Vec<ServiceDoc> {
        serde_json::from_value(self.services.clone()).unwrap_or_default()
    }

    pub fn policy(&self) -> PolicyDoc {
        PolicyDoc {
            mode: if self.mode == "mitigate" {
                ModeDoc::Mitigate
            } else {
                ModeDoc::Observe
            },
            syncookies: self.syncookies,
            enforce_services: self.enforce_services,
            fragments: if self.fragments == "allow" {
                FragDoc::Allow
            } else {
                FragDoc::Drop
            },
            pps_per_src: self.pps_per_src.max(0) as u32,
            burst: self.burst.max(0) as u32,
        }
    }

    pub fn asset_doc(&self) -> Result<AssetDoc> {
        Ok(AssetDoc {
            v: SCHEMA_V,
            version: self.config_version as u64,
            asset: u32::try_from(self.id).context("asset id exceeds u32")?,
            tenant: u32::try_from(self.tenant_id).context("tenant id exceeds u32")?,
            prefix: self.prefix.parse::<Prefix>().map_err(|e| anyhow!(e.0))?,
            origin: self.origin.parse::<Ipv4Addr>()?,
            policy: self.policy(),
        })
    }

    pub fn services_doc(&self) -> ServicesDoc {
        ServicesDoc {
            v: SCHEMA_V,
            version: self.config_version as u64,
            services: self.services(),
        }
    }
}

pub fn asset_key(id: i64) -> String {
    format!("asset.{id}")
}

pub async fn enqueue(
    tx: &mut Tx,
    bucket: &str,
    key: &str,
    value: Option<Value>,
) -> sqlx::Result<()> {
    sqlx::query("INSERT INTO kv_outbox (bucket, key, value) VALUES ($1, $2, $3)")
        .bind(bucket)
        .bind(key)
        .bind(value)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Queues the asset's tenants and services documents.
pub async fn enqueue_asset(tx: &mut Tx, a: &AssetRow) -> Result<()> {
    let key = asset_key(a.id);
    let asset = serde_json::to_value(a.asset_doc()?)?;
    let services = serde_json::to_value(a.services_doc())?;
    enqueue(tx, BUCKET_TENANTS, &key, Some(asset)).await?;
    enqueue(tx, BUCKET_SERVICES, &key, Some(services)).await?;
    Ok(())
}

pub async fn enqueue_asset_delete(tx: &mut Tx, id: i64) -> sqlx::Result<()> {
    let key = asset_key(id);
    enqueue(tx, BUCKET_TENANTS, &key, None).await?;
    enqueue(tx, BUCKET_SERVICES, &key, None).await
}

#[derive(FromRow)]
struct RuleRow {
    kind: String,
    prefix: String,
    expires_ms: Option<i64>,
}

/// Rebuilds a tenant's (0 = global) rules document with a new version.
pub async fn enqueue_rules(tx: &mut Tx, tenant: i64) -> Result<u64> {
    let rows: Vec<RuleRow> = sqlx::query_as(
        "SELECT kind, prefix::text AS prefix, \
                (extract(epoch FROM expires_at) * 1000)::bigint AS expires_ms \
         FROM rules WHERE tenant_id IS NOT DISTINCT FROM $1 \
           AND (expires_at IS NULL OR expires_at > now()) ORDER BY id",
    )
    .bind((tenant != 0).then_some(tenant))
    .fetch_all(&mut **tx)
    .await?;
    let version: i64 = sqlx::query_scalar(
        "INSERT INTO tenant_rules_version (tenant_id, version) VALUES ($1, nextval('config_version_seq')) \
         ON CONFLICT (tenant_id) DO UPDATE SET version = EXCLUDED.version RETURNING version",
    )
    .bind(tenant)
    .fetch_one(&mut **tx)
    .await?;
    let mut doc = RulesDoc {
        v: SCHEMA_V,
        version: version as u64,
        allow: vec![],
        block: vec![],
    };
    for r in rows {
        let rule = RuleDoc {
            prefix: r
                .prefix
                .parse()
                .map_err(|e: sentinel_common::prefix::PrefixError| anyhow!(e.0))?,
            expires_at: r.expires_ms.map(|m| m.max(0) as u64),
            // Free-text reasons stay in PostgreSQL; agents get a known code.
            reason: Some("manual".into()),
        };
        if r.kind == "allow" {
            doc.allow.push(rule)
        } else {
            doc.block.push(rule)
        }
    }
    enqueue(
        tx,
        BUCKET_RULES,
        &format!("tenant.{tenant}"),
        Some(serde_json::to_value(doc)?),
    )
    .await?;
    Ok(version as u64)
}

pub async fn enqueue_platform(tx: &mut Tx, observe: bool) -> Result<u64> {
    let version: i64 = sqlx::query_scalar("SELECT nextval('config_version_seq')")
        .fetch_one(&mut **tx)
        .await?;
    let doc = PlatformDoc {
        v: SCHEMA_V,
        version: version as u64,
        observe,
    };
    enqueue(
        tx,
        BUCKET_PLATFORM,
        PLATFORM_KEY,
        Some(serde_json::to_value(doc)?),
    )
    .await?;
    Ok(version as u64)
}

// ---- NATS side ---------------------------------------------------------------------

pub async fn connect(cfg: &NatsCfg) -> Result<async_nats::Client> {
    let seed = std::fs::read_to_string(&cfg.nkey_seed_file)
        .with_context(|| format!("reading {}", cfg.nkey_seed_file.display()))?;
    async_nats::ConnectOptions::with_nkey(seed.trim().to_string())
        .add_root_certificates(cfg.ca.clone())
        .require_tls(true)
        .name("sentinel-api")
        .retry_on_initial_connect()
        .event_callback(|ev| async move { info!("nats: {ev}") })
        .connect(&cfg.url)
        .await
        .with_context(|| format!("connecting to {}", cfg.url))
}

#[derive(FromRow)]
struct OutboxRow {
    id: i64,
    bucket: String,
    key: String,
    value: Option<Value>,
}

/// Drains the outbox forever. `wake` is notified after commits that queued
/// documents; a 2-second tick covers everything else.
pub async fn publisher(pool: PgPool, nats: async_nats::Client, wake: Arc<Notify>) {
    let js = async_nats::jetstream::new(nats);
    let mut backoff = Duration::from_millis(500);
    loop {
        match drain_once(&pool, &js).await {
            Ok(0) => {
                backoff = Duration::from_millis(500);
                tokio::select! {
                    _ = wake.notified() => {}
                    _ = tokio::time::sleep(Duration::from_secs(2)) => {}
                }
            }
            Ok(_) => backoff = Duration::from_millis(500),
            Err(e) => {
                warn!("KV outbox: {e:#}; retrying in {backoff:?}");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(30));
            }
        }
    }
}

async fn drain_once(pool: &PgPool, js: &async_nats::jetstream::Context) -> Result<usize> {
    let mut tx = pool.begin().await?;
    let rows: Vec<OutboxRow> = sqlx::query_as(
        "SELECT id, bucket, key, value FROM kv_outbox ORDER BY id LIMIT 100 FOR UPDATE SKIP LOCKED",
    )
    .fetch_all(&mut *tx)
    .await?;
    if rows.is_empty() {
        return Ok(0);
    }
    let mut done = Vec::with_capacity(rows.len());
    for r in &rows {
        let store = js
            .get_key_value(&r.bucket)
            .await
            .with_context(|| format!("bucket {}", r.bucket))?;
        match &r.value {
            Some(v) => {
                store
                    .put(&r.key, serde_json::to_vec(v)?.into())
                    .await
                    .context("KV put")?;
            }
            None => store.delete(&r.key).await.context("KV delete")?,
        }
        done.push(r.id);
    }
    sqlx::query("DELETE FROM kv_outbox WHERE id = ANY($1)")
        .bind(&done)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(done.len())
}

/// Records agents' acknowledgements (config_acks) and health (pops).
pub async fn consumers(pool: PgPool, nats: async_nats::Client) {
    let acks = consume(pool.clone(), nats.clone(), "config.ack.>", record_ack);
    let health = consume(pool, nats, "health.>", record_health);
    tokio::join!(acks, health);
}

async fn consume<F, Fut>(pool: PgPool, nats: async_nats::Client, subject: &'static str, f: F)
where
    F: Fn(PgPool, Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    loop {
        match nats.subscribe(subject).await {
            Ok(mut sub) => {
                while let Some(msg) = sub.next().await {
                    if let Err(e) = f(pool.clone(), msg.payload.to_vec()).await {
                        warn!(subject, "ignoring message: {e:#}");
                    }
                }
            }
            Err(e) => warn!(subject, "subscribe: {e}"),
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

async fn record_ack(pool: PgPool, body: Vec<u8>) -> Result<()> {
    let a: ConfigAck = serde_json::from_slice(&body)?;
    sqlx::query(
        "INSERT INTO config_acks (pop, bucket, key, version, ok, error, ts) \
         VALUES ($1, $2, $3, $4, $5, $6, now()) \
         ON CONFLICT (pop, bucket, key) DO UPDATE \
         SET version = EXCLUDED.version, ok = EXCLUDED.ok, error = EXCLUDED.error, ts = now()",
    )
    .bind(&a.pop)
    .bind(&a.bucket)
    .bind(&a.key)
    .bind(a.version.map(|v| v as i64))
    .bind(a.ok)
    .bind(&a.error)
    .execute(&pool)
    .await?;
    Ok(())
}

async fn record_health(pool: PgPool, body: Vec<u8>) -> Result<()> {
    let h: HealthMsg = serde_json::from_slice(&body)?;
    sqlx::query(
        "INSERT INTO pops (id, region, unicast_ip, status, last_seen, config_version_applied) \
         VALUES ($1, $2, $3::inet, 'active', now(), $4) \
         ON CONFLICT (id) DO UPDATE SET region = EXCLUDED.region, unicast_ip = EXCLUDED.unicast_ip, \
           last_seen = now(), config_version_applied = EXCLUDED.config_version_applied, \
           status = CASE WHEN pops.status = 'draining' THEN 'draining' ELSE 'active' END",
    )
    .bind(&h.pop)
    .bind(&h.region)
    .bind(h.pop_ip4.map(|i| i.to_string()))
    .bind(h.config_version as i64)
    .execute(&pool)
    .await?;
    Ok(())
}
