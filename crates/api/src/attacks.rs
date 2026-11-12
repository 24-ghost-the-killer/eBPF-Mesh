// SPDX-License-Identifier: MIT OR Apache-2.0
//! attack.> and decision.global -> PostgreSQL (ADR 0021).
//!
//! Workers each report their own view of an attack. The API keeps one
//! active attack per tenant and merges the reports: peaks are the maximum
//! (volume comes from the PoPs' exact counters, so every worker sees the
//! same totals), top sources are the union, decisions the sum. The attack
//! ends when every worker that reported it has ended it, or has been silent
//! for a minute (a worker that died).
//!
//! Decisions are recorded only after the same verification the agents do
//! (known, unrevoked issuer; valid signature), so the portal never shows a
//! decision the PoPs would refuse.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{Context, Result};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{FromRow, PgPool};
use tracing::{info, warn};

use sentinel_common::decision::{
    parse_public_key, public_key_b64, Decision, KeyDoc, Verifier, BUCKET_KEYS, SUBJECT_DECISIONS,
};
use sentinel_common::msg::{AttackMsg, SourceRate};
use sentinel_common::units::now_unix_ms;

use crate::db::{self, Scope, Tx};
use crate::kvsync;
use crate::live::ActiveAttack;
use crate::AppState;

/// A worker silent this long no longer keeps an attack open.
pub const REPORTER_TIMEOUT_S: i64 = 60;

const ADMIN: Scope = Scope {
    user: None,
    tenant: None,
    key_tenant: None,
    admin: true,
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Reporter {
    pub id: String,
    pub ended: bool,
    pub ts: u64,
    pub decisions: u32,
}

/// What a report did to the tenant's attack (for webhooks and the live view).
#[derive(Clone, Debug, PartialEq)]
pub enum Change {
    Started(i64),
    Updated(i64),
    Ended(i64),
    Ignored,
}

/// Merges top sources: union, highest rate per source, top 10.
pub fn merge_sources(a: &[SourceRate], b: &[SourceRate]) -> Vec<SourceRate> {
    let mut m: HashMap<&str, f64> = HashMap::new();
    for s in a.iter().chain(b) {
        let e = m.entry(&s.src).or_default();
        *e = e.max(s.pps);
    }
    let mut v: Vec<SourceRate> = m
        .into_iter()
        .map(|(src, pps)| SourceRate {
            src: src.to_string(),
            pps,
        })
        .collect();
    v.sort_by(|x, y| y.pps.total_cmp(&x.pps).then(x.src.cmp(&y.src)));
    v.truncate(10);
    v
}

/// True when no reporter keeps the attack open at `now_ms`.
pub fn all_ended(reporters: &HashMap<String, Reporter>, now_ms: u64) -> bool {
    reporters
        .values()
        .all(|r| r.ended || now_ms.saturating_sub(r.ts) > REPORTER_TIMEOUT_S as u64 * 1000)
}

#[derive(FromRow)]
struct OpenAttack {
    id: i64,
    reporters: Value,
    top_sources: Value,
}

fn ms_ts(ms: u64) -> f64 {
    ms as f64 / 1000.0
}

/// Applies one worker report.
pub async fn record_attack(pool: &PgPool, m: &AttackMsg) -> Result<Change> {
    if m.v != 1 || m.tenant == 0 || !["started", "updated", "ended"].contains(&m.status.as_str()) {
        anyhow::bail!("unsupported attack message");
    }
    let tenant = i64::from(m.tenant);
    let now = now_unix_ms();
    let mut tx = db::begin(pool, ADMIN).await?;
    let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM tenants WHERE id = $1)")
        .bind(tenant)
        .fetch_one(&mut *tx)
        .await?;
    if !exists {
        return Ok(Change::Ignored);
    }
    // One attack per tenant at a time; serialise reports for the tenant.
    sqlx::query("SELECT pg_advisory_xact_lock(7002, $1::int)")
        .bind(m.tenant as i32)
        .execute(&mut *tx)
        .await?;
    let open: Option<OpenAttack> = sqlx::query_as(
        "SELECT id, reporters, top_sources FROM attacks WHERE tenant_id = $1 AND status = 'active'",
    )
    .bind(tenant)
    .fetch_optional(&mut *tx)
    .await?;
    let me = Reporter {
        id: m.id.clone(),
        ended: m.status == "ended",
        ts: m.ts.min(now),
        decisions: m.decisions,
    };
    let asset: Option<i64> = match m.targets.first() {
        Some(t) => sqlx::query_scalar(
            "SELECT id FROM assets WHERE tenant_id = $1 AND protected_prefix >>= $2::inet LIMIT 1",
        )
        .bind(tenant)
        .bind(t)
        .fetch_optional(&mut *tx)
        .await
        .unwrap_or(None),
        None => None,
    };
    let (id, change) = match open {
        None if me.ended => return Ok(Change::Ignored), // already closed
        None => {
            let reporters = HashMap::from([(m.issuer.clone(), me.clone())]);
            let id: i64 = sqlx::query_scalar(
                "INSERT INTO attacks (tenant_id, asset_id, vector, started_at, peak_pps, peak_bps, pops, \
                     status, reporters, pps, bps, dropped_ratio, targets, top_sources, decisions, updated_at) \
                 VALUES ($1, $2, $3, to_timestamp($4), $5, $6, $7, 'active', $8, $9, $10, $11, $12, $13, $14, now()) \
                 RETURNING id",
            )
            .bind(tenant)
            .bind(asset)
            .bind(&m.vector)
            .bind(ms_ts(m.started_at.min(now)))
            .bind(m.peak_pps as i64)
            .bind(m.peak_bps as i64)
            .bind(&m.pops)
            .bind(serde_json::to_value(&reporters)?)
            .bind(m.pps)
            .bind(m.bps)
            .bind(m.dropped_ratio)
            .bind(&m.targets)
            .bind(serde_json::to_value(merge_sources(&m.top_sources, &[]))?)
            .bind(m.decisions as i32)
            .fetch_one(&mut *tx)
            .await?;
            (id, Change::Started(id))
        }
        Some(o) => {
            let mut reporters: HashMap<String, Reporter> =
                serde_json::from_value(o.reporters).unwrap_or_default();
            reporters.insert(m.issuer.clone(), me);
            let top: Vec<SourceRate> = serde_json::from_value(o.top_sources).unwrap_or_default();
            let ended = all_ended(&reporters, now);
            let decisions: u32 = reporters.values().map(|r| r.decisions).sum();
            sqlx::query(
                "UPDATE attacks SET vector = $2, asset_id = coalesce(asset_id, $3), \
                     peak_pps = greatest(peak_pps, $4), peak_bps = greatest(peak_bps, $5), \
                     pops = ARRAY(SELECT DISTINCT unnest(pops || $6::text[]) ORDER BY 1), \
                     reporters = $7, pps = $8, bps = $9, dropped_ratio = $10, \
                     targets = CASE WHEN cardinality($11::text[]) > 0 THEN $11 ELSE targets END, \
                     top_sources = $12, decisions = $13, updated_at = now(), \
                     status = CASE WHEN $14 THEN 'ended' ELSE 'active' END, \
                     ended_at = CASE WHEN $14 THEN to_timestamp($15) ELSE NULL END \
                 WHERE id = $1",
            )
            .bind(o.id)
            .bind(&m.vector)
            .bind(asset)
            .bind(m.peak_pps as i64)
            .bind(m.peak_bps as i64)
            .bind(&m.pops)
            .bind(serde_json::to_value(&reporters)?)
            .bind(if ended { 0.0 } else { m.pps })
            .bind(if ended { 0.0 } else { m.bps })
            .bind(m.dropped_ratio)
            .bind(&m.targets)
            .bind(serde_json::to_value(merge_sources(&top, &m.top_sources))?)
            .bind(decisions as i32)
            .bind(ended)
            .bind(ms_ts(m.ended_at.unwrap_or(m.ts).min(now)))
            .execute(&mut *tx)
            .await?;
            (
                o.id,
                if ended {
                    Change::Ended(o.id)
                } else {
                    Change::Updated(o.id)
                },
            )
        }
    };
    sqlx::query(
        "INSERT INTO attack_samples (attack_id, tenant_id, ts, pps, bps, dropped_ratio) \
         VALUES ($1, $2, to_timestamp($3), $4, $5, $6) ON CONFLICT DO NOTHING",
    )
    .bind(id)
    .bind(tenant)
    .bind(ms_ts(m.ts.min(now)))
    .bind(m.pps)
    .bind(m.bps)
    .bind(m.dropped_ratio)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(change)
}

/// Ends attacks whose workers all went silent. Returns the ended ids.
pub async fn sweep(pool: &PgPool) -> Result<Vec<(i64, i64)>> {
    let mut tx = db::begin(pool, ADMIN).await?;
    let rows: Vec<(i64, i64)> = sqlx::query_as(
        "UPDATE attacks SET status = 'ended', ended_at = updated_at, pps = 0, bps = 0 \
         WHERE status = 'active' AND updated_at < now() - make_interval(secs => $1) \
         RETURNING id, tenant_id",
    )
    .bind(REPORTER_TIMEOUT_S as f64)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(rows)
}

#[derive(FromRow)]
struct ActiveRow {
    tenant_id: i64,
    id: i64,
    vector: String,
    started_at: i64,
    pps: f64,
    bps: f64,
    peak_pps: i64,
    dropped_ratio: f64,
}

/// The live view's entry for an active attack.
pub async fn active_view(pool: &PgPool, id: i64) -> Result<Option<(i64, ActiveAttack)>> {
    let mut tx = db::begin(pool, ADMIN).await?;
    let r: Option<ActiveRow> = sqlx::query_as(
        "SELECT tenant_id, id, vector, (extract(epoch FROM started_at) * 1000)::bigint AS started_at, \
                pps, bps, coalesce(peak_pps, 0) AS peak_pps, dropped_ratio \
         FROM attacks WHERE id = $1 AND status = 'active'",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(r.map(|r| {
        (
            r.tenant_id,
            ActiveAttack {
                id: r.id,
                vector: r.vector,
                started_at: r.started_at,
                pps: r.pps,
                bps: r.bps,
                peak_pps: r.peak_pps as f64,
                dropped_ratio: r.dropped_ratio,
            },
        )
    }))
}

async fn tenant_of(pool: &PgPool, attack: i64) -> Result<Option<i64>> {
    let mut tx = db::begin(pool, ADMIN).await?;
    let t = sqlx::query_scalar("SELECT tenant_id FROM attacks WHERE id = $1")
        .bind(attack)
        .fetch_optional(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(t)
}

async fn after_change(state: &AppState, change: Change) {
    let res: Result<()> = async {
        match change {
            Change::Started(id) | Change::Updated(id) => {
                if let Some((tenant, v)) = active_view(&state.pool, id).await? {
                    state.live.set_attack(tenant, v);
                }
                if matches!(change, Change::Started(_)) {
                    crate::webhook::attack_event(state, id, "attack.started").await?;
                }
            }
            Change::Ended(id) => {
                if let Some(t) = tenant_of(&state.pool, id).await? {
                    state.live.clear_attack(t, id);
                }
                crate::webhook::attack_event(state, id, "attack.ended").await?;
            }
            Change::Ignored => {}
        }
        Ok(())
    }
    .await;
    if let Err(e) = res {
        warn!("after attack change: {e:#}");
    }
}

/// Subscribes to attack.> and keeps the attacks table, the live view and
/// webhooks up to date; sweeps attacks of silent workers.
pub async fn consume_attacks(state: AppState, nats: async_nats::Client) {
    {
        let state = state.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(10));
            loop {
                tick.tick().await;
                match sweep(&state.pool).await {
                    Ok(ended) => {
                        for (id, tenant) in ended {
                            info!(attack = id, "attack ended (workers silent)");
                            state.live.clear_attack(tenant, id);
                            if let Err(e) =
                                crate::webhook::attack_event(&state, id, "attack.ended").await
                            {
                                warn!("webhook: {e:#}");
                            }
                        }
                    }
                    Err(e) => warn!("attack sweep: {e:#}"),
                }
            }
        });
    }
    loop {
        match nats.subscribe("attack.>").await {
            Ok(mut sub) => {
                while let Some(msg) = sub.next().await {
                    let m: AttackMsg = match serde_json::from_slice(&msg.payload) {
                        Ok(m) => m,
                        Err(e) => {
                            warn!("ignoring attack message: {e}");
                            continue;
                        }
                    };
                    if msg.subject.as_str() != format!("attack.{}", m.tenant) {
                        warn!(subject = %msg.subject, "attack for another tenant");
                        continue;
                    }
                    match record_attack(&state.pool, &m).await {
                        Ok(change) => after_change(&state, change).await,
                        Err(e) => warn!("recording attack: {e:#}"),
                    }
                }
            }
            Err(e) => warn!("subscribe attack.>: {e}"),
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

// ---- decisions --------------------------------------------------------------------------

async fn load_keys(pool: &PgPool) -> Result<Verifier> {
    let rows: Vec<(String, Vec<u8>, bool)> =
        sqlx::query_as("SELECT issuer, public_key, revoked FROM signing_keys")
            .fetch_all(pool)
            .await?;
    let mut v = Verifier::default();
    for (issuer, pk, revoked) in rows {
        if let Ok(arr) = <[u8; 32]>::try_from(pk.as_slice()) {
            if let Ok(k) = ed25519_dalek::VerifyingKey::from_bytes(&arr) {
                v.set_key(&issuer, k, revoked);
            }
        }
    }
    Ok(v)
}

/// Verifies and stores one decision; false if refused.
pub async fn record_decision(pool: &PgPool, v: &mut Verifier, d: &mut Decision) -> Result<bool> {
    let prefix = match v.accept(d, now_unix_ms()) {
        Ok(p) => p,
        Err(e) => {
            warn!(issuer = %d.issuer, id = %d.id, "decision not recorded: {e}");
            return Ok(false);
        }
    };
    let mut tx = db::begin(pool, ADMIN).await?;
    let tenant: Option<i64> = if d.tenant == 0 {
        None
    } else {
        match sqlx::query_scalar("SELECT id FROM tenants WHERE id = $1")
            .bind(i64::from(d.tenant))
            .fetch_optional(&mut *tx)
            .await?
        {
            Some(t) => Some(t),
            None => return Ok(false), // unknown tenant: nothing to show it to
        }
    };
    sqlx::query(
        "INSERT INTO decisions (issuer, id, tenant_id, src, action, ttl_s, reason, ts, expires_at) \
         VALUES ($1, $2, $3, $4::cidr, $5, $6, $7, to_timestamp($8), \
                 to_timestamp($8) + make_interval(secs => $6)) ON CONFLICT DO NOTHING",
    )
    .bind(&d.issuer)
    .bind(&d.id)
    .bind(tenant)
    .bind(prefix.to_string())
    .bind(&d.action)
    .bind(d.ttl_s as i32)
    .bind(&d.reason)
    .bind(ms_ts(d.ts))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(true)
}

/// Subscribes to decision.global; reloads the trusted keys every 10 s.
pub async fn consume_decisions(pool: PgPool, nats: async_nats::Client) {
    let mut verifier = Verifier::default();
    let mut loaded = std::time::Instant::now() - Duration::from_secs(60);
    loop {
        match nats.subscribe(SUBJECT_DECISIONS).await {
            Ok(mut sub) => {
                while let Some(msg) = sub.next().await {
                    if loaded.elapsed() > Duration::from_secs(10) {
                        match load_keys(&pool).await {
                            Ok(v) => {
                                // Keep the replay cache: move keys only.
                                verifier = merge_keys(verifier, v);
                                loaded = std::time::Instant::now();
                            }
                            Err(e) => warn!("loading signing keys: {e:#}"),
                        }
                    }
                    let Ok(mut d) = serde_json::from_slice::<Decision>(&msg.payload) else {
                        warn!("ignoring malformed decision");
                        continue;
                    };
                    if let Err(e) = record_decision(&pool, &mut verifier, &mut d).await {
                        warn!("recording decision: {e:#}");
                    }
                }
            }
            Err(e) => warn!("subscribe decisions: {e}"),
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

fn merge_keys(mut old: Verifier, new: Verifier) -> Verifier {
    old.replace_keys(new);
    old
}

// ---- signing keys -----------------------------------------------------------------------

/// Registers (or replaces) an issuer's public key and publishes it to KV.
pub async fn add_signing_key(tx: &mut Tx, issuer: &str, public_key: &str) -> Result<()> {
    sentinel_common::msg::validate_pop_id(issuer).map_err(anyhow::Error::msg)?;
    let k = parse_public_key(public_key).map_err(anyhow::Error::msg)?;
    let revoked: Option<bool> =
        sqlx::query_scalar("SELECT revoked FROM signing_keys WHERE issuer = $1")
            .bind(issuer)
            .fetch_optional(&mut **tx)
            .await?;
    if revoked == Some(true) {
        anyhow::bail!("issuer {issuer} was revoked; use a new issuer name");
    }
    sqlx::query(
        "INSERT INTO signing_keys (issuer, public_key) VALUES ($1, $2) \
         ON CONFLICT (issuer) DO UPDATE SET public_key = EXCLUDED.public_key",
    )
    .bind(issuer)
    .bind(k.to_bytes().to_vec())
    .execute(&mut **tx)
    .await?;
    enqueue_key(tx, issuer).await
}

pub async fn revoke_signing_key(tx: &mut Tx, issuer: &str) -> Result<bool> {
    let n = sqlx::query(
        "UPDATE signing_keys SET revoked = true, revoked_at = coalesce(revoked_at, now()) WHERE issuer = $1",
    )
    .bind(issuer)
    .execute(&mut **tx)
    .await?
    .rows_affected();
    if n > 0 {
        enqueue_key(tx, issuer).await?;
    }
    Ok(n > 0)
}

async fn enqueue_key(tx: &mut Tx, issuer: &str) -> Result<()> {
    let (pk, revoked): (Vec<u8>, bool) =
        sqlx::query_as("SELECT public_key, revoked FROM signing_keys WHERE issuer = $1")
            .bind(issuer)
            .fetch_one(&mut **tx)
            .await?;
    let version: i64 = sqlx::query_scalar("SELECT nextval('config_version_seq')")
        .fetch_one(&mut **tx)
        .await?;
    let arr = <[u8; 32]>::try_from(pk.as_slice()).context("stored key length")?;
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&arr).context("stored key")?;
    let doc = KeyDoc {
        v: 1,
        version: version as u64,
        issuer: issuer.to_string(),
        public_key: base64_of(&vk),
        revoked,
    };
    kvsync::enqueue(
        tx,
        BUCKET_KEYS,
        &KeyDoc::key_name(issuer),
        Some(serde_json::to_value(doc)?),
    )
    .await?;
    Ok(())
}

fn base64_of(k: &ed25519_dalek::VerifyingKey) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(k.to_bytes())
}

/// Registers the API's own decision key at start-up (unless revoked).
pub async fn register_own_key(state: &AppState) -> Result<()> {
    let Some(key) = &state.decision_key else {
        return Ok(());
    };
    let issuer = &state.cfg.decisions.issuer;
    let mut tx = db::begin(&state.pool, ADMIN).await?;
    let current: Option<(Vec<u8>, bool)> =
        sqlx::query_as("SELECT public_key, revoked FROM signing_keys WHERE issuer = $1")
            .bind(issuer)
            .fetch_optional(&mut *tx)
            .await?;
    let pk = key.verifying_key().to_bytes().to_vec();
    match current {
        Some((_, true)) => warn!(issuer, "the API's decision key is revoked"),
        Some((existing, false)) if existing == pk => {}
        _ => {
            add_signing_key(&mut tx, issuer, &public_key_b64(key)).await?;
            db::audit(
                &mut tx,
                None,
                None,
                "signing_key.add",
                json!({"issuer": issuer, "by": "api"}),
                None,
            )
            .await?;
            info!(issuer, "registered the API's decision key");
        }
    }
    tx.commit().await?;
    state.outbox.notify_one();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sources_merge() {
        let s = |src: &str, pps: f64| SourceRate {
            src: src.into(),
            pps,
        };
        let m = merge_sources(
            &[s("203.0.113.1", 10.0), s("203.0.113.2", 50.0)],
            &[s("203.0.113.1", 30.0), s("203.0.113.3", 5.0)],
        );
        assert_eq!(
            m,
            vec![
                s("203.0.113.2", 50.0),
                s("203.0.113.1", 30.0),
                s("203.0.113.3", 5.0)
            ]
        );
        let many: Vec<_> = (0..20)
            .map(|i| s(&format!("203.0.113.{i}"), i as f64))
            .collect();
        assert_eq!(merge_sources(&many, &[]).len(), 10);
    }

    #[test]
    fn end_needs_every_reporter() {
        let r = |ended: bool, ts: u64| Reporter {
            id: "x".into(),
            ended,
            ts,
            decisions: 0,
        };
        let now = 1_000_000;
        let mut m = HashMap::from([
            ("w1".to_string(), r(true, now)),
            ("w2".to_string(), r(false, now)),
        ]);
        assert!(!all_ended(&m, now));
        m.insert("w2".into(), r(false, now - 61_000));
        assert!(
            all_ended(&m, now),
            "a silent worker no longer keeps it open"
        );
        m.insert("w2".into(), r(true, now));
        assert!(all_ended(&m, now));
    }
}
