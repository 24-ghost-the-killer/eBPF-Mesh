// SPDX-License-Identifier: MIT OR Apache-2.0
//! NATS KV -> BPF maps (ADR 0015).
//!
//! One task per bucket. Each keeps a snapshot of its bucket (from a
//! "last value per key" watch) and, after the initial snapshot and after
//! every change, reconciles the maps it owns to exactly what the snapshot
//! describes. Reconciling the whole bucket every time makes ordering,
//! renames (an asset's prefix changes) and restarts trivially correct.
//!
//! Ownership: tenants -> xs_tenants(6), services -> xs_services,
//! rules -> xs_allow(6)/xs_block(6), platform -> the kill-switch flag in
//! xs_cfg. Entries in those maps that KV does not describe are removed.
//!
//! An invalid document is acknowledged with ok=false and the map entries it
//! would replace are kept: a bad push never removes protection.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use async_nats::jetstream::{self, kv::Operation};
use futures::StreamExt;
use tracing::{info, warn};

use sentinel_bpf::maps::{self, U8Val};
use sentinel_bpf::rules::{self, RuleKind};
use sentinel_common::abi::{Reason, XsAsset, XsRule, XsSvcKey, XS_CFG_F_OBSERVE};
use sentinel_common::msg::{
    key_id, parse_doc, pop_key, subject_ack, AssetDoc, ConfigAck, PlatformDoc, PopDoc, RulesDoc,
    ServicesDoc, BUCKET_PLATFORM, BUCKET_RULES, BUCKET_SERVICES, BUCKET_TENANTS, PLATFORM_KEY,
    SCHEMA_V,
};
use sentinel_common::prefix::Prefix;
use sentinel_common::telemetry::diff;
use sentinel_common::units::{now_unix_ms, unix_ms_to_boot_ns};

use super::Shared;

/// Latest value of one key (None = deleted).
struct Val {
    revision: u64,
    value: Option<Vec<u8>>,
}

type Snapshot = BTreeMap<String, Val>;

/// Outcome of one key in a reconcile pass.
struct KeyResult {
    key: String,
    revision: u64,
    deleted: bool,
    version: Option<u64>,
    error: Option<String>,
}

pub async fn run(sh: Arc<Shared>, bucket: &'static str) {
    let mut backoff = Duration::from_secs(1);
    loop {
        match sync(&sh, bucket).await {
            Ok(()) => backoff = Duration::from_secs(1),
            Err(e) => warn!(bucket, "KV sync stopped: {e:#}; retrying in {backoff:?}"),
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}

async fn sync(sh: &Shared, bucket: &'static str) -> Result<()> {
    let js = jetstream::new(sh.nats.clone());
    let store = js
        .get_key_value(bucket)
        .await
        .with_context(|| format!("opening KV bucket {bucket}"))?;
    let empty = store.status().await.context("bucket status")?.values() == 0;
    let mut watch = store.watch_with_history(">").await.context("watching")?;
    let mut snap = Snapshot::new();
    let mut initial = !empty;
    if empty {
        let results = reconcile(sh, bucket, &snap)?;
        publish_acks(sh, bucket, &results, None).await;
        info!(bucket, "in sync (bucket empty)");
    }
    while let Some(entry) = watch.next().await {
        let entry = entry.context("watch")?;
        let value = match entry.operation {
            Operation::Put => Some(entry.value.to_vec()),
            Operation::Delete | Operation::Purge => None,
        };
        snap.insert(
            entry.key.clone(),
            Val {
                revision: entry.revision,
                value,
            },
        );
        if initial {
            if entry.delta > 0 {
                continue;
            }
            initial = false;
            let results = reconcile(sh, bucket, &snap)?;
            publish_acks(sh, bucket, &results, None).await;
            info!(bucket, keys = snap.len(), "in sync");
        } else {
            let results = reconcile(sh, bucket, &snap)?;
            publish_acks(sh, bucket, &results, Some(&entry.key)).await;
        }
        snap.retain(|_, v| v.value.is_some());
    }
    bail!("watch ended")
}

async fn publish_acks(sh: &Shared, bucket: &str, results: &[KeyResult], only: Option<&str>) {
    let mut max_version = 0;
    for r in results.iter().filter(|r| only.is_none_or(|k| k == r.key)) {
        let ok = r.error.is_none();
        sh.metrics.bucket(bucket, ok);
        if ok {
            max_version = max_version.max(r.version.unwrap_or(0));
        } else {
            warn!(bucket, key = %r.key, "rejected: {}", r.error.as_deref().unwrap_or(""));
        }
        let ack = ConfigAck {
            kind: "config_ack".into(),
            v: SCHEMA_V,
            pop: sh.pop().to_string(),
            bucket: bucket.to_string(),
            key: r.key.clone(),
            op: if r.deleted { "delete" } else { "put" }.into(),
            revision: r.revision,
            version: r.version,
            ok,
            error: r.error.clone(),
            ts: now_unix_ms(),
        };
        match serde_json::to_vec(&ack) {
            Ok(body) => {
                if let Err(e) = sh.nats.publish(subject_ack(sh.pop()), body.into()).await {
                    warn!("publishing ack: {e}");
                }
            }
            Err(e) => warn!("encoding ack: {e}"),
        }
    }
    let v = sh
        .config_version
        .fetch_max(max_version, Ordering::Relaxed)
        .max(max_version);
    sh.metrics.config_version.set(v as i64);
}

/// The document's "version", even from a document that failed validation.
fn loose_version(bytes: &[u8]) -> Option<u64> {
    serde_json::from_slice::<serde_json::Value>(bytes)
        .ok()?
        .get("version")?
        .as_u64()
}

fn result(key: &str, v: &Val, outcome: Result<u64, String>) -> KeyResult {
    let (version, error) = match outcome {
        Ok(ver) => (Some(ver), None),
        Err(e) => (v.value.as_deref().and_then(loose_version), Some(e)),
    };
    KeyResult {
        key: key.to_string(),
        revision: v.revision,
        deleted: v.value.is_none(),
        version,
        error,
    }
}

fn reconcile(sh: &Shared, bucket: &str, snap: &Snapshot) -> Result<Vec<KeyResult>> {
    match bucket {
        BUCKET_TENANTS => reconcile_tenants(sh, snap),
        BUCKET_SERVICES => reconcile_services(sh, snap),
        BUCKET_RULES => reconcile_rules(sh, snap),
        BUCKET_PLATFORM => reconcile_platform(sh, snap),
        _ => bail!("unknown bucket {bucket}"),
    }
}

fn deleted(key: &str, v: &Val) -> KeyResult {
    KeyResult {
        key: key.to_string(),
        revision: v.revision,
        deleted: true,
        version: None,
        error: None,
    }
}

// ---- tenants: asset.<id> -> xs_tenants / xs_tenants6 ----------------------------

fn reconcile_tenants(sh: &Shared, snap: &Snapshot) -> Result<Vec<KeyResult>> {
    let actual: HashMap<Prefix, XsAsset> = maps::assets(&sh.pins)?.into_iter().collect();
    let mut desired: HashMap<Prefix, XsAsset> = HashMap::new();
    let mut results = Vec::new();
    let reserved = [
        ("PoP IP", Some(sh.cfg.pop.pop_ip4)),
        ("tunnel endpoint", sh.cfg.pop.tunnel_ep4),
    ];
    for (key, v) in snap {
        let Some(bytes) = &v.value else {
            results.push(deleted(key, v));
            continue;
        };
        let outcome = parse_doc::<AssetDoc>(bytes).and_then(|d| {
            d.validate(key)?;
            for (what, ip) in reserved {
                if let Some(ip) = ip.filter(|ip| d.prefix.contains(IpAddr::V4(*ip))) {
                    return Err(format!("{} contains this PoP's {what} {ip}", d.prefix));
                }
            }
            if let Some(other) = desired.get(&d.prefix).filter(|o| o.asset != d.asset) {
                return Err(format!("{} is already asset {}", d.prefix, other.asset));
            }
            desired.insert(d.prefix, d.to_xs());
            Ok(d.version)
        });
        if outcome.is_err() {
            // Keep whatever this asset had: a bad push never removes protection.
            if let Some(id) = key_id(key, "asset") {
                for (p, a) in actual.iter().filter(|(_, a)| a.asset == id) {
                    desired.entry(*p).or_insert(*a);
                }
            }
        }
        results.push(result(key, v, outcome));
    }
    let d = diff(&actual, &desired);
    for p in &d.delete {
        maps::del_asset(&sh.pins, p)?;
    }
    for (p, a) in &d.put {
        maps::put_asset(&sh.pins, p, a)?;
    }
    if !d.put.is_empty() || !d.delete.is_empty() {
        info!(
            bucket = BUCKET_TENANTS,
            put = d.put.len(),
            deleted = d.delete.len(),
            "maps updated"
        );
    }
    Ok(results)
}

// ---- services: asset.<id> -> xs_services ------------------------------------------

fn reconcile_services(sh: &Shared, snap: &Snapshot) -> Result<Vec<KeyResult>> {
    let map = maps::open(&sh.pins, "xs_services")?;
    let actual: HashMap<XsSvcKey, u8> = maps::entries::<XsSvcKey, U8Val>(&map)?
        .into_iter()
        .map(|(k, v)| (k, v.0))
        .collect();
    let mut desired = HashMap::new();
    let mut results = Vec::new();
    for (key, v) in snap {
        let Some(bytes) = &v.value else {
            results.push(deleted(key, v));
            continue;
        };
        let outcome = parse_doc::<ServicesDoc>(bytes).and_then(|d| {
            for k in d.keys(key)? {
                desired.insert(k, 1u8);
            }
            Ok(d.version)
        });
        if outcome.is_err() {
            if let Some(id) = key_id(key, "asset") {
                for k in actual.keys().filter(|k| k.asset == id) {
                    desired.insert(*k, 1);
                }
            }
        }
        results.push(result(key, v, outcome));
    }
    let d = diff(&actual, &desired);
    for k in &d.delete {
        maps::del(&map, k)?;
    }
    for (k, v) in &d.put {
        maps::put(&map, k, &U8Val(*v))?;
    }
    Ok(results)
}

// ---- rules: tenant.<id> -> xs_allow(6) / xs_block(6) --------------------------------

type RuleId = (RuleKind, u32, Prefix);

fn reconcile_rules(sh: &Shared, snap: &Snapshot) -> Result<Vec<KeyResult>> {
    let mut actual: HashMap<RuleId, XsRule> = HashMap::new();
    for kind in RuleKind::ALL {
        for (tenant, p, r) in rules::list(&sh.pins, kind)? {
            actual.insert((kind, tenant, p), r);
        }
    }
    // One pair of clock readings for the whole pass.
    let (now_unix, now_boot) = (now_unix_ms(), maps::boot_ns());
    let mut desired: HashMap<RuleId, XsRule> = HashMap::new();
    let mut results = Vec::new();
    for (key, v) in snap {
        let Some(bytes) = &v.value else {
            results.push(deleted(key, v));
            continue;
        };
        let outcome = parse_doc::<RulesDoc>(bytes).and_then(|d| {
            let (tenant, allow, block) = d.validate(key)?;
            for (kind, list) in [(RuleKind::Allow, allow), (RuleKind::Block, block)] {
                for (prefix, expires_at, reason) in list {
                    let expires_ns = match expires_at {
                        None => 0,
                        Some(ms) => match unix_ms_to_boot_ns(ms, now_unix, now_boot) {
                            Some(ns) => ns,
                            None => continue, // already expired
                        },
                    };
                    desired.insert(
                        (kind, tenant, prefix),
                        XsRule {
                            expires_ns,
                            reason: reason as u32,
                            _pad: 0,
                        },
                    );
                }
            }
            Ok(d.version)
        });
        if outcome.is_err() {
            if let Some(t) = key_id(key, "tenant") {
                for (id, r) in actual.iter().filter(|(id, _)| id.1 == t) {
                    desired.entry(*id).or_insert(*r);
                }
            }
        }
        results.push(result(key, v, outcome));
    }
    // Blocks written from signed decisions belong to the decision task
    // (ADR 0021): KV only replaces them when it describes the same key.
    actual.retain(|id, r| {
        !(id.0 == RuleKind::Block && r.reason == Reason::Decision as u32)
            || desired.contains_key(id)
    });
    // Expiry converted on another pass differs by the clock jitter between
    // readings; treat < 1 s as unchanged instead of rewriting every rule.
    for (id, want) in desired.iter_mut() {
        if let Some(have) = actual.get(id) {
            if have.reason == want.reason
                && have.expires_ns.abs_diff(want.expires_ns) < 1_000_000_000
            {
                *want = *have;
            }
        }
    }
    let d = diff(&actual, &desired);
    for (kind, tenant, p) in &d.delete {
        rules::set(&sh.pins, *kind, *tenant, p, None)?;
    }
    for ((kind, tenant, p), r) in &d.put {
        rules::set(&sh.pins, *kind, *tenant, p, Some(*r))?;
    }
    Ok(results)
}

// ---- platform: global -> kill switch ------------------------------------------------

fn reconcile_platform(sh: &Shared, snap: &Snapshot) -> Result<Vec<KeyResult>> {
    let mut observe = false;
    let mut drain = false;
    let own = pop_key(sh.pop());
    let mut results = Vec::new();
    for (key, v) in snap {
        let Some(bytes) = &v.value else {
            results.push(deleted(key, v));
            continue;
        };
        if key.starts_with("pop.") {
            // Per-PoP settings: only our own key changes anything here.
            let outcome = parse_doc::<PopDoc>(bytes).and_then(|d| {
                d.validate(key)?;
                if *key == own {
                    if sh.cfg.bird.is_none() {
                        return Err("draining needs [bird] in the agent config".into());
                    }
                    drain = d.drain;
                }
                Ok(d.version)
            });
            if outcome.is_err() && *key == own {
                drain = super::bird::current_drain(sh).unwrap_or(false);
            }
            results.push(result(key, v, outcome));
            continue;
        }
        let outcome = parse_doc::<PlatformDoc>(bytes).and_then(|d| {
            d.validate(key)?;
            observe = d.observe;
            Ok(d.version)
        });
        if outcome.is_err() && key == PLATFORM_KEY {
            // Keep the current setting.
            observe = maps::read_cfg(&sh.pins)
                .map(|c| c.flags & XS_CFG_F_OBSERVE != 0)
                .unwrap_or(false);
        }
        results.push(result(key, v, outcome));
    }
    if sh.cfg.bird.is_some() {
        if let Err(e) = super::bird::set_drain(sh, drain) {
            // Report it on our key's ack (or log when there is none).
            match results.iter_mut().find(|r| r.key == own) {
                Some(r) => r.error = Some(format!("{e:#}")),
                None => warn!("drain: {e:#}"),
            }
        }
    }
    sh.update_cfg(|c| {
        let before = c.flags & XS_CFG_F_OBSERVE != 0;
        if observe {
            c.flags |= XS_CFG_F_OBSERVE;
        } else {
            c.flags &= !XS_CFG_F_OBSERVE;
        }
        if before != observe {
            warn!(
                "kill switch {}",
                if observe {
                    "ON: nothing is dropped"
                } else {
                    "off"
                }
            );
        }
    })?;
    Ok(results)
}
