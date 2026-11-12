// SPDX-License-Identifier: MIT OR Apache-2.0
//! Signed decisions (spec section 6, ADR 0021).
//!
//! Two tasks share one [`Verifier`]: the first follows the `keys` KV bucket
//! (trusted issuer keys, revocations), the second subscribes to
//! `decision.global` and writes accepted blocks into xs_block(6) with reason
//! `decision` and the decision's TTL as expiry (enforced in XDP; the gc task
//! removes them later). Decision entries are not touched by the rules
//! bucket's reconcile, and never override an operator's manual block or a
//! source on an allowlist.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use async_nats::jetstream::{self, kv::Operation};
use futures::StreamExt;
use tracing::{info, warn};

use sentinel_bpf::maps;
use sentinel_bpf::rules::{self, RuleKind};
use sentinel_common::abi::{Reason, XsRule};
use sentinel_common::decision::{Decision, KeyDoc, Verifier, BUCKET_KEYS, SUBJECT_DECISIONS};
use sentinel_common::prefix::Prefix;
use sentinel_common::units::now_unix_ms;

use super::Shared;

pub type SharedVerifier = Arc<Mutex<Verifier>>;

pub async fn run_keys(sh: Arc<Shared>, v: SharedVerifier) {
    let mut backoff = Duration::from_secs(1);
    loop {
        if let Err(e) = follow_keys(&sh, &v).await {
            warn!("keys bucket: {e:#}; retrying in {backoff:?}");
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}

async fn follow_keys(sh: &Shared, v: &SharedVerifier) -> Result<()> {
    let js = jetstream::new(sh.nats.clone());
    let store = js
        .get_key_value(BUCKET_KEYS)
        .await
        .context("opening KV bucket keys")?;
    let mut watch = store.watch_with_history(">").await.context("watching")?;
    while let Some(entry) = watch.next().await {
        let entry = entry.context("watch")?;
        let Some(issuer) = entry.key.strip_prefix("issuer.") else {
            continue;
        };
        let mut g = v.lock().expect("verifier lock");
        match entry.operation {
            Operation::Put => match serde_json::from_slice::<KeyDoc>(&entry.value) {
                Ok(doc) if doc.issuer == issuer && doc.v == 1 => match doc.verifying_key() {
                    Ok(k) => {
                        g.set_key(issuer, k, doc.revoked);
                        info!(issuer, revoked = doc.revoked, "decision key");
                    }
                    Err(e) => {
                        // Never keep trusting a key whose update we cannot read.
                        g.remove_key(issuer);
                        warn!(issuer, "bad key document: {e}");
                    }
                },
                Ok(_) | Err(_) => {
                    g.remove_key(issuer);
                    warn!(issuer, "bad key document");
                }
            },
            Operation::Delete | Operation::Purge => g.remove_key(issuer),
        }
    }
    bail!("watch ended")
}

pub async fn run_decisions(sh: Arc<Shared>, v: SharedVerifier) {
    loop {
        match sh.nats.subscribe(SUBJECT_DECISIONS).await {
            Ok(mut sub) => {
                while let Some(msg) = sub.next().await {
                    let result = handle(&sh, &v, &msg.payload);
                    sh.metrics.decision(&result);
                }
            }
            Err(e) => warn!("subscribing to decisions: {e}"),
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// Returns the outcome label.
fn handle(sh: &Shared, v: &SharedVerifier, payload: &[u8]) -> String {
    let mut d: Decision = match serde_json::from_slice(payload) {
        Ok(d) => d,
        Err(e) => {
            warn!("decision: invalid JSON: {e}");
            return "invalid".into();
        }
    };
    let prefix = match v
        .lock()
        .expect("verifier lock")
        .accept(&mut d, now_unix_ms())
    {
        Ok(p) => p,
        Err(e) => {
            warn!(id = %d.id, issuer = %d.issuer, "decision refused: {e}");
            return e.label().into();
        }
    };
    match apply(sh, &d, &prefix) {
        Ok(outcome) => {
            info!(id = %d.id, issuer = %d.issuer, tenant = d.tenant, src = %d.src,
                ttl_s = d.ttl_s, reason = %d.reason, "decision {outcome}");
            outcome.into()
        }
        Err(e) => {
            warn!(id = %d.id, "applying decision: {e:#}");
            "error".into()
        }
    }
}

fn apply(sh: &Shared, d: &Decision, prefix: &Prefix) -> Result<&'static str> {
    // The allowlist always wins: never block anything an allow entry of
    // the tenant or a global one touches.
    let allowed = rules::list(&sh.pins, RuleKind::Allow)?
        .into_iter()
        .any(|(t, p, _)| (t == d.tenant || t == 0) && p.overlaps(prefix));
    if allowed {
        return Ok("skipped_allowlisted");
    }
    let expires_ns = maps::boot_ns() + u64::from(d.ttl_s) * 1_000_000_000;
    let existing = rules::list(&sh.pins, RuleKind::Block)?
        .into_iter()
        .find(|(t, p, _)| *t == d.tenant && p == prefix)
        .map(|(_, _, r)| r);
    let outcome = match existing {
        Some(r) if r.reason != Reason::Decision as u32 => return Ok("skipped_manual"),
        Some(r) if r.expires_ns >= expires_ns => return Ok("kept"),
        Some(_) => "extended",
        None => "applied",
    };
    rules::set(
        &sh.pins,
        RuleKind::Block,
        d.tenant,
        prefix,
        Some(XsRule {
            expires_ns,
            reason: Reason::Decision as u32,
            _pad: 0,
        }),
    )?;
    Ok(outcome)
}
