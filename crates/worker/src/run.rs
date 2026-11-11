// SPDX-License-Identifier: MIT OR Apache-2.0
//! NATS side of the worker: feed the detector, sign and publish its output.
//!
//! - `telemetry.*.<shard>` for every shard, each in queue group
//!   `workers.shard.<shard>`: NATS gives every shard to one worker, and a
//!   new worker immediately takes over part of the shards.
//! - `stats.>` (all workers): exact per-tenant volume.
//! - KV `rules`: allowlists, so decisions never touch an allowed source.
//! - Publishes `attack.<tenant>` and signed `decision.global`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use async_nats::jetstream::{self, kv::Operation};
use ed25519_dalek::SigningKey;
use futures::StreamExt;
use tracing::{info, warn};

use sentinel_common::decision::{Decision, SUBJECT_DECISIONS};
use sentinel_common::msg::{
    key_id, parse_doc, subject_attack, FlowBatch, RulesDoc, StatsMsg, BUCKET_RULES,
};
use sentinel_common::prefix::Prefix;
use sentinel_common::units::now_unix_ms;

use crate::config::Config;
use crate::detect::{Detector, Output};

type Shared = Arc<Mutex<Detector>>;

pub async fn connect(cfg: &Config) -> Result<async_nats::Client> {
    let seed = std::fs::read_to_string(&cfg.nats.nkey_seed_file)
        .with_context(|| format!("reading {}", cfg.nats.nkey_seed_file.display()))?;
    async_nats::ConnectOptions::with_nkey(seed.trim().to_string())
        .add_root_certificates(cfg.nats.ca.clone())
        .require_tls(true)
        .name(format!("sentinel-worker/{}", cfg.worker.id))
        .retry_on_initial_connect()
        .event_callback(|ev| async move { info!("nats: {ev}") })
        .connect(&cfg.nats.url)
        .await
        .with_context(|| format!("connecting to {}", cfg.nats.url))
}

pub async fn run(cfg: Config, key: SigningKey) -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let sink = match &cfg.clickhouse {
        Some(ch) => Some(crate::clickhouse::start(ch.clone())?),
        None => None,
    };
    let nats = connect(&cfg).await?;
    let det: Shared = Arc::new(Mutex::new(Detector::new(
        &cfg.worker.id,
        cfg.detect.clone(),
        cfg.mitigate.clone(),
    )));
    info!(id = %cfg.worker.id, shards = cfg.worker.shards, "worker running");

    // Stats from every PoP.
    {
        let (nats, det) = (nats.clone(), det.clone());
        tokio::spawn(async move {
            loop {
                match nats.subscribe("stats.>").await {
                    Ok(mut sub) => {
                        while let Some(m) = sub.next().await {
                            match serde_json::from_slice::<StatsMsg>(&m.payload) {
                                Ok(s) if m.subject.as_str() == format!("stats.{}", s.pop) => {
                                    det.lock().expect("detector").on_stats(s, now_unix_ms())
                                }
                                Ok(_) => warn!(subject = %m.subject, "stats for another PoP"),
                                Err(e) => warn!("bad stats: {e}"),
                            }
                        }
                    }
                    Err(e) => warn!("subscribe stats.>: {e}"),
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
    }
    // Telemetry shards, one queue group per shard.
    for shard in 0..cfg.worker.shards {
        let (nats, det, sink) = (nats.clone(), det.clone(), sink.clone());
        tokio::spawn(async move {
            let subject = format!("telemetry.*.{shard}");
            let group = format!("workers.shard.{shard}");
            loop {
                match nats.queue_subscribe(subject.clone(), group.clone()).await {
                    Ok(mut sub) => {
                        while let Some(m) = sub.next().await {
                            match serde_json::from_slice::<FlowBatch>(&m.payload) {
                                Ok(b) => {
                                    det.lock().expect("detector").on_flows(&b);
                                    if let Some(s) = &sink {
                                        s.push(b.flows);
                                    }
                                }
                                Err(e) => warn!("bad telemetry: {e}"),
                            }
                        }
                    }
                    Err(e) => warn!("subscribe {subject}: {e}"),
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
    }
    // Allowlists.
    {
        let (nats, det) = (nats.clone(), det.clone());
        tokio::spawn(async move {
            loop {
                if let Err(e) = follow_allowlists(&nats, &det).await {
                    warn!("rules bucket: {e:#}");
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        });
    }

    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let issuer = cfg.worker.id.clone();
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = shutdown() => break,
        }
        let now = now_unix_ms();
        let out = det.lock().expect("detector").tick(now);
        for o in out {
            if let Err(e) = publish(&nats, &issuer, &key, o, now).await {
                warn!("publish: {e:#}");
            }
        }
    }
    info!("stopping");
    let _ = tokio::time::timeout(Duration::from_secs(2), nats.flush()).await;
    Ok(())
}

async fn publish(
    nats: &async_nats::Client,
    issuer: &str,
    key: &SigningKey,
    o: Output,
    now: u64,
) -> Result<()> {
    match o {
        Output::Attack(a) => {
            info!(tenant = a.tenant, status = %a.status, vector = %a.vector,
                pps = a.pps, decisions = a.decisions, "attack");
            nats.publish(subject_attack(a.tenant), serde_json::to_vec(&*a)?.into())
                .await?;
        }
        Output::Block(b) => {
            let mut d = Decision {
                kind: "decision".into(),
                v: 1,
                id: uuid::Uuid::now_v7().to_string(),
                issuer: issuer.to_string(),
                tenant: b.tenant,
                src: b.src.to_string(),
                action: "block".into(),
                ttl_s: b.ttl_s,
                reason: b.reason,
                ts: now,
                sig: String::new(),
            };
            d.sign(key);
            info!(tenant = d.tenant, src = %d.src, ttl_s = d.ttl_s, reason = %d.reason, "decision");
            nats.publish(SUBJECT_DECISIONS, serde_json::to_vec(&d)?.into())
                .await?;
        }
    }
    Ok(())
}

async fn follow_allowlists(nats: &async_nats::Client, det: &Shared) -> Result<()> {
    let js = jetstream::new(nats.clone());
    let store = js
        .get_key_value(BUCKET_RULES)
        .await
        .context("opening KV bucket rules")?;
    let mut watch = store.watch_with_history(">").await.context("watching")?;
    let mut allow: HashMap<u32, Vec<Prefix>> = HashMap::new();
    while let Some(entry) = watch.next().await {
        let entry = entry.context("watch")?;
        let Some(tenant) = key_id(&entry.key, "tenant") else {
            continue;
        };
        match entry.operation {
            Operation::Put => {
                match parse_doc::<RulesDoc>(&entry.value).and_then(|d| d.validate(&entry.key)) {
                    Ok((_, a, _)) => {
                        allow.insert(tenant, a.into_iter().map(|(p, _, _)| p).collect());
                    }
                    // Keep the previous list: an invalid document never shrinks it.
                    Err(e) => warn!(key = %entry.key, "ignoring rules: {e}"),
                }
            }
            Operation::Delete | Operation::Purge => {
                allow.remove(&tenant);
            }
        }
        det.lock().expect("detector").set_allowlist(allow.clone());
    }
    bail!("watch ended")
}

async fn shutdown() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
    tokio::select! {
        _ = term.recv() => {}
        _ = tokio::signal::ctrl_c() => {}
    }
}
