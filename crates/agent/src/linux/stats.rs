// SPDX-License-Identifier: MIT OR Apache-2.0
//! stats.<pop>: per-(tenant, verdict) totals and rates every interval, and
//! the same counters for Prometheus.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use tracing::warn;

use sentinel_bpf::{maps, stats};
use sentinel_common::abi::XS_C_EVENTS_LOST;
use sentinel_common::msg::{subject_stats, StatsMsg, StatsRow, SCHEMA_V};
use sentinel_common::units::now_unix_ms;

use super::Shared;

type Totals = HashMap<(u32, u32), (u64, u64)>;

pub async fn run(sh: Arc<Shared>) {
    let mut tick = tokio::time::interval(Duration::from_millis(sh.cfg.agent.stats_interval_ms));
    let mut prev: Option<(Instant, Totals)> = None;
    loop {
        tick.tick().await;
        match collect(&sh, &mut prev) {
            Ok(Some(msg)) => match serde_json::to_vec(&msg) {
                Ok(body) => {
                    if let Err(e) = sh.nats.publish(subject_stats(sh.pop()), body.into()).await {
                        warn!("publishing stats: {e}");
                    }
                }
                Err(e) => warn!("encoding stats: {e}"),
            },
            Ok(None) => {}
            Err(e) => warn!("reading counters: {e:#}"),
        }
    }
}

fn collect(sh: &Shared, prev: &mut Option<(Instant, Totals)>) -> Result<Option<StatsMsg>> {
    let snap = stats::read(&sh.pins)?;
    let lost = maps::counter_sum(&sh.pins, XS_C_EVENTS_LOST)?;
    let sample_rate = maps::read_cfg(&sh.pins)?.sample_rate;
    sh.metrics.observe_lost(lost);
    let now = Instant::now();
    let totals: Totals = snap
        .entries
        .iter()
        .map(|e| ((e.tenant, e.verdict_id), (e.pkts, e.bytes)))
        .collect();
    let Some((t0, before)) = prev.replace((now, totals.clone())) else {
        return Ok(None); // first reading: no rates yet
    };
    let dt = now.duration_since(t0).as_secs_f64().max(1e-3);
    let mut entries = Vec::with_capacity(snap.entries.len());
    for e in &snap.entries {
        sh.metrics
            .observe_verdict(e.tenant, &e.verdict, e.pkts, e.bytes);
        let (p0, b0) = before
            .get(&(e.tenant, e.verdict_id))
            .copied()
            .unwrap_or((0, 0));
        entries.push(StatsRow {
            tenant: e.tenant,
            verdict: e.verdict.clone(),
            pkts: e.pkts,
            bytes: e.bytes,
            pps: e.pkts.saturating_sub(p0) as f64 / dt,
            bps: e.bytes.saturating_sub(b0) as f64 * 8.0 / dt,
        });
    }
    Ok(Some(StatsMsg {
        kind: "stats".into(),
        v: SCHEMA_V,
        pop: sh.pop().to_string(),
        ts: now_unix_ms(),
        interval_ms: (dt * 1000.0) as u64,
        sample_rate,
        events_lost: lost,
        entries,
    }))
}
