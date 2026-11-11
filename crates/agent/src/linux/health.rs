// SPDX-License-Identifier: MIT OR Apache-2.0
//! Heartbeat file + health.<pop> (spec section 6, read by the BGP health
//! check in section 11.3) and garbage collection of expired entries.

use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tracing::{info, warn};

use sentinel_bpf::{attach, maps, rules};
use sentinel_common::msg::{subject_health, HealthMsg, SCHEMA_V};
use sentinel_common::units::now_unix_ms;

use super::Shared;

pub async fn run(sh: Arc<Shared>) {
    let mut tick = tokio::time::interval(Duration::from_secs(sh.cfg.agent.health_interval_s));
    loop {
        tick.tick().await;
        let attached = attach::is_attached(&sh.pins, &sh.cfg.pop.iface);
        sh.metrics.xdp_attached.set(attached as i64);
        if !attached {
            warn!(iface = %sh.cfg.pop.iface, "XDP is not attached");
        }
        // The heartbeat says "the agent is alive"; the health check combines
        // it with its own XDP check before announcing the anycast prefix.
        if let Err(e) = write_heartbeat(&sh.cfg.agent.heartbeat_file) {
            warn!("heartbeat: {e:#}");
        }
        let msg = HealthMsg {
            kind: "health".into(),
            v: SCHEMA_V,
            pop: sh.pop().to_string(),
            region: sh.cfg.pop.region.clone(),
            pop_ip4: Some(sh.cfg.pop.pop_ip4),
            ts: now_unix_ms(),
            iface: sh.cfg.pop.iface.clone(),
            xdp_attached: attached,
            bgp: "n/a".into(),
            load1: load1(),
            config_version: sh.config_version.load(Ordering::Relaxed),
            sample_rate: maps::read_cfg(&sh.pins).map(|c| c.sample_rate).unwrap_or(0),
            uptime_s: sh.started.elapsed().as_secs(),
        };
        match serde_json::to_vec(&msg) {
            Ok(body) => {
                if let Err(e) = sh.nats.publish(subject_health(sh.pop()), body.into()).await {
                    warn!("publishing health: {e}");
                }
            }
            Err(e) => warn!("encoding health: {e}"),
        }
    }
}

/// Unix seconds, written atomically (temp file + rename).
fn write_heartbeat(path: &Path) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, format!("{}\n", now_unix_ms() / 1000))
        .with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("renaming to {}", path.display()))
}

fn load1() -> f64 {
    std::fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|s| s.split_whitespace().next()?.parse().ok())
        .unwrap_or(0.0)
}

pub async fn gc(sh: Arc<Shared>) {
    let mut tick = tokio::time::interval(Duration::from_secs(sh.cfg.agent.gc_interval_s));
    loop {
        tick.tick().await;
        match rules::gc(&sh.pins) {
            Ok(r) if r.allow + r.block + r.verified > 0 => {
                info!(
                    allow = r.allow,
                    block = r.block,
                    verified = r.verified,
                    "gc"
                )
            }
            Ok(_) => {}
            Err(e) => warn!("gc: {e:#}"),
        }
    }
}
