// SPDX-License-Identifier: MIT OR Apache-2.0
//! Flows -> ClickHouse `flows` (spec 12.2, ADR 0024).
//!
//! Each worker writes the flows of its own shards, so together the workers
//! write every flow once. Batches go through a bounded queue: when
//! ClickHouse is slow or down, the oldest batches are dropped (and counted),
//! detection never waits for storage.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{info, warn};

use sentinel_common::msg::FlowRecord;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClickHouseCfg {
    pub url: String,
    #[serde(default = "d_db")]
    pub database: String,
    /// Write-only user (INSERT on flows).
    pub user: String,
    #[serde(default = "d_pw_env")]
    pub password_env: String,
    #[serde(default = "d_batch")]
    pub batch_rows: usize,
    /// Batches waiting at most; older ones are dropped.
    #[serde(default = "d_queue")]
    pub queue_batches: usize,
}

fn d_db() -> String {
    "sentinel".into()
}
fn d_pw_env() -> String {
    "SENTINEL_CLICKHOUSE_PASSWORD".into()
}
fn d_batch() -> usize {
    5000
}
fn d_queue() -> usize {
    1000
}

#[derive(Serialize)]
struct Row<'a> {
    ts: String,
    pop: &'a str,
    tenant: u32,
    src: String,
    dst: String,
    proto: u8,
    dport: u16,
    pkts: u64,
    bytes: u64,
    verdict: &'a str,
}

/// IPv4 as IPv4-mapped IPv6 (the column type is IPv6).
pub fn ip6(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(a) => format!("::ffff:{a}"),
        IpAddr::V6(a) => a.to_string(),
    }
}

/// Unix ms -> "YYYY-MM-DD hh:mm:ss.mmm" (UTC; the column is UTC).
pub fn utc(ms: u64) -> String {
    let secs = (ms / 1000) as i64;
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    // Civil from days (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}.{:03}",
        sod / 3600,
        sod % 3600 / 60,
        sod % 60,
        ms % 1000
    )
}

pub fn encode(flows: &[FlowRecord]) -> String {
    let mut out = String::with_capacity(flows.len() * 200);
    for f in flows {
        let row = Row {
            ts: utc(f.first_ts),
            pop: &f.pop,
            tenant: f.tenant,
            src: ip6(f.src),
            dst: ip6(f.dst),
            proto: f.proto,
            dport: f.dport,
            pkts: f.pkts,
            bytes: f.bytes,
            verdict: &f.verdict,
        };
        if let Ok(s) = serde_json::to_string(&row) {
            out.push_str(&s);
            out.push('\n');
        }
    }
    out
}

#[derive(Clone)]
pub struct Sink {
    tx: mpsc::Sender<Vec<FlowRecord>>,
    pub dropped: Arc<AtomicU64>,
}

impl Sink {
    /// Queues a batch; drops it when the queue is full.
    pub fn push(&self, flows: Vec<FlowRecord>) {
        if flows.is_empty() {
            return;
        }
        let n = flows.len() as u64;
        if self.tx.try_send(flows).is_err() {
            let total = self.dropped.fetch_add(n, Ordering::Relaxed) + n;
            if total.is_power_of_two() {
                warn!(
                    dropped_flows = total,
                    "ClickHouse queue full: dropping flows"
                );
            }
        }
    }
}

pub fn start(cfg: ClickHouseCfg) -> Result<Sink> {
    let password = std::env::var(&cfg.password_env)
        .with_context(|| format!("environment variable {} is not set", cfg.password_env))?;
    let (tx, rx) = mpsc::channel(cfg.queue_batches.max(1));
    let sink = Sink {
        tx,
        dropped: Arc::new(AtomicU64::new(0)),
    };
    tokio::spawn(writer(cfg, password, rx));
    Ok(sink)
}

async fn writer(cfg: ClickHouseCfg, password: String, mut rx: mpsc::Receiver<Vec<FlowRecord>>) {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!("ClickHouse client: {e}");
            return;
        }
    };
    let mut buf: Vec<FlowRecord> = Vec::new();
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    let mut written: u64 = 0;
    loop {
        tokio::select! {
            b = rx.recv() => match b {
                Some(b) => {
                    buf.extend(b);
                    if buf.len() < cfg.batch_rows {
                        continue;
                    }
                }
                None => return,
            },
            _ = tick.tick() => {}
        }
        if buf.is_empty() {
            continue;
        }
        let batch = std::mem::take(&mut buf);
        match insert(&client, &cfg, &password, &batch).await {
            Ok(()) => {
                if written == 0 {
                    info!("writing flows to ClickHouse");
                }
                written += batch.len() as u64;
            }
            Err(e) => warn!(
                rows = batch.len(),
                "ClickHouse insert failed (rows dropped): {e:#}"
            ),
        }
    }
}

async fn insert(
    client: &reqwest::Client,
    cfg: &ClickHouseCfg,
    password: &str,
    flows: &[FlowRecord],
) -> Result<()> {
    let resp = client
        .post(&cfg.url)
        .query(&[
            ("database", cfg.database.as_str()),
            (
                "query",
                "INSERT INTO flows (ts, pop, tenant, src, dst, proto, dport, pkts, bytes, verdict) FORMAT JSONEachRow",
            ),
        ])
        .header("X-ClickHouse-User", &cfg.user)
        .header("X-ClickHouse-Key", password)
        .body(encode(flows))
        .send()
        .await?;
    if !resp.status().is_success() {
        let s = resp.status();
        let t = resp.text().await.unwrap_or_default();
        bail!("{s}: {}", t.chars().take(300).collect::<String>());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps() {
        assert_eq!(utc(0), "1970-01-01 00:00:00.000");
        assert_eq!(utc(1_762_790_400_123), "2025-11-10 16:00:00.123");
        assert_eq!(utc(951_782_400_000), "2000-02-29 00:00:00.000");
        assert_eq!(utc(4_107_542_399_999), "2100-02-28 23:59:59.999");
    }

    #[test]
    fn rows() {
        let f = FlowRecord {
            kind: "flow".into(),
            v: 1,
            pop: "pop-1".into(),
            tenant: 7,
            src: "203.0.113.7".parse().unwrap(),
            dst: "2001:db8:100::1".parse().unwrap(),
            proto: 17,
            dport: 53,
            pkts: 10,
            bytes: 1000,
            syn: 0,
            verdict: "drop_block".into(),
            first_ts: 0,
            last_ts: 0,
        };
        let s = encode(&[f.clone(), f]);
        assert_eq!(s.lines().count(), 2);
        let v: serde_json::Value = serde_json::from_str(s.lines().next().unwrap()).unwrap();
        assert_eq!(v["src"], "::ffff:203.0.113.7");
        assert_eq!(v["dst"], "2001:db8:100::1");
        assert_eq!(v["verdict"], "drop_block");
        assert_eq!(v["ts"], "1970-01-01 00:00:00.000");
    }
}
