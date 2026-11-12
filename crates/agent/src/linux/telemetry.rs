// SPDX-License-Identifier: MIT OR Apache-2.0
//! Sampled packets -> per-second flows -> telemetry.<pop>.<shard>, plus the
//! adaptive sample rate (spec section 6).
//!
//! A dedicated thread polls the ring buffer (libbpf's poll blocks) and hands
//! events to an async aggregator through a bounded channel; if the
//! aggregator falls behind, events are dropped and counted rather than
//! queued without limit.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use anyhow::{Context, Result};
use libbpf_rs::RingBufferBuilder;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tracing::{error, info, warn};

use sentinel_bpf::maps;
use sentinel_common::abi::{MapBytes, XsEvent};
use sentinel_common::msg::{subject_telemetry, FlowBatch, SCHEMA_V};
use sentinel_common::telemetry::{by_shard, FlowAggregator, SampleController};
use sentinel_common::units::now_unix_ms;

use crate::metrics::Metrics;

use super::Shared;

const CHANNEL: usize = 1 << 16;

pub fn start(
    sh: Arc<Shared>,
    stop: Arc<AtomicBool>,
    tasks: &mut JoinSet<()>,
) -> Result<JoinHandle<()>> {
    let (tx, rx) = mpsc::channel::<XsEvent>(CHANNEL);
    let (pins, metrics) = (sh.pins.clone(), sh.metrics.clone());
    let thread = std::thread::Builder::new()
        .name("ringbuf".into())
        .spawn(move || {
            if let Err(e) = poll(&pins, &tx, &stop, &metrics) {
                error!("ring buffer reader stopped: {e:#}");
            }
        })
        .context("starting ring buffer thread")?;
    tasks.spawn(aggregate(sh, rx));
    Ok(thread)
}

fn poll(
    pins: &sentinel_common::pin::PinLayout,
    tx: &mpsc::Sender<XsEvent>,
    stop: &AtomicBool,
    metrics: &Metrics,
) -> Result<()> {
    let map = maps::open(pins, "xs_events")?;
    let mut b = RingBufferBuilder::new();
    b.add(&map, |data: &[u8]| {
        if let Some(ev) = XsEvent::from_bytes(data) {
            if tx.try_send(ev).is_err() {
                metrics.events_dropped.inc();
            }
        }
        0
    })?;
    let rb = b.build()?;
    while !stop.load(Ordering::Relaxed) {
        if let Err(e) = rb.poll(Duration::from_millis(100)) {
            if e.kind() != libbpf_rs::ErrorKind::Interrupted {
                return Err(e.into());
            }
        }
    }
    Ok(())
}

async fn aggregate(sh: Arc<Shared>, mut rx: mpsc::Receiver<XsEvent>) {
    let t = &sh.cfg.telemetry;
    let ctl = SampleController {
        base: t.sample_base,
        max: t.sample_max,
        target_eps: t.target_events_per_sec,
    };
    let mut agg = FlowAggregator::default();
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            ev = rx.recv() => match ev {
                Some(ev) => agg.add(&ev, now_unix_ms()),
                None => return,
            },
            _ = tick.tick() => flush(&sh, &mut agg, &ctl).await,
        }
    }
}

async fn flush(sh: &Shared, agg: &mut FlowAggregator, ctl: &SampleController) {
    let events = agg.events();
    let flows = agg.drain(sh.pop());
    sh.metrics.events.inc_by(events);
    let ts = now_unix_ms();
    for (shard, flows) in by_shard(flows, sh.cfg.telemetry.shards) {
        let batch = FlowBatch {
            kind: "flows".into(),
            v: SCHEMA_V,
            pop: sh.pop().to_string(),
            shard,
            ts,
            flows,
        };
        match serde_json::to_vec(&batch) {
            Ok(body) => {
                if let Err(e) = sh
                    .nats
                    .publish(subject_telemetry(sh.pop(), shard), body.into())
                    .await
                {
                    warn!("publishing telemetry: {e}");
                }
            }
            Err(e) => warn!("encoding telemetry: {e}"),
        }
    }

    // Adapt the sampling to the event rate of the last second.
    let current = match maps::read_cfg(&sh.pins) {
        Ok(c) => c.sample_rate,
        Err(e) => {
            warn!("reading cfg: {e:#}");
            return;
        }
    };
    let next = ctl.next(current, events);
    if next != current {
        match sh.update_cfg(|c| c.sample_rate = next) {
            Ok(()) => info!(from = current, to = next, events, "sample rate changed"),
            Err(e) => warn!("updating sample rate: {e:#}"),
        }
    }
    sh.metrics.sample_rate.set(next as i64);
}
