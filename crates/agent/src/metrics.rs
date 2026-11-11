// SPDX-License-Identifier: MIT OR Apache-2.0
//! Prometheus metrics (spec section 6) served at http://<metrics_listen>/metrics.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use axum::{http::header, response::IntoResponse, routing::get, Router};
use prometheus_client::encoding::{text::encode, EncodeLabelSet};
use prometheus_client::metrics::{counter::Counter, family::Family, gauge::Gauge};
use prometheus_client::registry::Registry;

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct VerdictLabels {
    pub tenant: String,
    pub verdict: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct BucketLabels {
    pub bucket: String,
}

pub struct Metrics {
    registry: Registry,
    pub packets: Family<VerdictLabels, Counter>,
    pub bytes: Family<VerdictLabels, Counter>,
    pub events: Counter,
    pub events_lost: Counter,
    pub events_dropped: Counter,
    pub sample_rate: Gauge,
    pub config_version: Gauge,
    pub xdp_attached: Gauge,
    pub kv_applied: Family<BucketLabels, Counter>,
    pub kv_rejected: Family<BucketLabels, Counter>,
    /// Last cumulative kernel values, to turn them into counter increments.
    last: Mutex<HashMap<(u32, String), (u64, u64)>>,
    last_lost: Mutex<u64>,
}

impl Default for Metrics {
    fn default() -> Self {
        let mut registry = Registry::with_prefix("sentinel");
        let m = Metrics {
            packets: Family::default(),
            bytes: Family::default(),
            events: Counter::default(),
            events_lost: Counter::default(),
            events_dropped: Counter::default(),
            sample_rate: Gauge::default(),
            config_version: Gauge::default(),
            xdp_attached: Gauge::default(),
            kv_applied: Family::default(),
            kv_rejected: Family::default(),
            last: Mutex::new(HashMap::new()),
            last_lost: Mutex::new(0),
            registry: Registry::default(),
        };
        registry.register(
            "packets",
            "Packets by tenant and XDP verdict",
            m.packets.clone(),
        );
        registry.register("bytes", "Bytes by tenant and XDP verdict", m.bytes.clone());
        registry.register(
            "sampled_events",
            "Sampled packet events read",
            m.events.clone(),
        );
        registry.register(
            "sampled_events_lost",
            "Samples lost in XDP (ring buffer full)",
            m.events_lost.clone(),
        );
        registry.register(
            "sampled_events_dropped",
            "Samples dropped by the agent (aggregator busy)",
            m.events_dropped.clone(),
        );
        registry.register(
            "sample_rate",
            "Current 1-in-N sampling",
            m.sample_rate.clone(),
        );
        registry.register(
            "config_version",
            "Highest configuration version applied",
            m.config_version.clone(),
        );
        registry.register(
            "xdp_attached",
            "1 if XDP is attached",
            m.xdp_attached.clone(),
        );
        registry.register("kv_applied", "KV changes applied", m.kv_applied.clone());
        registry.register("kv_rejected", "KV changes rejected", m.kv_rejected.clone());
        Metrics { registry, ..m }
    }
}

impl Metrics {
    /// Feeds cumulative kernel counters; increments by the change since the
    /// last call (a smaller value means the maps were recreated).
    pub fn observe_verdict(&self, tenant: u32, verdict: &str, pkts: u64, bytes: u64) {
        let mut last = self.last.lock().expect("metrics lock");
        let prev = last
            .insert((tenant, verdict.to_string()), (pkts, bytes))
            .unwrap_or((0, 0));
        let dp = if pkts >= prev.0 { pkts - prev.0 } else { pkts };
        let db = if bytes >= prev.1 {
            bytes - prev.1
        } else {
            bytes
        };
        let l = VerdictLabels {
            tenant: tenant.to_string(),
            verdict: verdict.to_string(),
        };
        self.packets.get_or_create(&l).inc_by(dp);
        self.bytes.get_or_create(&l).inc_by(db);
    }

    pub fn observe_lost(&self, cumulative: u64) {
        let mut last = self.last_lost.lock().expect("metrics lock");
        let d = cumulative.checked_sub(*last).unwrap_or(cumulative);
        *last = cumulative;
        self.events_lost.inc_by(d);
    }

    pub fn bucket(&self, bucket: &str, ok: bool) {
        let l = BucketLabels {
            bucket: bucket.to_string(),
        };
        if ok {
            self.kv_applied.get_or_create(&l).inc();
        } else {
            self.kv_rejected.get_or_create(&l).inc();
        }
    }

    pub fn render(&self) -> String {
        let mut out = String::new();
        encode(&mut out, &self.registry).expect("writing to a String cannot fail");
        out
    }
}

pub async fn serve(metrics: Arc<Metrics>, addr: SocketAddr) -> Result<()> {
    let app = Router::new().route(
        "/metrics",
        get(move || {
            let m = metrics.clone();
            async move {
                (
                    [(
                        header::CONTENT_TYPE,
                        "application/openmetrics-text; version=1.0.0; charset=utf-8",
                    )],
                    m.render(),
                )
                    .into_response()
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding metrics endpoint {addr}"))?;
    axum::serve(listener, app).await.context("metrics server")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_follow_kernel_totals() {
        let m = Metrics::default();
        m.observe_verdict(42, "pass", 10, 1000);
        m.observe_verdict(42, "pass", 15, 1500);
        m.observe_verdict(42, "pass", 3, 300); // maps recreated
        m.observe_lost(5);
        m.observe_lost(7);
        m.bucket("tenants", true);
        m.bucket("tenants", false);
        m.sample_rate.set(64);
        let text = m.render();
        assert!(
            text.contains(r#"sentinel_packets_total{tenant="42",verdict="pass"} 18"#),
            "{text}"
        );
        assert!(text.contains(r#"sentinel_bytes_total{tenant="42",verdict="pass"} 1800"#));
        assert!(text.contains("sentinel_sampled_events_lost_total 7"));
        assert!(text.contains(r#"sentinel_kv_rejected_total{bucket="tenants"} 1"#));
        assert!(text.contains("sentinel_sample_rate 64"));
    }
}
