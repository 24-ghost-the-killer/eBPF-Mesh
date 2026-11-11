// SPDX-License-Identifier: MIT OR Apache-2.0
//! The agent proper (Linux): attach, connect, run the tasks, shut down.

mod health;
mod kv;
mod probe;
mod stats;
mod telemetry;

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio::task::JoinSet;
use tracing::{error, info, warn};

use sentinel_bpf::attach::{self, AttachOpts, XdpMode};
use sentinel_bpf::maps;
use sentinel_common::abi::XsCfg;
use sentinel_common::msg::BUCKETS;
use sentinel_common::pin::PinLayout;

use crate::config::{Config, XdpModeCfg};
use crate::metrics::{self, Metrics};

/// State shared by every task.
pub struct Shared {
    pub cfg: Config,
    pub pins: PinLayout,
    pub nats: async_nats::Client,
    pub metrics: Arc<Metrics>,
    /// Serialises read-modify-write of xs_cfg (kill switch, sample rate).
    cfg_lock: Mutex<()>,
    /// Highest document version applied from any bucket.
    pub config_version: AtomicU64,
    pub started: Instant,
}

impl Shared {
    pub fn update_cfg(&self, f: impl FnOnce(&mut XsCfg)) -> Result<()> {
        let _g = self.cfg_lock.lock().expect("cfg lock");
        let mut c = maps::read_cfg(&self.pins)?;
        f(&mut c);
        maps::write_cfg(&self.pins, &c)
    }

    pub fn pop(&self) -> &str {
        &self.cfg.pop.id
    }
}

pub async fn run(cfg: Config, keep_attached: bool) -> Result<()> {
    let pins = PinLayout::new(&cfg.xdp.pin_dir);
    attach_or_adopt(&pins, &cfg)?;
    write_static_cfg(&pins, &cfg)?;

    let nats = connect(&cfg).await?;
    let sh = Arc::new(Shared {
        cfg,
        pins,
        nats,
        metrics: Arc::new(Metrics::default()),
        cfg_lock: Mutex::new(()),
        config_version: AtomicU64::new(0),
        started: Instant::now(),
    });
    info!(pop = sh.pop(), iface = %sh.cfg.pop.iface, "agent running");

    let mut tasks = JoinSet::new();
    for bucket in BUCKETS {
        tasks.spawn(kv::run(sh.clone(), bucket));
    }
    tasks.spawn(stats::run(sh.clone()));
    tasks.spawn(health::run(sh.clone()));
    tasks.spawn(health::gc(sh.clone()));
    tasks.spawn(probe::run(sh.clone()));
    {
        let (m, addr) = (sh.metrics.clone(), sh.cfg.agent.metrics_listen);
        tasks.spawn(async move {
            if let Err(e) = metrics::serve(m, addr).await {
                error!("metrics endpoint: {e:#}");
            }
        });
    }
    let stop = Arc::new(AtomicBool::new(false));
    let ringbuf = telemetry::start(sh.clone(), stop.clone(), &mut tasks)?;

    shutdown_signal().await;
    info!("stopping");
    stop.store(true, Ordering::Relaxed);
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    let _ = ringbuf.join();
    let _ = tokio::time::timeout(Duration::from_secs(2), sh.nats.flush()).await;

    if keep_attached {
        info!("leaving XDP attached (--keep-attached)");
    } else {
        let d = attach::detach(&sh.pins, &sh.cfg.pop.iface)?;
        for w in d.warnings {
            warn!("{w}");
        }
        info!(iface = %sh.cfg.pop.iface, "XDP detached");
    }
    Ok(())
}

/// Attaches, or adopts the attachment a previous agent left behind (crash
/// or --keep-attached), so a restart never interrupts protection.
fn attach_or_adopt(pins: &PinLayout, cfg: &Config) -> Result<()> {
    let iface = cfg.pop.iface.as_str();
    if attach::is_attached(pins, iface) {
        info!(iface, "adopting existing XDP attachment");
        return Ok(());
    }
    if pins.xdp_link(iface)?.exists() {
        warn!(
            iface,
            "stale XDP link pin (interface recreated?); attaching again"
        );
        let _ = attach::detach(pins, iface);
    }
    let mode = match cfg.xdp.mode {
        XdpModeCfg::Native => XdpMode::Native,
        XdpModeCfg::Generic => XdpMode::Generic,
    };
    let done = attach::attach(
        pins,
        &AttachOpts {
            iface,
            obj: &cfg.xdp.object,
            mode,
            pop_ip4: Some(cfg.pop.pop_ip4),
            pop_ip6: cfg.pop.pop_ip6,
        },
    )?;
    for w in done.warnings {
        warn!("{w}");
    }
    info!(
        iface,
        ifindex = done.ifindex,
        mtu = done.mtu,
        ?mode,
        "XDP attached"
    );
    Ok(())
}

/// PoP-local settings come from the config file, never from KV.
fn write_static_cfg(pins: &PinLayout, cfg: &Config) -> Result<()> {
    let mtu = maps::iface_mtu(&cfg.pop.iface)?;
    let mut c = maps::read_cfg(pins)?;
    c.pop_ip4 = cfg.pop.pop_ip4.octets();
    c.pop_ip6 = cfg.pop.pop_ip6.map(|a| a.octets()).unwrap_or_default();
    c.tunnel_ep4 = cfg.pop.tunnel_ep4.map(|a| a.octets()).unwrap_or_default();
    c.nexthop_mac = cfg.nexthop_mac().unwrap_or_default();
    c.uplink_mtu = u16::try_from(mtu).unwrap_or(u16::MAX);
    c.sample_rate = cfg.telemetry.sample_base;
    if c.cookie_key == [0, 0] {
        c.cookie_key = maps::random_key()?;
    }
    maps::write_cfg(pins, &c)
}

async fn connect(cfg: &Config) -> Result<async_nats::Client> {
    let seed = std::fs::read_to_string(&cfg.nats.nkey_seed_file)
        .with_context(|| format!("reading {}", cfg.nats.nkey_seed_file.display()))?;
    // Connects in the background and keeps reconnecting: XDP keeps running
    // with the last applied state while NATS is away.
    async_nats::ConnectOptions::with_nkey(seed.trim().to_string())
        .add_root_certificates(cfg.nats.ca.clone())
        .require_tls(true)
        .name(format!("sentinel-agent/{}", cfg.pop.id))
        .retry_on_initial_connect()
        .event_callback(|ev| async move { info!("nats: {ev}") })
        .connect(&cfg.nats.url)
        .await
        .with_context(|| format!("connecting to {}", cfg.nats.url))
}

async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
    tokio::select! {
        _ = term.recv() => {}
        _ = tokio::signal::ctrl_c() => {}
    }
}
