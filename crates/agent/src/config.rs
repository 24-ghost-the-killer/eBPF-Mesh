// SPDX-License-Identifier: MIT OR Apache-2.0
//! Agent configuration (TOML). Site values live only here: nothing about a
//! PoP is compiled in. See configs/agent.example.toml.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::Deserialize;

use sentinel_common::msg::validate_pop_id;
use sentinel_common::pin::{validate_ifname, DEFAULT_PIN_DIR};
use sentinel_common::units::parse_mac;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub pop: PopCfg,
    pub xdp: XdpCfg,
    pub nats: NatsCfg,
    #[serde(default)]
    pub telemetry: TelemetryCfg,
    #[serde(default)]
    pub agent: AgentCfg,
    /// BIRD integration (draining); without it drain requests are refused.
    #[serde(default)]
    pub bird: Option<BirdCfg>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BirdCfg {
    /// Included by the BIRD config; holds `define DRAIN = 0;` (or 1).
    pub drain_file: PathBuf,
    #[serde(default = "d_birdc")]
    pub birdc: PathBuf,
    /// BIRD control socket (birdc -s); default: birdc's default.
    #[serde(default)]
    pub socket: Option<PathBuf>,
}

fn d_birdc() -> PathBuf {
    "birdc".into()
}

/// Content of the drain include file.
pub fn drain_conf(drain: bool) -> String {
    format!(
        "# Written by sentinel-agent (admin panel drain). Do not edit.\ndefine DRAIN = {};\n",
        u8::from(drain)
    )
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PopCfg {
    /// Subject token: telemetry.<id>.*, stats.<id>, ...
    pub id: String,
    pub region: String,
    /// Uplink interface the XDP program attaches to.
    pub iface: String,
    pub pop_ip4: Ipv4Addr,
    #[serde(default)]
    pub pop_ip6: Option<Ipv6Addr>,
    /// Anycast endpoint origins send replies to (ADR 0012).
    #[serde(default)]
    pub tunnel_ep4: Option<Ipv4Addr>,
    /// Uplink router MAC; omit to send frames back to their sender.
    #[serde(default)]
    pub nexthop_mac: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum XdpModeCfg {
    #[default]
    Native,
    Generic,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XdpCfg {
    pub object: PathBuf,
    #[serde(default = "default_pin_dir")]
    pub pin_dir: PathBuf,
    #[serde(default)]
    pub mode: XdpModeCfg,
    /// Required to use mode = "generic" (tests and labs only).
    #[serde(default)]
    pub allow_generic: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NatsCfg {
    /// tls://host:port
    pub url: String,
    /// CA that signed the server certificate.
    pub ca: PathBuf,
    /// This PoP's NATS nkey seed (secret; `sentinel-agent nkey generate`).
    pub nkey_seed_file: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryCfg {
    #[serde(default = "d_shards")]
    pub shards: u32,
    /// Normal sampling: 1 in N packets.
    #[serde(default = "d_sample_base")]
    pub sample_base: u32,
    #[serde(default = "d_sample_max")]
    pub sample_max: u32,
    /// Above this many sampled events per second, sample less.
    #[serde(default = "d_target_eps")]
    pub target_events_per_sec: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentCfg {
    #[serde(default = "d_heartbeat")]
    pub heartbeat_file: PathBuf,
    #[serde(default = "d_metrics")]
    pub metrics_listen: SocketAddr,
    #[serde(default = "d_stats_ms")]
    pub stats_interval_ms: u64,
    #[serde(default = "d_health_s")]
    pub health_interval_s: u64,
    #[serde(default = "d_gc_s")]
    pub gc_interval_s: u64,
}

fn default_pin_dir() -> PathBuf {
    DEFAULT_PIN_DIR.into()
}
fn d_shards() -> u32 {
    16
}
fn d_sample_base() -> u32 {
    64
}
fn d_sample_max() -> u32 {
    65536
}
fn d_target_eps() -> u64 {
    20_000
}
fn d_heartbeat() -> PathBuf {
    "/run/sentinel/heartbeat".into()
}
fn d_metrics() -> SocketAddr {
    "127.0.0.1:9466".parse().expect("valid default")
}
fn d_stats_ms() -> u64 {
    1000
}
fn d_health_s() -> u64 {
    5
}
fn d_gc_s() -> u64 {
    10
}

impl Default for TelemetryCfg {
    fn default() -> Self {
        TelemetryCfg {
            shards: d_shards(),
            sample_base: d_sample_base(),
            sample_max: d_sample_max(),
            target_events_per_sec: d_target_eps(),
        }
    }
}

impl Default for AgentCfg {
    fn default() -> Self {
        AgentCfg {
            heartbeat_file: d_heartbeat(),
            metrics_listen: d_metrics(),
            stats_interval_ms: d_stats_ms(),
            health_interval_s: d_health_s(),
            gc_interval_s: d_gc_s(),
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Config> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let cfg: Config =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        validate_pop_id(&self.pop.id).map_err(anyhow::Error::msg)?;
        validate_ifname(&self.pop.iface)?;
        if let Some(m) = &self.pop.nexthop_mac {
            parse_mac(m).map_err(anyhow::Error::msg)?;
        }
        if self.xdp.mode == XdpModeCfg::Generic && !self.xdp.allow_generic {
            bail!("xdp.mode = \"generic\" needs xdp.allow_generic = true (tests and labs only)");
        }
        if !self.nats.url.starts_with("tls://") {
            bail!("nats.url must use tls:// (spec section 10: NATS with TLS)");
        }
        let t = &self.telemetry;
        if !(1..=4096).contains(&t.shards) {
            bail!("telemetry.shards must be 1..=4096");
        }
        if t.sample_base == 0 || t.sample_base > t.sample_max {
            bail!("telemetry.sample_base must be >= 1 and <= sample_max");
        }
        if t.target_events_per_sec == 0 {
            bail!("telemetry.target_events_per_sec must be > 0");
        }
        let a = &self.agent;
        if a.stats_interval_ms < 100 || a.health_interval_s == 0 || a.gc_interval_s == 0 {
            bail!("agent intervals too small");
        }
        Ok(())
    }

    pub fn nexthop_mac(&self) -> Option<[u8; 6]> {
        self.pop
            .nexthop_mac
            .as_deref()
            .and_then(|m| parse_mac(m).ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../configs/agent.example.toml"
    ));

    fn parse(s: &str) -> Result<Config> {
        let c: Config = toml::from_str(s)?;
        c.validate()?;
        Ok(c)
    }

    #[test]
    fn example_config_is_valid() {
        let c = parse(EXAMPLE).unwrap();
        assert_eq!(c.pop.id, "lab1");
        assert_eq!(c.telemetry.shards, 16);
        assert_eq!(c.nexthop_mac(), Some([2, 0, 0, 0, 0, 1]));
        let b = c.bird.as_ref().expect("[bird] in the example");
        assert_eq!(b.drain_file, PathBuf::from("/etc/bird/drain.conf"));
        assert_eq!(
            drain_conf(true),
            "# Written by sentinel-agent (admin panel drain). Do not edit.\ndefine DRAIN = 1;\n"
        );
    }

    #[test]
    fn minimal_config_gets_defaults() {
        let c = parse(
            r#"
            [pop]
            id = "p1"
            region = "eu"
            iface = "eth0"
            pop_ip4 = "10.10.1.1"
            [xdp]
            object = "xdp_main.o"
            [nats]
            url = "tls://127.0.0.1:4222"
            ca = "ca.pem"
            nkey_seed_file = "p1.nk"
            "#,
        )
        .unwrap();
        assert_eq!(c.xdp.pin_dir, PathBuf::from(DEFAULT_PIN_DIR));
        assert_eq!(c.xdp.mode, XdpModeCfg::Native);
        assert_eq!(c.telemetry.sample_base, 64);
        assert_eq!(c.agent.metrics_listen.port(), 9466);
        assert_eq!(c.nexthop_mac(), None);
    }

    #[test]
    fn rejects_bad_configs() {
        let bad = |from: &str, to: &str| {
            let s = EXAMPLE.replacen(from, to, 1);
            assert_ne!(s, EXAMPLE, "pattern {from:?} not in example");
            assert!(parse(&s).is_err(), "accepted {to:?}");
        };
        bad("id = \"lab1\"", "id = \"Lab.1\"");
        bad("url = \"tls://", "url = \"nats://");
        bad("mode = \"native\"", "mode = \"generic\"");
        bad("shards = 16", "shards = 0");
        bad("sample_base = 1", "sample_base = 0");
        bad(
            "nexthop_mac = \"02:00:00:00:00:01\"",
            "nexthop_mac = \"02:00\"",
        );
        bad("[pop]", "[pop]\nunknown = 1");
    }
}
