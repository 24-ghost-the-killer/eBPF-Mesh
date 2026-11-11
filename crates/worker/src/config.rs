// SPDX-License-Identifier: MIT OR Apache-2.0
//! Worker configuration (TOML; see configs/worker.example.toml).

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::Deserialize;

use sentinel_common::msg::validate_pop_id;

use crate::detect::{DetectCfg, MitigateCfg};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub worker: WorkerCfg,
    pub nats: NatsCfg,
    #[serde(default)]
    pub detect: DetectCfg,
    #[serde(default)]
    pub mitigate: MitigateCfg,
    /// Optional: store flows for traffic history (ADR 0024).
    #[serde(default)]
    pub clickhouse: Option<crate::clickhouse::ClickHouseCfg>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerCfg {
    /// Issuer name: signs decisions, must be registered in signing_keys.
    pub id: String,
    /// Base64 Ed25519 seed (secret; `sentinel-worker key generate`).
    pub signing_key_file: PathBuf,
    /// Must equal the agents' telemetry shard count.
    #[serde(default = "d_shards")]
    pub shards: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NatsCfg {
    pub url: String,
    pub ca: PathBuf,
    pub nkey_seed_file: PathBuf,
}

fn d_shards() -> u32 {
    16
}

impl Config {
    pub fn load(path: &Path) -> Result<Config> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let c: Config =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        c.validate()?;
        Ok(c)
    }

    pub fn validate(&self) -> Result<()> {
        validate_pop_id(&self.worker.id).map_err(|e| anyhow::anyhow!("worker.id: {e}"))?;
        if self.worker.shards == 0 || self.worker.shards > 4096 {
            bail!("worker.shards must be 1..=4096");
        }
        if !self.nats.url.starts_with("tls://") {
            bail!("nats.url must use tls://");
        }
        let d = &self.detect;
        if d.start_after_s == 0 || d.end_after_s == 0 || d.factor < 1.0 || d.half_life_s <= 0.0 {
            bail!("detect: start_after_s/end_after_s > 0, factor >= 1, half_life_s > 0");
        }
        let m = &self.mitigate;
        if m.ttl_s == 0 || m.ttl_s > sentinel_common::decision::MAX_TTL_S {
            bail!("mitigate.ttl_s must be 1..=86400");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../configs/worker.example.toml"
    ));

    #[test]
    fn example_is_valid() {
        let c: Config = toml::from_str(EXAMPLE).unwrap();
        c.validate().unwrap();
        assert_eq!(c.worker.shards, 16);
        assert!(c.mitigate.enabled);
    }

    #[test]
    fn rejects_bad() {
        for (from, to) in [
            ("id = \"worker-1\"", "id = \"Worker 1\""),
            ("url = \"tls://", "url = \"nats://"),
            ("ttl_s = 300", "ttl_s = 0"),
            ("[worker]", "[worker]\nextra = 1"),
        ] {
            let s = EXAMPLE.replacen(from, to, 1);
            assert_ne!(s, EXAMPLE, "{from} not in example");
            let ok = toml::from_str::<Config>(&s)
                .map(|c| c.validate().is_ok())
                .unwrap_or(false);
            assert!(!ok, "accepted {to}");
        }
    }
}
