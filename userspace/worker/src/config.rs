//! Worker configuration (TOML, strict). See `configs/worker.example.toml`.

use anyhow::{Result, bail};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Stable identifier of this worker (appears in published decisions).
    pub worker_id: String,
    /// NATS server URL (`nats://` or `tls://`). Used from Phase 5.
    pub nats_url: String,
}

impl Config {
    pub fn from_toml(text: &str) -> Result<Self> {
        let cfg: Config = toml::from_str(text)?;
        let id_ok = !cfg.worker_id.is_empty()
            && cfg.worker_id.len() <= 64
            && cfg.worker_id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if !id_ok {
            bail!("worker_id must be 1-64 characters of [A-Za-z0-9_-]");
        }
        let Some((scheme, rest)) = cfg.nats_url.split_once("://") else {
            bail!("nats_url {:?} is not a URL", cfg.nats_url);
        };
        if !matches!(scheme, "nats" | "tls") || rest.is_empty() {
            bail!("nats_url must be nats://host:port or tls://host:port");
        }
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid() {
        let c =
            Config::from_toml("worker_id = \"w-1\"\nnats_url = \"nats://10.0.0.5:4222\"").unwrap();
        assert_eq!(c.worker_id, "w-1");
        assert!(Config::from_toml("worker_id = \"a\"\nnats_url = \"tls://n:4222\"").is_ok());
    }

    #[test]
    fn invalid() {
        for bad in [
            "worker_id = \"\"\nnats_url = \"nats://h:1\"",
            "worker_id = \"a b\"\nnats_url = \"nats://h:1\"",
            "worker_id = \"a\"\nnats_url = \"http://h:1\"",
            "worker_id = \"a\"\nnats_url = \"nats://\"",
            "worker_id = \"a\"\nnats_url = \"h:1\"",
            "worker_id = \"a\"",
            "worker_id = \"a\"\nnats_url = \"nats://h:1\"\nextra = 1",
        ] {
            assert!(Config::from_toml(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn example_config_is_valid() {
        let text = include_str!("../../../configs/worker.example.toml");
        Config::from_toml(text).unwrap();
    }
}
