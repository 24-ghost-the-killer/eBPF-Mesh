//! Agent configuration: TOML with strict (unknown-field) validation, so a typo
//! is an error rather than a silently ignored setting. See
//! `configs/agent.example.toml`.

use std::collections::HashSet;
use std::path::PathBuf;

use anyhow::{Result, bail};
use serde::Deserialize;

fn default_pin_root() -> PathBuf {
    PathBuf::from(em_common::pin::DEFAULT_PIN_ROOT)
}
fn default_bpf_obj() -> PathBuf {
    PathBuf::from("/usr/lib/ebpf-mesh/em_xdp.bpf.o")
}

/// XDP attach mode. Called `xdp_mode` in TOML, so that `mode` stays free for
/// the node role (edge PoP, lab, ...) in later phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum XdpMode {
    /// Driver (native) XDP: the production mode.
    #[default]
    Native,
    /// Generic (skb) XDP: NICs without native support, tests.
    Generic,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Interface {
    pub name: String,
    #[serde(default)]
    pub xdp_mode: XdpMode,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "default_pin_root")]
    pub pin_root: PathBuf,
    #[serde(default = "default_bpf_obj")]
    pub bpf_obj: PathBuf,
    /// `[[interface]]` blocks.
    #[serde(default, rename = "interface")]
    pub interfaces: Vec<Interface>,
}

impl Config {
    pub fn from_toml(text: &str) -> Result<Self> {
        let cfg: Config = toml::from_str(text)?;
        if cfg.interfaces.is_empty() {
            bail!("config has no [[interface]] entries; nothing to manage");
        }
        if !cfg.pin_root.is_absolute() {
            bail!("pin_root {:?} must be an absolute path", cfg.pin_root);
        }
        let mut seen = HashSet::new();
        for i in &cfg.interfaces {
            em_common::pin::validate_ifname(&i.name)?;
            if !seen.insert(i.name.as_str()) {
                bail!("interface {:?} is listed twice", i.name);
            }
        }
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_uses_defaults() {
        let c = Config::from_toml("[[interface]]\nname = \"eth1\"\n").unwrap();
        assert_eq!(c.interfaces.len(), 1);
        assert_eq!(c.interfaces[0].xdp_mode, XdpMode::Native);
        assert_eq!(c.pin_root, default_pin_root());
        assert_eq!(c.bpf_obj, default_bpf_obj());
    }

    #[test]
    fn full() {
        let c = Config::from_toml(
            r#"
            pin_root = "/sys/fs/bpf/test"
            bpf_obj = "/opt/em/em_xdp.bpf.o"
            [[interface]]
            name = "eth1"
            xdp_mode = "generic"
            [[interface]]
            name = "eth2"
        "#,
        )
        .unwrap();
        assert_eq!(c.pin_root, PathBuf::from("/sys/fs/bpf/test"));
        assert_eq!(c.interfaces[0].xdp_mode, XdpMode::Generic);
        assert_eq!(c.interfaces[1].xdp_mode, XdpMode::Native);
    }

    #[test]
    fn rejects_bad_configs() {
        // unknown top-level and interface fields
        assert!(Config::from_toml("nope = 1\n[[interface]]\nname = \"eth0\"").is_err());
        assert!(Config::from_toml("[[interface]]\nname = \"eth0\"\nmode = \"native\"").is_err());
        // bad values
        assert!(Config::from_toml("[[interface]]\nname = \"eth0\"\nxdp_mode = \"auto\"").is_err());
        assert!(Config::from_toml("[[interface]]\nname = \"a/b\"").is_err());
        assert!(Config::from_toml("pin_root = \"rel\"\n[[interface]]\nname = \"eth0\"").is_err());
        // no interfaces / duplicates
        assert!(Config::from_toml("").is_err());
        assert!(Config::from_toml("[[interface]]\nname=\"a\"\n[[interface]]\nname=\"a\"").is_err());
    }

    #[test]
    fn example_config_is_valid() {
        let text = include_str!("../../../configs/agent.example.toml");
        Config::from_toml(text).unwrap();
    }
}
