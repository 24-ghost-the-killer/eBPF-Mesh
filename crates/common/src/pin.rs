// SPDX-License-Identifier: MIT OR Apache-2.0
//! Layout of pinned BPF objects on bpffs.
//!
//! ```text
//! $SENTINEL_PIN_DIR/            default /sys/fs/bpf/sentinel
//!   xs_cfg, xs_stats, ...       maps, shared by every attached interface
//!   link_xdp_<ifname>           one pinned bpf_link per attached interface
//! ```

use std::fmt;
use std::path::{Path, PathBuf};

pub const DEFAULT_PIN_DIR: &str = "/sys/fs/bpf/sentinel";
pub const ENV_PIN_DIR: &str = "SENTINEL_PIN_DIR";
const LINK_PREFIX: &str = "link_xdp_";

/// Maximum Linux interface name length (IFNAMSIZ - 1).
pub const IFNAME_MAX: usize = 15;

#[derive(Debug, PartialEq, Eq)]
pub struct InvalidIfName(pub String);

impl fmt::Display for InvalidIfName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid interface name {:?} (1-{IFNAME_MAX} chars, no '/', whitespace or ':')",
            self.0
        )
    }
}

impl std::error::Error for InvalidIfName {}

/// Validates a Linux interface name, as the kernel's `dev_valid_name` does.
pub fn validate_ifname(name: &str) -> Result<(), InvalidIfName> {
    let bad = name.is_empty()
        || name.len() > IFNAME_MAX
        || name == "."
        || name == ".."
        || name
            .chars()
            .any(|c| c == '/' || c == ':' || c.is_whitespace() || c.is_control());
    if bad {
        Err(InvalidIfName(name.to_string()))
    } else {
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinLayout {
    root: PathBuf,
}

impl PinLayout {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        PinLayout { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn map(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    pub fn xdp_link(&self, ifname: &str) -> Result<PathBuf, InvalidIfName> {
        validate_ifname(ifname)?;
        Ok(self.root.join(format!("{LINK_PREFIX}{ifname}")))
    }

    /// Interface name for a pin file name, if it is an XDP link pin.
    pub fn ifname_of_link(file_name: &str) -> Option<&str> {
        file_name
            .strip_prefix(LINK_PREFIX)
            .filter(|n| validate_ifname(n).is_ok())
    }
}

impl Default for PinLayout {
    fn default() -> Self {
        PinLayout::new(DEFAULT_PIN_DIR)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ifname_validation() {
        for ok in ["eth0", "veth-xs-b", "enp1s0f0np0", "a", "abcdefghijklmno"] {
            assert!(validate_ifname(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "abcdefghijklmnop",
            "a/b",
            "a b",
            "a:1",
            ".",
            "..",
            "x\n",
        ] {
            assert!(validate_ifname(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn paths() {
        let p = PinLayout::new("/sys/fs/bpf/t");
        assert_eq!(p.map("xs_stats"), PathBuf::from("/sys/fs/bpf/t/xs_stats"));
        assert_eq!(
            p.xdp_link("eth0").unwrap(),
            PathBuf::from("/sys/fs/bpf/t/link_xdp_eth0")
        );
        assert!(p.xdp_link("../etc").is_err());
        assert_eq!(PinLayout::ifname_of_link("link_xdp_eth0"), Some("eth0"));
        assert_eq!(PinLayout::ifname_of_link("xs_stats"), None);
        assert_eq!(PinLayout::default().root(), Path::new(DEFAULT_PIN_DIR));
    }
}
