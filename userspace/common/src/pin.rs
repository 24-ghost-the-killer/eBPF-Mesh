//! bpffs pin layout.
//!
//! Every interface gets its own directory, so two interfaces never share maps
//! by accident and one interface can be torn down independently:
//!
//! ```text
//! <pin_root>/<ifname>/em_xdp_main   program (identifies "our" attachment)
//! <pin_root>/<ifname>/em_stats      per-CPU counters
//! ```
//!
//! Pinned maps outlive every userspace process, so the dataplane keeps its
//! counters across `meshctl` runs, agent crashes and program upgrades.

use std::path::{Path, PathBuf};

use crate::AbiError;

/// Default pin root; overridable with `--pin-root` / `pin_root` in config.
pub const DEFAULT_PIN_ROOT: &str = "/sys/fs/bpf/ebpf-mesh";
/// Name of the XDP program in the object (and of its pin).
pub const PROG_NAME: &str = "em_xdp_main";
/// Per-CPU counters map.
pub const MAP_STATS: &str = "em_stats";

/// Linux `IFNAMSIZ` including the terminating NUL.
const IFNAMSIZ: usize = 16;

/// Validate an interface name with the kernel's own rules
/// (`dev_valid_name()`): 1..=15 bytes, not `.`/`..`, no `/`, `:` or
/// whitespace. The name becomes a path component, so this is also what keeps
/// it from escaping the pin root.
pub fn validate_ifname(name: &str) -> Result<(), AbiError> {
    let bad = name.is_empty()
        || name.len() >= IFNAMSIZ
        || name == "."
        || name == ".."
        || name.bytes().any(|b| b == b'/' || b == b':' || b == 0 || b.is_ascii_whitespace());
    if bad { Err(AbiError::InvalidIfname(name.to_string())) } else { Ok(()) }
}

/// Validated per-interface pin directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinLayout {
    iface: String,
    dir: PathBuf,
}

impl PinLayout {
    pub fn new(root: &Path, iface: &str) -> Result<Self, AbiError> {
        validate_ifname(iface)?;
        if !root.is_absolute() {
            return Err(AbiError::RelativePinRoot(root.to_path_buf()));
        }
        Ok(PinLayout { iface: iface.to_string(), dir: root.join(iface) })
    }

    pub fn iface(&self) -> &str {
        &self.iface
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn prog(&self) -> PathBuf {
        self.dir.join(PROG_NAME)
    }

    pub fn map(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_paths() {
        let l = PinLayout::new(Path::new("/sys/fs/bpf/em"), "eth1").unwrap();
        assert_eq!(l.iface(), "eth1");
        assert_eq!(l.dir(), Path::new("/sys/fs/bpf/em/eth1"));
        assert_eq!(l.prog(), Path::new("/sys/fs/bpf/em/eth1/em_xdp_main"));
        assert_eq!(l.map(MAP_STATS), Path::new("/sys/fs/bpf/em/eth1/em_stats"));
    }

    #[test]
    fn accepts_kernel_valid_names() {
        for ok in ["eth0", "enp3s0f1", "vlan.100", "veth-a_b", "a", "123456789012345"] {
            assert!(validate_ifname(ok).is_ok(), "{ok}");
        }
    }

    #[test]
    fn rejects_invalid_names() {
        for bad in
            ["", ".", "..", "a/b", "../x", "eth0:1", "a b", "a\tb", "1234567890123456", "a\0b"]
        {
            assert!(validate_ifname(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn rejects_relative_root() {
        assert!(matches!(
            PinLayout::new(Path::new("relative/root"), "eth0"),
            Err(AbiError::RelativePinRoot(_))
        ));
    }
}
