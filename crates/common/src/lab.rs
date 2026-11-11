// SPDX-License-Identifier: MIT OR Apache-2.0
//! The lab address plan (spec section 11.1). Traffic generators refuse any
//! destination (and spoofed source) outside these ranges unless the operator
//! passes an explicitly named override flag.

use std::net::IpAddr;

use crate::prefix::Prefix;

/// Name of the override flag every traffic generator must use.
pub const OVERRIDE_FLAG: &str = "--allow-non-lab-destination";

pub const LAB_RANGES: [&str; 5] = [
    "198.51.100.0/24",   // anycast prefix (protected IPs)
    "2001:db8:100::/48", // anycast prefix IPv6
    "10.10.1.0/24",      // PoP unicast / management
    "192.0.2.0/24",      // customer origins
    "203.0.113.0/24",    // bots and test clients
];

pub fn lab_prefixes() -> Vec<Prefix> {
    LAB_RANGES
        .iter()
        .map(|s| s.parse().expect("LAB_RANGES are valid"))
        .collect()
}

pub fn is_lab_addr(ip: IpAddr) -> bool {
    lab_prefixes().iter().any(|p| p.contains(ip))
}

/// True if every address of `p` is inside one lab range.
pub fn is_lab_prefix(p: &Prefix) -> bool {
    lab_prefixes()
        .iter()
        .any(|lab| lab.prefix_len() <= p.prefix_len() && lab.contains(p.network_addr()))
}

impl Prefix {
    /// First address of the prefix.
    pub fn network_addr(&self) -> IpAddr {
        match self.network() {
            Prefix::V4(a, _) => IpAddr::V4(a),
            Prefix::V6(a, _) => IpAddr::V6(a),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lab_addresses() {
        for ok in [
            "198.51.100.10",
            "203.0.113.200",
            "2001:db8:100::10",
            "10.10.1.1",
        ] {
            assert!(is_lab_addr(ok.parse().unwrap()), "{ok}");
        }
        for bad in [
            "8.8.8.8",
            "198.51.101.1",
            "2001:db8:101::1",
            "10.10.2.1",
            "::1",
        ] {
            assert!(!is_lab_addr(bad.parse().unwrap()), "{bad}");
        }
    }

    #[test]
    fn lab_prefixes_must_fit() {
        assert!(is_lab_prefix(&"203.0.113.128/25".parse().unwrap()));
        assert!(is_lab_prefix(&"203.0.113.0/24".parse().unwrap()));
        assert!(!is_lab_prefix(&"203.0.112.0/23".parse().unwrap()));
        assert!(!is_lab_prefix(&"0.0.0.0/0".parse().unwrap()));
    }
}
