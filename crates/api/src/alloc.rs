// SPDX-License-Identifier: MIT OR Apache-2.0
//! Protected-IP allocation from the anycast prefix.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};

use sentinel_common::prefix::Prefix;

/// First free /32 of `prefix`, skipping the network and broadcast
/// addresses, everything in `reserved`, and `used`.
pub fn pick_free(
    prefix: &Prefix,
    reserved: &[Ipv4Addr],
    used: &HashSet<Ipv4Addr>,
) -> Option<Ipv4Addr> {
    let Prefix::V4(net, len) = prefix.network() else {
        return None;
    };
    let first = u32::from(net);
    let size = 1u64 << (32 - len as u32);
    let (lo, hi) = if size > 2 {
        (first as u64 + 1, first as u64 + size - 2) // no network/broadcast
    } else {
        (first as u64, first as u64 + size - 1)
    };
    (lo..=hi)
        .map(|a| Ipv4Addr::from(a as u32))
        .find(|a| !reserved.contains(a) && !used.contains(a))
}

/// Used /32s out of a list of protected prefixes (wider ones count fully).
pub fn used_hosts(prefixes: &[Prefix], within: &Prefix) -> HashSet<Ipv4Addr> {
    let mut out = HashSet::new();
    for p in prefixes {
        if let Prefix::V4(net, len) = p.network() {
            let start = u32::from(net) as u64;
            for a in start..start + (1u64 << (32 - len as u32)) {
                let ip = Ipv4Addr::from(a as u32);
                if within.contains(IpAddr::V4(ip)) {
                    out.insert(ip);
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Prefix {
        s.parse().unwrap()
    }

    #[test]
    fn skips_network_broadcast_reserved_and_used() {
        let net = p("198.51.100.0/24");
        let ep = "198.51.100.1".parse().unwrap();
        let none = HashSet::new();
        assert_eq!(
            pick_free(&net, &[ep], &none),
            Some("198.51.100.2".parse().unwrap())
        );
        let used = used_hosts(&[p("198.51.100.2/32"), p("198.51.100.4/31")], &net);
        assert_eq!(used.len(), 3);
        assert_eq!(
            pick_free(&net, &[ep], &used),
            Some("198.51.100.3".parse().unwrap())
        );
    }

    #[test]
    fn exhaustion() {
        let net = p("198.51.100.0/30"); // .1 and .2 usable
        let ep: Ipv4Addr = "198.51.100.1".parse().unwrap();
        let used = used_hosts(&[p("198.51.100.2/32")], &net);
        assert_eq!(pick_free(&net, &[ep], &used), None);
        assert_eq!(pick_free(&p("2001:db8::/64"), &[], &HashSet::new()), None);
    }
}
