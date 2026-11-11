// SPDX-License-Identifier: MIT OR Apache-2.0
//! IP prefixes (CIDR) without external dependencies, plus conversion to the
//! LPM keys used by `xs_allow(6)` / `xs_block(6)`.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use crate::abi::{XsSrc6Key, XsSrcKey, XsTenant6Key, XsTenantKey};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Prefix {
    V4(Ipv4Addr, u8),
    V6(Ipv6Addr, u8),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrefixError(pub String);

impl fmt::Display for PrefixError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PrefixError {}

fn mask4(len: u8) -> u32 {
    if len == 0 {
        0
    } else {
        u32::MAX << (32 - len)
    }
}

fn mask6(len: u8) -> u128 {
    if len == 0 {
        0
    } else {
        u128::MAX << (128 - len)
    }
}

impl Prefix {
    /// Builds a prefix, rejecting host bits set below the prefix length.
    pub fn new(addr: IpAddr, len: u8) -> Result<Prefix, PrefixError> {
        let p = match addr {
            IpAddr::V4(a) if len <= 32 => Prefix::V4(a, len),
            IpAddr::V6(a) if len <= 128 => Prefix::V6(a, len),
            _ => {
                return Err(PrefixError(format!(
                    "prefix length /{len} too long for {addr}"
                )))
            }
        };
        let net = p.network();
        if net != p {
            return Err(PrefixError(format!(
                "{p} has host bits set; did you mean {net}?"
            )));
        }
        Ok(p)
    }

    pub fn prefix_len(&self) -> u8 {
        match *self {
            Prefix::V4(_, l) | Prefix::V6(_, l) => l,
        }
    }

    pub fn is_v4(&self) -> bool {
        matches!(self, Prefix::V4(..))
    }

    /// The prefix with host bits cleared.
    pub fn network(&self) -> Prefix {
        match *self {
            Prefix::V4(a, l) => Prefix::V4((u32::from(a) & mask4(l)).into(), l),
            Prefix::V6(a, l) => Prefix::V6((u128::from(a) & mask6(l)).into(), l),
        }
    }

    /// The network address.
    pub fn addr(&self) -> IpAddr {
        match *self {
            Prefix::V4(a, _) => IpAddr::V4(a),
            Prefix::V6(a, _) => IpAddr::V6(a),
        }
    }

    /// True when the two prefixes share at least one address.
    pub fn overlaps(&self, other: &Prefix) -> bool {
        self.contains(other.addr()) || other.contains(self.addr())
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (*self, ip) {
            (Prefix::V4(n, l), IpAddr::V4(a)) => u32::from(a) & mask4(l) == u32::from(n),
            (Prefix::V6(n, l), IpAddr::V6(a)) => u128::from(a) & mask6(l) == u128::from(n),
            _ => false,
        }
    }

    /// Rules may never cover the whole address space (spec section 10).
    /// `min_len` is the shortest prefix accepted for this family.
    pub fn check_rule(&self, min_len_v4: u8, min_len_v6: u8) -> Result<(), PrefixError> {
        let min = if self.is_v4() { min_len_v4 } else { min_len_v6 };
        if self.prefix_len() == 0 {
            return Err(PrefixError(format!("{self} covers every address; refused")));
        }
        if self.prefix_len() < min {
            return Err(PrefixError(format!(
                "{self} is wider than the allowed /{min}; refused"
            )));
        }
        Ok(())
    }

    pub fn key4(&self, tenant: u32) -> Option<XsSrcKey> {
        match *self {
            Prefix::V4(a, l) => Some(XsSrcKey {
                prefixlen: 32 + l as u32,
                tenant,
                src: a.octets(),
            }),
            Prefix::V6(..) => None,
        }
    }

    pub fn key6(&self, tenant: u32) -> Option<XsSrc6Key> {
        match *self {
            Prefix::V6(a, l) => Some(XsSrc6Key {
                prefixlen: 32 + l as u32,
                tenant,
                src: a.octets(),
            }),
            Prefix::V4(..) => None,
        }
    }

    /// xs_tenants key (IPv4 prefixes only).
    pub fn tenant_key4(&self) -> Option<XsTenantKey> {
        match *self {
            Prefix::V4(a, l) => Some(XsTenantKey {
                prefixlen: l as u32,
                addr: a.octets(),
            }),
            Prefix::V6(..) => None,
        }
    }

    /// xs_tenants6 key (IPv6 prefixes only).
    pub fn tenant_key6(&self) -> Option<XsTenant6Key> {
        match *self {
            Prefix::V6(a, l) => Some(XsTenant6Key {
                prefixlen: l as u32,
                addr: a.octets(),
            }),
            Prefix::V4(..) => None,
        }
    }

    pub fn from_tenant_key4(k: &XsTenantKey) -> Option<Prefix> {
        (k.prefixlen <= 32).then(|| Prefix::V4(Ipv4Addr::from(k.addr), k.prefixlen as u8))
    }

    pub fn from_tenant_key6(k: &XsTenant6Key) -> Option<Prefix> {
        (k.prefixlen <= 128).then(|| Prefix::V6(Ipv6Addr::from(k.addr), k.prefixlen as u8))
    }

    pub fn from_key4(k: &XsSrcKey) -> Option<(u32, Prefix)> {
        let len = k.prefixlen.checked_sub(32).filter(|l| *l <= 32)? as u8;
        Some((k.tenant, Prefix::V4(Ipv4Addr::from(k.src), len)))
    }

    pub fn from_key6(k: &XsSrc6Key) -> Option<(u32, Prefix)> {
        let len = k.prefixlen.checked_sub(32).filter(|l| *l <= 128)? as u8;
        Some((k.tenant, Prefix::V6(Ipv6Addr::from(k.src), len)))
    }
}

impl FromStr for Prefix {
    type Err = PrefixError;

    /// `a.b.c.d/len`, `x::y/len`, or a bare address (= /32 or /128).
    fn from_str(s: &str) -> Result<Prefix, PrefixError> {
        let (addr, len) = match s.split_once('/') {
            Some((a, l)) => (a, Some(l)),
            None => (s, None),
        };
        let addr: IpAddr = addr
            .parse()
            .map_err(|_| PrefixError(format!("invalid address in {s:?}")))?;
        let len = match len {
            Some(l) => l
                .parse::<u8>()
                .map_err(|_| PrefixError(format!("invalid prefix length in {s:?}")))?,
            None if addr.is_ipv4() => 32,
            None => 128,
        };
        Prefix::new(addr, len)
    }
}

impl serde::Serialize for Prefix {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for Prefix {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = <std::borrow::Cow<'de, str>>::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Prefix::V4(a, l) => write!(f, "{a}/{l}"),
            Prefix::V6(a, l) => write!(f, "{a}/{l}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Prefix {
        s.parse().unwrap()
    }

    #[test]
    fn parse_and_display() {
        assert_eq!(p("203.0.113.0/24").to_string(), "203.0.113.0/24");
        assert_eq!(p("203.0.113.7").to_string(), "203.0.113.7/32");
        assert_eq!(p("2001:db8::/32").to_string(), "2001:db8::/32");
        assert_eq!(p("2001:db8::1").prefix_len(), 128);
        assert!("203.0.113.0/33".parse::<Prefix>().is_err());
        assert!("2001:db8::/129".parse::<Prefix>().is_err());
        assert!("nope/8".parse::<Prefix>().is_err());
        assert!("10.0.0.0/x".parse::<Prefix>().is_err());
    }

    #[test]
    fn host_bits_rejected_with_hint() {
        let e = "203.0.113.7/24".parse::<Prefix>().unwrap_err();
        assert!(e.0.contains("did you mean 203.0.113.0/24"), "{e}");
        assert!("2001:db8::1/64".parse::<Prefix>().is_err());
    }

    #[test]
    fn contains() {
        let n = p("203.0.113.0/25");
        assert!(n.contains("203.0.113.127".parse().unwrap()));
        assert!(!n.contains("203.0.113.128".parse().unwrap()));
        assert!(!n.contains("2001:db8::1".parse().unwrap()));
        assert!(p("::/0").contains("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn rule_limits() {
        assert!(p("0.0.0.0/0").check_rule(8, 32).is_err());
        assert!(p("::/0").check_rule(8, 32).is_err());
        assert!(p("10.0.0.0/7").check_rule(8, 32).is_err());
        assert!(p("10.0.0.0/8").check_rule(8, 32).is_ok());
        assert!(p("2001:db8::/32").check_rule(8, 32).is_ok());
        assert!(p("2001::/16").check_rule(8, 32).is_err());
    }

    #[test]
    fn lpm_keys_round_trip() {
        let v4 = p("203.0.113.0/24");
        let k = v4.key4(42).unwrap();
        assert_eq!(k.prefixlen, 56);
        assert_eq!(k.src, [203, 0, 113, 0]);
        assert_eq!(Prefix::from_key4(&k), Some((42, v4)));
        assert!(v4.key6(0).is_none());

        let v6 = p("2001:db8:100::/48");
        let k = v6.key6(0).unwrap();
        assert_eq!(k.prefixlen, 80);
        assert_eq!(Prefix::from_key6(&k), Some((0, v6)));
        assert_eq!(
            Prefix::from_key4(&XsSrcKey {
                prefixlen: 70,
                ..Default::default()
            }),
            None
        );

        let t = p("198.51.100.8/29");
        let k = t.tenant_key4().unwrap();
        assert_eq!((k.prefixlen, k.addr), (29, [198, 51, 100, 8]));
        assert_eq!(Prefix::from_tenant_key4(&k), Some(t));
        let t6 = p("2001:db8:100::10/128");
        assert_eq!(
            Prefix::from_tenant_key6(&t6.tenant_key6().unwrap()),
            Some(t6)
        );
        assert!(t.tenant_key6().is_none() && t6.tenant_key4().is_none());
    }
}
