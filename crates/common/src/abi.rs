// SPDX-License-Identifier: MIT OR Apache-2.0
//! Rust mirror of `ebpf/include/abi.h`.
//!
//! Every struct is `#[repr(C)]` with the same field order, explicit padding and
//! compile-time size/alignment asserts. Fields that are big-endian (`__be32`,
//! `__be16`) in C are byte arrays here, so their byte order can never be
//! confused. The test module parses `abi.h` and fails if any constant, enum
//! value or struct layout drifts between C and Rust.

use std::mem::{align_of, size_of};
use std::net::{Ipv4Addr, Ipv6Addr};

pub const XS_ABI_VERSION: u32 = 3;
pub const XS_MAX_VLAN_TAGS: u32 = 2;
pub const XS_MAX_IPV6_EXT_HDRS: u32 = 4;
pub const XS_STATS_MAX_ENTRIES: u32 = 65536;
pub const XS_RULES_MAX_ENTRIES: u32 = 65536;
pub const XS_SERVICES_MAX_ENTRIES: u32 = 4096;
pub const XS_RL_MAX_ENTRIES: u32 = 262144;
pub const XS_VERIFIED_MAX_ENTRIES: u32 = 262144;
pub const XS_TENANTS_MAX_ENTRIES: u32 = 65536;
pub const XS_TUNNEL_OVERHEAD: u32 = 20;
pub const XS_DEFAULT_MTU: u32 = 1500;
pub const XS_TENANT_GLOBAL: u32 = 0;
pub const XS_RL_V6_PREFIX: u32 = 64;
pub const XS_VERIFY_TTL_DEFAULT_S: u32 = 300;

pub const XS_CFG_F_OBSERVE: u32 = 1 << 0;

pub const XS_P_MITIGATE: u32 = 1 << 0;
pub const XS_P_SYNCOOKIE: u32 = 1 << 1;
pub const XS_P_SERVICES: u32 = 1 << 2;
pub const XS_P_ALLOW_FRAG: u32 = 1 << 3;

/// Number of defined verdicts (`XS_V__COUNT`).
pub const XS_V_COUNT: u32 = 19;

/// Packet verdicts (`enum xs_verdict`). Append-only.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Verdict {
    Pass = 0,
    DropMalformed = 1,
    PassNonIp = 2,
    Fragment = 3,
    PassLocal = 4,
    DropBogon = 5,
    PassAllow = 6,
    DropBlock = 7,
    DropService = 8,
    DropFragment = 9,
    DropRatelimit = 10,
    TxSynChallenge = 11,
    SynVerified = 12,
    DropUnverified = 13,
    DropNoTenant = 14,
    DropTooBig = 15,
    DropTunnel = 16,
    TxReturn = 17,
    DropReturn = 18,
}

impl Verdict {
    pub const ALL: [Verdict; XS_V_COUNT as usize] = [
        Verdict::Pass,
        Verdict::DropMalformed,
        Verdict::PassNonIp,
        Verdict::Fragment,
        Verdict::PassLocal,
        Verdict::DropBogon,
        Verdict::PassAllow,
        Verdict::DropBlock,
        Verdict::DropService,
        Verdict::DropFragment,
        Verdict::DropRatelimit,
        Verdict::TxSynChallenge,
        Verdict::SynVerified,
        Verdict::DropUnverified,
        Verdict::DropNoTenant,
        Verdict::DropTooBig,
        Verdict::DropTunnel,
        Verdict::TxReturn,
        Verdict::DropReturn,
    ];

    /// Stable name used in CLI output, JSON and (later) NATS messages.
    /// Equals the C name without the `XS_V_` prefix, lower-cased.
    pub fn name(self) -> &'static str {
        match self {
            Verdict::Pass => "pass",
            Verdict::DropMalformed => "drop_malformed",
            Verdict::PassNonIp => "pass_non_ip",
            Verdict::Fragment => "fragment",
            Verdict::PassLocal => "pass_local",
            Verdict::DropBogon => "drop_bogon",
            Verdict::PassAllow => "pass_allow",
            Verdict::DropBlock => "drop_block",
            Verdict::DropService => "drop_service",
            Verdict::DropFragment => "drop_fragment",
            Verdict::DropRatelimit => "drop_ratelimit",
            Verdict::TxSynChallenge => "tx_syn_challenge",
            Verdict::SynVerified => "syn_verified",
            Verdict::DropUnverified => "drop_unverified",
            Verdict::DropNoTenant => "drop_no_tenant",
            Verdict::DropTooBig => "drop_too_big",
            Verdict::DropTunnel => "drop_tunnel",
            Verdict::TxReturn => "tx_return",
            Verdict::DropReturn => "drop_return",
        }
    }

    pub fn from_name(name: &str) -> Option<Verdict> {
        Self::ALL.into_iter().find(|v| v.name() == name)
    }

    /// True if the packet is dropped when mitigating (`xs_verdict_drops`).
    pub fn is_drop(self) -> bool {
        matches!(
            self,
            Verdict::DropMalformed
                | Verdict::DropBogon
                | Verdict::DropBlock
                | Verdict::DropService
                | Verdict::DropFragment
                | Verdict::DropRatelimit
                | Verdict::SynVerified
                | Verdict::DropUnverified
                | Verdict::DropNoTenant
                | Verdict::DropTooBig
                | Verdict::DropTunnel
                | Verdict::DropReturn
        )
    }
}

impl TryFrom<u32> for Verdict {
    type Error = u32;
    fn try_from(v: u32) -> Result<Self, u32> {
        Self::ALL.get(v as usize).copied().ok_or(v)
    }
}

/// Rule reasons (`enum xs_reason`). Append-only.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Reason {
    None = 0,
    Manual = 1,
}

impl Reason {
    pub const ALL: [Reason; 2] = [Reason::None, Reason::Manual];

    pub fn name(self) -> &'static str {
        match self {
            Reason::None => "none",
            Reason::Manual => "manual",
        }
    }

    pub fn from_name(name: &str) -> Option<Reason> {
        Self::ALL.into_iter().find(|r| r.name() == name)
    }
}

/// Name of a raw reason code; unknown codes stay visible.
pub fn reason_name(code: u32) -> String {
    Reason::ALL
        .into_iter()
        .find(|r| *r as u32 == code)
        .map(|r| r.name().to_string())
        .unwrap_or_else(|| format!("unknown_{code}"))
}

/// `struct xs_cfg`
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct XsCfg {
    pub flags: u32,
    /// Network byte order; all-zero = unset.
    pub pop_ip4: [u8; 4],
    /// All-zero = unset.
    pub pop_ip6: [u8; 16],
    /// SipHash key for SYN cookies; all-zero = SYN cookies disabled.
    pub cookie_key: [u64; 2],
    /// 0 = XS_VERIFY_TTL_DEFAULT_S.
    pub verify_ttl_s: u32,
    /// Anycast endpoint for origin replies (network order); zero = none.
    pub tunnel_ep4: [u8; 4],
    /// Uplink router MAC; zero = send back to the frame's sender.
    pub nexthop_mac: [u8; 6],
    /// 0 = XS_DEFAULT_MTU.
    pub uplink_mtu: u16,
}

impl XsCfg {
    pub fn pop_ip4(&self) -> Option<Ipv4Addr> {
        (self.pop_ip4 != [0; 4]).then(|| Ipv4Addr::from(self.pop_ip4))
    }
    pub fn pop_ip6(&self) -> Option<Ipv6Addr> {
        (self.pop_ip6 != [0; 16]).then(|| Ipv6Addr::from(self.pop_ip6))
    }
    pub fn tunnel_ep4(&self) -> Option<Ipv4Addr> {
        (self.tunnel_ep4 != [0; 4]).then(|| Ipv4Addr::from(self.tunnel_ep4))
    }
    pub fn nexthop_mac(&self) -> Option<[u8; 6]> {
        (self.nexthop_mac != [0; 6]).then_some(self.nexthop_mac)
    }
    pub fn uplink_mtu(&self) -> u32 {
        if self.uplink_mtu == 0 {
            XS_DEFAULT_MTU
        } else {
            self.uplink_mtu as u32
        }
    }
    pub fn verify_ttl_s(&self) -> u32 {
        if self.verify_ttl_s == 0 {
            XS_VERIFY_TTL_DEFAULT_S
        } else {
            self.verify_ttl_s
        }
    }
}

/// `struct xs_tenant_key` (LPM key; prefixlen = prefix length)
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct XsTenantKey {
    pub prefixlen: u32,
    pub addr: [u8; 4],
}

/// `struct xs_tenant6_key`
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct XsTenant6Key {
    pub prefixlen: u32,
    pub addr: [u8; 16],
}

/// `struct xs_asset`: one protected prefix (ADR 0004).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct XsAsset {
    pub tenant: u32,
    pub asset: u32,
    /// Tunnel destination (network order).
    pub origin4: [u8; 4],
    pub _pad: u32,
    pub policy: XsPolicy,
}

/// `struct xs_policy`
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct XsPolicy {
    pub flags: u32,
    pub pps_per_src: u32,
    pub burst: u32,
    pub _pad: u32,
}

/// `struct xs_src_key` (LPM key; prefixlen = 32 + source prefix length)
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct XsSrcKey {
    pub prefixlen: u32,
    pub tenant: u32,
    pub src: [u8; 4],
}

/// `struct xs_src6_key`
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct XsSrc6Key {
    pub prefixlen: u32,
    pub tenant: u32,
    pub src: [u8; 16],
}

/// `struct xs_rule`
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct XsRule {
    pub expires_ns: u64,
    pub reason: u32,
    pub _pad: u32,
}

/// `struct xs_svc_key`
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct XsSvcKey {
    pub asset: u32,
    pub proto: u8,
    pub _pad: u8,
    /// Network byte order; 0 = every port / whole protocol.
    pub port: [u8; 2],
}

impl XsSvcKey {
    pub fn new(asset: u32, proto: u8, port: u16) -> Self {
        XsSvcKey {
            asset,
            proto,
            _pad: 0,
            port: port.to_be_bytes(),
        }
    }
    pub fn port(&self) -> u16 {
        u16::from_be_bytes(self.port)
    }
}

/// `struct xs_addr_key` (xs_rl, xs_verified)
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct XsAddrKey {
    pub tenant: u32,
    pub addr: [u8; 16],
}

/// `struct xs_rl`
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct XsRl {
    pub tokens: u64,
    pub last_ns: u64,
}

/// `struct xs_stats_key`
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct XsStatsKey {
    pub tenant: u32,
    pub verdict: u32,
}

/// `struct xs_stats_val`
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct XsStatsVal {
    pub pkts: u64,
    pub bytes: u64,
}

const _: () = assert!(size_of::<XsCfg>() == 56 && align_of::<XsCfg>() == 8);
const _: () = assert!(size_of::<XsTenantKey>() == 8 && align_of::<XsTenantKey>() == 4);
const _: () = assert!(size_of::<XsTenant6Key>() == 20 && align_of::<XsTenant6Key>() == 4);
const _: () = assert!(size_of::<XsAsset>() == 32 && align_of::<XsAsset>() == 4);
const _: () = assert!(size_of::<XsPolicy>() == 16 && align_of::<XsPolicy>() == 4);
const _: () = assert!(size_of::<XsSrcKey>() == 12 && align_of::<XsSrcKey>() == 4);
const _: () = assert!(size_of::<XsSrc6Key>() == 24 && align_of::<XsSrc6Key>() == 4);
const _: () = assert!(size_of::<XsRule>() == 16 && align_of::<XsRule>() == 8);
const _: () = assert!(size_of::<XsSvcKey>() == 8 && align_of::<XsSvcKey>() == 4);
const _: () = assert!(size_of::<XsAddrKey>() == 20 && align_of::<XsAddrKey>() == 4);
const _: () = assert!(size_of::<XsRl>() == 16 && align_of::<XsRl>() == 8);
const _: () = assert!(size_of::<XsStatsKey>() == 8 && align_of::<XsStatsKey>() == 4);
const _: () = assert!(size_of::<XsStatsVal>() == 16 && align_of::<XsStatsVal>() == 8);

/// Conversion to and from the raw bytes stored in BPF maps (native endian,
/// C layout). Implemented by hand so the crate needs no `unsafe`.
pub trait MapBytes: Sized {
    const SIZE: usize;
    fn to_bytes(&self) -> Vec<u8>;
    /// Returns `None` if `b` is not exactly `SIZE` bytes long.
    fn from_bytes(b: &[u8]) -> Option<Self>;
}

/// Sequential writer/reader for the field-by-field conversions.
struct W(Vec<u8>);
impl W {
    fn u8s(mut self, b: &[u8]) -> Self {
        self.0.extend_from_slice(b);
        self
    }
    fn u16(self, v: u16) -> Self {
        self.u8s(&v.to_ne_bytes())
    }
    fn u32(self, v: u32) -> Self {
        self.u8s(&v.to_ne_bytes())
    }
    fn u64(self, v: u64) -> Self {
        self.u8s(&v.to_ne_bytes())
    }
}

struct R<'a>(&'a [u8]);
impl R<'_> {
    fn arr<const N: usize>(&mut self) -> [u8; N] {
        let (head, rest) = self.0.split_at(N);
        self.0 = rest;
        head.try_into().expect("split_at(N)")
    }
    fn u16(&mut self) -> u16 {
        u16::from_ne_bytes(self.arr())
    }
    fn u32(&mut self) -> u32 {
        u32::from_ne_bytes(self.arr())
    }
    fn u64(&mut self) -> u64 {
        u64::from_ne_bytes(self.arr())
    }
}

macro_rules! map_bytes {
    ($t:ty, |$s:ident, $w:ident| $write:expr, |$r:ident| $read:expr) => {
        impl MapBytes for $t {
            const SIZE: usize = size_of::<$t>();
            fn to_bytes(&self) -> Vec<u8> {
                let $s = self;
                let $w = W(Vec::with_capacity(Self::SIZE));
                let out: W = $write;
                debug_assert_eq!(out.0.len(), Self::SIZE);
                out.0
            }
            fn from_bytes(b: &[u8]) -> Option<Self> {
                if b.len() != Self::SIZE {
                    return None;
                }
                let mut $r = R(b);
                Some($read)
            }
        }
    };
}

map_bytes!(
    XsCfg,
    |s, w| w
        .u32(s.flags)
        .u8s(&s.pop_ip4)
        .u8s(&s.pop_ip6)
        .u64(s.cookie_key[0])
        .u64(s.cookie_key[1])
        .u32(s.verify_ttl_s)
        .u8s(&s.tunnel_ep4)
        .u8s(&s.nexthop_mac)
        .u16(s.uplink_mtu),
    |r| XsCfg {
        flags: r.u32(),
        pop_ip4: r.arr(),
        pop_ip6: r.arr(),
        cookie_key: [r.u64(), r.u64()],
        verify_ttl_s: r.u32(),
        tunnel_ep4: r.arr(),
        nexthop_mac: r.arr(),
        uplink_mtu: r.u16(),
    }
);
map_bytes!(XsTenantKey, |s, w| w.u32(s.prefixlen).u8s(&s.addr), |r| {
    XsTenantKey {
        prefixlen: r.u32(),
        addr: r.arr(),
    }
});
map_bytes!(XsTenant6Key, |s, w| w.u32(s.prefixlen).u8s(&s.addr), |r| {
    XsTenant6Key {
        prefixlen: r.u32(),
        addr: r.arr(),
    }
});
map_bytes!(
    XsAsset,
    |s, w| w
        .u32(s.tenant)
        .u32(s.asset)
        .u8s(&s.origin4)
        .u32(s._pad)
        .u32(s.policy.flags)
        .u32(s.policy.pps_per_src)
        .u32(s.policy.burst)
        .u32(s.policy._pad),
    |r| XsAsset {
        tenant: r.u32(),
        asset: r.u32(),
        origin4: r.arr(),
        _pad: r.u32(),
        policy: XsPolicy {
            flags: r.u32(),
            pps_per_src: r.u32(),
            burst: r.u32(),
            _pad: r.u32()
        },
    }
);
map_bytes!(
    XsPolicy,
    |s, w| w.u32(s.flags).u32(s.pps_per_src).u32(s.burst).u32(s._pad),
    |r| XsPolicy {
        flags: r.u32(),
        pps_per_src: r.u32(),
        burst: r.u32(),
        _pad: r.u32()
    }
);
map_bytes!(
    XsSrcKey,
    |s, w| w.u32(s.prefixlen).u32(s.tenant).u8s(&s.src),
    |r| XsSrcKey {
        prefixlen: r.u32(),
        tenant: r.u32(),
        src: r.arr()
    }
);
map_bytes!(
    XsSrc6Key,
    |s, w| w.u32(s.prefixlen).u32(s.tenant).u8s(&s.src),
    |r| XsSrc6Key {
        prefixlen: r.u32(),
        tenant: r.u32(),
        src: r.arr()
    }
);
map_bytes!(
    XsRule,
    |s, w| w.u64(s.expires_ns).u32(s.reason).u32(s._pad),
    |r| XsRule {
        expires_ns: r.u64(),
        reason: r.u32(),
        _pad: r.u32()
    }
);
map_bytes!(
    XsSvcKey,
    |s, w| w.u32(s.asset).u8s(&[s.proto, s._pad]).u8s(&s.port),
    |r| {
        let asset = r.u32();
        let [proto, _pad] = r.arr();
        XsSvcKey {
            asset,
            proto,
            _pad,
            port: r.arr(),
        }
    }
);
map_bytes!(XsAddrKey, |s, w| w.u32(s.tenant).u8s(&s.addr), |r| {
    XsAddrKey {
        tenant: r.u32(),
        addr: r.arr(),
    }
});
map_bytes!(XsRl, |s, w| w.u64(s.tokens).u64(s.last_ns), |r| XsRl {
    tokens: r.u64(),
    last_ns: r.u64()
});
map_bytes!(XsStatsKey, |s, w| w.u32(s.tenant).u32(s.verdict), |r| {
    XsStatsKey {
        tenant: r.u32(),
        verdict: r.u32(),
    }
});
map_bytes!(XsStatsVal, |s, w| w.u64(s.pkts).u64(s.bytes), |r| {
    XsStatsVal {
        pkts: r.u64(),
        bytes: r.u64(),
    }
});

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const ABI_H: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../ebpf/include/abi.h"
    ));

    /// Parses `#define NAME <int>` and `#define NAME (1U << n)`.
    fn c_defines() -> HashMap<String, u64> {
        let mut out = HashMap::new();
        for line in ABI_H.lines() {
            let mut it = line.split_whitespace();
            if it.next() != Some("#define") {
                continue;
            }
            let (Some(name), Some(rest)) = (it.next(), it.next()) else {
                continue;
            };
            let rest = rest.trim_start_matches('(');
            let value = if let Some(shift) = line.split("<<").nth(1) {
                let base: u64 = rest.trim_end_matches(['U', 'u']).parse().unwrap();
                let n: u64 = shift
                    .split(|c: char| !c.is_ascii_digit())
                    .find(|s| !s.is_empty())
                    .unwrap()
                    .parse()
                    .unwrap();
                base << n
            } else if let Ok(v) = rest.parse() {
                v
            } else {
                continue; // header guards etc.
            };
            out.insert(name.to_string(), value);
        }
        out
    }

    /// Parses enum members of the form `<PREFIX>NAME = <int>,`.
    fn c_enum_values(prefix: &str) -> HashMap<String, u64> {
        ABI_H
            .lines()
            .filter_map(|l| {
                let (name, rest) = l.trim().split_once('=')?;
                let name = name.trim();
                if !name.starts_with(prefix) {
                    return None;
                }
                let v = rest.trim().split(|c: char| !c.is_ascii_digit()).next()?;
                Some((name.to_string(), v.parse().ok()?))
            })
            .collect()
    }

    /// Parses `_Static_assert(sizeof(struct NAME) == N` and `_Alignof`.
    fn c_layout(kind: &str) -> HashMap<String, usize> {
        let pat = format!("_Static_assert({kind}(struct ");
        ABI_H
            .lines()
            .filter_map(|l| {
                let rest = l.trim().strip_prefix(&pat)?;
                let (name, rest) = rest.split_once(')')?;
                let n = rest.trim().strip_prefix("==")?.trim();
                let n = n.split(|c: char| !c.is_ascii_digit()).next()?;
                Some((name.to_string(), n.parse().ok()?))
            })
            .collect()
    }

    #[test]
    fn defines_match_c() {
        let d = c_defines();
        let want: &[(&str, u32)] = &[
            ("XS_ABI_VERSION", XS_ABI_VERSION),
            ("XS_MAX_VLAN_TAGS", XS_MAX_VLAN_TAGS),
            ("XS_MAX_IPV6_EXT_HDRS", XS_MAX_IPV6_EXT_HDRS),
            ("XS_STATS_MAX_ENTRIES", XS_STATS_MAX_ENTRIES),
            ("XS_RULES_MAX_ENTRIES", XS_RULES_MAX_ENTRIES),
            ("XS_SERVICES_MAX_ENTRIES", XS_SERVICES_MAX_ENTRIES),
            ("XS_RL_MAX_ENTRIES", XS_RL_MAX_ENTRIES),
            ("XS_VERIFIED_MAX_ENTRIES", XS_VERIFIED_MAX_ENTRIES),
            ("XS_TENANTS_MAX_ENTRIES", XS_TENANTS_MAX_ENTRIES),
            ("XS_TUNNEL_OVERHEAD", XS_TUNNEL_OVERHEAD),
            ("XS_DEFAULT_MTU", XS_DEFAULT_MTU),
            ("XS_TENANT_GLOBAL", XS_TENANT_GLOBAL),
            ("XS_RL_V6_PREFIX", XS_RL_V6_PREFIX),
            ("XS_VERIFY_TTL_DEFAULT_S", XS_VERIFY_TTL_DEFAULT_S),
            ("XS_CFG_F_OBSERVE", XS_CFG_F_OBSERVE),
            ("XS_P_MITIGATE", XS_P_MITIGATE),
            ("XS_P_SYNCOOKIE", XS_P_SYNCOOKIE),
            ("XS_P_SERVICES", XS_P_SERVICES),
            ("XS_P_ALLOW_FRAG", XS_P_ALLOW_FRAG),
        ];
        for (name, v) in want {
            assert_eq!(
                d.get(*name),
                Some(&(*v as u64)),
                "{name} differs between abi.h and abi.rs"
            );
        }
        for name in d.keys() {
            assert!(
                want.iter().any(|(n, _)| n == name),
                "{name} is defined in abi.h but not mirrored in abi.rs"
            );
        }
    }

    #[test]
    fn verdicts_match_c() {
        let e = c_enum_values("XS_V_");
        for v in Verdict::ALL {
            let c = format!("XS_V_{}", v.name().to_uppercase());
            assert_eq!(e.get(&c), Some(&(v as u64)), "{v:?}");
        }
        assert_eq!(e.get("XS_V__COUNT"), Some(&(XS_V_COUNT as u64)));
        assert_eq!(e.len(), Verdict::ALL.len() + 1, "C has verdicts Rust lacks");
    }

    #[test]
    fn reasons_match_c() {
        let e = c_enum_values("XS_R_");
        for r in Reason::ALL {
            let c = format!("XS_R_{}", r.name().to_uppercase());
            assert_eq!(e.get(&c), Some(&(r as u64)), "{r:?}");
        }
        assert_eq!(e.len(), Reason::ALL.len(), "C has reasons Rust lacks");
    }

    #[test]
    fn struct_layouts_match_c() {
        let sizes = c_layout("sizeof");
        let aligns = c_layout("_Alignof");
        macro_rules! l {
            ($n:literal, $t:ty) => {
                (
                    $n,
                    size_of::<$t>(),
                    align_of::<$t>(),
                    <$t as MapBytes>::SIZE,
                )
            };
        }
        let rust = [
            l!("xs_cfg", XsCfg),
            l!("xs_policy", XsPolicy),
            l!("xs_tenant_key", XsTenantKey),
            l!("xs_tenant6_key", XsTenant6Key),
            l!("xs_asset", XsAsset),
            l!("xs_src_key", XsSrcKey),
            l!("xs_src6_key", XsSrc6Key),
            l!("xs_rule", XsRule),
            l!("xs_svc_key", XsSvcKey),
            l!("xs_addr_key", XsAddrKey),
            l!("xs_rl", XsRl),
            l!("xs_stats_key", XsStatsKey),
            l!("xs_stats_val", XsStatsVal),
        ];
        assert_eq!(sizes.len(), rust.len(), "struct count differs");
        assert_eq!(aligns.len(), rust.len(), "struct count differs");
        for (name, size, align, bytes) in rust {
            assert_eq!(sizes.get(name), Some(&size), "sizeof {name}");
            assert_eq!(aligns.get(name), Some(&align), "alignof {name}");
            assert_eq!(bytes, size, "MapBytes::SIZE {name}");
        }
    }

    #[test]
    fn verdict_round_trip() {
        for v in Verdict::ALL {
            assert_eq!(Verdict::try_from(v as u32), Ok(v));
            assert_eq!(Verdict::from_name(v.name()), Some(v));
        }
        assert_eq!(Verdict::try_from(XS_V_COUNT), Err(XS_V_COUNT));
        assert_eq!(Verdict::from_name("nope"), None);
        assert!(Verdict::DropBlock.is_drop());
        assert!(!Verdict::TxSynChallenge.is_drop());
        assert_eq!(reason_name(1), "manual");
        assert_eq!(reason_name(77), "unknown_77");
    }

    fn round_trip<T: MapBytes + PartialEq + std::fmt::Debug>(v: T) {
        let b = v.to_bytes();
        assert_eq!(b.len(), T::SIZE);
        assert_eq!(T::from_bytes(&b), Some(v));
        assert_eq!(T::from_bytes(&b[1..]), None);
    }

    #[test]
    fn map_bytes_round_trip() {
        round_trip(XsCfg {
            flags: XS_CFG_F_OBSERVE,
            pop_ip4: [10, 10, 1, 1],
            pop_ip6: [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            cookie_key: [u64::MAX, 7],
            verify_ttl_s: 300,
            tunnel_ep4: [198, 51, 100, 1],
            nexthop_mac: [2, 0, 0, 0, 0, 1],
            uplink_mtu: 9000,
        });
        round_trip(XsTenantKey {
            prefixlen: 32,
            addr: [198, 51, 100, 10],
        });
        round_trip(XsTenant6Key {
            prefixlen: 128,
            addr: [7; 16],
        });
        round_trip(XsAsset {
            tenant: 42,
            asset: 7,
            origin4: [192, 0, 2, 10],
            _pad: 0,
            policy: XsPolicy {
                flags: 3,
                pps_per_src: 100,
                burst: 200,
                _pad: 0,
            },
        });
        round_trip(XsPolicy {
            flags: 5,
            pps_per_src: 1000,
            burst: 2000,
            _pad: 0,
        });
        round_trip(XsSrcKey {
            prefixlen: 56,
            tenant: 42,
            src: [203, 0, 113, 0],
        });
        round_trip(XsSrc6Key {
            prefixlen: 80,
            tenant: 1,
            src: [9; 16],
        });
        round_trip(XsRule {
            expires_ns: 1 << 50,
            reason: 1,
            _pad: 0,
        });
        round_trip(XsSvcKey::new(0, 6, 443));
        round_trip(XsAddrKey {
            tenant: 3,
            addr: [1; 16],
        });
        round_trip(XsRl {
            tokens: 5,
            last_ns: 6,
        });
        round_trip(XsStatsKey {
            tenant: 42,
            verdict: 3,
        });
        round_trip(XsStatsVal {
            pkts: 1 << 40,
            bytes: u64::MAX,
        });
    }

    #[test]
    fn network_order_fields() {
        let k = XsSvcKey::new(0, 6, 443);
        assert_eq!(k.to_bytes()[6..8], [0x01, 0xbb]);
        assert_eq!(k.port(), 443);
        let c = XsCfg {
            pop_ip4: [10, 10, 1, 1],
            ..Default::default()
        };
        assert_eq!(c.pop_ip4(), Some(Ipv4Addr::new(10, 10, 1, 1)));
        assert_eq!(c.pop_ip6(), None);
        assert_eq!(c.verify_ttl_s(), XS_VERIFY_TTL_DEFAULT_S);
        assert_eq!(c.uplink_mtu(), 1500);
        assert_eq!(c.tunnel_ep4(), None);
        assert_eq!(c.nexthop_mac(), None);
        let a = XsAsset {
            origin4: [192, 0, 2, 10],
            ..Default::default()
        };
        assert_eq!(a.to_bytes()[8..12], [192, 0, 2, 10]);
    }
}
