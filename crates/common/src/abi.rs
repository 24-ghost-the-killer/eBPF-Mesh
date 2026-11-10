// SPDX-License-Identifier: MIT OR Apache-2.0
//! Rust mirror of `ebpf/include/abi.h`.
//!
//! Every struct is `#[repr(C)]` with the same field order, explicit padding and
//! compile-time size/alignment asserts. The test module parses `abi.h` and
//! fails if any constant, enum value or struct size drifts between C and Rust.

use std::mem::{align_of, size_of};

pub const XS_ABI_VERSION: u32 = 1;
pub const XS_MAX_VLAN_TAGS: u32 = 2;
pub const XS_MAX_IPV6_EXT_HDRS: u32 = 4;
pub const XS_STATS_MAX_ENTRIES: u32 = 65536;
pub const XS_TENANT_GLOBAL: u32 = 0;
pub const XS_CFG_F_OBSERVE: u32 = 1 << 0;

/// Number of defined verdicts (`XS_V__COUNT`).
pub const XS_V_COUNT: u32 = 4;

/// Packet verdicts (`enum xs_verdict`). Append-only.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Verdict {
    Pass = 0,
    DropMalformed = 1,
    PassNonIp = 2,
    Fragment = 3,
}

impl Verdict {
    pub const ALL: [Verdict; XS_V_COUNT as usize] = [
        Verdict::Pass,
        Verdict::DropMalformed,
        Verdict::PassNonIp,
        Verdict::Fragment,
    ];

    /// Stable name used in CLI output, JSON and (later) NATS messages.
    pub fn name(self) -> &'static str {
        match self {
            Verdict::Pass => "pass",
            Verdict::DropMalformed => "drop_malformed",
            Verdict::PassNonIp => "pass_non_ip",
            Verdict::Fragment => "fragment",
        }
    }

    pub fn from_name(name: &str) -> Option<Verdict> {
        Self::ALL.into_iter().find(|v| v.name() == name)
    }

    /// True if the verdict drops the packet when the tenant is mitigating.
    pub fn is_drop(self) -> bool {
        matches!(self, Verdict::DropMalformed)
    }
}

impl TryFrom<u32> for Verdict {
    type Error = u32;
    fn try_from(v: u32) -> Result<Self, u32> {
        Self::ALL.get(v as usize).copied().ok_or(v)
    }
}

/// `struct xs_cfg`
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct XsCfg {
    pub flags: u32,
    pub _pad: u32,
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

const _: () = assert!(size_of::<XsCfg>() == 8);
const _: () = assert!(align_of::<XsCfg>() == 4);
const _: () = assert!(size_of::<XsStatsKey>() == 8);
const _: () = assert!(align_of::<XsStatsKey>() == 4);
const _: () = assert!(size_of::<XsStatsVal>() == 16);
const _: () = assert!(align_of::<XsStatsVal>() == 8);

/// Conversion to and from the raw bytes stored in BPF maps (native endian,
/// C layout). Implemented by hand so the crate needs no `unsafe`.
pub trait MapBytes: Sized {
    const SIZE: usize;
    fn to_bytes(&self) -> Vec<u8>;
    /// Returns `None` if `b` is not exactly `SIZE` bytes long.
    fn from_bytes(b: &[u8]) -> Option<Self>;
}

fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_ne_bytes(b[off..off + 4].try_into().expect("slice of 4"))
}

fn u64_at(b: &[u8], off: usize) -> u64 {
    u64::from_ne_bytes(b[off..off + 8].try_into().expect("slice of 8"))
}

impl MapBytes for XsCfg {
    const SIZE: usize = size_of::<Self>();
    fn to_bytes(&self) -> Vec<u8> {
        [self.flags.to_ne_bytes(), self._pad.to_ne_bytes()].concat()
    }
    fn from_bytes(b: &[u8]) -> Option<Self> {
        (b.len() == Self::SIZE).then(|| XsCfg {
            flags: u32_at(b, 0),
            _pad: u32_at(b, 4),
        })
    }
}

impl MapBytes for XsStatsKey {
    const SIZE: usize = size_of::<Self>();
    fn to_bytes(&self) -> Vec<u8> {
        [self.tenant.to_ne_bytes(), self.verdict.to_ne_bytes()].concat()
    }
    fn from_bytes(b: &[u8]) -> Option<Self> {
        (b.len() == Self::SIZE).then(|| XsStatsKey {
            tenant: u32_at(b, 0),
            verdict: u32_at(b, 4),
        })
    }
}

impl MapBytes for XsStatsVal {
    const SIZE: usize = size_of::<Self>();
    fn to_bytes(&self) -> Vec<u8> {
        [self.pkts.to_ne_bytes(), self.bytes.to_ne_bytes()].concat()
    }
    fn from_bytes(b: &[u8]) -> Option<Self> {
        (b.len() == Self::SIZE).then(|| XsStatsVal {
            pkts: u64_at(b, 0),
            bytes: u64_at(b, 8),
        })
    }
}

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

    /// Parses enum members of the form `NAME = <int>,`.
    fn c_enum_values() -> HashMap<String, u64> {
        ABI_H
            .lines()
            .filter_map(|l| {
                let l = l.trim();
                let (name, rest) = l.split_once('=')?;
                let name = name.trim();
                if !name.starts_with("XS_V_") {
                    return None;
                }
                let v = rest.trim().trim_end_matches(|c: char| !c.is_ascii_digit());
                let v = v.split(|c: char| !c.is_ascii_digit()).next()?;
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
        let want: &[(&str, u64)] = &[
            ("XS_ABI_VERSION", XS_ABI_VERSION as u64),
            ("XS_MAX_VLAN_TAGS", XS_MAX_VLAN_TAGS as u64),
            ("XS_MAX_IPV6_EXT_HDRS", XS_MAX_IPV6_EXT_HDRS as u64),
            ("XS_STATS_MAX_ENTRIES", XS_STATS_MAX_ENTRIES as u64),
            ("XS_TENANT_GLOBAL", XS_TENANT_GLOBAL as u64),
            ("XS_CFG_F_OBSERVE", XS_CFG_F_OBSERVE as u64),
        ];
        for (name, v) in want {
            assert_eq!(
                d.get(*name),
                Some(v),
                "{name} differs between abi.h and abi.rs"
            );
        }
        // Every XS_ define in C must be mirrored (header guard excluded).
        for name in d.keys() {
            assert!(
                want.iter().any(|(n, _)| n == name),
                "{name} is defined in abi.h but not mirrored in abi.rs"
            );
        }
    }

    #[test]
    fn verdicts_match_c() {
        let e = c_enum_values();
        let c_name = |v: Verdict| format!("XS_V_{}", v.name().to_uppercase());
        for v in Verdict::ALL {
            assert_eq!(e.get(&c_name(v)), Some(&(v as u64)), "{:?}", v);
        }
        assert_eq!(e.get("XS_V__COUNT"), Some(&(XS_V_COUNT as u64)));
        assert_eq!(e.len(), Verdict::ALL.len() + 1, "C has verdicts Rust lacks");
    }

    #[test]
    fn struct_layouts_match_c() {
        let sizes = c_layout("sizeof");
        let aligns = c_layout("_Alignof");
        let rust: &[(&str, usize, usize)] = &[
            ("xs_cfg", size_of::<XsCfg>(), align_of::<XsCfg>()),
            (
                "xs_stats_key",
                size_of::<XsStatsKey>(),
                align_of::<XsStatsKey>(),
            ),
            (
                "xs_stats_val",
                size_of::<XsStatsVal>(),
                align_of::<XsStatsVal>(),
            ),
        ];
        assert_eq!(sizes.len(), rust.len(), "struct count differs");
        assert_eq!(aligns.len(), rust.len(), "struct count differs");
        for (name, size, align) in rust {
            assert_eq!(sizes.get(*name), Some(size), "sizeof {name}");
            assert_eq!(aligns.get(*name), Some(align), "alignof {name}");
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
    }

    #[test]
    fn map_bytes_round_trip() {
        let k = XsStatsKey {
            tenant: 42,
            verdict: 3,
        };
        assert_eq!(XsStatsKey::from_bytes(&k.to_bytes()), Some(k));
        let v = XsStatsVal {
            pkts: 1 << 40,
            bytes: u64::MAX,
        };
        assert_eq!(XsStatsVal::from_bytes(&v.to_bytes()), Some(v));
        let c = XsCfg {
            flags: XS_CFG_F_OBSERVE,
            _pad: 0,
        };
        assert_eq!(XsCfg::from_bytes(&c.to_bytes()), Some(c));
        assert_eq!(XsStatsVal::from_bytes(&[0; 15]), None);
    }
}
