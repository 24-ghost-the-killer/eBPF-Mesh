//! Rust mirror of `ebpf/src/abi.h`.
//!
//! `abi.h` is the single source of truth. The `const` assertions below pin
//! the struct sizes, and `tests::tables_match_abi_h` parses `abi.h` so any
//! drift in counter slots, parse codes or sizes fails `cargo test`.

use serde::Serialize;

use crate::AbiError;

/// `EM_ABI_VERSION`.
pub const ABI_VERSION: u32 = 1;
/// `EM_CNT_SLOTS`: counter slots in one per-CPU `struct em_stats`.
pub const CNT_SLOTS: usize = 128;
/// `EM_CNT_PARSE_BASE`: first slot of the parse-outcome histogram.
pub const CNT_PARSE_BASE: usize = 64;
/// `EM_PARSE_RC_MAX`: number of parse result codes.
pub const PARSE_RC_MAX: usize = 24;
/// `EM_PARSE_ERR_FIRST`: first malformed-frame result code.
pub const PARSE_ERR_FIRST: usize = 8;

/// `sizeof(struct em_counter)`.
pub const COUNTER_SIZE: usize = 16;
/// `sizeof(struct em_stats)`: value size of the `em_stats` map (per CPU).
pub const STATS_SIZE: usize = 2048;

/// `struct em_counter`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Counter {
    pub packets: u64,
    pub bytes: u64,
}

/// `struct em_stats`, summed over CPUs (or one CPU's copy).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stats {
    pub c: [Counter; CNT_SLOTS],
}

const _: () = assert!(size_of::<Counter>() == COUNTER_SIZE);
const _: () = assert!(size_of::<Stats>() == STATS_SIZE);
const _: () = assert!(CNT_PARSE_BASE + PARSE_RC_MAX <= CNT_SLOTS);

/// Named classification slots (`enum em_counter_id`, without PARSE_BASE and
/// SLOTS). The name is the C enumerator without `EM_CNT_`, lower-cased.
pub const COUNTERS: &[(usize, &str)] = &[
    (0, "rx"),
    (1, "verdict_pass"),
    (2, "verdict_drop"),
    (3, "verdict_tx"),
    (4, "verdict_redirect"),
    (8, "l2_vlan1"),
    (9, "l2_vlan2"),
    (16, "l3_ipv4"),
    (17, "l3_ipv6"),
    (18, "l3_arp"),
    (19, "l3_other"),
    (24, "l4_tcp"),
    (25, "l4_udp"),
    (26, "l4_icmp"),
    (27, "l4_icmpv6"),
    (28, "l4_other"),
    (32, "frag_first"),
    (33, "frag_later"),
    (34, "ipv6_ext"),
    (40, "tcp_syn"),
    (41, "tcp_synack"),
    (42, "tcp_ack"),
    (43, "tcp_fin"),
    (44, "tcp_rst"),
    (48, "anom_ipv4_options"),
    (49, "anom_tcp_bad_flags"),
    (50, "anom_udp_len_mismatch"),
    (51, "anom_land"),
    (52, "anom_ttl_zero"),
    (53, "anom_port_zero"),
];

/// Parse result codes (`enum em_parse_rc`, without ERR_FIRST and RC_MAX),
/// named `parse_<enumerator without EM_PARSE_, lower-cased>`. Slot is
/// `CNT_PARSE_BASE + code`.
pub const PARSE_RCS: &[(usize, &str)] = &[
    (0, "parse_ok"),
    (1, "parse_not_ip"),
    (2, "parse_unsup_vlan_depth"),
    (3, "parse_unsup_ipv6_ext_depth"),
    (8, "parse_err_eth_trunc"),
    (9, "parse_err_vlan_trunc"),
    (10, "parse_err_ipv4_trunc"),
    (11, "parse_err_ipv4_version"),
    (12, "parse_err_ipv4_ihl"),
    (13, "parse_err_ipv4_totlen"),
    (14, "parse_err_ipv6_trunc"),
    (15, "parse_err_ipv6_version"),
    (16, "parse_err_ipv6_plen"),
    (17, "parse_err_ipv6_ext_trunc"),
    (18, "parse_err_frag_tiny"),
    (19, "parse_err_tcp_trunc"),
    (20, "parse_err_tcp_doff"),
    (21, "parse_err_udp_trunc"),
    (22, "parse_err_udp_len"),
    (23, "parse_err_icmp_trunc"),
];

/// Slot index of a named counter (class or `parse_*`).
pub fn slot_of(name: &str) -> Option<usize> {
    COUNTERS
        .iter()
        .find(|(_, n)| *n == name)
        .map(|(s, _)| *s)
        .or_else(|| PARSE_RCS.iter().find(|(_, n)| *n == name).map(|(rc, _)| CNT_PARSE_BASE + rc))
}

/// Every named slot in slot order: class counters, then parse outcomes.
pub fn named_slots() -> impl Iterator<Item = (usize, &'static str)> {
    COUNTERS.iter().copied().chain(PARSE_RCS.iter().map(|(rc, n)| (CNT_PARSE_BASE + rc, *n)))
}

/// How a parse result code is classified (see `enum em_parse_rc`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseClass {
    Ok,
    Unsupported,
    Malformed,
}

pub fn parse_class(rc: usize) -> ParseClass {
    match rc {
        0 | 1 => ParseClass::Ok,
        _ if rc < PARSE_ERR_FIRST => ParseClass::Unsupported,
        _ => ParseClass::Malformed,
    }
}

impl Default for Stats {
    fn default() -> Self {
        Stats { c: [Counter::default(); CNT_SLOTS] }
    }
}

impl Stats {
    /// Decode one CPU's `struct em_stats` (native byte order, as returned by
    /// a per-CPU map lookup).
    pub fn from_bytes(raw: &[u8]) -> Result<Self, AbiError> {
        if raw.len() != STATS_SIZE {
            return Err(AbiError::Size { what: "em_stats", got: raw.len(), want: STATS_SIZE });
        }
        let mut s = Stats::default();
        for (i, chunk) in raw.chunks_exact(COUNTER_SIZE).enumerate() {
            let (p, b) = chunk.split_at(8);
            s.c[i] = Counter {
                packets: u64::from_ne_bytes(p.try_into().expect("8 bytes")),
                bytes: u64::from_ne_bytes(b.try_into().expect("8 bytes")),
            };
        }
        Ok(s)
    }

    /// Sum the per-CPU copies of `em_stats` into one total. Wrapping, like
    /// the counters themselves.
    pub fn sum_percpu<I, B>(values: I) -> Result<Self, AbiError>
    where
        I: IntoIterator<Item = B>,
        B: AsRef<[u8]>,
    {
        let mut total = Stats::default();
        for v in values {
            let cpu = Stats::from_bytes(v.as_ref())?;
            for (t, c) in total.c.iter_mut().zip(cpu.c.iter()) {
                t.packets = t.packets.wrapping_add(c.packets);
                t.bytes = t.bytes.wrapping_add(c.bytes);
            }
        }
        Ok(total)
    }

    /// `self - prev` per slot with wrapping subtraction: counters are
    /// monotonic and may wrap, so a delta is always the forward distance.
    pub fn delta(&self, prev: &Stats) -> Stats {
        let mut d = Stats::default();
        for (i, slot) in d.c.iter_mut().enumerate() {
            *slot = Counter {
                packets: self.c[i].packets.wrapping_sub(prev.c[i].packets),
                bytes: self.c[i].bytes.wrapping_sub(prev.c[i].bytes),
            };
        }
        d
    }

    /// Counter by name (`rx`, `l4_tcp`, `parse_ok`, ...).
    pub fn get(&self, name: &str) -> Option<Counter> {
        slot_of(name).map(|s| self.c[s])
    }

    /// Sum of the parse-outcome histogram; equals `rx` by construction.
    pub fn parse_sum(&self) -> u64 {
        self.c[CNT_PARSE_BASE..CNT_PARSE_BASE + PARSE_RC_MAX]
            .iter()
            .fold(0u64, |a, c| a.wrapping_add(c.packets))
    }

    /// Sum of all verdict slots; equals `rx` by construction.
    pub fn verdict_sum(&self) -> u64 {
        self.c[1..=4].iter().fold(0u64, |a, c| a.wrapping_add(c.packets))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ABI_H: &str = include_str!("../../../ebpf/src/abi.h");

    /// `(NAME, value)` for every `PREFIX<NAME> = <value>,` enumerator line.
    fn enumerators(prefix: &str) -> Vec<(String, usize)> {
        ABI_H
            .lines()
            .filter_map(|l| {
                let l = l.trim();
                let rest = l.strip_prefix(prefix)?;
                let (name, val) = rest.split_once('=')?;
                let val = val.split_whitespace().next()?.trim_end_matches(',');
                Some((name.trim().to_lowercase(), val.parse().ok()?))
            })
            .collect()
    }

    fn get(list: &[(String, usize)], name: &str) -> usize {
        list.iter().find(|(n, _)| n == name).unwrap_or_else(|| panic!("{name} missing")).1
    }

    #[test]
    fn tables_match_abi_h() {
        let cnt = enumerators("EM_CNT_");
        let mut c_counters: Vec<(usize, String)> = cnt
            .iter()
            .filter(|(n, _)| n != "parse_base" && n != "slots")
            .map(|(n, v)| (*v, n.clone()))
            .collect();
        c_counters.sort();
        let ours: Vec<(usize, String)> =
            COUNTERS.iter().map(|(s, n)| (*s, (*n).to_string())).collect();
        assert_eq!(ours, c_counters, "COUNTERS drifted from ebpf/src/abi.h");
        assert_eq!(get(&cnt, "slots"), CNT_SLOTS);
        assert_eq!(get(&cnt, "parse_base"), CNT_PARSE_BASE);

        let rc = enumerators("EM_PARSE_");
        let mut c_rcs: Vec<(usize, String)> = rc
            .iter()
            .filter(|(n, _)| n != "err_first" && n != "rc_max")
            .map(|(n, v)| (*v, format!("parse_{n}")))
            .collect();
        c_rcs.sort();
        let ours: Vec<(usize, String)> =
            PARSE_RCS.iter().map(|(s, n)| (*s, (*n).to_string())).collect();
        assert_eq!(ours, c_rcs, "PARSE_RCS drifted from ebpf/src/abi.h");
        assert_eq!(get(&rc, "rc_max"), PARSE_RC_MAX);
        assert_eq!(get(&rc, "err_first"), PARSE_ERR_FIRST);

        assert!(ABI_H.contains(&format!("#define EM_ABI_VERSION {ABI_VERSION}\n")));
        assert!(ABI_H.contains(&format!("sizeof(struct em_counter) == {COUNTER_SIZE}")));
        assert!(ABI_H.contains(&format!("sizeof(struct em_stats) == {STATS_SIZE}")));
    }

    #[test]
    fn tables_are_sorted_unique_and_in_range() {
        assert!(COUNTERS.windows(2).all(|w| w[0].0 < w[1].0));
        assert!(PARSE_RCS.windows(2).all(|w| w[0].0 < w[1].0));
        assert!(COUNTERS.iter().all(|(s, _)| *s < CNT_PARSE_BASE));
        assert!(PARSE_RCS.iter().all(|(rc, _)| *rc < PARSE_RC_MAX));
        let mut names: Vec<&str> = named_slots().map(|(_, n)| n).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), COUNTERS.len() + PARSE_RCS.len());
    }

    fn cpu_bytes(set: &[(usize, u64, u64)]) -> Vec<u8> {
        let mut raw = vec![0u8; STATS_SIZE];
        for &(slot, p, b) in set {
            raw[slot * 16..slot * 16 + 8].copy_from_slice(&p.to_ne_bytes());
            raw[slot * 16 + 8..slot * 16 + 16].copy_from_slice(&b.to_ne_bytes());
        }
        raw
    }

    #[test]
    fn sums_percpu_and_rejects_bad_size() {
        let cpus = [cpu_bytes(&[(0, 3, 300), (64, 3, 300)]), cpu_bytes(&[(0, 2, 20), (65, 2, 20)])];
        let s = Stats::sum_percpu(&cpus).unwrap();
        assert_eq!(s.get("rx"), Some(Counter { packets: 5, bytes: 320 }));
        assert_eq!(s.get("parse_ok").unwrap().packets, 3);
        assert_eq!(s.get("parse_not_ip").unwrap().packets, 2);
        assert_eq!(s.parse_sum(), 5);
        assert_eq!(s.get("nope"), None);
        assert!(matches!(
            Stats::from_bytes(&[0u8; 100]),
            Err(AbiError::Size { got: 100, want: STATS_SIZE, .. })
        ));
    }

    #[test]
    fn delta_wraps() {
        let mut a = Stats::default();
        let mut b = Stats::default();
        a.c[0] = Counter { packets: u64::MAX - 1, bytes: u64::MAX };
        b.c[0] = Counter { packets: 3, bytes: 9 };
        let d = b.delta(&a);
        assert_eq!(d.c[0], Counter { packets: 5, bytes: 10 });
        assert_eq!(d.c[1], Counter::default());
    }

    #[test]
    fn classifies_parse_codes() {
        assert_eq!(parse_class(0), ParseClass::Ok);
        assert_eq!(parse_class(1), ParseClass::Ok);
        assert_eq!(parse_class(3), ParseClass::Unsupported);
        assert_eq!(parse_class(8), ParseClass::Malformed);
        assert_eq!(parse_class(23), ParseClass::Malformed);
    }

    #[test]
    fn slot_lookup() {
        assert_eq!(slot_of("rx"), Some(0));
        assert_eq!(slot_of("tcp_rst"), Some(44));
        assert_eq!(slot_of("parse_err_icmp_trunc"), Some(CNT_PARSE_BASE + 23));
        assert_eq!(slot_of("bogus"), None);
    }
}
