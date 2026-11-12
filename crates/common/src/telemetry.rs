// SPDX-License-Identifier: MIT OR Apache-2.0
//! Telemetry building blocks shared by agents and workers: source-prefix
//! sharding, per-second flow aggregation of sampled events, the adaptive
//! sample-rate controller, and a generic map diff for reconciliation.

use std::collections::HashMap;
use std::hash::Hash;
use std::net::IpAddr;

use crate::abi::{Verdict, XsEvent};
use crate::msg::{FlowRecord, SCHEMA_V};

/// Shard of a source address: FNV-1a 64 over its /24 (IPv4) or /48 (IPv6),
/// modulo `shards`. Agents publish to `telemetry.<pop>.<shard>`; every
/// worker of a shard's queue group must compute the same value.
pub fn shard_of(src: IpAddr, shards: u32) -> u32 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut feed = |b: &[u8]| {
        for x in b {
            h ^= *x as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
    };
    match src {
        IpAddr::V4(a) => feed(&a.octets()[..3]),
        IpAddr::V6(a) => feed(&a.octets()[..6]),
    }
    (h % shards.max(1) as u64) as u32
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct FlowKey {
    tenant: u32,
    src: IpAddr,
    dst: IpAddr,
    proto: u8,
    dport: u16,
    verdict: u8,
}

#[derive(Clone, Copy, Debug)]
struct FlowAcc {
    pkts: u64,
    bytes: u64,
    syn: u64,
    first_ts: u64,
    last_ts: u64,
}

const TCP_SYN: u8 = 0x02;
const TCP_ACK: u8 = 0x10;
const IPPROTO_TCP: u8 = 6;

/// Collects sampled events and turns them into flow records. Every event
/// stands for `sample_rate` packets.
#[derive(Debug, Default)]
pub struct FlowAggregator {
    flows: HashMap<FlowKey, FlowAcc>,
    events: u64,
}

impl FlowAggregator {
    /// `now_ms`: wall-clock time the event was read (Unix ms).
    pub fn add(&mut self, e: &XsEvent, now_ms: u64) {
        self.events += 1;
        let scale = e.sample_rate.max(1) as u64;
        let key = FlowKey {
            tenant: e.tenant,
            src: e.src_ip(),
            dst: e.dst_ip(),
            proto: e.proto,
            dport: e.dport(),
            verdict: e.verdict,
        };
        let syn = e.proto == IPPROTO_TCP && e.tcp_flags & (TCP_SYN | TCP_ACK) == TCP_SYN;
        let acc = self.flows.entry(key).or_insert(FlowAcc {
            pkts: 0,
            bytes: 0,
            syn: 0,
            first_ts: now_ms,
            last_ts: now_ms,
        });
        acc.pkts += scale;
        acc.bytes += e.len as u64 * scale;
        if syn {
            acc.syn += scale;
        }
        acc.first_ts = acc.first_ts.min(now_ms);
        acc.last_ts = acc.last_ts.max(now_ms);
    }

    /// Events added since the last drain.
    pub fn events(&self) -> u64 {
        self.events
    }

    /// Returns all flows (sorted, for stable output) and resets.
    pub fn drain(&mut self, pop: &str) -> Vec<FlowRecord> {
        let mut out: Vec<FlowRecord> = self
            .flows
            .drain()
            .map(|(k, a)| FlowRecord {
                kind: "flow".into(),
                v: SCHEMA_V,
                pop: pop.to_string(),
                tenant: k.tenant,
                src: k.src,
                dst: k.dst,
                proto: k.proto,
                dport: k.dport,
                pkts: a.pkts,
                bytes: a.bytes,
                syn: a.syn,
                verdict: crate::stats::verdict_name(k.verdict as u32),
                first_ts: a.first_ts,
                last_ts: a.last_ts,
            })
            .collect();
        out.sort_by(|a, b| {
            (b.pkts, a.tenant, a.src, a.dst, a.dport)
                .cmp(&(a.pkts, b.tenant, b.src, b.dst, b.dport))
        });
        self.events = 0;
        out
    }
}

/// Groups flow records by shard of their source.
pub fn by_shard(flows: Vec<FlowRecord>, shards: u32) -> HashMap<u32, Vec<FlowRecord>> {
    let mut out: HashMap<u32, Vec<FlowRecord>> = HashMap::new();
    for f in flows {
        out.entry(shard_of(f.src, shards)).or_default().push(f);
    }
    out
}

/// Adaptive sampling (spec section 6): raise the divisor when events per
/// second exceed the target so analysis never drowns; lower it again when
/// traffic calms down, never below the configured base.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SampleController {
    pub base: u32,
    pub max: u32,
    pub target_eps: u64,
}

impl SampleController {
    pub fn next(&self, rate: u32, events_per_sec: u64) -> u32 {
        let rate = rate.clamp(self.base.max(1), self.max.max(self.base.max(1)));
        if events_per_sec > self.target_eps {
            // Jump straight to the factor that gets us under the target.
            let factor = events_per_sec
                .div_ceil(self.target_eps.max(1))
                .next_power_of_two();
            rate.saturating_mul(factor.min(1 << 16) as u32)
                .min(self.max)
        } else if events_per_sec < self.target_eps / 4 && rate > self.base {
            (rate / 2).max(self.base)
        } else {
            rate
        }
    }
}

/// Map reconciliation: what to write and what to delete so `actual` becomes
/// `desired`.
#[derive(Debug, PartialEq, Eq)]
pub struct Diff<K, V> {
    pub put: Vec<(K, V)>,
    pub delete: Vec<K>,
}

pub fn diff<K, V>(actual: &HashMap<K, V>, desired: &HashMap<K, V>) -> Diff<K, V>
where
    K: Eq + Hash + Clone,
    V: PartialEq + Clone,
{
    let put = desired
        .iter()
        .filter(|(k, v)| actual.get(*k) != Some(*v))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let delete = actual
        .keys()
        .filter(|k| !desired.contains_key(*k))
        .cloned()
        .collect();
    Diff { put, delete }
}

/// Verdict name for counters (re-exported for message builders).
pub fn verdict_name(v: Verdict) -> &'static str {
    v.name()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(src: [u8; 4], dport: u16, flags: u8, rate: u32, verdict: Verdict) -> XsEvent {
        let mut s = [0u8; 16];
        s[10] = 0xff;
        s[11] = 0xff;
        s[12..].copy_from_slice(&src);
        let mut d = s;
        d[12..].copy_from_slice(&[198, 51, 100, 10]);
        XsEvent {
            ts: 1,
            tenant: 42,
            asset: 1,
            src: s,
            dst: d,
            sport: 40000u16.to_be_bytes(),
            dport: dport.to_be_bytes(),
            proto: 6,
            tcp_flags: flags,
            verdict: verdict as u8,
            family: 4,
            len: 60,
            _pad: 0,
            sample_rate: rate,
        }
    }

    #[test]
    fn shards_are_stable_per_prefix() {
        let a: IpAddr = "203.0.113.7".parse().unwrap();
        let b: IpAddr = "203.0.113.200".parse().unwrap();
        assert_eq!(shard_of(a, 16), shard_of(b, 16), "same /24, same shard");
        let v6a: IpAddr = "2001:db8:1::1".parse().unwrap();
        let v6b: IpAddr = "2001:db8:1:ffff::9".parse().unwrap();
        assert_eq!(shard_of(v6a, 16), shard_of(v6b, 16), "same /48, same shard");
        assert_eq!(shard_of(a, 1), 0);
        assert_eq!(shard_of(a, 0), 0, "0 shards treated as 1");
        // Spread: 256 different /24s over 16 shards hit every shard.
        let mut seen = std::collections::HashSet::new();
        for i in 0..=255u8 {
            seen.insert(shard_of(IpAddr::from([10, i, 0, 1]), 16));
        }
        assert_eq!(seen.len(), 16);
        // Pinned value: workers in other languages must agree.
        assert_eq!(shard_of(a, 1 << 31), 1177988509); // computed independently (Python)
    }

    #[test]
    fn aggregates_and_scales() {
        let mut agg = FlowAggregator::default();
        agg.add(&ev([203, 0, 113, 7], 443, 0x02, 8, Verdict::Pass), 1000);
        agg.add(&ev([203, 0, 113, 7], 443, 0x02, 8, Verdict::Pass), 1500);
        agg.add(&ev([203, 0, 113, 7], 443, 0x12, 8, Verdict::Pass), 1200);
        agg.add(
            &ev([203, 0, 113, 7], 443, 0x02, 8, Verdict::DropBlock),
            1100,
        );
        agg.add(&ev([203, 0, 113, 9], 80, 0x10, 1, Verdict::Pass), 1300);
        assert_eq!(agg.events(), 5);
        let flows = agg.drain("cph1");
        assert_eq!(agg.events(), 0);
        assert_eq!(flows.len(), 3);
        let top = &flows[0];
        assert_eq!(
            (top.pkts, top.bytes, top.syn),
            (24, 1440, 16),
            "SYN-ACK is not a SYN"
        );
        assert_eq!((top.first_ts, top.last_ts), (1000, 1500));
        assert_eq!(top.verdict, "pass");
        assert_eq!(top.src.to_string(), "203.0.113.7");
        assert!(flows
            .iter()
            .any(|f| f.verdict == "drop_block" && f.pkts == 8));
        let shards = by_shard(flows, 4);
        assert_eq!(shards.values().map(Vec::len).sum::<usize>(), 3);
        assert!(agg.drain("cph1").is_empty());
    }

    #[test]
    fn sample_controller() {
        let c = SampleController {
            base: 1,
            max: 1024,
            target_eps: 1000,
        };
        assert_eq!(c.next(1, 500), 1, "under target: unchanged");
        assert_eq!(c.next(1, 1500), 2);
        assert_eq!(c.next(1, 9000), 16, "jumps to the needed factor");
        assert_eq!(c.next(512, 1_000_000), 1024, "capped at max");
        assert_eq!(c.next(16, 100), 8, "quiet: halve");
        assert_eq!(c.next(1, 0), 1, "never below base");
        let b = SampleController {
            base: 64,
            max: 65536,
            target_eps: 20000,
        };
        assert_eq!(b.next(0, 0), 64, "0 is lifted to base");
        assert_eq!(b.next(100, 0), 64);
    }

    #[test]
    fn diff_maps() {
        let actual: HashMap<u32, &str> = [(1, "a"), (2, "b"), (3, "c")].into();
        let desired: HashMap<u32, &str> = [(1, "a"), (2, "B"), (4, "d")].into();
        let mut d = diff(&actual, &desired);
        d.put.sort();
        d.delete.sort();
        assert_eq!(d.put, vec![(2, "B"), (4, "d")]);
        assert_eq!(d.delete, vec![3]);
        let same = diff(&desired, &desired);
        assert!(same.put.is_empty() && same.delete.is_empty());
    }
}
