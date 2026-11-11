// SPDX-License-Identifier: MIT OR Apache-2.0
//! Attack detection and mitigation decisions (spec section 8, ADR 0021).
//!
//! Pure logic, driven once per second by [`Detector::tick`]:
//!
//! - **Volume** per tenant comes from `stats.<pop>` (exact per-PoP counters,
//!   identical on every worker): packets and bits per second.
//! - **Shape** comes from the sampled flows of this worker's shards: SYN
//!   packets per second, new sources per second, protocol mix, the largest
//!   sources and destinations.
//! - Each signal has an exponentially weighted baseline (mean and variance,
//!   half-life of hours). A signal is high when it exceeds an absolute floor,
//!   `factor` x its mean and mean + `sigma` standard deviations.
//! - An attack starts when at least two signals stay high for
//!   `start_after_s` seconds, and ends after `end_after_s` seconds without a
//!   high signal (hysteresis). Baselines learn only outside attacks.
//! - During an attack the largest sources matching the attack's protocol
//!   (from this worker's shards, so workers never duplicate decisions) are
//!   blocked with a TTL, aggregated to /24 (/48) when many share a prefix,
//!   never touching an allowlisted prefix, and renewed while they keep
//!   sending.

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;

use serde::Deserialize;

use sentinel_common::msg::{AttackMsg, FlowBatch, SourceRate, StatsMsg, SCHEMA_V};
use sentinel_common::prefix::Prefix;
use sentinel_common::stats::{traffic_class, TrafficClass};

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

/// Stats older than this are ignored (PoP gone).
const STATS_FRESH_MS: u64 = 5_000;
/// A source is "new" if not seen for this long.
const SOURCE_MEMORY_MS: u64 = 600_000;
/// Remembered sources per tenant (oldest forgotten first).
const SOURCE_MEMORY_MAX: usize = 200_000;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetectCfg {
    #[serde(default = "d_start")]
    pub start_after_s: u32,
    #[serde(default = "d_end")]
    pub end_after_s: u32,
    /// Absolute floors: nothing below these is an attack.
    #[serde(default = "d_min_pps")]
    pub min_pps: f64,
    #[serde(default = "d_min_bps")]
    pub min_bps: f64,
    #[serde(default = "d_min_syn")]
    pub min_syn_pps: f64,
    #[serde(default = "d_min_new")]
    pub min_new_sources: f64,
    #[serde(default = "d_factor")]
    pub factor: f64,
    #[serde(default = "d_sigma")]
    pub sigma: f64,
    #[serde(default = "d_half_life")]
    pub half_life_s: f64,
    /// Seconds of baseline before relative thresholds apply.
    #[serde(default = "d_warmup")]
    pub warmup_s: u32,
    /// Seconds between "updated" attack events.
    #[serde(default = "d_update")]
    pub update_every_s: u32,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MitigateCfg {
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default = "d_ttl")]
    pub ttl_s: u32,
    /// A source must send at least this many attack packets per second.
    #[serde(default = "d_min_src")]
    pub min_src_pps: f64,
    /// Block a whole /24 (/48) when this many of its sources qualify.
    #[serde(default = "d_agg")]
    pub aggregate_min_sources: usize,
    #[serde(default = "d_max_tick")]
    pub max_per_tick: usize,
}

fn d_start() -> u32 {
    3
}
fn d_end() -> u32 {
    30
}
fn d_min_pps() -> f64 {
    50_000.0
}
fn d_min_bps() -> f64 {
    200e6
}
fn d_min_syn() -> f64 {
    10_000.0
}
fn d_min_new() -> f64 {
    1_000.0
}
fn d_factor() -> f64 {
    4.0
}
fn d_sigma() -> f64 {
    6.0
}
fn d_half_life() -> f64 {
    3.0 * 3600.0
}
fn d_warmup() -> u32 {
    300
}
fn d_update() -> u32 {
    5
}
fn yes() -> bool {
    true
}
fn d_ttl() -> u32 {
    300
}
fn d_min_src() -> f64 {
    1_000.0
}
fn d_agg() -> usize {
    8
}
fn d_max_tick() -> usize {
    50
}

impl Default for DetectCfg {
    fn default() -> Self {
        toml_default()
    }
}
impl Default for MitigateCfg {
    fn default() -> Self {
        toml_default()
    }
}
fn toml_default<T: for<'de> Deserialize<'de>>() -> T {
    serde_json::from_str("{}").expect("all fields have defaults")
}

/// Exponentially weighted mean and variance.
#[derive(Clone, Copy, Debug, Default)]
struct Ewma {
    mean: f64,
    var: f64,
}

impl Ewma {
    fn update(&mut self, x: f64, alpha: f64) {
        let d = x - self.mean;
        self.mean += alpha * d;
        self.var = (1.0 - alpha) * (self.var + alpha * d * d);
    }

    fn threshold(&self, floor: f64, cfg: &DetectCfg, warm: bool) -> f64 {
        if !warm {
            return floor;
        }
        floor
            .max(self.mean * cfg.factor)
            .max(self.mean + cfg.sigma * self.var.sqrt())
    }
}

/// Packets per protocol class: [SYN, other TCP, UDP, ICMP/other].
type ProtoMix = [f64; 4];

fn class_of(proto: u8) -> usize {
    match proto {
        IPPROTO_TCP => 1,
        IPPROTO_UDP => 2,
        _ => 3,
    }
}

/// Flows of one tenant since the last tick.
#[derive(Default)]
struct Window {
    mix: ProtoMix,
    sources: HashMap<IpAddr, ProtoMix>,
    targets: HashMap<IpAddr, f64>,
}

struct Attack {
    id: String,
    started_at: u64,
    vector: String,
    mix: ProtoMix,
    peak_pps: f64,
    peak_bps: f64,
    pops: BTreeSet<String>,
    targets: HashMap<IpAddr, f64>,
    top: HashMap<IpAddr, f64>,
    decisions: u32,
    last_report: u64,
}

#[derive(Default)]
struct TenantState {
    pps: Ewma,
    bps: Ewma,
    syn: Ewma,
    new_sources: Ewma,
    age_s: u32,
    high_streak: u32,
    calm_streak: u32,
    /// Protocol mix while the signals are high (before the attack starts).
    streak_mix: ProtoMix,
    attack: Option<Attack>,
    seen: HashMap<IpAddr, u64>,
    /// Blocks issued: prefix -> expiry (Unix ms).
    blocked: HashMap<Prefix, u64>,
}

/// A block the run loop signs and publishes.
#[derive(Clone, Debug, PartialEq)]
pub struct BlockReq {
    pub tenant: u32,
    pub src: Prefix,
    pub ttl_s: u32,
    pub reason: String,
}

#[derive(Debug)]
pub enum Output {
    Attack(Box<AttackMsg>),
    Block(BlockReq),
}

pub struct Detector {
    issuer: String,
    detect: DetectCfg,
    mitigate: MitigateCfg,
    stats: HashMap<String, (u64, StatsMsg)>,
    windows: HashMap<u32, Window>,
    tenants: HashMap<u32, TenantState>,
    allow: HashMap<u32, Vec<Prefix>>,
    last_tick: Option<u64>,
}

/// Per-tenant totals over all fresh PoPs.
#[derive(Default)]
struct Volume {
    pps: f64,
    bps: f64,
    filtered_pps: f64,
    pops: BTreeSet<String>,
}

impl Detector {
    pub fn new(issuer: &str, detect: DetectCfg, mitigate: MitigateCfg) -> Detector {
        Detector {
            issuer: issuer.to_string(),
            detect,
            mitigate,
            stats: HashMap::new(),
            windows: HashMap::new(),
            tenants: HashMap::new(),
            allow: HashMap::new(),
            last_tick: None,
        }
    }

    /// Allowlisted prefixes per tenant (0 = global), from the rules bucket.
    pub fn set_allowlist(&mut self, allow: HashMap<u32, Vec<Prefix>>) {
        self.allow = allow;
    }

    pub fn on_stats(&mut self, msg: StatsMsg, now_ms: u64) {
        self.stats.insert(msg.pop.clone(), (now_ms, msg));
    }

    pub fn on_flows(&mut self, batch: &FlowBatch) {
        for f in &batch.flows {
            let w = self.windows.entry(f.tenant).or_default();
            let pkts = f.pkts as f64;
            let syn = (f.syn as f64).min(pkts);
            let mut mix: ProtoMix = [0.0; 4];
            if f.proto == IPPROTO_TCP {
                mix[0] = syn;
                mix[1] = pkts - syn;
            } else {
                mix[class_of(f.proto)] = pkts;
            }
            let s = w.sources.entry(f.src).or_default();
            for i in 0..4 {
                s[i] += mix[i];
                w.mix[i] += mix[i];
            }
            *w.targets.entry(f.dst).or_default() += pkts;
        }
    }

    fn volume(&self, now_ms: u64) -> HashMap<u32, Volume> {
        let mut out: HashMap<u32, Volume> = HashMap::new();
        for (recv, m) in self.stats.values() {
            if now_ms.saturating_sub(*recv) > STATS_FRESH_MS {
                continue;
            }
            for r in &m.entries {
                let class = traffic_class(&r.verdict);
                if !matches!(class, TrafficClass::Clean | TrafficClass::Filtered) || r.tenant == 0 {
                    continue;
                }
                let v = out.entry(r.tenant).or_default();
                v.pps += r.pps;
                v.bps += r.bps;
                if class == TrafficClass::Filtered {
                    v.filtered_pps += r.pps;
                }
                if r.pps > 0.0 {
                    v.pops.insert(m.pop.clone());
                }
            }
        }
        out
    }

    /// One detection step (call once per second).
    pub fn tick(&mut self, now_ms: u64) -> Vec<Output> {
        let dt = self
            .last_tick
            .map(|t| (now_ms.saturating_sub(t) as f64 / 1000.0).clamp(0.2, 10.0))
            .unwrap_or(1.0);
        self.last_tick = Some(now_ms);
        let alpha = 1.0 - (-std::f64::consts::LN_2 * dt / self.detect.half_life_s).exp();
        let volume = self.volume(now_ms);
        let mut windows = std::mem::take(&mut self.windows);
        let mut ids: BTreeSet<u32> = volume.keys().copied().collect();
        ids.extend(windows.keys().copied());
        ids.extend(self.tenants.keys().copied());
        let mut out = Vec::new();
        for tenant in ids {
            let vol = volume.get(&tenant);
            let win = windows.remove(&tenant).unwrap_or_default();
            self.tenant_tick(tenant, vol, win, now_ms, dt, alpha, &mut out);
        }
        // Forget idle tenants without an attack.
        self.tenants
            .retain(|_, s| s.attack.is_some() || s.age_s < 86_400 || !s.seen.is_empty());
        out
    }

    #[allow(clippy::too_many_arguments)]
    fn tenant_tick(
        &mut self,
        tenant: u32,
        vol: Option<&Volume>,
        win: Window,
        now: u64,
        dt: f64,
        alpha: f64,
        out: &mut Vec<Output>,
    ) {
        let cfg = &self.detect;
        let st = self.tenants.entry(tenant).or_default();
        st.age_s = st.age_s.saturating_add(dt.round() as u32);
        let (pps, bps) = vol.map(|v| (v.pps, v.bps)).unwrap_or((0.0, 0.0));
        let syn = win.mix[0] / dt;
        // New sources this second.
        let mut new = 0.0;
        for src in win.sources.keys() {
            match st.seen.insert(*src, now) {
                Some(t) if now.saturating_sub(t) < SOURCE_MEMORY_MS => {}
                _ => new += 1.0,
            }
        }
        if st.seen.len() > SOURCE_MEMORY_MAX {
            st.seen
                .retain(|_, t| now.saturating_sub(*t) < SOURCE_MEMORY_MS / 10);
        }
        let new_rate = new / dt;
        let warm = st.age_s >= cfg.warmup_s;
        let high = [
            pps > st.pps.threshold(cfg.min_pps, cfg, warm),
            bps > st.bps.threshold(cfg.min_bps, cfg, warm),
            syn > st.syn.threshold(cfg.min_syn_pps, cfg, warm),
            new_rate > st.new_sources.threshold(cfg.min_new_sources, cfg, warm),
        ];
        let nhigh = high.iter().filter(|h| **h).count();

        if st.attack.is_none() {
            if nhigh >= 2 {
                st.high_streak += 1;
                for i in 0..4 {
                    st.streak_mix[i] += win.mix[i];
                }
            } else {
                st.high_streak = 0;
                st.streak_mix = [0.0; 4];
                st.pps.update(pps, alpha);
                st.bps.update(bps, alpha);
                st.syn.update(syn, alpha);
                st.new_sources.update(new_rate, alpha);
            }
            if st.high_streak >= cfg.start_after_s.max(1) {
                let started_at = now.saturating_sub(u64::from(st.high_streak - 1) * 1000);
                st.attack = Some(Attack {
                    id: format!("{}-{}-{}", self.issuer, tenant, started_at),
                    started_at,
                    vector: vector_of(&st.streak_mix),
                    mix: st.streak_mix,
                    peak_pps: pps,
                    peak_bps: bps,
                    pops: BTreeSet::new(),
                    targets: HashMap::new(),
                    top: HashMap::new(),
                    decisions: 0,
                    last_report: now,
                });
                st.high_streak = 0;
                st.calm_streak = 0;
                st.streak_mix = [0.0; 4];
                // Report "started" below, after this second's data is in.
                if let Some(a) = st.attack.as_mut() {
                    a.last_report = 0;
                }
            } else {
                return;
            }
        }

        // ---- attack in progress --------------------------------------------------------
        let issuer = self.issuer.clone();
        let mitigate = self.mitigate.clone();
        let allow: Vec<Prefix> = self
            .allow
            .get(&tenant)
            .into_iter()
            .chain(self.allow.get(&0))
            .flatten()
            .copied()
            .collect();
        let st = self.tenants.get_mut(&tenant).expect("tenant state");
        let a = st.attack.as_mut().expect("attack");
        let first_report = a.last_report == 0;
        a.peak_pps = a.peak_pps.max(pps);
        a.peak_bps = a.peak_bps.max(bps);
        for i in 0..4 {
            a.mix[i] += win.mix[i];
        }
        a.vector = vector_of(&a.mix);
        if let Some(v) = vol {
            a.pops.extend(v.pops.iter().cloned());
        }
        for (d, p) in &win.targets {
            *a.targets.entry(*d).or_default() += p;
        }
        let class = vector_class(&a.vector);
        let mut rates: Vec<(IpAddr, f64)> = win
            .sources
            .iter()
            .map(|(s, m)| (*s, class.map(|c| m[c]).unwrap_or(m.iter().sum()) / dt))
            .collect();
        rates.sort_by(|x, y| y.1.total_cmp(&x.1));
        for (s, r) in rates.iter().take(20) {
            let e = a.top.entry(*s).or_default();
            *e = e.max(*r);
        }
        if a.top.len() > 50 {
            let mut v: Vec<_> = a.top.drain().collect();
            v.sort_by(|x, y| y.1.total_cmp(&x.1));
            v.truncate(20);
            a.top = v.into_iter().collect();
        }

        // Decisions.
        if mitigate.enabled {
            st.blocked.retain(|_, until| *until > now);
            let reqs = choose_blocks(&rates, &mitigate, &allow, &st.blocked, now);
            for p in &reqs {
                st.blocked
                    .insert(*p, now + u64::from(mitigate.ttl_s) * 1000);
                out.push(Output::Block(BlockReq {
                    tenant,
                    src: *p,
                    ttl_s: mitigate.ttl_s,
                    reason: a.vector.clone(),
                }));
            }
            a.decisions += reqs.len() as u32;
        }

        if nhigh == 0 {
            st.calm_streak += 1;
        } else {
            st.calm_streak = 0;
        }
        let ended = st.calm_streak >= self.detect.end_after_s.max(1);
        let dropped_ratio = vol
            .filter(|v| v.pps > 0.0)
            .map(|v| (v.filtered_pps / v.pps).clamp(0.0, 1.0))
            .unwrap_or(0.0);
        let status = if first_report {
            "started"
        } else if ended {
            "ended"
        } else if now.saturating_sub(a.last_report) >= u64::from(self.detect.update_every_s) * 1000
        {
            "updated"
        } else {
            ""
        };
        if !status.is_empty() {
            a.last_report = now;
            out.push(Output::Attack(Box::new(report(
                &issuer,
                tenant,
                a,
                status,
                now,
                pps,
                bps,
                dropped_ratio,
                ended,
            ))));
        }
        if ended {
            st.attack = None;
            st.calm_streak = 0;
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn report(
    issuer: &str,
    tenant: u32,
    a: &Attack,
    status: &str,
    now: u64,
    pps: f64,
    bps: f64,
    dropped_ratio: f64,
    ended: bool,
) -> AttackMsg {
    let mut targets: Vec<_> = a.targets.iter().collect();
    targets.sort_by(|x, y| y.1.total_cmp(x.1));
    let mut top: Vec<_> = a.top.iter().collect();
    top.sort_by(|x, y| y.1.total_cmp(x.1));
    AttackMsg {
        kind: "attack".into(),
        v: SCHEMA_V,
        id: a.id.clone(),
        issuer: issuer.to_string(),
        tenant,
        status: status.into(),
        vector: a.vector.clone(),
        started_at: a.started_at,
        ended_at: ended.then_some(now),
        ts: now,
        pps: round(pps),
        bps: round(bps),
        peak_pps: round(a.peak_pps),
        peak_bps: round(a.peak_bps),
        dropped_ratio: (dropped_ratio * 1000.0).round() / 1000.0,
        pops: a.pops.iter().cloned().collect(),
        targets: targets.iter().take(5).map(|(d, _)| d.to_string()).collect(),
        top_sources: top
            .iter()
            .take(10)
            .map(|(s, p)| SourceRate {
                src: s.to_string(),
                pps: round(**p),
            })
            .collect(),
        decisions: a.decisions,
    }
}

fn round(x: f64) -> f64 {
    (x * 10.0).round() / 10.0
}

/// The attack vector from the protocol mix.
pub fn vector_of(mix: &ProtoMix) -> String {
    let total: f64 = mix.iter().sum();
    if total <= 0.0 {
        return "volumetric".into();
    }
    let share = |i: usize| mix[i] / total;
    if share(0) > 0.5 {
        "syn_flood"
    } else if share(2) > 0.5 {
        "udp_flood"
    } else if share(3) > 0.5 {
        "icmp_flood"
    } else if share(1) > 0.5 {
        "ack_flood"
    } else {
        "volumetric"
    }
    .into()
}

/// Which protocol class a vector's sources are ranked by.
fn vector_class(vector: &str) -> Option<usize> {
    match vector {
        "syn_flood" => Some(0),
        "ack_flood" => Some(1),
        "udp_flood" => Some(2),
        "icmp_flood" => Some(3),
        _ => None,
    }
}

/// Picks the prefixes to block this second: sources at or above
/// `min_src_pps`, grouped into /24 (/48) when enough share one, never
/// overlapping an allowlisted prefix, skipping blocks with more than a third
/// of their TTL left.
pub fn choose_blocks(
    rates: &[(IpAddr, f64)],
    cfg: &MitigateCfg,
    allow: &[Prefix],
    blocked: &HashMap<Prefix, u64>,
    now: u64,
) -> Vec<Prefix> {
    let host = |ip: IpAddr| match ip {
        IpAddr::V4(a) => Prefix::V4(a, 32),
        IpAddr::V6(a) => Prefix::V6(a, 128),
    };
    let net = |ip: IpAddr| match ip {
        IpAddr::V4(a) => Prefix::V4(a, 24).network(),
        IpAddr::V6(a) => Prefix::V6(a, 48).network(),
    };
    let heavy: Vec<(IpAddr, f64)> = rates
        .iter()
        .copied()
        .filter(|(_, r)| *r >= cfg.min_src_pps)
        .collect();
    let mut per_net: HashMap<Prefix, (usize, f64)> = HashMap::new();
    for (ip, r) in &heavy {
        let e = per_net.entry(net(*ip)).or_default();
        e.0 += 1;
        e.1 += r;
    }
    let mut cands: Vec<(Prefix, f64)> = Vec::new();
    for (ip, r) in &heavy {
        let n = net(*ip);
        if per_net[&n].0 >= cfg.aggregate_min_sources {
            if !cands.iter().any(|(p, _)| *p == n) {
                cands.push((n, per_net[&n].1));
            }
        } else {
            cands.push((host(*ip), *r));
        }
    }
    cands.sort_by(|x, y| y.1.total_cmp(&x.1));
    let renew_before = u64::from(cfg.ttl_s) * 1000 / 3;
    let mut out = Vec::new();
    for (p, _) in cands {
        if out.len() >= cfg.max_per_tick {
            break;
        }
        if allow.iter().any(|a| a.overlaps(&p)) {
            continue;
        }
        if let Some(until) = blocked.get(&p) {
            if until.saturating_sub(now) > renew_before {
                continue;
            }
        }
        // A /24 block covers its hosts: do not also block them one by one.
        if blocked.iter().any(|(b, until)| {
            *b != p
                && b.overlaps(&p)
                && b.prefix_len() <= p.prefix_len()
                && until.saturating_sub(now) > renew_before
        }) {
            continue;
        }
        out.push(p);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_common::msg::{FlowRecord, StatsRow};
    use std::net::Ipv4Addr;

    fn cfg() -> (DetectCfg, MitigateCfg) {
        let d = DetectCfg {
            min_pps: 1000.0,
            min_bps: 1e6,
            min_syn_pps: 500.0,
            min_new_sources: 50.0,
            warmup_s: 10,
            end_after_s: 5,
            ..DetectCfg::default()
        };
        let m = MitigateCfg {
            min_src_pps: 100.0,
            ttl_s: 60,
            ..MitigateCfg::default()
        };
        (d, m)
    }

    fn stats(pop: &str, tenant: u32, pps: f64, dropped: f64) -> StatsMsg {
        let row = |verdict: &str, pps: f64| StatsRow {
            tenant,
            verdict: verdict.into(),
            pkts: 0,
            bytes: 0,
            pps,
            bps: pps * 800.0,
        };
        StatsMsg {
            kind: "stats".into(),
            v: 1,
            pop: pop.into(),
            ts: 0,
            interval_ms: 1000,
            sample_rate: 1,
            events_lost: 0,
            entries: vec![
                row("pass", pps - dropped),
                row("drop_block", dropped),
                row("tx_return", 9e9),
            ],
        }
    }

    fn flow(tenant: u32, src: Ipv4Addr, proto: u8, pkts: u64, syn: u64) -> FlowRecord {
        FlowRecord {
            kind: "flow".into(),
            v: 1,
            pop: "lab1".into(),
            tenant,
            src: IpAddr::V4(src),
            dst: "198.51.100.2".parse().unwrap(),
            proto,
            dport: 27015,
            pkts,
            bytes: pkts * 100,
            syn,
            verdict: "pass".into(),
            first_ts: 0,
            last_ts: 0,
        }
    }

    fn batch(flows: Vec<FlowRecord>) -> FlowBatch {
        FlowBatch {
            kind: "flows".into(),
            v: 1,
            pop: "lab1".into(),
            shard: 0,
            ts: 0,
            flows,
        }
    }

    /// Normal traffic for `secs` seconds starting at `t`; returns outputs.
    fn normal(det: &mut Detector, t: &mut u64, secs: u32) -> Vec<Output> {
        let mut out = Vec::new();
        for _ in 0..secs {
            *t += 1000;
            det.on_stats(stats("lab1", 7, 100.0, 0.0), *t);
            det.on_flows(&batch(vec![flow(
                7,
                Ipv4Addr::new(192, 0, 2, 50),
                IPPROTO_TCP,
                100,
                2,
            )]));
            out.extend(det.tick(*t));
        }
        out
    }

    fn bots(n: u8) -> Vec<Ipv4Addr> {
        (0..n).map(|i| Ipv4Addr::new(203, 0, 113, 64 + i)).collect()
    }

    #[test]
    fn udp_flood_is_detected_mitigated_and_ends() {
        let (d, m) = cfg();
        let mut det = Detector::new("worker-1", d, m);
        let mut t = 1_000_000;
        assert!(
            normal(&mut det, &mut t, 30).is_empty(),
            "quiet traffic is no attack"
        );

        // 4 bots, 5000 pps of UDP in total, 400 B packets.
        let mut started = None;
        let mut blocks = Vec::new();
        for s in 0..6 {
            t += 1000;
            det.on_stats(
                stats("lab1", 7, 5100.0, if s > 3 { 4000.0 } else { 0.0 }),
                t,
            );
            let mut flows: Vec<_> = bots(4)
                .iter()
                .map(|b| flow(7, *b, IPPROTO_UDP, 1250, 0))
                .collect();
            flows.push(flow(7, Ipv4Addr::new(192, 0, 2, 50), IPPROTO_TCP, 100, 2));
            det.on_flows(&batch(flows));
            for o in det.tick(t) {
                match o {
                    Output::Attack(a) => {
                        if a.status == "started" {
                            started = Some((s, a));
                        }
                    }
                    Output::Block(b) => blocks.push(b),
                }
            }
        }
        let (s, a) = started.expect("attack started");
        assert_eq!(s, 2, "after start_after_s = 3 high seconds");
        assert_eq!(a.vector, "udp_flood");
        assert_eq!(a.tenant, 7);
        assert_eq!(a.pops, vec!["lab1".to_string()]);
        assert_eq!(a.targets, vec!["198.51.100.2".to_string()]);
        assert!(a.id.starts_with("worker-1-7-"));
        // Every bot blocked exactly once (no renewals within the TTL), the
        // legitimate TCP client never.
        let mut srcs: Vec<String> = blocks.iter().map(|b| b.src.to_string()).collect();
        srcs.sort();
        assert_eq!(
            srcs,
            vec![
                "203.0.113.64/32",
                "203.0.113.65/32",
                "203.0.113.66/32",
                "203.0.113.67/32"
            ]
        );
        assert!(blocks
            .iter()
            .all(|b| b.ttl_s == 60 && b.reason == "udp_flood" && b.tenant == 7));

        // Flood stops: "ended" after end_after_s calm seconds, not before.
        let out = normal(&mut det, &mut t, 4);
        assert!(!out
            .iter()
            .any(|o| matches!(o, Output::Attack(a) if a.status == "ended")));
        let out = normal(&mut det, &mut t, 2);
        let ended: Vec<_> = out
            .iter()
            .filter_map(|o| match o {
                Output::Attack(a) if a.status == "ended" => Some(a),
                _ => None,
            })
            .collect();
        assert_eq!(ended.len(), 1);
        assert_eq!(ended[0].peak_pps, 5100.0);
        assert!(ended[0].ended_at.is_some());
        assert_eq!(ended[0].decisions, 4);
    }

    #[test]
    fn one_signal_is_not_enough_and_baseline_adapts() {
        let (mut d, m) = cfg();
        d.warmup_s = 5;
        let mut det = Detector::new("w", d, m);
        let mut t = 0;
        // Steady 3000 pps of small packets: above min_pps but bps below
        // min_bps, so only one signal -> never an attack.
        for _ in 0..20 {
            t += 1000;
            let mut s = stats("lab1", 1, 3000.0, 0.0);
            for r in &mut s.entries {
                r.bps = r.pps * 64.0;
            }
            det.on_stats(s, t);
            assert!(det.tick(t).is_empty());
        }
    }

    #[test]
    fn syn_flood_from_spoofed_sources() {
        let (d, m) = cfg();
        let mut det = Detector::new("w", d, m);
        let mut t = 0;
        normal(&mut det, &mut t, 20);
        let mut vector = None;
        let mut blocks = 0;
        for s in 0..4u32 {
            t += 1000;
            let mut st = stats("lab1", 7, 20_000.0, 0.0);
            for r in &mut st.entries {
                r.bps = r.pps * 480.0;
            }
            det.on_stats(st, t);
            // 1000 different spoofed sources, 20 SYNs each: many new sources,
            // high SYN rate, but no single source worth blocking.
            let flows = (0..1000u32)
                .map(|i| {
                    let ip = Ipv4Addr::from(0xCB00_7180u32 + s * 1000 + i);
                    flow(7, ip, IPPROTO_TCP, 20, 20)
                })
                .collect();
            det.on_flows(&batch(flows));
            for o in det.tick(t) {
                match o {
                    Output::Attack(a) => vector = Some(a.vector),
                    Output::Block(_) => blocks += 1,
                }
            }
        }
        assert_eq!(vector.as_deref(), Some("syn_flood"));
        assert_eq!(blocks, 0, "spoofed floods are left to SYN cookies");
    }

    #[test]
    fn block_choice_aggregates_and_respects_allowlist() {
        let (_, mut m) = cfg();
        m.aggregate_min_sources = 3;
        let ip = |a: u8, b: u8| IpAddr::V4(Ipv4Addr::new(203, 0, a, b));
        let rates = vec![
            (ip(113, 1), 500.0),
            (ip(113, 2), 500.0),
            (ip(113, 3), 500.0),
            (ip(114, 9), 900.0),
            (ip(115, 9), 800.0),
            (ip(116, 9), 50.0), // below min_src_pps
        ];
        let allow = vec!["203.0.115.0/28".parse().unwrap()];
        let now = 1000;
        let got = choose_blocks(&rates, &m, &allow, &HashMap::new(), now);
        let got: Vec<String> = got.iter().map(|p| p.to_string()).collect();
        assert_eq!(got, vec!["203.0.113.0/24", "203.0.114.9/32"]);

        // Recently blocked: skipped until a third of the TTL is left.
        let mut blocked = HashMap::new();
        blocked.insert("203.0.114.9/32".parse().unwrap(), now + 50_000);
        let got = choose_blocks(&rates, &m, &allow, &blocked, now);
        assert!(!got.iter().any(|p| p.to_string() == "203.0.114.9/32"));
        blocked.insert("203.0.114.9/32".parse().unwrap(), now + 10_000);
        let got = choose_blocks(&rates, &m, &allow, &blocked, now);
        assert!(
            got.iter().any(|p| p.to_string() == "203.0.114.9/32"),
            "renewed"
        );

        m.max_per_tick = 1;
        assert_eq!(
            choose_blocks(&rates, &m, &allow, &HashMap::new(), now).len(),
            1
        );
    }

    #[test]
    fn vectors() {
        assert_eq!(vector_of(&[90.0, 5.0, 5.0, 0.0]), "syn_flood");
        assert_eq!(vector_of(&[0.0, 10.0, 80.0, 10.0]), "udp_flood");
        assert_eq!(vector_of(&[0.0, 10.0, 10.0, 80.0]), "icmp_flood");
        assert_eq!(vector_of(&[0.0, 80.0, 10.0, 10.0]), "ack_flood");
        assert_eq!(vector_of(&[30.0, 30.0, 40.0, 0.0]), "volumetric");
        assert_eq!(vector_of(&[0.0; 4]), "volumetric");
    }

    #[test]
    fn stale_pops_and_tenant_zero_are_ignored() {
        let (d, m) = cfg();
        let mut det = Detector::new("w", d, m);
        det.on_stats(stats("old", 7, 1e6, 0.0), 0);
        det.on_stats(stats("lab1", 0, 1e6, 0.0), 10_000);
        let v = det.volume(10_000);
        assert!(v.is_empty(), "{:?}", v.keys().collect::<Vec<_>>());
    }
}
