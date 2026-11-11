// SPDX-License-Identifier: MIT OR Apache-2.0
//! Every command except attach/detach.

use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use libbpf_rs::{MapCore, MapFlags};
use serde::Serialize;

use sentinel_common::abi::{
    reason_name, MapBytes, XsAddrKey, XsPolicy, XsRule, XsSrc6Key, XsSrcKey, XsStatsKey,
    XsStatsVal, XsSvcKey, XS_CFG_F_OBSERVE, XS_P_ALLOW_FRAG, XS_P_MITIGATE, XS_P_SERVICES,
    XS_P_SYNCOOKIE,
};
use sentinel_common::pin::PinLayout;
use sentinel_common::prefix::Prefix;
use sentinel_common::stats::Snapshot;
use sentinel_common::units::{expires_at, format_remaining, proto_name};

use super::maps::{self, U64Val, U8Val};
use crate::{ConfigCmd, PolicyCmd, RuleAdd, RuleCmd, ServiceCmd};

fn print_json<T: Serialize>(v: &T) -> Result<()> {
    println!("{}", serde_json::to_string(v)?);
    Ok(())
}

// ---- stats / observe --------------------------------------------------------

pub fn read_stats(pins: &PinLayout) -> Result<Snapshot> {
    let map = maps::open(pins, "xs_stats")?;
    let mut rows = Vec::new();
    for key in map.keys() {
        let k = XsStatsKey::from_bytes(&key).ok_or_else(|| {
            anyhow!(
                "xs_stats key has unexpected size {} (ABI mismatch)",
                key.len()
            )
        })?;
        // An entry can vanish between keys() and lookup; skip it.
        let Some(per_cpu) = map.lookup_percpu(&key, MapFlags::ANY)? else {
            continue;
        };
        let vals = per_cpu
            .iter()
            .map(|b| {
                XsStatsVal::from_bytes(b)
                    .ok_or_else(|| anyhow!("xs_stats value has unexpected size {}", b.len()))
            })
            .collect::<Result<Vec<_>>>()?;
        rows.push((k, vals));
    }
    Ok(Snapshot::from_percpu(rows))
}

pub fn stats(pins: &PinLayout, json: bool, watch: bool, interval: u64) -> Result<()> {
    loop {
        let snap = read_stats(pins)?;
        if json {
            print_json(&snap)?;
        } else {
            if watch {
                print!("\x1b[2J\x1b[H"); // clear screen
            }
            print!("{}", snap.render_table());
        }
        if !watch {
            return Ok(());
        }
        std::thread::sleep(Duration::from_secs(interval));
    }
}

pub fn observe(pins: &PinLayout, on: bool) -> Result<()> {
    let mut cfg = maps::read_cfg(pins)?;
    if on {
        cfg.flags |= XS_CFG_F_OBSERVE;
    } else {
        cfg.flags &= !XS_CFG_F_OBSERVE;
    }
    maps::write_cfg(pins, &cfg)?;
    println!(
        "global observe {}",
        if on { "ON: nothing is dropped" } else { "off" }
    );
    Ok(())
}

// ---- config -------------------------------------------------------------------

#[derive(Serialize)]
struct ConfigView {
    observe: bool,
    pop_ip4: Option<String>,
    pop_ip6: Option<String>,
    syncookie_key_set: bool,
    verify_ttl_s: u32,
}

pub fn config(pins: &PinLayout, cmd: ConfigCmd, json: bool) -> Result<()> {
    let mut cfg = maps::read_cfg(pins)?;
    if let ConfigCmd::Set {
        pop_ip4,
        pop_ip6,
        verify_ttl,
    } = cmd
    {
        if let Some(ip) = pop_ip4 {
            cfg.pop_ip4 = ip.octets();
        }
        if let Some(ip) = pop_ip6 {
            cfg.pop_ip6 = ip.octets();
        }
        if let Some(ttl) = verify_ttl {
            cfg.verify_ttl_s =
                u32::try_from(ttl.as_secs()).map_err(|_| anyhow!("--verify-ttl is too large"))?;
        }
        maps::write_cfg(pins, &cfg)?;
    }
    let view = ConfigView {
        observe: cfg.flags & XS_CFG_F_OBSERVE != 0,
        pop_ip4: cfg.pop_ip4().map(|a| a.to_string()),
        pop_ip6: cfg.pop_ip6().map(|a| a.to_string()),
        syncookie_key_set: cfg.cookie_key != [0, 0],
        verify_ttl_s: cfg.verify_ttl_s(),
    };
    if json {
        return print_json(&view);
    }
    let none = || "-".to_string();
    println!(
        "global observe   {}",
        if view.observe { "ON" } else { "off" }
    );
    println!("pop ipv4         {}", view.pop_ip4.unwrap_or_else(none));
    println!("pop ipv6         {}", view.pop_ip6.unwrap_or_else(none));
    println!(
        "syncookie key    {}",
        if view.syncookie_key_set {
            "set"
        } else {
            "MISSING"
        }
    );
    println!("verify ttl       {}s", view.verify_ttl_s);
    Ok(())
}

// ---- policy -------------------------------------------------------------------

#[derive(Serialize)]
struct PolicyView {
    mode: &'static str,
    syncookies: bool,
    enforce_services: bool,
    fragments: &'static str,
    pps_per_src: u32,
    burst: u32,
}

fn policy_view(p: &XsPolicy) -> PolicyView {
    PolicyView {
        mode: if p.flags & XS_P_MITIGATE != 0 {
            "mitigate"
        } else {
            "observe"
        },
        syncookies: p.flags & XS_P_SYNCOOKIE != 0,
        enforce_services: p.flags & XS_P_SERVICES != 0,
        fragments: if p.flags & XS_P_ALLOW_FRAG != 0 {
            "allow"
        } else {
            "drop"
        },
        pps_per_src: p.pps_per_src,
        burst: if p.burst == 0 { p.pps_per_src } else { p.burst },
    }
}

pub fn policy(pins: &PinLayout, cmd: PolicyCmd, json: bool) -> Result<()> {
    let mut p = maps::read_policy(pins)?;
    if let PolicyCmd::Set(set) = cmd {
        p = set.apply(p);
        maps::write_policy(pins, &p)?;
    }
    let v = policy_view(&p);
    if json {
        return print_json(&v);
    }
    let onoff = |b: bool| if b { "on" } else { "off" };
    println!("mode             {}", v.mode);
    println!("syncookies       {}", onoff(v.syncookies));
    println!("enforce services {}", onoff(v.enforce_services));
    println!("fragments        {}", v.fragments);
    if v.pps_per_src == 0 {
        println!("rate limit       off");
    } else {
        println!(
            "rate limit       {} pps per source, burst {}",
            v.pps_per_src, v.burst
        );
    }
    Ok(())
}

// ---- services -------------------------------------------------------------------

#[derive(Serialize)]
struct ServiceView {
    proto: String,
    port: Option<u16>,
}

pub fn service(pins: &PinLayout, cmd: ServiceCmd, json: bool) -> Result<()> {
    let map = maps::open(pins, "xs_services")?;
    match cmd {
        ServiceCmd::Add(s) => {
            maps::put(&map, &s.key()?, &U8Val(1))?;
            println!("service added");
        }
        ServiceCmd::Del(s) => {
            if !maps::del(&map, &s.key()?)? {
                bail!("no such service");
            }
            println!("service removed");
        }
        ServiceCmd::List => {
            let mut list: Vec<XsSvcKey> = maps::entries::<XsSvcKey, U8Val>(&map)?
                .into_iter()
                .map(|(k, _)| k)
                .collect();
            list.sort_by_key(|k| (k.asset, k.proto, k.port()));
            let views: Vec<_> = list
                .iter()
                .map(|k| ServiceView {
                    proto: proto_name(k.proto),
                    port: (k.port() != 0).then(|| k.port()),
                })
                .collect();
            if json {
                return print_json(&views);
            }
            if views.is_empty() {
                println!("(no services)");
            }
            for v in views {
                match v.port {
                    Some(p) => println!("{}/{p}", v.proto),
                    None => println!("{} (all)", v.proto),
                }
            }
        }
    }
    Ok(())
}

// ---- allow / block ------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RuleKind {
    Allow,
    Block,
}

impl RuleKind {
    fn maps(self) -> (&'static str, &'static str) {
        match self {
            RuleKind::Allow => ("xs_allow", "xs_allow6"),
            RuleKind::Block => ("xs_block", "xs_block6"),
        }
    }
    fn name(self) -> &'static str {
        match self {
            RuleKind::Allow => "allow",
            RuleKind::Block => "block",
        }
    }
    /// Mirrors xs_rule_active() in policy.h.
    fn active(self, r: &XsRule, now: u64) -> bool {
        match (self, r.expires_ns) {
            (RuleKind::Allow, 0) => true,
            (RuleKind::Block, 0) => false,
            (_, e) => e > now,
        }
    }
}

#[derive(Serialize)]
struct RuleView {
    tenant: u32,
    prefix: String,
    active: bool,
    expires_ns: u64,
    expires_in: String,
    reason: String,
}

/// All rules of one kind, v4 then v6.
fn list_rules(pins: &PinLayout, kind: RuleKind) -> Result<Vec<(u32, Prefix, XsRule)>> {
    let (m4, m6) = kind.maps();
    let mut out = Vec::new();
    for (k, r) in maps::entries::<XsSrcKey, XsRule>(&maps::open(pins, m4)?)? {
        if let Some((t, p)) = Prefix::from_key4(&k) {
            out.push((t, p, r));
        }
    }
    for (k, r) in maps::entries::<XsSrc6Key, XsRule>(&maps::open(pins, m6)?)? {
        if let Some((t, p)) = Prefix::from_key6(&k) {
            out.push((t, p, r));
        }
    }
    out.sort_by_key(|(t, p, _)| (*t, !p.is_v4(), p.to_string()));
    Ok(out)
}

/// Writes or deletes the LPM entry for (tenant, prefix).
fn rule_entry(
    pins: &PinLayout,
    kind: RuleKind,
    tenant: u32,
    p: &Prefix,
    rule: Option<XsRule>,
) -> Result<bool> {
    let (m4, m6) = kind.maps();
    match (p.key4(tenant), p.key6(tenant)) {
        (Some(k), _) => {
            let m = maps::open(pins, m4)?;
            match rule {
                Some(r) => maps::put(&m, &k, &r).map(|_| true),
                None => maps::del(&m, &k),
            }
        }
        (None, Some(k)) => {
            let m = maps::open(pins, m6)?;
            match rule {
                Some(r) => maps::put(&m, &k, &r).map(|_| true),
                None => maps::del(&m, &k),
            }
        }
        (None, None) => unreachable!("a prefix is v4 or v6"),
    }
}

pub fn rules(pins: &PinLayout, kind: RuleKind, cmd: RuleCmd, json: bool) -> Result<()> {
    match cmd {
        RuleCmd::Add(RuleAdd {
            prefix,
            ttl,
            tenant,
            reason,
        }) => {
            let expires_ns = match ttl {
                Some(t) => expires_at(maps::boot_ns(), t),
                None if kind == RuleKind::Allow => 0,
                None => bail!("a block needs --ttl"),
            };
            let rule = XsRule {
                expires_ns,
                reason: reason as u32,
                _pad: 0,
            };
            rule_entry(pins, kind, tenant, &prefix, Some(rule))?;
            println!(
                "{} {prefix} (tenant {tenant}) {}",
                kind.name(),
                match ttl {
                    Some(t) => format!("for {}s", t.as_secs()),
                    None => "permanently".into(),
                }
            );
        }
        RuleCmd::Del { prefix, tenant } => {
            if !rule_entry(pins, kind, tenant, &prefix, None)? {
                bail!("no {} rule for {prefix} (tenant {tenant})", kind.name());
            }
            println!("removed {} {prefix} (tenant {tenant})", kind.name());
        }
        RuleCmd::List => {
            let now = maps::boot_ns();
            let views: Vec<_> = list_rules(pins, kind)?
                .into_iter()
                .map(|(tenant, p, r)| RuleView {
                    tenant,
                    prefix: p.to_string(),
                    active: kind.active(&r, now),
                    expires_ns: r.expires_ns,
                    expires_in: format_remaining(r.expires_ns, now),
                    reason: reason_name(r.reason),
                })
                .collect();
            if json {
                return print_json(&views);
            }
            println!("{:<8} {:<44} {:<12} REASON", "TENANT", "PREFIX", "EXPIRES");
            if views.is_empty() {
                println!("(no {} rules)", kind.name());
            }
            for v in views {
                println!(
                    "{:<8} {:<44} {:<12} {}",
                    v.tenant, v.prefix, v.expires_in, v.reason
                );
            }
        }
    }
    Ok(())
}

// ---- syncookie / gc -------------------------------------------------------------

pub fn rotate(pins: &PinLayout) -> Result<()> {
    let mut cfg = maps::read_cfg(pins)?;
    cfg.cookie_key = maps::random_key()?;
    maps::write_cfg(pins, &cfg)?;
    println!("syncookie key rotated");
    Ok(())
}

#[derive(Serialize, Default)]
struct GcReport {
    allow: usize,
    block: usize,
    verified: usize,
}

pub fn gc(pins: &PinLayout, json: bool) -> Result<()> {
    let now = maps::boot_ns();
    let mut report = GcReport::default();
    for kind in [RuleKind::Allow, RuleKind::Block] {
        let mut n = 0;
        for (tenant, p, r) in list_rules(pins, kind)? {
            if !kind.active(&r, now) && rule_entry(pins, kind, tenant, &p, None)? {
                n += 1;
            }
        }
        match kind {
            RuleKind::Allow => report.allow = n,
            RuleKind::Block => report.block = n,
        }
    }
    let verified = maps::open(pins, "xs_verified")?;
    for (k, exp) in maps::entries::<XsAddrKey, U64Val>(&verified)? {
        if exp.0 <= now && maps::del(&verified, &k)? {
            report.verified += 1;
        }
    }
    if json {
        return print_json(&report);
    }
    println!(
        "removed {} expired allow, {} expired block, {} expired verified entries",
        report.allow, report.block, report.verified
    );
    Ok(())
}
