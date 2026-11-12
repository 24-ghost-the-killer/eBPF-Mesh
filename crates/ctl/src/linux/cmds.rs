// SPDX-License-Identifier: MIT OR Apache-2.0
//! Every command except attach/detach.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use serde::Serialize;

use sentinel_common::abi::{
    reason_name, XsAsset, XsPolicy, XsRule, XsSvcKey, XS_CFG_F_OBSERVE, XS_P_ALLOW_FRAG,
    XS_P_MITIGATE, XS_P_SERVICES, XS_P_SYNCOOKIE,
};
use sentinel_common::pin::PinLayout;
use sentinel_common::prefix::Prefix;
use sentinel_common::tunnel::TunnelScript;
use sentinel_common::units::{expires_at, format_remaining, proto_name};

use sentinel_bpf::attach::{self, AttachOpts, XdpMode};
use sentinel_bpf::maps::{self, U8Val};
use sentinel_bpf::rules::{self, RuleKind};
use sentinel_bpf::stats;

use crate::{
    AssetCmd, AssetRef, AttachArgs, ConfigCmd, Mode, PolicyCmd, RuleAdd, RuleCmd, ServiceCmd,
};

fn print_json<T: Serialize>(v: &T) -> Result<()> {
    println!("{}", serde_json::to_string(v)?);
    Ok(())
}

// ---- attach / detach --------------------------------------------------------------

pub fn attach(pins: &PinLayout, a: &AttachArgs) -> Result<()> {
    let mode = match a.mode {
        Mode::Native => XdpMode::Native,
        Mode::Generic => XdpMode::Generic,
    };
    let done = attach::attach(
        pins,
        &AttachOpts {
            iface: &a.iface,
            obj: &a.obj,
            mode,
            pop_ip4: a.pop_ip4,
            pop_ip6: a.pop_ip6,
        },
    )?;
    for w in &done.warnings {
        eprintln!("sentinelctl: warning: {w}");
    }
    println!(
        "attached {} to {} (ifindex {}, {} mode, mtu {}); pins in {}",
        attach::PROG_NAME,
        a.iface,
        done.ifindex,
        if mode == XdpMode::Native {
            "native"
        } else {
            "generic"
        },
        done.mtu,
        pins.root().display()
    );
    Ok(())
}

pub fn detach(pins: &PinLayout, iface: &str) -> Result<()> {
    let done = attach::detach(pins, iface)?;
    for w in &done.warnings {
        eprintln!("sentinelctl: warning: {w}");
    }
    println!(
        "detached from {iface}{}",
        if done.maps_removed {
            "; removed pinned maps"
        } else {
            ""
        }
    );
    Ok(())
}

fn resolve_asset(pins: &PinLayout, r: &AssetRef) -> Result<(Prefix, XsAsset)> {
    maps::assets(pins)?
        .into_iter()
        .find(|(p, a)| match r {
            AssetRef::Id(id) => a.asset == *id,
            AssetRef::Prefix(q) => p == q,
        })
        .ok_or_else(|| match r {
            AssetRef::Id(id) => anyhow!("no asset with id {id}"),
            AssetRef::Prefix(q) => anyhow!("no asset for {q} (prefixes must match exactly)"),
        })
}

// ---- stats / observe --------------------------------------------------------

pub fn stats(pins: &PinLayout, json: bool, watch: bool, interval: u64) -> Result<()> {
    loop {
        let snap = stats::read(pins)?;
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
    tunnel_ep4: Option<String>,
    nexthop_mac: Option<String>,
    uplink_mtu: u32,
    syncookie_key_set: bool,
    verify_ttl_s: u32,
}

fn fmt_mac(m: [u8; 6]) -> String {
    m.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

pub fn config(pins: &PinLayout, cmd: ConfigCmd, json: bool) -> Result<()> {
    let mut cfg = maps::read_cfg(pins)?;
    if let ConfigCmd::Set {
        pop_ip4,
        pop_ip6,
        verify_ttl,
        tunnel_ep4,
        nexthop_mac,
        mtu,
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
        if let Some(ep) = tunnel_ep4 {
            if let Some((p, a)) = maps::assets(pins)?
                .into_iter()
                .find(|(p, _)| p.contains(IpAddr::V4(ep)))
            {
                bail!(
                    "{ep} is inside asset {} ({p}); the tunnel endpoint must not be protected",
                    a.asset
                );
            }
            cfg.tunnel_ep4 = ep.octets();
        }
        if let Some(mac) = nexthop_mac {
            cfg.nexthop_mac = mac;
        }
        if let Some(m) = mtu {
            cfg.uplink_mtu = m;
        }
        maps::write_cfg(pins, &cfg)?;
    }
    let view = ConfigView {
        observe: cfg.flags & XS_CFG_F_OBSERVE != 0,
        pop_ip4: cfg.pop_ip4().map(|a| a.to_string()),
        pop_ip6: cfg.pop_ip6().map(|a| a.to_string()),
        tunnel_ep4: cfg.tunnel_ep4().map(|a| a.to_string()),
        nexthop_mac: cfg.nexthop_mac().map(fmt_mac),
        uplink_mtu: cfg.uplink_mtu(),
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
    println!("tunnel endpoint  {}", view.tunnel_ep4.unwrap_or_else(none));
    println!(
        "next hop         {}",
        view.nexthop_mac
            .unwrap_or_else(|| "(reply to sender)".into())
    );
    println!("uplink mtu       {}", view.uplink_mtu);
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

// ---- assets -------------------------------------------------------------------

#[derive(Serialize)]
struct AssetView {
    id: u32,
    tenant: u32,
    prefix: String,
    origin: String,
    policy: PolicyView,
}

fn asset_view(p: &Prefix, a: &XsAsset) -> AssetView {
    AssetView {
        id: a.asset,
        tenant: a.tenant,
        prefix: p.to_string(),
        origin: Ipv4Addr::from(a.origin4).to_string(),
        policy: policy_view(&a.policy),
    }
}

pub fn asset(pins: &PinLayout, cmd: AssetCmd, json: bool) -> Result<()> {
    match cmd {
        AssetCmd::Add(add) => {
            let all = maps::assets(pins)?;
            if let Some((p, a)) = all.iter().find(|(p, _)| *p == add.prefix) {
                bail!("{p} is already asset {}", a.asset);
            }
            let id = match add.id {
                Some(id) if all.iter().any(|(_, a)| a.asset == id) => {
                    bail!("asset id {id} is taken")
                }
                Some(id) => id,
                None => all.iter().map(|(_, a)| a.asset).max().unwrap_or(0) + 1,
            };
            let cfg = maps::read_cfg(pins)?;
            for (what, ip) in [
                ("tunnel endpoint", cfg.tunnel_ep4()),
                ("PoP IP", cfg.pop_ip4()),
            ] {
                if let Some(ip) = ip.filter(|ip| add.prefix.contains(IpAddr::V4(*ip))) {
                    bail!("{} contains the {what} {ip}", add.prefix);
                }
            }
            let a = XsAsset {
                tenant: add.tenant,
                asset: id,
                origin4: add.origin.octets(),
                _pad: 0,
                policy: XsPolicy::default(), // observe mode, nothing enforced
            };
            maps::put_asset(pins, &add.prefix, &a)?;
            println!(
                "asset {id}: {} (tenant {}) -> origin {}, observe mode",
                add.prefix, add.tenant, add.origin
            );
        }
        AssetCmd::Del { asset } => {
            let (p, a) = resolve_asset(pins, &asset)?;
            maps::del_asset(pins, &p)?;
            let svc = maps::open(pins, "xs_services")?;
            let mut n = 0;
            for (k, _) in maps::entries::<XsSvcKey, U8Val>(&svc)? {
                if k.asset == a.asset && maps::del(&svc, &k)? {
                    n += 1;
                }
            }
            println!("removed asset {} ({p}) and {n} services", a.asset);
        }
        AssetCmd::List => {
            let views: Vec<_> = maps::assets(pins)?
                .iter()
                .map(|(p, a)| asset_view(p, a))
                .collect();
            if json {
                return print_json(&views);
            }
            println!(
                "{:<6} {:<8} {:<28} {:<16} {:<9} {:<10} RATE",
                "ID", "TENANT", "PREFIX", "ORIGIN", "MODE", "SYNCOOKIE"
            );
            if views.is_empty() {
                println!("(no assets)");
            }
            for v in views {
                println!(
                    "{:<6} {:<8} {:<28} {:<16} {:<9} {:<10} {}",
                    v.id,
                    v.tenant,
                    v.prefix,
                    v.origin,
                    v.policy.mode,
                    if v.policy.syncookies { "on" } else { "off" },
                    if v.policy.pps_per_src == 0 {
                        "-".to_string()
                    } else {
                        format!("{} pps", v.policy.pps_per_src)
                    }
                );
            }
        }
        AssetCmd::Script(sc) => {
            let (p, a) = resolve_asset(pins, &sc.asset)?;
            let cfg = maps::read_cfg(pins)?;
            let script = TunnelScript {
                asset_id: a.asset,
                prefix: p,
                origin: Ipv4Addr::from(a.origin4),
                tunnel_ep: cfg.tunnel_ep4(),
                pop_mtu: cfg.uplink_mtu(),
                return_mode: sc.return_mode.into(),
                device: sc.tunnel_dev.as_deref(),
            }
            .render()
            .map_err(|e| anyhow!(e))?;
            print!("{script}");
        }
    }
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
    let (prefix, mut a) = match &cmd {
        PolicyCmd::Show { asset } | PolicyCmd::Set { asset, .. } => resolve_asset(pins, asset)?,
    };
    if let PolicyCmd::Set { change, .. } = cmd {
        a.policy = change.apply(a.policy);
        maps::put_asset(pins, &prefix, &a)?;
    }
    let v = policy_view(&a.policy);
    if json {
        return print_json(&v);
    }
    let onoff = |b: bool| if b { "on" } else { "off" };
    println!("asset            {} ({prefix})", a.asset);
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
    asset: u32,
    proto: String,
    port: Option<u16>,
}

pub fn service(pins: &PinLayout, cmd: ServiceCmd, json: bool) -> Result<()> {
    let map = maps::open(pins, "xs_services")?;
    match cmd {
        ServiceCmd::Add(s) => {
            let (_, a) = resolve_asset(pins, &s.asset)?;
            maps::put(&map, &s.key(a.asset), &U8Val(1))?;
            println!("service added to asset {}", a.asset);
        }
        ServiceCmd::Del(s) => {
            let (_, a) = resolve_asset(pins, &s.asset)?;
            if !maps::del(&map, &s.key(a.asset))? {
                bail!("no such service on asset {}", a.asset);
            }
            println!("service removed from asset {}", a.asset);
        }
        ServiceCmd::List { asset } => {
            let only = match asset {
                Some(r) => Some(resolve_asset(pins, &r)?.1.asset),
                None => None,
            };
            let mut list: Vec<XsSvcKey> = maps::entries::<XsSvcKey, U8Val>(&map)?
                .into_iter()
                .map(|(k, _)| k)
                .filter(|k| only.is_none_or(|id| k.asset == id))
                .collect();
            list.sort_by_key(|k| (k.asset, k.proto, k.port()));
            let views: Vec<_> = list
                .iter()
                .map(|k| ServiceView {
                    asset: k.asset,
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
                    Some(p) => println!("asset {:<5} {}/{p}", v.asset, v.proto),
                    None => println!("asset {:<5} {} (all)", v.asset, v.proto),
                }
            }
        }
    }
    Ok(())
}

// ---- allow / block ------------------------------------------------------------

#[derive(Serialize)]
struct RuleView {
    tenant: u32,
    prefix: String,
    active: bool,
    expires_ns: u64,
    expires_in: String,
    reason: String,
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
            rules::set(pins, kind, tenant, &prefix, Some(rule))?;
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
            if !rules::set(pins, kind, tenant, &prefix, None)? {
                bail!("no {} rule for {prefix} (tenant {tenant})", kind.name());
            }
            println!("removed {} {prefix} (tenant {tenant})", kind.name());
        }
        RuleCmd::List => {
            let now = maps::boot_ns();
            let views: Vec<_> = rules::list(pins, kind)?
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

#[derive(Serialize)]
struct GcView {
    allow: usize,
    block: usize,
    verified: usize,
}

pub fn gc(pins: &PinLayout, json: bool) -> Result<()> {
    let r = rules::gc(pins)?;
    if json {
        return print_json(&GcView {
            allow: r.allow,
            block: r.block,
            verified: r.verified,
        });
    }
    println!(
        "removed {} expired allow, {} expired block, {} expired verified entries",
        r.allow, r.block, r.verified
    );
    Ok(())
}
