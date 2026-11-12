// SPDX-License-Identifier: MIT OR Apache-2.0
//! Allow/block rules (LPM tries) and garbage collection.

use anyhow::Result;

use sentinel_common::abi::{XsAddrKey, XsRule, XsSrc6Key, XsSrcKey};
use sentinel_common::pin::PinLayout;
use sentinel_common::prefix::Prefix;

use crate::maps::{self, U64Val};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RuleKind {
    Allow,
    Block,
}

impl RuleKind {
    pub const ALL: [RuleKind; 2] = [RuleKind::Allow, RuleKind::Block];

    pub fn maps(self) -> (&'static str, &'static str) {
        match self {
            RuleKind::Allow => ("xs_allow", "xs_allow6"),
            RuleKind::Block => ("xs_block", "xs_block6"),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            RuleKind::Allow => "allow",
            RuleKind::Block => "block",
        }
    }

    /// Mirrors xs_rule_active() in policy.h.
    pub fn active(self, r: &XsRule, now: u64) -> bool {
        match (self, r.expires_ns) {
            (RuleKind::Allow, 0) => true,
            (RuleKind::Block, 0) => false,
            (_, e) => e > now,
        }
    }
}

/// All rules of one kind, IPv4 then IPv6, sorted by tenant and prefix.
pub fn list(pins: &PinLayout, kind: RuleKind) -> Result<Vec<(u32, Prefix, XsRule)>> {
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

/// Writes (Some) or deletes (None) the entry for (tenant, prefix). Returns
/// false when deleting an entry that did not exist.
pub fn set(
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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GcReport {
    pub allow: usize,
    pub block: usize,
    pub verified: usize,
}

/// Deletes inactive rules and expired verified sources. XDP already ignores
/// them; this only frees map space (and un-shadows shorter prefixes).
pub fn gc(pins: &PinLayout) -> Result<GcReport> {
    let now = maps::boot_ns();
    let mut report = GcReport::default();
    for kind in RuleKind::ALL {
        let mut n = 0;
        for (tenant, p, r) in list(pins, kind)? {
            if !kind.active(&r, now) && set(pins, kind, tenant, &p, None)? {
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
    Ok(report)
}
