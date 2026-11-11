// SPDX-License-Identifier: MIT OR Apache-2.0
//! NATS subjects, KV documents and published messages (spec section 7,
//! ADR 0015). Everything is JSON with a `"v": 1` schema version.
//!
//! KV documents are written by the API (phase 5) and read by every PoP
//! agent; published messages are written by agents and read by the API and
//! the analysis workers.

use std::net::{IpAddr, Ipv4Addr};

use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::abi::{
    Reason, XsAsset, XsPolicy, XsSvcKey, XS_P_ALLOW_FRAG, XS_P_MITIGATE, XS_P_SERVICES,
    XS_P_SYNCOOKIE,
};
use crate::prefix::Prefix;
use crate::units::{parse_proto, proto_has_ports, proto_name};

pub const SCHEMA_V: u32 = 1;

/// KV buckets the agent watches.
pub const BUCKET_TENANTS: &str = "tenants";
pub const BUCKET_SERVICES: &str = "services";
pub const BUCKET_RULES: &str = "rules";
pub const BUCKET_PLATFORM: &str = "platform";
pub const BUCKETS: [&str; 4] = [
    BUCKET_TENANTS,
    BUCKET_SERVICES,
    BUCKET_RULES,
    BUCKET_PLATFORM,
];
pub const PLATFORM_KEY: &str = "global";

/// PoP ids become NATS subject tokens: lower-case letters, digits and '-'.
pub fn validate_pop_id(id: &str) -> Result<(), String> {
    let ok = !id.is_empty()
        && id.len() <= 32
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if ok {
        Ok(())
    } else {
        Err(format!("invalid PoP id {id:?} (1-32 of a-z, 0-9, '-')"))
    }
}

pub fn subject_telemetry(pop: &str, shard: u32) -> String {
    format!("telemetry.{pop}.{shard}")
}
pub fn subject_stats(pop: &str) -> String {
    format!("stats.{pop}")
}
pub fn subject_health(pop: &str) -> String {
    format!("health.{pop}")
}
pub fn subject_ack(pop: &str) -> String {
    format!("config.ack.{pop}")
}
/// Request/reply: the API asks one PoP to test an asset's tunnel.
pub fn subject_probe(pop: &str) -> String {
    format!("probe.{pop}")
}

/// Parses a KV value; error text is what the agent puts in its ack.
pub fn parse_doc<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, String> {
    serde_json::from_slice(bytes).map_err(|e| format!("invalid JSON document: {e}"))
}

/// `asset.42` -> 42 for prefix "asset".
pub fn key_id(key: &str, prefix: &str) -> Option<u32> {
    key.strip_prefix(prefix)?.strip_prefix('.')?.parse().ok()
}

fn check_v(v: u32) -> Result<(), String> {
    if v == SCHEMA_V {
        Ok(())
    } else {
        Err(format!(
            "unsupported schema version {v} (this agent reads {SCHEMA_V})"
        ))
    }
}

// ---- KV: tenants bucket, key asset.<id> ---------------------------------------

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ModeDoc {
    #[default]
    Observe,
    Mitigate,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FragDoc {
    #[default]
    Drop,
    Allow,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDoc {
    #[serde(default)]
    pub mode: ModeDoc,
    #[serde(default)]
    pub syncookies: bool,
    #[serde(default)]
    pub enforce_services: bool,
    #[serde(default)]
    pub fragments: FragDoc,
    #[serde(default)]
    pub pps_per_src: u32,
    #[serde(default)]
    pub burst: u32,
}

impl PolicyDoc {
    pub fn to_xs(&self) -> XsPolicy {
        let mut flags = 0;
        if self.mode == ModeDoc::Mitigate {
            flags |= XS_P_MITIGATE;
        }
        if self.syncookies {
            flags |= XS_P_SYNCOOKIE;
        }
        if self.enforce_services {
            flags |= XS_P_SERVICES;
        }
        if self.fragments == FragDoc::Allow {
            flags |= XS_P_ALLOW_FRAG;
        }
        XsPolicy {
            flags,
            pps_per_src: self.pps_per_src,
            burst: self.burst,
            _pad: 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssetDoc {
    pub v: u32,
    pub version: u64,
    pub asset: u32,
    pub tenant: u32,
    pub prefix: Prefix,
    pub origin: Ipv4Addr,
    #[serde(default)]
    pub policy: PolicyDoc,
}

impl AssetDoc {
    pub fn validate(&self, key: &str) -> Result<(), String> {
        check_v(self.v)?;
        if key_id(key, "asset") != Some(self.asset) || self.asset == 0 {
            return Err(format!("key {key:?} does not match asset {}", self.asset));
        }
        if self.tenant == 0 {
            return Err("tenant 0 is reserved for global rules".into());
        }
        self.prefix.check_rule(1, 1).map_err(|e| e.0)?;
        let o = self.origin;
        if o.is_unspecified() || o.is_loopback() || o.is_multicast() || o.is_broadcast() {
            return Err(format!("origin {o} is not a routable unicast address"));
        }
        if self.prefix.contains(IpAddr::V4(o)) {
            return Err(format!("origin {o} is inside the protected prefix"));
        }
        Ok(())
    }

    pub fn to_xs(&self) -> XsAsset {
        XsAsset {
            tenant: self.tenant,
            asset: self.asset,
            origin4: self.origin.octets(),
            _pad: 0,
            policy: self.policy.to_xs(),
        }
    }
}

// ---- KV: services bucket, key asset.<id> ----------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceDoc {
    /// "tcp", "udp", "icmp", "icmpv6" or a protocol number.
    pub proto: String,
    /// TCP/UDP destination port; omit for every port / the whole protocol.
    #[serde(default)]
    pub port: Option<u16>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServicesDoc {
    pub v: u32,
    pub version: u64,
    #[serde(default)]
    pub services: Vec<ServiceDoc>,
}

impl ServicesDoc {
    /// Validates and returns the xs_services keys for the asset in `key`.
    pub fn keys(&self, key: &str) -> Result<Vec<XsSvcKey>, String> {
        check_v(self.v)?;
        let asset = key_id(key, "asset")
            .filter(|a| *a != 0)
            .ok_or_else(|| format!("key {key:?} is not asset.<id>"))?;
        let mut out = Vec::new();
        for s in &self.services {
            let proto = parse_proto(&s.proto)?;
            match s.port {
                Some(0) => return Err("port 0 is not a port; omit it for all ports".into()),
                Some(_) if !proto_has_ports(proto) => {
                    return Err(format!("{} has no ports", proto_name(proto)))
                }
                _ => {}
            }
            out.push(XsSvcKey::new(asset, proto, s.port.unwrap_or(0)));
        }
        out.sort_by_key(|k| (k.proto, k.port()));
        out.dedup();
        Ok(out)
    }
}

// ---- KV: rules bucket, key tenant.<id> (0 = global) -----------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleDoc {
    pub prefix: Prefix,
    /// Unix time in milliseconds; null = permanent (allow only).
    #[serde(default)]
    pub expires_at: Option<u64>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RulesDoc {
    pub v: u32,
    pub version: u64,
    #[serde(default)]
    pub allow: Vec<RuleDoc>,
    #[serde(default)]
    pub block: Vec<RuleDoc>,
}

/// A validated rule ready for the agent: (prefix, expiry in Unix ms, reason).
pub type ValidRule = (Prefix, Option<u64>, Reason);

impl RulesDoc {
    /// Validates; returns the tenant and the (allow, block) rules.
    pub fn validate(&self, key: &str) -> Result<(u32, Vec<ValidRule>, Vec<ValidRule>), String> {
        check_v(self.v)?;
        let tenant =
            key_id(key, "tenant").ok_or_else(|| format!("key {key:?} is not tenant.<id>"))?;
        let conv = |r: &RuleDoc, block: bool| -> Result<ValidRule, String> {
            r.prefix.check_rule(1, 1).map_err(|e| e.0)?;
            if block && r.expires_at.is_none() {
                return Err(format!(
                    "block {} has no expires_at: blocks must expire",
                    r.prefix
                ));
            }
            let reason = match r.reason.as_deref() {
                None => Reason::Manual,
                Some(n) => Reason::from_name(n).ok_or_else(|| format!("unknown reason {n:?}"))?,
            };
            Ok((r.prefix, r.expires_at, reason))
        };
        let allow = self
            .allow
            .iter()
            .map(|r| conv(r, false))
            .collect::<Result<_, _>>()?;
        let block = self
            .block
            .iter()
            .map(|r| conv(r, true))
            .collect::<Result<_, _>>()?;
        Ok((tenant, allow, block))
    }
}

// ---- KV: platform bucket, key "global" ----------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformDoc {
    pub v: u32,
    pub version: u64,
    /// Kill switch: every PoP counts verdicts but drops nothing.
    #[serde(default)]
    pub observe: bool,
}

impl PlatformDoc {
    pub fn validate(&self, key: &str) -> Result<(), String> {
        check_v(self.v)?;
        if key != PLATFORM_KEY {
            return Err(format!("unknown platform key {key:?}"));
        }
        Ok(())
    }
}

// ---- published messages -----------------------------------------------------------

/// One flow (spec section 7). Counts are scaled by the sample rate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowRecord {
    #[serde(rename = "type")]
    pub kind: String,
    pub v: u32,
    pub pop: String,
    pub tenant: u32,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub proto: u8,
    pub dport: u16,
    pub pkts: u64,
    pub bytes: u64,
    pub syn: u64,
    pub verdict: String,
    pub first_ts: u64,
    pub last_ts: u64,
}

/// `telemetry.<pop>.<shard>`: the flows of one shard for one second.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowBatch {
    #[serde(rename = "type")]
    pub kind: String,
    pub v: u32,
    pub pop: String,
    pub shard: u32,
    pub ts: u64,
    pub flows: Vec<FlowRecord>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StatsRow {
    pub tenant: u32,
    pub verdict: String,
    pub pkts: u64,
    pub bytes: u64,
    pub pps: f64,
    pub bps: f64,
}

/// `stats.<pop>`: cumulative counters and per-second rates.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StatsMsg {
    #[serde(rename = "type")]
    pub kind: String,
    pub v: u32,
    pub pop: String,
    pub ts: u64,
    pub interval_ms: u64,
    pub sample_rate: u32,
    pub events_lost: u64,
    pub entries: Vec<StatsRow>,
}

/// `health.<pop>`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HealthMsg {
    #[serde(rename = "type")]
    pub kind: String,
    pub v: u32,
    pub pop: String,
    pub region: String,
    /// The PoP's unicast address (for the API's PoP list).
    #[serde(default)]
    pub pop_ip4: Option<Ipv4Addr>,
    pub ts: u64,
    pub iface: String,
    pub xdp_attached: bool,
    /// "n/a" until the BIRD integration (phase 8).
    pub bgp: String,
    pub load1: f64,
    pub config_version: u64,
    pub sample_rate: u32,
    pub uptime_s: u64,
}

/// `config.ack.<pop>`: one per applied (or rejected) KV change.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigAck {
    #[serde(rename = "type")]
    pub kind: String,
    pub v: u32,
    pub pop: String,
    pub bucket: String,
    pub key: String,
    /// "put" or "delete".
    pub op: String,
    /// KV revision of the change.
    pub revision: u64,
    /// Document version (null for deletes and unparsable documents).
    pub version: Option<u64>,
    pub ok: bool,
    pub error: Option<String>,
    pub ts: u64,
}

/// `probe.<pop>` request: test the tunnel of one asset (ADR 0020). The
/// agent only probes assets it has applied, so the API cannot make a PoP
/// send packets to an arbitrary host.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeReq {
    pub v: u32,
    pub asset: u32,
    /// Echo requests to send (1..=5).
    pub count: u8,
}

/// Reply to a [`ProbeReq`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProbeResp {
    pub v: u32,
    pub pop: String,
    pub asset: u32,
    pub sent: u8,
    pub received: u8,
    /// Mean round trip of the answered probes.
    pub rtt_ms: Option<f64>,
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pop_ids() {
        for ok in ["cph1", "pop-2", "a"] {
            assert!(validate_pop_id(ok).is_ok(), "{ok}");
        }
        for bad in ["", "CPH1", "a.b", "a*", "a>", "x y", &"a".repeat(33)] {
            assert!(validate_pop_id(bad).is_err(), "{bad:?}");
        }
        assert_eq!(subject_telemetry("cph1", 3), "telemetry.cph1.3");
        assert_eq!(subject_ack("cph1"), "config.ack.cph1");
        assert_eq!(subject_probe("cph1"), "probe.cph1");
    }

    #[test]
    fn probe_req_is_strict() {
        let r: ProbeReq = serde_json::from_str(r#"{"v":1,"asset":3,"count":3}"#).unwrap();
        assert_eq!(r.asset, 3);
        assert!(
            serde_json::from_str::<ProbeReq>(r#"{"v":1,"asset":3,"count":3,"dst":"1.2.3.4"}"#)
                .is_err()
        );
    }

    #[test]
    fn keys() {
        assert_eq!(key_id("asset.42", "asset"), Some(42));
        assert_eq!(key_id("tenant.0", "tenant"), Some(0));
        for bad in ["asset42", "asset.", "asset.x", "tenant.1", "asset.1.2"] {
            assert_eq!(key_id(bad, "asset"), None, "{bad}");
        }
    }

    const ASSET: &str = r#"{"v":1,"version":7,"asset":1,"tenant":42,
        "prefix":"198.51.100.10/32","origin":"192.0.2.10",
        "policy":{"mode":"mitigate","syncookies":true,"pps_per_src":1000}}"#;

    #[test]
    fn asset_doc() {
        let d: AssetDoc = parse_doc(ASSET.as_bytes()).unwrap();
        d.validate("asset.1").unwrap();
        let x = d.to_xs();
        assert_eq!((x.tenant, x.asset, x.origin4), (42, 1, [192, 0, 2, 10]));
        assert_eq!(x.policy.flags, XS_P_MITIGATE | XS_P_SYNCOOKIE);
        assert_eq!(x.policy.pps_per_src, 1000);
        assert!(d
            .validate("asset.2")
            .unwrap_err()
            .contains("does not match"));

        let minimal: AssetDoc = parse_doc(
            br#"{"v":1,"version":1,"asset":3,"tenant":9,"prefix":"2001:db8:100::/48","origin":"192.0.2.20"}"#,
        )
        .unwrap();
        minimal.validate("asset.3").unwrap();
        assert_eq!(minimal.to_xs().policy.flags, 0, "defaults to observe");
    }

    #[test]
    fn asset_doc_rejects() {
        let bad = |json: &str| -> String {
            match parse_doc::<AssetDoc>(json.as_bytes()) {
                Err(e) => e,
                Ok(d) => d.validate("asset.1").unwrap_err(),
            }
        };
        let base = |field: &str, value: &str| ASSET.replacen(field, value, 1);
        assert!(bad(&base(r#""tenant":42"#, r#""tenant":0"#)).contains("tenant 0"));
        assert!(bad(&base("198.51.100.10/32", "0.0.0.0/0")).contains("every address"));
        assert!(bad(&base("192.0.2.10", "127.0.0.1")).contains("routable"));
        assert!(bad(&base("192.0.2.10", "198.51.100.10")).contains("inside"));
        assert!(bad(&base(r#""v":1"#, r#""v":2"#)).contains("schema version"));
        assert!(bad(&base(r#""mode":"mitigate""#, r#""mode":"drop""#)).contains("invalid JSON"));
        assert!(bad(&ASSET.replacen("{", r#"{"extra":1,"#, 1)).contains("unknown field"));
        assert!(bad("not json").contains("invalid JSON"));
    }

    #[test]
    fn services_doc() {
        let d: ServicesDoc = parse_doc(
            br#"{"v":1,"version":3,"services":[{"proto":"tcp","port":443},{"proto":"icmp"},{"proto":"tcp","port":443}]}"#,
        )
        .unwrap();
        let keys = d.keys("asset.5").unwrap();
        assert_eq!(keys, vec![XsSvcKey::new(5, 1, 0), XsSvcKey::new(5, 6, 443)]);
        assert!(d.keys("tenant.5").is_err());
        let icmp_port: ServicesDoc =
            parse_doc(br#"{"v":1,"version":1,"services":[{"proto":"icmp","port":1}]}"#).unwrap();
        assert!(icmp_port.keys("asset.1").unwrap_err().contains("no ports"));
        let zero: ServicesDoc =
            parse_doc(br#"{"v":1,"version":1,"services":[{"proto":"udp","port":0}]}"#).unwrap();
        assert!(zero.keys("asset.1").is_err());
    }

    #[test]
    fn rules_doc() {
        let d: RulesDoc = parse_doc(
            br#"{"v":1,"version":4,
                "allow":[{"prefix":"192.0.2.0/24"}],
                "block":[{"prefix":"203.0.113.0/24","expires_at":1762790405000,"reason":"manual"}]}"#,
        )
        .unwrap();
        let (tenant, allow, block) = d.validate("tenant.0").unwrap();
        assert_eq!(tenant, 0);
        assert_eq!(allow[0].1, None);
        assert_eq!(block[0].1, Some(1762790405000));
        let forever: RulesDoc =
            parse_doc(br#"{"v":1,"version":1,"block":[{"prefix":"203.0.113.0/24"}]}"#).unwrap();
        assert!(forever
            .validate("tenant.1")
            .unwrap_err()
            .contains("must expire"));
        let world: RulesDoc =
            parse_doc(br#"{"v":1,"version":1,"allow":[{"prefix":"::/0"}]}"#).unwrap();
        assert!(world.validate("tenant.1").is_err());
        let reason: RulesDoc = parse_doc(
            br#"{"v":1,"version":1,"block":[{"prefix":"203.0.113.0/24","expires_at":1,"reason":"x"}]}"#,
        )
        .unwrap();
        assert!(reason
            .validate("tenant.1")
            .unwrap_err()
            .contains("unknown reason"));
    }

    #[test]
    fn platform_doc() {
        let d: PlatformDoc = parse_doc(br#"{"v":1,"version":2,"observe":true}"#).unwrap();
        d.validate("global").unwrap();
        assert!(d.observe);
        assert!(d.validate("other").is_err());
    }

    #[test]
    fn flow_record_matches_spec_shape() {
        let f = FlowRecord {
            kind: "flow".into(),
            v: 1,
            pop: "cph1".into(),
            tenant: 42,
            src: "203.0.113.7".parse().unwrap(),
            dst: "198.51.100.10".parse().unwrap(),
            proto: 6,
            dport: 443,
            pkts: 1800,
            bytes: 108000,
            syn: 1800,
            verdict: "pass".into(),
            first_ts: 1762790400000,
            last_ts: 1762790401000,
        };
        let j = serde_json::to_value(&f).unwrap();
        let spec = serde_json::json!({
            "type": "flow", "v": 1, "pop": "cph1", "tenant": 42,
            "src": "203.0.113.7", "dst": "198.51.100.10", "proto": 6, "dport": 443,
            "pkts": 1800, "bytes": 108000, "syn": 1800, "verdict": "pass",
            "first_ts": 1762790400000u64, "last_ts": 1762790401000u64
        });
        assert_eq!(j, spec);
    }
}
