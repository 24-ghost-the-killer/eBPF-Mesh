// SPDX-License-Identifier: MIT OR Apache-2.0
//! Signed mitigation decisions (spec section 7, ADR 0021).
//!
//! A decision is signed with the issuer's Ed25519 key over a canonical byte
//! encoding of every field except `sig`: a fixed domain prefix, then each
//! field in a fixed order as `name`, `value` pairs, both length-prefixed
//! (u32 big endian) UTF-8. Numbers are decimal without leading zeros, the
//! source prefix is in its normalised `addr/len` form. The encoding is
//! independent of JSON formatting, field order and whitespace, and no two
//! different decisions encode to the same bytes.
//!
//! Agents accept a decision only if the issuer's key is known and not
//! revoked, the signature verifies, the timestamp is within the window, the
//! id has not been seen, and the fields are sane ([`Decision::check`]).

use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::msg::validate_pop_id;
use crate::prefix::Prefix;

pub const SUBJECT_DECISIONS: &str = "decision.global";
/// KV bucket with the trusted public keys (`issuer.<name>`).
pub const BUCKET_KEYS: &str = "keys";
/// Accepted clock difference between issuer and agent.
pub const WINDOW_MS: u64 = 60_000;
/// Longest block a decision may ask for.
pub const MAX_TTL_S: u32 = 86_400;
/// Decisions never block wider than this (customers' rule limits are
/// stricter and live in the API).
pub const MIN_PREFIX_V4: u8 = 16;
pub const MIN_PREFIX_V6: u8 = 32;

const DOMAIN: &[u8] = b"sentinel-edge/decision/v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Decision {
    #[serde(rename = "type")]
    pub kind: String,
    pub v: u32,
    /// UUIDv7 (or any 1-64 of [A-Za-z0-9-]).
    pub id: String,
    pub issuer: String,
    /// 0 = global.
    pub tenant: u32,
    pub src: String,
    /// "block" (rate-limit decisions are not implemented yet).
    pub action: String,
    pub ttl_s: u32,
    pub reason: String,
    /// Unix ms.
    pub ts: u64,
    /// Base64 Ed25519 signature over [`Decision::canonical`].
    #[serde(default)]
    pub sig: String,
}

fn field(out: &mut Vec<u8>, name: &str, value: &str) {
    for part in [name.as_bytes(), value.as_bytes()] {
        out.extend_from_slice(&(part.len() as u32).to_be_bytes());
        out.extend_from_slice(part);
    }
}

impl Decision {
    /// The bytes that are signed: every field except `sig`, in a fixed order.
    pub fn canonical(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(&(DOMAIN.len() as u32).to_be_bytes());
        out.extend_from_slice(DOMAIN);
        field(&mut out, "type", &self.kind);
        field(&mut out, "v", &self.v.to_string());
        field(&mut out, "id", &self.id);
        field(&mut out, "issuer", &self.issuer);
        field(&mut out, "tenant", &self.tenant.to_string());
        field(&mut out, "src", &self.src);
        field(&mut out, "action", &self.action);
        field(&mut out, "ttl_s", &self.ttl_s.to_string());
        field(&mut out, "reason", &self.reason);
        field(&mut out, "ts", &self.ts.to_string());
        out
    }

    /// Validates the fields (not the signature) and normalises `src`.
    pub fn validate(&mut self) -> Result<Prefix, String> {
        if self.kind != "decision" || self.v != 1 {
            return Err("not a v1 decision".into());
        }
        let id_ok = !self.id.is_empty()
            && self.id.len() <= 64
            && self
                .id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-');
        if !id_ok {
            return Err("invalid id".into());
        }
        validate_pop_id(&self.issuer).map_err(|_| "invalid issuer".to_string())?;
        if self.action != "block" {
            return Err(format!("unsupported action {:?}", self.action));
        }
        if self.ttl_s == 0 || self.ttl_s > MAX_TTL_S {
            return Err(format!("ttl_s must be 1..={MAX_TTL_S}"));
        }
        let reason_ok = !self.reason.is_empty()
            && self.reason.len() <= 32
            && self
                .reason
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
        if !reason_ok {
            return Err("invalid reason".into());
        }
        let p: Prefix = self.src.parse().map_err(|e| format!("invalid src: {e}"))?;
        p.check_rule(MIN_PREFIX_V4, MIN_PREFIX_V6)
            .map_err(|e| format!("src: {e}"))?;
        if p.to_string() != self.src {
            return Err(format!("src must be written as {p}"));
        }
        Ok(p)
    }

    pub fn sign(&mut self, key: &SigningKey) {
        self.sig = B64.encode(key.sign(&self.canonical()).to_bytes());
    }

    pub fn verify(&self, key: &VerifyingKey) -> bool {
        let Ok(bytes) = B64.decode(&self.sig) else {
            return false;
        };
        let Ok(sig) = Signature::from_slice(&bytes) else {
            return false;
        };
        key.verify(&self.canonical(), &sig).is_ok()
    }
}

/// Why a decision was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum Reject {
    Invalid(String),
    UnknownIssuer,
    RevokedIssuer,
    BadSignature,
    Stale,
    Replay,
}

impl Reject {
    /// Stable label for metrics.
    pub fn label(&self) -> &'static str {
        match self {
            Reject::Invalid(_) => "invalid",
            Reject::UnknownIssuer => "unknown_issuer",
            Reject::RevokedIssuer => "revoked_issuer",
            Reject::BadSignature => "bad_signature",
            Reject::Stale => "stale",
            Reject::Replay => "replay",
        }
    }
}

impl std::fmt::Display for Reject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Reject::Invalid(e) => write!(f, "invalid: {e}"),
            other => f.write_str(other.label()),
        }
    }
}

/// `keys` bucket document: one trusted issuer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyDoc {
    pub v: u32,
    pub version: u64,
    pub issuer: String,
    /// Base64 of the 32-byte Ed25519 public key.
    pub public_key: String,
    pub revoked: bool,
}

impl KeyDoc {
    pub fn key_name(issuer: &str) -> String {
        format!("issuer.{issuer}")
    }

    pub fn verifying_key(&self) -> Result<VerifyingKey, String> {
        parse_public_key(&self.public_key)
    }
}

pub fn parse_public_key(b64: &str) -> Result<VerifyingKey, String> {
    let bytes = B64
        .decode(b64.trim())
        .map_err(|e| format!("public key: {e}"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "public key must be 32 bytes".to_string())?;
    VerifyingKey::from_bytes(&arr).map_err(|e| format!("public key: {e}"))
}

pub fn public_key_b64(key: &SigningKey) -> String {
    B64.encode(key.verifying_key().to_bytes())
}

/// Seed files hold the base64 32-byte seed (and nothing else).
pub fn signing_key_from_b64(seed: &str) -> Result<SigningKey, String> {
    let bytes = B64.decode(seed.trim()).map_err(|e| format!("seed: {e}"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "seed must be 32 bytes".to_string())?;
    Ok(SigningKey::from_bytes(&arr))
}

pub fn seed_b64(key: &SigningKey) -> String {
    B64.encode(key.to_bytes())
}

/// Trusted keys and the replay cache: everything an agent needs to accept
/// or refuse a decision.
#[derive(Default)]
pub struct Verifier {
    keys: HashMap<String, (VerifyingKey, bool)>,
    seen: HashMap<String, u64>,
}

impl Verifier {
    pub fn set_key(&mut self, issuer: &str, key: VerifyingKey, revoked: bool) {
        self.keys.insert(issuer.to_string(), (key, revoked));
    }

    pub fn remove_key(&mut self, issuer: &str) {
        self.keys.remove(issuer);
    }

    /// Replaces the trusted keys, keeping the replay cache.
    pub fn replace_keys(&mut self, other: Verifier) {
        self.keys = other.keys;
    }

    pub fn issuers(&self) -> usize {
        self.keys.len()
    }

    /// Full check; on success the id is remembered and the parsed source
    /// prefix returned.
    pub fn accept(&mut self, d: &mut Decision, now_ms: u64) -> Result<Prefix, Reject> {
        let prefix = d.validate().map_err(Reject::Invalid)?;
        let (key, revoked) = self.keys.get(&d.issuer).ok_or(Reject::UnknownIssuer)?;
        if *revoked {
            return Err(Reject::RevokedIssuer);
        }
        if !d.verify(key) {
            return Err(Reject::BadSignature);
        }
        if d.ts.abs_diff(now_ms) > WINDOW_MS {
            return Err(Reject::Stale);
        }
        // Ids older than the window are refused as stale anyway, so the
        // cache only needs to cover the window on both sides.
        self.seen.retain(|_, until| *until > now_ms);
        let key = format!("{}/{}", d.issuer, d.id);
        if self.seen.contains_key(&key) {
            return Err(Reject::Replay);
        }
        self.seen.insert(key, d.ts + 2 * WINDOW_MS);
        Ok(prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> SigningKey {
        SigningKey::from_bytes(&[n; 32])
    }

    fn decision() -> Decision {
        Decision {
            kind: "decision".into(),
            v: 1,
            id: "0190f5c3-6d2a-7b4e-9a1f-2c3d4e5f6a7b".into(),
            issuer: "worker-2".into(),
            tenant: 42,
            src: "203.0.113.0/24".into(),
            action: "block".into(),
            ttl_s: 300,
            reason: "syn_flood".into(),
            ts: 1762790405000,
            sig: String::new(),
        }
    }

    #[test]
    fn canonical_encoding_is_fixed() {
        let d = decision();
        let c = d.canonical();
        // domain, then (name, value) pairs with u32 BE lengths
        assert_eq!(&c[..4], &25u32.to_be_bytes());
        assert_eq!(&c[4..29], b"sentinel-edge/decision/v1");
        assert_eq!(&c[29..33], &4u32.to_be_bytes());
        assert_eq!(&c[33..37], b"type");
        // Independent of JSON field order and whitespace.
        let json = r#"{ "sig":"", "ts":1762790405000, "reason":"syn_flood", "ttl_s":300,
            "action":"block", "src":"203.0.113.0/24", "tenant":42, "issuer":"worker-2",
            "id":"0190f5c3-6d2a-7b4e-9a1f-2c3d4e5f6a7b", "v":1, "type":"decision" }"#;
        let parsed: Decision = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.canonical(), c);
        // Pinned digest: changing the encoding breaks every deployed signer.
        let mut h: u64 = 0xcbf29ce484222325;
        for b in &c {
            h ^= *b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        assert_eq!(c.len(), 249);
        assert_eq!(h, 0xb2d4_9f4f_7d03_4462, "canonical encoding changed");
        // Test vector: seed [7; 32] signs this decision as follows.
        let mut s = d.clone();
        s.sign(&SigningKey::from_bytes(&[7; 32]));
        assert_eq!(
            s.sig,
            "bE1iTKBu7IHjOUaDjRJ9N3NqN4jflYTKQmO9jf7bwxvnjSDHmKCm3cFWF9EqyYe6ynhOY3q8Ut3+QI0tWcrbCA=="
        );
    }

    #[test]
    fn no_field_boundary_ambiguity() {
        let mut a = decision();
        let mut b = decision();
        a.reason = "syn".into();
        a.issuer = "worker-2".into();
        b.reason = "syn".into();
        b.issuer = "worker-".into();
        b.id = format!("2{}", b.id); // shift a byte between fields
        assert_ne!(a.canonical(), b.canonical());
    }

    #[test]
    fn sign_and_verify() {
        let k = key(7);
        let mut d = decision();
        d.sign(&k);
        assert!(d.verify(&k.verifying_key()));
        assert!(!d.verify(&key(8).verifying_key()), "other key");
        // Every signed field is covered.
        type Tamper = Box<dyn Fn(&mut Decision)>;
        let tamper: Vec<Tamper> = vec![
            Box::new(|d| d.id.push('x')),
            Box::new(|d| d.issuer = "worker-3".into()),
            Box::new(|d| d.tenant = 43),
            Box::new(|d| d.src = "203.0.113.0/25".into()),
            Box::new(|d| d.action = "allow".into()),
            Box::new(|d| d.ttl_s = 301),
            Box::new(|d| d.reason = "udp_flood".into()),
            Box::new(|d| d.ts += 1),
            Box::new(|d| d.v = 2),
        ];
        for t in tamper {
            let mut x = d.clone();
            t(&mut x);
            assert!(!x.verify(&k.verifying_key()), "{x:?}");
        }
        let mut garbage = d.clone();
        garbage.sig = "not base64!".into();
        assert!(!garbage.verify(&k.verifying_key()));
        // Ed25519 is deterministic: the same decision, the same signature.
        let mut again = decision();
        again.sign(&k);
        assert_eq!(again.sig, d.sig);
        // JSON round trip keeps it valid.
        let back: Decision = serde_json::from_str(&serde_json::to_string(&d).unwrap()).unwrap();
        assert!(back.verify(&k.verifying_key()));
    }

    #[test]
    fn field_checks() {
        let bad = |f: &dyn Fn(&mut Decision)| {
            let mut d = decision();
            f(&mut d);
            d.validate().is_err()
        };
        assert!(decision().validate().is_ok());
        assert!(bad(&|d| d.src = "0.0.0.0/0".into()));
        assert!(bad(&|d| d.src = "10.0.0.0/8".into()));
        assert!(bad(&|d| d.src = "::/0".into()));
        assert!(bad(&|d| d.src = "203.0.113.7/24".into()), "host bits");
        assert!(bad(&|d| d.src = "nope".into()));
        assert!(bad(&|d| d.ttl_s = 0));
        assert!(bad(&|d| d.ttl_s = MAX_TTL_S + 1));
        assert!(bad(&|d| d.action = "allow".into()));
        assert!(bad(&|d| d.reason = "Bad Reason".into()));
        assert!(bad(&|d| d.issuer = "Worker 2".into()));
        assert!(bad(&|d| d.id = String::new()));
        assert!(bad(&|d| d.kind = "flow".into()));
        assert!(serde_json::from_str::<Decision>(r#"{"type":"decision","extra":1}"#).is_err());
    }

    #[test]
    fn verifier_window_replay_and_keys() {
        let k = key(1);
        let now = 1762790405000;
        let mut v = Verifier::default();
        let mut d = decision();
        d.ts = now;
        d.sign(&k);
        assert_eq!(v.accept(&mut d.clone(), now), Err(Reject::UnknownIssuer));
        v.set_key("worker-2", k.verifying_key(), false);
        assert_eq!(
            v.accept(&mut d.clone(), now).unwrap().to_string(),
            "203.0.113.0/24"
        );
        assert_eq!(v.accept(&mut d.clone(), now + 1000), Err(Reject::Replay));
        // A fresh id is fine; a timestamp outside the window is not.
        let mut d2 = d.clone();
        d2.id = "other".into();
        d2.sign(&k);
        assert_eq!(
            v.accept(&mut d2.clone(), now + WINDOW_MS + 1),
            Err(Reject::Stale)
        );
        assert_eq!(
            v.accept(&mut d2.clone(), now - WINDOW_MS - 1),
            Err(Reject::Stale)
        );
        assert!(v.accept(&mut d2.clone(), now + 5000).is_ok());
        // Forged by another key.
        let mut forged = d.clone();
        forged.id = "forged".into();
        forged.sign(&key(9));
        assert_eq!(v.accept(&mut forged, now), Err(Reject::BadSignature));
        // Revocation.
        v.set_key("worker-2", k.verifying_key(), true);
        let mut d3 = d.clone();
        d3.id = "third".into();
        d3.sign(&k);
        assert_eq!(v.accept(&mut d3, now), Err(Reject::RevokedIssuer));
    }

    #[test]
    fn key_encodings() {
        let k = key(3);
        let doc = KeyDoc {
            v: 1,
            version: 1,
            issuer: "worker-1".into(),
            public_key: public_key_b64(&k),
            revoked: false,
        };
        assert_eq!(doc.verifying_key().unwrap(), k.verifying_key());
        assert_eq!(
            signing_key_from_b64(&seed_b64(&k)).unwrap().to_bytes(),
            k.to_bytes()
        );
        assert!(parse_public_key("AAAA").is_err());
        assert_eq!(KeyDoc::key_name("worker-1"), "issuer.worker-1");
    }
}
