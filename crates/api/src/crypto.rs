// SPDX-License-Identifier: MIT OR Apache-2.0
//! Tokens, hashes and encryption of secrets at rest.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::Aes256Gcm;
use anyhow::{anyhow, bail, Result};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use sha2::{Digest, Sha256};

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).expect("OS random number generator");
    b
}

/// A random URL-safe token with 256 bits of entropy.
pub fn token() -> String {
    URL_SAFE_NO_PAD.encode(random_bytes::<32>())
}

/// Lower-case hex SHA-256: how session tokens, email tokens and API keys
/// are stored.
pub fn sha256_hex(s: &str) -> String {
    Sha256::digest(s.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Constant-time comparison.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// AES-256-GCM key for secrets at rest. Ciphertext = nonce (12) || sealed.
#[derive(Clone)]
pub struct DataKey(Aes256Gcm);

impl DataKey {
    pub fn from_base64(s: &str) -> Result<DataKey> {
        let raw = STANDARD
            .decode(s.trim())
            .map_err(|_| anyhow!("data key is not base64"))?;
        if raw.len() != 32 {
            bail!("data key must be 32 bytes (got {})", raw.len());
        }
        Ok(DataKey(
            Aes256Gcm::new_from_slice(&raw).map_err(|_| anyhow!("bad key"))?,
        ))
    }

    pub fn encrypt(&self, plain: &[u8]) -> Vec<u8> {
        let nonce = random_bytes::<12>();
        let sealed = self
            .0
            .encrypt(&nonce.into(), plain)
            .expect("AES-GCM encryption cannot fail for small inputs");
        [nonce.as_slice(), &sealed].concat()
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 12 + 16 {
            bail!("ciphertext too short");
        }
        let (nonce, sealed) = data.split_at(12);
        let nonce: [u8; 12] = nonce.try_into().expect("12 bytes");
        self.0
            .decrypt(&nonce.into(), sealed)
            .map_err(|_| anyhow!("decryption failed (wrong key or tampered data)"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_random_and_urlsafe() {
        let (a, b) = (token(), token());
        assert_ne!(a, b);
        assert_eq!(a.len(), 43);
        assert!(a
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn sha256() {
        assert_eq!(
            sha256_hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn constant_time_eq() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }

    #[test]
    fn data_key_round_trip_and_tamper() {
        let k = DataKey::from_base64(&STANDARD.encode([7u8; 32])).unwrap();
        let c = k.encrypt(b"totp secret");
        assert_eq!(k.decrypt(&c).unwrap(), b"totp secret");
        assert_ne!(k.encrypt(b"x"), k.encrypt(b"x"), "fresh nonce each time");
        let mut t = c.clone();
        *t.last_mut().unwrap() ^= 1;
        assert!(k.decrypt(&t).is_err());
        let other = DataKey::from_base64(&STANDARD.encode([8u8; 32])).unwrap();
        assert!(other.decrypt(&c).is_err());
        assert!(DataKey::from_base64("c2hvcnQ=").is_err());
    }
}
