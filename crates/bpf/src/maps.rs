// SPDX-License-Identifier: MIT OR Apache-2.0
//! Typed access to the pinned maps.

use std::ffi::CString;
use std::fs::File;
use std::io::Read;

use anyhow::{anyhow, bail, Context, Result};
use libbpf_rs::{ErrorKind, MapCore, MapFlags, MapHandle};

use sentinel_common::abi::{MapBytes, XsAsset, XsCfg, XsTenant6Key, XsTenantKey};
use sentinel_common::pin::PinLayout;
use sentinel_common::prefix::Prefix;

pub fn open(pins: &PinLayout, name: &str) -> Result<MapHandle> {
    let path = pins.map(name);
    if !path.exists() {
        bail!(
            "XDP program is not attached ({} does not exist)",
            path.display()
        );
    }
    MapHandle::from_pinned_path(&path).with_context(|| format!("opening {}", path.display()))
}

pub fn get<K: MapBytes, V: MapBytes>(m: &MapHandle, k: &K) -> Result<Option<V>> {
    match m.lookup(&k.to_bytes(), MapFlags::ANY)? {
        None => Ok(None),
        Some(b) => V::from_bytes(&b).map(Some).ok_or_else(|| {
            anyhow!(
                "{}: value has unexpected size {} (ABI mismatch)",
                name(m),
                b.len()
            )
        }),
    }
}

pub fn put<K: MapBytes, V: MapBytes>(m: &MapHandle, k: &K, v: &V) -> Result<()> {
    m.update(&k.to_bytes(), &v.to_bytes(), MapFlags::ANY)
        .with_context(|| format!("updating {}", name(m)))
}

/// Deletes a key; Ok(false) if it did not exist.
pub fn del<K: MapBytes>(m: &MapHandle, k: &K) -> Result<bool> {
    match m.delete(&k.to_bytes()) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e).with_context(|| format!("deleting from {}", name(m))),
    }
}

/// Every (key, value) pair. Entries deleted while iterating are skipped.
pub fn entries<K: MapBytes, V: MapBytes>(m: &MapHandle) -> Result<Vec<(K, V)>> {
    let mut out = Vec::new();
    for kb in m.keys() {
        let k = K::from_bytes(&kb).ok_or_else(|| {
            anyhow!(
                "{}: key has unexpected size {} (ABI mismatch)",
                name(m),
                kb.len()
            )
        })?;
        if let Some(v) = get::<K, V>(m, &k)? {
            out.push((k, v));
        }
    }
    Ok(out)
}

fn name(m: &MapHandle) -> String {
    m.name().to_string_lossy().into_owned()
}

pub const ZERO: U32Key = U32Key(0);

/// Key of the single-entry ARRAY maps.
#[derive(Clone, Copy)]
pub struct U32Key(pub u32);

impl MapBytes for U32Key {
    const SIZE: usize = 4;
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_ne_bytes().to_vec()
    }
    fn from_bytes(b: &[u8]) -> Option<Self> {
        Some(U32Key(u32::from_ne_bytes(b.try_into().ok()?)))
    }
}

/// `__u8` map value (xs_services).
pub struct U8Val(pub u8);

impl MapBytes for U8Val {
    const SIZE: usize = 1;
    fn to_bytes(&self) -> Vec<u8> {
        vec![self.0]
    }
    fn from_bytes(b: &[u8]) -> Option<Self> {
        (b.len() == 1).then(|| U8Val(b[0]))
    }
}

/// `__u64` map value (xs_verified).
pub struct U64Val(pub u64);

impl MapBytes for U64Val {
    const SIZE: usize = 8;
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_ne_bytes().to_vec()
    }
    fn from_bytes(b: &[u8]) -> Option<Self> {
        Some(U64Val(u64::from_ne_bytes(b.try_into().ok()?)))
    }
}

pub fn read_cfg(pins: &PinLayout) -> Result<XsCfg> {
    Ok(get(&open(pins, "xs_cfg")?, &ZERO)?.unwrap_or_default())
}

pub fn write_cfg(pins: &PinLayout, cfg: &XsCfg) -> Result<()> {
    put(&open(pins, "xs_cfg")?, &ZERO, cfg)
}

/// Every asset, IPv4 then IPv6, sorted by id.
pub fn assets(pins: &PinLayout) -> Result<Vec<(Prefix, XsAsset)>> {
    let mut out = Vec::new();
    for (k, a) in entries::<XsTenantKey, XsAsset>(&open(pins, "xs_tenants")?)? {
        if let Some(p) = Prefix::from_tenant_key4(&k) {
            out.push((p, a));
        }
    }
    for (k, a) in entries::<XsTenant6Key, XsAsset>(&open(pins, "xs_tenants6")?)? {
        if let Some(p) = Prefix::from_tenant_key6(&k) {
            out.push((p, a));
        }
    }
    out.sort_by_key(|(_, a)| a.asset);
    Ok(out)
}

pub fn put_asset(pins: &PinLayout, p: &Prefix, a: &XsAsset) -> Result<()> {
    match (p.tenant_key4(), p.tenant_key6()) {
        (Some(k), _) => put(&open(pins, "xs_tenants")?, &k, a),
        (None, Some(k)) => put(&open(pins, "xs_tenants6")?, &k, a),
        _ => unreachable!("a prefix is v4 or v6"),
    }
}

pub fn del_asset(pins: &PinLayout, p: &Prefix) -> Result<bool> {
    match (p.tenant_key4(), p.tenant_key6()) {
        (Some(k), _) => del(&open(pins, "xs_tenants")?, &k),
        (None, Some(k)) => del(&open(pins, "xs_tenants6")?, &k),
        _ => unreachable!("a prefix is v4 or v6"),
    }
}

/// CLOCK_BOOTTIME in nanoseconds: the clock bpf_ktime_get_boot_ns() uses.
pub fn boot_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: valid out-pointer; CLOCK_BOOTTIME always exists on Linux.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) };
    assert_eq!(rc, 0, "clock_gettime(CLOCK_BOOTTIME) failed");
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/// MTU of an interface in the current network namespace (SIOCGIFMTU; not
/// sysfs, which may belong to another namespace under nsenter).
pub fn iface_mtu(iface: &str) -> Result<u32> {
    // SAFETY: plain socket(2); closed below.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("socket for SIOCGIFMTU");
    }
    // SAFETY: zeroed ifreq is valid; the name fits (validated, <= 15 bytes).
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    for (d, s) in ifr.ifr_name.iter_mut().zip(iface.bytes()) {
        *d = s as libc::c_char;
    }
    // SAFETY: valid fd and ifreq pointer for SIOCGIFMTU.
    let rc = unsafe { libc::ioctl(fd, libc::SIOCGIFMTU as _, &mut ifr) };
    let err = std::io::Error::last_os_error();
    // SAFETY: fd is ours.
    unsafe { libc::close(fd) };
    if rc < 0 {
        return Err(err).with_context(|| format!("reading MTU of {iface}"));
    }
    // SAFETY: SIOCGIFMTU filled the ifru_mtu member of the union.
    Ok(unsafe { ifr.ifr_ifru.ifru_mtu } as u32)
}

/// A fresh, never-zero SipHash key from the kernel CSPRNG.
pub fn random_key() -> Result<[u64; 2]> {
    let mut b = [0u8; 16];
    File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut b))
        .context("reading /dev/urandom")?;
    let k = [
        u64::from_ne_bytes(b[..8].try_into().expect("8 bytes")),
        u64::from_ne_bytes(b[8..].try_into().expect("8 bytes")),
    ];
    if k == [0, 0] {
        bail!("/dev/urandom returned zeros");
    }
    Ok(k)
}

/// Interface index in the current network namespace.
pub fn ifindex(iface: &str) -> Result<u32> {
    let c = CString::new(iface)?;
    // SAFETY: c is a valid NUL-terminated string.
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    if idx == 0 {
        bail!(
            "no such interface: {iface} ({})",
            std::io::Error::last_os_error()
        );
    }
    Ok(idx)
}

/// Sum over CPUs of entry `idx` of the xs_counters PERCPU_ARRAY.
pub fn counter_sum(pins: &PinLayout, idx: u32) -> Result<u64> {
    let m = open(pins, "xs_counters")?;
    let per_cpu = m
        .lookup_percpu(&idx.to_ne_bytes(), MapFlags::ANY)?
        .unwrap_or_default();
    Ok(per_cpu
        .iter()
        .filter_map(|b| b.as_slice().try_into().ok().map(u64::from_ne_bytes))
        .sum())
}
