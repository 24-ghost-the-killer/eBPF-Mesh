// SPDX-License-Identifier: MIT OR Apache-2.0
//! Attach/detach: libbpf-rs loads the object, a pinned `bpf_link` per
//! interface holds the attachment.
//!
//! Why a pinned bpf_link (not a netlink attach): the link keeps the program
//! attached after this process exits, cannot be silently replaced by another
//! tool, and is removed atomically by `detach`.

use std::ffi::CString;
use std::fs;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use libbpf_rs::query::LinkTypeInfo;
use libbpf_rs::{Link, ObjectBuilder};

use sentinel_common::pin::PinLayout;

use crate::maps::{self, ifindex};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XdpMode {
    /// Driver (native) XDP.
    Native,
    /// Generic (skb) XDP: tests only.
    Generic,
}

pub struct AttachOpts<'a> {
    pub iface: &'a str,
    pub obj: &'a Path,
    pub mode: XdpMode,
    pub pop_ip4: Option<Ipv4Addr>,
    pub pop_ip6: Option<Ipv6Addr>,
}

#[derive(Debug)]
pub struct Attached {
    pub ifindex: u32,
    pub mtu: u32,
    /// Problems worth telling the operator about (attach still succeeded).
    pub warnings: Vec<String>,
}

#[derive(Debug)]
pub struct Detached {
    /// The pinned maps were removed (no interface uses them any more).
    pub maps_removed: bool,
    pub warnings: Vec<String>,
}

pub const PROG_NAME: &str = "xs_xdp";
const MAP_PREFIX: &str = "xs_";
const BPF_FS_MAGIC: i64 = 0xcafe_4a11;

pub fn attach(pins: &PinLayout, opts: &AttachOpts) -> Result<Attached> {
    let (iface, obj, mode) = (opts.iface, opts.obj, opts.mode);
    let link_pin = pins.xdp_link(iface)?;
    ensure_pin_dir(pins)?;
    if link_pin.exists() {
        bail!(
            "already attached to {iface} ({}); detach first",
            link_pin.display()
        );
    }
    let ifindex = ifindex(iface)?;

    let result = load_and_link(pins, ifindex, iface, obj, mode, &link_pin)
        .and_then(|_| init_cfg(pins, opts));
    if result.is_err() {
        // Roll back completely: no half-configured program, no orphan pins.
        if link_pin.exists() {
            if let Ok(link) = Link::open(&link_pin) {
                let _ = link.detach();
            }
            let _ = fs::remove_file(&link_pin);
        }
        let _ = cleanup_if_unused(pins);
    }
    let (mtu, warnings) = result?;
    Ok(Attached {
        ifindex,
        mtu,
        warnings,
    })
}

/// Sets the PoP addresses if given, the uplink MTU, and a SYN-cookie key if
/// the (possibly reused) config has none yet.
fn init_cfg(pins: &PinLayout, opts: &AttachOpts) -> Result<(u32, Vec<String>)> {
    let mut cfg = maps::read_cfg(pins)?;
    let mut warnings = Vec::new();
    if let Some(ip) = opts.pop_ip4 {
        cfg.pop_ip4 = ip.octets();
    }
    if let Some(ip) = opts.pop_ip6 {
        cfg.pop_ip6 = ip.octets();
    }
    if cfg.cookie_key == [0, 0] {
        cfg.cookie_key = maps::random_key()?;
    }
    // Tunnelled packets must fit this interface (ADR 0012).
    let mtu = maps::iface_mtu(opts.iface)?;
    cfg.uplink_mtu = u16::try_from(mtu).unwrap_or(u16::MAX);
    if cfg.pop_ip4().is_none() {
        warnings.push(
            "no PoP IPv4 configured; protected traffic cannot be tunnelled \
             and is dropped as drop_tunnel"
                .into(),
        );
    }
    maps::write_cfg(pins, &cfg)?;
    Ok((mtu, warnings))
}

/// True if the pinned link exists and still holds this interface (the kernel
/// releases it when the interface disappears).
pub fn is_attached(pins: &PinLayout, iface: &str) -> bool {
    let (Ok(path), Ok(idx)) = (pins.xdp_link(iface), ifindex(iface)) else {
        return false;
    };
    let Ok(link) = Link::open(&path) else {
        return false;
    };
    matches!(link.info().map(|i| i.info), Ok(LinkTypeInfo::Xdp(x)) if x.ifindex == idx)
}

fn load_and_link(
    pins: &PinLayout,
    ifindex: u32,
    iface: &str,
    obj: &Path,
    mode: XdpMode,
    link_pin: &Path,
) -> Result<()> {
    let mut open = ObjectBuilder::default()
        .open_file(obj)
        .with_context(|| format!("opening BPF object {}", obj.display()))?;
    for mut map in open.maps_mut() {
        let name = map.name().to_string_lossy().into_owned();
        if name.starts_with(MAP_PREFIX) {
            // libbpf reuses an existing compatible pin, otherwise creates it.
            map.set_pin_path(pins.map(&name))
                .with_context(|| format!("setting pin path for {name}"))?;
        }
    }
    let loaded = open.load().with_context(|| {
        format!(
            "loading {} (if pinned maps from an incompatible build exist, \
             detach every interface to clear {})",
            obj.display(),
            pins.root().display()
        )
    })?;
    let prog = loaded
        .progs()
        .find(|p| p.name().as_bytes() == PROG_NAME.as_bytes())
        .ok_or_else(|| anyhow!("program {PROG_NAME} not found in {}", obj.display()))?;

    let flags = match mode {
        XdpMode::Native => libbpf_sys::XDP_FLAGS_DRV_MODE,
        XdpMode::Generic => libbpf_sys::XDP_FLAGS_SKB_MODE,
    };
    let opts = libbpf_sys::bpf_link_create_opts {
        sz: std::mem::size_of::<libbpf_sys::bpf_link_create_opts>() as _,
        flags,
        ..Default::default()
    };
    // SAFETY: prog fd is valid for the lifetime of `loaded`; opts is a fully
    // initialised struct with the correct `sz`; ifindex is a plain integer.
    let fd = unsafe {
        libbpf_sys::bpf_link_create(
            std::os::fd::AsFd::as_fd(&prog).as_raw_fd(),
            ifindex as i32,
            libbpf_sys::BPF_XDP,
            &opts,
        )
    };
    if fd < 0 {
        let err = io::Error::from_raw_os_error(-fd);
        return Err(match err.raw_os_error() {
            Some(libc::EOPNOTSUPP) | Some(libc::EINVAL) if mode == XdpMode::Native => anyhow!(
                "{iface}: driver does not support native XDP ({err}); generic mode is \
                 only for tests: --mode generic --allow-generic"
            ),
            Some(libc::EBUSY) | Some(libc::EEXIST) => anyhow!(
                "{iface}: another XDP program is already attached ({err}); \
                 check `ip link show dev {iface}`"
            ),
            _ => anyhow!("{iface}: creating XDP link failed: {err}"),
        });
    }
    // SAFETY: fd was just returned by bpf_link_create and is owned by us.
    let link_fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let path_c = CString::new(link_pin.as_os_str().as_bytes())?;
    // SAFETY: valid fd and NUL-terminated path.
    let rc = unsafe { libbpf_sys::bpf_obj_pin(link_fd.as_raw_fd(), path_c.as_ptr()) };
    if rc < 0 {
        // Dropping link_fd destroys the unpinned link, detaching the program.
        bail!(
            "pinning link at {}: {}",
            link_pin.display(),
            io::Error::from_raw_os_error(-rc)
        );
    }
    Ok(())
}

pub fn detach(pins: &PinLayout, iface: &str) -> Result<Detached> {
    let link_pin = pins.xdp_link(iface)?;
    if !link_pin.exists() {
        bail!(
            "not attached to {iface} (no {}); nothing to detach",
            link_pin.display()
        );
    }
    let mut warnings = Vec::new();
    let link = Link::open(&link_pin).with_context(|| format!("opening {}", link_pin.display()))?;
    // If the interface is gone the kernel already detached the link; the
    // pin still has to go, so a detach error is only a warning.
    if let Err(e) = link.detach() {
        warnings.push(format!("detaching link on {iface}: {e}"));
    }
    drop(link);
    fs::remove_file(&link_pin).with_context(|| format!("removing {}", link_pin.display()))?;
    let maps_removed = cleanup_if_unused(pins)?;
    Ok(Detached {
        maps_removed,
        warnings,
    })
}

/// Creates the pin directory and checks that it lives on bpffs.
fn ensure_pin_dir(pins: &PinLayout) -> Result<()> {
    let root = pins.root();
    fs::create_dir_all(root).with_context(|| format!("creating {}", root.display()))?;
    let c = CString::new(root.as_os_str().as_bytes())?;
    // SAFETY: zeroed statfs is a valid out-parameter; c is NUL-terminated.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(c.as_ptr(), &mut st) } != 0 {
        return Err(io::Error::last_os_error()).context(format!("statfs {}", root.display()));
    }
    // f_type is i64 on most 64-bit targets but not all; keep the cast.
    #[allow(clippy::unnecessary_cast)]
    let f_type = st.f_type as i64;
    if f_type != BPF_FS_MAGIC {
        bail!(
            "{} is not on bpffs; mount it with `mount -t bpf bpf /sys/fs/bpf`",
            root.display()
        );
    }
    Ok(())
}

/// Removes map pins and the pin directory when no interface uses them.
/// Returns true if anything was removed.
fn cleanup_if_unused(pins: &PinLayout) -> Result<bool> {
    let root = pins.root();
    let Ok(entries) = fs::read_dir(root) else {
        return Ok(false);
    };
    let names: Vec<String> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    if names.iter().any(|n| PinLayout::ifname_of_link(n).is_some()) {
        return Ok(false);
    }
    let mut removed = false;
    for n in names.iter().filter(|n| n.starts_with(MAP_PREFIX)) {
        fs::remove_file(root.join(n)).with_context(|| format!("removing pin {n}"))?;
        removed = true;
    }
    // Only succeeds if empty, which is what we want.
    let _ = fs::remove_dir(root);
    Ok(removed)
}
