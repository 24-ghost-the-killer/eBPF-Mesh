//! Linux implementation: libbpf-rs loader, netlink XDP attach, map access.
//!
//! Attachment uses the netlink XDP API (`bpf_xdp_attach`) with an explicit
//! mode flag rather than a `bpf_link`:
//!   * the attachment is owned by the interface, so the dataplane keeps
//!     running when this process (or, later, the agent) exits or crashes;
//!   * the mode (driver vs generic) is explicit, and a missing driver
//!     capability is an error instead of a silent generic fallback;
//!   * `XDP_FLAGS_UPDATE_IF_NOEXIST` refuses to clobber a foreign program;
//!   * `XDP_FLAGS_REPLACE` with the expected old program makes upgrade and
//!     detach compare-and-swap: they fail if someone else's program is there.
//!
//! Maps are pinned per interface so they survive program replacement and
//! userspace restarts.

use std::ffi::CString;
use std::fs;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use em_common::Stats;
use em_common::abi::STATS_SIZE;
use em_common::pin::{MAP_STATS, PROG_NAME, PinLayout};
use libbpf_rs::libbpf_sys;
use libbpf_rs::{MapCore, MapFlags, MapHandle, ObjectBuilder, PrintLevel, Program, Xdp, XdpFlags};

use crate::render::{self, Rates};
use crate::{Cli, Cmd, Mode};

/// `BPF_FS_MAGIC` from `<linux/magic.h>`.
const BPF_FS_MAGIC: i64 = 0xcafe_4a11;

pub fn run(cli: Cli) -> Result<()> {
    configure_libbpf_logging(cli.verbose);
    match cli.cmd {
        Cmd::Attach { ref iface, ref obj, mode, replace } => {
            attach(&layout(&cli, iface)?, obj, mode, replace)
        }
        Cmd::Detach { ref iface, keep_maps } => detach(&layout(&cli, iface)?, keep_maps),
        Cmd::Stats { ref iface, json, all, watch, count } => {
            stats(&layout(&cli, iface)?, json, all, watch, count)
        }
    }
}

fn configure_libbpf_logging(verbose: bool) {
    fn print(level: PrintLevel, msg: String) {
        eprint!("libbpf[{level:?}]: {msg}");
    }
    let level = if verbose { PrintLevel::Debug } else { PrintLevel::Warn };
    let _ = libbpf_rs::set_print(Some((level, print)));
}

fn layout(cli: &Cli, iface: &str) -> Result<PinLayout> {
    Ok(PinLayout::new(&cli.pin_root, iface)?)
}

fn ifindex(iface: &str) -> Result<i32> {
    let name = CString::new(iface).context("interface name contains NUL")?;
    // SAFETY: `name` is a valid NUL-terminated C string that outlives the
    // call; if_nametoindex does not retain the pointer.
    let idx = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if idx == 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("interface {iface} not found"));
    }
    i32::try_from(idx).context("ifindex out of range")
}

/// Refuse to create pins on something that is not bpffs: pins on tmpfs would
/// silently not hold anything.
fn ensure_bpffs(path: &Path) -> Result<()> {
    let mut probe = path;
    while !probe.exists() {
        probe = probe.parent().ok_or_else(|| anyhow!("no existing parent of {path:?}"))?;
    }
    let c = CString::new(probe.as_os_str().as_encoded_bytes())?;
    // SAFETY: statfs is plain old data; all-zero is a valid value.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: `c` is a valid C string and `st` a valid, writable statfs.
    if unsafe { libc::statfs(c.as_ptr(), &mut st) } != 0 {
        return Err(std::io::Error::last_os_error()).context("statfs");
    }
    #[allow(clippy::unnecessary_cast)] // f_type's integer type differs by libc target
    if st.f_type as i64 != BPF_FS_MAGIC {
        bail!(
            "{probe:?} is not on a bpffs mount; mount one with `mount -t bpf bpf /sys/fs/bpf` \
             (systemd does this by default) or pass --pin-root"
        );
    }
    Ok(())
}

/// What is attached to an interface right now, as far as we are concerned.
#[derive(Debug, PartialEq, Eq)]
enum Attached {
    Nothing,
    /// Our pinned program, in this mode.
    Ours(Mode),
    /// Something we did not attach (or that is no longer pinned by us).
    Foreign(u32),
}

fn xdp_query(ifindex: i32) -> Result<libbpf_sys::bpf_xdp_query_opts> {
    // bpf_xdp_query ignores the program fd; any valid fd works for Xdp::new.
    let devnull = fs::File::open("/dev/null")?;
    Xdp::new(devnull.as_fd()).query(ifindex, XdpFlags::NONE).context("query XDP attachment")
}

fn pinned_prog(layout: &PinLayout) -> Option<(OwnedFd, u32)> {
    let fd = Program::fd_from_pinned_path(layout.prog()).ok()?;
    let id = Program::id_from_fd(fd.as_fd()).ok()?;
    Some((fd, id))
}

fn classify(info: &libbpf_sys::bpf_xdp_query_opts, ours: Option<u32>) -> Attached {
    let ours = ours.unwrap_or(0);
    if ours != 0 && info.drv_prog_id == ours {
        return Attached::Ours(Mode::Native);
    }
    if ours != 0 && info.skb_prog_id == ours {
        return Attached::Ours(Mode::Generic);
    }
    for id in [info.prog_id, info.drv_prog_id, info.skb_prog_id, info.hw_prog_id] {
        if id != 0 {
            return Attached::Foreign(id);
        }
    }
    Attached::Nothing
}

fn mode_flags(mode: Mode) -> XdpFlags {
    match mode {
        Mode::Native => XdpFlags::DRV_MODE,
        Mode::Generic => XdpFlags::SKB_MODE,
    }
}

/// `bpf_xdp_attach`. With `expected`, the kernel only swaps if that program
/// is the one currently attached (XDP_FLAGS_REPLACE); `prog` = None detaches.
fn xdp_set(
    ifindex: i32,
    prog: Option<BorrowedFd<'_>>,
    flags: XdpFlags,
    expected: Option<BorrowedFd<'_>>,
) -> Result<()> {
    let opts = libbpf_sys::bpf_xdp_attach_opts {
        sz: size_of::<libbpf_sys::bpf_xdp_attach_opts>() as _,
        old_prog_fd: expected.map(|fd| fd.as_raw_fd()).unwrap_or(-1),
        ..Default::default()
    };
    let flags = if expected.is_some() { flags | XdpFlags::REPLACE } else { flags };
    let prog_fd = prog.map(|fd| fd.as_raw_fd()).unwrap_or(-1);
    // SAFETY: `opts` is a valid, fully initialised bpf_xdp_attach_opts that
    // outlives the call; the fds are borrowed and stay open for the call.
    let rc = unsafe { libbpf_sys::bpf_xdp_attach(ifindex, prog_fd, flags.bits(), &opts) };
    if rc < 0 { Err(std::io::Error::from_raw_os_error(-rc).into()) } else { Ok(()) }
}

fn attach(layout: &PinLayout, obj_path: &Path, mode: Mode, replace: bool) -> Result<()> {
    let ifindex = ifindex(layout.iface())?;
    let pinned = pinned_prog(layout);
    let state = classify(&xdp_query(ifindex)?, pinned.as_ref().map(|p| p.1));
    match (&state, replace) {
        (Attached::Nothing, _) => {}
        (Attached::Ours(_), false) => bail!(
            "{} already runs eBPF Mesh; use --replace to upgrade it atomically",
            layout.iface()
        ),
        (Attached::Ours(cur), true) if *cur != mode => bail!(
            "{} runs eBPF Mesh in {cur:?} mode; detach first to switch to {mode:?} mode",
            layout.iface()
        ),
        (Attached::Ours(_), true) => {}
        (Attached::Foreign(id), _) => bail!(
            "{} already has XDP program id {id}, which is not the eBPF Mesh program pinned in \
             {:?}; refusing to replace it",
            layout.iface(),
            layout.dir()
        ),
    }

    ensure_bpffs(layout.dir())?;
    let fresh_dir = !layout.dir().exists();
    fs::create_dir_all(layout.dir())
        .with_context(|| format!("create pin directory {:?}", layout.dir()))?;

    let result = load_and_attach(layout, obj_path, ifindex, mode, pinned.as_ref().map(|p| &p.0));
    if result.is_err() && fresh_dir {
        // Nothing was attached before and nothing is now: drop the pins this
        // attempt created so a retry starts clean.
        let _ = remove_pins(layout);
    }
    let id = result?;
    println!(
        "attached {PROG_NAME} (prog id {id}) to {} in {mode:?} mode{}; pins in {:?}",
        layout.iface(),
        if replace && state != Attached::Nothing { " (replaced)" } else { "" },
        layout.dir()
    );
    Ok(())
}

fn load_and_attach(
    layout: &PinLayout,
    obj_path: &Path,
    ifindex: i32,
    mode: Mode,
    old: Option<&OwnedFd>,
) -> Result<u32> {
    let mut open = ObjectBuilder::default()
        .open_file(obj_path)
        .with_context(|| format!("open BPF object {obj_path:?}"))?;
    for mut map in open.maps_mut() {
        let name = map.name().to_string_lossy().into_owned();
        // .rodata/.bss/.data style internal maps are per-object, never pinned.
        if name.contains('.') {
            continue;
        }
        map.set_pin_path(layout.map(&name))?;
    }
    // Existing pins with the same definition are reused (counters survive an
    // upgrade); a pin whose key/value size changed makes the load fail.
    let obj = open.load().with_context(|| {
        format!(
            "load {obj_path:?} (verifier rejection, or incompatible pinned maps in {:?}: \
             `meshctl detach -i {}` removes stale pins; -v shows the verifier log)",
            layout.dir(),
            layout.iface()
        )
    })?;
    let mut prog = obj
        .progs_mut()
        .find(|p| p.name() == PROG_NAME)
        .ok_or_else(|| anyhow!("object has no program {PROG_NAME}"))?;

    match old {
        Some(old) => xdp_set(ifindex, Some(prog.as_fd()), mode_flags(mode), Some(old.as_fd()))
            .context("atomic program replace (did someone else change the attachment?)")?,
        None => xdp_set(
            ifindex,
            Some(prog.as_fd()),
            mode_flags(mode) | XdpFlags::UPDATE_IF_NOEXIST,
            None,
        )
        .with_context(|| {
            format!(
                "attach to {} in {mode:?} mode{}",
                layout.iface(),
                if mode == Mode::Native {
                    " (driver may lack native XDP, or the MTU is too large for single-buffer XDP)"
                } else {
                    ""
                }
            )
        })?,
    }

    // Swap the program pin atomically: pin under a temporary name, then
    // rename over the old pin, so there is never a moment without one.
    // bpffs rejects names containing '.' (EPERM, reserved by the kernel).
    let tmp = layout.dir().join(format!("{PROG_NAME}_new"));
    remove_pin(&tmp)?;
    prog.pin(&tmp).with_context(|| format!("pin program at {tmp:?}"))?;
    fs::rename(&tmp, layout.prog())
        .with_context(|| format!("rename pin to {:?}", layout.prog()))?;
    Ok(Program::id_from_fd(prog.as_fd())?)
}

fn detach(layout: &PinLayout, keep_maps: bool) -> Result<()> {
    let ifindex = ifindex(layout.iface())?;
    let pinned = pinned_prog(layout);
    match classify(&xdp_query(ifindex)?, pinned.as_ref().map(|p| p.1)) {
        Attached::Foreign(id) => bail!(
            "XDP program id {id} on {} is not the eBPF Mesh program pinned in {:?}; refusing \
             to detach it",
            layout.iface(),
            layout.dir()
        ),
        Attached::Ours(mode) => {
            let (fd, id) = pinned.as_ref().expect("Ours implies a pinned program");
            xdp_set(ifindex, None, mode_flags(mode), Some(fd.as_fd()))
                .context("detach XDP program")?;
            println!("detached program id {id} ({mode:?} mode) from {}", layout.iface());
        }
        Attached::Nothing => println!("no XDP program attached to {}", layout.iface()),
    }
    remove_pin(&layout.prog())?;
    if !keep_maps {
        remove_pins(layout)?;
    }
    Ok(())
}

fn remove_pin(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("remove {path:?}")),
    }
}

/// Remove every pin in the interface directory, then the directory. attach
/// pins every map in the object, so this removes the directory's contents
/// rather than a fixed list that would drift as maps are added.
fn remove_pins(layout: &PinLayout) -> Result<()> {
    if let Ok(entries) = fs::read_dir(layout.dir()) {
        for entry in entries {
            remove_pin(&entry?.path())?;
        }
    }
    match fs::remove_dir(layout.dir()) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("remove {:?}", layout.dir())),
    }
}

fn open_stats(layout: &PinLayout) -> Result<MapHandle> {
    let path = layout.map(MAP_STATS);
    let map = MapHandle::from_pinned_path(&path)
        .with_context(|| format!("open {path:?} (is the program attached?)"))?;
    if map.value_size() as usize != STATS_SIZE {
        bail!("{path:?}: value size {} != {STATS_SIZE}: ABI mismatch", map.value_size());
    }
    Ok(map)
}

fn read_stats(map: &MapHandle) -> Result<Stats> {
    let vals = map
        .lookup_percpu(&0u32.to_ne_bytes(), MapFlags::ANY)?
        .ok_or_else(|| anyhow!("{MAP_STATS} has no element 0"))?;
    Ok(Stats::sum_percpu(&vals)?)
}

fn unix_ms() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0)
}

fn stats(
    layout: &PinLayout,
    json: bool,
    all: bool,
    watch: Option<f64>,
    count: Option<u64>,
) -> Result<()> {
    let map = open_stats(layout)?;
    let print = |snap: &Stats, rates: Option<Rates<'_>>| {
        if json {
            println!("{}", render::json(layout.iface(), snap, rates, unix_ms()));
        } else {
            print!("{}", render::table(layout.iface(), snap, rates, all));
        }
    };
    let Some(interval) = watch else {
        print(&read_stats(&map)?, None);
        return Ok(());
    };
    if !(interval.is_finite() && interval > 0.0) {
        bail!("--watch must be a positive number of seconds");
    }
    let mut prev = read_stats(&map)?;
    let mut t_prev = Instant::now();
    let mut n = 0u64;
    loop {
        thread::sleep(Duration::from_secs_f64(interval));
        let cur = read_stats(&map)?;
        let now = Instant::now();
        let delta = cur.delta(&prev);
        print(&cur, Some(Rates { delta: &delta, secs: now.duration_since(t_prev).as_secs_f64() }));
        prev = cur;
        t_prev = now;
        n += 1;
        if count.is_some_and(|c| n >= c) {
            return Ok(());
        }
    }
}
