// SPDX-License-Identifier: MIT OR Apache-2.0
//! `sentinelctl`: operator CLI for a Sentinel-Edge PoP.
//!
//! Phase 1 commands: attach / detach the XDP program, read counters, toggle
//! the global observe flag.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};

use sentinel_common::pin::{PinLayout, DEFAULT_PIN_DIR, ENV_PIN_DIR};

#[cfg(target_os = "linux")]
mod linux;

#[derive(Parser, Debug)]
#[command(name = "sentinelctl", version, about = "Sentinel-Edge operator CLI")]
struct Cli {
    /// bpffs directory holding the pinned maps and links.
    #[arg(long, global = true, env = ENV_PIN_DIR, default_value = DEFAULT_PIN_DIR)]
    pin_dir: PathBuf,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum Mode {
    /// Driver (native) XDP. Required for production.
    Native,
    /// Generic (skb) XDP. Slow; only with --allow-generic.
    Generic,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Load the XDP program and attach it to an interface.
    Attach {
        /// Interface to attach to.
        #[arg(long, env = "XS_IFACE")]
        iface: String,
        /// Compiled XDP object.
        #[arg(
            long,
            env = "SENTINEL_BPF_OBJ",
            default_value = "build/ebpf/xdp_main.o"
        )]
        obj: PathBuf,
        #[arg(long, value_enum, default_value_t = Mode::Native)]
        mode: Mode,
        /// Permit generic (skb) mode. Never use this on a production PoP.
        #[arg(long)]
        allow_generic: bool,
    },
    /// Detach the XDP program from an interface.
    Detach {
        #[arg(long, env = "XS_IFACE")]
        iface: String,
    },
    /// Show per-(tenant, verdict) packet and byte counters.
    Stats {
        /// Machine-readable output.
        #[arg(long)]
        json: bool,
        /// Refresh every --interval seconds until interrupted.
        #[arg(long)]
        watch: bool,
        #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u64).range(1..))]
        interval: u64,
    },
    /// Set the global observe flag: count verdicts but never drop.
    Observe {
        #[arg(value_enum)]
        state: OnOff,
    },
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum OnOff {
    On,
    Off,
}

/// Rejects generic mode unless explicitly allowed (spec: native only).
fn check_mode(mode: Mode, allow_generic: bool) -> Result<()> {
    if mode == Mode::Generic && !allow_generic {
        anyhow::bail!(
            "generic XDP mode is refused: it is slow and not suitable for a PoP; \
             pass --allow-generic if you really mean it (tests/labs only)"
        );
    }
    Ok(())
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        eprintln!("sentinelctl: {e:#}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    let pins = PinLayout::new(&cli.pin_dir);
    match cli.cmd {
        Cmd::Attach {
            iface,
            obj,
            mode,
            allow_generic,
        } => {
            check_mode(mode, allow_generic)?;
            sentinel_common::pin::validate_ifname(&iface)?;
            platform::attach(&pins, &iface, &obj, mode)
        }
        Cmd::Detach { iface } => {
            sentinel_common::pin::validate_ifname(&iface)?;
            platform::detach(&pins, &iface)
        }
        Cmd::Stats {
            json,
            watch,
            interval,
        } => loop {
            let snap = platform::read_stats(&pins)?;
            if json {
                println!("{}", serde_json::to_string(&snap)?);
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
        },
        Cmd::Observe { state } => platform::set_observe(&pins, state == OnOff::On),
    }
}

#[cfg(target_os = "linux")]
use linux as platform;

/// Non-Linux builds compile (so `cargo test` works on a Mac) but cannot act.
#[cfg(not(target_os = "linux"))]
mod platform {
    use super::Mode;
    use anyhow::{bail, Result};
    use sentinel_common::{pin::PinLayout, stats::Snapshot};
    use std::path::Path;

    const MSG: &str = "this command needs Linux (run it on a PoP or via `make docker-shell`)";

    pub fn attach(_: &PinLayout, _: &str, _: &Path, _: Mode) -> Result<()> {
        bail!(MSG)
    }
    pub fn detach(_: &PinLayout, _: &str) -> Result<()> {
        bail!(MSG)
    }
    pub fn read_stats(_: &PinLayout) -> Result<Snapshot> {
        bail!(MSG)
    }
    pub fn set_observe(_: &PinLayout, _: bool) -> Result<()> {
        bail!(MSG)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn generic_needs_flag() {
        assert!(check_mode(Mode::Native, false).is_ok());
        assert!(check_mode(Mode::Generic, false).is_err());
        assert!(check_mode(Mode::Generic, true).is_ok());
    }

    #[test]
    fn parses_attach() {
        let cli = Cli::try_parse_from([
            "sentinelctl",
            "--pin-dir",
            "/sys/fs/bpf/x",
            "attach",
            "--iface",
            "eth0",
            "--mode",
            "generic",
            "--allow-generic",
        ])
        .unwrap();
        assert_eq!(cli.pin_dir, PathBuf::from("/sys/fs/bpf/x"));
        match cli.cmd {
            Cmd::Attach {
                iface,
                mode,
                allow_generic,
                ..
            } => {
                assert_eq!(iface, "eth0");
                assert_eq!(mode, Mode::Generic);
                assert!(allow_generic);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn rejects_zero_interval() {
        assert!(Cli::try_parse_from(["sentinelctl", "stats", "--interval", "0"]).is_err());
    }
}
