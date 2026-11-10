//! `meshctl`: load/attach/detach the eBPF Mesh XDP program and read its
//! counters.
//!
//! Phase 0 scope: `attach`, `detach`, `stats`. Everything site-specific
//! (interface, object path, pin root) is a flag; nothing is hardcoded.

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

#[cfg(target_os = "linux")]
mod linux;
// Only the Linux backend renders output; elsewhere the module is test-only.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod render;

/// Default install location of the XDP object (overridable with --obj).
const DEFAULT_OBJ: &str = "/usr/lib/ebpf-mesh/em_xdp.bpf.o";

#[derive(Debug, Parser)]
#[command(name = "meshctl", version, about = "eBPF Mesh dataplane control")]
pub struct Cli {
    /// bpffs directory under which per-interface pins are kept.
    #[arg(long, global = true, default_value = em_common::pin::DEFAULT_PIN_ROOT)]
    pub pin_root: PathBuf,
    /// Print libbpf debug output (including the verifier log on failure).
    #[arg(short, long, global = true)]
    pub verbose: bool,
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Debug, Subcommand)]
pub enum Cmd {
    /// Load the XDP object, pin its maps and attach it to an interface.
    Attach {
        #[arg(short, long)]
        iface: String,
        /// Compiled XDP object.
        #[arg(long, default_value = DEFAULT_OBJ)]
        obj: PathBuf,
        /// XDP attach mode. There is deliberately no "auto": a silent fallback
        /// to generic mode runs XDP after skb allocation and loses most of its
        /// performance, so a missing driver capability must be an error.
        #[arg(long, value_enum, default_value_t = Mode::Native)]
        mode: Mode,
        /// Atomically replace an already attached eBPF Mesh program (upgrade
        /// without a window where no program is attached). Pinned maps and
        /// therefore counters are kept.
        #[arg(long)]
        replace: bool,
    },
    /// Detach the eBPF Mesh program. Refuses to touch a program it did not
    /// attach.
    Detach {
        #[arg(short, long)]
        iface: String,
        /// Keep the pinned maps (counters) for a later attach.
        #[arg(long)]
        keep_maps: bool,
    },
    /// Show dataplane counters.
    Stats {
        #[arg(short, long)]
        iface: String,
        /// Machine-readable output (one JSON object per sample).
        #[arg(long)]
        json: bool,
        /// Also show counters that are zero (table output).
        #[arg(long)]
        all: bool,
        /// Sample every SECS seconds and show rates.
        #[arg(long, value_name = "SECS")]
        watch: Option<f64>,
        /// Stop after N samples (with --watch).
        #[arg(long, value_name = "N", requires = "watch")]
        count: Option<u64>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Mode {
    /// Driver (native) XDP.
    Native,
    /// Generic (skb) XDP: for testing on NICs without native support.
    Generic,
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        eprintln!("meshctl: {e:#}");
        std::process::exit(1);
    }
}

#[cfg(target_os = "linux")]
fn run(cli: Cli) -> anyhow::Result<()> {
    linux::run(cli)
}

#[cfg(not(target_os = "linux"))]
fn run(_cli: Cli) -> anyhow::Result<()> {
    anyhow::bail!("meshctl manages XDP programs and only runs on Linux")
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_attach_defaults() {
        let c = Cli::try_parse_from(["meshctl", "attach", "-i", "eth1"]).unwrap();
        assert_eq!(c.pin_root, PathBuf::from(em_common::pin::DEFAULT_PIN_ROOT));
        match c.cmd {
            Cmd::Attach { iface, obj, mode, replace } => {
                assert_eq!(iface, "eth1");
                assert_eq!(obj, PathBuf::from(DEFAULT_OBJ));
                assert_eq!(mode, Mode::Native);
                assert!(!replace);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn parses_global_flags_and_generic_mode() {
        let c = Cli::try_parse_from([
            "meshctl",
            "attach",
            "-i",
            "veth0",
            "--mode",
            "generic",
            "--replace",
            "--obj",
            "/x.o",
            "--pin-root",
            "/sys/fs/bpf/t",
        ])
        .unwrap();
        assert_eq!(c.pin_root, PathBuf::from("/sys/fs/bpf/t"));
        assert!(matches!(c.cmd, Cmd::Attach { mode: Mode::Generic, replace: true, .. }));
    }

    #[test]
    fn rejects_auto_mode_and_count_without_watch() {
        assert!(Cli::try_parse_from(["meshctl", "attach", "-i", "e", "--mode", "auto"]).is_err());
        assert!(Cli::try_parse_from(["meshctl", "stats", "-i", "e", "--count", "3"]).is_err());
        assert!(
            Cli::try_parse_from(["meshctl", "stats", "-i", "e", "--watch", "1", "--count", "3"])
                .is_ok()
        );
    }

    #[test]
    fn interface_is_required() {
        assert!(Cli::try_parse_from(["meshctl", "detach"]).is_err());
        assert!(Cli::try_parse_from(["meshctl", "stats"]).is_err());
    }
}
