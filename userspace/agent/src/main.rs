//! `mesh-agent`: the long-running per-PoP agent.
//!
//! Phase 0 is a stub: it loads and validates its configuration and reports
//! what it would manage. Owning the dataplane (attach, map writes, TTL'd
//! mitigations) arrives in Phase 1; ring-buffer sampling and NATS publishing
//! in Phase 5 (docs/architecture.md).

mod config;

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "mesh-agent", version, about = "eBPF Mesh PoP agent (Phase 0 stub)")]
struct Cli {
    /// Agent configuration file (TOML).
    #[arg(short, long, default_value = "/etc/ebpf-mesh/agent.toml")]
    config: PathBuf,
}

fn main() {
    if let Err(e) = run(Cli::parse()) {
        eprintln!("mesh-agent: {e:#}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> anyhow::Result<()> {
    let text =
        std::fs::read_to_string(&cli.config).with_context(|| format!("read {:?}", cli.config))?;
    let cfg =
        config::Config::from_toml(&text).with_context(|| format!("parse {:?}", cli.config))?;
    println!("config {:?} OK", cli.config);
    println!("  pin_root: {:?}", cfg.pin_root);
    println!("  bpf_obj:  {:?}", cfg.bpf_obj);
    for i in &cfg.interfaces {
        println!("  interface {} (xdp_mode {:?})", i.name, i.xdp_mode);
    }
    println!("phase 0: no dataplane management yet; use `meshctl attach` (docs/running.md)");
    Ok(())
}
