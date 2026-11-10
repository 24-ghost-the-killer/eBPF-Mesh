//! `mesh-worker`: distributed analysis worker.
//!
//! Phase 0 is a stub: it loads and validates its configuration. Consuming
//! partitioned flow records from NATS and running the detector arrive in
//! Phase 5; signed decisions in Phase 6 (docs/architecture.md).

mod config;

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "mesh-worker", version, about = "eBPF Mesh analysis worker (Phase 0 stub)")]
struct Cli {
    /// Worker configuration file (TOML).
    #[arg(short, long, default_value = "/etc/ebpf-mesh/worker.toml")]
    config: PathBuf,
}

fn main() {
    if let Err(e) = run(Cli::parse()) {
        eprintln!("mesh-worker: {e:#}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> anyhow::Result<()> {
    let text =
        std::fs::read_to_string(&cli.config).with_context(|| format!("read {:?}", cli.config))?;
    let cfg =
        config::Config::from_toml(&text).with_context(|| format!("parse {:?}", cli.config))?;
    println!("config {:?} OK: worker {} (nats {})", cli.config, cfg.worker_id, cfg.nats_url);
    println!("phase 0: analysis pipeline not implemented yet (Phase 5)");
    Ok(())
}
