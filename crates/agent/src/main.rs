// SPDX-License-Identifier: MIT OR Apache-2.0
//! `sentinel-agent`: the PoP agent (spec section 6).
//!
//! - attaches the XDP program (native) and detaches it on clean shutdown
//! - applies the NATS KV buckets (tenants, services, rules, platform) to the
//!   BPF maps and acknowledges every change on config.ack.<pop>
//! - publishes stats.<pop> (per second), telemetry.<pop>.<shard> (sampled
//!   flows) and health.<pop>; writes the heartbeat file; serves Prometheus
//! - garbage-collects expired map entries and adapts the sampling rate

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

// Used by the Linux-only `linux` module; on other systems only the config
// check and the tests use them.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod config;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod metrics;

#[cfg(target_os = "linux")]
mod linux;

#[derive(Parser, Debug)]
#[command(name = "sentinel-agent", version, about = "Sentinel-Edge PoP agent")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Run the agent.
    Run {
        #[arg(long, env = "SENTINEL_AGENT_CONFIG")]
        config: PathBuf,
        /// Leave XDP attached on shutdown (for upgrades; the next agent
        /// adopts the attachment).
        #[arg(long)]
        keep_attached: bool,
    },
    /// Validate a config file and exit.
    CheckConfig {
        #[arg(long, env = "SENTINEL_AGENT_CONFIG")]
        config: PathBuf,
    },
    /// NATS nkey management.
    #[command(subcommand)]
    Nkey(NkeyCmd),
}

#[derive(Subcommand, Debug)]
enum NkeyCmd {
    /// Create a user nkey: writes the seed (secret, mode 0600) and prints
    /// the public key for the NATS server config.
    Generate {
        #[arg(long)]
        out: PathBuf,
    },
}

fn nkey_generate(out: &PathBuf) -> Result<()> {
    use std::io::Write;
    let kp = nkeys::KeyPair::new_user();
    let seed = kp.seed().context("encoding nkey seed")?;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(out)
        .with_context(|| format!("creating {} (refusing to overwrite)", out.display()))?;
    writeln!(f, "{seed}")?;
    println!("{}", kp.public_key());
    Ok(())
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_target(false)
        .init();
    let cli = Cli::parse();
    let res = match cli.cmd {
        Cmd::CheckConfig { config } => config::Config::load(&config).map(|c| {
            println!("{}: ok (PoP {})", config.display(), c.pop.id);
        }),
        Cmd::Nkey(NkeyCmd::Generate { out }) => nkey_generate(&out),
        Cmd::Run {
            config,
            keep_attached,
        } => run(&config, keep_attached),
    };
    if let Err(e) = res {
        eprintln!("sentinel-agent: {e:#}");
        std::process::exit(1);
    }
}

#[cfg(target_os = "linux")]
fn run(config: &std::path::Path, keep_attached: bool) -> Result<()> {
    let cfg = config::Config::load(config)?;
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting tokio")?
        .block_on(linux::run(cfg, keep_attached))
}

#[cfg(not(target_os = "linux"))]
fn run(config: &std::path::Path, _keep_attached: bool) -> Result<()> {
    config::Config::load(config)?;
    anyhow::bail!("the agent needs Linux (XDP); `check-config` works everywhere")
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
    fn nkey_generate_writes_seed_once() {
        let dir = std::env::temp_dir().join(format!("sentinel-nkey-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("pop.nk");
        let _ = std::fs::remove_file(&out);
        nkey_generate(&out).unwrap();
        let seed = std::fs::read_to_string(&out).unwrap();
        assert!(seed.starts_with("SU"), "user seed: {seed}");
        assert!(nkey_generate(&out).is_err(), "must not overwrite a seed");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&out).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        std::fs::remove_file(&out).unwrap();
    }
}
