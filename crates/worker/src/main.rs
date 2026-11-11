// SPDX-License-Identifier: MIT OR Apache-2.0
//! `sentinel-worker`: attack detection and signed mitigation decisions
//! (spec section 8, ADR 0021).

mod config;
mod detect;
mod run;

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use sentinel_common::decision::{public_key_b64, seed_b64, signing_key_from_b64};

#[derive(Parser)]
#[command(
    name = "sentinel-worker",
    version,
    about = "Sentinel-Edge analysis worker"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the worker.
    Run {
        #[arg(long, env = "SENTINEL_WORKER_CONFIG")]
        config: PathBuf,
    },
    /// Validate the configuration and the signing key; print the public key.
    CheckConfig {
        #[arg(long, env = "SENTINEL_WORKER_CONFIG")]
        config: PathBuf,
    },
    /// Ed25519 signing keys for decisions.
    Key {
        #[command(subcommand)]
        cmd: KeyCmd,
    },
    /// NATS nkey for this worker's NATS user.
    Nkey {
        #[command(subcommand)]
        cmd: KeyCmd,
    },
    /// Print a signed block decision (JSON) for `nats pub decision.global`:
    /// for operators without the portal, and for tests.
    Sign {
        /// File with the base64 signing seed.
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        issuer: String,
        /// 0 = global.
        #[arg(long)]
        tenant: u32,
        #[arg(long)]
        src: String,
        #[arg(long, default_value_t = 300)]
        ttl: u32,
        #[arg(long, default_value = "manual")]
        reason: String,
        /// Unix ms (default: now).
        #[arg(long)]
        ts: Option<u64>,
        /// Decision id (default: a new UUIDv7).
        #[arg(long)]
        id: Option<String>,
    },
}

#[derive(Subcommand)]
enum KeyCmd {
    /// Write a new secret seed (mode 0600, never overwrites) and print the
    /// public key to register (`sentinel-api signing-key add`).
    Generate {
        #[arg(long)]
        out: PathBuf,
    },
}

fn write_secret(out: &Path, content: &str) -> Result<()> {
    use std::io::Write;
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
    writeln!(f, "{content}")?;
    Ok(())
}

fn load_key(path: &Path) -> Result<ed25519_dalek::SigningKey> {
    let s = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    signing_key_from_b64(&s).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_target(false)
        .init();
    if let Err(e) = real_main() {
        eprintln!("sentinel-worker: {e:#}");
        std::process::exit(1);
    }
}

fn real_main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Key {
            cmd: KeyCmd::Generate { out },
        } => {
            let mut seed = [0u8; 32];
            getrandom::fill(&mut seed).map_err(|e| anyhow::anyhow!("random: {e}"))?;
            let key = ed25519_dalek::SigningKey::from_bytes(&seed);
            write_secret(&out, &seed_b64(&key))?;
            println!("{}", public_key_b64(&key));
            Ok(())
        }
        Cmd::Nkey {
            cmd: KeyCmd::Generate { out },
        } => {
            let kp = nkeys::KeyPair::new_user();
            write_secret(&out, &kp.seed().context("encoding nkey seed")?)?;
            println!("{}", kp.public_key());
            Ok(())
        }
        Cmd::Sign {
            key,
            issuer,
            tenant,
            src,
            ttl,
            reason,
            ts,
            id,
        } => {
            let k = load_key(&key)?;
            let mut d = sentinel_common::decision::Decision {
                kind: "decision".into(),
                v: 1,
                id: id.unwrap_or_else(|| uuid::Uuid::now_v7().to_string()),
                issuer,
                tenant,
                src,
                action: "block".into(),
                ttl_s: ttl,
                reason,
                ts: ts.unwrap_or_else(sentinel_common::units::now_unix_ms),
                sig: String::new(),
            };
            d.validate().map_err(|e| anyhow::anyhow!(e))?;
            d.sign(&k);
            println!("{}", serde_json::to_string(&d)?);
            Ok(())
        }
        Cmd::CheckConfig { config } => {
            let cfg = config::Config::load(&config)?;
            let key = load_key(&cfg.worker.signing_key_file)?;
            println!(
                "ok: {} (public key {})",
                cfg.worker.id,
                public_key_b64(&key)
            );
            Ok(())
        }
        Cmd::Run { config } => {
            let cfg = config::Config::load(&config)?;
            let key = load_key(&cfg.worker.signing_key_file)?;
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(run::run(cfg, key))
        }
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
    fn key_generate_writes_once() {
        let dir = std::env::temp_dir().join(format!("sw-key-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("k");
        let _ = std::fs::remove_file(&p);
        let key = ed25519_dalek::SigningKey::from_bytes(&[5; 32]);
        write_secret(&p, &seed_b64(&key)).unwrap();
        assert!(write_secret(&p, "x").is_err(), "never overwrites");
        assert_eq!(load_key(&p).unwrap().to_bytes(), key.to_bytes());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
