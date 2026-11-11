// SPDX-License-Identifier: MIT OR Apache-2.0
//! `sentinel-api`: serve | migrate | create-admin | openapi.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use sqlx::postgres::PgPoolOptions;

use sentinel_api::config::Config;
use sentinel_api::{auth, crypto, mail, router, start_nats, AppState};

#[derive(Parser)]
#[command(
    name = "sentinel-api",
    version,
    about = "Sentinel-Edge control-plane API"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the API.
    Serve {
        #[arg(long, env = "SENTINEL_API_CONFIG")]
        config: PathBuf,
    },
    /// Apply database migrations (uses the owner URL).
    Migrate {
        #[arg(long, env = "SENTINEL_API_CONFIG")]
        config: PathBuf,
    },
    /// Create (or promote) a platform administrator; the password is read
    /// from SENTINEL_ADMIN_PASSWORD.
    CreateAdmin {
        #[arg(long, env = "SENTINEL_API_CONFIG")]
        config: PathBuf,
        #[arg(long)]
        email: String,
    },
    /// Print the OpenAPI document.
    Openapi,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_target(false)
        .init();
    let cli = Cli::parse();
    if let Cmd::Openapi = cli.cmd {
        println!("{}", sentinel_api::openapi_json());
        return Ok(());
    }
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async move {
            match cli.cmd {
                Cmd::Serve { config } => serve(Config::load(&config)?).await,
                Cmd::Migrate { config } => {
                    let cfg = Config::load(&config)?;
                    let pool = PgPoolOptions::new()
                        .max_connections(1)
                        .connect(&Config::env(&cfg.database.owner_url_env)?)
                        .await
                        .context("connecting with the owner URL")?;
                    sqlx::migrate!("../../migrations/postgres").run(&pool).await?;
                    println!("migrations applied");
                    Ok(())
                }
                Cmd::CreateAdmin { config, email } => {
                    let cfg = Config::load(&config)?;
                    let pw = Config::env("SENTINEL_ADMIN_PASSWORD")?;
                    auth::check_password_policy(&pw, cfg.auth.min_password_len)
                        .map_err(|e| anyhow::anyhow!(e.message))?;
                    let pool = PgPoolOptions::new()
                        .max_connections(1)
                        .connect(&Config::env(&cfg.database.url_env)?)
                        .await?;
                    let hash = auth::hash_password(pw).await?;
                    sqlx::query(
                        "INSERT INTO users (email, password_hash, email_verified, is_platform_admin) \
                         VALUES ($1, $2, true, true) ON CONFLICT (email) DO UPDATE \
                         SET password_hash = EXCLUDED.password_hash, is_platform_admin = true, email_verified = true",
                    )
                    .bind(email.trim().to_lowercase())
                    .bind(hash)
                    .execute(&pool)
                    .await?;
                    println!("platform admin {email} ready (enable 2FA before using admin endpoints)");
                    Ok(())
                }
                Cmd::Openapi => unreachable!(),
            }
        })
}

async fn serve(cfg: Config) -> Result<()> {
    let pool = PgPoolOptions::new()
        .max_connections(cfg.database.max_connections)
        .connect(&Config::env(&cfg.database.url_env)?)
        .await
        .context("connecting to PostgreSQL")?;
    let data_key = crypto::DataKey::from_base64(&Config::env(&cfg.auth.data_key_env)?)?;
    let listen = cfg.server.listen;
    let mailer = Arc::from(mail::from_config(&cfg.mail));
    let state = AppState::new(cfg, pool, mailer, data_key)?;
    start_nats(&state).await?;
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .with_context(|| format!("binding {listen}"))?;
    tracing::info!(%listen, "API listening");
    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
