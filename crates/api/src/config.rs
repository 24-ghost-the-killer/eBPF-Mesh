// SPDX-License-Identifier: MIT OR Apache-2.0
//! API configuration (TOML). Secrets (database URLs, the data key) come from
//! environment variables named here, never from the file.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::Deserialize;

use sentinel_common::prefix::Prefix;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub server: ServerCfg,
    #[serde(default)]
    pub database: DbCfg,
    pub anycast: AnycastCfg,
    #[serde(default)]
    pub rules: RulesCfg,
    #[serde(default)]
    pub sessions: SessionCfg,
    #[serde(default)]
    pub auth: AuthCfg,
    pub mail: MailCfg,
    /// Without NATS the outbox keeps accumulating (and is published later).
    #[serde(default)]
    pub nats: Option<NatsCfg>,
    #[serde(default)]
    pub webhooks: WebhooksCfg,
    #[serde(default)]
    pub decisions: DecisionsCfg,
    /// Traffic history (ADR 0024); without it /traffic answers 503.
    #[serde(default)]
    pub clickhouse: Option<ClickHouseCfg>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClickHouseCfg {
    /// HTTP interface, e.g. https://clickhouse.mgmt:8443
    pub url: String,
    #[serde(default = "d_ch_db")]
    pub database: String,
    /// Read-only user (SELECT on traffic_1m).
    pub user: String,
    /// Env var with the user's password.
    #[serde(default = "d_ch_pw_env")]
    pub password_env: String,
}

fn d_ch_db() -> String {
    "sentinel".into()
}
fn d_ch_pw_env() -> String {
    "SENTINEL_CLICKHOUSE_PASSWORD".into()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhooksCfg {
    /// Allow http:// targets (labs only).
    #[serde(default)]
    pub allow_http: bool,
    /// Allow targets that resolve to private, loopback or other
    /// non-public addresses (labs only; SSRF protection otherwise).
    #[serde(default)]
    pub allow_private_targets: bool,
    #[serde(default = "d_wh_timeout")]
    pub timeout_s: u64,
    #[serde(default = "d_wh_max")]
    pub max_per_tenant: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionsCfg {
    /// Issuer name of the API's own decisions (admin panel).
    #[serde(default = "d_dec_issuer")]
    pub issuer: String,
    /// Env var with the base64 Ed25519 seed; without it the API cannot issue
    /// decisions (it still records the workers').
    #[serde(default = "d_dec_env")]
    pub signing_key_env: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerCfg {
    pub listen: SocketAddr,
    /// Base URL of the portal, for links in emails.
    pub public_url: String,
    /// Secure cookie flag; only switch off for plain-HTTP labs.
    #[serde(default = "yes")]
    pub cookie_secure: bool,
    /// Take the client IP from X-Forwarded-For (behind a trusted proxy only).
    #[serde(default)]
    pub trust_proxy: bool,
    /// Origins of the separately hosted status page, allowed to read
    /// GET /status cross-origin (ADR 0025). Nothing else is CORS-enabled.
    #[serde(default)]
    pub status_page_origins: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DbCfg {
    /// Env var with the URL the API serves with (role sentinel_api).
    #[serde(default = "d_db_env")]
    pub url_env: String,
    /// Env var with the owner URL `sentinel-api migrate` uses.
    #[serde(default = "d_db_owner_env")]
    pub owner_url_env: String,
    #[serde(default = "d_db_conns")]
    pub max_connections: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnycastCfg {
    /// Protected IPs are allocated from here.
    pub prefix4: Prefix,
    /// Anycast tunnel endpoint (ADR 0012): never allocated.
    pub tunnel_ep4: Ipv4Addr,
    /// More addresses never to allocate.
    #[serde(default)]
    pub reserved4: Vec<Ipv4Addr>,
    /// MTU of the PoP uplinks (for the customer script's DSR MSS).
    #[serde(default = "d_mtu")]
    pub pop_mtu: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RulesCfg {
    /// Customers cannot allow/block anything wider than these.
    #[serde(default = "d_min_v4")]
    pub min_prefix_v4: u8,
    #[serde(default = "d_min_v6")]
    pub min_prefix_v6: u8,
    #[serde(default = "d_max_rules")]
    pub max_per_tenant: i64,
    #[serde(default = "d_max_ttl")]
    pub max_block_ttl_days: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionCfg {
    #[serde(default = "d_abs_h")]
    pub absolute_hours: i64,
    #[serde(default = "d_idle_m")]
    pub idle_minutes: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthCfg {
    /// Failed logins per account per window before 429.
    #[serde(default = "d_fail_acct")]
    pub login_max_failures: i64,
    /// Failed logins per client IP per window before 429.
    #[serde(default = "d_fail_ip")]
    pub login_ip_max_failures: i64,
    #[serde(default = "d_window")]
    pub window_minutes: i64,
    #[serde(default = "d_min_pw")]
    pub min_password_len: usize,
    /// Env var with the base64 32-byte key for secrets at rest (TOTP).
    #[serde(default = "d_key_env")]
    pub data_key_env: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MailMode {
    /// One JSON file per message in `dir` (labs and tests).
    File,
    /// Log the message (development).
    Log,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailCfg {
    pub mode: MailMode,
    #[serde(default)]
    pub dir: Option<PathBuf>,
    pub from: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NatsCfg {
    pub url: String,
    pub ca: PathBuf,
    pub nkey_seed_file: PathBuf,
}

fn yes() -> bool {
    true
}
fn d_db_env() -> String {
    "SENTINEL_DATABASE_URL".into()
}
fn d_db_owner_env() -> String {
    "SENTINEL_DATABASE_OWNER_URL".into()
}
fn d_db_conns() -> u32 {
    10
}
fn d_mtu() -> u32 {
    1500
}
fn d_min_v4() -> u8 {
    16
}
fn d_min_v6() -> u8 {
    32
}
fn d_max_rules() -> i64 {
    1000
}
fn d_max_ttl() -> u64 {
    30
}
fn d_abs_h() -> i64 {
    12
}
fn d_idle_m() -> i64 {
    60
}
fn d_fail_acct() -> i64 {
    5
}
fn d_fail_ip() -> i64 {
    30
}
fn d_window() -> i64 {
    15
}
fn d_min_pw() -> usize {
    12
}
fn d_key_env() -> String {
    "SENTINEL_DATA_KEY".into()
}
fn d_wh_timeout() -> u64 {
    5
}
fn d_wh_max() -> i64 {
    10
}
fn d_dec_issuer() -> String {
    "api".into()
}
fn d_dec_env() -> String {
    "SENTINEL_DECISION_KEY".into()
}

impl Default for WebhooksCfg {
    fn default() -> Self {
        WebhooksCfg {
            allow_http: false,
            allow_private_targets: false,
            timeout_s: d_wh_timeout(),
            max_per_tenant: d_wh_max(),
        }
    }
}
impl Default for DecisionsCfg {
    fn default() -> Self {
        DecisionsCfg {
            issuer: d_dec_issuer(),
            signing_key_env: d_dec_env(),
        }
    }
}

impl Default for DbCfg {
    fn default() -> Self {
        DbCfg {
            url_env: d_db_env(),
            owner_url_env: d_db_owner_env(),
            max_connections: d_db_conns(),
        }
    }
}
impl Default for RulesCfg {
    fn default() -> Self {
        RulesCfg {
            min_prefix_v4: d_min_v4(),
            min_prefix_v6: d_min_v6(),
            max_per_tenant: d_max_rules(),
            max_block_ttl_days: d_max_ttl(),
        }
    }
}
impl Default for SessionCfg {
    fn default() -> Self {
        SessionCfg {
            absolute_hours: d_abs_h(),
            idle_minutes: d_idle_m(),
        }
    }
}
impl Default for AuthCfg {
    fn default() -> Self {
        AuthCfg {
            login_max_failures: d_fail_acct(),
            login_ip_max_failures: d_fail_ip(),
            window_minutes: d_window(),
            min_password_len: d_min_pw(),
            data_key_env: d_key_env(),
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Config> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let c: Config =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        c.validate()?;
        Ok(c)
    }

    pub fn validate(&self) -> Result<()> {
        let p = self.anycast.prefix4;
        if !p.is_v4() || !(8..=30).contains(&p.prefix_len()) {
            bail!("anycast.prefix4 must be an IPv4 prefix between /8 and /30");
        }
        if !p.contains(self.anycast.tunnel_ep4.into()) {
            bail!("anycast.tunnel_ep4 must be inside anycast.prefix4");
        }
        if self.mail.mode == MailMode::File && self.mail.dir.is_none() {
            bail!("mail.mode = \"file\" needs mail.dir");
        }
        if self.sessions.absolute_hours <= 0 || self.sessions.idle_minutes <= 0 {
            bail!("session lifetimes must be positive");
        }
        if self.auth.min_password_len < 8 {
            bail!("auth.min_password_len must be at least 8");
        }
        if let Some(n) = &self.nats {
            if !n.url.starts_with("tls://") {
                bail!("nats.url must use tls://");
            }
        }
        sentinel_common::msg::validate_pop_id(&self.decisions.issuer)
            .map_err(|e| anyhow::anyhow!("decisions.issuer: {e}"))?;
        for o in &self.server.status_page_origins {
            let u =
                url::Url::parse(o).map_err(|e| anyhow::anyhow!("status_page_origins: {o}: {e}"))?;
            if u.origin().ascii_serialization() != *o {
                bail!("status_page_origins: {o} must be a bare origin like https://status.example.org");
            }
        }
        if let Some(c) = &self.clickhouse {
            if !(c.url.starts_with("https://") || c.url.starts_with("http://")) {
                bail!("clickhouse.url must be http(s)://");
            }
        }
        if !(1..=30).contains(&self.webhooks.timeout_s) {
            bail!("webhooks.timeout_s must be 1..=30");
        }
        Ok(())
    }

    pub fn env(name: &str) -> Result<String> {
        std::env::var(name).with_context(|| format!("environment variable {name} is not set"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../configs/api.example.toml"
    ));

    #[test]
    fn example_is_valid() {
        let c: Config = toml::from_str(EXAMPLE).unwrap();
        c.validate().unwrap();
        assert_eq!(c.sessions.absolute_hours, 12);
        assert_eq!(c.sessions.idle_minutes, 60);
        assert!(c.server.cookie_secure);
    }

    #[test]
    fn rejects_bad() {
        let bad = |from: &str, to: &str| {
            let s = EXAMPLE.replacen(from, to, 1);
            assert_ne!(s, EXAMPLE, "{from:?} not in example");
            let c: Result<Config, _> = toml::from_str(&s);
            assert!(
                c.map(|c| c.validate().is_err()).unwrap_or(true),
                "accepted {to:?}"
            );
        };
        bad(
            "tunnel_ep4 = \"198.51.100.1\"",
            "tunnel_ep4 = \"203.0.113.1\"",
        );
        bad(
            "prefix4 = \"198.51.100.0/24\"",
            "prefix4 = \"2001:db8::/32\"",
        );
        bad("url = \"tls://", "url = \"nats://");
        bad("[server]", "[server]\nextra = 1");
        bad(
            "status_page_origins = [\"https://status.example.org\"]",
            "status_page_origins = [\"https://status.example.org/path\"]",
        );
    }
}
