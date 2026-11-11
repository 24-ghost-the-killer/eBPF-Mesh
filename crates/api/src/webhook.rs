// SPDX-License-Identifier: MIT OR Apache-2.0
//! Attack notifications: Discord, Slack, signed HTTP, email (ADR 0022).
//!
//! Targets are customer-controlled URLs, so delivery guards against SSRF:
//! https only, no credentials in URLs, no redirects, and the host must
//! resolve only to public addresses; the connection then goes to exactly
//! the address that was checked (no second DNS lookup). Discord and Slack
//! targets must be those services' webhook hosts. Labs can relax this with
//! `[webhooks] allow_http` / `allow_private_targets`.
//!
//! HTTP webhooks are signed: `X-Sentinel-Signature: sha256=<hex HMAC-SHA256
//! over "<timestamp>.<body>">` with the webhook's secret, and
//! `X-Sentinel-Timestamp: <unix seconds>`.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use hmac::{Hmac, KeyInit, Mac};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::Sha256;
use sqlx::FromRow;
use tracing::{info, warn};
use utoipa::ToSchema;

use crate::config::WebhooksCfg;
use crate::db::{self, Scope};
use crate::mail::Mail;
use crate::AppState;

pub const KINDS: [&str; 4] = ["discord", "slack", "http", "email"];

const ADMIN: Scope = Scope {
    user: None,
    tenant: None,
    key_tenant: None,
    admin: true,
};

/// Addresses a webhook may never reach (unless the lab allows it).
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => v4_public(a),
        IpAddr::V6(a) => {
            if let Some(m) = a.to_ipv4_mapped() {
                return v4_public(m);
            }
            let s = a.segments();
            !(a.is_loopback()
                || a.is_unspecified()
                || a.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00 // unique local
                || (s[0] & 0xffc0) == 0xfe80 // link local
                || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation
                || (s[0] == 0x0064 && s[1] == 0xff9b)) // NAT64 (maps to v4)
        }
    }
}

fn v4_public(a: Ipv4Addr) -> bool {
    let o = a.octets();
    !(a.is_private()
        || a.is_loopback()
        || a.is_link_local()
        || a.is_unspecified()
        || a.is_broadcast()
        || a.is_multicast()
        || a.is_documentation()
        || o[0] == 0
        || o[0] >= 240
        || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64/10 CGNAT
        || (o[0] == 198 && (o[1] & 0xfe) == 18) // 198.18/15 benchmarking
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)) // 192.0.0/24
}

/// Checks a target when it is saved (and again before every delivery).
pub fn check_target(cfg: &WebhooksCfg, kind: &str, target: &str) -> Result<(), String> {
    if target.len() > 512 {
        return Err("target too long".into());
    }
    if kind == "email" {
        return crate::auth::check_email(target).map_err(|e| e.message);
    }
    if !KINDS.contains(&kind) {
        return Err("kind must be discord, slack, http or email".into());
    }
    let url = url::Url::parse(target).map_err(|e| format!("not a URL: {e}"))?;
    match url.scheme() {
        "https" => {}
        "http" if cfg.allow_http => {}
        _ => return Err("the URL must use https".into()),
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("no credentials in the URL".into());
    }
    let host = url.host_str().ok_or("the URL needs a host")?;
    match kind {
        "discord"
            if !matches!(host, "discord.com" | "discordapp.com")
                || !url.path().starts_with("/api/webhooks/") =>
        {
            return Err("not a Discord webhook URL (https://discord.com/api/webhooks/...)".into())
        }
        "slack" if host != "hooks.slack.com" => {
            return Err("not a Slack webhook URL (https://hooks.slack.com/...)".into())
        }
        _ => {}
    }
    if let Ok(ip) = host.trim_matches(['[', ']']).parse::<IpAddr>() {
        if !cfg.allow_private_targets && !is_public(ip) {
            return Err("the URL points to a private or reserved address".into());
        }
    } else if !cfg.allow_private_targets
        && (host == "localhost"
            || host.ends_with(".localhost")
            || host.ends_with(".internal")
            || !host.contains('.'))
    {
        return Err("the URL points to a private host name".into());
    }
    Ok(())
}

/// Resolves the target and returns the one address to connect to.
async fn resolve(cfg: &WebhooksCfg, url: &url::Url) -> Result<SocketAddr> {
    let host = url.host_str().context("no host")?;
    let port = url.port_or_known_default().context("no port")?;
    let addrs: Vec<SocketAddr> = match host.trim_matches(['[', ']']).parse::<IpAddr>() {
        Ok(ip) => vec![SocketAddr::new(ip, port)],
        Err(_) => tokio::net::lookup_host((host, port))
            .await
            .with_context(|| format!("resolving {host}"))?
            .collect(),
    };
    if addrs.is_empty() {
        bail!("{host} has no address");
    }
    if !cfg.allow_private_targets && addrs.iter().any(|a| !is_public(a.ip())) {
        bail!("{host} resolves to a private or reserved address");
    }
    Ok(addrs[0])
}

pub fn sign(secret: &[u8], ts: u64, body: &[u8]) -> String {
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(secret).expect("HMAC takes any key length");
    mac.update(ts.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    let tag = mac.finalize().into_bytes();
    format!(
        "sha256={}",
        tag.iter().map(|b| format!("{b:02x}")).collect::<String>()
    )
}

#[derive(FromRow)]
struct Hook {
    id: i64,
    kind: String,
    target: String,
    secret: Option<Vec<u8>>,
}

/// One delivery attempt.
async fn post(state: &AppState, hook: &Hook, event: &Value, text: &str) -> Result<String> {
    let cfg = &state.cfg.webhooks;
    if hook.kind == "email" {
        state.mailer.send(Mail {
            to: hook.target.clone(),
            from: state.cfg.mail.from.clone(),
            subject: format!(
                "Sentinel-Edge: {}",
                event["event"].as_str().unwrap_or("event")
            ),
            body: format!("{text}\n\n{}", serde_json::to_string_pretty(event)?),
        })?;
        return Ok("sent".into());
    }
    check_target(cfg, &hook.kind, &hook.target).map_err(|e| anyhow!(e))?;
    let url = url::Url::parse(&hook.target)?;
    let addr = resolve(cfg, &url).await?;
    let mut b = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(cfg.timeout_s))
        .user_agent("Sentinel-Edge-Webhook/1");
    if let Some(host) = url.host_str() {
        if host.parse::<IpAddr>().is_err() {
            b = b.resolve(host, addr);
        }
    }
    let client = b.build()?;
    let body = match hook.kind.as_str() {
        "discord" => serde_json::to_vec(&json!({ "content": text }))?,
        "slack" => serde_json::to_vec(&json!({ "text": text }))?,
        _ => serde_json::to_vec(event)?,
    };
    let mut req = client
        .post(url)
        .header("content-type", "application/json")
        .header("x-sentinel-event", event["event"].as_str().unwrap_or(""));
    if hook.kind == "http" {
        let ts = sentinel_common::units::now_unix_ms() / 1000;
        if let Some(enc) = &hook.secret {
            let secret = state.data_key.decrypt(enc)?;
            req = req
                .header("x-sentinel-timestamp", ts.to_string())
                .header("x-sentinel-signature", sign(&secret, ts, &body));
        }
    }
    let resp = req.body(body).send().await?;
    let status = resp.status();
    if !status.is_success() {
        bail!("HTTP {}", status.as_u16());
    }
    Ok(format!("HTTP {}", status.as_u16()))
}

/// Delivers with up to 3 attempts and records the outcome on the webhook.
async fn deliver(
    state: AppState,
    hook: Hook,
    event: Value,
    text: String,
) -> Result<String, String> {
    let mut last = String::new();
    for (i, wait) in [0u64, 1, 3].into_iter().enumerate() {
        if wait > 0 {
            tokio::time::sleep(Duration::from_secs(wait)).await;
        }
        match post(&state, &hook, &event, &text).await {
            Ok(s) => {
                record(&state, hook.id, &format!("ok: {s}")).await;
                info!(webhook = hook.id, kind = %hook.kind, "delivered {}", event["event"]);
                return Ok(s);
            }
            Err(e) => {
                last = format!("{e:#}");
                warn!(
                    webhook = hook.id,
                    attempt = i + 1,
                    "delivery failed: {last}"
                );
            }
        }
    }
    record(&state, hook.id, &format!("error: {last}")).await;
    Err(last)
}

async fn record(state: &AppState, id: i64, status: &str) {
    let r = async {
        let mut tx = db::begin(&state.pool, ADMIN).await?;
        sqlx::query("UPDATE webhooks SET last_at = now(), last_status = $2 WHERE id = $1")
            .bind(id)
            .bind(status.chars().take(200).collect::<String>())
            .execute(&mut *tx)
            .await?;
        tx.commit().await
    }
    .await;
    if let Err(e) = r {
        warn!("recording webhook status: {e}");
    }
}

#[derive(Serialize, ToSchema, FromRow)]
pub struct AttackSummary {
    pub id: i64,
    pub tenant_id: i64,
    pub vector: String,
    pub status: String,
    pub started_at: i64,
    pub ended_at: Option<i64>,
    pub peak_pps: i64,
    pub peak_bps: i64,
    pub pops: Vec<String>,
    pub targets: Vec<String>,
    pub decisions: i32,
}

fn describe(event: &str, a: &AttackSummary, link: &str) -> String {
    let target = a
        .targets
        .first()
        .map(String::as_str)
        .unwrap_or("your protected IPs");
    match event {
        "attack.started" => format!(
            "Attack started on {target}: {} at {} pps. {link}",
            a.vector, a.peak_pps
        ),
        "attack.ended" => format!(
            "Attack on {target} ended: {}, peak {} pps, {} sources blocked. {link}",
            a.vector, a.peak_pps, a.decisions
        ),
        _ => format!("Sentinel-Edge test notification. {link}"),
    }
}

/// Notifies every webhook of the attack's tenant (in the background).
pub async fn attack_event(state: &AppState, attack: i64, event: &str) -> Result<()> {
    let mut tx = db::begin(&state.pool, ADMIN).await?;
    let a: Option<AttackSummary> = sqlx::query_as(
        "SELECT id, tenant_id, vector, status, (extract(epoch FROM started_at) * 1000)::bigint AS started_at, \
                (extract(epoch FROM ended_at) * 1000)::bigint AS ended_at, coalesce(peak_pps, 0) AS peak_pps, \
                coalesce(peak_bps, 0) AS peak_bps, coalesce(pops, '{}') AS pops, targets, decisions \
         FROM attacks WHERE id = $1",
    )
    .bind(attack)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(a) = a else {
        return Ok(());
    };
    let hooks: Vec<Hook> =
        sqlx::query_as("SELECT id, kind, target, secret FROM webhooks WHERE tenant_id = $1")
            .bind(a.tenant_id)
            .fetch_all(&mut *tx)
            .await?;
    tx.commit().await?;
    let link = format!(
        "{}/t/{}/attacks/{}",
        state.cfg.server.public_url.trim_end_matches('/'),
        a.tenant_id,
        a.id
    );
    let text = describe(event, &a, &link);
    let payload = json!({
        "event": event,
        "ts": sentinel_common::units::now_unix_ms(),
        "tenant": a.tenant_id,
        "attack": a,
        "url": link,
    });
    for h in hooks {
        tokio::spawn(deliver(state.clone(), h, payload.clone(), text.clone()));
    }
    Ok(())
}

/// Sends a test event to one webhook and waits for the result.
pub async fn test(state: &AppState, tenant: i64, id: i64) -> Result<Result<String, String>> {
    let mut tx = db::begin(&state.pool, ADMIN).await?;
    let hook: Option<Hook> = sqlx::query_as(
        "SELECT id, kind, target, secret FROM webhooks WHERE id = $1 AND tenant_id = $2",
    )
    .bind(id)
    .bind(tenant)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    let Some(hook) = hook else {
        bail!("no such webhook");
    };
    let link = format!(
        "{}/t/{tenant}",
        state.cfg.server.public_url.trim_end_matches('/')
    );
    let event = json!({
        "event": "test",
        "ts": sentinel_common::units::now_unix_ms(),
        "tenant": tenant,
        "url": link,
    });
    let text = format!("Sentinel-Edge test notification. {link}");
    Ok(deliver(state.clone(), hook, event, text).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(lab: bool) -> WebhooksCfg {
        WebhooksCfg {
            allow_http: lab,
            allow_private_targets: lab,
            ..WebhooksCfg::default()
        }
    }

    #[test]
    fn public_addresses() {
        for ok in ["8.8.8.8", "1.1.1.1", "2606:4700::1111"] {
            assert!(is_public(ok.parse().unwrap()), "{ok}");
        }
        for bad in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
            "192.0.2.1",
            "198.18.0.1",
            "240.0.0.1",
            "::1",
            "::",
            "fd00::1",
            "fe80::1",
            "2001:db8::1",
            "::ffff:127.0.0.1",
            "64:ff9b::a00:1",
        ] {
            assert!(!is_public(bad.parse().unwrap()), "{bad}");
        }
    }

    #[test]
    fn targets() {
        let c = cfg(false);
        assert!(check_target(&c, "http", "https://hooks.example.org/sentinel").is_ok());
        assert!(
            check_target(&c, "http", "http://hooks.example.org/x").is_err(),
            "http"
        );
        assert!(
            check_target(&c, "http", "https://user:pw@example.org/").is_err(),
            "credentials"
        );
        assert!(
            check_target(&c, "http", "https://169.254.169.254/latest").is_err(),
            "metadata"
        );
        assert!(check_target(&c, "http", "https://[::1]/").is_err());
        assert!(check_target(&c, "http", "https://localhost/").is_err());
        assert!(check_target(&c, "http", "https://intranet/").is_err());
        assert!(check_target(&c, "http", "ftp://example.org/").is_err());
        assert!(check_target(&c, "discord", "https://discord.com/api/webhooks/1/abc").is_ok());
        assert!(check_target(&c, "discord", "https://evil.example/api/webhooks/1").is_err());
        assert!(check_target(&c, "slack", "https://hooks.slack.com/services/T/B/X").is_ok());
        assert!(check_target(&c, "slack", "https://slack.example.org/x").is_err());
        assert!(check_target(&c, "email", "ops@example.org").is_ok());
        assert!(check_target(&c, "email", "not-an-email").is_err());
        assert!(check_target(&c, "sms", "x").is_err());
        // Labs may allow plain HTTP to private addresses.
        assert!(check_target(&cfg(true), "http", "http://127.0.0.1:9000/hook").is_ok());
    }

    #[test]
    fn hmac_signature() {
        // HMAC-SHA256(key = "secret", "1700000000.{}"), computed with Python hmac.
        assert_eq!(
            sign(b"secret", 1700000000, b"{}"),
            "sha256=b8569b78799ff9e3cbff0fc2d63a33a2b57f3282abd07c37ae5e8e7d79a5f163"
        );
    }
}
