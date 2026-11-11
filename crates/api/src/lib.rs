// SPDX-License-Identifier: MIT OR Apache-2.0
//! Sentinel-Edge control-plane API (spec section 9).
//!
//! PostgreSQL is the source of truth; configuration reaches the PoPs through
//! NATS KV via a transactional outbox; agents' acknowledgements and health
//! come back over NATS. The web app talks only to this API.

pub mod alloc;
pub mod auth;
pub mod config;
pub mod crypto;
pub mod db;
pub mod error;
pub mod kvsync;
pub mod live;
pub mod mail;
pub mod routes;

use std::sync::{Arc, OnceLock};

use anyhow::Context;
use axum::http::{header, HeaderValue};
use axum::routing::{delete, get, post};
use axum::Router;
use sqlx::PgPool;
use tokio::sync::Notify;
use utoipa::openapi::security::{ApiKey, ApiKeyValue, HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};

use crate::config::Config;
use crate::crypto::DataKey;
use crate::live::LiveHub;
use crate::mail::Mailer;

#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<Config>,
    pub pool: PgPool,
    pub mailer: Arc<dyn Mailer>,
    pub data_key: DataKey,
    /// Wakes the outbox publisher after a commit that queued KV documents.
    pub outbox: Arc<Notify>,
    /// Passkeys: relying party = the portal's public URL.
    pub webauthn: Arc<webauthn_rs::Webauthn>,
    /// scheme://host[:port] of the portal, for WebSocket Origin checks.
    pub public_origin: Arc<String>,
    /// Latest stats per PoP for /tenants/{id}/live.
    pub live: LiveHub,
    /// Set once NATS is connected (tunnel tests use request/reply).
    pub nats: Arc<OnceLock<async_nats::Client>>,
}

impl AppState {
    pub fn new(
        cfg: Config,
        pool: PgPool,
        mailer: Arc<dyn Mailer>,
        data_key: DataKey,
    ) -> anyhow::Result<AppState> {
        let url = url::Url::parse(&cfg.server.public_url).context("server.public_url")?;
        let host = url
            .host_str()
            .context("server.public_url needs a host name")?
            .to_string();
        let webauthn = webauthn_rs::WebauthnBuilder::new(&host, &url)
            .context("passkeys: relying party from server.public_url")?
            .rp_name("Sentinel-Edge")
            .build()
            .context("passkeys")?;
        Ok(AppState {
            public_origin: Arc::new(url.origin().ascii_serialization()),
            cfg: Arc::new(cfg),
            pool,
            mailer,
            data_key,
            outbox: Arc::new(Notify::new()),
            webauthn: Arc::new(webauthn),
            live: LiveHub::default(),
            nats: Arc::new(OnceLock::new()),
        })
    }
}

struct Security;

impl Modify for Security {
    fn modify(&self, api: &mut utoipa::openapi::OpenApi) {
        let c = api.components.get_or_insert_with(Default::default);
        c.add_security_scheme(
            "session",
            SecurityScheme::ApiKey(ApiKey::Cookie(ApiKeyValue::with_description(
                auth::SESSION_COOKIE,
                "Session cookie from /auth/login; state-changing requests also need X-CSRF-Token",
            ))),
        );
        c.add_security_scheme(
            "api_key",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .description(Some("Tenant API key (xs_...)"))
                    .build(),
            ),
        );
    }
}

#[derive(OpenApi)]
#[openapi(
    info(title = "Sentinel-Edge API", version = "1",
        description = "Control-plane API. Errors are {\"error\": \"code\", \"message\": \"text\"}."),
    paths(
        routes::auth::signup, routes::auth::verify_email, routes::auth::login, routes::auth::logout,
        routes::auth::totp_setup, routes::auth::totp_enable, routes::auth::totp_verify,
        routes::auth::reset_request, routes::auth::reset_confirm,
        routes::webauthn::register_start, routes::webauthn::register_finish,
        routes::webauthn::login_start, routes::webauthn::login_finish,
        routes::webauthn::list, routes::webauthn::remove,
        routes::me::me,
        routes::tenant::list_assets, routes::tenant::create_asset, routes::tenant::get_asset,
        routes::tenant::delete_asset, routes::tenant::get_policy, routes::tenant::put_policy,
        routes::tenant::tunnel_script, routes::tenant::asset_status, routes::tenant::tunnel_test,
        live::live,
        routes::tenant::list_rules, routes::tenant::create_rule, routes::tenant::delete_rule,
        routes::tenant::list_members, routes::tenant::add_member, routes::tenant::remove_member,
        routes::tenant::list_keys, routes::tenant::create_key, routes::tenant::delete_key,
        routes::tenant::audit_log,
        routes::platform::status, routes::platform::admin_pops, routes::platform::admin_tenants,
        routes::platform::killswitch,
    ),
    modifiers(&Security)
)]
pub struct ApiDoc;

pub fn openapi_json() -> String {
    ApiDoc::openapi()
        .to_pretty_json()
        .expect("OpenAPI serialises")
}

pub fn router(state: AppState) -> Router {
    use routes::{auth as a, me, platform as p, tenant as t, webauthn as w};
    let api = Router::new()
        .route("/auth/signup", post(a::signup))
        .route("/auth/verify-email", post(a::verify_email))
        .route("/auth/login", post(a::login))
        .route("/auth/logout", post(a::logout))
        .route("/auth/2fa/setup", post(a::totp_setup))
        .route("/auth/2fa/enable", post(a::totp_enable))
        .route("/auth/2fa/verify", post(a::totp_verify))
        .route("/auth/reset-password", post(a::reset_request))
        .route("/auth/reset-password/confirm", post(a::reset_confirm))
        .route("/auth/webauthn/register/start", post(w::register_start))
        .route("/auth/webauthn/register/finish", post(w::register_finish))
        .route("/auth/webauthn/login/start", post(w::login_start))
        .route("/auth/webauthn/login/finish", post(w::login_finish))
        .route("/auth/webauthn/credentials", get(w::list))
        .route("/auth/webauthn/credentials/{id}", delete(w::remove))
        .route("/me", get(me::me))
        .route(
            "/tenants/{tid}/assets",
            get(t::list_assets).post(t::create_asset),
        )
        .route(
            "/tenants/{tid}/assets/{aid}",
            get(t::get_asset).delete(t::delete_asset),
        )
        .route(
            "/tenants/{tid}/assets/{aid}/policy",
            get(t::get_policy).put(t::put_policy),
        )
        .route("/tenants/{tid}/assets/{aid}/tunnel", get(t::tunnel_script))
        .route("/tenants/{tid}/assets/{aid}/status", get(t::asset_status))
        .route(
            "/tenants/{tid}/assets/{aid}/tunnel-test",
            post(t::tunnel_test),
        )
        .route("/tenants/{tid}/live", get(live::live))
        .route(
            "/tenants/{tid}/rules",
            get(t::list_rules).post(t::create_rule),
        )
        .route("/tenants/{tid}/rules/{rid}", delete(t::delete_rule))
        .route(
            "/tenants/{tid}/users",
            get(t::list_members).post(t::add_member),
        )
        .route("/tenants/{tid}/users/{uid}", delete(t::remove_member))
        .route(
            "/tenants/{tid}/api-keys",
            get(t::list_keys).post(t::create_key),
        )
        .route("/tenants/{tid}/api-keys/{kid}", delete(t::delete_key))
        .route("/tenants/{tid}/audit", get(t::audit_log))
        .route("/status", get(p::status))
        .route("/admin/pops", get(p::admin_pops))
        .route("/admin/tenants", get(p::admin_tenants))
        .route("/admin/killswitch", post(p::killswitch))
        .route(
            "/openapi.json",
            get(|| async { ([(header::CONTENT_TYPE, "application/json")], openapi_json()) }),
        )
        .with_state(state);
    Router::new()
        .nest("/api/v1", api)
        .layer(axum::middleware::map_response(
            |mut r: axum::response::Response| async move {
                let h = r.headers_mut();
                h.insert(
                    "x-content-type-options",
                    HeaderValue::from_static("nosniff"),
                );
                h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
                h.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
                r
            },
        ))
}

/// Starts the outbox publisher and the ack/health consumers.
pub async fn start_nats(state: &AppState) -> anyhow::Result<()> {
    if let Some(n) = &state.cfg.nats {
        let client = kvsync::connect(n).await?;
        let _ = state.nats.set(client.clone());
        tokio::spawn(kvsync::publisher(
            state.pool.clone(),
            client.clone(),
            state.outbox.clone(),
        ));
        tokio::spawn(kvsync::stats_consumer(state.live.clone(), client.clone()));
        tokio::spawn(kvsync::consumers(state.pool.clone(), client));
    } else {
        tracing::warn!(
            "no [nats] section: configuration stays in the outbox until NATS is configured"
        );
    }
    Ok(())
}
