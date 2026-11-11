// SPDX-License-Identifier: MIT OR Apache-2.0
//! Test harness: a fresh database per test in the throwaway cluster that
//! `make test-api` starts (SENTINEL_TEST_PG), the API in-process, and a
//! small client that handles the session cookie and CSRF header.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use base64::Engine;
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use sqlx::{Connection, PgConnection, PgPool};

use sentinel_api::config::Config;
use sentinel_api::{crypto, mail, router, AppState};

pub const PASSWORD: &str = "correct horse battery";

pub struct Lab {
    pub base: String,
    pub mail_dir: PathBuf,
    /// Superuser pool on the test database (owner: bypasses RLS).
    pub su: PgPool,
    /// The API's own pool (role sentinel_api: subject to RLS).
    pub api_pool: PgPool,
    pub db_url_api: String,
}

fn url_with_db(base: &str, db: &str, user: &str) -> String {
    // postgres://postgres@localhost/postgres?host=..&port=..
    let (head, query) = base.split_once('?').expect("URL with ?host=");
    let (_, rest) = head.split_once("://").unwrap();
    let host = rest
        .split_once('@')
        .map(|x| x.1)
        .unwrap_or(rest)
        .split('/')
        .next()
        .unwrap();
    format!("postgres://{user}@{host}/{db}?{query}")
}

impl Lab {
    pub async fn new() -> Lab {
        let base = std::env::var("SENTINEL_TEST_PG")
            .expect("SENTINEL_TEST_PG is not set: run these tests with `make test-api`");
        let db = format!(
            "t_{}",
            &crypto::token().to_lowercase().replace(['-', '_'], "")[..12]
        );
        let mut c = PgConnection::connect(&base)
            .await
            .expect("connect to test cluster");
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {db}")))
            .execute(&mut c)
            .await
            .unwrap();
        let su = PgPoolOptions::new()
            .max_connections(4)
            .connect(&url_with_db(&base, &db, "postgres"))
            .await
            .unwrap();
        sqlx::migrate!("../../migrations/postgres")
            .run(&su)
            .await
            .expect("migrations");
        sqlx::query("ALTER ROLE sentinel_api LOGIN")
            .execute(&su)
            .await
            .unwrap();
        let db_url_api = url_with_db(&base, &db, "sentinel_api");
        let api_pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(&db_url_api)
            .await
            .unwrap();

        let mail_dir = std::env::temp_dir().join(format!("sentinel-mail-{db}"));
        let cfg: Config = toml::from_str(&format!(
            r#"
            [server]
            listen = "127.0.0.1:0"
            public_url = "https://portal.test"
            [anycast]
            prefix4 = "198.51.100.0/24"
            tunnel_ep4 = "198.51.100.1"
            [mail]
            mode = "file"
            dir = "{}"
            from = "noreply@test"
            "#,
            mail_dir.display()
        ))
        .unwrap();
        cfg.validate().unwrap();
        let key = base64::engine::general_purpose::STANDARD.encode(crypto::random_bytes::<32>());
        let state = AppState {
            mailer: Arc::from(mail::from_config(&cfg.mail)),
            cfg: Arc::new(cfg),
            pool: api_pool.clone(),
            data_key: crypto::DataKey::from_base64(&key).unwrap(),
            outbox: Arc::new(tokio::sync::Notify::new()),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(
                listener,
                router(state).into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap()
        });
        Lab {
            base: format!("http://{addr}/api/v1"),
            mail_dir,
            su,
            api_pool,
            db_url_api,
        }
    }

    pub fn client(&self) -> Client {
        Client {
            base: self.base.clone(),
            http: reqwest::Client::new(),
            cookie: None,
            csrf: None,
            bearer: None,
        }
    }

    /// The newest mail to `to`.
    pub fn last_mail(&self, to: &str) -> Value {
        let mut files: Vec<_> = std::fs::read_dir(&self.mail_dir)
            .map(|d| d.filter_map(|e| e.ok()).map(|e| e.path()).collect())
            .unwrap_or_default();
        files.sort();
        files
            .iter()
            .rev()
            .map(|f| serde_json::from_slice::<Value>(&std::fs::read(f).unwrap()).unwrap())
            .find(|m| m["to"] == to)
            .unwrap_or_else(|| panic!("no mail to {to}"))
    }

    pub fn mail_token(&self, to: &str) -> String {
        let body = self.last_mail(to)["body"].as_str().unwrap().to_string();
        body.split("token=")
            .nth(1)
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .to_string()
    }

    /// Signs up, verifies and logs in. Returns the client and the tenant id.
    pub async fn customer(&self, email: &str) -> (Client, i64) {
        let mut c = self.client();
        let (s, _) = c
            .call(
                Method::POST,
                "/auth/signup",
                Some(json!({"email": email, "password": PASSWORD, "tenant_name": email})),
            )
            .await;
        assert_eq!(s, StatusCode::ACCEPTED);
        let t = self.mail_token(email);
        let (s, _) = c
            .call(
                Method::POST,
                "/auth/verify-email",
                Some(json!({"token": t})),
            )
            .await;
        assert_eq!(s, StatusCode::OK);
        let (s, b) = c.login(email, PASSWORD).await;
        assert_eq!(s, StatusCode::OK, "{b}");
        let (_, me) = c.call(Method::GET, "/me", None).await;
        let tid = me["tenants"][0]["id"].as_i64().unwrap();
        (c, tid)
    }

    pub async fn outbox(&self, bucket: &str, key: &str) -> Option<Value> {
        sqlx::query_scalar::<_, Option<Value>>(
            "SELECT value FROM kv_outbox WHERE bucket = $1 AND key = $2 ORDER BY id DESC LIMIT 1",
        )
        .bind(bucket)
        .bind(key)
        .fetch_optional(&self.su)
        .await
        .unwrap()
        .flatten()
    }
}

pub struct Client {
    pub base: String,
    pub http: reqwest::Client,
    pub cookie: Option<String>,
    pub csrf: Option<String>,
    pub bearer: Option<String>,
}

impl Client {
    pub async fn raw(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
        csrf: bool,
    ) -> reqwest::Response {
        let mut r = self.http.request(method, format!("{}{path}", self.base));
        if let Some(c) = &self.cookie {
            r = r.header("cookie", format!("xs_session={c}"));
        }
        if let (true, Some(t)) = (csrf, &self.csrf) {
            r = r.header("x-csrf-token", t);
        }
        if let Some(k) = &self.bearer {
            r = r.header("authorization", format!("Bearer {k}"));
        }
        if let Some(b) = body {
            r = r.json(&b);
        }
        r.send().await.unwrap()
    }

    pub async fn call(
        &mut self,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let resp = self.raw(method, path, body, true).await;
        let s = resp.status();
        let text = resp.text().await.unwrap();
        (
            s,
            serde_json::from_str(&text).unwrap_or(Value::String(text)),
        )
    }

    pub async fn login(&mut self, email: &str, password: &str) -> (StatusCode, Value) {
        let resp = self
            .raw(
                Method::POST,
                "/auth/login",
                Some(json!({"email": email, "password": password})),
                false,
            )
            .await;
        let s = resp.status();
        if let Some(sc) = resp
            .headers()
            .get("set-cookie")
            .and_then(|v| v.to_str().ok())
        {
            self.cookie = sc
                .split(';')
                .next()
                .and_then(|kv| kv.split_once('='))
                .map(|x| x.1.to_string());
        }
        let b: Value = resp.json().await.unwrap_or(Value::Null);
        if let Some(t) = b["csrf_token"].as_str() {
            self.csrf = Some(t.to_string());
        }
        (s, b)
    }

    /// Enables TOTP; returns the base32 secret.
    pub async fn enable_totp(&mut self, email: &str) -> String {
        let (s, b) = self.call(Method::POST, "/auth/2fa/setup", None).await;
        assert_eq!(s, StatusCode::OK, "{b}");
        let secret = b["secret"].as_str().unwrap().to_string();
        let (s, b) = self
            .call(
                Method::POST,
                "/auth/2fa/enable",
                Some(json!({"code": totp(&secret, email, 0)})),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{b}");
        secret
    }
}

/// TOTP code for the current step + `ahead` (the server accepts ±1 step).
pub fn totp(secret_b32: &str, email: &str, ahead: u64) -> String {
    let t = totp_rs::Builder::new()
        .with_secret(totp_rs::Secret::try_from_base32(secret_b32).unwrap())
        .with_account_name(email)
        .with_issuer(Some("Sentinel-Edge"))
        .build()
        .unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    t.generate(now + ahead * 30).to_string()
}
