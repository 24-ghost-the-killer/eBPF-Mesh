// SPDX-License-Identifier: MIT OR Apache-2.0
//! API integration tests against a real PostgreSQL (`make test-api`).

mod common;

use reqwest::{Method, StatusCode};
use serde_json::json;

use common::{totp, Lab, PASSWORD};
use sentinel_common::msg::{parse_doc, AssetDoc, RulesDoc, ServicesDoc};

const PG: &str = "needs PostgreSQL: run with `make test-api`";

/// Phase 5 "done when": a customer can be created and given a protected IP
/// via the API, and a second customer cannot read it.
#[tokio::test]
#[ignore = "needs PostgreSQL: run with `make test-api`"]
async fn customer_gets_protected_ip_and_others_cannot_see_it() {
    let lab = Lab::new().await;
    let (mut a, ta) = lab.customer("alice@a.test").await;
    let (mut b, tb) = lab.customer("bob@b.test").await;
    assert_ne!(ta, tb);

    let (s, asset) = a
        .call(
            Method::POST,
            &format!("/tenants/{ta}/assets"),
            Some(json!({"origin_ip": "192.0.2.10", "services": [{"proto": "tcp", "port": 443}]})),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{asset}");
    let aid = asset["id"].as_i64().unwrap();
    let ip = asset["protected_prefix"].as_str().unwrap().to_string();
    assert!(ip.starts_with("198.51.100.") && ip.ends_with("/32"), "{ip}");
    assert_ne!(ip, "198.51.100.1/32", "tunnel endpoint is never allocated");
    assert_ne!(ip, "198.51.100.0/32");
    assert_eq!(
        asset["policy"]["mode"], "observe",
        "new customers start in observe mode"
    );

    // Bob: not a single bit of Alice's asset.
    for (m, path, body) in [
        (Method::GET, format!("/tenants/{ta}/assets"), None),
        (Method::GET, format!("/tenants/{ta}/assets/{aid}"), None),
        (
            Method::GET,
            format!("/tenants/{ta}/assets/{aid}/policy"),
            None,
        ),
        (
            Method::GET,
            format!("/tenants/{ta}/assets/{aid}/tunnel"),
            None,
        ),
        (
            Method::GET,
            format!("/tenants/{ta}/assets/{aid}/status"),
            None,
        ),
        (
            Method::PUT,
            format!("/tenants/{ta}/assets/{aid}/policy"),
            Some(asset["policy"].clone()),
        ),
        (Method::DELETE, format!("/tenants/{ta}/assets/{aid}"), None),
        (Method::GET, format!("/tenants/{ta}/rules"), None),
        (Method::GET, format!("/tenants/{ta}/audit"), None),
        // Bob's own tenant id with Alice's asset id:
        (Method::GET, format!("/tenants/{tb}/assets/{aid}"), None),
        (Method::DELETE, format!("/tenants/{tb}/assets/{aid}"), None),
    ] {
        let (s, body) = b.call(m.clone(), &path, body).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{m} {path}: {body}");
    }
    let (_, mine) = b
        .call(Method::GET, &format!("/tenants/{tb}/assets"), None)
        .await;
    assert_eq!(mine, json!([]));
    let (s, other) = b
        .call(
            Method::POST,
            &format!("/tenants/{tb}/assets"),
            Some(json!({"origin_ip": "192.0.2.20"})),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED);
    assert_ne!(
        other["protected_prefix"], asset["protected_prefix"],
        "IPs are never shared"
    );

    // Second safety net: RLS hides the row even from a query that forgets
    // the tenant filter (Bob, properly scoped to his own tenant).
    let bob: i64 = sqlx::query_scalar("SELECT id FROM users WHERE email = 'bob@b.test'")
        .fetch_one(&lab.su)
        .await
        .unwrap();
    let mut tx = lab.api_pool.begin().await.unwrap();
    sqlx::query(
        "SELECT set_config('app.tenant_id', $1, true), set_config('app.user_id', $2, true)",
    )
    .bind(tb.to_string())
    .bind(bob.to_string())
    .execute(&mut *tx)
    .await
    .unwrap();
    let visible: i64 = sqlx::query_scalar("SELECT count(*) FROM assets WHERE id = $1")
        .bind(aid)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert_eq!(visible, 0, "RLS must hide tenant A's asset from tenant B");
    let all: i64 = sqlx::query_scalar("SELECT count(*) FROM policies")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert_eq!(all, 1, "only B's policy row is visible");
    tx.rollback().await.unwrap();
    let unscoped: i64 = sqlx::query_scalar("SELECT count(*) FROM assets")
        .fetch_one(&lab.api_pool)
        .await
        .unwrap();
    assert_eq!(unscoped, 0, "without a tenant, RLS shows nothing");
    // RLS does not trust the tenant id (it comes from the URL): Bob asking
    // for tenant A, as if a handler forgot its role check, still sees nothing.
    let mut tx = lab.api_pool.begin().await.unwrap();
    sqlx::query(
        "SELECT set_config('app.tenant_id', $1, true), set_config('app.user_id', $2, true)",
    )
    .bind(ta.to_string())
    .bind(bob.to_string())
    .execute(&mut *tx)
    .await
    .unwrap();
    for (table, col, id) in [
        ("assets", "tenant_id", ta),
        ("policies", "asset_id", aid),
        ("rules", "tenant_id", ta),
        ("api_keys", "tenant_id", ta),
        ("audit_log", "tenant_id", ta),
        ("memberships", "tenant_id", ta),
    ] {
        let n: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT count(*) FROM {table} WHERE {col} = $1"
        )))
        .bind(id)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        assert_eq!(
            n, 0,
            "{table}: tenant A visible to a non-member via app.tenant_id"
        );
    }
    let res = sqlx::query(
        "INSERT INTO rules (tenant_id, kind, prefix, expires_at) \
         VALUES ($1, 'block', '203.0.113.0/24', now() + interval '1 hour')",
    )
    .bind(ta)
    .execute(&mut *tx)
    .await;
    assert!(
        res.is_err(),
        "a non-member cannot write tenant A's rows either"
    );
    tx.rollback().await.unwrap();

    // The KV documents for the PoPs pass the agent's own validation.
    let doc = lab
        .outbox("tenants", &format!("asset.{aid}"))
        .await
        .unwrap();
    let d: AssetDoc = parse_doc(doc.to_string().as_bytes()).unwrap();
    d.validate(&format!("asset.{aid}")).unwrap();
    assert_eq!(d.prefix.to_string(), ip);
    assert_eq!(d.tenant as i64, ta);
    let svc = lab
        .outbox("services", &format!("asset.{aid}"))
        .await
        .unwrap();
    let s: ServicesDoc = parse_doc(svc.to_string().as_bytes()).unwrap();
    assert_eq!(s.keys(&format!("asset.{aid}")).unwrap().len(), 1);

    // The tunnel script is for Alice's origin and protected IP.
    let (s, script) = a
        .call(
            Method::GET,
            &format!("/tenants/{ta}/assets/{aid}/tunnel"),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let script = script.as_str().unwrap();
    assert!(
        script.contains("local 192.0.2.10") && script.contains(&ip),
        "{script}"
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL: run with `make test-api`"]
async fn authentication_security() {
    let _ = PG;
    let lab = Lab::new().await;
    let mut c = lab.client();
    let email = "carol@c.test";
    c.call(
        Method::POST,
        "/auth/signup",
        Some(json!({"email": email, "password": PASSWORD, "tenant_name": "C"})),
    )
    .await;

    // Unverified email cannot log in.
    let (s, b) = c.login(email, PASSWORD).await;
    assert_eq!(
        (s, b["error"].as_str()),
        (StatusCode::FORBIDDEN, Some("email_unverified"))
    );
    let t = lab.mail_token(email);
    c.call(
        Method::POST,
        "/auth/verify-email",
        Some(json!({"token": t})),
    )
    .await;
    let (s, _) = c
        .call(
            Method::POST,
            "/auth/verify-email",
            Some(json!({"token": t})),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "email tokens are single-use");

    // Signing up again does not reveal the account; the owner is told.
    let (s, _) = c
        .call(
            Method::POST,
            "/auth/signup",
            Some(json!({"email": email, "password": PASSWORD, "tenant_name": "X"})),
        )
        .await;
    assert_eq!(s, StatusCode::ACCEPTED);
    assert!(lab.last_mail(email)["subject"]
        .as_str()
        .unwrap()
        .contains("sign-up attempt"));

    // Weak passwords are refused.
    let (s, _) = c
        .call(
            Method::POST,
            "/auth/signup",
            Some(json!({"email": "d@d.test", "password": "short", "tenant_name": "D"})),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // Passwords are argon2id; the cookie is HttpOnly, SameSite=Strict, Secure.
    let hash: String = sqlx::query_scalar("SELECT password_hash FROM users WHERE email = $1")
        .bind(email)
        .fetch_one(&lab.su)
        .await
        .unwrap();
    assert!(hash.starts_with("$argon2id$"));
    let resp = c
        .raw(
            Method::POST,
            "/auth/login",
            Some(json!({"email": email, "password": PASSWORD})),
            false,
        )
        .await;
    let cookie = resp.headers()["set-cookie"].to_str().unwrap().to_string();
    for flag in ["HttpOnly", "SameSite=Strict", "Secure", "Path=/"] {
        assert!(cookie.contains(flag), "cookie lacks {flag}: {cookie}");
    }
    let (s, _) = c.login(email, PASSWORD).await;
    assert_eq!(s, StatusCode::OK);
    let token_hash: i64 = sqlx::query_scalar("SELECT count(*) FROM sessions WHERE token_hash = $1")
        .bind(c.cookie.clone().unwrap())
        .fetch_one(&lab.su)
        .await
        .unwrap();
    assert_eq!(token_hash, 0, "session tokens are stored hashed only");

    // CSRF: state-changing requests need the token.
    let resp = c.raw(Method::POST, "/auth/2fa/setup", None, false).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        resp.json::<serde_json::Value>().await.unwrap()["error"],
        "csrf"
    );

    // TOTP: enable, then a new login needs the code; codes are single-use.
    let secret = c.enable_totp(email).await;
    let stored: Vec<u8> = sqlx::query_scalar("SELECT totp_secret FROM users WHERE email = $1")
        .bind(email)
        .fetch_one(&lab.su)
        .await
        .unwrap();
    assert_eq!(
        stored.len(),
        12 + 20 + 16,
        "secret stored AES-GCM encrypted"
    );
    let mut c2 = lab.client();
    let (s, b) = c2.login(email, PASSWORD).await;
    assert_eq!(
        (s, b["mfa_required"].as_bool()),
        (StatusCode::OK, Some(true))
    );
    let (s, b) = c2.call(Method::GET, "/me", None).await;
    assert_eq!(
        (s, b["error"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("mfa_required"))
    );
    let (s, _) = c2
        .call(
            Method::POST,
            "/auth/2fa/verify",
            Some(json!({"code": "000000"})),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let code = totp(&secret, email, 1);
    let (s, _) = c2
        .call(
            Method::POST,
            "/auth/2fa/verify",
            Some(json!({"code": code})),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = c2.call(Method::GET, "/me", None).await;
    assert_eq!(s, StatusCode::OK);
    let mut c3 = lab.client();
    c3.login(email, PASSWORD).await;
    let (s, _) = c3
        .call(
            Method::POST,
            "/auth/2fa/verify",
            Some(json!({"code": code})),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "a TOTP code is accepted once");
    // Enabling 2FA ended the other sessions; c2 is new and still valid.
    let (s, _) = c.call(Method::GET, "/me", None).await;
    assert_eq!(s, StatusCode::OK, "the session that enabled 2FA stays");

    // Logout revokes the session server-side.
    let old = c2.cookie.clone();
    let (s, _) = c2.call(Method::POST, "/auth/logout", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    c2.cookie = old;
    let (s, _) = c2.call(Method::GET, "/me", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // Password reset ends every session.
    c.call(
        Method::POST,
        "/auth/reset-password",
        Some(json!({"email": email})),
    )
    .await;
    let t = lab.mail_token(email);
    let (s, _) = c
        .call(
            Method::POST,
            "/auth/reset-password/confirm",
            Some(json!({"token": t, "password": "a brand new password"})),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = c.call(Method::GET, "/me", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "reset revoked the session");
    let (s, _) = lab.client().login(email, PASSWORD).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "old password no longer works");

    // Login rate limit (per account): the right password is refused too.
    // A fresh account: failed 2FA codes above count towards the limit.
    let (_, _) = lab.customer("erin@e.test").await;
    let mut d = lab.client();
    for _ in 0..5 {
        let (s, _) = d.login("erin@e.test", "wrong password!").await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
    }
    let (s, b) = d.login("erin@e.test", PASSWORD).await;
    assert_eq!(
        (s, b["error"].as_str()),
        (StatusCode::TOO_MANY_REQUESTS, Some("rate_limited"))
    );
    // Unknown accounts behave the same (no enumeration).
    let (s, b) = lab.client().login("nobody@x.test", "whatever!").await;
    assert_eq!(
        (s, b["error"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("invalid_credentials"))
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL: run with `make test-api`"]
async fn roles_policies_rules_and_api_keys() {
    let lab = Lab::new().await;
    let (mut owner, t) = lab.customer("owner@o.test").await;
    let (mut viewer, _) = lab.customer("viewer@o.test").await;
    let (mut admin, _) = lab.customer("admin@o.test").await;
    for (who, role) in [("viewer@o.test", "viewer"), ("admin@o.test", "admin")] {
        let (s, b) = owner
            .call(
                Method::POST,
                &format!("/tenants/{t}/users"),
                Some(json!({"email": who, "role": role})),
            )
            .await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
    }
    let (s, asset) = admin
        .call(
            Method::POST,
            &format!("/tenants/{t}/assets"),
            Some(json!({"origin_ip": "192.0.2.10"})),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "admins create assets");
    let aid = asset["id"].as_i64().unwrap();

    // Viewer reads, cannot write.
    let (s, _) = viewer
        .call(Method::GET, &format!("/tenants/{t}/assets"), None)
        .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = viewer
        .call(
            Method::POST,
            &format!("/tenants/{t}/assets"),
            Some(json!({"origin_ip": "192.0.2.11"})),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // Admin cannot do owner things.
    for (m, p) in [
        (Method::DELETE, format!("/tenants/{t}/assets/{aid}")),
        (Method::GET, format!("/tenants/{t}/users")),
        (Method::GET, format!("/tenants/{t}/audit")),
        (Method::GET, format!("/tenants/{t}/api-keys")),
    ] {
        let (s, _) = admin.call(m.clone(), &p, None).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{m} {p}");
    }
    // Last owner cannot be removed.
    let (_, me) = owner.call(Method::GET, "/me", None).await;
    let uid = me["user"]["id"].as_i64().unwrap();
    let (s, _) = owner
        .call(Method::DELETE, &format!("/tenants/{t}/users/{uid}"), None)
        .await;
    assert_eq!(s, StatusCode::CONFLICT);

    // Mitigate needs 2FA.
    let mut pol = asset["policy"].clone();
    pol["mode"] = json!("mitigate");
    pol["syncookies"] = json!(true);
    let (s, b) = owner
        .call(
            Method::PUT,
            &format!("/tenants/{t}/assets/{aid}/policy"),
            Some(pol.clone()),
        )
        .await;
    assert_eq!(
        (s, b["error"].as_str()),
        (StatusCode::FORBIDDEN, Some("mfa_required"))
    );
    owner.enable_totp("owner@o.test").await;
    let (s, updated) = owner
        .call(
            Method::PUT,
            &format!("/tenants/{t}/assets/{aid}/policy"),
            Some(pol),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{updated}");
    assert!(
        updated["config_version"].as_i64() > asset["config_version"].as_i64(),
        "version bumped"
    );
    let doc = lab
        .outbox("tenants", &format!("asset.{aid}"))
        .await
        .unwrap();
    assert_eq!(doc["policy"]["mode"], "mitigate");
    assert_eq!(doc["version"], updated["config_version"]);

    // Rules: limits and validation.
    for (body, code) in [
        (
            json!({"kind": "block", "prefix": "0.0.0.0/0", "ttl_seconds": 60}),
            "prefix_too_wide",
        ),
        (
            json!({"kind": "block", "prefix": "203.0.0.0/8", "ttl_seconds": 60}),
            "prefix_too_wide",
        ),
        (
            json!({"kind": "block", "prefix": "203.0.113.0/24"}),
            "ttl_required",
        ),
        (
            json!({"kind": "deny", "prefix": "203.0.113.0/24", "ttl_seconds": 60}),
            "invalid_kind",
        ),
        (
            json!({"kind": "allow", "prefix": "203.0.113.7/24"}),
            "invalid_prefix",
        ),
    ] {
        let (s, b) = owner
            .call(
                Method::POST,
                &format!("/tenants/{t}/rules"),
                Some(body.clone()),
            )
            .await;
        assert_eq!(
            (s, b["error"].as_str()),
            (StatusCode::BAD_REQUEST, Some(code)),
            "{body}"
        );
    }
    let (s, rule) = owner.call(Method::POST, &format!("/tenants/{t}/rules"),
        Some(json!({"kind": "block", "prefix": "203.0.113.0/24", "ttl_seconds": 600, "reason": "flood"}))).await;
    assert_eq!(s, StatusCode::CREATED, "{rule}");
    let rules = lab.outbox("rules", &format!("tenant.{t}")).await.unwrap();
    let r: RulesDoc = parse_doc(rules.to_string().as_bytes()).unwrap();
    let (tenant, allow, block) = r.validate(&format!("tenant.{t}")).unwrap();
    assert_eq!((tenant as i64, allow.len(), block.len()), (t, 0, 1));

    // API keys: owners with 2FA only; scopes enforced; tenant-bound.
    let (s, b) = admin
        .call(
            Method::POST,
            &format!("/tenants/{t}/api-keys"),
            Some(json!({"scopes": ["read"]})),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{b}");
    let (s, k) = owner
        .call(
            Method::POST,
            &format!("/tenants/{t}/api-keys"),
            Some(json!({"name": "ci", "scopes": ["read"]})),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{k}");
    let key = k["key"].as_str().unwrap().to_string();
    assert!(key.starts_with("xs_"));
    let (_, keys) = owner
        .call(Method::GET, &format!("/tenants/{t}/api-keys"), None)
        .await;
    assert!(!keys.to_string().contains(&key), "keys are shown once");
    let mut bot = lab.client();
    bot.bearer = Some(key.clone());
    let (s, _) = bot
        .call(Method::GET, &format!("/tenants/{t}/assets"), None)
        .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = bot
        .call(
            Method::POST,
            &format!("/tenants/{t}/rules"),
            Some(json!({"kind": "allow", "prefix": "192.0.2.0/24"})),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "read key cannot write");
    let (s, _) = bot
        .call(Method::GET, &format!("/tenants/{}/assets", t + 1000), None)
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND, "keys are tenant-bound");
    let (s, _) = bot
        .call(Method::GET, &format!("/tenants/{t}/audit"), None)
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "keys never act as owner");
    let (s, w) = owner
        .call(
            Method::POST,
            &format!("/tenants/{t}/api-keys"),
            Some(json!({"scopes": ["read", "write"]})),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED);
    bot.bearer = Some(w["key"].as_str().unwrap().to_string());
    let (s, _) = bot
        .call(
            Method::POST,
            &format!("/tenants/{t}/rules"),
            Some(json!({"kind": "allow", "prefix": "192.0.2.0/24"})),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "write key can create rules");
    let (s, _) = bot
        .call(
            Method::POST,
            &format!("/tenants/{t}/api-keys"),
            Some(json!({"scopes": ["read"]})),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let kid = k["id"].as_i64().unwrap();
    owner
        .call(
            Method::DELETE,
            &format!("/tenants/{t}/api-keys/{kid}"),
            None,
        )
        .await;
    bot.bearer = Some(key);
    let (s, _) = bot
        .call(Method::GET, &format!("/tenants/{t}/assets"), None)
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "deleted keys stop working");
    let hashed: i64 =
        sqlx::query_scalar("SELECT count(*) FROM api_keys WHERE key_hash LIKE 'xs_%'")
            .fetch_one(&lab.su)
            .await
            .unwrap();
    assert_eq!(hashed, 0, "keys are stored hashed");

    // Audit trail.
    let (s, log) = owner
        .call(Method::GET, &format!("/tenants/{t}/audit"), None)
        .await;
    assert_eq!(s, StatusCode::OK);
    let actions: Vec<&str> = log
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["action"].as_str().unwrap())
        .collect();
    for a in [
        "asset.create",
        "policy.update",
        "rule.create",
        "api_key.create",
        "api_key.delete",
        "member.add",
    ] {
        assert!(actions.contains(&a), "audit lacks {a}: {actions:?}");
    }
    let res = sqlx::query("UPDATE audit_log SET action = 'x'")
        .execute(&lab.api_pool)
        .await;
    assert!(res.is_err(), "the API role cannot rewrite the audit log");

    // Owner deletes the asset: KV delete documents are queued.
    let (s, _) = owner
        .call(Method::DELETE, &format!("/tenants/{t}/assets/{aid}"), None)
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert!(
        lab.outbox("tenants", &format!("asset.{aid}"))
            .await
            .is_none(),
        "latest outbox entry is a delete"
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL: run with `make test-api`"]
async fn admin_and_public_status() {
    let lab = Lab::new().await;
    let (mut c, _) = lab.customer("ops@p.test").await;
    let (s, _) = c.call(Method::GET, "/admin/pops", None).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    sqlx::query("UPDATE users SET is_platform_admin = true WHERE email = 'ops@p.test'")
        .execute(&lab.su)
        .await
        .unwrap();
    let (s, _) = c.call(Method::GET, "/admin/pops", None).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "admins need 2FA");
    c.enable_totp("ops@p.test").await;
    sqlx::query("INSERT INTO pops (id, region, unicast_ip, last_seen) VALUES ('lab1', 'eu', '10.10.1.1', now())")
        .execute(&lab.su).await.unwrap();
    let (s, pops) = c.call(Method::GET, "/admin/pops", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(pops[0]["status"], "up");
    let (s, tenants) = c.call(Method::GET, "/admin/tenants", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(tenants.as_array().unwrap().len(), 1);
    let (s, k) = c
        .call(
            Method::POST,
            "/admin/killswitch",
            Some(json!({"observe": true})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{k}");
    let doc = lab.outbox("platform", "global").await.unwrap();
    assert_eq!(doc["observe"], true);

    let (s, st) = lab.client().call(Method::GET, "/status", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(st["pops"][0]["id"], "lab1");
    assert!(
        st["pops"][0].get("unicast_ip").is_none(),
        "public status hides addresses"
    );
}

/// Phase 6: the live WebSocket only ever carries the caller's tenant, and
/// refuses other origins and other tenants.
#[tokio::test]
#[ignore = "needs PostgreSQL: run with `make test-api`"]
async fn live_view_is_per_tenant() {
    use futures::StreamExt;
    use sentinel_common::msg::{StatsMsg, StatsRow, SCHEMA_V};
    use tokio_tungstenite::tungstenite::{client::IntoClientRequest, Message};

    let lab = Lab::new().await;
    let (a, ta) = lab.customer("live-a@a.test").await;
    let (_b, tb) = lab.customer("live-b@b.test").await;
    let row = |tenant: i64, verdict: &str, pps: f64| StatsRow {
        tenant: tenant as u32,
        verdict: verdict.into(),
        pkts: 1,
        bytes: 1,
        pps,
        bps: pps * 8000.0,
    };
    lab.live.update(StatsMsg {
        kind: "stats".into(),
        v: SCHEMA_V,
        pop: "lab1".into(),
        ts: 0,
        interval_ms: 1000,
        sample_rate: 1,
        events_lost: 0,
        entries: vec![
            row(ta, "pass", 12.0),
            row(ta, "drop_block", 3.0),
            row(tb, "pass", 777.0),
        ],
    });

    let ws_url = |tid: i64| format!("{}/tenants/{tid}/live", lab.base.replacen("http", "ws", 1));
    let connect = |tid: i64, origin: &'static str, cookie: Option<String>| {
        let mut req = ws_url(tid).into_client_request().unwrap();
        req.headers_mut().insert("origin", origin.parse().unwrap());
        if let Some(c) = cookie {
            req.headers_mut()
                .insert("cookie", format!("xs_session={c}").parse().unwrap());
        }
        tokio_tungstenite::connect_async(req)
    };

    let (mut ws, _) = connect(ta, "https://portal.test", a.cookie.clone())
        .await
        .expect("own tenant");
    let frame = loop {
        match ws.next().await.unwrap().unwrap() {
            Message::Text(t) => break serde_json::from_str::<serde_json::Value>(&t).unwrap(),
            _ => continue,
        }
    };
    assert_eq!(frame["total"]["in_pps"], 15.0, "{frame}");
    assert_eq!(frame["total"]["filtered_pps"], 3.0);
    assert_eq!(frame["pops"][0]["pop"], "lab1");
    assert!(
        !frame.to_string().contains("777"),
        "other tenant leaked: {frame}"
    );

    let status = |r: Result<_, tokio_tungstenite::tungstenite::Error>| match r {
        Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => resp.status().as_u16(),
        Err(e) => panic!("{e}"),
        Ok(_) => 101,
    };
    assert_eq!(
        status(connect(tb, "https://portal.test", a.cookie.clone()).await),
        404
    );
    assert_eq!(
        status(connect(ta, "https://evil.test", a.cookie.clone()).await),
        403
    );
    assert_eq!(status(connect(ta, "https://portal.test", None).await), 401);
}

/// Phase 6: passkey endpoints, the tunnel test and the TOTP/passkey split.
#[tokio::test]
#[ignore = "needs PostgreSQL: run with `make test-api`"]
async fn passkeys_and_tunnel_test() {
    let lab = Lab::new().await;
    let (mut a, ta) = lab.customer("pk-a@a.test").await;
    let (mut b, _) = lab.customer("pk-b@b.test").await;

    // Registration options name the portal as relying party and carry a
    // random user handle, not the e-mail or the database id.
    let (s, opts) = a
        .call(Method::POST, "/auth/webauthn/register/start", None)
        .await;
    assert_eq!(s, StatusCode::OK, "{opts}");
    assert_eq!(opts["publicKey"]["rp"]["id"], "portal.test");
    let challenge = opts["publicKey"]["challenge"].as_str().unwrap().to_string();
    assert!(challenge.len() >= 32);
    let uid = opts["publicKey"]["user"]["id"].as_str().unwrap();
    assert!(!uid.contains("pk-a") && uid.len() > 8);
    // A new start replaces the challenge; the state is stored encrypted.
    let (_, opts2) = a
        .call(Method::POST, "/auth/webauthn/register/start", None)
        .await;
    assert_ne!(opts2["publicKey"]["challenge"].as_str().unwrap(), challenge);
    let stored: Vec<u8> = sqlx::query_scalar("SELECT state FROM webauthn_challenges")
        .fetch_one(&lab.su)
        .await
        .unwrap();
    assert!(!String::from_utf8_lossy(&stored).contains(&challenge));

    // A forged credential is rejected and consumes the challenge.
    let fake = json!({"name": "x", "credential": {
        "id": "AAAA", "rawId": "AAAA", "type": "public-key",
        "response": {"attestationObject": "AAAA", "clientDataJSON": "AAAA"}}});
    let (s, b2) = a
        .call(
            Method::POST,
            "/auth/webauthn/register/finish",
            Some(fake.clone()),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{b2}");
    let (s, b2) = a
        .call(Method::POST, "/auth/webauthn/register/finish", Some(fake))
        .await;
    assert_eq!(
        (s, b2["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("no_challenge"))
    );

    // No passkeys yet: nothing to log in with; TOTP verify without TOTP fails.
    let (s, e) = a
        .call(Method::POST, "/auth/webauthn/login/start", None)
        .await;
    assert_eq!(
        (s, e["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("no_passkeys"))
    );
    let (s, e) = a
        .call(
            Method::POST,
            "/auth/2fa/verify",
            Some(json!({"code": "000000"})),
        )
        .await;
    assert_eq!(
        (s, e["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("no_totp"))
    );
    let (s, list) = a
        .call(Method::GET, "/auth/webauthn/credentials", None)
        .await;
    assert_eq!((s, list), (StatusCode::OK, json!([])));
    let (s, _) = a
        .call(Method::DELETE, "/auth/webauthn/credentials/1", None)
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // Tunnel test: without NATS the API says so; other tenants get 404.
    let (_, asset) = a
        .call(
            Method::POST,
            &format!("/tenants/{ta}/assets"),
            Some(json!({"origin_ip": "192.0.2.10", "services": []})),
        )
        .await;
    let aid = asset["id"].as_i64().unwrap();
    let path = format!("/tenants/{ta}/assets/{aid}/tunnel-test");
    let (s, e) = b.call(Method::POST, &path, None).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{e}");
    let (s, e) = a.call(Method::POST, &path, None).await;
    assert_eq!(
        (s, e["error"].as_str()),
        (StatusCode::SERVICE_UNAVAILABLE, Some("unavailable"))
    );
    let (s, _) = a.call(Method::POST, &path, None).await;
    assert_eq!(
        s,
        StatusCode::TOO_MANY_REQUESTS,
        "one test per asset every 5 s"
    );
    let resp = a.raw(Method::POST, &path, None, false).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "CSRF still applies");

    // Passkey challenges are bound to the session: logging out removes them.
    let _ = a
        .call(Method::POST, "/auth/webauthn/register/start", None)
        .await;
    let (s, _) = a.call(Method::POST, "/auth/logout", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM webauthn_challenges")
        .fetch_one(&lab.su)
        .await
        .unwrap();
    assert_eq!(left, 0);
    let _ = PASSWORD;
    let _ = totp;
}
