// SPDX-License-Identifier: MIT OR Apache-2.0
//! The committed OpenAPI document (docs/openapi.json) is what the web app's
//! client is generated from: it must match the code. Regenerate with
//! `UPDATE_OPENAPI=1 cargo test -p sentinel-api --test openapi`.

#[test]
fn openapi_snapshot_is_current() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/openapi.json");
    let current = sentinel_api::openapi_json() + "\n";
    if std::env::var_os("UPDATE_OPENAPI").is_some() {
        std::fs::write(path, &current).unwrap();
    }
    let committed = std::fs::read_to_string(path).unwrap_or_default();
    assert!(
        committed == current,
        "docs/openapi.json is stale: run with UPDATE_OPENAPI=1"
    );
}

#[test]
fn openapi_covers_the_spec_endpoints() {
    let doc: serde_json::Value = serde_json::from_str(&sentinel_api::openapi_json()).unwrap();
    let paths = doc["paths"].as_object().unwrap();
    for p in [
        "/api/v1/auth/login",
        "/api/v1/auth/signup",
        "/api/v1/auth/2fa/verify",
        "/api/v1/me",
        "/api/v1/tenants/{tid}/assets",
        "/api/v1/tenants/{tid}/assets/{aid}/tunnel",
        "/api/v1/tenants/{tid}/assets/{aid}/status",
        "/api/v1/tenants/{tid}/assets/{aid}/policy",
        "/api/v1/tenants/{tid}/rules",
        "/api/v1/tenants/{tid}/users",
        "/api/v1/tenants/{tid}/api-keys",
        "/api/v1/tenants/{tid}/audit",
        "/api/v1/status",
        "/api/v1/admin/pops",
        "/api/v1/admin/killswitch",
    ] {
        assert!(paths.contains_key(p), "missing {p}");
    }
    assert!(doc["components"]["securitySchemes"]["session"].is_object());
}
