//! Source-shape invariants for auth / tenant / Casbin gates.

use std::process::Command;

use vcp::perms::{PolicyStore, TRACKED_PERMS};

#[test]
fn inv_check_auth_tenant_script() {
    let output = Command::new("bash")
        .arg("scripts/check_auth_tenant.sh")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run check_auth_tenant.sh");
    assert!(
        output.status.success(),
        "scripts/check_auth_tenant.sh failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn inv_require_org_maps_unauthenticated_to_not_found() {
    let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/auth.rs"));
    assert!(
        src.contains("require_auth(cx).await.ok()?")
            || src.contains("Err(_) => return Err(not_found())"),
        "org_context must map auth failure to None / not_found (anti-enumeration)"
    );
    assert!(
        src.contains("ok_or_else(not_found)"),
        "require_org must 404 missing org / membership"
    );
}

#[test]
fn inv_require_org_is_memoized() {
    let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/auth.rs"));
    assert!(
        src.contains("async fn org_context"),
        "memoized org_context helper must exist"
    );
    let fn_idx = src.find("async fn org_context").expect("org_context fn");
    let window = &src[fn_idx.saturating_sub(80)..fn_idx];
    assert!(
        window.contains("#[memoize]"),
        "org_context must be annotated with #[memoize]"
    );
    assert!(
        src.contains("org_context(cx, slug)"),
        "require_org must call memoized org_context"
    );
}

#[test]
fn inv_admin_compose_forms_use_post() {
    for rel in [
        "src/app/admin/docs/new.rs",
        "src/app/admin/releases/new.rs",
        "src/app/admin/companies/new.rs",
    ] {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
        let src = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {rel}: {e}"));
        assert!(
            src.contains("method=\"POST\""),
            "{rel} must POST compose forms"
        );
        assert!(
            !src.contains("method=\"GET\""),
            "{rel} must not GET compose forms"
        );
    }
}

#[test]
fn inv_admin_nest_checks_admin_view() {
    let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/app/admin.rs"));
    assert!(
        src.contains("require_staff"),
        "admin nest must gate via require_staff"
    );
    let auth = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/auth.rs"));
    assert!(
        auth.contains("require_admin_view"),
        "require_staff must enforce admin_view via require_admin_view"
    );
}

#[test]
fn inv_capability_denied_helper_exists() {
    let auth = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/auth.rs"));
    assert!(
        auth.contains("pub fn capability_denied"),
        "capability_denied must be public for entry gates"
    );
}

#[test]
fn inv_reserved_org_staff_only_in_org_context() {
    let auth = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/auth.rs"));
    let start = auth.find("async fn org_context").expect("org_context");
    let body = &auth[start..start + 800.min(auth.len() - start)];
    assert!(
        body.contains("RESERVED_ORG_SLUG") && body.contains("PORTAL_ROLE_ADMIN"),
        "org_context must gate reserved org to staff"
    );
}

#[test]
fn inv_login_uses_verify_login_password_and_limiter() {
    let login = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/app/login.rs"));
    assert!(login.contains("verify_login_password"));
    assert!(login.contains("LoginRateLimiter"));
    let default_toml = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/config/default.toml"));
    assert!(default_toml.contains("[login]"));
    assert!(default_toml.contains("max_attempts"));
}

#[test]
fn inv_require_org_admin_not_forbidden() {
    let auth = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/auth.rs"));
    let start = auth
        .find("pub async fn require_org_admin")
        .expect("require_org_admin");
    let rest = &auth[start..];
    let end = rest[1..]
        .find("\npub async fn ")
        .map(|i| i + 1)
        .unwrap_or(rest.len());
    let body = &rest[..end];
    assert!(
        !body.contains("forbidden()"),
        "require_org_admin must not remap to forbidden"
    );
}

#[test]
fn inv_require_staff_maps_denials_to_not_found() {
    let auth = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/auth.rs"));
    let start = auth
        .find("pub async fn require_staff")
        .expect("require_staff");
    let rest = &auth[start..];
    let end = rest[1..]
        .find("\npub async fn ")
        .map(|i| i + 1)
        .unwrap_or(rest.len());
    let body = &rest[..end];
    assert!(
        body.contains("not_found()"),
        "require_staff must 404 on denial"
    );
    assert!(
        !body.contains("forbidden()"),
        "require_staff must not 403 (anti-enumeration for /admin/*)"
    );
}

#[test]
fn inv_router_trusts_public_origins() {
    let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/app.rs"));
    assert!(
        src.contains("trust_origin"),
        "router must trust configured public_origins"
    );
    assert!(
        src.contains("dangerous_disable_origin_verification"),
        "session Origin bypass must be explicit"
    );
}

#[test]
fn inv_tracked_perms_match_default_policy_csv() {
    let store = PolicyStore::load_from_csv(PolicyStore::default_path()).unwrap();
    for &(resource, action) in TRACKED_PERMS {
        let granted =
            store.allows("admin", resource, action) || store.allows("org", resource, action);
        assert!(
            granted,
            "tracked permission {resource}:{action} missing from default_policy.csv grants"
        );
    }
}

#[test]
fn inv_session_entry_redirects_via_home_org_slug() {
    let app = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/app.rs"));
    assert!(
        app.contains("home_org_slug"),
        "GET / must land authenticated users via home_org_slug"
    );
    let login = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/app/login.rs"));
    assert!(
        login.contains("home_org_slug"),
        "GET /login must redirect authenticated users via home_org_slug"
    );
    assert!(
        !login.contains("Continue to portal"),
        "login must not offer a Continue to portal button"
    );
    let auth = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/auth.rs"));
    assert!(
        auth.contains("fn resolve_home_org_slug"),
        "pure resolve_home_org_slug must exist for unit/proptest coverage"
    );
}

#[test]
fn inv_policy_csv_roles_use_role_prefix() {
    let csv = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/config/access/default_policy.csv"
    ));
    for line in csv.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<_> = line.split(',').map(str::trim).collect();
        assert_eq!(parts[0], "p");
        assert!(
            parts[1].starts_with("role:"),
            "policy subject must be role:* (got {})",
            parts[1]
        );
    }
}
