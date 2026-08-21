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
        window.contains("#[memoize"),
        "org_context must be annotated with #[memoize]"
    );
    assert!(
        src.contains("org_context(cx,"),
        "require_org must call memoized org_context"
    );
}

#[test]
fn inv_admin_compose_forms_use_post() {
    for rel in [
        "src/app/admin/docs/new.rs",
        "src/app/admin/releases/new.rs",
        "src/app/admin/companies/form.rs",
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
fn inv_portal_role_closed_catalogue() {
    let models = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/models/mod.rs"));
    assert!(models.contains("PORTAL_ROLE_ORG"));
    assert!(models.contains("fn is_allowed_portal_role"));
    assert!(
        !models.contains("Empty for client"),
        "client portal_role must be org, not empty string docs"
    );
    let mig = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/toasty/migrations/0007_portal_role_org_check.sql"
    ));
    assert!(mig.contains("users_portal_role_check"));
    assert!(mig.contains("'admin'") && mig.contains("'org'"));
}

#[test]
fn inv_login_uses_magic_link_and_limiter() {
    let login = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/app/login.rs"));
    assert!(login.contains("issue_token"));
    assert!(login.contains("consume_token"));
    assert!(login.contains("LoginRateLimiter"));
    assert!(!login.contains("verify_login_password"));
    assert!(!login.contains("password_hash"));
    let default_toml = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/config/default.toml"));
    assert!(default_toml.contains("[login]"));
    assert!(default_toml.contains("max_attempts"));
    assert!(default_toml.contains("[magiclinks]"));
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
        src.contains("OriginPolicy") && src.contains("trust_origins"),
        "router must trust configured public_origins via OriginPolicy"
    );
    assert!(
        src.contains("max_request_body") && src.contains("BodyLimit"),
        "router must apply configurable BodyLimit"
    );
    assert!(
        !src.contains("dangerous_disable_origin_verification")
            && !src.contains("dangerous_disable()"),
        "OriginPolicy must stay enabled (no CSRF bypass switch)"
    );
    let conf = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/config/vcp.conf"));
    let default = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/config/default.toml"));
    let testing = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/config/testing.toml"));
    for (label, body) in [
        ("vcp.conf", conf),
        ("default.toml", default),
        ("testing.toml", testing),
    ] {
        assert!(
            !body.contains("dangerous_disable_origin_verification"),
            "{label} must not expose Origin verification bypass"
        );
    }
}

#[test]
fn inv_tracked_perms_match_vcp_policy_csv() {
    let store = PolicyStore::load_from_csv(PolicyStore::default_path()).unwrap();
    for &(resource, action) in TRACKED_PERMS {
        let granted =
            store.allows("admin", resource, action) || store.allows("org", resource, action);
        assert!(
            granted,
            "tracked permission {resource}:{action} missing from vcp_policy.csv grants"
        );
    }
}

#[test]
fn inv_session_entry_redirects_via_post_auth_landing() {
    let app = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/app.rs"));
    assert!(
        app.contains("post_auth_landing"),
        "GET / must land authenticated users via post_auth_landing"
    );
    let login = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/app/login.rs"));
    assert!(
        login.contains("post_auth_landing"),
        "GET /login must redirect authenticated users via post_auth_landing"
    );
    assert!(
        login.contains("/choose-org"),
        "login module must expose /choose-org multi-org picker"
    );
    assert!(
        !login.contains("Continue to portal"),
        "login must not offer a Continue to portal button"
    );
    let auth = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/auth.rs"));
    assert!(
        auth.contains("fn classify_post_auth_landing"),
        "pure classify_post_auth_landing must exist for unit/proptest coverage"
    );
    assert!(
        auth.contains("fn resolve_home_org_slug"),
        "pure resolve_home_org_slug must exist for unit/proptest coverage"
    );
    assert!(
        auth.contains("enum PostAuthLanding"),
        "PostAuthLanding enum must exist"
    );
}

/// Slice from `marker` through the matching close brace of the function body.
fn fn_body<'a>(src: &'a str, marker: &str) -> &'a str {
    let start = src
        .find(marker)
        .unwrap_or_else(|| panic!("missing {marker}"));
    let rest = &src[start..];
    let open = rest
        .find('{')
        .unwrap_or_else(|| panic!("{marker}: missing '{{'"));
    let mut depth = 0usize;
    for (i, ch) in rest[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return &rest[..open + i + 1];
                }
            }
            _ => {}
        }
    }
    panic!("{marker}: unbalanced braces");
}

#[test]
fn inv_get_navigational_redirects_use_redirect_not_see_other() {
    let app = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/app.rs"));
    let root = fn_body(app, "async fn root(cx");
    assert!(
        root.contains("Err(redirect(") && !root.contains("see_other"),
        "GET / must Err(redirect(...)), not see_other"
    );
    let admin = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/app/admin.rs"));
    let hub = fn_body(admin, "async fn admin_index");
    assert!(
        hub.contains("Err(redirect(") && !hub.contains("see_other"),
        "GET /admin must Err(redirect(...)), not see_other"
    );
    let issues = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/org/issues.rs"
    ));
    let list = fn_body(issues, "async fn redirect_reserved_issues_list");
    assert!(
        list.contains("Err(redirect(") && !list.contains("see_other"),
        "GET /vauban/issues must Err(redirect(...))"
    );
    let create = fn_body(issues, "async fn redirect_reserved_issues_create");
    assert!(
        create.contains("see_other") && !create.contains("Err(redirect("),
        "POST /vauban/issues alias must keep see_other (303)"
    );
}

#[test]
fn inv_policy_csv_roles_use_role_prefix() {
    let csv = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/config/access/vcp_policy.csv"
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

/// Audit F1 option B: no Casbin engine artifacts; CSV + PolicyStore only.
#[test]
fn inv_no_casbin_model_conf_or_model_path() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let model = root.join("config/access/model.conf");
    assert!(
        !model.exists(),
        "config/access/model.conf must stay deleted (PolicyStore loads CSV only)"
    );
    assert!(
        root.join("config/access/vcp_policy.csv").is_file(),
        "config/access/vcp_policy.csv must exist"
    );
    assert!(
        !root.join("config/access/default_policy.csv").exists(),
        "legacy default_policy.csv must stay removed"
    );
    let access_cfg = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/config.rs"));
    assert!(
        access_cfg.contains("struct AccessConfig"),
        "AccessConfig must remain in src/config.rs"
    );
    assert!(
        !access_cfg.contains("model_path"),
        "AccessConfig must not expose model_path"
    );
    for path in [
        "config/default.toml",
        "config/development.toml",
        "config/vcp.conf",
    ] {
        let body =
            std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(path))
                .unwrap_or_else(|e| panic!("read {path}: {e}"));
        assert!(
            !body.contains("model_path"),
            "{path} must not set access.model_path"
        );
        assert!(
            !body.contains("model.conf"),
            "{path} must not reference model.conf"
        );
    }
}
