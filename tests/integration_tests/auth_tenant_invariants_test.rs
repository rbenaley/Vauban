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
        "src/app/org/admin/docs/new.rs",
        "src/app/org/admin/releases/new.rs",
        "src/app/org/admin/companies/new.rs",
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
    let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/app/org/admin.rs"));
    assert!(
        src.contains("admin_view"),
        "admin nest must gate on admin_view"
    );
    assert!(
        src.contains("forbidden()"),
        "admin nest must fail closed with forbidden"
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
            store.allows("admin", resource, action) || store.allows("member", resource, action);
        assert!(
            granted,
            "tracked permission {resource}:{action} missing from default_policy.csv grants"
        );
    }
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
