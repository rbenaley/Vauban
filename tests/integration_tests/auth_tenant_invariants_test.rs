//! Source-shape invariants for auth / tenant / Casbin gates.

use std::process::Command;

use vcp::perms::{PolicyStore, TRACKED_PERMS};

#[test]
fn inv_check_auth_tenant_script() {
    let status = Command::new("bash")
        .arg("scripts/check_auth_tenant.sh")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .status()
        .expect("run check_auth_tenant.sh");
    assert!(status.success(), "scripts/check_auth_tenant.sh failed");
}

#[test]
fn inv_require_org_maps_unauthenticated_to_not_found() {
    let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/auth.rs"));
    assert!(
        src.contains("Err(_) => return Err(not_found())"),
        "require_org must map auth failure to not_found (anti-enumeration)"
    );
    assert!(
        src.contains("ok_or_else(not_found)"),
        "require_org must 404 missing org / membership"
    );
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
