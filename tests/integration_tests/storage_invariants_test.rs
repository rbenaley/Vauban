//! Source-shape invariants for the storage helper (architecture 1.2).

use std::process::Command;

#[test]
fn inv_check_storage_script() {
    let output = Command::new("bash")
        .arg("scripts/check_storage.sh")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run check_storage.sh");
    assert!(
        output.status.success(),
        "scripts/check_storage.sh failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn inv_release_model_has_no_digest_columns() {
    let models = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/models/mod.rs"));
    let release = models
        .split("pub struct Release")
        .nth(1)
        .and_then(|s| s.split("pub struct ").next())
        .expect("Release struct");
    assert!(
        !release.contains("pub sha256"),
        "Release must not expose sha256 (digests live in helper SQLite + Postgres mirror)"
    );
    assert!(
        !release.contains("pub size_mb"),
        "Release must not expose size_mb (digests live in helper SQLite + Postgres mirror)"
    );
    assert!(models.contains("struct StorageObject"));
    assert!(models.contains("mirror") || models.contains("SoT"));
    assert!(models.contains("STORAGE_SCOPE_RELEASE"));
    assert!(models.contains("STORAGE_SCOPE_IMAGE"));
}

#[test]
fn inv_meta_sqlite_sot_and_verify_on_read() {
    let meta = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/storage/meta_db.rs"
    ));
    assert!(meta.contains("meta.sqlite"));
    assert!(meta.contains("CREATE TABLE IF NOT EXISTS objects"));

    let engine = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/storage/engine.rs"
    ));
    assert!(engine.contains("get_verified"));
    assert!(engine.contains("IntegrityMismatch"));
    assert!(engine.contains("MetaDb"));

    let proto = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/storage/protocol.rs"
    ));
    let get = proto.split("Get {").nth(1).expect("Get variant");
    assert!(
        get.contains("sha256: String"),
        "IPC Get must require expected sha256"
    );

    let dl = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/org/builds/download.rs"
    ));
    assert!(dl.contains("INTEGRITY_MISMATCH") || dl.contains("integrity mismatch"));
    assert!(dl.contains("obj.sha256"));
}

#[test]
fn inv_download_uses_storage_objects_not_501() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/org/builds/download.rs"
    ));
    assert!(src.contains("find_release_object"));
    assert!(src.contains("DOWNLOAD_UNAVAILABLE"));
    assert!(src.contains("get_release"));
    assert!(src.contains("X-Content-Type-Options"));
    assert!(!src.contains("NOT_IMPLEMENTED"));
    assert!(!src.contains("download not configured"));
}

#[test]
fn inv_image_routes_gate_before_ipc() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/org/images.rs"
    ));
    assert!(src.contains("find_image_object"));
    assert!(src.contains("require_org"));
    assert!(src.contains("X-Content-Type-Options"));
    assert!(src.contains("normalize_image_ext"));
    assert!(src.contains("is_uuid_key"));
    // Lookup must precede get_image in source order.
    let find = src.find("find_image_object").expect("find_image_object");
    let get = src.find("get_image").expect("get_image");
    assert!(find < get, "DB lookup must happen before IPC get_image");
}

#[test]
fn inv_vcp_store_pins_peercred_and_capsicum() {
    let bin = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bin/vcp_store.rs"));
    assert!(bin.contains("peer_uid"));
    assert!(bin.contains("peercred failed") || bin.contains("reject peer uid"));
    assert!(bin.contains("enter_capability_mode"));

    let cap = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/storage/capsicum.rs"
    ));
    assert!(cap.contains("cap_enter"));
    assert!(cap.contains("enter_capability_mode"));

    let ipc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/storage/ipc.rs"));
    assert!(ipc.contains("fn peer_uid"));
}

#[test]
fn inv_production_conf_is_socket_mode() {
    let conf = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/config/vcp.conf"));
    assert!(conf.contains("ipc = \"socket\""));
    assert!(conf.contains("socket_path = \"/var/run/vcp/store.sock\""));
    assert!(
        !conf
            .lines()
            .any(|l| l.trim_start().starts_with("blob_path")),
        "vcp.conf must not set blob_path (helper conf owns it)"
    );

    let store = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/config/vcp-store.conf"
    ));
    assert!(store.contains("blob_path = \"/var/db/vcp/storage\""));
    assert!(store.contains("listen = \"/var/run/vcp/store.sock\""));
}

#[test]
fn inv_webauthn_12_and_adrs_pinned() {
    let store = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/config/vcp-store.conf"
    ));
    assert!(store.contains("webauthn_required = true"));
    assert!(store.contains("webauthn_strict_sign_count = false"));
    assert!(store.contains("webauthn_user_verification = \"required\""));

    let err = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/storage/error.rs"));
    for code in [
        "webauthn_required",
        "webauthn_invalid",
        "webauthn_expired",
        "challenge_unknown",
        "object_modified",
    ] {
        assert!(err.contains(code), "missing {code}");
    }

    let bin = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bin/vcp_store.rs"));
    assert!(bin.contains("ctap2"));
    assert!(bin.contains("approve"));
    assert!(bin.contains("validate_production_webauthn"));

    assert!(
        std::path::Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/adr/002-storage-webauthn-ceremony-channel-c1.md"
        ))
        .is_file()
    );
    assert!(
        std::path::Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/adr/003-ctap2-enrol-revoke-asymmetry.md"
        ))
        .is_file()
    );
    assert!(
        std::path::Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/adr/004-webauthn-sign-count-policy.md"
        ))
        .is_file()
    );
    assert!(
        std::path::Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/technical/VCP_Storage_Helper_Architecture_EN(1.2).md"
        ))
        .is_file()
    );

    let confirm = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/releases/confirm.rs"
    ));
    assert!(confirm.contains("vcp-webauthn-summary"));
    assert!(confirm.contains("vcp-store ctap2 pending"));
}

/// §6.5 / ADR 003 dashboard contract: fingerprint at E1, CLI approve
/// instructions, pending cross-check hint, Casbin gate, typed revoke confirm.
#[test]
fn inv_ctap2_dashboard_ui_pinned() {
    let page = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/ctap2.rs"
    ));
    assert!(page.contains("perms.ctap2_manage"), "Casbin gate");
    assert!(
        page.contains("vcp-ctap2-fingerprint"),
        "E1 fingerprint block"
    );
    assert!(
        page.contains("ctap2 approve --fingerprint"),
        "CLI approve command (E2)"
    );
    assert!(
        page.contains("VCP_ENVIRONMENT=development"),
        "dev spawn approve command must set VCP_ENVIRONMENT"
    );
    assert!(
        page.contains("vcp-store ctap2 pending"),
        "helper-host cross-check hint"
    );
    assert!(
        page.contains("!= \"revoke\""),
        "typed confirmation gates ctap2_revoke"
    );
    assert!(page.contains("data-mode=\"create\""), "E1 ceremony root");
    assert!(
        page.contains("https://localhost:3000"),
        "dev hint: WebAuthn requires localhost, not 127.0.0.1"
    );

    let rail = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/_components/rail.rs"
    ));
    assert!(
        rail.contains("ico_key(cx"),
        "rail must use the dedicated key icon for /admin/ctap2"
    );

    let js = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/assets/vcp_webauthn.js"
    ));
    assert!(
        js.contains("cannot run on an IP address"),
        "ceremony JS must reject IP hosts before navigator.credentials"
    );
}

#[test]
fn inv_normalize_image_ext_and_uuid_exported() {
    assert_eq!(vcp::storage::normalize_image_ext("JPG"), Some("jpeg"));
    assert_eq!(vcp::storage::normalize_image_ext("png"), Some("png"));
    assert_eq!(vcp::storage::normalize_image_ext("webp"), Some("webp"));
    assert_eq!(vcp::storage::normalize_image_ext("svg"), None);
    assert!(vcp::storage::is_uuid_key(
        "550e8400-e29b-41d4-a716-446655440000"
    ));
    assert!(!vcp::storage::is_uuid_key("../x"));
}
