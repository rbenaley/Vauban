//! Source-shape invariants for the storage helper (architecture 1.0).

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
        "Release must not expose sha256 (storage_objects SoT)"
    );
    assert!(
        !release.contains("pub size_mb"),
        "Release must not expose size_mb (storage_objects SoT)"
    );
    assert!(models.contains("struct StorageObject"));
    assert!(models.contains("STORAGE_SCOPE_RELEASE"));
    assert!(models.contains("STORAGE_SCOPE_IMAGE"));
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
    assert!(conf.contains("blob_path = \"/var/db/vcp/storage\""));
    assert!(conf.contains("socket_path = \"/var/run/vcp/store.sock\""));
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
