//! Supervisor-side recording delete tests (filesystem + path validation).

use std::fs;

use shared::recording_paths::{
    delete_recording_storage_path, recording_root_relative, validate_recording_delete_relative_path,
};
use uuid::Uuid;

#[test]
fn delete_recording_directory_removes_all_files() {
    let base = tempfile::tempdir().expect("tempdir");
    let uuid = Uuid::new_v4();
    let rel = format!("2026/05/{uuid}/");
    let dir = base.path().join(&rel);
    fs::create_dir_all(&dir).expect("mkdir");
    fs::write(dir.join("session.cast"), b"cast-data").expect("write cast");
    fs::write(dir.join("meta.json"), b"{}").expect("write meta");

    let freed = delete_recording_storage_path(base.path(), &rel, &uuid.to_string())
        .expect("delete dir");
    assert!(freed >= 5);
    assert!(!dir.exists());
}

#[test]
fn delete_legacy_flat_mp4_and_blake3_sidecar() {
    let base = tempfile::tempdir().expect("tempdir");
    let uuid = Uuid::new_v4();
    let rel = format!("2026/02/{uuid}.mp4");
    let mp4 = base.path().join(&rel);
    fs::create_dir_all(mp4.parent().unwrap()).expect("mkdir");
    fs::write(&mp4, vec![0u8; 1024]).expect("write mp4");
    fs::write(format!("{}.blake3", mp4.display()), b"hash").expect("write blake3");

    delete_recording_storage_path(base.path(), &rel, &uuid.to_string()).expect("delete flat");
    assert!(!mp4.exists());
}

#[test]
fn delete_is_idempotent_when_path_missing() {
    let base = tempfile::tempdir().expect("tempdir");
    let uuid = Uuid::new_v4();
    let rel = format!("2026/05/{uuid}/");
    let freed =
        delete_recording_storage_path(base.path(), &rel, &uuid.to_string()).expect("delete missing");
    assert_eq!(freed, 0);
}

#[test]
fn reject_path_traversal() {
    let base = tempfile::tempdir().expect("tempdir");
    let uuid = Uuid::new_v4();
    assert!(validate_recording_delete_relative_path("../secret", &uuid.to_string()).is_err());
    assert!(
        delete_recording_storage_path(base.path(), "../secret", &uuid.to_string()).is_err()
    );
}

#[test]
fn reject_uuid_mismatch_in_relative_path() {
    let uuid = Uuid::new_v4();
    let other = Uuid::new_v4();
    let rel = format!("2026/05/{other}/");
    assert!(validate_recording_delete_relative_path(&rel, &uuid.to_string()).is_err());
}

#[test]
fn recording_root_relative_strips_storage_prefix() {
    let uuid = Uuid::new_v4();
    let path = format!("/var/vauban/recordings/2026/05/{uuid}/");
    assert_eq!(
        recording_root_relative("/var/vauban/recordings", &path),
        Some(format!("2026/05/{uuid}/"))
    );
}

#[test]
fn resolved_path_stays_under_storage_base() {
    let base = tempfile::tempdir().expect("tempdir");
    let uuid = Uuid::new_v4();
    let rel = format!("2026/05/{uuid}/");
    let dir = base.path().join(&rel);
    fs::create_dir_all(&dir).expect("mkdir");
    let resolved =
        shared::recording_paths::resolve_recording_path_under_base(base.path(), &rel)
            .expect("resolve");
    assert!(resolved.starts_with(base.path().canonicalize().unwrap()));
}
