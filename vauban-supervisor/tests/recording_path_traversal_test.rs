//! E2E filesystem proof of the VAU-006 recording-file path confinement.
//!
//! The supervisor's recording-file broker turns an untrusted
//! `(storage_base, relative_path, session_id)` triple into a concrete path
//! and hands the resulting FD (opened/created as root) to a sandboxed peer
//! via SCM_RIGHTS. Before the fix, a `relative_path` with `../` or an
//! absolute path escaped `storage_base`. These tests drive the real shared
//! seam `resolve_recording_file_target` against a real tempdir (real
//! files, real symlink) to prove INV-1 (confinement under base, anchored
//! to session_id, symlink-safe).
//!
//! Behavioral wiring of the handler itself is pinned by
//! `recording_broker_path_pin_test.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use shared::recording_paths::resolve_recording_file_target;
use std::fs;
use uuid::Uuid;

/// A legitimate recording file (create path, target not yet on disk)
/// resolves to a path strictly under the storage base.
#[test]
fn resolves_legit_file_under_base() {
    let base = tempfile::tempdir().expect("tempdir");
    let uuid = Uuid::new_v4();
    let rel = format!("2026/05/{uuid}/session.cast");

    let resolved = resolve_recording_file_target(base.path(), &rel, &uuid.to_string())
        .expect("legit path must resolve");

    assert!(resolved.starts_with(base.path()), "must stay under base");
    assert!(resolved.ends_with("session.cast"));
}

/// `..` traversal is rejected before any filesystem access, even when the
/// path is otherwise anchored to the session_id.
#[test]
fn blocks_dotdot_traversal_before_fs() {
    let base = tempfile::tempdir().expect("tempdir");
    let uuid = Uuid::new_v4();

    // A secret outside the base that an attacker would target.
    let secret_name = format!("vau006_secret_{uuid}");
    let secret = base.path().parent().unwrap().join(&secret_name);
    fs::write(&secret, b"top secret").expect("write secret");

    // Buried traversal that still contains the session_id substring.
    let rel = format!("2026/05/{uuid}/../../../../../{secret_name}");
    let result = resolve_recording_file_target(base.path(), &rel, &uuid.to_string());

    assert!(result.is_err(), "traversal must be rejected: {result:?}");

    // Cleanup (best-effort).
    let _ = fs::remove_file(&secret);
}

/// An absolute `relative_path` must not override the base (Path::join
/// pitfall) and is rejected.
#[test]
fn blocks_absolute_path_escape() {
    let base = tempfile::tempdir().expect("tempdir");
    let uuid = Uuid::new_v4();

    let result = resolve_recording_file_target(base.path(), "/etc/hostname", &uuid.to_string());
    assert!(result.is_err(), "absolute path must be rejected");

    // Even an absolute path that contains the session_id substring.
    let rel_abs = format!("/etc/{uuid}/passwd");
    let result2 = resolve_recording_file_target(base.path(), &rel_abs, &uuid.to_string());
    assert!(
        result2.is_err(),
        "absolute path with session_id must still be rejected"
    );
}

/// A symlink planted under the base that points outside is rejected on the
/// read/existing-target path thanks to canonical containment (INV-1
/// symlink defense).
#[test]
fn blocks_symlink_escape_on_read() {
    let base = tempfile::tempdir().expect("tempdir");
    let uuid = Uuid::new_v4();

    // Secret outside the base.
    let secret = base
        .path()
        .parent()
        .unwrap()
        .join(format!("vau006_symlink_secret_{uuid}"));
    fs::write(&secret, b"top secret").expect("write secret");

    // Plant base/2026/05/<uuid>/leak -> secret.
    let dir = base.path().join(format!("2026/05/{uuid}"));
    fs::create_dir_all(&dir).expect("mkdir");
    let link = dir.join("leak");
    std::os::unix::fs::symlink(&secret, &link).expect("symlink");

    let rel = format!("2026/05/{uuid}/leak");
    let result = resolve_recording_file_target(base.path(), &rel, &uuid.to_string());

    assert!(
        result.is_err(),
        "symlink escaping the base must be rejected, got {result:?}"
    );

    let _ = fs::remove_file(&secret);
}

/// On the create path (target not yet present), the resolved target AND its
/// parent stay under the base, so the handler's `create_dir_all(parent)`
/// cannot escape.
#[test]
fn create_path_parent_stays_under_base() {
    let base = tempfile::tempdir().expect("tempdir");
    let uuid = Uuid::new_v4();
    let rel = format!("2026/05/{uuid}/001.mp4");

    let resolved = resolve_recording_file_target(base.path(), &rel, &uuid.to_string())
        .expect("create-path target must resolve");

    assert!(resolved.starts_with(base.path()));
    let parent = resolved.parent().expect("has parent");
    assert!(
        parent.starts_with(base.path()),
        "create_dir_all parent must stay under base"
    );
}
