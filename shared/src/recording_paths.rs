//! Helpers for recording storage paths (retention reaper + supervisor delete).
//!
//! Keeps path normalization and validation in one place so vauban-web and
//! vauban-supervisor apply identical rules.

use std::path::{Component, Path, PathBuf};

/// Strip `storage_base` and return the relative root path for IPC delete.
///
/// Directory recordings end with `/` in DB (`2026/05/uuid/`). Legacy flat
/// RDP paths are single files (`2026/05/uuid.mp4`).
pub fn recording_root_relative(storage_base: &str, recording_path: &str) -> Option<String> {
    if recording_path.is_empty() {
        return None;
    }
    let stripped = recording_path
        .strip_prefix(storage_base)
        .unwrap_or(recording_path)
        .trim_start_matches('/');
    if stripped.is_empty() {
        return None;
    }
    Some(stripped.to_string())
}

/// Validate structural rules for a relative recording path (no traversal).
fn validate_recording_relative_structure(relative_path: &str) -> Result<(), String> {
    if relative_path.is_empty() {
        return Err("relative_path must not be empty".into());
    }
    if relative_path.starts_with('/') {
        return Err("relative_path must not be absolute".into());
    }
    for component in Path::new(relative_path).components() {
        if matches!(component, Component::ParentDir) {
            return Err("relative_path must not contain ..".into());
        }
    }
    Ok(())
}

/// Validate gzip source/destination paths for IACS PCAP recording.
///
/// Kept for callers that still validate both sides together; the
/// live ChannelEnd path uses [`validate_recording_unlink_relative_path`]
/// for the raw `.pcap` and [`validate_recording_file_relative_path`]
/// for the `.pcap.gz` FD request.
pub fn validate_recording_gzip_relative_paths(
    src_relative: &str,
    dst_relative: &str,
    session_id: &str,
) -> Result<(), String> {
    validate_recording_relative_structure(src_relative)?;
    validate_recording_relative_structure(dst_relative)?;
    if !src_relative.contains(session_id) || !dst_relative.contains(session_id) {
        return Err("gzip paths must contain session_id".into());
    }
    if !src_relative.ends_with(".pcap") {
        return Err("gzip source must be a .pcap file".into());
    }
    if !dst_relative.ends_with(".pcap.gz") {
        return Err("gzip destination must be a .pcap.gz file".into());
    }
    Ok(())
}

/// Validate a relative path before the supervisor unlinks a raw IACS
/// `.pcap` after audit has gzipped it on SCM_RIGHTS FDs.
///
/// # Invariants
///
/// - Must end with `.pcap` (NOT `.pcap.gz`).
/// - Must contain `session_id`.
/// - Same anti-traversal rules as other recording path validators.
pub fn validate_recording_unlink_relative_path(
    relative_path: &str,
    session_id: &str,
) -> Result<(), String> {
    validate_recording_relative_structure(relative_path)?;
    if !relative_path.contains(session_id) {
        return Err("relative_path must contain session_id".into());
    }
    if relative_path.ends_with(".pcap.gz") {
        return Err("unlink path must be a raw .pcap, not .pcap.gz".into());
    }
    if !relative_path.ends_with(".pcap") {
        return Err("unlink path must be a .pcap file".into());
    }
    Ok(())
}

/// Validate a relative path before the supervisor deletes anything on disk.
pub fn validate_recording_delete_relative_path(
    relative_path: &str,
    session_id: &str,
) -> Result<(), String> {
    validate_recording_relative_structure(relative_path)?;
    if !relative_path.contains(session_id) {
        return Err("relative_path must contain session_id".into());
    }
    Ok(())
}

/// Validate a relative path before the supervisor opens/creates a recording
/// file on behalf of a sandboxed peer (VAU-006).
///
/// # Invariant INV-1 (confinement)
///
/// Enforces no traversal (`..`), no absolute path, no empty path, and that
/// the path is anchored to `session_id`. This is the structural half of
/// the file-broker gate; the canonical containment check lives in
/// [`resolve_recording_file_target`].
pub fn validate_recording_file_relative_path(
    relative_path: &str,
    session_id: &str,
) -> Result<(), String> {
    validate_recording_relative_structure(relative_path)?;
    if !relative_path.contains(session_id) {
        return Err("relative_path must contain session_id".into());
    }
    Ok(())
}

/// Resolve the on-disk target for a supervisor recording-file request.
///
/// # Invariant INV-3 (single seam)
///
/// This is the ONE function the supervisor's recording-file broker
/// (`handle_recording_file_request`) uses to turn an untrusted
/// `(storage_base, relative_path, session_id)` triple into a concrete
/// path. It MUST be called before any filesystem syscall (open / create /
/// create_dir_all): a forgotten call re-opens the VAU-006 path traversal.
///
/// Validates structure + `session_id` anchoring (INV-1), then resolves
/// under `storage_base`. When the target exists (read / playback path) the
/// result is canonicalized and checked to stay under the canonical base,
/// which also defeats symlink escapes. When the target does not yet exist
/// (create path) the result is the lexical join, which is bounded under
/// the base because the structural validation already rejected `..` and
/// absolute paths.
pub fn resolve_recording_file_target(
    storage_base: &Path,
    relative_path: &str,
    session_id: &str,
) -> Result<PathBuf, String> {
    validate_recording_file_relative_path(relative_path, session_id)?;
    resolve_recording_path_under_base(storage_base, relative_path)
}

/// Resolve `storage_base.join(relative_path)` and ensure it stays under base.
pub fn resolve_recording_path_under_base(
    storage_base: &Path,
    relative_path: &str,
) -> Result<PathBuf, String> {
    validate_recording_relative_structure(relative_path)?;
    let full = storage_base.join(relative_path);
    if full.exists() {
        let canonical = full
            .canonicalize()
            .map_err(|e| format!("canonicalize: {e}"))?;
        let base_canonical = storage_base
            .canonicalize()
            .map_err(|e| format!("canonicalize storage_base: {e}"))?;
        if !canonical.starts_with(&base_canonical) {
            return Err("path escapes storage_base".into());
        }
        Ok(canonical)
    } else {
        // ENOENT delete is idempotent; still reject obvious traversal.
        if relative_path.contains("..") {
            return Err("relative_path must not contain ..".into());
        }
        Ok(full)
    }
}

/// Delete a recording directory or file under `storage_base`.
///
/// Returns an estimate of bytes freed (best-effort directory walk).
pub fn delete_recording_storage_path(
    storage_base: &Path,
    relative_path: &str,
    session_id: &str,
) -> Result<u64, String> {
    validate_recording_delete_relative_path(relative_path, session_id)?;
    let full = resolve_recording_path_under_base(storage_base, relative_path)?;

    if !full.exists() {
        return Ok(0);
    }

    let bytes = dir_size_bytes(&full).unwrap_or(0);

    if full.is_dir() {
        std::fs::remove_dir_all(&full).map_err(|e| format!("remove_dir_all: {e}"))?;
        Ok(bytes)
    } else {
        std::fs::remove_file(&full).map_err(|e| format!("remove_file: {e}"))?;
        let mut freed = bytes;
        // Legacy RDP flat layout: `{uuid}.mp4` + integrity sidecar
        // `{uuid}.mp4.blake3`. `with_added_extension` appends without
        // replacing `.mp4` (unlike `with_extension`).
        let blake3_path = full.with_added_extension("blake3");
        if blake3_path.exists() {
            if let Ok(meta) = blake3_path.metadata() {
                freed = freed.saturating_add(meta.len());
            }
            let _ = std::fs::remove_file(&blake3_path);
        }
        Ok(freed)
    }
}

fn dir_size_bytes(path: &Path) -> Result<u64, std::io::Error> {
    if path.is_file() {
        return Ok(path.metadata()?.len());
    }
    let mut total = 0u64;
    if path.is_dir() {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let meta = entry.metadata()?;
            if meta.is_dir() {
                total = total.saturating_add(dir_size_bytes(&entry.path())?);
            } else {
                total = total.saturating_add(meta.len());
            }
        }
    }
    Ok(total)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn recording_root_relative_strips_base() {
        assert_eq!(
            recording_root_relative("/var/rec", "/var/rec/2026/05/uuid/"),
            Some("2026/05/uuid/".to_string())
        );
    }

    #[test]
    fn validate_rejects_parent_dir() {
        assert!(validate_recording_delete_relative_path("../etc/passwd", "uuid").is_err());
    }

    #[test]
    fn validate_requires_session_id_substring() {
        assert!(validate_recording_delete_relative_path("2026/05/other/", "uuid").is_err());
    }

    // ==================== Recording file broker (VAU-006) ====================

    const UUID: &str = "11111111-2222-3333-4444-555555555555";

    #[test]
    fn validate_recording_file_rejects_parent_dir() {
        assert!(validate_recording_file_relative_path("../etc/passwd", UUID).is_err());
    }

    #[test]
    fn validate_recording_file_rejects_absolute() {
        assert!(validate_recording_file_relative_path("/etc/passwd", UUID).is_err());
    }

    #[test]
    fn validate_recording_file_rejects_empty() {
        assert!(validate_recording_file_relative_path("", UUID).is_err());
    }

    #[test]
    fn validate_recording_file_rejects_session_id_mismatch() {
        assert!(
            validate_recording_file_relative_path("2026/05/other-uuid/session.cast", UUID).is_err()
        );
    }

    #[test]
    fn validate_recording_file_accepts_legit_layouts() {
        for rel in [
            format!("2026/05/{UUID}/session.cast"),
            format!("2026/05/{UUID}/meta.json"),
            format!("2026/05/{UUID}/001.mp4"),
            format!("2026/05/{UUID}/channels/000.pcap"),
            // Legacy flat RDP layout.
            format!("2026/02/{UUID}.mp4"),
        ] {
            assert!(
                validate_recording_file_relative_path(&rel, UUID).is_ok(),
                "legit layout must be accepted: {rel}"
            );
        }
    }

    /// Adversarial: `..` buried mid-path still escapes and must be rejected,
    /// even when the path also contains the session_id (so the substring
    /// anchor alone is not enough -- the component scan catches it).
    #[test]
    fn validate_recording_file_rejects_buried_traversal_even_with_session_id() {
        for rel in [
            format!("2026/05/{UUID}/../../../etc/passwd"),
            format!("{UUID}/../../etc/{UUID}"),
            format!("2026/05/{UUID}/sub/../../../../etc/shadow"),
        ] {
            assert!(
                validate_recording_file_relative_path(&rel, UUID).is_err(),
                "buried traversal must be rejected: {rel}"
            );
        }
    }

    #[test]
    fn resolve_recording_file_target_accepts_legit_under_base() {
        let base = tempfile::tempdir().expect("tempdir");
        let rel = format!("2026/05/{UUID}/session.cast");
        let resolved = resolve_recording_file_target(base.path(), &rel, UUID).expect("resolve");
        // Create path (target does not exist yet): lexical join under base.
        assert!(resolved.starts_with(base.path()));
        assert!(resolved.ends_with("session.cast"));
    }

    #[test]
    fn resolve_recording_file_target_rejects_traversal_and_absolute() {
        let base = tempfile::tempdir().expect("tempdir");
        assert!(resolve_recording_file_target(base.path(), "../escape", UUID).is_err());
        assert!(resolve_recording_file_target(base.path(), "/etc/passwd", UUID).is_err());
    }

    // ==================== Recording unlink (IACS raw .pcap) ====================

    #[test]
    fn validate_recording_unlink_accepts_raw_pcap() {
        let rel = format!("2026/05/{UUID}/channels/001.pcap");
        assert!(validate_recording_unlink_relative_path(&rel, UUID).is_ok());
    }

    #[test]
    fn validate_recording_unlink_rejects_pcap_gz() {
        let rel = format!("2026/05/{UUID}/channels/001.pcap.gz");
        assert!(validate_recording_unlink_relative_path(&rel, UUID).is_err());
    }

    #[test]
    fn validate_recording_unlink_rejects_wrong_suffix() {
        let rel = format!("2026/05/{UUID}/meta.json");
        assert!(validate_recording_unlink_relative_path(&rel, UUID).is_err());
    }

    #[test]
    fn validate_recording_unlink_rejects_traversal_and_session_mismatch() {
        assert!(
            validate_recording_unlink_relative_path(
                &format!("2026/05/{UUID}/../../../etc/passwd.pcap"),
                UUID
            )
            .is_err()
        );
        assert!(
            validate_recording_unlink_relative_path("2026/05/other/channels/001.pcap", UUID)
                .is_err()
        );
        assert!(validate_recording_unlink_relative_path("", UUID).is_err());
        assert!(
            validate_recording_unlink_relative_path(&format!("/abs/{UUID}/x.pcap"), UUID).is_err()
        );
    }

    // ==================== Legacy RDP BLAKE3 sidecar delete ====================

    #[test]
    fn delete_legacy_flat_mp4_removes_blake3_sidecar_and_counts_bytes() {
        let base = tempfile::tempdir().expect("tempdir");
        let rel = format!("2026/02/{UUID}.mp4");
        let media = base.path().join(&rel);
        std::fs::create_dir_all(media.parent().expect("parent")).expect("mkdir");
        std::fs::write(&media, b"fake-mp4-bytes").expect("write mp4");
        let sidecar = media.with_added_extension("blake3");
        std::fs::write(&sidecar, b"deadbeef").expect("write blake3");

        let freed = delete_recording_storage_path(base.path(), &rel, UUID).expect("delete");
        assert!(!media.exists(), "media must be removed");
        assert!(!sidecar.exists(), "sidecar must be removed");
        assert_eq!(
            freed,
            b"fake-mp4-bytes".len() as u64 + b"deadbeef".len() as u64
        );
    }

    #[test]
    fn delete_legacy_flat_mp4_without_sidecar_succeeds() {
        let base = tempfile::tempdir().expect("tempdir");
        let rel = format!("2026/02/{UUID}.mp4");
        let media = base.path().join(&rel);
        std::fs::create_dir_all(media.parent().expect("parent")).expect("mkdir");
        std::fs::write(&media, b"solo").expect("write mp4");

        let freed = delete_recording_storage_path(base.path(), &rel, UUID).expect("delete");
        assert!(!media.exists());
        assert_eq!(freed, b"solo".len() as u64);
    }

    #[test]
    fn delete_recording_storage_path_uses_with_added_extension_for_blake3() {
        let src = include_str!("recording_paths.rs");
        let fn_start = src
            .find("pub fn delete_recording_storage_path")
            .expect("delete_recording_storage_path must exist");
        let body = &src[fn_start..];
        let fn_end = body
            .find("\nfn dir_size_bytes")
            .unwrap_or(body.len().min(2500));
        let body = &body[..fn_end];
        assert!(
            body.contains("with_added_extension(\"blake3\")"),
            "delete must resolve sidecar via with_added_extension(\"blake3\")"
        );
        assert!(
            !body.contains("with_extension(\"mp4.blake3\")"),
            "must not use with_extension(\"mp4.blake3\") workaround"
        );
        assert!(
            !body.contains("format!(\"{}.blake3\""),
            "must not build sidecar via format!(\"{{}}.blake3\")"
        );
    }

    /// Battle: concurrent deletes of distinct legacy flat pairs under one base.
    #[test]
    fn battle_concurrent_delete_legacy_flat_mp4_and_sidecar() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let base = Arc::new(tempfile::tempdir().expect("tempdir"));
        let n = 8usize;
        let barrier = Arc::new(Barrier::new(n));
        let mut handles = Vec::with_capacity(n);
        for i in 0..n {
            let base = Arc::clone(&base);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                let uuid = format!("11111111-2222-3333-4444-{:012}", i);
                let rel = format!("2026/02/{uuid}.mp4");
                let media = base.path().join(&rel);
                std::fs::create_dir_all(media.parent().expect("parent")).expect("mkdir");
                std::fs::write(&media, format!("media-{i}")).expect("write mp4");
                let sidecar = media.with_added_extension("blake3");
                std::fs::write(&sidecar, format!("hash-{i}")).expect("write blake3");
                barrier.wait();
                delete_recording_storage_path(base.path(), &rel, &uuid).expect("delete");
                assert!(!media.exists());
                assert!(!sidecar.exists());
            }));
        }
        for h in handles {
            h.join().expect("thread");
        }
    }
}
