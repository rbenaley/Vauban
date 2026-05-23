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
        let sidecar = full.with_extension("mp4.blake3");
        // Legacy sidecar: `{uuid}.mp4.blake3` — with_extension replaces `.mp4`.
        let blake3_path = PathBuf::from(format!("{}.blake3", full.display()));
        for extra in [sidecar, blake3_path] {
            if extra.exists() {
                if let Ok(meta) = extra.metadata() {
                    freed = freed.saturating_add(meta.len());
                }
                let _ = std::fs::remove_file(&extra);
            }
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
}
