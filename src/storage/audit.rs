//! Append-only WebAuthn audit log under `blob_path/audit/webauthn.log`.
//!
//! The log file is opened once at helper boot (before Capsicum `cap_enter`) and
//! kept open for append — absolute reopen after capability mode fails with
//! ENOTCAPABLE.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::json;

use super::error::{StorageError, StorageErrorCode};

pub const AUDIT_REL_DIR: &str = "audit";
pub const AUDIT_LOG_FILE: &str = "webauthn.log";

pub struct WebauthnAudit {
    path: PathBuf,
    file: Mutex<File>,
}

impl WebauthnAudit {
    pub fn open(blob_root: impl AsRef<Path>) -> Result<Self, StorageError> {
        let dir = blob_root.as_ref().join(AUDIT_REL_DIR);
        std::fs::create_dir_all(&dir)
            .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("mkdir audit: {e}")))?;
        let path = dir.join(AUDIT_LOG_FILE);
        if !path.exists() {
            File::create(&path).map_err(|e| {
                StorageError::new(StorageErrorCode::Io, format!("create audit log: {e}"))
            })?;
        }
        let file = OpenOptions::new()
            .append(true)
            .open(&path)
            .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("open audit: {e}")))?;
        Ok(Self {
            path,
            file: Mutex::new(file),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn append(&self, event: &str, fields: serde_json::Value) -> Result<(), StorageError> {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut line = json!({
            "ts": ts,
            "event": event,
        });
        if let Some(obj) = line.as_object_mut()
            && let Some(extra) = fields.as_object()
        {
            for (k, v) in extra {
                obj.insert(k.clone(), v.clone());
            }
        }
        let mut f = self.file.lock().expect("audit mutex");
        writeln!(f, "{line}")
            .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("write audit: {e}")))?;
        f.sync_all()
            .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("fsync audit: {e}")))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_audit_held_fd_append_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let audit = WebauthnAudit::open(dir.path()).unwrap();
        audit
            .append("enrol_stage", json!({ "fingerprint": "abc" }))
            .unwrap();
        audit
            .append("key_approve", json!({ "fingerprint": "abc" }))
            .unwrap();
        let text = std::fs::read_to_string(audit.path()).unwrap();
        assert!(text.contains("enrol_stage"));
        assert!(text.contains("key_approve"));
        assert_eq!(text.lines().count(), 2);
    }
}
