//! SQLite digest SoT for `vcp-store` (`blob_path/meta.sqlite`).

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, params};

use super::error::{StorageError, StorageErrorCode};
use super::ids::StorageScope;

/// Relative filename under `blob_path`.
pub const META_DB_FILE: &str = "meta.sqlite";

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS objects (
    scope TEXT NOT NULL,
    object_key TEXT NOT NULL,
    org_id TEXT NOT NULL DEFAULT '',
    sha256 TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    content_type TEXT NOT NULL DEFAULT '',
    ext TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (scope, object_key)
);
"#;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetaObject {
    pub scope: StorageScope,
    pub object_key: String,
    pub org_id: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub content_type: String,
    pub ext: String,
}

/// Sync SQLite handle owned by the helper / inline engine.
pub struct MetaDb {
    conn: Connection,
    path: PathBuf,
}

impl MetaDb {
    pub fn open(blob_root: impl AsRef<Path>) -> Result<Self, StorageError> {
        let path = blob_root.as_ref().join(META_DB_FILE);
        let conn = Connection::open(&path).map_err(|e| {
            StorageError::new(StorageErrorCode::Io, format!("open meta.sqlite: {e}"))
        })?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")
            .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("pragma: {e}")))?;
        conn.execute_batch(SCHEMA)
            .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("schema: {e}")))?;
        Ok(Self { conn, path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn upsert(&self, obj: &MetaObject) -> Result<(), StorageError> {
        let ts = now_unix();
        let scope = obj.scope.as_str();
        self.conn
            .execute(
                r#"
                INSERT INTO objects (
                    scope, object_key, org_id, sha256, size_bytes,
                    content_type, ext, created_at, updated_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)
                ON CONFLICT(scope, object_key) DO UPDATE SET
                    org_id = excluded.org_id,
                    sha256 = excluded.sha256,
                    size_bytes = excluded.size_bytes,
                    content_type = excluded.content_type,
                    ext = excluded.ext,
                    updated_at = excluded.updated_at
                "#,
                params![
                    scope,
                    obj.object_key,
                    obj.org_id,
                    obj.sha256,
                    obj.size_bytes as i64,
                    obj.content_type,
                    obj.ext,
                    ts,
                ],
            )
            .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("upsert: {e}")))?;
        Ok(())
    }

    pub fn get(
        &self,
        scope: StorageScope,
        object_key: &str,
    ) -> Result<Option<MetaObject>, StorageError> {
        let mut stmt = self
            .conn
            .prepare(
                r#"
                SELECT scope, object_key, org_id, sha256, size_bytes, content_type, ext
                FROM objects WHERE scope = ?1 AND object_key = ?2
                "#,
            )
            .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("prepare get: {e}")))?;
        let row = stmt
            .query_row(params![scope.as_str(), object_key], |r| {
                let scope_raw: String = r.get(0)?;
                Ok(MetaObject {
                    scope: StorageScope::parse(&scope_raw).unwrap_or(scope),
                    object_key: r.get(1)?,
                    org_id: r.get(2)?,
                    sha256: r.get(3)?,
                    size_bytes: r.get::<_, i64>(4)? as u64,
                    content_type: r.get(5)?,
                    ext: r.get(6)?,
                })
            })
            .optional()
            .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("get: {e}")))?;
        Ok(row)
    }

    pub fn delete(&self, scope: StorageScope, object_key: &str) -> Result<(), StorageError> {
        self.conn
            .execute(
                "DELETE FROM objects WHERE scope = ?1 AND object_key = ?2",
                params![scope.as_str(), object_key],
            )
            .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("delete: {e}")))?;
        Ok(())
    }

    pub fn delete_org(&self, org_id: &str) -> Result<u32, StorageError> {
        let n = self
            .conn
            .execute(
                "DELETE FROM objects WHERE scope = 'image' AND org_id = ?1",
                params![org_id],
            )
            .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("delete_org: {e}")))?;
        Ok(n as u32)
    }
}

/// Build object_key for a release blob.
pub fn release_object_key(release_id: &str) -> String {
    release_id.to_owned()
}

/// Build object_key for an image blob (matches Postgres mirror shape).
pub fn image_object_key(org_id: &str, image_id: &str, ext: &str) -> String {
    format!("{org_id}/{image_id}.{ext}")
}

/// Constant-time equality for equal-length hex digests.
pub fn ct_eq_hex(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.as_bytes().iter().zip(b.as_bytes().iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn upsert_get_delete_roundtrip() {
        let dir = tempdir().unwrap();
        let db = MetaDb::open(dir.path()).unwrap();
        let obj = MetaObject {
            scope: StorageScope::Release,
            object_key: "42".into(),
            org_id: String::new(),
            sha256: "a".repeat(64),
            size_bytes: 100,
            content_type: String::new(),
            ext: String::new(),
        };
        db.upsert(&obj).unwrap();
        let got = db.get(StorageScope::Release, "42").unwrap().unwrap();
        assert_eq!(got.sha256, obj.sha256);
        assert_eq!(got.size_bytes, 100);
        db.delete(StorageScope::Release, "42").unwrap();
        assert!(db.get(StorageScope::Release, "42").unwrap().is_none());
    }

    #[test]
    fn ct_eq_hex_detects_mismatch() {
        let a = "a".repeat(64);
        let mut b = a.clone();
        assert!(ct_eq_hex(&a, &b));
        b.replace_range(0..1, "b");
        assert!(!ct_eq_hex(&a, &b));
    }

    #[test]
    fn delete_org_images_only() {
        let dir = tempdir().unwrap();
        let db = MetaDb::open(dir.path()).unwrap();
        db.upsert(&MetaObject {
            scope: StorageScope::Image,
            object_key: image_object_key("9", "550e8400-e29b-41d4-a716-446655440000", "png"),
            org_id: "9".into(),
            sha256: "b".repeat(64),
            size_bytes: 10,
            content_type: "png".into(),
            ext: "png".into(),
        })
        .unwrap();
        db.upsert(&MetaObject {
            scope: StorageScope::Release,
            object_key: "1".into(),
            org_id: String::new(),
            sha256: "c".repeat(64),
            size_bytes: 1,
            content_type: String::new(),
            ext: String::new(),
        })
        .unwrap();
        assert_eq!(db.delete_org("9").unwrap(), 1);
        assert!(db.get(StorageScope::Release, "1").unwrap().is_some());
    }
}
