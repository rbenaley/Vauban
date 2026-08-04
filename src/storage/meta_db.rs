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

CREATE TABLE IF NOT EXISTS webauthn_credentials (
    credential_id BLOB PRIMARY KEY,
    public_key_cose BLOB NOT NULL,
    user_handle TEXT NOT NULL,
    admin_label TEXT NOT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'pending',
    is_soft INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    activated_at INTEGER,
    revoked_at INTEGER
);

CREATE TABLE IF NOT EXISTS webauthn_challenges (
    challenge_id TEXT PRIMARY KEY,
    op TEXT NOT NULL,
    binding_json TEXT NOT NULL,
    summary TEXT NOT NULL,
    challenge_b64 TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_expires
    ON webauthn_challenges(expires_at);
CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_b64
    ON webauthn_challenges(challenge_b64);
"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialStatus {
    Pending,
    Active,
    /// PENDING enrolment not approved within `webauthn_pending_ttl_hours`.
    Expired,
}

impl CredentialStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Expired => "expired",
        }
    }

    pub fn parse(raw: &str) -> Self {
        match raw {
            "active" => Self::Active,
            "expired" => Self::Expired,
            _ => Self::Pending,
        }
    }
}

#[derive(Debug, Clone)]
pub struct WebauthnCredentialRow {
    pub credential_id: Vec<u8>,
    pub public_key_cose: Vec<u8>,
    pub user_handle: String,
    pub admin_label: String,
    pub sign_count: u32,
    pub status: CredentialStatus,
    pub is_soft: bool,
    pub created_at: i64,
    pub activated_at: Option<i64>,
    pub revoked_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct WebauthnChallengeRow {
    pub challenge_id: String,
    pub op: String,
    pub binding_json: String,
    pub summary: String,
    pub challenge_b64: String,
    pub expires_at: i64,
    pub consumed_at: Option<i64>,
}

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
        // Concurrent helper opens / put_commit under the same blob_path (battle
        // tests, multi-process) must retry on SQLITE_BUSY instead of failing.
        conn.busy_timeout(std::time::Duration::from_secs(30))
            .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("busy_timeout: {e}")))?;
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

    /// Insert a credential row. Replaces revoked / expired / pending rows with the
    /// same `credential_id` (re-enrol after revoke or PENDING retry). Rejects when
    /// an ACTIVE non-revoked credential already exists.
    pub fn insert_credential(&self, row: &WebauthnCredentialRow) -> Result<(), StorageError> {
        if let Some(existing) = self.get_credential(&row.credential_id)? {
            let replaceable = existing.revoked_at.is_some()
                || existing.status == CredentialStatus::Expired
                || existing.status == CredentialStatus::Pending;
            if !replaceable {
                return Err(StorageError::new(
                    StorageErrorCode::WebauthnInvalid,
                    "credential already active",
                ));
            }
            self.conn
                .execute(
                    "DELETE FROM webauthn_credentials WHERE credential_id = ?1",
                    params![row.credential_id],
                )
                .map_err(|e| {
                    StorageError::new(StorageErrorCode::Io, format!("replace credential: {e}"))
                })?;
        }
        self.conn
            .execute(
                r#"
                INSERT INTO webauthn_credentials (
                    credential_id, public_key_cose, user_handle, admin_label,
                    sign_count, status, is_soft, created_at, activated_at, revoked_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                "#,
                params![
                    row.credential_id,
                    row.public_key_cose,
                    row.user_handle,
                    row.admin_label,
                    row.sign_count as i64,
                    row.status.as_str(),
                    if row.is_soft { 1 } else { 0 },
                    row.created_at,
                    row.activated_at,
                    row.revoked_at,
                ],
            )
            .map_err(|e| {
                StorageError::new(StorageErrorCode::Io, format!("insert credential: {e}"))
            })?;
        Ok(())
    }

    pub fn get_credential(
        &self,
        credential_id: &[u8],
    ) -> Result<Option<WebauthnCredentialRow>, StorageError> {
        let mut stmt = self
            .conn
            .prepare(
                r#"
                SELECT credential_id, public_key_cose, user_handle, admin_label,
                       sign_count, status, is_soft, created_at, activated_at, revoked_at
                FROM webauthn_credentials WHERE credential_id = ?1
                "#,
            )
            .map_err(|e| {
                StorageError::new(StorageErrorCode::Io, format!("prepare get cred: {e}"))
            })?;
        let row = stmt
            .query_row(params![credential_id], |r| {
                Ok(WebauthnCredentialRow {
                    credential_id: r.get(0)?,
                    public_key_cose: r.get(1)?,
                    user_handle: r.get(2)?,
                    admin_label: r.get(3)?,
                    sign_count: r.get::<_, i64>(4)? as u32,
                    status: CredentialStatus::parse(&r.get::<_, String>(5)?),
                    is_soft: r.get::<_, i64>(6)? != 0,
                    created_at: r.get(7)?,
                    activated_at: r.get(8)?,
                    revoked_at: r.get(9)?,
                })
            })
            .optional()
            .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("get cred: {e}")))?;
        Ok(row)
    }

    pub fn list_active_credentials(&self) -> Result<Vec<WebauthnCredentialRow>, StorageError> {
        let mut stmt = self
            .conn
            .prepare(
                r#"
                SELECT credential_id, public_key_cose, user_handle, admin_label,
                       sign_count, status, is_soft, created_at, activated_at, revoked_at
                FROM webauthn_credentials
                WHERE status = 'active' AND revoked_at IS NULL
                ORDER BY created_at ASC
                "#,
            )
            .map_err(|e| {
                StorageError::new(StorageErrorCode::Io, format!("prepare list cred: {e}"))
            })?;
        let rows = stmt
            .query_map([], |r| {
                Ok(WebauthnCredentialRow {
                    credential_id: r.get(0)?,
                    public_key_cose: r.get(1)?,
                    user_handle: r.get(2)?,
                    admin_label: r.get(3)?,
                    sign_count: r.get::<_, i64>(4)? as u32,
                    status: CredentialStatus::parse(&r.get::<_, String>(5)?),
                    is_soft: r.get::<_, i64>(6)? != 0,
                    created_at: r.get(7)?,
                    activated_at: r.get(8)?,
                    revoked_at: r.get(9)?,
                })
            })
            .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("list cred: {e}")))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|e| {
                StorageError::new(StorageErrorCode::Io, format!("list cred row: {e}"))
            })?);
        }
        Ok(out)
    }

    pub fn list_pending_credentials(&self) -> Result<Vec<WebauthnCredentialRow>, StorageError> {
        self.query_credentials(
            r#"
                SELECT credential_id, public_key_cose, user_handle, admin_label,
                       sign_count, status, is_soft, created_at, activated_at, revoked_at
                FROM webauthn_credentials
                WHERE status = 'pending' AND revoked_at IS NULL
                ORDER BY created_at ASC
                "#,
            "pending",
        )
    }

    /// All credential rows (pending, active, revoked) for ops CLI `ctap2 list`.
    pub fn list_all_credentials(&self) -> Result<Vec<WebauthnCredentialRow>, StorageError> {
        self.query_credentials(
            r#"
                SELECT credential_id, public_key_cose, user_handle, admin_label,
                       sign_count, status, is_soft, created_at, activated_at, revoked_at
                FROM webauthn_credentials
                ORDER BY created_at ASC
                "#,
            "all creds",
        )
    }

    fn query_credentials(
        &self,
        sql: &str,
        what: &str,
    ) -> Result<Vec<WebauthnCredentialRow>, StorageError> {
        let mut stmt = self
            .conn
            .prepare(sql)
            .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("prepare {what}: {e}")))?;
        let rows = stmt
            .query_map([], |r| {
                Ok(WebauthnCredentialRow {
                    credential_id: r.get(0)?,
                    public_key_cose: r.get(1)?,
                    user_handle: r.get(2)?,
                    admin_label: r.get(3)?,
                    sign_count: r.get::<_, i64>(4)? as u32,
                    status: CredentialStatus::parse(&r.get::<_, String>(5)?),
                    is_soft: r.get::<_, i64>(6)? != 0,
                    created_at: r.get(7)?,
                    activated_at: r.get(8)?,
                    revoked_at: r.get(9)?,
                })
            })
            .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("{what}: {e}")))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|e| {
                StorageError::new(StorageErrorCode::Io, format!("{what} row: {e}"))
            })?);
        }
        Ok(out)
    }

    pub fn activate_credential(&self, credential_id: &[u8]) -> Result<(), StorageError> {
        let n = self
            .conn
            .execute(
                r#"
                UPDATE webauthn_credentials
                SET status = 'active', activated_at = ?1
                WHERE credential_id = ?2 AND status = 'pending' AND revoked_at IS NULL
                "#,
                params![now_unix(), credential_id],
            )
            .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("activate: {e}")))?;
        if n == 0 {
            return Err(StorageError::new(
                StorageErrorCode::NotFound,
                "pending credential",
            ));
        }
        Ok(())
    }

    pub fn revoke_credential(&self, credential_id: &[u8]) -> Result<(), StorageError> {
        let n = self
            .conn
            .execute(
                r#"
                UPDATE webauthn_credentials
                SET revoked_at = ?1
                WHERE credential_id = ?2 AND revoked_at IS NULL
                "#,
                params![now_unix(), credential_id],
            )
            .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("revoke: {e}")))?;
        if n == 0 {
            return Err(StorageError::new(StorageErrorCode::NotFound, "credential"));
        }
        Ok(())
    }

    pub fn update_sign_count(
        &self,
        credential_id: &[u8],
        sign_count: u32,
    ) -> Result<(), StorageError> {
        self.conn
            .execute(
                "UPDATE webauthn_credentials SET sign_count = ?1 WHERE credential_id = ?2",
                params![sign_count as i64, credential_id],
            )
            .map_err(|e| {
                StorageError::new(StorageErrorCode::Io, format!("update sign_count: {e}"))
            })?;
        Ok(())
    }

    pub fn insert_challenge(&self, row: &WebauthnChallengeRow) -> Result<(), StorageError> {
        self.conn
            .execute(
                r#"
                INSERT INTO webauthn_challenges (
                    challenge_id, op, binding_json, summary, challenge_b64,
                    expires_at, consumed_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                "#,
                params![
                    row.challenge_id,
                    row.op,
                    row.binding_json,
                    row.summary,
                    row.challenge_b64,
                    row.expires_at,
                    row.consumed_at,
                ],
            )
            .map_err(|e| {
                StorageError::new(StorageErrorCode::Io, format!("insert challenge: {e}"))
            })?;
        Ok(())
    }

    pub fn get_challenge(
        &self,
        challenge_id: &str,
    ) -> Result<Option<WebauthnChallengeRow>, StorageError> {
        self.query_challenge("challenge_id = ?1", params![challenge_id])
    }

    pub fn get_challenge_by_b64(
        &self,
        challenge_b64: &str,
    ) -> Result<Option<WebauthnChallengeRow>, StorageError> {
        self.query_challenge("challenge_b64 = ?1", params![challenge_b64])
    }

    fn query_challenge(
        &self,
        where_clause: &str,
        params: impl rusqlite::Params,
    ) -> Result<Option<WebauthnChallengeRow>, StorageError> {
        let sql = format!(
            r#"
            SELECT challenge_id, op, binding_json, summary, challenge_b64, expires_at, consumed_at
            FROM webauthn_challenges WHERE {where_clause}
            "#
        );
        let mut stmt = self.conn.prepare(&sql).map_err(|e| {
            StorageError::new(StorageErrorCode::Io, format!("prepare challenge: {e}"))
        })?;
        let row = stmt
            .query_row(params, |r| {
                Ok(WebauthnChallengeRow {
                    challenge_id: r.get(0)?,
                    op: r.get(1)?,
                    binding_json: r.get(2)?,
                    summary: r.get(3)?,
                    challenge_b64: r.get(4)?,
                    expires_at: r.get(5)?,
                    consumed_at: r.get(6)?,
                })
            })
            .optional()
            .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("get challenge: {e}")))?;
        Ok(row)
    }

    pub fn consume_challenge(&self, challenge_id: &str) -> Result<(), StorageError> {
        let n = self
            .conn
            .execute(
                r#"
                UPDATE webauthn_challenges
                SET consumed_at = ?1
                WHERE challenge_id = ?2 AND consumed_at IS NULL
                "#,
                params![now_unix(), challenge_id],
            )
            .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("consume: {e}")))?;
        if n == 0 {
            return Err(StorageError::new(
                StorageErrorCode::ChallengeUnknown,
                "consume",
            ));
        }
        Ok(())
    }

    pub fn purge_expired_challenges(&self) -> Result<u32, StorageError> {
        let n = self
            .conn
            .execute(
                "DELETE FROM webauthn_challenges WHERE expires_at < ?1 OR (consumed_at IS NOT NULL AND consumed_at < ?2)",
                params![now_unix(), now_unix().saturating_sub(3600)],
            )
            .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("purge: {e}")))?;
        Ok(n as u32)
    }

    /// Mark PENDING credentials older than `ttl_hours` as `expired` (no delete).
    /// `ttl_hours == 0` disables the transition.
    pub fn expire_stale_pending_credentials(&self, ttl_hours: u64) -> Result<u32, StorageError> {
        if ttl_hours == 0 {
            return Ok(0);
        }
        let ttl_secs = (ttl_hours as i64).saturating_mul(3600);
        let cutoff = now_unix().saturating_sub(ttl_secs);
        let n = self
            .conn
            .execute(
                r#"
                UPDATE webauthn_credentials
                SET status = 'expired'
                WHERE status = 'pending'
                  AND revoked_at IS NULL
                  AND created_at < ?1
                "#,
                params![cutoff],
            )
            .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("expire pending: {e}")))?;
        Ok(n as u32)
    }

    pub fn delete_challenges_matching_upload(&self, upload_id: &str) -> Result<(), StorageError> {
        // binding_json contains "upload_id":"..."
        let needle = format!("\"upload_id\":\"{upload_id}\"");
        self.conn
            .execute(
                "DELETE FROM webauthn_challenges WHERE binding_json LIKE ?1 AND consumed_at IS NULL",
                params![format!("%{needle}%")],
            )
            .map_err(|e| {
                StorageError::new(StorageErrorCode::Io, format!("drop upload challenges: {e}"))
            })?;
        Ok(())
    }

    pub fn list_pending_challenges(&self) -> Result<Vec<WebauthnChallengeRow>, StorageError> {
        let mut stmt = self
            .conn
            .prepare(
                r#"
                SELECT challenge_id, op, binding_json, summary, challenge_b64, expires_at, consumed_at
                FROM webauthn_challenges
                WHERE consumed_at IS NULL AND expires_at >= ?1
                ORDER BY expires_at ASC
                "#,
            )
            .map_err(|e| {
                StorageError::new(StorageErrorCode::Io, format!("prepare pending ch: {e}"))
            })?;
        let rows = stmt
            .query_map(params![now_unix()], |r| {
                Ok(WebauthnChallengeRow {
                    challenge_id: r.get(0)?,
                    op: r.get(1)?,
                    binding_json: r.get(2)?,
                    summary: r.get(3)?,
                    challenge_b64: r.get(4)?,
                    expires_at: r.get(5)?,
                    consumed_at: r.get(6)?,
                })
            })
            .map_err(|e| {
                StorageError::new(StorageErrorCode::Io, format!("list pending ch: {e}"))
            })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|e| {
                StorageError::new(StorageErrorCode::Io, format!("pending ch row: {e}"))
            })?);
        }
        Ok(out)
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

    #[test]
    fn expire_stale_pending_credentials_by_ttl_hours() {
        let dir = tempdir().unwrap();
        let db = MetaDb::open(dir.path()).unwrap();
        let old = now_unix().saturating_sub(25 * 3600);
        db.insert_credential(&WebauthnCredentialRow {
            credential_id: b"stale-pend".to_vec(),
            public_key_cose: b"cose".to_vec(),
            user_handle: "1".into(),
            admin_label: "old".into(),
            sign_count: 0,
            status: CredentialStatus::Pending,
            is_soft: true,
            created_at: old,
            activated_at: None,
            revoked_at: None,
        })
        .unwrap();
        db.insert_credential(&WebauthnCredentialRow {
            credential_id: b"fresh-pend".to_vec(),
            public_key_cose: b"cose2".to_vec(),
            user_handle: "1".into(),
            admin_label: "new".into(),
            sign_count: 0,
            status: CredentialStatus::Pending,
            is_soft: true,
            created_at: now_unix(),
            activated_at: None,
            revoked_at: None,
        })
        .unwrap();
        assert_eq!(db.expire_stale_pending_credentials(0).unwrap(), 0);
        assert_eq!(db.list_pending_credentials().unwrap().len(), 2);
        assert_eq!(db.expire_stale_pending_credentials(24).unwrap(), 1);
        let pending = db.list_pending_credentials().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].admin_label, "new");
        let stale = db.get_credential(b"stale-pend").unwrap().unwrap();
        assert_eq!(stale.status, CredentialStatus::Expired);
    }
}
