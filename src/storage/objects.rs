//! Postgres `storage_objects` helpers (portal **mirror** of helper SQLite SoT).

use std::io::Cursor;
use std::time::{SystemTime, UNIX_EPOCH};

use toasty::Db;
use uuid::Uuid;

use crate::models::{STORAGE_ORG_NONE, STORAGE_SCOPE_IMAGE, STORAGE_SCOPE_RELEASE, StorageObject};
use crate::release_pkg::size_mb_from_bytes;

use super::client::{StorageClient, write_and_hash};
use super::error::{StorageError, StorageErrorCode};
use super::ids::normalize_image_ext;

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Lookup release blob metadata by catalog release id.
pub async fn find_release_object(db: &mut Db, release_id: u64) -> Option<StorageObject> {
    let key = release_id.to_string();
    let rows = StorageObject::all()
        .filter(
            StorageObject::fields()
                .scope()
                .eq(STORAGE_SCOPE_RELEASE.to_owned()),
        )
        .filter(StorageObject::fields().object_key().eq(key))
        .limit(1)
        .exec(db)
        .await
        .ok()?;
    rows.into_iter().next()
}

/// Lookup image blob metadata.
pub async fn find_image_object(
    db: &mut Db,
    org_id: u64,
    image_id: &str,
    ext: &str,
) -> Option<StorageObject> {
    let key = format!("{org_id}/{image_id}.{ext}");
    let rows = StorageObject::all()
        .filter(
            StorageObject::fields()
                .scope()
                .eq(STORAGE_SCOPE_IMAGE.to_owned()),
        )
        .filter(StorageObject::fields().object_key().eq(key))
        .limit(1)
        .exec(db)
        .await
        .ok()?;
    rows.into_iter().next()
}

/// Upsert release digest/size after a successful helper `put_commit`.
pub async fn upsert_release_object(
    db: &mut Db,
    release_id: u64,
    sha256: &str,
    size_bytes: u64,
) -> Result<StorageObject, StorageError> {
    let sha = sha256.trim().to_ascii_lowercase();
    if sha.len() != 64 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(StorageError::new(
            StorageErrorCode::DigestMismatch,
            "invalid sha256",
        ));
    }
    let key = release_id.to_string();
    let ts = now_unix();
    if let Some(mut existing) = find_release_object(db, release_id).await {
        existing
            .update()
            .sha256(sha)
            .size_bytes(size_bytes)
            .updated_at(ts)
            .exec(db)
            .await
            .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("db update: {e}")))?;
        return find_release_object(db, release_id)
            .await
            .ok_or_else(|| StorageError::new(StorageErrorCode::Io, "missing after update"));
    }
    toasty::create!(StorageObject {
        scope: STORAGE_SCOPE_RELEASE.to_owned(),
        object_key: key,
        organization_id: STORAGE_ORG_NONE,
        sha256: sha,
        size_bytes,
        content_type: String::new(),
        created_at: ts,
        updated_at: ts,
    })
    .exec(db)
    .await
    .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("db create: {e}")))
}

/// Put one tenant image through the helper and mirror it in Postgres.
/// Returns the canonical token `{uuid}.{ext}` (`jpg` normalized to `jpeg`).
pub async fn put_tenant_image(
    db: &mut Db,
    client: &StorageClient,
    org_id: u64,
    bytes: &[u8],
    ext: &str,
) -> Result<String, StorageError> {
    let Some(ext) = normalize_image_ext(ext) else {
        return Err(StorageError::new(
            StorageErrorCode::BadImage,
            "unsupported image type",
        ));
    };
    if bytes.is_empty() {
        return Err(StorageError::new(StorageErrorCode::BadImage, "empty image"));
    }
    let image_id = Uuid::new_v4().to_string();
    let (upload_id, mut file) = client.put_begin_image(org_id, bytes.len() as u64, ext)?;
    let (size, sha) = match write_and_hash(&mut file, Cursor::new(bytes)) {
        Ok(v) => v,
        Err(e) => {
            let _ = client.put_abort(&upload_id);
            return Err(e);
        }
    };
    drop(file);
    client.put_commit_image(&upload_id, org_id, &image_id, ext, &sha)?;
    upsert_image_object(db, org_id, &image_id, ext, &sha, size).await?;
    Ok(format!("{image_id}.{ext}"))
}

/// Upsert image digest/size after a successful helper `put_commit`.
pub async fn upsert_image_object(
    db: &mut Db,
    org_id: u64,
    image_id: &str,
    ext: &str,
    sha256: &str,
    size_bytes: u64,
) -> Result<StorageObject, StorageError> {
    let sha = sha256.trim().to_ascii_lowercase();
    if sha.len() != 64 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(StorageError::new(
            StorageErrorCode::DigestMismatch,
            "invalid sha256",
        ));
    }
    let key = format!("{org_id}/{image_id}.{ext}");
    let ts = now_unix();
    if let Some(mut existing) = find_image_object(db, org_id, image_id, ext).await {
        existing
            .update()
            .sha256(sha)
            .size_bytes(size_bytes)
            .content_type(ext.to_owned())
            .updated_at(ts)
            .exec(db)
            .await
            .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("db update: {e}")))?;
        return find_image_object(db, org_id, image_id, ext)
            .await
            .ok_or_else(|| StorageError::new(StorageErrorCode::Io, "missing after update"));
    }
    toasty::create!(StorageObject {
        scope: STORAGE_SCOPE_IMAGE.to_owned(),
        object_key: key,
        organization_id: org_id,
        sha256: sha,
        size_bytes,
        content_type: ext.to_owned(),
        created_at: ts,
        updated_at: ts,
    })
    .exec(db)
    .await
    .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("db create: {e}")))
}

pub async fn delete_release_object(db: &mut Db, release_id: u64) -> Result<(), StorageError> {
    if let Some(obj) = find_release_object(db, release_id).await {
        obj.delete()
            .exec(db)
            .await
            .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("db delete: {e}")))?;
    }
    Ok(())
}

pub async fn delete_org_objects(db: &mut Db, org_id: u64) -> Result<u32, StorageError> {
    let rows = StorageObject::all()
        .filter(
            StorageObject::fields()
                .scope()
                .eq(STORAGE_SCOPE_IMAGE.to_owned()),
        )
        .filter(StorageObject::fields().organization_id().eq(org_id))
        .exec(db)
        .await
        .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("db list: {e}")))?;
    let n = rows.len() as u32;
    for row in rows {
        row.delete()
            .exec(db)
            .await
            .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("db delete: {e}")))?;
    }
    Ok(n)
}

/// Display helpers for Builds / admin list UI.
#[derive(Debug, Clone)]
pub struct BlobDisplay {
    pub sha256: String,
    pub size_mb: String,
    pub size_bytes: u64,
}

impl BlobDisplay {
    pub fn pending() -> Self {
        Self {
            sha256: "pending".into(),
            size_mb: "—".into(),
            size_bytes: 0,
        }
    }

    pub fn from_object(obj: &StorageObject) -> Self {
        Self {
            sha256: obj.sha256.clone(),
            size_mb: size_mb_from_bytes(obj.size_bytes),
            size_bytes: obj.size_bytes,
        }
    }
}

pub async fn release_blob_display(db: &mut Db, release_id: u64) -> BlobDisplay {
    find_release_object(db, release_id)
        .await
        .map(|o| BlobDisplay::from_object(&o))
        .unwrap_or_else(BlobDisplay::pending)
}

/// Map helper / storage errors onto artifact HTTP status codes.
pub fn storage_http_status(err: &StorageError) -> u16 {
    match err.code {
        StorageErrorCode::NotFound => 404,
        StorageErrorCode::Busy
        | StorageErrorCode::Quota
        | StorageErrorCode::OrgQuota
        | StorageErrorCode::IntegrityMismatch
        | StorageErrorCode::Io => 503,
        StorageErrorCode::DigestMismatch
        | StorageErrorCode::BadImage
        | StorageErrorCode::InvalidId
        | StorageErrorCode::WebauthnRequired
        | StorageErrorCode::WebauthnInvalid
        | StorageErrorCode::WebauthnExpired
        | StorageErrorCode::ChallengeUnknown
        | StorageErrorCode::ObjectModified => 400,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::StorageObject;

    #[test]
    fn pending_display_is_safe() {
        let d = BlobDisplay::pending();
        assert_eq!(d.sha256, "pending");
        assert_eq!(d.size_mb, "—");
    }

    #[test]
    fn from_object_formats_mb() {
        let obj = StorageObject {
            id: 1,
            scope: STORAGE_SCOPE_RELEASE.into(),
            object_key: "1".into(),
            organization_id: 0,
            sha256: "a".repeat(64),
            size_bytes: 1_048_576,
            content_type: String::new(),
            created_at: 0,
            updated_at: 0,
        };
        let d = BlobDisplay::from_object(&obj);
        assert_eq!(d.size_mb, "1.0");
        assert_eq!(d.sha256.len(), 64);
    }

    #[test]
    fn http_mapping_closed() {
        assert_eq!(
            storage_http_status(&StorageError::new(StorageErrorCode::NotFound, "x")),
            404
        );
        assert_eq!(
            storage_http_status(&StorageError::new(StorageErrorCode::Io, "x")),
            503
        );
        assert_eq!(
            storage_http_status(&StorageError::new(StorageErrorCode::DigestMismatch, "x")),
            400
        );
        assert_eq!(
            storage_http_status(&StorageError::new(StorageErrorCode::IntegrityMismatch, "x")),
            503
        );
    }
}
