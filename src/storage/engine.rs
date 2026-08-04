//! Portable blob engine: dirfd semantics via `cap-std`, tmp+rename, digest.

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ambient_authority::ambient_authority;
use cap_std::fs::{Dir, OpenOptions};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::config::StorageConfig;
use serde_json::json;

use super::audit::WebauthnAudit;
use super::error::{StorageError, StorageErrorCode};
use super::ids::{
    StorageScope, image_rel_path, is_decimal_id, is_uuid_key, normalize_image_ext,
    release_rel_path, tmp_rel_path,
};
use super::meta_db::{
    CredentialStatus, MetaDb, MetaObject, WebauthnCredentialRow, ct_eq_hex, image_object_key,
    release_object_key,
};
use super::sniff::sniff_matches_ext;
use super::webauthn::{
    ChallengeIssued, credential_fingerprint, drop_challenge_for_upload, issue_challenge,
    verify_and_consume,
};

#[derive(Debug, Clone)]
pub struct PutBeginOk {
    pub upload_id: String,
}

#[derive(Debug, Clone)]
pub struct ObjectStat {
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone)]
pub struct PrepareOk {
    pub digest: String,
    pub challenge: ChallengeIssued,
}

#[derive(Clone)]
struct InflightUpload {
    scope: StorageScope,
    release_id: Option<String>,
    org_id: Option<String>,
    ext: Option<String>,
    declared_size: u64,
    prepared_digest: Option<String>,
    challenge_id: Option<String>,
}

/// In-process storage engine (also used by `vcp-store`).
pub struct StorageEngine {
    dir: Dir,
    root: PathBuf,
    cfg: StorageConfig,
    inflight: Mutex<HashMap<String, InflightUpload>>,
    meta: Mutex<MetaDb>,
    audit: WebauthnAudit,
}

impl StorageEngine {
    pub fn open(root: impl AsRef<Path>, cfg: StorageConfig) -> Result<Self, StorageError> {
        let root = root.as_ref().to_path_buf();
        if !root.is_absolute() {
            return Err(StorageError::new(
                StorageErrorCode::Io,
                "blob_path must be absolute",
            ));
        }
        std::fs::create_dir_all(&root).map_err(|e| {
            StorageError::new(StorageErrorCode::Io, format!("create blob root: {e}"))
        })?;
        let dir = Dir::open_ambient_dir(&root, ambient_authority())
            .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("open blob root: {e}")))?;
        for sub in ["releases", "images", "tmp", "audit"] {
            if !dir.exists(sub) {
                match dir.create_dir(sub) {
                    Ok(()) => {}
                    // Concurrent openers (tests / multi-helper) may race create.
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(e) => {
                        return Err(StorageError::new(
                            StorageErrorCode::Io,
                            format!("mkdirat {sub}: {e}"),
                        ));
                    }
                }
            }
        }
        let meta = MetaDb::open(&root)?;
        let audit = WebauthnAudit::open(&root)?;
        let engine = Self {
            dir,
            root,
            cfg,
            inflight: Mutex::new(HashMap::new()),
            meta: Mutex::new(meta),
            audit,
        };
        engine.purge_expired_tmp()?;
        Ok(engine)
    }

    /// Refuse production boot when WebAuthn is disabled (architecture §3.2).
    pub fn validate_production_webauthn(
        production: bool,
        cfg: &StorageConfig,
    ) -> Result<(), String> {
        if production && !cfg.webauthn_required {
            return Err(
                "production refuses webauthn_required=false (architecture 1.2 / ADR)".into(),
            );
        }
        if cfg.webauthn_user_verification != "required" {
            return Err("webauthn_user_verification must be \"required\"".into());
        }
        Ok(())
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn cfg(&self) -> &StorageConfig {
        &self.cfg
    }

    pub fn meta_db_path(&self) -> PathBuf {
        self.meta.lock().expect("meta mutex").path().to_path_buf()
    }

    pub fn purge_expired_tmp(&self) -> Result<u32, StorageError> {
        let ttl = Duration::from_secs(self.cfg.upload_ttl_secs.max(1));
        let now = SystemTime::now();
        let mut removed = 0u32;
        let entries = self
            .dir
            .read_dir("tmp")
            .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("read tmp: {e}")))?;
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !name.ends_with(".partial") {
                continue;
            }
            let abs = self.root.join(format!("tmp/{name}"));
            let stale = std::fs::metadata(&abs)
                .and_then(|m| m.modified())
                .map(|m| now.duration_since(m).unwrap_or_default() > ttl)
                .unwrap_or(true);
            if stale {
                let _ = self.dir.remove_file(format!("tmp/{name}"));
                removed = removed.saturating_add(1);
            }
        }
        Ok(removed)
    }

    pub fn put_begin(
        &self,
        scope: StorageScope,
        release_id: Option<&str>,
        org_id: Option<&str>,
        declared_size: u64,
        ext: Option<&str>,
    ) -> Result<PutBeginOk, StorageError> {
        {
            let map = self.inflight.lock().expect("inflight mutex");
            if map.len() as u32 >= self.cfg.max_concurrent_uploads.max(1) {
                return Err(StorageError::new(
                    StorageErrorCode::Busy,
                    "too many uploads",
                ));
            }
        }

        let max = match scope {
            StorageScope::Release => self.cfg.max_artifact_bytes,
            StorageScope::Image => self.cfg.max_image_bytes,
        };
        if declared_size == 0 || declared_size > max {
            return Err(StorageError::new(StorageErrorCode::Quota, "declared_size"));
        }

        match scope {
            StorageScope::Release => {
                let id = release_id.ok_or_else(|| {
                    StorageError::new(StorageErrorCode::InvalidId, "missing release_id")
                })?;
                if !is_decimal_id(id) {
                    return Err(StorageError::new(StorageErrorCode::InvalidId, "release_id"));
                }
            }
            StorageScope::Image => {
                let org = org_id.ok_or_else(|| {
                    StorageError::new(StorageErrorCode::InvalidId, "missing org_id")
                })?;
                if !is_decimal_id(org) {
                    return Err(StorageError::new(StorageErrorCode::InvalidId, "org_id"));
                }
                let ext = ext
                    .ok_or_else(|| StorageError::new(StorageErrorCode::InvalidId, "missing ext"))?;
                if normalize_image_ext(ext).is_none() {
                    return Err(StorageError::new(StorageErrorCode::BadImage, "ext"));
                }
                let count = self.count_org_images(org)?;
                if count >= self.cfg.max_images_per_org as u64 {
                    return Err(StorageError::new(
                        StorageErrorCode::OrgQuota,
                        "max_images_per_org",
                    ));
                }
                if !self.dir.exists(format!("images/{org}")) {
                    self.dir.create_dir(format!("images/{org}")).map_err(|e| {
                        StorageError::new(StorageErrorCode::Io, format!("mkdir images: {e}"))
                    })?;
                }
            }
        }

        let upload_id = Uuid::new_v4().to_string();
        let rel = tmp_rel_path(&upload_id).expect("uuid upload id");
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true).read(true);
        let _file = self
            .dir
            .open_with(&rel, &opts)
            .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("create partial: {e}")))?;

        self.inflight.lock().expect("inflight mutex").insert(
            upload_id.clone(),
            InflightUpload {
                scope,
                release_id: release_id.map(str::to_owned),
                org_id: org_id.map(str::to_owned),
                ext: ext.map(str::to_owned),
                declared_size,
                prepared_digest: None,
                challenge_id: None,
            },
        );
        Ok(PutBeginOk { upload_id })
    }

    /// Hash the partial (release), issue WebAuthn challenge; no renameat.
    pub fn put_prepare(
        &self,
        upload_id: &str,
        expected_sha256: &str,
    ) -> Result<PrepareOk, StorageError> {
        let meta = {
            let map = self.inflight.lock().expect("inflight mutex");
            map.get(upload_id)
                .cloned()
                .ok_or_else(|| StorageError::new(StorageErrorCode::NotFound, "unknown upload_id"))?
        };
        if meta.scope != StorageScope::Release {
            return Err(StorageError::new(
                StorageErrorCode::InvalidId,
                "put_prepare is release-only",
            ));
        }
        let (digest, size) = self.hash_partial(upload_id, &meta)?;
        let expected = expected_sha256.trim().to_ascii_lowercase();
        if digest != expected
            || expected.len() != 64
            || !expected.chars().all(|c| c.is_ascii_hexdigit())
        {
            return Err(StorageError::new(
                StorageErrorCode::DigestMismatch,
                "sha256",
            ));
        }
        let _ = size;
        let release_id = meta.release_id.clone().unwrap_or_default();
        let binding = json!({
            "op": "release_put_commit",
            "release_id": release_id,
            "upload_id": upload_id,
            "digest": digest,
        });
        let db = self.meta.lock().expect("meta mutex");
        let issued = issue_challenge(
            &db,
            &self.audit,
            "release_put_commit",
            binding,
            self.cfg.webauthn_challenge_ttl_secs,
            &self.cfg.webauthn_rp_id,
        )?;
        drop(db);
        {
            let mut map = self.inflight.lock().expect("inflight mutex");
            if let Some(row) = map.get_mut(upload_id) {
                row.prepared_digest = Some(digest.clone());
                row.challenge_id = Some(issued.challenge_id.clone());
            }
        }
        Ok(PrepareOk {
            digest,
            challenge: issued,
        })
    }

    fn hash_partial(
        &self,
        upload_id: &str,
        meta: &InflightUpload,
    ) -> Result<(String, u64), StorageError> {
        let rel_tmp = tmp_rel_path(upload_id)
            .ok_or_else(|| StorageError::new(StorageErrorCode::InvalidId, "upload_id"))?;
        let mut open_opts = OpenOptions::new();
        open_opts.read(true).write(true);
        let mut file = self
            .dir
            .open_with(&rel_tmp, &open_opts)
            .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("open partial: {e}")))?;
        let size = file
            .seek(SeekFrom::End(0))
            .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("seek: {e}")))?;
        let max = match meta.scope {
            StorageScope::Release => self.cfg.max_artifact_bytes,
            StorageScope::Image => self.cfg.max_image_bytes,
        };
        if size == 0 || size > max || size > meta.declared_size {
            return Err(StorageError::new(StorageErrorCode::Quota, "size"));
        }
        file.seek(SeekFrom::Start(0))
            .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("rewind: {e}")))?;
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = file
                .read(&mut buf)
                .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("read: {e}")))?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Ok((hex::encode(hasher.finalize()), size))
    }

    /// Absolute path to the partial file (for FD handoff / streaming tests).
    pub fn partial_abs_path(&self, upload_id: &str) -> Result<PathBuf, StorageError> {
        let rel = tmp_rel_path(upload_id)
            .ok_or_else(|| StorageError::new(StorageErrorCode::InvalidId, "upload_id"))?;
        Ok(self.root.join(rel))
    }

    pub fn put_commit(
        &self,
        upload_id: &str,
        expected_sha256: &str,
        image_id: Option<&str>,
        assertion: Option<&str>,
    ) -> Result<ObjectStat, StorageError> {
        // Peek first so WebAuthn failures keep the inflight upload for retry.
        let meta = {
            let map = self.inflight.lock().expect("inflight mutex");
            map.get(upload_id)
                .cloned()
                .ok_or_else(|| StorageError::new(StorageErrorCode::NotFound, "unknown upload_id"))?
        };

        if meta.scope == StorageScope::Release && self.cfg.webauthn_required {
            let assertion = assertion.ok_or_else(|| {
                StorageError::new(StorageErrorCode::WebauthnRequired, "assertion")
            })?;
            let digest = meta.prepared_digest.clone().ok_or_else(|| {
                StorageError::new(StorageErrorCode::WebauthnRequired, "put_prepare first")
            })?;
            let expected = expected_sha256.trim().to_ascii_lowercase();
            if !ct_eq_hex(&digest, &expected) {
                return Err(StorageError::new(
                    StorageErrorCode::DigestMismatch,
                    "sha256",
                ));
            }
            let binding = json!({
                "op": "release_put_commit",
                "release_id": meta.release_id.clone().unwrap_or_default(),
                "upload_id": upload_id,
                "digest": digest,
            });
            let db = self.meta.lock().expect("meta mutex");
            verify_and_consume(
                &db,
                &self.audit,
                assertion,
                "release_put_commit",
                &binding,
                &self.cfg.webauthn_rp_id,
                &self.cfg.webauthn_origin,
                self.cfg.webauthn_strict_sign_count,
                true,
            )?;
            drop(db);
        }

        let meta = {
            let mut map = self.inflight.lock().expect("inflight mutex");
            map.remove(upload_id)
                .ok_or_else(|| StorageError::new(StorageErrorCode::NotFound, "unknown upload_id"))?
        };

        let rel_tmp = tmp_rel_path(upload_id)
            .ok_or_else(|| StorageError::new(StorageErrorCode::InvalidId, "upload_id"))?;

        let mut open_opts = OpenOptions::new();
        open_opts.read(true).write(true);
        let mut file = self
            .dir
            .open_with(&rel_tmp, &open_opts)
            .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("open partial: {e}")))?;

        let size = file
            .seek(SeekFrom::End(0))
            .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("seek: {e}")))?;
        let max = match meta.scope {
            StorageScope::Release => self.cfg.max_artifact_bytes,
            StorageScope::Image => self.cfg.max_image_bytes,
        };
        if size == 0 || size > max || size > meta.declared_size {
            let _ = self.dir.remove_file(&rel_tmp);
            return Err(StorageError::new(StorageErrorCode::Quota, "size"));
        }

        file.seek(SeekFrom::Start(0))
            .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("rewind: {e}")))?;
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 64 * 1024];
        let mut head = Vec::with_capacity(16);
        loop {
            let n = file
                .read(&mut buf)
                .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("read: {e}")))?;
            if n == 0 {
                break;
            }
            if head.len() < 16 {
                let need = 16 - head.len();
                head.extend_from_slice(&buf[..n.min(need)]);
            }
            hasher.update(&buf[..n]);
        }
        let digest = hex::encode(hasher.finalize());
        let expected = expected_sha256.trim().to_ascii_lowercase();
        if digest != expected
            || expected.len() != 64
            || !expected.chars().all(|c| c.is_ascii_hexdigit())
        {
            let _ = self.dir.remove_file(&rel_tmp);
            return Err(StorageError::new(
                StorageErrorCode::DigestMismatch,
                "sha256",
            ));
        }

        let dest = match meta.scope {
            StorageScope::Release => {
                let id = meta.release_id.as_deref().unwrap_or("");
                release_rel_path(id)
                    .ok_or_else(|| StorageError::new(StorageErrorCode::InvalidId, "release_id"))?
            }
            StorageScope::Image => {
                let org = meta.org_id.as_deref().unwrap_or("");
                let img = image_id.ok_or_else(|| {
                    StorageError::new(StorageErrorCode::InvalidId, "missing image_id")
                })?;
                if !is_uuid_key(img) {
                    let _ = self.dir.remove_file(&rel_tmp);
                    return Err(StorageError::new(StorageErrorCode::InvalidId, "image_id"));
                }
                let ext = meta.ext.as_deref().unwrap_or("");
                sniff_matches_ext(&head, ext).map_err(|_| {
                    let _ = self.dir.remove_file(&rel_tmp);
                    StorageError::new(StorageErrorCode::BadImage, "sniff")
                })?;
                image_rel_path(org, img, ext)
                    .ok_or_else(|| StorageError::new(StorageErrorCode::InvalidId, "image path"))?
            }
        };

        file.sync_all()
            .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("fsync: {e}")))?;
        drop(file);

        // Atomic replace within the same blob_path.
        if self.dir.exists(&dest) {
            let _ = self.dir.remove_file(&dest);
        }
        if let Some(parent) = Path::new(&dest).parent()
            && !parent.as_os_str().is_empty()
            && !self.dir.exists(parent)
        {
            self.dir.create_dir(parent).map_err(|e| {
                StorageError::new(StorageErrorCode::Io, format!("mkdir parent: {e}"))
            })?;
        }
        self.dir.rename(&rel_tmp, &self.dir, &dest).map_err(|e| {
            let _ = self.dir.remove_file(&rel_tmp);
            StorageError::new(StorageErrorCode::Io, format!("renameat: {e}"))
        })?;

        let (object_key, org_id, content_type, ext) = match meta.scope {
            StorageScope::Release => {
                let id = meta.release_id.as_deref().unwrap_or("");
                (
                    release_object_key(id),
                    String::new(),
                    String::new(),
                    String::new(),
                )
            }
            StorageScope::Image => {
                let org = meta.org_id.as_deref().unwrap_or("").to_owned();
                let img = image_id.unwrap_or("");
                let ext = meta.ext.as_deref().unwrap_or("").to_owned();
                (image_object_key(&org, img, &ext), org, String::new(), ext)
            }
        };
        {
            let db = self.meta.lock().expect("meta mutex");
            db.upsert(&MetaObject {
                scope: meta.scope,
                object_key,
                org_id,
                sha256: digest.clone(),
                size_bytes: size,
                content_type,
                ext,
            })?;
        }

        Ok(ObjectStat {
            size,
            sha256: digest,
        })
    }

    pub fn put_abort(&self, upload_id: &str) -> Result<(), StorageError> {
        let _ = self
            .inflight
            .lock()
            .expect("inflight mutex")
            .remove(upload_id);
        {
            let db = self.meta.lock().expect("meta mutex");
            let _ = drop_challenge_for_upload(&db, upload_id);
        }
        if let Some(rel) = tmp_rel_path(upload_id) {
            let _ = self.dir.remove_file(rel);
        }
        Ok(())
    }

    pub fn challenge_begin_delete(
        &self,
        scope: StorageScope,
        release_id: Option<&str>,
        org_id: Option<&str>,
        image_id: Option<&str>,
        ext: Option<&str>,
    ) -> Result<ChallengeIssued, StorageError> {
        let object_key = match scope {
            StorageScope::Release => release_object_key(release_id.unwrap_or("")),
            StorageScope::Image => image_object_key(
                org_id.unwrap_or(""),
                image_id.unwrap_or(""),
                ext.unwrap_or(""),
            ),
        };
        let sot_sha = {
            let db = self.meta.lock().expect("meta mutex");
            db.get(scope, &object_key)?.map(|o| o.sha256)
        };
        let mut binding = json!({
            "op": "delete",
            "scope": scope.as_str(),
        });
        if let Some(obj) = binding.as_object_mut() {
            if let Some(id) = release_id {
                obj.insert("release_id".into(), json!(id));
            }
            if let Some(id) = org_id {
                obj.insert("org_id".into(), json!(id));
            }
            if let Some(id) = image_id {
                obj.insert("image_id".into(), json!(id));
            }
            if let Some(e) = ext {
                obj.insert("ext".into(), json!(e));
            }
            if let Some(sha) = &sot_sha {
                obj.insert("sha256".into(), json!(sha));
            }
        }
        let db = self.meta.lock().expect("meta mutex");
        issue_challenge(
            &db,
            &self.audit,
            "delete",
            binding,
            self.cfg.webauthn_challenge_ttl_secs,
            &self.cfg.webauthn_rp_id,
        )
    }

    pub fn challenge_begin_delete_org(
        &self,
        org_id: &str,
    ) -> Result<ChallengeIssued, StorageError> {
        if !is_decimal_id(org_id) {
            return Err(StorageError::new(StorageErrorCode::InvalidId, "org_id"));
        }
        let binding = json!({"op": "delete_org", "org_id": org_id});
        let db = self.meta.lock().expect("meta mutex");
        issue_challenge(
            &db,
            &self.audit,
            "delete_org",
            binding,
            self.cfg.webauthn_challenge_ttl_secs,
            &self.cfg.webauthn_rp_id,
        )
    }

    pub fn ctap2_enrol_stage(
        &self,
        credential_id: &[u8],
        public_key_cose: &[u8],
        user_handle: &str,
        admin_label: &str,
        is_soft: bool,
    ) -> Result<String, StorageError> {
        let fp = credential_fingerprint(credential_id, public_key_cose);
        let db = self.meta.lock().expect("meta mutex");
        db.insert_credential(&WebauthnCredentialRow {
            credential_id: credential_id.to_vec(),
            public_key_cose: public_key_cose.to_vec(),
            user_handle: user_handle.to_owned(),
            admin_label: admin_label.to_owned(),
            sign_count: 0,
            status: CredentialStatus::Pending,
            is_soft,
            created_at: now_unix(),
            activated_at: None,
            revoked_at: None,
        })?;
        let _ = self.audit.append(
            "enrol_stage",
            json!({
                "fingerprint": fp,
                "admin_label": admin_label,
                "user_handle": user_handle,
            }),
        );
        Ok(fp)
    }

    pub fn ctap2_approve(&self, expected_fingerprint: &str) -> Result<(), StorageError> {
        let db = self.meta.lock().expect("meta mutex");
        let pending = db.list_pending_credentials()?;
        let mut matched = None;
        for row in pending {
            let fp = credential_fingerprint(&row.credential_id, &row.public_key_cose);
            if ct_eq_hex(&fp, &expected_fingerprint.trim().to_ascii_lowercase())
                || fp == expected_fingerprint.trim().to_ascii_lowercase()
            {
                matched = Some(row);
                break;
            }
        }
        let Some(row) = matched else {
            return Err(StorageError::new(
                StorageErrorCode::WebauthnInvalid,
                "fingerprint mismatch",
            ));
        };
        let fp = credential_fingerprint(&row.credential_id, &row.public_key_cose);
        db.activate_credential(&row.credential_id)?;
        let _ = self.audit.append(
            "ctap2_approve",
            json!({
                "fingerprint": fp,
                "admin_label": row.admin_label,
            }),
        );
        Ok(())
    }

    pub fn ctap2_revoke(&self, credential_id: &[u8]) -> Result<(), StorageError> {
        let db = self.meta.lock().expect("meta mutex");
        db.revoke_credential(credential_id)?;
        let _ = self.audit.append(
            "ctap2_revoke",
            json!({
                "credential_id": hex::encode(credential_id),
            }),
        );
        tracing::warn!(
            target: "vcp_storage_alert",
            cred = %hex::encode(credential_id),
            "ALERT ctap2_revoke"
        );
        Ok(())
    }

    pub fn list_pending_challenges_cli(
        &self,
    ) -> Result<Vec<super::meta_db::WebauthnChallengeRow>, StorageError> {
        let db = self.meta.lock().expect("meta mutex");
        db.list_pending_challenges()
    }

    /// PENDING credentials awaiting E2 (`ctap2 approve`) — helper-host ops view.
    pub fn list_pending_credentials_cli(&self) -> Result<Vec<WebauthnCredentialRow>, StorageError> {
        let db = self.meta.lock().expect("meta mutex");
        db.list_pending_credentials()
    }

    /// All credentials (pending / active / revoked) for `ctap2 list`.
    pub fn list_all_credentials_cli(&self) -> Result<Vec<WebauthnCredentialRow>, StorageError> {
        let db = self.meta.lock().expect("meta mutex");
        db.list_all_credentials()
    }

    /// JSON list of pending or active credentials for IPC / CTAP2 UI.
    pub fn ctap2_list_json(&self, kind: &str) -> Result<String, StorageError> {
        let db = self.meta.lock().expect("meta mutex");
        let rows = match kind {
            "pending" => db.list_pending_credentials()?,
            _ => db.list_active_credentials()?,
        };
        let items: Vec<serde_json::Value> = rows
            .into_iter()
            .map(|r| {
                json!({
                    "credential_id_hex": hex::encode(&r.credential_id),
                    "fingerprint": credential_fingerprint(&r.credential_id, &r.public_key_cose),
                    "admin_label": r.admin_label,
                    "user_handle": r.user_handle,
                    "status": r.status.as_str(),
                    "is_soft": r.is_soft,
                })
            })
            .collect();
        Ok(serde_json::to_string(&items).unwrap_or_else(|_| "[]".into()))
    }

    pub fn seed_soft_active_credential(
        &self,
        credential_id: &[u8],
        admin_label: &str,
    ) -> Result<String, StorageError> {
        let cose = b"soft-cose-placeholder".to_vec();
        let fp = credential_fingerprint(credential_id, &cose);
        let db = self.meta.lock().expect("meta mutex");
        db.insert_credential(&WebauthnCredentialRow {
            credential_id: credential_id.to_vec(),
            public_key_cose: cose,
            user_handle: "soft".into(),
            admin_label: admin_label.to_owned(),
            sign_count: 0,
            status: CredentialStatus::Active,
            is_soft: true,
            created_at: now_unix(),
            activated_at: Some(now_unix()),
            revoked_at: None,
        })?;
        Ok(fp)
    }

    pub fn get_stat(
        &self,
        scope: StorageScope,
        release_id: Option<&str>,
        org_id: Option<&str>,
        image_id: Option<&str>,
        ext: Option<&str>,
    ) -> Result<ObjectStat, StorageError> {
        let rel = self.object_rel(scope, release_id, org_id, image_id, ext)?;
        let mut file = self
            .dir
            .open(&rel)
            .map_err(|_| StorageError::new(StorageErrorCode::NotFound, "object"))?;
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 64 * 1024];
        let mut size = 0u64;
        loop {
            let n = file
                .read(&mut buf)
                .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("read: {e}")))?;
            if n == 0 {
                break;
            }
            size += n as u64;
            hasher.update(&buf[..n]);
        }
        Ok(ObjectStat {
            size,
            sha256: hex::encode(hasher.finalize()),
        })
    }

    /// Lookup SQLite SoT, compare expected mirror digest, re-hash disk (verify-on-read).
    pub fn get_verified(
        &self,
        scope: StorageScope,
        release_id: Option<&str>,
        org_id: Option<&str>,
        image_id: Option<&str>,
        ext: Option<&str>,
        expected_sha256: &str,
    ) -> Result<(ObjectStat, PathBuf), StorageError> {
        let expected = expected_sha256.trim().to_ascii_lowercase();
        if expected.len() != 64 || !expected.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(StorageError::new(
                StorageErrorCode::InvalidId,
                "expected sha256",
            ));
        }
        let object_key = match scope {
            StorageScope::Release => release_object_key(release_id.unwrap_or("")),
            StorageScope::Image => image_object_key(
                org_id.unwrap_or(""),
                image_id.unwrap_or(""),
                ext.unwrap_or(""),
            ),
        };
        let sot = {
            let db = self.meta.lock().expect("meta mutex");
            db.get(scope, &object_key)?
                .ok_or_else(|| StorageError::new(StorageErrorCode::NotFound, "meta"))?
        };
        if !ct_eq_hex(&sot.sha256, &expected) {
            return Err(StorageError::new(
                StorageErrorCode::IntegrityMismatch,
                "mirror vs SoT",
            ));
        }
        let st = self.get_stat(scope, release_id, org_id, image_id, ext)?;
        if !ct_eq_hex(&st.sha256, &sot.sha256) || st.size != sot.size_bytes {
            return Err(StorageError::new(
                StorageErrorCode::IntegrityMismatch,
                "disk vs SoT",
            ));
        }
        let path = self.object_abs_path(scope, release_id, org_id, image_id, ext)?;
        Ok((st, path))
    }

    pub fn object_abs_path(
        &self,
        scope: StorageScope,
        release_id: Option<&str>,
        org_id: Option<&str>,
        image_id: Option<&str>,
        ext: Option<&str>,
    ) -> Result<PathBuf, StorageError> {
        let rel = self.object_rel(scope, release_id, org_id, image_id, ext)?;
        if !self.dir.exists(&rel) {
            return Err(StorageError::new(StorageErrorCode::NotFound, "object"));
        }
        Ok(self.root.join(rel))
    }

    pub fn delete(
        &self,
        scope: StorageScope,
        release_id: Option<&str>,
        org_id: Option<&str>,
        image_id: Option<&str>,
        ext: Option<&str>,
        assertion: Option<&str>,
    ) -> Result<(), StorageError> {
        let object_key = match scope {
            StorageScope::Release => release_object_key(release_id.unwrap_or("")),
            StorageScope::Image => image_object_key(
                org_id.unwrap_or(""),
                image_id.unwrap_or(""),
                ext.unwrap_or(""),
            ),
        };
        let sot = {
            let db = self.meta.lock().expect("meta mutex");
            db.get(scope, &object_key)?
        };
        if self.cfg.webauthn_required {
            let assertion = assertion.ok_or_else(|| {
                StorageError::new(StorageErrorCode::WebauthnRequired, "assertion")
            })?;
            let mut binding = json!({
                "op": "delete",
                "scope": scope.as_str(),
            });
            if let Some(obj) = binding.as_object_mut() {
                if let Some(id) = release_id {
                    obj.insert("release_id".into(), json!(id));
                }
                if let Some(id) = org_id {
                    obj.insert("org_id".into(), json!(id));
                }
                if let Some(id) = image_id {
                    obj.insert("image_id".into(), json!(id));
                }
                if let Some(e) = ext {
                    obj.insert("ext".into(), json!(e));
                }
            }
            // Re-load challenge binding from DB via verify — check digest drift first
            // by reconstructing expected binding with sha when SoT existed at challenge.
            let db = self.meta.lock().expect("meta mutex");
            // Find unconsumed delete challenge for this object via pending list.
            let pending = db.list_pending_challenges()?;
            let mut matched_binding = None;
            for ch in pending {
                if ch.op != "delete" {
                    continue;
                }
                let bound: serde_json::Value =
                    serde_json::from_str(&ch.binding_json).unwrap_or(json!({}));
                let same_scope =
                    bound.get("scope").and_then(|v| v.as_str()) == Some(scope.as_str());
                let same_release = release_id
                    .is_none_or(|id| bound.get("release_id").and_then(|v| v.as_str()) == Some(id));
                let same_image = image_id
                    .is_none_or(|id| bound.get("image_id").and_then(|v| v.as_str()) == Some(id));
                if same_scope && same_release && same_image {
                    matched_binding = Some(bound);
                    break;
                }
            }
            let bound = matched_binding.ok_or_else(|| {
                StorageError::new(StorageErrorCode::ChallengeUnknown, "delete challenge")
            })?;
            if let Some(bound_sha) = bound.get("sha256").and_then(|v| v.as_str()) {
                match &sot {
                    Some(obj) if !ct_eq_hex(&obj.sha256, bound_sha) => {
                        return Err(StorageError::new(
                            StorageErrorCode::ObjectModified,
                            "digest drifted",
                        ));
                    }
                    None => {
                        return Err(StorageError::new(
                            StorageErrorCode::ObjectModified,
                            "object vanished",
                        ));
                    }
                    _ => {}
                }
            }
            verify_and_consume(
                &db,
                &self.audit,
                assertion,
                "delete",
                &bound,
                &self.cfg.webauthn_rp_id,
                &self.cfg.webauthn_origin,
                self.cfg.webauthn_strict_sign_count,
                true,
            )?;
            drop(db);
            let _ = binding;
        }
        {
            let db = self.meta.lock().expect("meta mutex");
            db.delete(scope, &object_key)?;
        }
        let rel = self.object_rel(scope, release_id, org_id, image_id, ext)?;
        match self.dir.remove_file(&rel) {
            Ok(()) => Ok(()),
            Err(_) if sot.is_none() => Ok(()), // idempotent absent
            Err(_) => Err(StorageError::new(StorageErrorCode::NotFound, "object")),
        }
    }

    pub fn delete_org(&self, org_id: &str, assertion: Option<&str>) -> Result<u32, StorageError> {
        if !is_decimal_id(org_id) {
            return Err(StorageError::new(StorageErrorCode::InvalidId, "org_id"));
        }
        if self.cfg.webauthn_required {
            let assertion = assertion.ok_or_else(|| {
                StorageError::new(StorageErrorCode::WebauthnRequired, "assertion")
            })?;
            let binding = json!({"op": "delete_org", "org_id": org_id});
            tracing::warn!(
                target: "vcp_storage_alert",
                org_id,
                "ALERT delete_org ceremony"
            );
            let db = self.meta.lock().expect("meta mutex");
            verify_and_consume(
                &db,
                &self.audit,
                assertion,
                "delete_org",
                &binding,
                &self.cfg.webauthn_rp_id,
                &self.cfg.webauthn_origin,
                self.cfg.webauthn_strict_sign_count,
                true,
            )?;
        }
        {
            let db = self.meta.lock().expect("meta mutex");
            let _ = db.delete_org(org_id)?;
        }
        let path = format!("images/{org_id}");
        if !self.dir.exists(&path) {
            return Ok(0);
        }
        let mut n = 0u32;
        let entries = self.dir.read_dir(&path).map_err(|e| {
            StorageError::new(StorageErrorCode::Io, format!("read org images: {e}"))
        })?;
        for entry in entries.flatten() {
            let name = entry.file_name();
            let rel = format!("images/{org_id}/{}", name.to_string_lossy());
            if self.dir.remove_file(&rel).is_ok() {
                n = n.saturating_add(1);
            }
        }
        let _ = self.dir.remove_dir(&path);
        Ok(n)
    }

    fn object_rel(
        &self,
        scope: StorageScope,
        release_id: Option<&str>,
        org_id: Option<&str>,
        image_id: Option<&str>,
        ext: Option<&str>,
    ) -> Result<String, StorageError> {
        match scope {
            StorageScope::Release => release_rel_path(release_id.unwrap_or(""))
                .ok_or_else(|| StorageError::new(StorageErrorCode::InvalidId, "release_id")),
            StorageScope::Image => image_rel_path(
                org_id.unwrap_or(""),
                image_id.unwrap_or(""),
                ext.unwrap_or(""),
            )
            .ok_or_else(|| StorageError::new(StorageErrorCode::InvalidId, "image")),
        }
    }

    fn count_org_images(&self, org_id: &str) -> Result<u64, StorageError> {
        let path = format!("images/{org_id}");
        if !self.dir.exists(&path) {
            return Ok(0);
        }
        let entries = self
            .dir
            .read_dir(&path)
            .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("count images: {e}")))?;
        Ok(entries.flatten().count() as u64)
    }
}

/// Write bytes into an absolute path (used by tests / client after put_begin).
pub fn write_abs_file(path: &Path, data: &[u8]) -> Result<(), StorageError> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("open write: {e}")))?;
    f.write_all(data)
        .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("write: {e}")))?;
    f.sync_all()
        .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("fsync: {e}")))?;
    Ok(())
}

pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{StorageConfig, StorageIpcMode};

    fn test_cfg() -> StorageConfig {
        StorageConfig {
            blob_path: "/tmp/unused".into(),
            ipc: StorageIpcMode::Spawn,
            max_artifact_bytes: 1024 * 1024,
            max_image_bytes: 64 * 1024,
            max_concurrent_uploads: 4,
            max_images_per_org: 3,
            webauthn_required: false,
            ..StorageConfig::default()
        }
    }

    #[test]
    fn release_put_commit_get_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let eng = StorageEngine::open(&root, test_cfg()).unwrap();
        let begin = eng
            .put_begin(StorageScope::Release, Some("42"), None, 11, None)
            .unwrap();
        let data = b"hello-world";
        let digest = sha256_hex(data);
        write_abs_file(&eng.partial_abs_path(&begin.upload_id).unwrap(), data).unwrap();
        let st = eng
            .put_commit(&begin.upload_id, &digest, None, None)
            .unwrap();
        assert_eq!(st.size, 11);
        assert_eq!(st.sha256, digest);
        let (got, _) = eng
            .get_verified(StorageScope::Release, Some("42"), None, None, None, &digest)
            .unwrap();
        assert_eq!(got.sha256, digest);
        let bad = eng
            .get_verified(
                StorageScope::Release,
                Some("42"),
                None,
                None,
                None,
                &"0".repeat(64),
            )
            .unwrap_err();
        assert_eq!(bad.code, StorageErrorCode::IntegrityMismatch);
    }

    #[test]
    fn digest_mismatch_aborts() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let eng = StorageEngine::open(&root, test_cfg()).unwrap();
        let begin = eng
            .put_begin(StorageScope::Release, Some("7"), None, 4, None)
            .unwrap();
        write_abs_file(&eng.partial_abs_path(&begin.upload_id).unwrap(), b"abcd").unwrap();
        let err = eng
            .put_commit(&begin.upload_id, &sha256_hex(b"nope"), None, None)
            .unwrap_err();
        assert_eq!(err.code, StorageErrorCode::DigestMismatch);
    }

    #[test]
    fn release_webauthn_required_without_assertion() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let mut cfg = test_cfg();
        cfg.webauthn_required = true;
        let eng = StorageEngine::open(&root, cfg).unwrap();
        let begin = eng
            .put_begin(StorageScope::Release, Some("8"), None, 4, None)
            .unwrap();
        write_abs_file(&eng.partial_abs_path(&begin.upload_id).unwrap(), b"abcd").unwrap();
        let digest = sha256_hex(b"abcd");
        let prep = eng.put_prepare(&begin.upload_id, &digest).unwrap();
        assert!(prep.challenge.summary.contains("release_put_commit"));
        let err = eng
            .put_commit(&begin.upload_id, &digest, None, None)
            .unwrap_err();
        assert_eq!(err.code, StorageErrorCode::WebauthnRequired);
    }

    #[test]
    fn release_webauthn_soft_ok() {
        use crate::storage::webauthn::soft_assertion_json;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let mut cfg = test_cfg();
        cfg.webauthn_required = true;
        let eng = StorageEngine::open(&root, cfg).unwrap();
        let cred = b"soft-release-1";
        eng.seed_soft_active_credential(cred, "t").unwrap();
        let begin = eng
            .put_begin(StorageScope::Release, Some("9"), None, 4, None)
            .unwrap();
        write_abs_file(&eng.partial_abs_path(&begin.upload_id).unwrap(), b"abcd").unwrap();
        let digest = sha256_hex(b"abcd");
        let prep = eng.put_prepare(&begin.upload_id, &digest).unwrap();
        let assertion = soft_assertion_json(cred, &prep.challenge.challenge_id, true, 0);
        let st = eng
            .put_commit(&begin.upload_id, &digest, None, Some(&assertion))
            .unwrap();
        assert_eq!(st.sha256, digest);
    }

    #[test]
    fn production_boot_refuses_webauthn_bypass() {
        let cfg = StorageConfig {
            webauthn_required: false,
            ..StorageConfig::default()
        };
        let err = StorageEngine::validate_production_webauthn(true, &cfg).unwrap_err();
        assert!(err.contains("webauthn_required=false"));
    }

    #[test]
    fn delete_object_modified_on_digest_drift() {
        use crate::storage::webauthn::soft_assertion_json;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let mut cfg = test_cfg();
        cfg.webauthn_required = true;
        let eng = StorageEngine::open(&root, cfg).unwrap();
        let cred = b"soft-del-1";
        eng.seed_soft_active_credential(cred, "t").unwrap();
        let begin = eng
            .put_begin(StorageScope::Release, Some("55"), None, 4, None)
            .unwrap();
        write_abs_file(&eng.partial_abs_path(&begin.upload_id).unwrap(), b"abcd").unwrap();
        let digest = sha256_hex(b"abcd");
        let prep = eng.put_prepare(&begin.upload_id, &digest).unwrap();
        let assertion = soft_assertion_json(cred, &prep.challenge.challenge_id, true, 0);
        eng.put_commit(&begin.upload_id, &digest, None, Some(&assertion))
            .unwrap();

        let ch = eng
            .challenge_begin_delete(StorageScope::Release, Some("55"), None, None, None)
            .unwrap();
        // Overwrite blob digest in SoT to simulate drift.
        {
            let db = eng.meta.lock().unwrap();
            db.upsert(&MetaObject {
                scope: StorageScope::Release,
                object_key: "55".into(),
                org_id: String::new(),
                sha256: "f".repeat(64),
                size_bytes: 4,
                content_type: String::new(),
                ext: String::new(),
            })
            .unwrap();
        }
        let a2 = soft_assertion_json(cred, &ch.challenge_id, true, 0);
        let err = eng
            .delete(
                StorageScope::Release,
                Some("55"),
                None,
                None,
                None,
                Some(&a2),
            )
            .unwrap_err();
        assert_eq!(err.code, StorageErrorCode::ObjectModified);
    }

    #[test]
    fn ctap2_approve_fingerprint_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let eng = StorageEngine::open(&root, test_cfg()).unwrap();
        let cred = b"pend-1";
        let cose = b"cose-pend";
        let fp = eng
            .ctap2_enrol_stage(cred, cose, "u", "label", true)
            .unwrap();
        let err = eng.ctap2_approve("0".repeat(64).as_str()).unwrap_err();
        assert_eq!(err.code, StorageErrorCode::WebauthnInvalid);
        eng.ctap2_approve(&fp).unwrap();
    }

    #[test]
    fn ctap2_pending_lists_staged_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let eng = StorageEngine::open(&root, test_cfg()).unwrap();
        assert!(eng.list_pending_credentials_cli().unwrap().is_empty());
        let fp = eng
            .ctap2_enrol_stage(b"pend-cli", b"cose-cli", "42", "macbook", true)
            .unwrap();
        let pending = eng.list_pending_credentials_cli().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].admin_label, "macbook");
        assert_eq!(
            credential_fingerprint(&pending[0].credential_id, &pending[0].public_key_cose),
            fp
        );
        // Ceremony challenge table stays empty until put_prepare / challenge_begin.
        assert!(eng.list_pending_challenges_cli().unwrap().is_empty());
        eng.ctap2_approve(&fp).unwrap();
        assert!(eng.list_pending_credentials_cli().unwrap().is_empty());
        let all = eng.list_all_credentials_cli().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].status, CredentialStatus::Active);
    }

    #[test]
    fn image_bad_sniff_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let eng = StorageEngine::open(&root, test_cfg()).unwrap();
        let fake = b"<svg xmlns='x'></svg>!!!!";
        let begin = eng
            .put_begin(
                StorageScope::Image,
                None,
                Some("9"),
                fake.len() as u64,
                Some("png"),
            )
            .unwrap();
        write_abs_file(&eng.partial_abs_path(&begin.upload_id).unwrap(), fake).unwrap();
        let err = eng
            .put_commit(
                &begin.upload_id,
                &sha256_hex(fake),
                Some("550e8400-e29b-41d4-a716-446655440000"),
                None,
            )
            .unwrap_err();
        assert_eq!(err.code, StorageErrorCode::BadImage);
    }

    #[test]
    fn org_quota_enforced() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let mut cfg = test_cfg();
        cfg.max_images_per_org = 1;
        let eng = StorageEngine::open(&root, cfg).unwrap();
        let png = {
            let mut v = vec![0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n'];
            v.extend_from_slice(&[0u8; 8]);
            v
        };
        let id1 = "550e8400-e29b-41d4-a716-446655440001";
        let begin = eng
            .put_begin(
                StorageScope::Image,
                None,
                Some("3"),
                png.len() as u64,
                Some("png"),
            )
            .unwrap();
        write_abs_file(&eng.partial_abs_path(&begin.upload_id).unwrap(), &png).unwrap();
        eng.put_commit(&begin.upload_id, &sha256_hex(&png), Some(id1), None)
            .unwrap();
        let err = eng
            .put_begin(
                StorageScope::Image,
                None,
                Some("3"),
                png.len() as u64,
                Some("png"),
            )
            .unwrap_err();
        assert_eq!(err.code, StorageErrorCode::OrgQuota);
    }
}
