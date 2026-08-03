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

use super::error::{StorageError, StorageErrorCode};
use super::ids::{
    StorageScope, image_rel_path, is_decimal_id, is_uuid_key, normalize_image_ext,
    release_rel_path, tmp_rel_path,
};
use super::sniff::sniff_matches_ext;

#[derive(Debug, Clone)]
pub struct PutBeginOk {
    pub upload_id: String,
}

#[derive(Debug, Clone)]
pub struct ObjectStat {
    pub size: u64,
    pub sha256: String,
}

struct InflightUpload {
    scope: StorageScope,
    release_id: Option<String>,
    org_id: Option<String>,
    ext: Option<String>,
    declared_size: u64,
}

/// In-process storage engine (also used by `vcp-store`).
pub struct StorageEngine {
    dir: Dir,
    root: PathBuf,
    cfg: StorageConfig,
    inflight: Mutex<HashMap<String, InflightUpload>>,
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
        for sub in ["releases", "images", "tmp"] {
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
        let engine = Self {
            dir,
            root,
            cfg,
            inflight: Mutex::new(HashMap::new()),
        };
        engine.purge_expired_tmp()?;
        Ok(engine)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn cfg(&self) -> &StorageConfig {
        &self.cfg
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
            },
        );
        Ok(PutBeginOk { upload_id })
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
    ) -> Result<ObjectStat, StorageError> {
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
        if let Some(rel) = tmp_rel_path(upload_id) {
            let _ = self.dir.remove_file(rel);
        }
        Ok(())
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
    ) -> Result<(), StorageError> {
        let rel = self.object_rel(scope, release_id, org_id, image_id, ext)?;
        self.dir
            .remove_file(&rel)
            .map_err(|_| StorageError::new(StorageErrorCode::NotFound, "object"))
    }

    pub fn delete_org(&self, org_id: &str) -> Result<u32, StorageError> {
        if !is_decimal_id(org_id) {
            return Err(StorageError::new(StorageErrorCode::InvalidId, "org_id"));
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
            socket_path: String::new(),
            helper_path: String::new(),
            max_artifact_bytes: 1024 * 1024,
            max_image_bytes: 64 * 1024,
            allowed_image_types: vec!["png".into(), "jpeg".into(), "webp".into()],
            max_concurrent_uploads: 4,
            max_images_per_org: 3,
            upload_ttl_secs: 3600,
            expected_peer_uid: None,
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
        let st = eng.put_commit(&begin.upload_id, &digest, None).unwrap();
        assert_eq!(st.size, 11);
        assert_eq!(st.sha256, digest);
        let got = eng
            .get_stat(StorageScope::Release, Some("42"), None, None, None)
            .unwrap();
        assert_eq!(got.sha256, digest);
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
            .put_commit(&begin.upload_id, &sha256_hex(b"nope"), None)
            .unwrap_err();
        assert_eq!(err.code, StorageErrorCode::DigestMismatch);
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
        eng.put_commit(&begin.upload_id, &sha256_hex(&png), Some(id1))
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
