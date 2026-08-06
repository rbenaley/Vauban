//! Storage client used by `vcp` (spawn, named socket, or inline engine).

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::config::{StorageConfig, StorageIpcMode};
use uuid::Uuid;

use super::engine::StorageEngine;
use super::error::{StorageError, StorageErrorCode};
use super::ids::StorageScope;
use super::ipc::{encode_request, recv_fd, recv_response, send_bytes};
use super::log as store_log;
use super::protocol::{StorageRequest, StorageResponse};

/// Map a denied IPC response to [`StorageError`] and WARN on the portal.
fn ipc_denied(op: &str, resp: &StorageResponse) -> StorageError {
    let code = StorageErrorCode::parse(resp.err.as_deref().unwrap_or("io"))
        .unwrap_or(StorageErrorCode::Io);
    let detail = resp.err.clone().unwrap_or_else(|| op.to_owned());
    let err = StorageError::new(code, detail);
    store_log::portal_storage_failed(op, &err);
    err
}

enum Backend {
    Ipc {
        stream: Mutex<UnixStream>,
        _child: Option<Child>,
    },
    Inline(Box<Mutex<StorageEngine>>),
}

/// Portal-side pending release finalize (C1) after `put_prepare`.
#[derive(Debug, Clone)]
pub struct PendingReleaseCeremony {
    pub upload_id: String,
    pub release_id: u64,
    pub sha256: String,
    pub summary: String,
    pub challenge_id: String,
    pub challenge: String,
    pub rp_id: String,
    pub allow_credentials: Vec<String>,
    pub expires_at: i64,
}

/// Portal-side pending gated delete (C1).
#[derive(Debug, Clone)]
pub struct PendingDeleteCeremony {
    pub kind: String,
    pub release_id: Option<u64>,
    pub org_id: Option<u64>,
    pub summary: String,
    pub challenge_id: String,
    pub challenge: String,
    pub rp_id: String,
    pub allow_credentials: Vec<String>,
}

/// Connected storage helper client.
pub struct StorageClient {
    backend: Backend,
    pending_release: Mutex<HashMap<String, PendingReleaseCeremony>>,
    pending_delete: Mutex<HashMap<String, PendingDeleteCeremony>>,
    webauthn_required: bool,
}

impl StorageClient {
    pub fn connect(cfg: &StorageConfig) -> Result<Self, StorageError> {
        match cfg.ipc {
            StorageIpcMode::Spawn => Self::spawn(cfg),
            StorageIpcMode::Socket => Self::connect_socket(cfg),
            StorageIpcMode::Inline => {
                let engine = StorageEngine::open(&cfg.blob_path, cfg.clone())?;
                Ok(Self {
                    backend: Backend::Inline(Box::new(Mutex::new(engine))),
                    pending_release: Mutex::new(HashMap::new()),
                    pending_delete: Mutex::new(HashMap::new()),
                    webauthn_required: cfg.webauthn_required,
                })
            }
        }
    }

    pub fn webauthn_required(&self) -> bool {
        self.webauthn_required
    }

    pub fn stash_pending_release(&self, pending: PendingReleaseCeremony) -> String {
        let token = Uuid::new_v4().to_string();
        self.pending_release
            .lock()
            .expect("pending mutex")
            .insert(token.clone(), pending);
        token
    }

    pub fn take_pending_release(&self, token: &str) -> Option<PendingReleaseCeremony> {
        self.pending_release
            .lock()
            .expect("pending mutex")
            .remove(token)
    }

    pub fn peek_pending_release(&self, token: &str) -> Option<PendingReleaseCeremony> {
        self.pending_release
            .lock()
            .expect("pending mutex")
            .get(token)
            .cloned()
    }

    pub fn stash_pending_delete(&self, pending: PendingDeleteCeremony) -> String {
        let token = Uuid::new_v4().to_string();
        self.pending_delete
            .lock()
            .expect("pending delete mutex")
            .insert(token.clone(), pending);
        token
    }

    pub fn take_pending_delete(&self, token: &str) -> Option<PendingDeleteCeremony> {
        self.pending_delete
            .lock()
            .expect("pending delete mutex")
            .remove(token)
    }

    pub fn peek_pending_delete(&self, token: &str) -> Option<PendingDeleteCeremony> {
        self.pending_delete
            .lock()
            .expect("pending delete mutex")
            .get(token)
            .cloned()
    }

    fn connect_socket(cfg: &StorageConfig) -> Result<Self, StorageError> {
        if cfg.socket_path.is_empty() {
            return Err(StorageError::new(
                StorageErrorCode::Io,
                "socket_path required",
            ));
        }
        let stream = UnixStream::connect(&cfg.socket_path)
            .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("connect: {e}")))?;
        stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
        stream.set_write_timeout(Some(Duration::from_secs(10))).ok();
        Ok(Self {
            backend: Backend::Ipc {
                stream: Mutex::new(stream),
                _child: None,
            },
            pending_release: Mutex::new(HashMap::new()),
            pending_delete: Mutex::new(HashMap::new()),
            webauthn_required: cfg.webauthn_required,
        })
    }

    fn spawn(cfg: &StorageConfig) -> Result<Self, StorageError> {
        let helper = if cfg.helper_path.is_empty() {
            default_helper_path()
        } else {
            PathBuf::from(&cfg.helper_path)
        };
        if !helper.exists() {
            return Err(StorageError::new(
                StorageErrorCode::Io,
                format!("helper missing: {}", helper.display()),
            ));
        }
        let sock_path =
            std::env::temp_dir().join(format!("vcp-store-spawn-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&sock_path);

        let listener = std::os::unix::net::UnixListener::bind(&sock_path).map_err(|e| {
            StorageError::new(StorageErrorCode::Io, format!("bind spawn sock: {e}"))
        })?;

        let mut child = Command::new(&helper)
            .arg("--blob-path")
            .arg(&cfg.blob_path)
            .arg("--listen")
            .arg(&sock_path)
            .arg("--spawn-mode")
            .arg("--max-artifact-bytes")
            .arg(cfg.max_artifact_bytes.to_string())
            .arg("--max-image-bytes")
            .arg(cfg.max_image_bytes.to_string())
            .arg("--max-concurrent-uploads")
            .arg(cfg.max_concurrent_uploads.to_string())
            .arg("--max-images-per-org")
            .arg(cfg.max_images_per_org.to_string())
            .arg("--upload-ttl-secs")
            .arg(cfg.upload_ttl_secs.to_string())
            .arg("--webauthn-required")
            .arg(if cfg.webauthn_required {
                "true"
            } else {
                "false"
            })
            .arg("--webauthn-origin")
            .arg(&cfg.webauthn_origin)
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("spawn helper: {e}")))?;

        listener
            .set_nonblocking(false)
            .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("listener: {e}")))?;

        let (stream, _) = listener.accept().map_err(|e| {
            let _ = child.kill();
            StorageError::new(StorageErrorCode::Io, format!("accept helper: {e}"))
        })?;
        stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
        stream.set_write_timeout(Some(Duration::from_secs(10))).ok();
        let _ = std::fs::remove_file(&sock_path);
        Ok(Self {
            backend: Backend::Ipc {
                stream: Mutex::new(stream),
                _child: Some(child),
            },
            pending_release: Mutex::new(HashMap::new()),
            pending_delete: Mutex::new(HashMap::new()),
            webauthn_required: cfg.webauthn_required,
        })
    }

    pub fn ceremony_ttl_unix(secs: u64) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
            .saturating_add(secs as i64)
    }

    pub fn put_begin_release(
        &self,
        release_id: u64,
        declared_size: u64,
    ) -> Result<(String, File), StorageError> {
        match &self.backend {
            Backend::Inline(engine) => {
                let eng = engine.lock().expect("inline engine");
                let ok = eng.put_begin(
                    StorageScope::Release,
                    Some(&release_id.to_string()),
                    None,
                    declared_size,
                    None,
                )?;
                let file = eng.open_partial_for_handoff(&ok.upload_id)?;
                Ok((ok.upload_id, file))
            }
            Backend::Ipc { .. } => {
                let req = StorageRequest::PutBegin {
                    scope: StorageScope::Release.as_str().into(),
                    release_id: Some(release_id.to_string()),
                    org_id: None,
                    declared_size,
                    ext: None,
                };
                self.roundtrip_with_fd(req)
            }
        }
    }

    pub fn put_begin_image(
        &self,
        org_id: u64,
        declared_size: u64,
        ext: &str,
    ) -> Result<(String, File), StorageError> {
        match &self.backend {
            Backend::Inline(engine) => {
                let eng = engine.lock().expect("inline engine");
                let ok = eng.put_begin(
                    StorageScope::Image,
                    None,
                    Some(&org_id.to_string()),
                    declared_size,
                    Some(ext),
                )?;
                let file = eng.open_partial_for_handoff(&ok.upload_id)?;
                Ok((ok.upload_id, file))
            }
            Backend::Ipc { .. } => {
                let req = StorageRequest::PutBegin {
                    scope: StorageScope::Image.as_str().into(),
                    release_id: None,
                    org_id: Some(org_id.to_string()),
                    declared_size,
                    ext: Some(ext.to_owned()),
                };
                self.roundtrip_with_fd(req)
            }
        }
    }

    pub fn put_prepare_release(
        &self,
        upload_id: &str,
        release_id: u64,
        sha256: &str,
    ) -> Result<PrepareClientOk, StorageError> {
        match &self.backend {
            Backend::Inline(engine) => {
                let eng = engine.lock().expect("inline engine");
                let _ = release_id;
                let ok = eng.put_prepare(upload_id, sha256)?;
                Ok(PrepareClientOk {
                    digest: ok.digest,
                    challenge_id: ok.challenge.challenge_id,
                    challenge: ok.challenge.challenge_b64,
                    summary: ok.challenge.summary,
                    rp_id: ok.challenge.rp_id,
                    allow_credentials: ok.challenge.allow_credentials,
                })
            }
            Backend::Ipc { .. } => {
                let req = StorageRequest::PutPrepare {
                    upload_id: upload_id.to_owned(),
                    sha256: sha256.to_owned(),
                    release_id: Some(release_id.to_string()),
                };
                let resp = self.roundtrip(req)?;
                ok_challenge(resp)
            }
        }
    }

    pub fn put_commit_release(
        &self,
        upload_id: &str,
        release_id: u64,
        sha256: &str,
    ) -> Result<(u64, String), StorageError> {
        self.put_commit_release_asserted(upload_id, release_id, sha256, None)
    }

    pub fn put_commit_release_asserted(
        &self,
        upload_id: &str,
        release_id: u64,
        sha256: &str,
        assertion: Option<&str>,
    ) -> Result<(u64, String), StorageError> {
        match &self.backend {
            Backend::Inline(engine) => {
                let eng = engine.lock().expect("inline engine");
                let st = eng.put_commit(upload_id, sha256, None, assertion)?;
                let _ = release_id;
                Ok((st.size, st.sha256))
            }
            Backend::Ipc { .. } => {
                let req = StorageRequest::PutCommit {
                    upload_id: upload_id.to_owned(),
                    scope: StorageScope::Release.as_str().into(),
                    sha256: sha256.to_owned(),
                    release_id: Some(release_id.to_string()),
                    org_id: None,
                    image_id: None,
                    ext: None,
                    assertion: assertion.map(str::to_owned),
                    challenge_id: None,
                };
                let resp = self.roundtrip(req)?;
                ok_stat(resp)
            }
        }
    }

    pub fn put_commit_image(
        &self,
        upload_id: &str,
        org_id: u64,
        image_id: &str,
        ext: &str,
        sha256: &str,
    ) -> Result<(u64, String), StorageError> {
        match &self.backend {
            Backend::Inline(engine) => {
                let eng = engine.lock().expect("inline engine");
                let st = eng.put_commit(upload_id, sha256, Some(image_id), None)?;
                let _ = (org_id, ext);
                Ok((st.size, st.sha256))
            }
            Backend::Ipc { .. } => {
                let req = StorageRequest::PutCommit {
                    upload_id: upload_id.to_owned(),
                    scope: StorageScope::Image.as_str().into(),
                    sha256: sha256.to_owned(),
                    release_id: None,
                    org_id: Some(org_id.to_string()),
                    image_id: Some(image_id.to_owned()),
                    ext: Some(ext.to_owned()),
                    assertion: None,
                    challenge_id: None,
                };
                let resp = self.roundtrip(req)?;
                ok_stat(resp)
            }
        }
    }

    pub fn put_abort(&self, upload_id: &str) -> Result<(), StorageError> {
        match &self.backend {
            Backend::Inline(engine) => {
                let eng = engine.lock().expect("inline engine");
                eng.put_abort(upload_id)
            }
            Backend::Ipc { .. } => {
                let req = StorageRequest::PutAbort {
                    upload_id: upload_id.to_owned(),
                };
                let resp = self.roundtrip(req)?;
                if resp.ok {
                    Ok(())
                } else {
                    Err(ipc_denied("put_abort", &resp))
                }
            }
        }
    }

    pub fn get_release(
        &self,
        release_id: u64,
        expected_sha256: &str,
    ) -> Result<(u64, String, File), StorageError> {
        match &self.backend {
            Backend::Inline(engine) => {
                let eng = engine.lock().expect("inline engine");
                let id = release_id.to_string();
                let (st, _) = eng.get_verified(
                    StorageScope::Release,
                    Some(&id),
                    None,
                    None,
                    None,
                    expected_sha256,
                )?;
                let file = eng.open_object_for_handoff(
                    StorageScope::Release,
                    Some(&id),
                    None,
                    None,
                    None,
                )?;
                Ok((st.size, st.sha256, file))
            }
            Backend::Ipc { .. } => {
                let req = StorageRequest::Get {
                    scope: StorageScope::Release.as_str().into(),
                    sha256: expected_sha256.to_owned(),
                    release_id: Some(release_id.to_string()),
                    org_id: None,
                    image_id: None,
                    ext: None,
                };
                let (resp, file) = self.roundtrip_with_fd_file(req)?;
                let (size, sha) = ok_stat(resp)?;
                Ok((size, sha, file))
            }
        }
    }

    pub fn get_image(
        &self,
        org_id: u64,
        image_id: &str,
        ext: &str,
        expected_sha256: &str,
    ) -> Result<(u64, String, File), StorageError> {
        match &self.backend {
            Backend::Inline(engine) => {
                let eng = engine.lock().expect("inline engine");
                let org = org_id.to_string();
                let (st, _) = eng.get_verified(
                    StorageScope::Image,
                    None,
                    Some(&org),
                    Some(image_id),
                    Some(ext),
                    expected_sha256,
                )?;
                let file = eng.open_object_for_handoff(
                    StorageScope::Image,
                    None,
                    Some(&org),
                    Some(image_id),
                    Some(ext),
                )?;
                Ok((st.size, st.sha256, file))
            }
            Backend::Ipc { .. } => {
                let req = StorageRequest::Get {
                    scope: StorageScope::Image.as_str().into(),
                    sha256: expected_sha256.to_owned(),
                    release_id: None,
                    org_id: Some(org_id.to_string()),
                    image_id: Some(image_id.to_owned()),
                    ext: Some(ext.to_owned()),
                };
                let (resp, file) = self.roundtrip_with_fd_file(req)?;
                let (size, sha) = ok_stat(resp)?;
                Ok((size, sha, file))
            }
        }
    }

    pub fn challenge_begin_delete_release(
        &self,
        release_id: u64,
    ) -> Result<PrepareClientOk, StorageError> {
        match &self.backend {
            Backend::Inline(engine) => {
                let eng = engine.lock().expect("inline engine");
                let ch = eng.challenge_begin_delete(
                    StorageScope::Release,
                    Some(&release_id.to_string()),
                    None,
                    None,
                    None,
                )?;
                Ok(PrepareClientOk {
                    digest: String::new(),
                    challenge_id: ch.challenge_id,
                    challenge: ch.challenge_b64,
                    summary: ch.summary,
                    rp_id: ch.rp_id,
                    allow_credentials: ch.allow_credentials,
                })
            }
            Backend::Ipc { .. } => {
                let req = StorageRequest::ChallengeBegin {
                    kind: "delete".into(),
                    scope: Some(StorageScope::Release.as_str().into()),
                    release_id: Some(release_id.to_string()),
                    org_id: None,
                    image_id: None,
                    ext: None,
                };
                let resp = self.roundtrip(req)?;
                ok_challenge(resp)
            }
        }
    }

    pub fn challenge_begin_delete_org(&self, org_id: u64) -> Result<PrepareClientOk, StorageError> {
        match &self.backend {
            Backend::Inline(engine) => {
                let eng = engine.lock().expect("inline engine");
                let ch = eng.challenge_begin_delete_org(&org_id.to_string())?;
                Ok(PrepareClientOk {
                    digest: String::new(),
                    challenge_id: ch.challenge_id,
                    challenge: ch.challenge_b64,
                    summary: ch.summary,
                    rp_id: ch.rp_id,
                    allow_credentials: ch.allow_credentials,
                })
            }
            Backend::Ipc { .. } => {
                let req = StorageRequest::ChallengeBegin {
                    kind: "delete_org".into(),
                    scope: None,
                    release_id: None,
                    org_id: Some(org_id.to_string()),
                    image_id: None,
                    ext: None,
                };
                let resp = self.roundtrip(req)?;
                ok_challenge(resp)
            }
        }
    }

    pub fn delete_release(&self, release_id: u64) -> Result<(), StorageError> {
        self.delete_release_asserted(release_id, None)
    }

    pub fn delete_release_asserted(
        &self,
        release_id: u64,
        assertion: Option<&str>,
    ) -> Result<(), StorageError> {
        match &self.backend {
            Backend::Inline(engine) => {
                let eng = engine.lock().expect("inline engine");
                eng.delete(
                    StorageScope::Release,
                    Some(&release_id.to_string()),
                    None,
                    None,
                    None,
                    assertion,
                )
            }
            Backend::Ipc { .. } => {
                let req = StorageRequest::Delete {
                    scope: StorageScope::Release.as_str().into(),
                    release_id: Some(release_id.to_string()),
                    org_id: None,
                    image_id: None,
                    ext: None,
                    assertion: assertion.map(str::to_owned),
                    challenge_id: None,
                };
                let resp = self.roundtrip(req)?;
                if resp.ok {
                    Ok(())
                } else {
                    Err(ipc_denied("delete", &resp))
                }
            }
        }
    }

    pub fn delete_org(&self, org_id: u64) -> Result<u32, StorageError> {
        self.delete_org_asserted(org_id, None)
    }

    pub fn delete_org_asserted(
        &self,
        org_id: u64,
        assertion: Option<&str>,
    ) -> Result<u32, StorageError> {
        match &self.backend {
            Backend::Inline(engine) => {
                let eng = engine.lock().expect("inline engine");
                eng.delete_org(&org_id.to_string(), assertion)
            }
            Backend::Ipc { .. } => {
                let req = StorageRequest::DeleteOrg {
                    org_id: org_id.to_string(),
                    assertion: assertion.map(str::to_owned),
                    challenge_id: None,
                };
                let resp = self.roundtrip(req)?;
                if resp.ok {
                    Ok(resp.deleted.unwrap_or(0))
                } else {
                    Err(ipc_denied("delete_org", &resp))
                }
            }
        }
    }

    pub fn key_enrol_stage(
        &self,
        credential_id: &[u8],
        public_key_cose: &[u8],
        user_handle: &str,
        admin_label: &str,
        is_soft: bool,
    ) -> Result<String, StorageError> {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        match &self.backend {
            Backend::Inline(engine) => {
                let eng = engine.lock().expect("inline engine");
                eng.key_enrol_stage(
                    credential_id,
                    public_key_cose,
                    user_handle,
                    admin_label,
                    is_soft,
                )
            }
            Backend::Ipc { .. } => {
                let req = StorageRequest::KeyEnrolStage {
                    credential_id_b64: URL_SAFE_NO_PAD.encode(credential_id),
                    public_key_cose_b64: URL_SAFE_NO_PAD.encode(public_key_cose),
                    user_handle: user_handle.to_owned(),
                    admin_label: admin_label.to_owned(),
                    is_soft,
                };
                let resp = self.roundtrip(req)?;
                if resp.ok {
                    Ok(resp.fingerprint.unwrap_or_default())
                } else {
                    Err(ipc_denied("enrol_stage", &resp))
                }
            }
        }
    }

    /// Paginated KEY list. Returns `(items_json_array, total_rows)`.
    pub fn key_list_page(
        &self,
        kind: &str,
        page: usize,
        page_size: usize,
    ) -> Result<(String, usize), StorageError> {
        match &self.backend {
            Backend::Inline(engine) => {
                let eng = engine.lock().expect("inline engine");
                eng.key_list_json(kind, page, page_size)
            }
            Backend::Ipc { .. } => {
                let req = StorageRequest::KeyList {
                    kind: kind.to_owned(),
                    page: u32::try_from(page.max(1)).unwrap_or(1),
                    page_size: u32::try_from(page_size.clamp(1, 100)).unwrap_or(4),
                };
                let resp = self.roundtrip(req)?;
                if resp.ok {
                    let total = resp.size.unwrap_or(0) as usize;
                    Ok((resp.summary.unwrap_or_else(|| "[]".into()), total))
                } else {
                    Err(ipc_denied("key_list", &resp))
                }
            }
        }
    }

    /// One credential JSON object (for revoke overlay across pages).
    pub fn key_get(&self, credential_id: &[u8]) -> Result<Option<String>, StorageError> {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        match &self.backend {
            Backend::Inline(engine) => {
                let eng = engine.lock().expect("inline engine");
                eng.key_get_json(credential_id)
            }
            Backend::Ipc { .. } => {
                let req = StorageRequest::KeyGet {
                    credential_id_b64: URL_SAFE_NO_PAD.encode(credential_id),
                };
                let resp = self.roundtrip(req)?;
                if resp.ok {
                    Ok(resp.summary)
                } else if resp.err.as_deref() == Some("not_found") {
                    Ok(None)
                } else {
                    Err(ipc_denied("key_get", &resp))
                }
            }
        }
    }

    pub fn key_revoke(&self, credential_id: &[u8]) -> Result<(), StorageError> {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        match &self.backend {
            Backend::Inline(engine) => {
                let eng = engine.lock().expect("inline engine");
                eng.key_revoke(credential_id)
            }
            Backend::Ipc { .. } => {
                let req = StorageRequest::KeyRevoke {
                    credential_id_b64: URL_SAFE_NO_PAD.encode(credential_id),
                };
                let resp = self.roundtrip(req)?;
                if resp.ok {
                    Ok(())
                } else {
                    Err(ipc_denied("revoke", &resp))
                }
            }
        }
    }

    fn roundtrip(&self, req: StorageRequest) -> Result<StorageResponse, StorageError> {
        let Backend::Ipc { stream, .. } = &self.backend else {
            return Err(StorageError::new(
                StorageErrorCode::Io,
                "roundtrip on inline backend",
            ));
        };
        let mut stream = stream.lock().expect("storage client mutex");
        let bytes = encode_request(&req)?;
        send_bytes(&mut stream, &bytes)?;
        recv_response(&mut stream)
    }

    fn roundtrip_with_fd(&self, req: StorageRequest) -> Result<(String, File), StorageError> {
        let (resp, file) = self.roundtrip_with_fd_file(req)?;
        if !resp.ok {
            return Err(ipc_denied("put_begin", &resp));
        }
        let upload_id = resp
            .upload_id
            .ok_or_else(|| StorageError::new(StorageErrorCode::Io, "missing upload_id"))?;
        Ok((upload_id, file))
    }

    fn roundtrip_with_fd_file(
        &self,
        req: StorageRequest,
    ) -> Result<(StorageResponse, File), StorageError> {
        let Backend::Ipc { stream, .. } = &self.backend else {
            return Err(StorageError::new(
                StorageErrorCode::Io,
                "roundtrip_fd on inline backend",
            ));
        };
        let mut stream = stream.lock().expect("storage client mutex");
        let bytes = encode_request(&req)?;
        send_bytes(&mut stream, &bytes)?;
        let resp = recv_response(&mut stream)?;
        if !resp.ok {
            return Err(ipc_denied("put_begin", &resp));
        }
        let owned: OwnedFd = recv_fd(&stream)?;
        let file = File::from(owned);
        Ok((resp, file))
    }
}

/// Challenge / prepare response returned to portal ceremony UI.
#[derive(Debug, Clone)]
pub struct PrepareClientOk {
    pub digest: String,
    pub challenge_id: String,
    pub challenge: String,
    pub summary: String,
    pub rp_id: String,
    pub allow_credentials: Vec<String>,
}

fn ok_stat(resp: StorageResponse) -> Result<(u64, String), StorageError> {
    if !resp.ok {
        return Err(ipc_denied("stat", &resp));
    }
    Ok((resp.size.unwrap_or(0), resp.sha256.unwrap_or_default()))
}

fn ok_challenge(resp: StorageResponse) -> Result<PrepareClientOk, StorageError> {
    if !resp.ok {
        return Err(ipc_denied("challenge", &resp));
    }
    Ok(PrepareClientOk {
        digest: resp.sha256.unwrap_or_default(),
        challenge_id: resp.challenge_id.unwrap_or_default(),
        challenge: resp.challenge.unwrap_or_default(),
        summary: resp.summary.unwrap_or_default(),
        rp_id: resp.rp_id.unwrap_or_default(),
        allow_credentials: resp.allow_credentials.unwrap_or_default(),
    })
}

fn default_helper_path() -> PathBuf {
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let candidate = dir.join("vcp-store");
        if candidate.exists() {
            return candidate;
        }
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/debug/vcp-store")
}

/// Stream bytes into a write FD while hashing.
pub fn write_and_hash(
    file: &mut File,
    mut reader: impl Read,
) -> Result<(u64, String), StorageError> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("read body: {e}")))?;
        if n == 0 {
            break;
        }
        file.write_all(&buf[..n])
            .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("write fd: {e}")))?;
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    file.sync_all()
        .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("fsync: {e}")))?;
    Ok((total, hex::encode(hasher.finalize())))
}

pub fn ensure_blob_dir(path: &Path) -> Result<(), StorageError> {
    std::fs::create_dir_all(path)
        .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("mkdir blob: {e}")))
}
