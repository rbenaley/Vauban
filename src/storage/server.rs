//! Helper request dispatch against [`StorageEngine`].

use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use super::engine::StorageEngine;
use super::error::{StorageError, StorageErrorCode};
use super::ids::StorageScope;
use super::ipc::{encode_response, recv_request, send_bytes, send_fd};
use super::log as store_log;
use super::protocol::{StorageRequest, StorageResponse};

fn parse_scope(raw: &str) -> Result<StorageScope, &'static str> {
    StorageScope::parse(raw).ok_or("invalid_id")
}

fn map_err(err: StorageError) -> StorageResponse {
    StorageResponse::err(err.code.as_str())
}

fn reply_engine_err(stream: &mut UnixStream, op: &str, err: StorageError) -> Result<(), ()> {
    store_log::op_failed(op, &err);
    reply(stream, op, &map_err(err), None)
}

fn reply(
    stream: &mut UnixStream,
    op: &str,
    resp: &StorageResponse,
    fd: Option<i32>,
) -> Result<(), ()> {
    let bytes = match encode_response(resp) {
        Ok(b) => b,
        Err(e) => {
            store_log::wire_failed(op, "encode_response", &e);
            return Err(());
        }
    };
    if let Err(e) = send_bytes(stream, &bytes) {
        store_log::wire_failed(op, "send_bytes", &e);
        return Err(());
    }
    if let Some(raw) = fd
        && let Err(e) = send_fd(stream, raw)
    {
        store_log::wire_failed(op, "send_fd", &e);
        return Err(());
    }
    Ok(())
}

fn challenge_resp(
    issued: super::webauthn::ChallengeIssued,
    digest: Option<String>,
) -> StorageResponse {
    StorageResponse::ok_challenge(
        digest,
        issued.challenge_id,
        issued.challenge_b64,
        issued.summary,
        issued.rp_id,
        issued.allow_credentials,
    )
}

/// Open an absolute path for SCM_RIGHTS handoff. Logs WARN on failure.
///
/// Note: absolute `open` after `cap_enter` fails on FreeBSD Capsicum; the
/// Capsicum fix (dirfd reopen) is intentionally separate from logging.
pub(crate) fn open_abs_for_handoff(
    op: &str,
    path: &Path,
    writable: bool,
) -> Result<File, StorageError> {
    let opened = if writable {
        File::options().write(true).read(false).open(path)
    } else {
        File::open(path)
    };
    opened.map_err(|e| {
        store_log::fd_handoff_failed(op, path, &e);
        StorageError::new(
            StorageErrorCode::Io,
            format!("SCM_RIGHTS open {}: {e}", path.display()),
        )
    })
}

/// Handle one client connection to completion.
pub fn serve_connection(engine: &StorageEngine, mut stream: UnixStream) {
    while let Ok(req) = recv_request(&mut stream) {
        if dispatch(engine, &mut stream, req).is_err() {
            break;
        }
    }
}

fn dispatch(
    engine: &StorageEngine,
    stream: &mut UnixStream,
    req: StorageRequest,
) -> Result<(), ()> {
    let op = request_op(&req);
    store_log::op_begin(op);
    match req {
        StorageRequest::PutBegin {
            scope: sc,
            release_id,
            org_id,
            declared_size,
            ext,
        } => {
            let scope = match parse_scope(&sc) {
                Ok(s) => s,
                Err(code) => {
                    store_log::op_failed(op, &StorageError::new(StorageErrorCode::InvalidId, code));
                    return reply(stream, op, &StorageResponse::err(code), None);
                }
            };
            match engine.put_begin(
                scope,
                release_id.as_deref(),
                org_id.as_deref(),
                declared_size,
                ext.as_deref(),
            ) {
                Ok(ok) => {
                    let path = match engine.partial_abs_path(&ok.upload_id) {
                        Ok(p) => p,
                        Err(e) => return reply_engine_err(stream, op, e),
                    };
                    match open_abs_for_handoff(op, &path, true) {
                        Ok(file) => {
                            tracing::debug!(
                                target: super::STORE_LOG_TARGET,
                                op,
                                upload_id = %ok.upload_id,
                                "SCM_RIGHTS handoff ready"
                            );
                            let resp = StorageResponse::ok_upload(ok.upload_id);
                            reply(stream, op, &resp, Some(file.as_raw_fd()))
                        }
                        Err(e) => {
                            // Already WARNed in open_abs_for_handoff.
                            // Keep connection; portal sees `io` and can WARN.
                            // Orphan 0-byte partial may remain until abort/TTL.
                            reply(stream, op, &map_err(e), None)
                        }
                    }
                }
                Err(e) => reply_engine_err(stream, op, e),
            }
        }
        StorageRequest::PutPrepare {
            upload_id, sha256, ..
        } => match engine.put_prepare(&upload_id, &sha256) {
            Ok(ok) => reply(
                stream,
                op,
                &challenge_resp(ok.challenge, Some(ok.digest)),
                None,
            ),
            Err(e) => reply_engine_err(stream, op, e),
        },
        StorageRequest::PutCommit {
            upload_id,
            sha256,
            image_id,
            assertion,
            ..
        } => match engine.put_commit(
            &upload_id,
            &sha256,
            image_id.as_deref(),
            assertion.as_deref(),
        ) {
            Ok(st) => reply(
                stream,
                op,
                &StorageResponse::ok_stat(st.size, st.sha256),
                None,
            ),
            Err(e) => reply_engine_err(stream, op, e),
        },
        StorageRequest::PutAbort { upload_id } => match engine.put_abort(&upload_id) {
            Ok(()) => reply(stream, op, &StorageResponse::ok_empty(), None),
            Err(e) => reply_engine_err(stream, op, e),
        },
        StorageRequest::Get {
            scope: sc,
            sha256,
            release_id,
            org_id,
            image_id,
            ext,
        } => {
            let scope = match parse_scope(&sc) {
                Ok(s) => s,
                Err(code) => {
                    store_log::op_failed(op, &StorageError::new(StorageErrorCode::InvalidId, code));
                    return reply(stream, op, &StorageResponse::err(code), None);
                }
            };
            match engine.get_verified(
                scope,
                release_id.as_deref(),
                org_id.as_deref(),
                image_id.as_deref(),
                ext.as_deref(),
                &sha256,
            ) {
                Ok((st, path)) => match open_abs_for_handoff(op, &path, false) {
                    Ok(file) => reply(
                        stream,
                        op,
                        &StorageResponse::ok_stat(st.size, st.sha256),
                        Some(file.as_raw_fd()),
                    ),
                    Err(e) => reply(stream, op, &map_err(e), None),
                },
                Err(e) => reply_engine_err(stream, op, e),
            }
        }
        StorageRequest::Stat {
            scope: sc,
            sha256,
            release_id,
            org_id,
            image_id,
            ext,
        } => {
            let scope = match parse_scope(&sc) {
                Ok(s) => s,
                Err(code) => {
                    store_log::op_failed(op, &StorageError::new(StorageErrorCode::InvalidId, code));
                    return reply(stream, op, &StorageResponse::err(code), None);
                }
            };
            match engine.get_verified(
                scope,
                release_id.as_deref(),
                org_id.as_deref(),
                image_id.as_deref(),
                ext.as_deref(),
                &sha256,
            ) {
                Ok((st, _)) => reply(
                    stream,
                    op,
                    &StorageResponse::ok_stat(st.size, st.sha256),
                    None,
                ),
                Err(e) => reply_engine_err(stream, op, e),
            }
        }
        StorageRequest::ChallengeBegin {
            kind,
            scope: sc,
            release_id,
            org_id,
            image_id,
            ext,
        } => {
            if kind == "delete_org" {
                let org = org_id.as_deref().unwrap_or("");
                match engine.challenge_begin_delete_org(org) {
                    Ok(ch) => reply(stream, op, &challenge_resp(ch, None), None),
                    Err(e) => reply_engine_err(stream, op, e),
                }
            } else {
                let scope = match parse_scope(sc.as_deref().unwrap_or("")) {
                    Ok(s) => s,
                    Err(code) => {
                        store_log::op_failed(
                            op,
                            &StorageError::new(StorageErrorCode::InvalidId, code),
                        );
                        return reply(stream, op, &StorageResponse::err(code), None);
                    }
                };
                match engine.challenge_begin_delete(
                    scope,
                    release_id.as_deref(),
                    org_id.as_deref(),
                    image_id.as_deref(),
                    ext.as_deref(),
                ) {
                    Ok(ch) => reply(stream, op, &challenge_resp(ch, None), None),
                    Err(e) => reply_engine_err(stream, op, e),
                }
            }
        }
        StorageRequest::Delete {
            scope: sc,
            release_id,
            org_id,
            image_id,
            ext,
            assertion,
            ..
        } => {
            let scope = match parse_scope(&sc) {
                Ok(s) => s,
                Err(code) => {
                    store_log::op_failed(op, &StorageError::new(StorageErrorCode::InvalidId, code));
                    return reply(stream, op, &StorageResponse::err(code), None);
                }
            };
            match engine.delete(
                scope,
                release_id.as_deref(),
                org_id.as_deref(),
                image_id.as_deref(),
                ext.as_deref(),
                assertion.as_deref(),
            ) {
                Ok(()) => reply(stream, op, &StorageResponse::ok_empty(), None),
                Err(e) => reply_engine_err(stream, op, e),
            }
        }
        StorageRequest::DeleteOrg {
            org_id, assertion, ..
        } => match engine.delete_org(&org_id, assertion.as_deref()) {
            Ok(n) => reply(stream, op, &StorageResponse::ok_deleted(n), None),
            Err(e) => reply_engine_err(stream, op, e),
        },
        StorageRequest::KeyEnrolStage {
            credential_id_b64,
            public_key_cose_b64,
            user_handle,
            admin_label,
            is_soft,
        } => {
            let cred = match URL_SAFE_NO_PAD.decode(credential_id_b64.trim()) {
                Ok(v) => v,
                Err(_) => {
                    store_log::op_failed(
                        op,
                        &StorageError::new(StorageErrorCode::InvalidId, "credential_id_b64"),
                    );
                    return reply(stream, op, &StorageResponse::err("invalid_id"), None);
                }
            };
            let cose = match URL_SAFE_NO_PAD.decode(public_key_cose_b64.trim()) {
                Ok(v) => v,
                Err(_) => {
                    store_log::op_failed(
                        op,
                        &StorageError::new(StorageErrorCode::InvalidId, "public_key_cose_b64"),
                    );
                    return reply(stream, op, &StorageResponse::err("invalid_id"), None);
                }
            };
            match engine.key_enrol_stage(&cred, &cose, &user_handle, &admin_label, is_soft) {
                Ok(fp) => reply(stream, op, &StorageResponse::ok_fingerprint(fp), None),
                Err(e) => reply_engine_err(stream, op, e),
            }
        }
        StorageRequest::KeyRevoke { credential_id_b64 } => {
            let cred = match URL_SAFE_NO_PAD.decode(credential_id_b64.trim()) {
                Ok(v) => v,
                Err(_) => {
                    store_log::op_failed(
                        op,
                        &StorageError::new(StorageErrorCode::InvalidId, "credential_id_b64"),
                    );
                    return reply(stream, op, &StorageResponse::err("invalid_id"), None);
                }
            };
            match engine.key_revoke(&cred) {
                Ok(()) => reply(stream, op, &StorageResponse::ok_empty(), None),
                Err(e) => reply_engine_err(stream, op, e),
            }
        }
        StorageRequest::KeyList {
            kind,
            page,
            page_size,
        } => {
            let page = page.max(1) as usize;
            let page_size = page_size.clamp(1, 100) as usize;
            match engine.key_list_json(&kind, page, page_size) {
                Ok((s, total)) => reply(
                    stream,
                    op,
                    &StorageResponse::ok_key_list(s, total as u64),
                    None,
                ),
                Err(e) => reply_engine_err(stream, op, e),
            }
        }
        StorageRequest::KeyGet { credential_id_b64 } => {
            let cred = match URL_SAFE_NO_PAD.decode(credential_id_b64.trim()) {
                Ok(v) => v,
                Err(_) => {
                    store_log::op_failed(
                        op,
                        &StorageError::new(StorageErrorCode::InvalidId, "credential_id_b64"),
                    );
                    return reply(stream, op, &StorageResponse::err("invalid_id"), None);
                }
            };
            match engine.key_get_json(&cred) {
                Ok(Some(s)) => reply(stream, op, &StorageResponse::ok_summary(s), None),
                Ok(None) => {
                    store_log::op_failed(
                        op,
                        &StorageError::new(StorageErrorCode::NotFound, "credential"),
                    );
                    reply(stream, op, &StorageResponse::err("not_found"), None)
                }
                Err(e) => reply_engine_err(stream, op, e),
            }
        }
    }
}

fn request_op(req: &StorageRequest) -> &'static str {
    match req {
        StorageRequest::PutBegin { .. } => "put_begin",
        StorageRequest::PutPrepare { .. } => "put_prepare",
        StorageRequest::PutCommit { .. } => "put_commit",
        StorageRequest::PutAbort { .. } => "put_abort",
        StorageRequest::Get { .. } => "get",
        StorageRequest::Stat { .. } => "stat",
        StorageRequest::ChallengeBegin { .. } => "challenge_begin",
        StorageRequest::Delete { .. } => "delete",
        StorageRequest::DeleteOrg { .. } => "delete_org",
        StorageRequest::KeyEnrolStage { .. } => "key_enrol_stage",
        StorageRequest::KeyRevoke { .. } => "key_revoke",
        StorageRequest::KeyList { .. } => "key_list",
        StorageRequest::KeyGet { .. } => "key_get",
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{open_abs_for_handoff, request_op};
    use crate::storage::error::StorageErrorCode;
    use crate::storage::protocol::StorageRequest;

    #[test]
    fn unit_request_op_covers_put_begin_and_key_enrol() {
        let put = StorageRequest::PutBegin {
            scope: "image".into(),
            release_id: None,
            org_id: Some("1".into()),
            declared_size: 1,
            ext: Some("png".into()),
        };
        assert_eq!(request_op(&put), "put_begin");
        let enrol = StorageRequest::KeyEnrolStage {
            credential_id_b64: String::new(),
            public_key_cose_b64: String::new(),
            user_handle: String::new(),
            admin_label: String::new(),
            is_soft: false,
        };
        assert_eq!(request_op(&enrol), "key_enrol_stage");
    }

    #[test]
    fn e2e_open_abs_for_handoff_missing_path_is_io() {
        let err = open_abs_for_handoff(
            "put_begin",
            Path::new("/no/such/vcp/tmp/missing.partial"),
            true,
        )
        .expect_err("missing path must fail");
        assert_eq!(err.code, StorageErrorCode::Io);
        assert!(
            err.message.contains("SCM_RIGHTS"),
            "message={}",
            err.message
        );
    }
}
