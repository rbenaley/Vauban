//! Helper request dispatch against [`StorageEngine`].

use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use super::engine::StorageEngine;
use super::ids::StorageScope;
use super::ipc::{encode_response, recv_request, send_bytes, send_fd};
use super::protocol::{StorageRequest, StorageResponse};

fn parse_scope(raw: &str) -> Result<StorageScope, &'static str> {
    StorageScope::parse(raw).ok_or("invalid_id")
}

fn map_err(err: super::error::StorageError) -> StorageResponse {
    StorageResponse::err(err.code.as_str())
}

fn reply(stream: &mut UnixStream, resp: &StorageResponse, fd: Option<i32>) -> Result<(), ()> {
    let bytes = encode_response(resp).map_err(|_| ())?;
    send_bytes(stream, &bytes).map_err(|_| ())?;
    if let Some(raw) = fd {
        send_fd(stream, raw).map_err(|_| ())?;
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
                Err(code) => return reply(stream, &StorageResponse::err(code), None),
            };
            match engine.put_begin(
                scope,
                release_id.as_deref(),
                org_id.as_deref(),
                declared_size,
                ext.as_deref(),
            ) {
                Ok(ok) => {
                    let path = engine.partial_abs_path(&ok.upload_id).map_err(|_| ())?;
                    let file = File::options()
                        .write(true)
                        .read(false)
                        .open(&path)
                        .map_err(|_| ())?;
                    let resp = StorageResponse::ok_upload(ok.upload_id);
                    reply(stream, &resp, Some(file.as_raw_fd()))
                }
                Err(e) => reply(stream, &map_err(e), None),
            }
        }
        StorageRequest::PutPrepare {
            upload_id, sha256, ..
        } => match engine.put_prepare(&upload_id, &sha256) {
            Ok(ok) => reply(stream, &challenge_resp(ok.challenge, Some(ok.digest)), None),
            Err(e) => reply(stream, &map_err(e), None),
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
            Ok(st) => reply(stream, &StorageResponse::ok_stat(st.size, st.sha256), None),
            Err(e) => reply(stream, &map_err(e), None),
        },
        StorageRequest::PutAbort { upload_id } => match engine.put_abort(&upload_id) {
            Ok(()) => reply(stream, &StorageResponse::ok_empty(), None),
            Err(e) => reply(stream, &map_err(e), None),
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
                Err(code) => return reply(stream, &StorageResponse::err(code), None),
            };
            match engine.get_verified(
                scope,
                release_id.as_deref(),
                org_id.as_deref(),
                image_id.as_deref(),
                ext.as_deref(),
                &sha256,
            ) {
                Ok((st, path)) => {
                    let file = File::open(&path).map_err(|_| ())?;
                    reply(
                        stream,
                        &StorageResponse::ok_stat(st.size, st.sha256),
                        Some(file.as_raw_fd()),
                    )
                }
                Err(e) => reply(stream, &map_err(e), None),
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
                Err(code) => return reply(stream, &StorageResponse::err(code), None),
            };
            match engine.get_verified(
                scope,
                release_id.as_deref(),
                org_id.as_deref(),
                image_id.as_deref(),
                ext.as_deref(),
                &sha256,
            ) {
                Ok((st, _)) => reply(stream, &StorageResponse::ok_stat(st.size, st.sha256), None),
                Err(e) => reply(stream, &map_err(e), None),
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
                    Ok(ch) => reply(stream, &challenge_resp(ch, None), None),
                    Err(e) => reply(stream, &map_err(e), None),
                }
            } else {
                let scope = match parse_scope(sc.as_deref().unwrap_or("")) {
                    Ok(s) => s,
                    Err(code) => return reply(stream, &StorageResponse::err(code), None),
                };
                match engine.challenge_begin_delete(
                    scope,
                    release_id.as_deref(),
                    org_id.as_deref(),
                    image_id.as_deref(),
                    ext.as_deref(),
                ) {
                    Ok(ch) => reply(stream, &challenge_resp(ch, None), None),
                    Err(e) => reply(stream, &map_err(e), None),
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
                Err(code) => return reply(stream, &StorageResponse::err(code), None),
            };
            match engine.delete(
                scope,
                release_id.as_deref(),
                org_id.as_deref(),
                image_id.as_deref(),
                ext.as_deref(),
                assertion.as_deref(),
            ) {
                Ok(()) => reply(stream, &StorageResponse::ok_empty(), None),
                Err(e) => reply(stream, &map_err(e), None),
            }
        }
        StorageRequest::DeleteOrg {
            org_id, assertion, ..
        } => match engine.delete_org(&org_id, assertion.as_deref()) {
            Ok(n) => reply(stream, &StorageResponse::ok_deleted(n), None),
            Err(e) => reply(stream, &map_err(e), None),
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
                Err(_) => return reply(stream, &StorageResponse::err("invalid_id"), None),
            };
            let cose = match URL_SAFE_NO_PAD.decode(public_key_cose_b64.trim()) {
                Ok(v) => v,
                Err(_) => return reply(stream, &StorageResponse::err("invalid_id"), None),
            };
            match engine.key_enrol_stage(&cred, &cose, &user_handle, &admin_label, is_soft) {
                Ok(fp) => reply(stream, &StorageResponse::ok_fingerprint(fp), None),
                Err(e) => reply(stream, &map_err(e), None),
            }
        }
        StorageRequest::KeyRevoke { credential_id_b64 } => {
            let cred = match URL_SAFE_NO_PAD.decode(credential_id_b64.trim()) {
                Ok(v) => v,
                Err(_) => return reply(stream, &StorageResponse::err("invalid_id"), None),
            };
            match engine.key_revoke(&cred) {
                Ok(()) => reply(stream, &StorageResponse::ok_empty(), None),
                Err(e) => reply(stream, &map_err(e), None),
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
                Ok((s, total)) => {
                    reply(stream, &StorageResponse::ok_key_list(s, total as u64), None)
                }
                Err(e) => reply(stream, &map_err(e), None),
            }
        }
        StorageRequest::KeyGet { credential_id_b64 } => {
            let cred = match URL_SAFE_NO_PAD.decode(credential_id_b64.trim()) {
                Ok(v) => v,
                Err(_) => return reply(stream, &StorageResponse::err("invalid_id"), None),
            };
            match engine.key_get_json(&cred) {
                Ok(Some(s)) => reply(stream, &StorageResponse::ok_summary(s), None),
                Ok(None) => reply(stream, &StorageResponse::err("not_found"), None),
                Err(e) => reply(stream, &map_err(e), None),
            }
        }
    }
}
