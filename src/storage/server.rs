//! Helper request dispatch against [`StorageEngine`].

use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;

use super::engine::StorageEngine;
use super::ids::StorageScope;
use super::ipc::{encode_response, recv_request, send_bytes, send_fd};
use super::protocol::{StorageRequest, StorageResponse};

fn parse_scope(raw: &str) -> Result<StorageScope, StorageResponse> {
    StorageScope::parse(raw).ok_or_else(|| StorageResponse::err("invalid_id"))
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
                Err(resp) => return reply(stream, &resp, None),
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
        StorageRequest::PutCommit {
            upload_id,
            sha256,
            image_id,
            ..
        } => match engine.put_commit(&upload_id, &sha256, image_id.as_deref()) {
            Ok(st) => reply(stream, &StorageResponse::ok_stat(st.size, st.sha256), None),
            Err(e) => reply(stream, &map_err(e), None),
        },
        StorageRequest::PutAbort { upload_id } => match engine.put_abort(&upload_id) {
            Ok(()) => reply(stream, &StorageResponse::ok_empty(), None),
            Err(e) => reply(stream, &map_err(e), None),
        },
        StorageRequest::Get {
            scope: sc,
            release_id,
            org_id,
            image_id,
            ext,
        } => {
            let scope = match parse_scope(&sc) {
                Ok(s) => s,
                Err(resp) => return reply(stream, &resp, None),
            };
            match engine.get_stat(
                scope,
                release_id.as_deref(),
                org_id.as_deref(),
                image_id.as_deref(),
                ext.as_deref(),
            ) {
                Ok(st) => {
                    let path = engine
                        .object_abs_path(
                            scope,
                            release_id.as_deref(),
                            org_id.as_deref(),
                            image_id.as_deref(),
                            ext.as_deref(),
                        )
                        .map_err(|_| ())?;
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
            release_id,
            org_id,
            image_id,
            ext,
        } => {
            let scope = match parse_scope(&sc) {
                Ok(s) => s,
                Err(resp) => return reply(stream, &resp, None),
            };
            match engine.get_stat(
                scope,
                release_id.as_deref(),
                org_id.as_deref(),
                image_id.as_deref(),
                ext.as_deref(),
            ) {
                Ok(st) => reply(stream, &StorageResponse::ok_stat(st.size, st.sha256), None),
                Err(e) => reply(stream, &map_err(e), None),
            }
        }
        StorageRequest::Delete {
            scope: sc,
            release_id,
            org_id,
            image_id,
            ext,
        } => {
            let scope = match parse_scope(&sc) {
                Ok(s) => s,
                Err(resp) => return reply(stream, &resp, None),
            };
            match engine.delete(
                scope,
                release_id.as_deref(),
                org_id.as_deref(),
                image_id.as_deref(),
                ext.as_deref(),
            ) {
                Ok(()) => reply(stream, &StorageResponse::ok_empty(), None),
                Err(e) => reply(stream, &map_err(e), None),
            }
        }
        StorageRequest::DeleteOrg { org_id } => match engine.delete_org(&org_id) {
            Ok(n) => reply(stream, &StorageResponse::ok_deleted(n), None),
            Err(e) => reply(stream, &map_err(e), None),
        },
    }
}
