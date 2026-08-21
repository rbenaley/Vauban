//! Package filename segment under `/releases/{eph_token}/{eph_pkg}`.

use std::io::Read;

use topcoat::{
    Result,
    context::Cx,
    router::{Body, StatusCode, error::not_found, header, path_param, response::Response, route},
};

use super::EphToken;
use crate::{
    app::org::builds::download::{DOWNLOAD_UNAVAILABLE, INTEGRITY_MISMATCH},
    app::org::builds::ephemeral::package_file_name,
    app::org::builds::find_visible_release_by_version,
    auth::{db, storage},
    db::now_unix,
    models::{EphemeralDownload, Organization},
    storage::{find_release_object, storage_http_status},
};

path_param!(pub(crate) eph_pkg);

#[route(GET)]
pub(crate) async fn ephemeral_download_get(cx: &Cx) -> Result<Response> {
    let token = path_param::<EphToken>(cx);
    let _pkg = path_param::<EphPkg>(cx);

    let mut database = db(cx);
    let rows = EphemeralDownload::all()
        .filter(EphemeralDownload::fields().token().eq(token))
        .limit(1)
        .exec(&mut database)
        .await
        .unwrap_or_default();
    let Some(row) = rows.into_iter().next() else {
        return Err(not_found().into());
    };
    let now = now_unix();
    if row.expires_at <= now {
        return Err(not_found().into());
    }

    let Some(org) = Organization::get_by_id(&mut database, row.organization_id)
        .await
        .ok()
    else {
        return Err(not_found().into());
    };
    let Some(rel) = find_visible_release_by_version(
        &mut database,
        &row.release_version,
        org.id,
        &org.slug,
        org.lts_subscriptions,
        org.industrial_lts_subscriptions,
    )
    .await
    else {
        return Err(not_found().into());
    };
    let Some(obj) = find_release_object(&mut database, rel.id).await else {
        return Err(not_found().into());
    };

    let client = storage(cx);
    let (size, _sha, mut file) = match client.get_release(rel.id, &obj.sha256) {
        Ok(v) => v,
        Err(e) => {
            let status = StatusCode::from_u16(storage_http_status(&e))
                .unwrap_or(StatusCode::SERVICE_UNAVAILABLE);
            let body = if e.code == crate::storage::StorageErrorCode::IntegrityMismatch {
                INTEGRITY_MISMATCH
            } else {
                DOWNLOAD_UNAVAILABLE
            };
            return Ok(Response::builder()
                .status(status)
                .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
                .body(Body::from(body))?);
        }
    };
    let mut bytes = Vec::with_capacity(size.min(64 * 1024 * 1024) as usize);
    if file.read_to_end(&mut bytes).is_err() {
        return Ok(Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(Body::from(DOWNLOAD_UNAVAILABLE))?);
    }
    let filename = package_file_name(&rel.version, &rel.channel);
    let disposition = format!("attachment; filename=\"{filename}\"");
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_DISPOSITION, disposition)
        .header(header::CONTENT_LENGTH, bytes.len().to_string())
        .header("X-Content-Type-Options", "nosniff")
        .body(Body::from(bytes))?)
}
