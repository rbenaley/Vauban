//! Entitlement-gated release artifact download via the storage helper.

use std::io::Read;

use topcoat::{
    Result,
    context::Cx,
    router::{
        Body, Response, StatusCode,
        error::{forbidden, not_found},
        header, path_param, route,
    },
};

use super::find_visible_release_by_version;
use super::release_ver::ReleaseVer;
use crate::{
    app::org::Org,
    auth::{db, require_org, storage},
    perms::perms_for_user,
    release_pkg::package_file_name,
    storage::{find_release_object, storage_http_status},
};

/// Artifact routes return this when the helper is unavailable.
pub const DOWNLOAD_UNAVAILABLE: &str = "download unavailable";

#[route(POST "/{org}/builds/{release_ver}/download")]
async fn builds_download(cx: &Cx) -> Result<Response> {
    let org_slug = path_param::<Org>(cx);
    let ver = path_param::<ReleaseVer>(cx);
    let ctx = require_org(cx, org_slug).await.map_err(|_| not_found())?;
    let perms = perms_for_user(cx, &ctx.user).await;
    if !perms.builds_download {
        return Err(forbidden().into());
    }

    let ver_key = ver.to_string();
    let mut database = db(cx);
    let Some(rel) =
        find_visible_release_by_version(&mut database, &ver_key, ctx.org.id, org_slug).await
    else {
        return Err(not_found().into());
    };

    let Some(obj) = find_release_object(&mut database, rel.id).await else {
        return Err(not_found().into());
    };

    let client = storage(cx);
    let (size, sha, mut file) = match client.get_release(rel.id) {
        Ok(v) => v,
        Err(e) => {
            let status = StatusCode::from_u16(storage_http_status(&e))
                .unwrap_or(StatusCode::SERVICE_UNAVAILABLE);
            return Ok(Response::builder()
                .status(status)
                .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
                .body(Body::from(DOWNLOAD_UNAVAILABLE))?);
        }
    };
    if sha != obj.sha256 || size != obj.size_bytes {
        tracing::warn!(
            release_id = rel.id,
            "storage digest/size drifted from storage_objects row"
        );
    }

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
