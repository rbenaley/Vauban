//! Tenant image upload / serve via the storage helper (`png` / `jpeg` / `webp`).

use std::io::{Cursor, Read};

use topcoat::{
    Result,
    context::Cx,
    router::{
        Body, Response, StatusCode, content::multipart::Multipart, error::not_found, header,
        path_param, route,
    },
};
use uuid::Uuid;

use crate::{
    app::org::Org,
    auth::{capability_denied, db, require_org, storage},
    perms::perms_for_user,
    storage::{
        find_image_object, is_uuid_key, normalize_image_ext, storage_http_status,
        upsert_image_object, write_and_hash,
    },
};

#[path_param]
struct ImageFile(str);

fn content_type_for_ext(ext: &str) -> &'static str {
    match ext {
        "png" => "image/png",
        "jpeg" => "image/jpeg",
        "webp" => "image/webp",
        _ => "application/octet-stream",
    }
}

fn parse_image_file(raw: &str) -> Option<(String, &'static str)> {
    let (id, ext) = raw.rsplit_once('.')?;
    if !is_uuid_key(id) {
        return None;
    }
    let ext = normalize_image_ext(ext)?;
    Some((id.to_owned(), ext))
}

/// Upload one image for the path org. AuthZ (membership) before any IPC.
#[route(POST "/{org}/images")]
async fn org_image_upload(cx: &Cx, mut multipart: Multipart) -> Result<Response> {
    let org_slug = path_param::<Org>(cx);
    let ctx = require_org(cx, org_slug).await.map_err(|_| not_found())?;
    let perms = perms_for_user(cx, &ctx.user).await;
    if !perms.issues_write && !perms.issues_read {
        return Err(capability_denied().into());
    }

    let mut file_bytes: Option<Vec<u8>> = None;
    let mut declared_ext: Option<&'static str> = None;
    while let Some(field) = multipart.next_field().await? {
        let name = field.name().unwrap_or("").to_owned();
        if name == "image" || name == "file" || name == "screenshot" {
            let fname = field.file_name().unwrap_or("").to_owned();
            let data = field.bytes().await?.to_vec();
            if let Some(ext) = fname
                .rsplit_once('.')
                .and_then(|(_, e)| normalize_image_ext(e))
            {
                declared_ext = Some(ext);
            }
            file_bytes = Some(data);
        }
    }
    let Some(bytes) = file_bytes.filter(|b| !b.is_empty()) else {
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(Body::from("missing image"))?);
    };
    let Some(ext) = declared_ext else {
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(Body::from("unsupported image type"))?);
    };

    let image_id = Uuid::new_v4().to_string();
    let client = storage(cx);
    let (upload_id, mut file) = match client.put_begin_image(ctx.org.id, bytes.len() as u64, ext) {
        Ok(v) => v,
        Err(e) => {
            let status = StatusCode::from_u16(storage_http_status(&e))
                .unwrap_or(StatusCode::SERVICE_UNAVAILABLE);
            return Ok(Response::builder()
                .status(status)
                .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
                .body(Body::from("upload unavailable"))?);
        }
    };
    let (size, sha) = match write_and_hash(&mut file, Cursor::new(&bytes)) {
        Ok(v) => v,
        Err(_) => {
            let _ = client.put_abort(&upload_id);
            return Ok(Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
                .body(Body::from("upload unavailable"))?);
        }
    };
    drop(file);
    if let Err(e) = client.put_commit_image(&upload_id, ctx.org.id, &image_id, ext, &sha) {
        let status =
            StatusCode::from_u16(storage_http_status(&e)).unwrap_or(StatusCode::BAD_REQUEST);
        return Ok(Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(Body::from(e.code.as_str()))?);
    }

    let mut database = db(cx);
    let _ = upsert_image_object(&mut database, ctx.org.id, &image_id, ext, &sha, size).await;

    let body = format!("{image_id}.{ext}");
    Ok(Response::builder()
        .status(StatusCode::CREATED)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(header::LOCATION, format!("/{org_slug}/images/{body}"))
        .body(Body::from(body))?)
}

/// Serve an org image. Cross-tenant / missing DB row -> 404 **before** IPC.
#[route(GET "/{org}/images/{image_file}")]
async fn org_image_get(cx: &Cx) -> Result<Response> {
    let org_slug = path_param::<Org>(cx);
    let raw = path_param::<ImageFile>(cx).to_string();
    let Some((image_id, ext)) = parse_image_file(&raw) else {
        return Err(not_found().into());
    };

    let ctx = require_org(cx, org_slug).await.map_err(|_| not_found())?;
    let perms = perms_for_user(cx, &ctx.user).await;
    if !perms.issues_read && !perms.issues_write {
        return Err(capability_denied().into());
    }

    let mut database = db(cx);
    let Some(obj) = find_image_object(&mut database, ctx.org.id, &image_id, ext).await else {
        return Err(not_found().into());
    };
    if obj.organization_id != ctx.org.id {
        return Err(not_found().into());
    }

    let client = storage(cx);
    let (size, _sha, mut file) = match client.get_image(ctx.org.id, &image_id, ext) {
        Ok(v) => v,
        Err(e) => {
            let status = StatusCode::from_u16(storage_http_status(&e))
                .unwrap_or(StatusCode::SERVICE_UNAVAILABLE);
            return Ok(Response::builder()
                .status(status)
                .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
                .body(Body::from("image unavailable"))?);
        }
    };
    let mut bytes = Vec::with_capacity(size.min(16 * 1024 * 1024) as usize);
    if file.read_to_end(&mut bytes).is_err() {
        return Ok(Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(Body::from("image unavailable"))?);
    }

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type_for_ext(ext))
        .header(header::CONTENT_LENGTH, bytes.len().to_string())
        .header("X-Content-Type-Options", "nosniff")
        .header(header::CACHE_CONTROL, "private, max-age=3600")
        .body(Body::from(bytes))?)
}
