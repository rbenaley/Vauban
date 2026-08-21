//! Tenant image upload / serve via the storage helper (`png` / `jpeg` / `webp`).

use std::io::Read;

use topcoat::{
    Result,
    context::Cx,
    router::{
        Body, StatusCode, content::multipart::Multipart, error::not_found, header, href,
        path_param, response::Response, route,
    },
};

use crate::{
    app::org::Org,
    auth::{AuthUser, capability_denied, current_user, db, require_org, storage},
    models::Organization,
    perms::perms_for_user,
    storage::{
        find_image_object, is_uuid_key, normalize_image_ext, put_tenant_image, storage_http_status,
    },
};

path_param!(pub(crate) image_file);

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

/// Resolve org id for image read: org member with issues access, **or**
/// Casbin `admin_view` + `issues_read|write` (support gallery without membership).
/// Cross-tenant clients stay 404 (anti-enumeration).
async fn authorize_image_org_id(cx: &Cx, org_slug: &str) -> Result<u64> {
    if let Ok(ctx) = require_org(cx, org_slug).await {
        let perms = perms_for_user(cx, &ctx.user).await;
        if !perms.issues_read && !perms.issues_write {
            return Err(capability_denied().into());
        }
        return Ok(ctx.org.id);
    }

    // Admin issue detail embeds `<img src="/{org}/images/…">` for support
    // users who are not client-org members. Gate only via PermissionContext.
    let Some(user) = current_user(cx).await else {
        return Err(not_found().into());
    };
    let auth = AuthUser {
        id: user.id,
        email: user.email.clone(),
        display_name: user.display_name.clone(),
        role: user.portal_role.clone(),
        portal_role: user.portal_role.clone(),
    };
    let perms = perms_for_user(cx, &auth).await;
    if !perms.admin_view || (!perms.issues_read && !perms.issues_write) {
        return Err(not_found().into());
    }

    let mut database = db(cx);
    let slug = org_slug.to_owned();
    let org = Organization::all()
        .filter(Organization::fields().slug().eq(slug))
        .limit(1)
        .exec(&mut database)
        .await
        .unwrap_or_default()
        .into_iter()
        .next();
    let Some(org) = org else {
        return Err(not_found().into());
    };
    Ok(org.id)
}

/// Upload one image for the path org. AuthZ (membership) before any IPC.
#[route(POST "/{org}/images")]
pub(crate) async fn org_image_upload(cx: &Cx, mut multipart: Multipart) -> Result<Response> {
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
            let ctype = field.content_type().map(|s| s.to_owned());
            let data = field.bytes().await?.to_vec();
            declared_ext = fname
                .rsplit_once('.')
                .and_then(|(_, e)| normalize_image_ext(e))
                .or_else(|| {
                    ctype.as_deref().and_then(|ct| {
                        match ct.split(';').next().unwrap_or("").trim() {
                            "image/png" => Some("png"),
                            "image/jpeg" | "image/jpg" => Some("jpeg"),
                            "image/webp" => Some("webp"),
                            _ => None,
                        }
                    })
                });
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

    let client = storage(cx);
    let mut database = db(cx);
    let body = match put_tenant_image(&mut database, &client, ctx.org.id, &bytes, ext).await {
        Ok(token) => token,
        Err(e) => {
            let status = StatusCode::from_u16(storage_http_status(&e))
                .unwrap_or(StatusCode::SERVICE_UNAVAILABLE);
            return Ok(Response::builder()
                .status(status)
                .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
                .body(Body::from(e.code.as_str()))?);
        }
    };

    Ok(Response::builder()
        .status(StatusCode::CREATED)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(
            header::LOCATION,
            href!(org_image_get, Org(org_slug), ImageFile(body.as_str())).resolve(cx),
        )
        .body(Body::from(body))?)
}

/// Serve an org image. Cross-tenant client / missing DB row -> 404 **before** IPC.
/// Casbin `admin_view` + issues access may fetch without org membership.
#[route(GET "/{org}/images/{image_file}")]
pub(crate) async fn org_image_get(cx: &Cx) -> Result<Response> {
    let org_slug = path_param::<Org>(cx);
    let raw = path_param::<ImageFile>(cx).to_string();
    let Some((image_id, ext)) = parse_image_file(&raw) else {
        return Err(not_found().into());
    };

    let org_id = authorize_image_org_id(cx, org_slug).await?;

    let mut database = db(cx);
    let Some(obj) = find_image_object(&mut database, org_id, &image_id, ext).await else {
        return Err(not_found().into());
    };
    if obj.organization_id != org_id {
        return Err(not_found().into());
    }

    let client = storage(cx);
    let (size, _sha, mut file) = match client.get_image(org_id, &image_id, ext, &obj.sha256) {
        Ok(v) => v,
        Err(e) => {
            let status = StatusCode::from_u16(storage_http_status(&e))
                .unwrap_or(StatusCode::SERVICE_UNAVAILABLE);
            let body = if e.code == crate::storage::StorageErrorCode::IntegrityMismatch {
                "integrity mismatch"
            } else {
                "image unavailable"
            };
            return Ok(Response::builder()
                .status(status)
                .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
                .body(Body::from(body))?);
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
