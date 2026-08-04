//! Server-issued ephemeral download links (POST/PRG; no client JS).

use std::io::Read;

use serde::Deserialize;
use topcoat::{
    Result,
    context::Cx,
    router::{
        Body, Response, StatusCode,
        content::Form,
        error::{SeeOther, forbidden, not_found, see_other},
        header, path_param, route,
    },
};
use uuid::Uuid;

use super::download::{DOWNLOAD_UNAVAILABLE, INTEGRITY_MISMATCH};
use super::find_visible_release_by_version;
use super::release_ver::ReleaseVer;
use crate::{
    app::org::Org,
    auth::{db, require_org, storage},
    db::now_unix,
    models::{EPH_DOWNLOAD_TTL_SECS, EphemeralDownload, Release},
    perms::perms_for_user,
    storage::{find_release_object, storage_http_status},
};

#[derive(Debug, Deserialize)]
struct EphRedirectForm {
    channel: Option<String>,
}

/// SSR view model for the open release's ephemeral panel.
#[derive(Debug, Clone)]
pub(super) struct EphPanel {
    pub url: String,
    /// Remaining seconds at render time (Topcoat `signal` seed for live countdown).
    pub remaining_secs: f64,
}

pub(super) use crate::release_pkg::package_file_name;

pub(super) fn eph_public_url(
    public_origin: &str,
    token: &str,
    version: &str,
    channel: &str,
) -> String {
    format!(
        "{public_origin}/releases/{token}/{}",
        package_file_name(version, channel)
    )
}

pub(super) fn format_countdown(expires_at: i64, now: i64) -> (String, bool, bool) {
    let remaining = expires_at - now;
    if remaining <= 0 {
        return ("expired".to_owned(), false, true);
    }
    let mins = remaining / 60;
    let secs = remaining % 60;
    (
        format!("expires in {mins}:{secs:02}"),
        remaining < 60,
        false,
    )
}

pub(super) async fn load_eph_for(
    cx: &Cx,
    user_id: u64,
    organization_id: u64,
    version: &str,
) -> Option<EphemeralDownload> {
    let mut database = db(cx);
    let rows = EphemeralDownload::all()
        .filter(EphemeralDownload::fields().user_id().eq(user_id))
        .exec(&mut database)
        .await
        .unwrap_or_default();
    rows.into_iter()
        .filter(|r| r.organization_id == organization_id && r.release_version == version)
        .max_by_key(|r| r.created_at)
}

pub(super) fn panel_from_row(
    public_origin: &str,
    row: &EphemeralDownload,
    version: &str,
    channel: &str,
    now: i64,
) -> EphPanel {
    let url = eph_public_url(public_origin, &row.token, version, channel);
    let (_countdown, _warn, expired) = format_countdown(row.expires_at, now);
    let remaining_secs = if expired {
        0.0
    } else {
        (row.expires_at - now) as f64
    };
    EphPanel {
        url,
        remaining_secs,
    }
}

fn redirect_detail(org: &str, ver: &str, form: &EphRedirectForm) -> SeeOther {
    let mut qs = Vec::new();
    if let Some(ch) = form
        .channel
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        qs.push(format!("channel={ch}"));
    }
    let path = if qs.is_empty() {
        format!("/{org}/builds/{ver}")
    } else {
        format!("/{org}/builds/{ver}?{}", qs.join("&"))
    };
    see_other(&path)
}

async fn require_downloadable_release(
    cx: &Cx,
    org_slug: &str,
    ver: &str,
) -> Result<(crate::auth::OrgContext, Release)> {
    let ctx = require_org(cx, org_slug).await.map_err(|_| not_found())?;
    let perms = perms_for_user(cx, &ctx.user).await;
    if !perms.builds_download {
        return Err(forbidden().into());
    }

    let ver_key = ver.to_owned();
    let mut database = db(cx);
    let Some(release) =
        find_visible_release_by_version(&mut database, &ver_key, ctx.org.id, org_slug).await
    else {
        return Err(not_found().into());
    };
    if find_release_object(&mut database, release.id)
        .await
        .is_none()
    {
        return Err(not_found().into());
    }
    Ok((ctx, release))
}

/// Public GET for a short-lived download token (no session).
///
/// Token / package segments are read from the absolute route capture map
/// (this module already owns `{release_ver}` via [`ReleaseVer`]; Topcoat
/// allows only one `#[path_param]` / `segment!` registration per module).
#[route(GET "/releases/{eph_token}/{eph_pkg}")]
async fn ephemeral_download_get(cx: &Cx) -> Result<Response> {
    let mut token = None;
    let mut pkg = None;
    for (key, value) in topcoat::router::raw_path_params(cx) {
        match key {
            "eph_token" => token = Some(value.to_owned()),
            "eph_pkg" => pkg = Some(value.to_owned()),
            _ => {}
        }
    }
    let Some(token) = token else {
        return Err(not_found().into());
    };
    let Some(_pkg) = pkg else {
        return Err(not_found().into());
    };

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

    let Some(org) = crate::models::Organization::get_by_id(&mut database, row.organization_id)
        .await
        .ok()
    else {
        return Err(not_found().into());
    };
    let Some(rel) =
        find_visible_release_by_version(&mut database, &row.release_version, org.id, &org.slug)
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

async fn delete_existing_for(
    database: &mut toasty::Db,
    user_id: u64,
    organization_id: u64,
    version: &str,
) {
    let rows = EphemeralDownload::all()
        .filter(EphemeralDownload::fields().user_id().eq(user_id))
        .exec(database)
        .await
        .unwrap_or_default();
    for row in rows {
        if row.organization_id == organization_id && row.release_version == version {
            let _ = row.delete().exec(database).await;
        }
    }
}

#[route(POST "/{org}/builds/{release_ver}/ephemeral")]
async fn builds_eph_generate(cx: &Cx, Form(form): Form<EphRedirectForm>) -> Result<SeeOther> {
    let org_slug = path_param::<Org>(cx);
    let ver = path_param::<ReleaseVer>(cx);
    let (ctx, _release) = require_downloadable_release(cx, org_slug, ver).await?;

    let now = now_unix();
    let token = Uuid::new_v4().to_string();
    let mut database = db(cx);
    delete_existing_for(&mut database, ctx.user.id, ctx.org.id, ver).await;
    let _ = toasty::create!(EphemeralDownload {
        token,
        user_id: ctx.user.id,
        organization_id: ctx.org.id,
        release_version: ver.to_owned(),
        expires_at: now + EPH_DOWNLOAD_TTL_SECS,
        created_at: now,
    })
    .exec(&mut database)
    .await;

    Ok(redirect_detail(org_slug, ver, &form))
}

#[route(POST "/{org}/builds/{release_ver}/ephemeral/revoke")]
async fn builds_eph_revoke(cx: &Cx, Form(form): Form<EphRedirectForm>) -> Result<SeeOther> {
    let org_slug = path_param::<Org>(cx);
    let ver = path_param::<ReleaseVer>(cx);
    let (ctx, _release) = require_downloadable_release(cx, org_slug, ver).await?;

    let mut database = db(cx);
    delete_existing_for(&mut database, ctx.user.id, ctx.org.id, ver).await;

    Ok(redirect_detail(org_slug, ver, &form))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_url_shape_strips_v() {
        let url = eph_public_url("https://access.vauban.sh", "tok-1", "v1.0.0", "LTS");
        assert_eq!(
            url,
            "https://access.vauban.sh/releases/tok-1/vauban-1.0.0+LTS.pkg"
        );
    }

    #[test]
    fn countdown_live_warn_and_expired() {
        let (label, warn, expired) = format_countdown(100, 40);
        assert_eq!(label, "expires in 1:00");
        assert!(!warn);
        assert!(!expired);

        let (label, warn, expired) = format_countdown(100, 50);
        assert_eq!(label, "expires in 0:50");
        assert!(warn);
        assert!(!expired);

        let (label, warn, expired) = format_countdown(100, 100);
        assert_eq!(label, "expired");
        assert!(!warn);
        assert!(expired);
    }
}
