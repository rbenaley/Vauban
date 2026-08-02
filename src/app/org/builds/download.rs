//! Entitlement-gated download stub: authorized -> 501 (no artifact storage yet).

use topcoat::{
    Result,
    context::Cx,
    router::{
        StatusCode,
        error::{forbidden, not_found},
        path_param, route,
    },
};

use super::find_visible_release_by_version;
use crate::{
    app::org::Org,
    auth::{db, require_org},
    perms::perms_for_user,
};

#[path_param]
struct ReleaseVer(str);

/// Stable message for authorized-but-unconfigured downloads (tests pin this).
pub const DOWNLOAD_NOT_CONFIGURED: &str = "download not configured";

#[route(POST "/{org}/builds/{release_ver}/download")]
async fn builds_download(cx: &Cx) -> Result<(StatusCode, &'static str)> {
    let org_slug = path_param::<Org>(cx);
    let ver = path_param::<ReleaseVer>(cx);
    let ctx = require_org(cx, org_slug).await.map_err(|_| not_found())?;
    let perms = perms_for_user(cx, &ctx.user).await;
    if !perms.builds_download {
        return Err(forbidden().into());
    }

    let ver_key = ver.to_string();
    let mut database = db(cx);
    if find_visible_release_by_version(&mut database, &ver_key, ctx.org.id, org_slug)
        .await
        .is_none()
    {
        return Err(not_found().into());
    }

    Ok((StatusCode::NOT_IMPLEMENTED, DOWNLOAD_NOT_CONFIGURED))
}
