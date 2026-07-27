//! Build expand at `/{org}/builds/{release_ver}` — same list with open panel.

use topcoat::{
    Result,
    context::Cx,
    router::{forbidden, page, path_param, query_params},
};

use super::{BuildsQuery, load_releases_for_org, release_visible_to_org, render_builds};
use crate::{app::org::Org, auth::require_org, models::Release, perms::perms_for_user};

#[path_param]
struct ReleaseVer(str);

#[page]
async fn build_detail_page(cx: &Cx) -> Result {
    let org_slug = path_param::<Org>(cx);
    let ver = path_param::<ReleaseVer>(cx);
    let ctx = require_org(cx, org_slug).await?;
    let perms = perms_for_user(cx, &ctx.user).await;
    if !perms.builds_read {
        return Err(forbidden().into());
    }

    let q = query_params::<BuildsQuery>(cx).ok();
    let channel = q
        .as_ref()
        .and_then(|q| q.channel.clone())
        .unwrap_or_default();
    let channel = channel.trim();
    let show_link = q
        .as_ref()
        .and_then(|q| q.link.as_deref())
        .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));

    let mut database = crate::auth::db(cx);
    let ver_key = ver.to_string();
    let matched = Release::all()
        .filter(Release::fields().version().eq(&ver_key))
        .exec(&mut database)
        .await
        .unwrap_or_default();
    let Some(matched) = matched
        .into_iter()
        .find(|r| release_visible_to_org(r, ctx.org.id))
    else {
        return Err(topcoat::router::not_found().into());
    };

    let releases = load_releases_for_org(cx, ctx.org.id, channel).await;
    // Ensure the open version is visible even if channel filter would hide it.
    let releases = if releases.iter().any(|r| r.version == *ver) {
        releases
    } else {
        std::iter::once(matched).chain(releases).collect()
    };

    render_builds(
        cx,
        org_slug,
        channel,
        &releases,
        Some(ver),
        show_link,
        perms.builds_download,
    )
    .await
}
