//! Build expand at `/{org}/builds/{release_ver}` — same list with open panel.

use topcoat::{
    Result,
    context::Cx,
    router::{forbidden, page, path_param, query_params},
};

use super::{BuildsQuery, load_releases, render_builds};
use crate::{
    app::org::Org,
    auth::require_org,
    layout::{self, NavSection},
    models::Release,
    perms::perms_for_user,
};

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
    let all = Release::all().exec(&mut database).await.unwrap_or_default();
    if !all.iter().any(|r| r.version == *ver) {
        return Err(topcoat::router::not_found().into());
    }

    let releases = load_releases(cx, channel).await;
    // Ensure the open version is visible even if channel filter would hide it.
    let releases = if releases.iter().any(|r| r.version == *ver) {
        releases
    } else {
        all.into_iter()
            .filter(|r| r.version == *ver)
            .chain(releases)
            .collect()
    };

    let body = render_builds(
        cx,
        org_slug,
        channel,
        &releases,
        Some(ver),
        show_link,
        perms.builds_download,
    )
    .await;
    layout::shell(cx, &ctx, &perms, NavSection::Builds, "builds", body).await
}
