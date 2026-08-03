//! Build expand at `/{org}/builds/{release_ver}` — same list with open panel.

use topcoat::{
    Result,
    context::Cx,
    router::{error::not_found, page, path_param, query_params},
};

use super::{
    BUILDS_PAGE_SIZE, BuildsQuery, clamp_page, count_releases_for_org,
    find_visible_release_by_version, load_releases_page_for_org, page_count, render_builds,
};
use crate::{
    app::org::Org,
    auth::{capability_denied, require_org},
    models::{RELEASE_GA_ORG_ID, RELEASE_STATUS_PUBLISHED, RESERVED_ORG_SLUG, Release},
    perms::perms_for_user,
};

/// `{release_ver}` segment for detail / download / ephemeral routes.
#[path_param]
pub(super) struct ReleaseVer(str);

#[page]
async fn build_detail_page(cx: &Cx) -> Result {
    let org_slug = path_param::<Org>(cx);
    let ver = path_param::<ReleaseVer>(cx);
    let ctx = require_org(cx, org_slug).await?;
    let perms = perms_for_user(cx, &ctx.user).await;
    if !perms.builds_read {
        return Err(capability_denied().into());
    }

    let q = query_params::<BuildsQuery>(cx).ok();
    let channel = q
        .as_ref()
        .and_then(|q| q.channel.clone())
        .unwrap_or_default();
    let channel = channel.trim();

    let mut database = crate::auth::db(cx);
    let ver_key = ver.to_string();
    let Some(matched) =
        find_visible_release_by_version(&mut database, &ver_key, ctx.org.id, org_slug).await
    else {
        return Err(not_found().into());
    };

    // Prefer page derived from SQL order so deep-links stay consistent.
    let total = count_releases_for_org(cx, ctx.org.id, org_slug, channel).await;
    let mut pages = page_count(total, BUILDS_PAGE_SIZE);
    let idx = release_index_in_sql_order(cx, ctx.org.id, org_slug, channel, &matched.version).await;
    let mut page = clamp_page(idx / BUILDS_PAGE_SIZE + 1, pages);
    let mut page_releases =
        load_releases_page_for_org(cx, ctx.org.id, org_slug, channel, page).await;

    // Ensure the open version is visible even if channel filter would hide it.
    if !page_releases.iter().any(|r| r.version == *ver) {
        page_releases.insert(0, matched);
        if page_releases.len() > BUILDS_PAGE_SIZE {
            page_releases.truncate(BUILDS_PAGE_SIZE);
        }
        pages = pages.max(1);
        page = 1;
    }

    render_builds(
        cx,
        org_slug,
        channel,
        &page_releases,
        Some(ver),
        perms.builds_download,
        ctx.user.id,
        ctx.org.id,
        page,
        pages,
    )
    .await
}

/// 0-based index of `version` in the SQL-ordered builds list (channel-filtered).
async fn release_index_in_sql_order(
    cx: &Cx,
    org_id: u64,
    org_slug: &str,
    channel: &str,
    version: &str,
) -> usize {
    let mut database = crate::auth::db(cx);
    let mut q = Release::all().filter(Release::fields().status().eq(RELEASE_STATUS_PUBLISHED));
    if !org_slug.eq_ignore_ascii_case(RESERVED_ORG_SLUG) {
        q = q.filter(
            Release::fields()
                .organization_id()
                .in_list([RELEASE_GA_ORG_ID, org_id]),
        );
    }
    if !channel.is_empty() {
        let channel_owned = channel.to_owned();
        q = q.filter(Release::fields().channel().eq(channel_owned));
    }
    let ordered = q
        .order_by((
            Release::fields().v_major().desc(),
            Release::fields().v_minor().desc(),
            Release::fields().v_patch().desc(),
            Release::fields().has_client_suffix().desc(),
            Release::fields().client_suffix().asc(),
        ))
        .exec(&mut database)
        .await
        .unwrap_or_default();
    ordered
        .iter()
        .position(|r| r.version == version)
        .unwrap_or(0)
}
