//! Admin releases list at `/admin/releases`.

mod new;

use topcoat::{
    Result,
    context::Cx,
    router::{page, query_params},
    view::view,
};

use crate::{
    app::_components::list_toolbar,
    auth::{capability_denied, require_staff},
    list_page::{
        LIST_PAGE_SIZE, PagerLinks, clamp_page, href_with_query, page_count, page_slice,
        parse_page, with_page_param,
    },
    models::{Organization, RELEASE_GA_ORG_ID, Release},
    perms::perms_for_user,
};

#[query_params]
struct AdminReleasesQuery {
    /// 1-based page index; omitted means page 1.
    page: Option<u32>,
}

#[page]
async fn admin_releases_page(cx: &Cx) -> Result {
    let staff = require_staff(cx).await?;
    let perms = perms_for_user(cx, &staff.user).await;
    if !perms.releases_manage {
        return Err(capability_denied().into());
    }

    let mut database = crate::auth::db(cx);
    let releases = Release::all().exec(&mut database).await.unwrap_or_default();
    let orgs = Organization::all()
        .exec(&mut database)
        .await
        .unwrap_or_default();

    let q = query_params::<AdminReleasesQuery>(cx).ok();
    let mut page = parse_page(q.as_ref().and_then(|q| q.page));
    let pages = page_count(releases.len(), LIST_PAGE_SIZE);
    page = clamp_page(page, pages);
    let page_releases = page_slice(&releases, page, LIST_PAGE_SIZE);
    let pager = PagerLinks::from_hrefs(page, pages, |n| {
        let mut parts = Vec::new();
        with_page_param(&mut parts, n);
        href_with_query("/admin/releases", &parts)
    });

    view! {
        cx =>
        <div
            style="display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; flex-wrap: wrap; margin-bottom: 18px;"
        >
            <div>
                <h1 class="vb-title">"Release manager"</h1>
                <p class="vb-lead" style="margin-bottom: 0;">
                    "Publish signed builds that appear in the customer Builds list."
                </p>
            </div>
            <a class="vb-btn" href="/admin/releases/new">"+ Publish release"</a>
        </div>

        list_toolbar(links: &pager)

        <div class="vb-table-wrap">
            <table class="vb-table">
                <thead>
                    <tr>
                        <th>"VERSION"</th>
                        <th>"CHANNEL"</th>
                        <th>"TARGET"</th>
                        <th>"DATE"</th>
                        <th>"SIZE"</th>
                        <th>"STATUS"</th>
                        <th>"ACTIONS"</th>
                    </tr>
                </thead>
                <tbody>
                    if releases.is_empty() {
                        <tr>
                            <td colspan="7">
                                <div class="vb-empty">"No releases recorded."</div>
                            </td>
                        </tr>
                    } else {
                        for rel in page_releases {
                            let target = if rel.organization_id == RELEASE_GA_ORG_ID {
                                "GA".to_owned()
                            } else {
                                orgs.iter()
                                    .find(|o| o.id == rel.organization_id)
                                    .map(|o| o.slug.clone())
                                    .unwrap_or_else(|| format!("org#{}", rel.organization_id))
                            };
                            <tr>
                                <td style="font-weight: 700;">(rel.version.clone())</td>
                                <td>
                                    <span class="vb-badge soft">(rel.channel.clone())</span>
                                </td>
                                <td>
                                    <span class="vb-mono" style="font-size: 11px;">
                                        (target)
                                    </span>
                                </td>
                                <td>(rel.released_on.clone())</td>
                                <td>
                                    (rel.size_mb.clone())
                                    " MB"
                                </td>
                                <td>(rel.status.clone())</td>
                                <td>
                                    <a
                                        class="vb-link"
                                        href="/admin/releases/new"
                                        style="margin: 0;"
                                    >
                                        "Edit"
                                    </a>
                                </td>
                            </tr>
                        }
                    }
                </tbody>
            </table>
        </div>
        <p class="vb-muted" style="margin-top: 14px;">
            "Upload and signing workflow ships in a later slice."
        </p>
    }
}
