//! Admin releases list at `/admin/releases`.

mod confirm;
mod delete_confirm;
mod new;
mod release_id;

use topcoat::{
    Result,
    context::Cx,
    router::{page, query_params},
    view::view,
};

use crate::{
    app::_components::{ico_trash, list_toolbar},
    auth::{capability_denied, require_staff},
    list_page::{
        LIST_PAGE_SIZE, PagerLinks, clamp_page, href_with_query, page_count, page_offset,
        parse_page, with_page_param,
    },
    models::{RELEASE_GA_ORG_ID, RELEASE_STATUS_PUBLISHED, Release},
    perms::perms_for_user,
    storage::{BlobDisplay, release_blob_display},
    ui::{channel_badge_class, release_status_badge_class},
};

#[query_params]
struct AdminReleasesQuery {
    delete: Option<String>,
    err: Option<String>,
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
    let total = Release::all()
        .count()
        .exec(&mut database)
        .await
        .unwrap_or(0) as usize;

    let q = query_params::<AdminReleasesQuery>(cx).ok();
    let delete_id = q
        .as_ref()
        .and_then(|q| q.delete.as_deref())
        .and_then(|s| s.parse::<u64>().ok());
    let delete_err = q
        .as_ref()
        .and_then(|q| q.err.as_deref())
        .is_some_and(|e| e == "confirm");
    let delete_target = if let Some(id) = delete_id {
        Release::all()
            .filter(Release::fields().id().eq(id))
            .exec(&mut database)
            .await
            .ok()
            .and_then(|mut rows| rows.pop())
    } else {
        None
    };

    let mut page = parse_page(q.as_ref().and_then(|q| q.page));
    let pages = page_count(total, LIST_PAGE_SIZE);
    page = clamp_page(page, pages);
    let page_releases = Release::all()
        .order_by((
            Release::fields().v_major().desc(),
            Release::fields().v_minor().desc(),
            Release::fields().v_patch().desc(),
            Release::fields().has_client_suffix().desc(),
            Release::fields().client_suffix().asc(),
        ))
        .limit(LIST_PAGE_SIZE)
        .offset(page_offset(page, LIST_PAGE_SIZE))
        .exec(&mut database)
        .await
        .unwrap_or_default();
    let org_ids: Vec<u64> = page_releases
        .iter()
        .map(|r| r.organization_id)
        .filter(|id| *id != RELEASE_GA_ORG_ID)
        .collect();
    let orgs = crate::id_lookups::orgs_by_ids(&mut database, &org_ids)
        .await
        .unwrap_or_default();
    let mut blobs: Vec<BlobDisplay> = Vec::with_capacity(page_releases.len());
    for rel in &page_releases {
        blobs.push(release_blob_display(&mut database, rel.id).await);
    }
    let rows: Vec<(&Release, &BlobDisplay)> = page_releases.iter().zip(blobs.iter()).collect();
    // Pager keeps only `page` — never sticky `delete` / `err` (overlay query).
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
            <a class="vb-btn" href="/admin/releases/new">"+ New release"</a>
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
                        <th class="vb-col-actions">"ACTIONS"</th>
                    </tr>
                </thead>
                <tbody>
                    if total == 0 {
                        <tr>
                            <td colspan="7">
                                <div class="vb-empty">"No releases recorded."</div>
                            </td>
                        </tr>
                    } else {
                        for (rel, blob) in rows {
                            let target = if rel.organization_id == RELEASE_GA_ORG_ID {
                                "GA".to_owned()
                            } else {
                                orgs.iter()
                                    .find(|o| o.id == rel.organization_id)
                                    .map(|o| o.slug.clone())
                                    .unwrap_or_else(|| format!("org#{}", rel.organization_id))
                            };
                            let channel_badge = channel_badge_class(&rel.channel).to_owned();
                            let status_badge = release_status_badge_class(&rel.status)
                                .to_owned();
                            let edit_href = format!("/admin/releases/{}", rel.id);
                            let publish_action = format!("/admin/releases/{}/publish", rel.id);
                            let unpublish_action = format!(
                                "/admin/releases/{}/unpublish", rel.id
                            );
                            let delete_href = if page > 1 {
                                format!("/admin/releases?delete={}&page={page}", rel.id)
                            } else {
                                format!("/admin/releases?delete={}", rel.id)
                            };
                            let is_published = rel.status == RELEASE_STATUS_PUBLISHED;
                            let size_label = format!("{} MB", blob.size_mb);
                            <tr>
                                <td style="font-weight: 700;">(rel.version.clone())</td>
                                <td>
                                    <span class=(channel_badge)>(rel.channel.clone())</span>
                                </td>
                                <td>(target)</td>
                                <td>(rel.released_on.clone())</td>
                                <td>(size_label)</td>
                                <td>
                                    <span class=(status_badge)>(rel.status.clone())</span>
                                </td>
                                <td class="vb-col-actions">
                                    <div class="vb-row-actions">
                                        <a class="vb-btn muted compact" href=(edit_href)>"Edit"</a>
                                        if is_published {
                                            <form method="POST" action=(unpublish_action)>
                                                <button class="vb-btn outline compact" type="submit">
                                                    "Unpublish"
                                                </button>
                                            </form>
                                        } else {
                                            <form method="POST" action=(publish_action)>
                                                <button class="vb-btn outline compact" type="submit">
                                                    "Publish"
                                                </button>
                                            </form>
                                        }
                                        <a
                                            class="vb-btn danger"
                                            href=(delete_href)
                                            title="Delete release"
                                            aria-label="Delete release"
                                        >
                                            (ico_trash(cx, 14).await?)
                                        </a>
                                    </div>
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

        if let Some(target) = delete_target {
            let cancel = if page > 1 {
                format!("/admin/releases?page={page}")
            } else {
                "/admin/releases".to_owned()
            };
            let action = format!("/admin/releases/{}/delete", target.id);
            <div
                class="vb-confirm-root"
                role="dialog"
                aria-modal="true"
                aria-label="Delete release"
            >
                <div class="vb-confirm">
                    <h2>"Delete this release?"</h2>
                    <p>
                        "This permanently removes "
                        <strong>(target.version.clone())</strong>
                        ". Type "
                        <span class="vb-mono">"delete"</span>
                        " to confirm."
                    </p>
                    if delete_err {
                        <p style="color: #b5403a; margin-bottom: 14px;">
                            "Confirmation text must be exactly "
                            <span class="vb-mono">"delete"</span>
                            "."
                        </p>
                    }
                    <form class="vb-form" method="POST" action=(action)>
                        <label for="confirm">"Confirm"</label>
                        <input
                            id="confirm"
                            name="confirm"
                            required=""
                            placeholder="delete"
                            autocomplete="off"
                        >
                        <div class="vb-confirm-actions">
                            <a class="vb-btn muted compact" href=(cancel)>"Cancel"</a>
                            <button
                                class="vb-btn danger"
                                type="submit"
                                style="padding: 10px 18px; font-size: 13px;"
                            >
                                "Delete permanently"
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        }
    }
}
