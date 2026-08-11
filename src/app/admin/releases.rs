//! Admin releases list at `/admin/releases`.

mod confirm;
mod delete_confirm;
mod new;
mod release_id;
mod staging;

use topcoat::{
    Result,
    context::Cx,
    router::{page, query_params},
    view::view,
};

use crate::{
    app::_components::{filter_row, ico_trash},
    auth::{capability_denied, require_staff},
    list_page::{
        LIST_PAGE_SIZE, PagerLinks, clamp_page, href_with_query, page_count, page_offset,
        parse_page, with_page_param,
    },
    models::{RELEASE_GA_ORG_ID, RELEASE_STATUS_PUBLISHED, RELEASE_STATUS_STAGING, Release},
    perms::perms_for_user,
    storage::{BlobDisplay, release_blob_display},
    ui::{channel_badge_class, channel_filter_label, release_status_badge_class},
};

/// Channel filter chips (same labels as `/{org}/builds`).
const CHANNEL_CHIPS: &[&str] = &["LTS", "LTS.industrial", "Stable", "EOL"];

#[query_params]
struct AdminReleasesQuery {
    delete: Option<String>,
    err: Option<String>,
    /// Channel filter (`LTS` / `Stable` / `EOL`); omitted means All.
    channel: Option<String>,
    /// 1-based page index; omitted means page 1.
    page: Option<u32>,
}

/// Shareable admin releases list URL (`page=1` and empty channel omitted).
pub fn admin_releases_list_href(channel: &str, page: usize) -> String {
    let mut parts = Vec::new();
    if !channel.is_empty() {
        parts.push(format!("channel={channel}"));
    }
    with_page_param(&mut parts, page);
    href_with_query("/admin/releases", &parts)
}

/// Delete-confirm overlay URL — keeps channel/page, never sticky `err`.
fn admin_releases_delete_href(channel: &str, page: usize, id: u64) -> String {
    let mut parts = Vec::new();
    if !channel.is_empty() {
        parts.push(format!("channel={channel}"));
    }
    parts.push(format!("delete={id}"));
    with_page_param(&mut parts, page);
    href_with_query("/admin/releases", &parts)
}

/// Normalize an unknown / empty channel query to All (`""`).
fn normalize_channel_filter(raw: Option<&str>) -> &str {
    let Some(raw) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return "";
    };
    CHANNEL_CHIPS
        .iter()
        .find(|ch| raw.eq_ignore_ascii_case(ch))
        .copied()
        .unwrap_or("")
}

#[page]
async fn admin_releases_page(cx: &Cx) -> Result {
    let staff = require_staff(cx).await?;
    let perms = perms_for_user(cx, &staff.user).await;
    if !perms.releases_manage {
        return Err(capability_denied().into());
    }

    // Landing here means any signature prompt was walked away from: undo the
    // abandoned ceremonies before the list is read.
    staging::sweep_staged_releases(cx).await;

    let q = query_params::<AdminReleasesQuery>(cx).ok();
    let channel = normalize_channel_filter(q.as_ref().and_then(|q| q.channel.as_deref()));
    let channel_owned = channel.to_owned();

    let mut database = crate::auth::db(cx);
    let mut total_q = Release::all().filter(
        Release::fields()
            .status()
            .ne(RELEASE_STATUS_STAGING.to_owned()),
    );
    if !channel.is_empty() {
        total_q = total_q.filter(Release::fields().channel().eq(channel_owned.clone()));
    }
    let total = total_q.count().exec(&mut database).await.unwrap_or(0) as usize;

    let delete_id = q
        .as_ref()
        .and_then(|q| q.delete.as_deref())
        .and_then(|s| s.parse::<u64>().ok());
    let delete_err = q.as_ref().and_then(|q| q.err.as_deref());
    let delete_err_confirm = delete_err == Some("confirm");
    let delete_err_webauthn = delete_err == Some("webauthn");
    let delete_target = if let Some(id) = delete_id {
        Release::all()
            .filter(Release::fields().id().eq(id))
            .filter(
                Release::fields()
                    .status()
                    .ne(RELEASE_STATUS_STAGING.to_owned()),
            )
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
    let mut page_q = Release::all().filter(
        Release::fields()
            .status()
            .ne(RELEASE_STATUS_STAGING.to_owned()),
    );
    if !channel.is_empty() {
        page_q = page_q.filter(Release::fields().channel().eq(channel_owned.clone()));
    }
    let page_releases = page_q
        .order_by((
            Release::fields().v_major().desc(),
            Release::fields().v_minor().desc(),
            Release::fields().v_patch().desc(),
            Release::fields().is_industrial().desc(),
            Release::fields().has_client_suffix().desc(),
            Release::fields().client_suffix().asc(),
            // Same semver: PUBLISHED before HIDDEN (`status DESC`; STAGING excluded).
            Release::fields().status().desc(),
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

    // Pager keeps channel + page — never sticky `delete` / `err`.
    let channel_for_pager = channel_owned.clone();
    let pager = PagerLinks::from_hrefs(page, pages, |n| {
        admin_releases_list_href(&channel_for_pager, n)
    });
    let pager_opt = Some(pager);

    let mut chips: Vec<(String, String, bool)> = Vec::with_capacity(1 + CHANNEL_CHIPS.len());
    chips.push((
        "All".to_owned(),
        admin_releases_list_href("", 1),
        channel.is_empty(),
    ));
    for ch in CHANNEL_CHIPS {
        chips.push((
            channel_filter_label(ch).to_owned(),
            // Chip hrefs omit `page` so a filter change resets to page 1.
            admin_releases_list_href(ch, 1),
            channel.eq_ignore_ascii_case(ch),
        ));
    }

    let empty_message = if channel.is_empty() {
        "No releases recorded."
    } else {
        "No releases on this channel."
    };

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

        filter_row(chips: &chips, pager: &pager_opt)

        <div class="vb-table-wrap vb-catalog-wrap">
            <div class="vb-rel-head">
                <div>"VERSION"</div>
                <div>"CHANNEL"</div>
                <div>"TARGET"</div>
                <div>"DATE"</div>
                <div>"SIZE"</div>
                <div>"STATUS"</div>
                <div class="vb-rel-actions">"ACTIONS"</div>
            </div>
            if total == 0 {
                <div class="vb-empty">(empty_message)</div>
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
                    let status_badge = release_status_badge_class(&rel.status).to_owned();
                    let edit_href = format!("/admin/releases/{}", rel.id);
                    let publish_action = format!("/admin/releases/{}/publish", rel.id);
                    let unpublish_action = format!("/admin/releases/{}/unpublish", rel.id);
                    let delete_href = admin_releases_delete_href(
                        &channel_owned,
                        page,
                        rel.id,
                    );
                    let is_published = rel.status == RELEASE_STATUS_PUBLISHED;
                    let size_label = format!("{} MB", blob.size_mb);
                    <div class="vb-rel-row">
                        <div class="vb-rel-version">
                            (crate::release_pkg::version_for_display(
                                    &rel.version,
                                )
                                .to_owned())
                        </div>
                        <div>
                            <span class=(channel_badge)>(rel.channel.clone())</span>
                        </div>
                        <div>(target)</div>
                        <div>(rel.released_on.clone())</div>
                        <div>(size_label)</div>
                        <div>
                            <span class=(status_badge)>(rel.status.clone())</span>
                        </div>
                        <div class="vb-rel-actions">
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
                        </div>
                    </div>
                }
            }
        </div>
        if let Some(target) = delete_target {
            let cancel = admin_releases_list_href(&channel_owned, page);
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
                        <strong>
                            (crate::release_pkg::version_for_display(
                                    &target.version,
                                )
                                .to_owned())
                        </strong>
                        ". Type "
                        <span class="vb-mono">"delete"</span>
                        " to confirm."
                    </p>
                    if delete_err_confirm {
                        <p style="color: #b5403a; margin-bottom: 14px;">
                            "Confirmation text must be exactly "
                            <span class="vb-mono">"delete"</span>
                            "."
                        </p>
                    }
                    if delete_err_webauthn {
                        <p style="color: #b5403a; margin-bottom: 14px;">
                            "Security key challenge failed. Try Delete again."
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_href_omits_page_one_and_empty_channel() {
        assert_eq!(admin_releases_list_href("", 1), "/admin/releases");
        assert_eq!(
            admin_releases_list_href("LTS", 1),
            "/admin/releases?channel=LTS"
        );
        assert_eq!(
            admin_releases_list_href("LTS", 2),
            "/admin/releases?channel=LTS&page=2"
        );
        assert_eq!(admin_releases_list_href("", 3), "/admin/releases?page=3");
    }

    #[test]
    fn delete_href_keeps_channel_and_page() {
        assert_eq!(
            admin_releases_delete_href("", 1, 42),
            "/admin/releases?delete=42"
        );
        assert_eq!(
            admin_releases_delete_href("Stable", 2, 7),
            "/admin/releases?channel=Stable&delete=7&page=2"
        );
    }

    #[test]
    fn normalize_channel_accepts_known_case_insensitive() {
        assert_eq!(normalize_channel_filter(None), "");
        assert_eq!(normalize_channel_filter(Some("")), "");
        assert_eq!(normalize_channel_filter(Some("  ")), "");
        assert_eq!(normalize_channel_filter(Some("lts")), "LTS");
        assert_eq!(normalize_channel_filter(Some("Stable")), "Stable");
        assert_eq!(normalize_channel_filter(Some("EOL")), "EOL");
        assert_eq!(normalize_channel_filter(Some("nightly")), "");
    }
}
