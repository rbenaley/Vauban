//! Builds list at `/{org}/builds` — Concept expandable changelog rows.

mod download;
mod ephemeral;
mod release_ver;

use topcoat::{
    Result,
    context::Cx,
    router::{page, path_param, query_params},
    view::{component, view},
};

use crate::{
    app::_components::{
        filter_row, ico_arrow_down, ico_check, ico_chevron_down, ico_chevron_right, ico_copy,
        ico_hourglass,
    },
    app::org::Org,
    auth::{capability_denied, config, require_org},
    db::now_unix,
    list_page::{PagerLinks, href_with_query, page_offset, with_page_param},
    models::{RELEASE_GA_ORG_ID, RELEASE_STATUS_PUBLISHED, RESERVED_ORG_SLUG, Release},
    perms::perms_for_user,
    release_pkg::{package_file_name, sha256_cmd},
    ui::channel_badge_class,
};

use self::ephemeral::{EphPanel, load_eph_for, panel_from_row};

#[allow(unused_imports)] // retained for test / API stability pins
pub use crate::list_page::page_slice;
/// Re-export shared pagination helpers for `builds_entitlement` / `vcp::app`.
pub use crate::list_page::{BUILDS_PAGE_SIZE, clamp_page, page_count, parse_page};

const CHANNELS: &[&str] = &["LTS", "Stable", "EOL"];

#[query_params]
pub(super) struct BuildsQuery {
    pub channel: Option<String>,
    /// When `none`, suppress default-open of the latest build (Concept collapse).
    pub open: Option<String>,
    /// 1-based page index; omitted means page 1.
    pub page: Option<u32>,
}

/// Shareable builds list URL (`page=1` and empty channel omitted).
pub fn builds_list_href(org: &str, channel: &str, page: usize, open_none: bool) -> String {
    let mut parts = Vec::new();
    if !channel.is_empty() {
        parts.push(format!("channel={channel}"));
    }
    with_page_param(&mut parts, page);
    if open_none {
        parts.push("open=none".to_owned());
    }
    href_with_query(&format!("/{org}/builds"), &parts)
}

#[page]
async fn builds_page(cx: &Cx) -> Result {
    let slug = path_param::<Org>(cx);
    let ctx = require_org(cx, slug).await?;
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
    let collapse = q
        .as_ref()
        .and_then(|q| q.open.as_deref())
        .is_some_and(|v| v.eq_ignore_ascii_case("none"));
    let mut page = parse_page(q.as_ref().and_then(|q| q.page));
    let total = count_releases_for_org(cx, ctx.org.id, slug, channel).await;
    let pages = page_count(total, BUILDS_PAGE_SIZE);
    page = clamp_page(page, pages);
    let page_releases = load_releases_page_for_org(cx, ctx.org.id, slug, channel, page).await;
    let open_version = if collapse || page != 1 {
        None
    } else {
        page_releases.first().map(|r| r.version.as_str())
    };

    render_builds(
        cx,
        slug,
        channel,
        &page_releases,
        open_version,
        perms.builds_download,
        ctx.user.id,
        ctx.org.id,
        page,
        pages,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn render_builds(
    cx: &Cx,
    org_slug: &str,
    channel: &str,
    releases: &[Release],
    open_version: Option<&str>,
    can_download: bool,
    user_id: u64,
    org_id: u64,
    page: usize,
    page_count: usize,
) -> Result {
    let base = format!("/{org_slug}/builds");
    let org = org_slug.to_owned();
    let channel_owned = channel.to_owned();
    let collapse_href = builds_list_href(&org, &channel_owned, page, true);
    let org_for_pager = org.clone();
    let channel_for_pager = channel_owned.clone();
    let pager = PagerLinks::from_hrefs(page, page_count, |n| {
        builds_list_href(&org_for_pager, &channel_for_pager, n, false)
    });
    let pager_opt = if pager.show() { Some(pager) } else { None };

    let mut chips: Vec<(String, String, bool)> = Vec::with_capacity(1 + CHANNELS.len());
    chips.push(("All".to_owned(), base.clone(), channel.is_empty()));
    for ch in CHANNELS {
        chips.push((
            (*ch).to_owned(),
            format!("{base}?channel={ch}"),
            channel.eq_ignore_ascii_case(ch),
        ));
    }

    let public_origin = config(cx).primary_public_origin().to_owned();
    let eph_model: Option<EphPanel> = if let Some(ver) = open_version {
        if can_download {
            if let Some(row) = load_eph_for(cx, user_id, org_id, ver).await {
                let rel_channel = releases
                    .iter()
                    .find(|r| r.version == ver)
                    .map(|r| r.channel.as_str())
                    .unwrap_or(channel);
                Some(panel_from_row(
                    &public_origin,
                    &row,
                    ver,
                    rel_channel,
                    now_unix(),
                ))
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };
    let has_eph = eph_model.is_some();
    let gen_label = if has_eph {
        "Regenerate link"
    } else {
        "5-minute download link"
    };

    view! {
        cx =>
        <h1 class="vb-title">"Certified LTS builds"</h1>
        <p class="vb-lead">
            "Signed and verified binaries. Click a version for its changelog."
        </p>

        filter_row(chips: &chips, pager: &pager_opt)

        <div class="vb-table-wrap">
            <div class="vb-build-head">
                <div>"VERSION"</div>
                <div>"CHANNEL"</div>
                <div>"DATE"</div>
                <div>"SIGNATURE (SHA-256)"</div>
                <div>"SIZE"</div>
                <div></div>
            </div>
            if releases.is_empty() {
                <div class="vb-empty">"No published builds."</div>
            } else {
                for rel in releases {
                    let is_open = open_version.is_some_and(|v| v == rel.version);
                    let row_href = if is_open {
                        collapse_href.clone()
                    } else if channel_owned.is_empty() {
                        format!("/{}/builds/{}", org, rel.version)
                    } else {
                        format!(
                            "/{}/builds/{}?channel={}", org, rel.version, channel_owned
                        )
                    };
                    let row_class = if is_open {
                        "vb-build-row open"
                    } else {
                        "vb-build-row"
                    };
                    let notes = parse_notes(&rel.notes);
                    let size_label = format!("{} MB", rel.size_mb);
                    let dl_label = format!("Download ({size_label})");
                    let channel_badge = channel_badge_class(&rel.channel).to_owned();
                    let eph_action = format!("/{}/builds/{}/ephemeral", org, rel.version);
                    let revoke_action = format!(
                        "/{}/builds/{}/ephemeral/revoke", org, rel.version
                    );
                    let open_panel = if is_open { eph_model.clone() } else { None };

                    <div>
                        <a class=(row_class) href=(row_href)>
                            <div style="font-weight: 700; color: #14171c;">
                                (rel.version.clone())
                            </div>
                            <div>
                                <span class=(channel_badge)>(rel.channel.clone())</span>
                            </div>
                            <div style="color: #5a5f66;">(rel.released_on.clone())</div>
                            <div class="vb-build-sig">
                                (ico_check(cx, 12).await?)
                                <span class="vb-build-sig-hash">(rel.sha256.clone())</span>
                            </div>
                            <div style="color: #5a5f66;">(size_label.clone())</div>
                            <div
                                style="color: var(--accent); display: flex; justify-content: flex-end;"
                            >
                                if is_open {
                                    (ico_chevron_down(cx, 14).await?)
                                } else {
                                    (ico_chevron_right(cx, 14).await?)
                                }
                            </div>
                        </a>
                        if is_open {
                            <div class="vb-build-panel">
                                <div class="vb-section-label">
                                    "RELEASE NOTES · "
                                    (rel.version.clone())
                                </div>
                                for (tag, color, text) in notes {
                                    let tag_style = format!(
                                        "font-size: 10px; font-weight: 600; flex: none; width: 76px; color: {color};"
                                    );
                                    <div
                                        style="display: flex; gap: 10px; margin-bottom: 8px; font-size: 13.5px; color: #3a3f46;"
                                    >
                                        <span class="vb-mono" style=(tag_style)>(tag)</span>
                                        <span>(text)</span>
                                    </div>
                                }
                                if can_download {
                                    build_download_actions(
                                        actions: BuildDownloadActions {
                                            org: org.clone(),
                                            version: rel.version.clone(),
                                            release_channel: rel.channel.clone(),
                                            sha256: rel.sha256.clone(),
                                            dl_label: dl_label.clone(),
                                            gen_label: gen_label.to_owned(),
                                            eph_action: eph_action.clone(),
                                            revoke_action: revoke_action.clone(),
                                            list_channel: channel_owned.clone(),
                                            eph_panel: open_panel.clone(),
                                        }
                                    )
                                }
                            </div>
                        }
                    </div>
                }
            }
        </div>
    }
}

struct EphPanelChrome {
    eph_action: String,
    revoke_action: String,
    channel: String,
}

struct BuildDownloadActions {
    org: String,
    version: String,
    release_channel: String,
    sha256: String,
    dl_label: String,
    gen_label: String,
    eph_action: String,
    revoke_action: String,
    list_channel: String,
    eph_panel: Option<EphPanel>,
}

/// Download / regenerate / verify controls + optional ephemeral panel.
/// Verify uses a client-only Topcoat signal (no POST).
#[component]
async fn build_download_actions(cx: &Cx, actions: BuildDownloadActions) -> Result {
    let BuildDownloadActions {
        org,
        version,
        release_channel,
        sha256,
        dl_label,
        gen_label,
        eph_action,
        revoke_action,
        list_channel,
        eph_panel,
    } = actions;
    let dl_action = format!("/{org}/builds/{version}/download");
    let package_name = package_file_name(&version, &release_channel);
    let verify_cmd = sha256_cmd(&package_name);
    let sha_copy = sha256.clone();
    let cmd_copy = verify_cmd.clone();

    view! {
        cx =>
        signal verify_open = false;

        <div class="vb-btn-row">
            <form method="POST" action=(dl_action)>
                <button class="vb-btn vb-btn-ico vb-btn-build" type="submit">
                    (ico_arrow_down(cx, 14).await?)
                    <span>(dl_label)</span>
                </button>
            </form>
            <form method="POST" action=(eph_action.clone())>
                if !list_channel.is_empty() {
                    <input type="hidden" name="channel" value=(list_channel.clone()) />
                }
                <button type="submit" class="vb-btn outline vb-btn-ico vb-btn-build">
                    (ico_hourglass(cx, 14).await?)
                    <span>(gen_label)</span>
                </button>
            </form>
            <button
                type="button"
                class="vb-btn outline vb-btn-build"
                @click=$(|_e| verify_open.set(!verify_open.get()))
            >
                "Verify signature"
            </button>
        </div>

        <div
            class="vb-ephemeral vb-verify"
            data-verify-signature-panel=""
            :style=$(if verify_open.get() { "" } else { "display:none" })
        >
            <div class="vb-ephemeral-bar">
                <div class="vb-ephemeral-title">"PACKAGE SIGNATURE"</div>
            </div>
            <div class="vb-ephemeral-body">
                <div class="vb-ephemeral-url-row">
                    <div class="vb-ephemeral-url vb-mono">(sha_copy.clone())</div>
                    <button
                        type="button"
                        class="vb-btn vb-btn-build"
                        data-copy=(sha_copy.clone())
                        @click="(e) => { const el = e.current_target.inner; navigator.clipboard.writeText(el.getAttribute('data-copy')); el.textContent = 'Copied'; }"
                    >
                        "Copy"
                    </button>
                </div>
                <div class="vb-ephemeral-cmd-head">
                    <div class="vb-mono vb-ephemeral-run-label">
                        "VERIFY ON YOUR SERVER"
                    </div>
                </div>
                <div class="vb-ephemeral-cmd">
                    <span class="vb-ephemeral-prompt">"$"</span>
                    " "
                    <span class="vb-ephemeral-cmd-bin">"sha256"</span>
                    " "
                    <span class="vb-ephemeral-cmd-url">(package_name.clone())</span>
                    <button
                        type="button"
                        class="vb-ephemeral-cmd-copy"
                        title="Copy command"
                        aria-label="Copy command"
                        data-copy=(cmd_copy.clone())
                        @click="(e) => { const el = e.current_target.inner; navigator.clipboard.writeText(el.getAttribute('data-copy')); el.classList.add('copied'); }"
                    >
                        (ico_copy(cx, 14).await?)
                    </button>
                </div>
            </div>
        </div>

        // Mutual exclusivity: Verify and the live ephemeral panel share one
        // slot. Opening Verify must hide EPHEMERAL DOWNLOAD LINK (and closing
        // Verify restores it when a token is still live).
        if let Some(panel) = eph_panel {
            <div
                data-ephemeral-panel-host=""
                :style=$(if verify_open.get() { "display:none" } else { "" })
            >
                ephemeral_link_panel(
                    panel: panel,
                    chrome: EphPanelChrome {
                        eph_action: eph_action.clone(),
                        revoke_action: revoke_action.clone(),
                        channel: list_channel.clone(),
                    }
                )
            </div>
        }
    }
}

#[component]
async fn ephemeral_link_panel(cx: &Cx, panel: EphPanel, chrome: EphPanelChrome) -> Result {
    let url = panel.url;
    let remaining_secs = panel.remaining_secs;
    let EphPanelChrome {
        eph_action,
        revoke_action,
        channel,
    } = chrome;
    let whole_secs = remaining_secs as i64;
    let initially_live = whole_secs > 0;
    let initially_warn = whole_secs > 0 && whole_secs < 60;
    let init_mins = (whole_secs / 60) as f64;
    let init_secs = (whole_secs % 60) as f64;
    let remaining_secs = whole_secs as f64;
    let fetch_cmd = format!("fetch {url}");
    let curl_cmd = format!("curl -fLO {url}");

    view! {
        cx =>
        signal remaining = remaining_secs;
        signal mins = init_mins;
        signal secs = init_secs;
        signal live = initially_live;
        signal warn = initially_warn;
        signal use_curl = false;

        <div class="vb-ephemeral">
            <div class="vb-ephemeral-bar">
                <div class="vb-ephemeral-title">"EPHEMERAL DOWNLOAD LINK"</div>
                <div class="vb-ephemeral-bar-actions">
                    <span
                        class="vb-mono vb-ephemeral-countdown"
                        :style=$(if live.get() {
                            if warn.get() { "color:#b5403a" } else { "color:#117a6b" }
                        } else {
                            "color:#b5403a"
                        })
                    >
                        $(if live.get() { "expires in " } else { "expired" })
                        $(if live.get() { mins.get() } else { 0.0 })
                        $(if live.get() { ":" } else { "" })
                        $(if live.get() {
                            if secs.get() < 10.0 { "0" } else { "" }
                        } else {
                            ""
                        })
                        $(if live.get() { secs.get() } else { 0.0 })
                    </span>
                    <form method="POST" action=(revoke_action.clone())>
                        if !channel.is_empty() {
                            <input
                                type="hidden"
                                name="channel"
                                value=(channel.clone())
                            />
                        }
                        <button type="submit" class="vb-ephemeral-revoke">
                            "Revoke"
                        </button>
                    </form>
                </div>
            </div>

            <span
                class="vb-eph-tick"
                aria-hidden="true"
                :style=$(if live.get() { "" } else { "display:none" })
                @animationiteration=$(|_e| {
                    let r = remaining.get();
                    if r > 0.0 {
                        let next = r - 1.0;
                        remaining.set(next);
                        let s = secs.get();
                        if s > 0.0 {
                            secs.set(s - 1.0);
                        } else {
                            secs.set(59.0);
                            let m = mins.get();
                            if m > 0.0 {
                                mins.set(m - 1.0);
                            }
                        }
                        if next < 60.0 {
                            warn.set(true);
                        }
                        if next <= 0.0 {
                            live.set(false);
                        }
                    }
                })
            ></span>

            <div
                class="vb-ephemeral-body"
                :style=$(if live.get() { "" } else { "display:none" })
            >
                <div class="vb-ephemeral-url-row">
                    <div class="vb-ephemeral-url vb-mono">(url.clone())</div>
                    <button
                        type="button"
                        class="vb-btn vb-btn-build"
                        data-copy=(url.clone())
                        @click="(e) => { const el = e.current_target.inner; navigator.clipboard.writeText(el.getAttribute('data-copy')); el.textContent = 'Copied'; }"
                    >
                        "Copy"
                    </button>
                </div>
                <div class="vb-ephemeral-cmd-head">
                    <div class="vb-mono vb-ephemeral-run-label">
                        "RUN ON YOUR SERVER · NO AUTH NEEDED"
                    </div>
                    <div class="vb-eph-seg">
                        <button
                            type="button"
                            :class=$(if use_curl.get() {
                                "vb-eph-seg-btn"
                            } else {
                                "vb-eph-seg-btn active"
                            })
                            @click=$(|_e| use_curl.set(false))
                        >
                            "fetch"
                        </button>
                        <button
                            type="button"
                            :class=$(if use_curl.get() {
                                "vb-eph-seg-btn active"
                            } else {
                                "vb-eph-seg-btn"
                            })
                            @click=$(|_e| use_curl.set(true))
                        >
                            "cURL"
                        </button>
                    </div>
                </div>
                <div class="vb-ephemeral-cmd">
                    <span class="vb-ephemeral-prompt">"$"</span>
                    " "
                    <span class="vb-ephemeral-cmd-bin">
                        $(if use_curl.get() { "curl -fLO" } else { "fetch" })
                    </span>
                    " "
                    <span class="vb-ephemeral-cmd-url">(url.clone())</span>
                    <button
                        type="button"
                        class="vb-ephemeral-cmd-copy"
                        title="Copy command"
                        aria-label="Copy command"
                        :data-copy=$(if use_curl.get() {
                            curl_cmd.to_owned()
                        } else {
                            fetch_cmd.to_owned()
                        })
                        @click="(e) => { const el = e.current_target.inner; navigator.clipboard.writeText(el.getAttribute('data-copy')); el.classList.add('copied'); }"
                    >
                        (ico_copy(cx, 14).await?)
                    </button>
                </div>
            </div>

            <div
                class="vb-ephemeral-expired"
                :style=$(if live.get() { "display:none" } else { "" })
            >
                <div class="vb-ephemeral-expired-copy">
                    "This link has expired. Tokens are valid for 5 minutes only."
                </div>
                <form method="POST" action=(eph_action.clone())>
                    if !channel.is_empty() {
                        <input type="hidden" name="channel" value=(channel.clone()) />
                    }
                    <button type="submit" class="vb-btn outline vb-btn-build">
                        "Generate new link"
                    </button>
                </form>
            </div>
        </div>
    }
}

pub(super) fn parse_notes(notes: &str) -> Vec<(String, &'static str, String)> {
    notes
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|line| {
            if let Some((tag, rest)) = line.split_once(':') {
                let tag = tag.trim().to_owned();
                let color = match tag.to_ascii_uppercase().as_str() {
                    "FIX" => "#2f7d52",
                    "FEAT" | "NEW" => "#2f5fb0",
                    "SECURITY" => "#b5403a",
                    "RBAC" => "#117a6b",
                    _ => "#117a6b",
                };
                (tag, color, rest.trim().to_owned())
            } else {
                ("NOTE".to_owned(), "#117a6b", line.trim().to_owned())
            }
        })
        .collect()
}

/// Whether a release row matches the SQL visibility net (status + org).
///
/// Used as the unit/proptest oracle for the Toasty filters in
/// [`load_releases_for_org`] / [`find_visible_release_by_version`].
pub fn release_matches_sql_visibility(
    status: &str,
    release_org_id: u64,
    viewer_org_id: u64,
    viewer_slug: &str,
) -> bool {
    if status != RELEASE_STATUS_PUBLISHED {
        return false;
    }
    if viewer_slug.eq_ignore_ascii_case(RESERVED_ORG_SLUG) {
        return true;
    }
    release_org_id == RELEASE_GA_ORG_ID || release_org_id == viewer_org_id
}

/// Releases visible on org Builds / dashboard: must be `PUBLISHED`, then either
/// GA (`organization_id == 0`) or targeted at that org. The reserved staff
/// tenant `vauban` still sees every **published** private client build; `HIDDEN`
/// rows stay on `/admin/releases` only (Unpublish removes them from chrome).
pub(super) fn release_visible_to_org(release: &Release, org_id: u64, org_slug: &str) -> bool {
    release_matches_sql_visibility(&release.status, release.organization_id, org_id, org_slug)
}

/// Apply published + tenant (+ optional channel) filters for org Builds queries.
macro_rules! builds_releases_filtered {
    ($org_id:expr, $org_slug:expr, $channel:expr) => {{
        let mut q = Release::all().filter(Release::fields().status().eq(RELEASE_STATUS_PUBLISHED));
        if !$org_slug.eq_ignore_ascii_case(RESERVED_ORG_SLUG) {
            q = q.filter(
                Release::fields()
                    .organization_id()
                    .in_list([RELEASE_GA_ORG_ID, $org_id]),
            );
        }
        if !$channel.is_empty() {
            let channel_owned = ($channel).to_owned();
            q = q.filter(Release::fields().channel().eq(channel_owned));
        }
        q
    }};
}

/// SQL order matching `release_pkg::cmp_version_desc`.
macro_rules! release_semver_order_by {
    () => {
        (
            Release::fields().v_major().desc(),
            Release::fields().v_minor().desc(),
            Release::fields().v_patch().desc(),
            Release::fields().has_client_suffix().desc(),
            Release::fields().client_suffix().asc(),
        )
    };
}

/// Count published releases visible to the org (SQL tenant + channel filters).
pub(crate) async fn count_releases_for_org(
    cx: &Cx,
    org_id: u64,
    org_slug: &str,
    channel: &str,
) -> usize {
    let mut database = crate::auth::db(cx);
    let q = builds_releases_filtered!(org_id, org_slug, channel);
    q.count().exec(&mut database).await.unwrap_or(0) as usize
}

/// One page of published releases (SQL entitlement + semver `ORDER BY` + limit/offset).
pub(crate) async fn load_releases_page_for_org(
    cx: &Cx,
    org_id: u64,
    org_slug: &str,
    channel: &str,
    page: usize,
) -> Vec<Release> {
    let mut database = crate::auth::db(cx);
    let mut filtered = builds_releases_filtered!(org_id, org_slug, channel)
        .order_by(release_semver_order_by!())
        .limit(BUILDS_PAGE_SIZE)
        .offset(page_offset(page, BUILDS_PAGE_SIZE))
        .exec(&mut database)
        .await
        .unwrap_or_default();
    // Defense in depth — SQL already applied the same net.
    filtered.retain(|r| release_visible_to_org(r, org_id, org_slug));
    filtered
}

/// All published releases for the org, SQL-ordered (dashboard + detail page index).
pub(crate) async fn load_releases_for_org(
    cx: &Cx,
    org_id: u64,
    org_slug: &str,
    channel: &str,
) -> Vec<Release> {
    let mut database = crate::auth::db(cx);
    let mut filtered = builds_releases_filtered!(org_id, org_slug, channel)
        .order_by(release_semver_order_by!())
        .exec(&mut database)
        .await
        .unwrap_or_default();
    filtered.retain(|r| release_visible_to_org(r, org_id, org_slug));
    filtered
}

/// Version lookup with the same SQL visibility net as the builds list.
pub(super) async fn find_visible_release_by_version(
    db: &mut toasty::Db,
    version: &str,
    org_id: u64,
    org_slug: &str,
) -> Option<Release> {
    let ver_key = version.to_owned();
    let mut q = Release::all()
        .filter(Release::fields().version().eq(ver_key))
        .filter(Release::fields().status().eq(RELEASE_STATUS_PUBLISHED));
    if !org_slug.eq_ignore_ascii_case(RESERVED_ORG_SLUG) {
        q = q.filter(
            Release::fields()
                .organization_id()
                .in_list([RELEASE_GA_ORG_ID, org_id]),
        );
    }
    let found = q.exec(db).await.unwrap_or_default();
    found
        .into_iter()
        .find(|r| release_visible_to_org(r, org_id, org_slug))
}

#[cfg(test)]
mod builds_entitlement_page_tests {
    use super::{builds_list_href, release_visible_to_org};
    use crate::models::{
        RELEASE_GA_ORG_ID, RELEASE_STATUS_HIDDEN, RELEASE_STATUS_PUBLISHED, Release,
    };

    fn sample_release(status: &str, organization_id: u64) -> Release {
        let sort = crate::release_pkg::version_sort_fields("v1.0.0");
        Release {
            id: 1,
            version: "v1.0.0".to_owned(),
            channel: "LTS".to_owned(),
            released_on: "2026-07-01".to_owned(),
            size_mb: "1.0".to_owned(),
            sha256: "pending".to_owned(),
            status: status.to_owned(),
            notes: "FIX: test".to_owned(),
            organization_id,
            v_major: sort.v_major,
            v_minor: sort.v_minor,
            v_patch: sort.v_patch,
            has_client_suffix: sort.has_client_suffix,
            client_suffix: sort.client_suffix,
        }
    }

    #[test]
    fn builds_entitlement_builds_list_href_omits_page_one() {
        assert_eq!(builds_list_href("acme", "", 1, false), "/acme/builds");
        assert_eq!(
            builds_list_href("acme", "LTS", 1, false),
            "/acme/builds?channel=LTS"
        );
        assert_eq!(
            builds_list_href("acme", "LTS", 2, false),
            "/acme/builds?channel=LTS&page=2"
        );
        assert_eq!(
            builds_list_href("acme", "", 2, true),
            "/acme/builds?page=2&open=none"
        );
    }

    #[test]
    fn release_visible_published_ga_for_client() {
        let rel = sample_release(RELEASE_STATUS_PUBLISHED, RELEASE_GA_ORG_ID);
        assert!(release_visible_to_org(&rel, 42, "acme"));
    }

    #[test]
    fn release_visible_hidden_ga_hidden_from_client() {
        let rel = sample_release(RELEASE_STATUS_HIDDEN, RELEASE_GA_ORG_ID);
        assert!(!release_visible_to_org(&rel, 42, "acme"));
    }

    #[test]
    fn release_visible_hidden_hidden_from_reserved_too() {
        let rel = sample_release(RELEASE_STATUS_HIDDEN, RELEASE_GA_ORG_ID);
        assert!(!release_visible_to_org(&rel, 1, "vauban"));
    }

    #[test]
    fn release_visible_reserved_still_sees_published_private() {
        let rel = sample_release(RELEASE_STATUS_PUBLISHED, 42);
        assert!(release_visible_to_org(&rel, 1, "vauban"));
    }

    #[test]
    fn release_visible_published_private_for_target_org_only() {
        let rel = sample_release(RELEASE_STATUS_PUBLISHED, 42);
        assert!(release_visible_to_org(&rel, 42, "acme"));
        assert!(!release_visible_to_org(&rel, 99, "other"));
    }
}

#[cfg(test)]
mod builds_entitlement_sql_prop {
    use super::release_matches_sql_visibility;
    use crate::models::{RELEASE_GA_ORG_ID, RELEASE_STATUS_HIDDEN, RELEASE_STATUS_PUBLISHED};
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(48))]

        #[test]
        fn prop_sql_visibility_matches_oracle(
            viewer_org in 1u64..200,
            release_org in 0u64..200,
            reserved in proptest::bool::ANY,
            published in proptest::bool::ANY,
        ) {
            let status = if published {
                RELEASE_STATUS_PUBLISHED
            } else {
                RELEASE_STATUS_HIDDEN
            };
            let slug = if reserved { "vauban" } else { "acme" };
            let ok = release_matches_sql_visibility(status, release_org, viewer_org, slug);
            if !published {
                prop_assert!(!ok);
            } else if reserved {
                prop_assert!(ok);
            } else {
                prop_assert_eq!(
                    ok,
                    release_org == RELEASE_GA_ORG_ID || release_org == viewer_org
                );
            }
        }
    }
}
