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
        ico_arrow_down, ico_check, ico_chevron_down, ico_chevron_right, ico_copy, ico_hourglass,
    },
    app::org::Org,
    auth::{capability_denied, config, require_org},
    db::now_unix,
    models::{RELEASE_GA_ORG_ID, Release},
    perms::perms_for_user,
};

use self::ephemeral::{EphPanel, load_eph_for, panel_from_row};

const CHANNELS: &[&str] = &["LTS", "Stable", "EOL"];

#[query_params]
pub(super) struct BuildsQuery {
    pub channel: Option<String>,
    /// When `none`, suppress default-open of the latest build (Concept collapse).
    pub open: Option<String>,
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

    let mut releases = load_releases_for_org(cx, ctx.org.id, channel).await;
    sort_releases(&mut releases);
    let open_version = if collapse {
        None
    } else {
        releases.first().map(|r| r.version.as_str())
    };

    render_builds(
        cx,
        slug,
        channel,
        &releases,
        open_version,
        perms.builds_download,
        ctx.user.id,
        ctx.org.id,
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
) -> Result {
    let all_class = if channel.is_empty() {
        "vb-chip active"
    } else {
        "vb-chip"
    };
    let base = format!("/{org_slug}/builds");
    let org = org_slug.to_owned();
    let channel_owned = channel.to_owned();
    let collapse_href = if channel_owned.is_empty() {
        format!("{base}?open=none")
    } else {
        format!("{base}?channel={channel_owned}&open=none")
    };

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

        <div class="vb-chip-row">
            <a class=(all_class) href=(base.clone())>"All"</a>
            for ch in CHANNELS {
                let href = format!("{base}?channel={ch}");
                let class = if channel.eq_ignore_ascii_case(ch) {
                    "vb-chip active"
                } else {
                    "vb-chip"
                };
                <a class=(class) href=(href)>(*ch)</a>
            }
        </div>

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
                                <span class="vb-badge soft">(rel.channel.clone())</span>
                            </div>
                            <div style="color: #5a5f66;">(rel.released_on.clone())</div>
                            <div
                                style="color: var(--ok); font-size: 11.5px; display: flex; align-items: center; gap: 6px;"
                            >
                                (ico_check(cx, 12).await?)
                                <span style="color: #8a8f96;">
                                    (rel.signature_prefix.clone())
                                    "…"
                                </span>
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
                                    let dl_action = format!(
                                        "/{}/builds/{}/download", org, rel.version
                                    );
                                    <div class="vb-btn-row">
                                        <form method="POST" action=(dl_action)>
                                            <button
                                                class="vb-btn vb-btn-ico vb-btn-build"
                                                type="submit"
                                            >
                                                (ico_arrow_down(cx, 14).await?)
                                                <span>(dl_label.clone())</span>
                                            </button>
                                        </form>
                                        <form method="POST" action=(eph_action.clone())>
                                            if !channel_owned.is_empty() {
                                                <input
                                                    type="hidden"
                                                    name="channel"
                                                    value=(channel_owned.clone())
                                                />
                                            }
                                            <button
                                                type="submit"
                                                class="vb-btn outline vb-btn-ico vb-btn-build"
                                            >
                                                (ico_hourglass(cx, 14).await?)
                                                <span>(gen_label)</span>
                                            </button>
                                        </form>
                                        <span class="vb-btn muted vb-btn-build">
                                            "Verify signature"
                                        </span>
                                    </div>
                                    if let Some(panel) = open_panel.clone() {
                                        ephemeral_link_panel(
                                            panel: panel,
                                            chrome: EphPanelChrome {
                                                eph_action: eph_action.clone(),
                                                revoke_action: revoke_action.clone(),
                                                channel: channel_owned.clone(),
                                            },
                                        )
                                    }
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
                <div class="vb-ephemeral-title">
                    <span
                        class="vb-ephemeral-dot"
                        :style=$(if live.get() {
                            if warn.get() { "background:#b5403a" } else { "background:var(--ok)" }
                        } else {
                            "background:#b5403a"
                        })
                    ></span>
                    "EPHEMERAL DOWNLOAD LINK"
                </div>
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
                            <input type="hidden" name="channel" value=(channel.clone()) />
                        }
                        <button type="submit" class="vb-ephemeral-revoke">"Revoke"</button>
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

            <div class="vb-ephemeral-body" :style=$(if live.get() { "" } else { "display:none" })>
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
                <div class="vb-ephemeral-help">
                    "Valid for 5 minutes, single binary, no authentication. After expiry the token is rejected -- generate a new link."
                </div>
            </div>

            <div class="vb-ephemeral-expired" :style=$(if live.get() { "display:none" } else { "" })>
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

/// Releases visible to an org: GA (`organization_id == 0`) or targeted at that org.
pub(super) fn release_visible_to_org(release: &Release, org_id: u64) -> bool {
    release.organization_id == RELEASE_GA_ORG_ID || release.organization_id == org_id
}

pub(super) fn sort_releases(releases: &mut [Release]) {
    releases.sort_by(|a, b| {
        b.released_on
            .cmp(&a.released_on)
            .then_with(|| b.version.cmp(&a.version))
    });
}

pub(super) async fn load_releases_for_org(cx: &Cx, org_id: u64, channel: &str) -> Vec<Release> {
    let mut database = crate::auth::db(cx);
    let all = if channel.is_empty() {
        Release::all().exec(&mut database).await.unwrap_or_default()
    } else {
        let channel_owned = channel.to_owned();
        Release::all()
            .filter(Release::fields().channel().eq(&channel_owned))
            .exec(&mut database)
            .await
            .unwrap_or_default()
    };
    let mut filtered: Vec<_> = all
        .into_iter()
        .filter(|r| release_visible_to_org(r, org_id))
        .collect();
    sort_releases(&mut filtered);
    filtered
}
