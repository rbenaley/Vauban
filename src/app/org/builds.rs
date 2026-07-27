//! Builds list at `/{org}/builds` — Concept expandable changelog rows.

mod download;
mod release_ver;

use topcoat::{
    Result,
    context::Cx,
    router::{forbidden, page, path_param, query_params},
    view::view,
};

use crate::{app::org::Org, auth::require_org, models::Release, perms::perms_for_user};

const CHANNELS: &[&str] = &["LTS", "Stable", "EOL"];

#[query_params]
pub(super) struct BuildsQuery {
    pub channel: Option<String>,
    pub link: Option<String>,
}

#[page]
async fn builds_page(cx: &Cx) -> Result {
    let slug = path_param::<Org>(cx);
    let ctx = require_org(cx, slug).await?;
    let perms = perms_for_user(cx, &ctx.user).await;
    if !perms.builds_read {
        return Err(forbidden().into());
    }

    let channel = query_params::<BuildsQuery>(cx)
        .ok()
        .and_then(|q| q.channel.clone())
        .unwrap_or_default();
    let channel = channel.trim();
    let releases = load_releases(cx, channel).await;
    render_builds(
        cx,
        slug,
        channel,
        &releases,
        None,
        false,
        perms.builds_download,
    )
    .await
}

pub(super) async fn render_builds(
    cx: &Cx,
    org_slug: &str,
    channel: &str,
    releases: &[Release],
    open_version: Option<&str>,
    show_link: bool,
    can_download: bool,
) -> Result {
    let all_class = if channel.is_empty() {
        "vb-chip active"
    } else {
        "vb-chip"
    };
    let base = format!("/{org_slug}/builds");
    let org = org_slug.to_owned();
    let channel_owned = channel.to_owned();
    let show_ephemeral = show_link && can_download;

    view! { cx =>
        signal panel_open = true;
        signal eph_tab = 0.0;

        <h1 class="vb-title">"Certified LTS builds"</h1>
        <p class="vb-lead">"Signed and verified binaries. Click a version for its changelog."</p>

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
                        if channel_owned.is_empty() {
                            base.clone()
                        } else {
                            format!("{base}?channel={channel_owned}")
                        }
                    } else if channel_owned.is_empty() {
                        format!("/{}/builds/{}", org, rel.version)
                    } else {
                        format!("/{}/builds/{}?channel={}", org, rel.version, channel_owned)
                    };
                    let row_class = if is_open {
                        "vb-build-row open"
                    } else {
                        "vb-build-row"
                    };
                    let caret = if is_open { "▾" } else { "▸" };
                    let notes = parse_notes(&rel.notes);
                    let size_label = format!("{} MB", rel.size_mb);
                    let gen_href = format!("/{}/builds/{}?link=1", org, rel.version);
                    let link_url = format!(
                        "https://dl.vauban.sh/eph/{}/{}?t=demo",
                        org, rel.version
                    );
                    let curl_line = format!("$ fetch {link_url}");

                    <div>
                        <a class=(row_class) href=(row_href)>
                            <div style="font-weight: 700; color: #14171c;">(rel.version.clone())</div>
                            <div><span class="vb-badge soft">(rel.channel.clone())</span></div>
                            <div style="color: #5a5f66;">(rel.released_on.clone())</div>
                            <div style="color: var(--ok); font-size: 11.5px; display: flex; align-items: center; gap: 6px;">
                                <span>"✓"</span>
                                <span style="color: #8a8f96;">(rel.signature_prefix.clone()) "…"</span>
                            </div>
                            <div style="color: #5a5f66;">(size_label.clone())</div>
                            <div style="color: var(--accent); text-align: right;">(caret)</div>
                        </a>
                        if is_open {
                            <div
                                class="vb-build-panel"
                                :style=$(if panel_open.get() { "" } else { "display: none" })
                            >
                                <div class="vb-section-label">
                                    "RELEASE NOTES · "
                                    (rel.version.clone())
                                </div>
                                for (tag, color, text) in notes {
                                    let tag_style = format!(
                                        "font-size: 10px; font-weight: 600; flex: none; width: 76px; color: {color};"
                                    );
                                    <div style="display: flex; gap: 10px; margin-bottom: 8px; font-size: 13.5px; color: #3a3f46;">
                                        <span class="vb-mono" style=(tag_style)>(tag)</span>
                                        <span>(text)</span>
                                    </div>
                                }
                                if can_download {
                                    let dl_action = format!(
                                        "/{}/builds/{}/download",
                                        org,
                                        rel.version
                                    );
                                    <div class="vb-btn-row">
                                        <form method="POST" action=(dl_action)>
                                            <button class="vb-btn" type="submit">
                                                "↓ Download ("
                                                (size_label)
                                                ")"
                                            </button>
                                        </form>
                                        <a class="vb-btn outline" href=(gen_href)>
                                            "⧖ Generate ephemeral link"
                                        </a>
                                        <button
                                            type="button"
                                            class="vb-btn muted"
                                            @click=$(|_e| panel_open.set(false))
                                        >"Collapse"</button>
                                        <span class="vb-btn muted">"Verify signature"</span>
                                    </div>
                                }
                                if show_ephemeral {
                                    <div class="vb-ephemeral">
                                        <div class="vb-ephemeral-bar">
                                            <div class="vb-mono" style="font-size: 11px; letter-spacing: 0.04em; color: var(--accent); display: flex; align-items: center; gap: 9px;">
                                                <span style="width: 7px; height: 7px; border-radius: 50%; background: var(--ok);"></span>
                                                "EPHEMERAL DOWNLOAD LINK"
                                            </div>
                                            <span class="vb-mono" style="font-size: 11.5px; color: var(--warn);">
                                                "04:58 remaining"
                                            </span>
                                        </div>
                                        <div style="padding: 14px 16px;">
                                            <div class="vb-chip-row" style="margin-bottom: 12px;">
                                                <button
                                                    type="button"
                                                    class="vb-chip"
                                                    :class=$(if eph_tab.get() == 0.0 { "vb-chip active" } else { "vb-chip" })
                                                    @click=$(|_e| eph_tab.set(0.0))
                                                >"URL"</button>
                                                <button
                                                    type="button"
                                                    class="vb-chip"
                                                    :class=$(if eph_tab.get() == 1.0 { "vb-chip active" } else { "vb-chip" })
                                                    @click=$(|_e| eph_tab.set(1.0))
                                                >"cURL"</button>
                                            </div>
                                            <div :style=$(if eph_tab.get() == 0.0 { "" } else { "display: none" })>
                                                <input
                                                    class="vb-mono"
                                                    readonly=""
                                                    value=(link_url.clone())
                                                    style="width: 100%; box-sizing: border-box; font-size: 12px; padding: 10px 12px; border: 1px solid #e8eae6; border-radius: 4px; background: #f7f8f6;"
                                                >
                                            </div>
                                            <div :style=$(if eph_tab.get() == 1.0 { "" } else { "display: none" })>
                                                <div class="vb-mono" style="font-size: 10px; letter-spacing: 0.06em; color: #8a8f96; margin-bottom: 8px;">
                                                    "RUN ON YOUR SERVER · NO AUTH NEEDED"
                                                </div>
                                                <pre class="vb-pre" style="margin: 0;">(curl_line.clone())</pre>
                                            </div>
                                            <div style="font-size: 12px; color: #8a8f96; margin-top: 10px; line-height: 1.5;">
                                                "Valid for 5 minutes, single binary, no authentication. Stub token for visual fidelity."
                                            </div>
                                        </div>
                                    </div>
                                }
                            </div>
                        }
                    </div>
                }
            }
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

pub(super) async fn load_releases(cx: &Cx, channel: &str) -> Vec<Release> {
    let mut database = crate::auth::db(cx);
    if channel.is_empty() {
        return Release::all().exec(&mut database).await.unwrap_or_default();
    }
    let channel_owned = channel.to_owned();
    Release::all()
        .filter(Release::fields().channel().eq(&channel_owned))
        .exec(&mut database)
        .await
        .unwrap_or_default()
}
