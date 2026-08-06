//! Issue screenshot thumbs + lightbox (no first-party JS asset).
//!
//! - Liaisons comment ↔ image: Postgres (`issue_attachments.issue_comment_id`).
//! - Lightbox: Topcoat `@click` string handlers read `data-src` (works inside
//!   `for` loops; no loop-capture into `$()` closures).
//! - Pre-submit previews: Topcoat `@change` function handler (File API).
//! - Published attachments are not removable from the portal UI.

use topcoat::{
    Result,
    context::Cx,
    view::{component, view},
};

use crate::{
    issue_attachments::{attachment_cap_hint, gallery_src},
    models::{ISSUE_COMMENT_KIND_STATUS, IssueAttachment},
};

/// One thumb inside a comment / opener bubble.
#[derive(Debug, Clone)]
pub struct ThumbView {
    pub src: String,
}

/// One timeline row for [`issue_discussion`].
#[derive(Debug, Clone)]
pub struct DiscussionRow {
    pub kind: String,
    pub author_name: String,
    pub author_role: String,
    pub body: String,
    pub when: String,
    pub support_side: bool,
    pub thumbs: Vec<ThumbView>,
}

pub fn thumbs_for_comment(
    org_slug: &str,
    attachments: &[IssueAttachment],
    comment_id: u64,
) -> Vec<ThumbView> {
    attachments
        .iter()
        .filter(|a| a.issue_comment_id == comment_id)
        .map(|a| ThumbView {
            src: gallery_src(org_slug, a),
        })
        .collect()
}

/// Marker for invariants / lint: preview host attribute.
pub const SHOT_PREVIEW_CHANGE: &str = "data-shot-preview";

/// Hidden file input + preview host (`@change` function expression).
///
/// `max` is `[issues].max_attachments_per_comment` (also enforced server-side).
///
/// A native `multiple` input **replaces** its `FileList` on every pick, so a
/// second trip to the file dialog would silently drop the first screenshot.
/// The handler therefore keeps its own accumulated list on the input
/// (`vcpShots`) and writes it back through a `DataTransfer` — picking one image
/// at a time still fills the whole per-message cap.
#[component]
pub async fn shot_file_input(cx: &Cx, label: Result, max: usize) -> Result {
    let _pin = SHOT_PREVIEW_CHANGE;
    let max = max.max(1);
    let max_attr = max.to_string();
    let hint = attachment_cap_hint(max);
    view! {
        cx =>
        <div class="vb-shot-picker">
            <div class="vb-shot-picker-row">
                <label class="vb-btn muted vb-btn-ico vb-shot-add" data-shot-add="">
                    <input
                        class="vb-shot-input"
                        type="file"
                        name="screenshots"
                        accept="image/png,image/jpeg,image/webp"
                        multiple=""
                        data-max=(max_attr)
                        @change="(e) => { const input = e.current_target.inner; const form = input.form; if (!form) return; const host = form.querySelector('[data-shot-preview]'); if (!host) return; const max = parseInt(input.getAttribute('data-max') || '5', 10) || 5; const keyOf = (f) => f.name + '|' + f.size + '|' + f.lastModified; const kept = input.vcpShots || []; const seen = {}; kept.forEach((f) => { seen[keyOf(f)] = true; }); let skipped = 0; Array.from(input.files || []).forEach((f) => { if (!f.type || f.type.indexOf('image/') !== 0) return; if (seen[keyOf(f)]) return; if (kept.length >= max) { skipped = skipped + 1; return; } seen[keyOf(f)] = true; kept.push(f); }); input.vcpShots = kept; const sync = () => { try { const dt = new DataTransfer(); (input.vcpShots || []).forEach((f) => dt.items.add(f)); input.files = dt.files; } catch (_e) {} }; sync(); host.querySelectorAll('img[data-preview-url]').forEach((img) => { try { URL.revokeObjectURL(img.getAttribute('data-preview-url')); } catch (_e) {} }); host.innerHTML = ''; host.hidden = kept.length === 0; kept.forEach((file, index) => { const url = URL.createObjectURL(file); const wrap = document.createElement('div'); wrap.className = 'vb-shot-preview-item'; wrap.title = file.name || 'Screenshot'; const img = document.createElement('img'); img.src = url; img.alt = file.name || 'Screenshot preview'; img.setAttribute('data-preview-url', url); const btn = document.createElement('button'); btn.type = 'button'; btn.className = 'vb-shot-preview-remove'; btn.setAttribute('aria-label', 'Remove ' + (file.name || 'screenshot')); btn.textContent = '×'; btn.addEventListener('click', () => { const list = input.vcpShots || []; list.splice(index, 1); input.vcpShots = list; sync(); input.dispatchEvent(new Event('change', { bubbles: true })); }); wrap.appendChild(img); wrap.appendChild(btn); host.appendChild(wrap); }); const status = form.querySelector('[data-shot-status]'); if (status) { let msg = kept.length ? (kept.length + ' of ' + max + ' attached') : ''; if (skipped) { msg = (msg ? msg + ' · ' : '') + skipped + ' ignored (limit ' + max + ')'; } status.textContent = msg; } const add = form.querySelector('[data-shot-add]'); if (add) { const full = kept.length >= max; add.setAttribute('aria-disabled', full ? 'true' : 'false'); input.tabIndex = full ? -1 : 0; } }"
                    >
                    (label?)
                </label>
                <span class="vb-shot-hint">(hint)</span>
            </div>
            <div class="vb-shot-preview" data-shot-preview="" hidden=""></div>
            <p
                class="vb-shot-status"
                data-shot-status=""
                role="status"
                aria-live="polite"
            ></p>
            <span style="display:none" aria-hidden="true">(_pin)</span>
        </div>
    }
}

/// Bundle for [`issue_discussion`] (keeps the component under clippy's arg limit).
#[derive(Debug, Clone)]
pub struct DiscussionPane {
    pub opener_name: String,
    pub opener_role: String,
    pub opener_when: String,
    pub opener_body: String,
    pub opener_thumbs: Vec<ThumbView>,
    pub timeline: Vec<DiscussionRow>,
    /// Non-empty when the issue has any attachment (drives lightbox mount).
    pub has_lightbox: bool,
}

/// DISCUSSION block: bubbles with thumbs + DOM lightbox in-pane.
#[component]
pub async fn issue_discussion(cx: &Cx, pane: DiscussionPane) -> Result {
    let DiscussionPane {
        opener_name,
        opener_role,
        opener_when,
        opener_body,
        opener_thumbs,
        timeline,
        has_lightbox,
    } = pane;

    view! {
        cx =>
        <div
            id="issue-discussion"
            style="display: flex; flex-direction: column; gap: 14px; margin-bottom: 22px;"
        >
            <div
                style="display: flex; flex-direction: column; align-items: flex-start;"
            >
                <div class="vb-bubble">
                    <div
                        style="display: flex; align-items: center; gap: 8px; margin-bottom: 6px;"
                    >
                        <span style="font-size: 12.5px; font-weight: 700;">
                            (opener_name)
                        </span>
                        <span
                            class="vb-mono"
                            style="font-size: 9.5px; color: #fff; background: #5a5f66; padding: 1px 6px; border-radius: 3px;"
                        >
                            (opener_role)
                        </span>
                        <span class="vb-mono" style="font-size: 10px; color: #9aa0a6;">
                            (opener_when)
                        </span>
                    </div>
                    <div
                        style="font-size: 13.5px; line-height: 1.55; color: #3a3f46; white-space: pre-wrap;"
                    >
                        (opener_body)
                    </div>
                    if !opener_thumbs.is_empty() {
                        <div class="vb-issue-thumbs">
                            for thumb in opener_thumbs.clone() {
                                <div class="vb-issue-thumb-wrap">
                                    <button
                                        type="button"
                                        class="vb-issue-thumb"
                                        aria-label="Open screenshot"
                                        data-src=(thumb.src.clone())
                                        @click="(e) => { const src = e.current_target.inner.getAttribute('data-src'); const box = document.getElementById('issue-lb'); const img = document.getElementById('issue-lb-img'); if (!src || !box || !img) return; const fig = img.closest('.vb-issue-lightbox-figure'); if (fig) { fig.classList.remove('is-fit'); fig.style.width = ''; fig.style.height = ''; } if (!box.open) { if (typeof box.showModal === 'function') { box.showModal(); } else { box.setAttribute('open', ''); } } if (img.getAttribute('src') !== src) { img.setAttribute('src', src); } else if (img.complete) { img.dispatchEvent(new Event('load')); } }"
                                    >
                                        <img src=(thumb.src.clone()) alt="Issue screenshot">
                                    </button>
                                </div>
                            }
                        </div>
                    }
                </div>
            </div>

            for row in timeline.clone() {
                if row.kind == ISSUE_COMMENT_KIND_STATUS {
                    let label = format!("{} · {}", row.body, row.when);
                    <div
                        style="display: flex; align-items: center; gap: 12px; padding: 2px 0;"
                    >
                        <div style="flex: 1; height: 1px; background: #eef0ed;"></div>
                        <span
                            class="vb-mono"
                            style="font-size: 11px; color: #8a8f96; white-space: nowrap;"
                        >
                            (label)
                        </span>
                        <div style="flex: 1; height: 1px; background: #eef0ed;"></div>
                    </div>
                } else {
                    let bubble_class = if row.support_side {
                        "vb-bubble support"
                    } else {
                        "vb-bubble"
                    };
                    let align = if row.support_side {
                        "display: flex; flex-direction: column; align-items: flex-end;"
                    } else {
                        "display: flex; flex-direction: column; align-items: flex-start;"
                    };
                    let name_style = if row.support_side {
                        "font-size: 12.5px; font-weight: 700; color: var(--accent);"
                    } else {
                        "font-size: 12.5px; font-weight: 700;"
                    };
                    let badge_bg = if row.support_side {
                        "font-size: 9.5px; color: #fff; background: var(--accent); padding: 1px 6px; border-radius: 3px;"
                    } else {
                        "font-size: 9.5px; color: #fff; background: #5a5f66; padding: 1px 6px; border-radius: 3px;"
                    };
                    <div style=(align)>
                        <div class=(bubble_class)>
                            <div
                                style="display: flex; align-items: center; gap: 8px; margin-bottom: 6px;"
                            >
                                <span style=(name_style)>(row.author_name.clone())</span>
                                <span class="vb-mono" style=(badge_bg)>
                                    (row.author_role.clone())
                                </span>
                                <span
                                    class="vb-mono"
                                    style="font-size: 10px; color: #9aa0a6;"
                                >
                                    (row.when.clone())
                                </span>
                            </div>
                            <div
                                style="font-size: 13.5px; line-height: 1.55; color: #3a3f46; white-space: pre-wrap;"
                            >
                                (row.body.clone())
                            </div>
                            if !row.thumbs.is_empty() {
                                <div class="vb-issue-thumbs">
                                    for thumb in row.thumbs.clone() {
                                        <div class="vb-issue-thumb-wrap">
                                            <button
                                                type="button"
                                                class="vb-issue-thumb"
                                                aria-label="Open screenshot"
                                                data-src=(thumb.src.clone())
                                                @click="(e) => { const src = e.current_target.inner.getAttribute('data-src'); const box = document.getElementById('issue-lb'); const img = document.getElementById('issue-lb-img'); if (!src || !box || !img) return; const fig = img.closest('.vb-issue-lightbox-figure'); if (fig) { fig.classList.remove('is-fit'); fig.style.width = ''; fig.style.height = ''; } if (!box.open) { if (typeof box.showModal === 'function') { box.showModal(); } else { box.setAttribute('open', ''); } } if (img.getAttribute('src') !== src) { img.setAttribute('src', src); } else if (img.complete) { img.dispatchEvent(new Event('load')); } }"
                                            >
                                                <img src=(thumb.src.clone()) alt="Issue screenshot">
                                            </button>
                                        </div>
                                    }
                                </div>
                            }
                        </div>
                    </div>
                }
            }
        </div>

        if has_lightbox {
            // Native <dialog>: top layer (no ancestor stacking / sizing
            // issues), Escape + focus trap for free. Both dismiss controls
            // are `method="dialog"` submits, so closing never depends on JS.
            // The close button lives in the figure so it overlays the rendered
            // image corner instead of floating in the backdrop. Shrink-wrapping
            // a two-axis-constrained <img> is not reliable across engines, so
            // `@load` pins the figure to the measured image box: the close
            // button then keeps its fixed 12px inset on the pixels themselves.
            <dialog id="issue-lb" class="vb-issue-lightbox" aria-label="Screenshot">
                <form method="dialog" class="vb-issue-lightbox-dismiss">
                    <button
                        type="submit"
                        class="vb-issue-lightbox-backdrop"
                        tabindex="-1"
                        aria-label="Close screenshot"
                    ></button>
                </form>
                <form method="dialog" class="vb-issue-lightbox-figure">
                    <img
                        id="issue-lb-img"
                        class="vb-issue-lightbox-img"
                        alt="Issue screenshot"
                        @load="(e) => { const img = e.current_target.inner; const fig = img.closest('.vb-issue-lightbox-figure'); if (!fig) return; const fit = () => { fig.style.width = ''; fig.style.height = ''; const r = img.getBoundingClientRect(); if (r.width > 0 && r.height > 0) { fig.style.width = r.width + 'px'; fig.style.height = r.height + 'px'; fig.classList.toggle('is-tiny', r.width < 220 || r.height < 160); } fig.classList.add('is-fit'); }; fit(); if (!img.vcpFitBound) { img.vcpFitBound = true; window.addEventListener('resize', fit); } }"
                    >
                    <button
                        type="submit"
                        class="vb-issue-lightbox-close"
                        aria-label="Close screenshot"
                    >
                        "×"
                    </button>
                </form>
            </dialog>
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ISSUE_ATTACHMENT_OPENER_COMMENT_ID;

    fn attachment(comment_id: u64, image_id: &str) -> IssueAttachment {
        IssueAttachment {
            id: 0,
            issue_id: 7,
            organization_id: 3,
            issue_comment_id: comment_id,
            image_id: image_id.to_owned(),
            ext: "png".to_owned(),
            uploaded_by_user_id: 1,
            created_at: 0,
            sort_order: 0,
        }
    }

    #[test]
    fn thumbs_stay_in_their_own_bubble() {
        let rows = [
            attachment(ISSUE_ATTACHMENT_OPENER_COMMENT_ID, "aaa"),
            attachment(42, "bbb"),
            attachment(42, "ccc"),
        ];
        assert_eq!(
            thumbs_for_comment("acme", &rows, ISSUE_ATTACHMENT_OPENER_COMMENT_ID).len(),
            1
        );
        assert_eq!(thumbs_for_comment("acme", &rows, 42).len(), 2);
        assert!(thumbs_for_comment("acme", &rows, 99).is_empty());
    }

    #[test]
    fn thumbs_expose_first_party_sources() {
        let rows = [attachment(42, "bbb")];
        let thumbs = thumbs_for_comment("acme", &rows, 42);
        // The lightbox copies this into `data-src` then into `img.src`.
        assert_eq!(thumbs[0].src, "/acme/images/bbb.png");
    }
}
