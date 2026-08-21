//! Issue screenshot thumbs + lightbox (no first-party JS asset).
//!
//! - Liaisons comment ↔ image: Postgres (`issue_attachments.issue_comment_id`).
//! - Lightbox: Topcoat `@click` string handlers read `data-src` (works inside
//!   `for` loops; no loop-capture into `$()` closures). Multi-image strips
//!   share one dialog; prev/next (+ arrow keys) walk siblings in the same
//!   `.vb-issue-thumbs` with wrap-around.
//! - Pre-submit previews: Topcoat `@change` function handler (File API).
//! - Drag-and-drop: `@dragover` / `@drop` on the picker feed the same
//!   `@change` accumulator (`vcpShots`) — no separate upload path.
//! - Published attachments are not removable from the portal UI.

use topcoat::{
    Result,
    context::Cx,
    view::{component, view},
};

use crate::{
    app::_components::docs_formatted_body,
    docs_body::DIALECT_HINT,
    issue_attachments::{attachment_cap_hint, gallery_src},
    models::{ISSUE_COMMENT_KIND_STATUS, IssueAttachment},
};

/// Lightbox prev control id (also used by keyboard ArrowLeft).
pub const ISSUE_LB_PREV: &str = "issue-lb-prev";
/// Lightbox next control id (also used by keyboard ArrowRight).
pub const ISSUE_LB_NEXT: &str = "issue-lb-next";

/// Wrap-around index for multi-image lightbox navigation.
///
/// Returns `None` when there are fewer than two images (nav is a no-op).
/// Otherwise applies `step` and wraps into `0..len`.
pub fn lightbox_step_index(index: usize, len: usize, step: i32) -> Option<usize> {
    if len < 2 {
        return None;
    }
    let n = len as i64;
    let i = index as i64 + i64::from(step);
    Some((((i % n) + n) % n) as usize)
}

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
    pub comment_id: u64,
    /// Show Edit on Support comments (`/admin/issues` only).
    pub can_edit: bool,
    pub editing: bool,
    pub edit_href: String,
    pub edit_action: String,
    pub edit_cancel: String,
    /// Non-empty when the body was edited after create.
    pub edited_label: String,
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

/// Marker: picker accepts OS drag-and-drop (compose + reply).
pub const SHOT_DROPZONE: &str = "data-shot-dropzone";

/// `@dragover` — allow drop + highlight (Topcoat Event: `prevent_default`,
/// native `dataTransfer` via `e.inner`). Must match the attribute literal.
pub const SHOT_DRAGOVER_JS: &str = "(e) => { e.prevent_default(); e.stop_propagation(); const picker = e.current_target.inner; picker.classList.add('is-dragover'); const dt = e.inner && e.inner.dataTransfer; if (dt) dt.dropEffect = 'copy'; }";

/// `@dragleave` — clear highlight when the pointer leaves the picker.
pub const SHOT_DRAGLEAVE_JS: &str = "(e) => { e.prevent_default(); const picker = e.current_target.inner; const related = e.inner && e.inner.relatedTarget; if (related && picker.contains(related)) return; picker.classList.remove('is-dragover'); }";

/// `@drop` — feed dropped files into the file input and reuse `@change`.
pub const SHOT_DROP_JS: &str = "(e) => { e.prevent_default(); e.stop_propagation(); const picker = e.current_target.inner; picker.classList.remove('is-dragover'); const input = picker.querySelector('input.vb-shot-input'); const nativeDt = e.inner && e.inner.dataTransfer; if (!input || !nativeDt) return; try { const dt = new DataTransfer(); Array.from(nativeDt.files || []).forEach((f) => dt.items.add(f)); input.files = dt.files; } catch (_err) { return; } input.dispatchEvent(new Event('change', { bubbles: true })); }";

/// Hidden file input + preview host (`@change` function expression).
///
/// `max` is `[issues].max_attachments_per_comment` (also enforced server-side).
///
/// A native `multiple` input **replaces** its `FileList` on every pick, so a
/// second trip to the file dialog would silently drop the first screenshot.
/// The handler therefore keeps its own accumulated list on the input
/// (`vcpShots`) and writes it back through a `DataTransfer` — picking one image
/// at a time still fills the whole per-message cap.
///
/// Drag-and-drop uses the same accumulator: `@drop` assigns `input.files` and
/// dispatches `change` so browse and drop stay on one code path.
#[component]
pub async fn shot_file_input(cx: &Cx, label: Result, max: usize) -> Result {
    let _pin = SHOT_PREVIEW_CHANGE;
    let _drop_pin = SHOT_DROPZONE;
    // Reachable so `-D dead_code` keeps the handler contracts next to the view.
    let _handlers = (SHOT_DRAGOVER_JS, SHOT_DRAGLEAVE_JS, SHOT_DROP_JS);
    let max = max.max(1);
    let max_attr = max.to_string();
    let hint = attachment_cap_hint(max);
    // Raw JS string attributes (Topcoat Expr); keep in sync with SHOT_*_JS.
    view! {
        cx =>
        <div
            class="vb-shot-picker"
            data-shot-dropzone=""
            @dragover="(e) => { e.prevent_default(); e.stop_propagation(); const picker = e.current_target.inner; picker.classList.add('is-dragover'); const dt = e.inner && e.inner.dataTransfer; if (dt) dt.dropEffect = 'copy'; }"
            @dragleave="(e) => { e.prevent_default(); const picker = e.current_target.inner; const related = e.inner && e.inner.relatedTarget; if (related && picker.contains(related)) return; picker.classList.remove('is-dragover'); }"
            @drop="(e) => { e.prevent_default(); e.stop_propagation(); const picker = e.current_target.inner; picker.classList.remove('is-dragover'); const input = picker.querySelector('input.vb-shot-input'); const nativeDt = e.inner && e.inner.dataTransfer; if (!input || !nativeDt) return; try { const dt = new DataTransfer(); Array.from(nativeDt.files || []).forEach((f) => dt.items.add(f)); input.files = dt.files; } catch (_err) { return; } input.dispatchEvent(new Event('change', { bubbles: true })); }"
        >
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
            <span style="display:none" aria-hidden="true">(_drop_pin)</span>
        </div>
    }
}

#[cfg(test)]
mod shot_drop_tests {
    use super::*;

    #[test]
    fn drop_handler_contract_and_wiring() {
        for js in [SHOT_DRAGOVER_JS, SHOT_DRAGLEAVE_JS, SHOT_DROP_JS] {
            let trimmed = js.trim_start();
            assert!(
                trimmed.starts_with("(e) =>") || trimmed.starts_with("() =>"),
                "must be a JS function expression: {js}"
            );
            assert!(js.contains("prevent_default"));
        }
        assert!(SHOT_DROP_JS.contains("e.inner.dataTransfer"));
        assert!(SHOT_DROP_JS.contains("input.vb-shot-input"));
        assert!(SHOT_DROP_JS.contains("dispatchEvent(new Event('change'"));
        assert!(SHOT_DRAGOVER_JS.contains("is-dragover"));
        assert_eq!(SHOT_DROPZONE, "data-shot-dropzone");

        // Attribute literals in `shot_file_input` must stay aligned with the
        // documented handler constants (Topcoat needs string attrs for Expr).
        let src = include_str!("issue_thumbs.rs");
        for (name, js) in [
            ("dragover", SHOT_DRAGOVER_JS),
            ("dragleave", SHOT_DRAGLEAVE_JS),
            ("drop", SHOT_DROP_JS),
        ] {
            let hits = src.matches(js).count();
            assert!(
                hits >= 2,
                "{name} handler must appear as const + view! attribute (hits={hits})"
            );
        }
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
                                        @click="(e) => { const btn = e.current_target.inner; const src = btn.getAttribute('data-src'); const box = document.getElementById('issue-lb'); const img = document.getElementById('issue-lb-img'); if (!src || !box || !img) return; const strip = btn.closest('.vb-issue-thumbs'); const buttons = strip ? Array.from(strip.querySelectorAll('.vb-issue-thumb[data-src]')) : [btn]; const srcs = buttons.map((b) => b.getAttribute('data-src')).filter((s) => !!s); let idx = srcs.indexOf(src); if (idx < 0) idx = 0; box.vcpGallery = srcs; box.vcpIndex = idx; const multi = srcs.length > 1; const prev = document.getElementById('issue-lb-prev'); const next = document.getElementById('issue-lb-next'); if (prev) { prev.hidden = !multi; } if (next) { next.hidden = !multi; } const fig = img.closest('.vb-issue-lightbox-figure'); if (fig) { fig.classList.remove('is-fit'); fig.style.width = ''; fig.style.height = ''; } if (!box.open) { if (typeof box.showModal === 'function') { box.showModal(); } else { box.setAttribute('open', ''); } } if (img.getAttribute('src') !== src) { img.setAttribute('src', src); } else if (img.complete) { img.dispatchEvent(new Event('load')); } }"
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
                    let comment_anchor = if row.comment_id > 0 {
                        format!("comment-{}", row.comment_id)
                    } else {
                        String::new()
                    };
                    <div style=(align) id=(comment_anchor)>
                        <div class=(bubble_class)>
                            <div
                                style="display: flex; align-items: center; gap: 8px; margin-bottom: 6px; flex-wrap: wrap;"
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
                                if row.can_edit && !row.editing {
                                    <a
                                        class="vb-mono"
                                        href=(row.edit_href.clone())
                                        style="font-size: 10px; color: var(--accent); text-decoration: none;"
                                    >
                                        "Edit"
                                    </a>
                                }
                            </div>
                            if row.editing {
                                <form method="POST" action=(row.edit_action.clone())>
                                    <input
                                        type="hidden"
                                        name="comment_id"
                                        value=(row.comment_id.to_string())
                                    >
                                    <textarea
                                        name="body"
                                        required=""
                                        style="width: 100%; min-height: 76px; font-size: 13.5px; padding: 10px 12px; border: 1px solid #e0e2de; border-radius: 4px; background: #fbfcfb; resize: vertical; font-family: 'Hanken Grotesk', sans-serif; line-height: 1.5; margin-bottom: 10px;"
                                    >
                                        (row.body.clone())
                                    </textarea>
                                    <p class="vb-form-hint">(DIALECT_HINT)</p>
                                    <div
                                        style="display: flex; gap: 10px; justify-content: flex-end;"
                                    >
                                        <a class="vb-btn muted" href=(row.edit_cancel.clone())>
                                            "Cancel"
                                        </a>
                                        <button class="vb-btn" type="submit">"Save"</button>
                                    </div>
                                </form>
                            } else {
                                <div
                                    class="vb-issue-prose"
                                    style="font-size: 13.5px; line-height: 1.55; color: #3a3f46;"
                                >
                                    docs_formatted_body(body: &row.body)
                                </div>
                                if !row.edited_label.is_empty() {
                                    <div
                                        class="vb-mono"
                                        style="font-size: 10px; color: #9aa0a6; margin-top: 6px;"
                                    >
                                        (format!(
                                            "Edited · {}", row.edited_label.clone()
                                        ))
                                    </div>
                                }
                            }
                            if !row.thumbs.is_empty() {
                                <div class="vb-issue-thumbs">
                                    for thumb in row.thumbs.clone() {
                                        <div class="vb-issue-thumb-wrap">
                                            <button
                                                type="button"
                                                class="vb-issue-thumb"
                                                aria-label="Open screenshot"
                                                data-src=(thumb.src.clone())
                                                @click="(e) => { const btn = e.current_target.inner; const src = btn.getAttribute('data-src'); const box = document.getElementById('issue-lb'); const img = document.getElementById('issue-lb-img'); if (!src || !box || !img) return; const strip = btn.closest('.vb-issue-thumbs'); const buttons = strip ? Array.from(strip.querySelectorAll('.vb-issue-thumb[data-src]')) : [btn]; const srcs = buttons.map((b) => b.getAttribute('data-src')).filter((s) => !!s); let idx = srcs.indexOf(src); if (idx < 0) idx = 0; box.vcpGallery = srcs; box.vcpIndex = idx; const multi = srcs.length > 1; const prev = document.getElementById('issue-lb-prev'); const next = document.getElementById('issue-lb-next'); if (prev) { prev.hidden = !multi; } if (next) { next.hidden = !multi; } const fig = img.closest('.vb-issue-lightbox-figure'); if (fig) { fig.classList.remove('is-fit'); fig.style.width = ''; fig.style.height = ''; } if (!box.open) { if (typeof box.showModal === 'function') { box.showModal(); } else { box.setAttribute('open', ''); } } if (img.getAttribute('src') !== src) { img.setAttribute('src', src); } else if (img.complete) { img.dispatchEvent(new Event('load')); } }"
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
            // Prev/next are type=button (not method=dialog) and start hidden;
            // the open handler reveals them only when the strip has 2+ images.
            <dialog
                id="issue-lb"
                class="vb-issue-lightbox"
                aria-label="Screenshot"
                @keydown="(e) => { const key = e.inner.key; if (key !== 'ArrowLeft' && key !== 'ArrowRight') return; const id = key === 'ArrowLeft' ? 'issue-lb-prev' : 'issue-lb-next'; const nav = document.getElementById(id); if (!nav || nav.hidden) return; nav.click(); }"
            >
                <form method="dialog" class="vb-issue-lightbox-dismiss">
                    <button
                        type="submit"
                        class="vb-issue-lightbox-backdrop"
                        tabindex="-1"
                        aria-label="Close screenshot"
                    ></button>
                </form>
                <button
                    type="button"
                    id=(ISSUE_LB_PREV)
                    class="vb-issue-lightbox-nav vb-issue-lightbox-prev"
                    data-step="-1"
                    hidden=""
                    aria-label="Previous screenshot"
                    @click="(e) => { const stepBtn = e.current_target.inner; const box = document.getElementById('issue-lb'); const img = document.getElementById('issue-lb-img'); if (!box || !img) return; const srcs = box.vcpGallery; if (!srcs || srcs.length < 2) return; const step = parseInt(stepBtn.getAttribute('data-step') || '0', 10) || 0; const n = srcs.length; let i = (typeof box.vcpIndex === 'number' ? box.vcpIndex : 0) + step; i = ((i % n) + n) % n; box.vcpIndex = i; const src = srcs[i]; if (!src) return; const fig = img.closest('.vb-issue-lightbox-figure'); if (fig) { fig.classList.remove('is-fit'); fig.style.width = ''; fig.style.height = ''; } if (img.getAttribute('src') !== src) { img.setAttribute('src', src); } else if (img.complete) { img.dispatchEvent(new Event('load')); } }"
                >
                    "‹"
                </button>
                <button
                    type="button"
                    id=(ISSUE_LB_NEXT)
                    class="vb-issue-lightbox-nav vb-issue-lightbox-next"
                    data-step="1"
                    hidden=""
                    aria-label="Next screenshot"
                    @click="(e) => { const stepBtn = e.current_target.inner; const box = document.getElementById('issue-lb'); const img = document.getElementById('issue-lb-img'); if (!box || !img) return; const srcs = box.vcpGallery; if (!srcs || srcs.length < 2) return; const step = parseInt(stepBtn.getAttribute('data-step') || '0', 10) || 0; const n = srcs.length; let i = (typeof box.vcpIndex === 'number' ? box.vcpIndex : 0) + step; i = ((i % n) + n) % n; box.vcpIndex = i; const src = srcs[i]; if (!src) return; const fig = img.closest('.vb-issue-lightbox-figure'); if (fig) { fig.classList.remove('is-fit'); fig.style.width = ''; fig.style.height = ''; } if (img.getAttribute('src') !== src) { img.setAttribute('src', src); } else if (img.complete) { img.dispatchEvent(new Event('load')); } }"
                >
                    "›"
                </button>
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

    #[test]
    fn lightbox_step_wraps_at_ends() {
        assert_eq!(lightbox_step_index(0, 3, -1), Some(2));
        assert_eq!(lightbox_step_index(2, 3, 1), Some(0));
        assert_eq!(lightbox_step_index(1, 3, 1), Some(2));
        assert_eq!(lightbox_step_index(1, 3, -1), Some(0));
    }

    #[test]
    fn lightbox_step_disabled_for_single_or_empty() {
        assert_eq!(lightbox_step_index(0, 0, 1), None);
        assert_eq!(lightbox_step_index(0, 1, 1), None);
        assert_eq!(lightbox_step_index(0, 1, -1), None);
    }

    #[test]
    fn lightbox_nav_ids_are_stable() {
        assert_eq!(ISSUE_LB_PREV, "issue-lb-prev");
        assert_eq!(ISSUE_LB_NEXT, "issue-lb-next");
    }
}
