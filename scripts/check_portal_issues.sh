#!/usr/bin/env bash
# Structural invariants for portal issue tracker surface.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() {
  echo "check_portal_issues: $*" >&2
  exit 1
}

LIST="src/app/org/issues.rs"
NEW="src/app/org/issues/new.rs"
DETAIL="src/app/org/issues/issue_key.rs"

[[ -f "$LIST" ]] || fail "missing $LIST"
[[ -f "$NEW" ]] || fail "missing $NEW"
[[ -f "$DETAIL" ]] || fail "missing $DETAIL"

grep -nE '#\[route\(POST' "$LIST" >/dev/null || fail "$LIST must define POST report_issue"
grep -n 'details' "$LIST" >/dev/null || fail "$LIST must persist form details"
grep -n 'store_screenshot_uploads\|attach_many' "$LIST" >/dev/null \
  || fail "$LIST must store/attach screenshots on create"
grep -n 'Multipart' "$LIST" >/dev/null || fail "$LIST report_issue must accept Multipart"

grep -n 'issues_write' "$LIST" >/dev/null || fail "$LIST must gate writes on issues_write"
grep -n 'organization_id' "$LIST" >/dev/null || fail "$LIST must scope issues by organization_id"
grep -n 'allocate_issue_key' "$LIST" >/dev/null \
  || fail "$LIST must allocate keys via allocate_issue_key"
grep -n 'err=create' "$LIST" >/dev/null \
  || fail "$LIST must redirect to err=create on failed create"
if grep -nE 'existing\.len\(\)\s*\+\s*200|len\(\)\s*\+\s*200' "$LIST" >/dev/null 2>&1; then
  fail "$LIST must not forge keys via existing.len() + 200"
fi
if grep -nE 'let _ = toasty::create!\(Issue' "$LIST" >/dev/null 2>&1; then
  fail "$LIST must not swallow create!(Issue) errors"
fi
grep -n 'fn allocate_issue_key' src/issue_key.rs >/dev/null \
  || fail "src/issue_key.rs must define allocate_issue_key"
grep -n 'fn list_for_issue' src/issue_attachments.rs >/dev/null \
  || fail "src/issue_attachments.rs must define list_for_issue"
grep -n 'fn attach_many' src/issue_attachments.rs >/dev/null \
  || fail "src/issue_attachments.rs must define attach_many"
grep -n 'issue_attachment_list_limit\|list_limit' src/issue_attachments.rs >/dev/null \
  || fail "list_for_issue must bound rows via issue_attachment_list_limit"
grep -n 'max_attachments_per_comment' src/config.rs config/default.toml config/vcp.conf >/dev/null \
  || fail "issues.max_attachments_per_comment must be configured"
if grep -nE 'fn unlink_one|attachments/remove' src/issue_attachments.rs src/app/org/issues/issue_key.rs >/dev/null 2>&1; then
  fail "published issue attachments must not expose unlink / remove"
fi
if grep -nE 'StorageObject::all\(\)\s*$|StorageObject::all\(\)\.exec' src/issue_attachments.rs >/dev/null 2>&1; then
  fail "issue_attachments must not scan StorageObject::all()"
fi
grep -n '0014_issue_attachments.sql' toasty/history.toml >/dev/null \
  || fail "toasty/history.toml must list 0014_issue_attachments.sql"
grep -n 'issue_attachments' toasty/migrations/0014_issue_attachments.sql >/dev/null \
  || fail "migration 0014 must create issue_attachments"
grep -n '0009_issue_org_key_unique.sql' toasty/history.toml >/dev/null \
  || fail "toasty/history.toml must list 0009_issue_org_key_unique.sql"
grep -n 'index_issues_by_organization_id_and_key' toasty/migrations/0009_issue_org_key_unique.sql >/dev/null \
  || fail "migration 0009 must create unique (organization_id, key) index"
# Light SSR pagination pin (full pyramid lives on org_issues_search_shard).
grep -n 'page: Option<u32>' "$LIST" >/dev/null || fail "$LIST IssuesQuery must include page: Option<u32>"
grep -n 'filter_row' "$LIST" >/dev/null || fail "$LIST must use filter_row for chips + pager"

grep -n 'method="POST"' "$NEW" >/dev/null || fail "$NEW must POST report form"
grep -n 'name="details"' "$NEW" >/dev/null || fail "$NEW must include details field"
grep -n 'ISSUE_COMPONENTS' "$NEW" >/dev/null \
  || fail "$NEW must render options from ISSUE_COMPONENTS"
if grep -nE 'SSH Proxy|RDP Gateway|Control plane' "$NEW" >/dev/null 2>&1; then
  fail "$NEW must not ship legacy component labels"
fi
grep -n 'fn normalize_issue_component' src/issue_component.rs >/dev/null \
  || fail "src/issue_component.rs must define normalize_issue_component"
grep -n 'Infrastructure' src/issue_component.rs >/dev/null \
  || fail "issue component catalogue must include Infrastructure"
grep -n 'normalize_issue_component' "$LIST" >/dev/null \
  || fail "$LIST must validate component via normalize_issue_component"
grep -n 'enctype="multipart/form-data"' "$NEW" >/dev/null \
  || fail "$NEW must use multipart/form-data for screenshots"
grep -n 'vb-drop' "$NEW" >/dev/null || fail "$NEW must include screenshot dropzone"
grep -n 'shot_file_input\|name="screenshots"' "$NEW" src/app/issue_thumbs.rs >/dev/null \
  || fail "$NEW must include screenshots file input (shot_file_input)"
if grep -nE 'vcp_issue_images\.js|VCP_ISSUE_IMAGES_JS' "$NEW" src/app.rs src/app/issue_thumbs.rs >/dev/null 2>&1; then
  fail "issue compose must not ship first-party vcp_issue_images.js (use Topcoat signals + multipart)"
fi
grep -n 'shot_file_input\|data-shot-preview' "$NEW" >/dev/null \
  || fail "$NEW must wire Topcoat shot_file_input preview"

grep -n 'issue_discussion\|opener_thumbs' "$DETAIL" >/dev/null \
  || fail "$DETAIL must render issue_discussion with comment-linked thumbs"
grep -n 'data-src\|issue-lb' src/app/issue_thumbs.rs >/dev/null \
  || fail "issue_thumbs must drive lightbox via data-src + #issue-lb"
grep -n '<dialog' src/app/issue_thumbs.rs >/dev/null \
  || fail "lightbox must be a native <dialog> (top layer, Escape, focus trap)"
grep -n 'method="dialog"' src/app/issue_thumbs.rs >/dev/null \
  || fail "lightbox dismiss must be a method=\"dialog\" submit (closes without JS)"
# Topcoat string handlers receive the Event wrapper: camelCase DOM methods
# throw and abort hydration of the remaining attributes.
if grep -nE 'preventDefault|stopPropagation' src/app/issue_thumbs.rs >/dev/null 2>&1; then
  fail "Topcoat handlers must use prevent_default/stop_propagation, not camelCase DOM methods"
fi
# Close button must live in the figure so it tracks the image corner.
if awk '/class="vb-issue-lightbox-figure"/,/<\/form>/' src/app/issue_thumbs.rs \
  | grep -q 'vb-issue-lightbox-close'; then
  :
else
  fail "lightbox close must sit inside .vb-issue-lightbox-figure (anchored to the image)"
fi
grep -nE '\.vb-issue-lightbox-figure' styles.css >/dev/null \
  || fail "styles.css must define .vb-issue-lightbox-figure"
grep -A3 '\.vb-issue-lightbox-figure {' styles.css | grep -q 'fit-content' \
  || fail ".vb-issue-lightbox-figure must shrink-wrap the image (width: fit-content)"
grep -A2 '\.vb-issue-lightbox-close {' styles.css | grep -qE 'top: [0-9]+px; right: [0-9]+px' \
  || fail ".vb-issue-lightbox-close must overlay the image top-right corner"
grep -A3 '\.vb-issue-lightbox-close {' styles.css | grep -qE 'width: 4[4-9]px|width: [5-9][0-9]px' \
  || fail ".vb-issue-lightbox-close must keep a >=44px touch target"
grep -A4 '\.vb-issue-lightbox-close {' styles.css | grep -qE 'background: rgba\([0-9]+, [0-9]+, [0-9]+, 0\.[0-9]+\)' \
  || fail ".vb-issue-lightbox-close must stay translucent over the screenshot"
# The figure only hugs the image if the image caps are viewport-based (a
# percentage resolves against the shrink-wrapping figure) and if @load pins
# the figure to the measured box.
if grep -n 'max-width: min(100%, 1180px)' styles.css >/dev/null 2>&1; then
  fail "lightbox image caps must be viewport-based (--vb-lb-max-w), not percentages"
fi
grep -n -- '--vb-lb-max-w' styles.css >/dev/null \
  || fail "styles.css must define --vb-lb-max-w / --vb-lb-max-h lightbox caps"
grep -n '@load' src/app/issue_thumbs.rs >/dev/null \
  || fail "lightbox image must bind @load to size the figure to the image"
grep -n 'getBoundingClientRect' src/app/issue_thumbs.rs >/dev/null \
  || fail "lightbox figure must be pinned to the measured image box"
grep -n 'lightbox_step_index\|vcpGallery' src/app/issue_thumbs.rs >/dev/null \
  || fail "lightbox must wrap multi-image strips (lightbox_step_index / vcpGallery)"
grep -n 'issue-lb-prev\|ISSUE_LB_PREV' src/app/issue_thumbs.rs >/dev/null \
  || fail "lightbox must ship prev control for multi-image comments"
grep -n 'issue-lb-next\|ISSUE_LB_NEXT' src/app/issue_thumbs.rs >/dev/null \
  || fail "lightbox must ship next control for multi-image comments"
grep -n 'ArrowLeft\|ArrowRight' src/app/issue_thumbs.rs >/dev/null \
  || fail "lightbox must bind ArrowLeft/ArrowRight for gallery navigation"
grep -nE '\.vb-issue-lightbox-nav' styles.css >/dev/null \
  || fail "styles.css must define .vb-issue-lightbox-nav"
# Nav buttons must not be method=dialog submits (that would close the lightbox).
# `type="button"` sits on the line above `id=(ISSUE_LB_*)` in the view.
grep -n 'vb-issue-lightbox-prev' src/app/issue_thumbs.rs >/dev/null \
  || fail "lightbox must declare vb-issue-lightbox-prev"
grep -n 'vb-issue-lightbox-next' src/app/issue_thumbs.rs >/dev/null \
  || fail "lightbox must declare vb-issue-lightbox-next"
if ! grep -B5 'vb-issue-lightbox-prev' src/app/issue_thumbs.rs | grep -q 'type="button"'; then
  fail "lightbox prev must be type=button (not a dialog dismiss submit)"
fi
if ! grep -B5 'vb-issue-lightbox-next' src/app/issue_thumbs.rs | grep -q 'type="button"'; then
  fail "lightbox next must be type=button (not a dialog dismiss submit)"
fi
# Picking a second image must add to the selection, not replace it.
grep -n 'input.vcpShots' src/app/issue_thumbs.rs >/dev/null \
  || fail "screenshot picker must accumulate picks (input.vcpShots)"
grep -n 'new DataTransfer()' src/app/issue_thumbs.rs >/dev/null \
  || fail "screenshot picker must write the accumulated list back via DataTransfer"
if grep -n 'Array.from(input.files).slice(0, max)' src/app/issue_thumbs.rs >/dev/null 2>&1; then
  fail "screenshot picker must merge with kept files, not slice the fresh FileList"
fi
grep -n 'data-shot-add' src/app/issue_thumbs.rs >/dev/null \
  || fail "screenshot picker must expose data-shot-add (cap state)"
grep -n 'data-shot-status' src/app/issue_thumbs.rs >/dev/null \
  || fail "screenshot picker must expose data-shot-status (live count)"
grep -n 'data-shot-dropzone\|SHOT_DROPZONE' src/app/issue_thumbs.rs >/dev/null \
  || fail "screenshot picker must expose a drag-and-drop dropzone"
grep -n 'SHOT_DROP_JS\|@drop' src/app/issue_thumbs.rs >/dev/null \
  || fail "screenshot picker must handle @drop"
grep -n 'e.inner.dataTransfer' src/app/issue_thumbs.rs >/dev/null \
  || fail "drop handler must read native dataTransfer via e.inner"
grep -n "dispatchEvent(new Event('change'" src/app/issue_thumbs.rs >/dev/null \
  || fail "drop must reuse the @change accumulator via dispatched change"
grep -n 'is-dragover' styles.css >/dev/null \
  || fail "styles.css must highlight is-dragover on the shot picker"
grep -n 'ISSUE_ATTACHMENT_OPENER_COMMENT_ID\|issue_comment_id' "$DETAIL" src/issue_attachments.rs >/dev/null \
  || fail "attachments must link to comment id (or opener sentinel)"
grep -n 'attach_many\|store_screenshot_uploads' "$DETAIL" >/dev/null \
  || fail "$DETAIL reply must store/attach screenshots"
if grep -nE 'attachments/remove|remove_action|unlink_one' "$DETAIL" >/dev/null 2>&1; then
  fail "$DETAIL must not expose attachment remove after publish"
fi
grep -n 'shot_file_input\|name="screenshots"' "$DETAIL" src/app/issue_thumbs.rs >/dev/null \
  || fail "$DETAIL must wire reply file input"
grep -n 'vb-drop-inline' "$DETAIL" >/dev/null \
  || fail "$DETAIL reply must wrap the picker in vb-drop-inline (visible dropzone)"
grep -n 'enctype="multipart/form-data"' "$DETAIL" >/dev/null \
  || fail "$DETAIL reply form must be multipart"
grep -n 'shot_file_input\|data-shot-preview' "$DETAIL" >/dev/null \
  || fail "$DETAIL reply must wire Topcoat screenshot preview"
# File input / shot_file_input must live inside the reply form.
if awk '/id=\(ISSUE_REPLY_ANCHOR\)/,/<\/form>/' "$DETAIL" | grep -qE 'name="screenshots"|shot_file_input'; then
  :
else
  fail "$DETAIL screenshots input must be inside #issue-reply form"
fi
grep -n 'issues_read' "$DETAIL" >/dev/null || fail "$DETAIL must gate on issues_read"
grep -n 'organization_id' "$DETAIL" >/dev/null || fail "$DETAIL must scope by organization_id"

grep -n 'IssueComment' "$DETAIL" >/dev/null \
  || fail "$DETAIL must load IssueComment timeline from DB"
grep -nE '#\[route\(POST|/reply' "$DETAIL" >/dev/null \
  || fail "$DETAIL must expose POST reply route"
grep -nE '#\[route\(POST "/\{org\}/issues/\{issue_key\}/close"\)' "$DETAIL" >/dev/null \
  || fail "$DETAIL must expose POST close route"
grep -nE '#\[route\(POST "/\{org\}/issues/\{issue_key\}/reopen"\)' "$DETAIL" >/dev/null \
  || fail "$DETAIL must expose POST reopen route"
grep -n 'issue_is_closed' "$DETAIL" >/dev/null \
  || fail "$DETAIL must use issue_is_closed"
grep -n 'advance_issue_with_retry' "$DETAIL" >/dev/null \
  || fail "$DETAIL must advance status via advance_issue_with_retry"
grep -n 'IssueEvent::Close\|IssueEvent::Reopen' "$DETAIL" >/dev/null \
  || fail "$DETAIL must use IssueEvent for close/reopen"
# Close/Reopen must be real forms, not Concept stub spans.
if grep -nE '<span class="vb-btn[^"]*">"Close issue"|<span class="vb-btn[^"]*">"Reopen issue"' "$DETAIL" >/dev/null 2>&1; then
  fail "$DETAIL must not stub Close/Reopen as non-submitting spans"
fi
grep -n 'opened_by_user_id' "$LIST" >/dev/null \
  || fail "$LIST must persist opened_by_user_id on create"
grep -n 'struct IssueComment' src/models/mod.rs >/dev/null \
  || fail "models must define IssueComment"
grep -n 'ISSUE_STATUS_CLOSED' src/models/mod.rs >/dev/null \
  || fail "models must define ISSUE_STATUS_CLOSED"
grep -n 'ISSUE_STATUS_OPEN' src/models/mod.rs >/dev/null \
  || fail "models must define ISSUE_STATUS_OPEN"
grep -n 'fn issue_is_closed' src/issue_status.rs >/dev/null \
  || fail "issue_status.rs must define issue_is_closed"
grep -n 'ISSUE_COMMENT_KIND_STATUS' src/issue_status.rs >/dev/null \
  || fail "close/reopen must write ISSUE_COMMENT_KIND_STATUS timeline rows"

# Support-side timeline authors must display as Vauban Support.
grep -n 'Vauban Support' "$DETAIL" >/dev/null \
  || fail "$DETAIL must label support-side authors as Vauban Support"

# No hardcodéd Concept relative-date fixtures.
if grep -nE '"3h ago"|"Jun 20"|"Jun 23"' "$DETAIL" "$LIST" src/app/org.rs >/dev/null 2>&1; then
  fail "issue/dashboard UI must not hardcode relative-date fixtures"
fi

ADMIN_LIST="src/app/admin/issues.rs"
ADMIN_DETAIL="src/app/admin/issues/issue_key.rs"
[[ -f "$ADMIN_LIST" ]] || fail "missing $ADMIN_LIST"
[[ -f "$ADMIN_DETAIL" ]] || fail "missing $ADMIN_DETAIL"
grep -n 'require_staff' "$ADMIN_LIST" >/dev/null || fail "$ADMIN_LIST must gate with require_staff"
grep -n 'issues_read' "$ADMIN_LIST" >/dev/null || fail "$ADMIN_LIST must gate on issues_read"
grep -n 'Vauban Support' "$ADMIN_DETAIL" >/dev/null \
  || fail "$ADMIN_DETAIL must label support-side authors as Vauban Support"
grep -nE '#\[route\(POST|/reply' "$ADMIN_DETAIL" >/dev/null \
  || fail "$ADMIN_DETAIL must expose POST reply route"
grep -n 'issue_discussion\|opener_thumbs\|list_for_issue' "$ADMIN_DETAIL" >/dev/null \
  || fail "$ADMIN_DETAIL must render issue_discussion with attachments"
grep -n 'shot_file_input\|data-shot-preview' "$ADMIN_DETAIL" >/dev/null \
  || fail "$ADMIN_DETAIL reply must wire Topcoat screenshot preview"
grep -n 'vb-drop-inline' "$ADMIN_DETAIL" >/dev/null \
  || fail "$ADMIN_DETAIL reply must wrap the picker in vb-drop-inline"
grep -n 'vb-drop-inline' styles.css >/dev/null \
  || fail "styles.css must define vb-drop-inline for the reply dropzone"
grep -nE '#\[route\(POST "/admin/issues/\{issue_key\}/close"\)' "$ADMIN_DETAIL" >/dev/null \
  || fail "$ADMIN_DETAIL must expose POST close route"
grep -nE '#\[route\(POST "/admin/issues/\{issue_key\}/reopen"\)' "$ADMIN_DETAIL" >/dev/null \
  || fail "$ADMIN_DETAIL must expose POST reopen route"
grep -nE '#\[route\(POST "/admin/issues/\{issue_key\}/start-analysis"\)' "$ADMIN_DETAIL" >/dev/null \
  || fail "$ADMIN_DETAIL must expose POST start-analysis route"
grep -nE '#\[route\(POST "/admin/issues/\{issue_key\}/resolve"\)' "$ADMIN_DETAIL" >/dev/null \
  || fail "$ADMIN_DETAIL must expose POST resolve route"
grep -n 'advance_issue_with_retry' "$ADMIN_DETAIL" >/dev/null \
  || fail "$ADMIN_DETAIL must advance status via advance_issue_with_retry"
grep -n 'issue_is_closed' "$ADMIN_DETAIL" >/dev/null \
  || fail "$ADMIN_DETAIL must use issue_is_closed"
# Org surface must not expose staff-only lifecycle routes.
if grep -nE 'start-analysis|/resolve"' "$DETAIL" >/dev/null 2>&1; then
  fail "$DETAIL must not expose start-analysis / resolve (admin-only)"
fi
grep -n '#\[version\]' src/models/mod.rs >/dev/null \
  || fail "Issue.version must use Toasty #[version]"
grep -n '0016_issue_version.sql' toasty/history.toml >/dev/null \
  || fail "toasty/history.toml must list 0016_issue_version.sql"
grep -n 'fn transition' src/issue_fsm.rs >/dev/null \
  || fail "issue_fsm.rs must define transition"
if grep -nE 'use toasty|use topcoat|sqlx' src/issue_fsm.rs >/dev/null 2>&1; then
  fail "issue_fsm.rs must stay free of toasty/topcoat/sqlx imports"
fi
if grep -nE 'user_role|PermissionContext|portal_role' src/issue_fsm.rs >/dev/null 2>&1; then
  fail "issue_fsm.rs must not take role / PermissionContext (ADR 005)"
fi
if grep -nE 'sqlx' src/issue_status.rs >/dev/null 2>&1; then
  fail "issue_status.rs must use Toasty #[version] OCC, not sqlx"
fi
grep -n 'is_condition_failed\|#\[version\]' src/issue_status.rs docs/adr/006-issue-status-optimistic-locking.md >/dev/null \
  || fail "OCC must document/use Toasty condition_failed / #[version]"
grep -n 'ISSUE_ROLE_SUPPORT' "$ADMIN_DETAIL" >/dev/null \
  || fail "$ADMIN_DETAIL staff replies must use ISSUE_ROLE_SUPPORT"
if grep -nE '<span class="vb-btn[^"]*">"Close issue"|<span class="vb-btn[^"]*">"Reopen issue"' "$ADMIN_DETAIL" >/dev/null 2>&1; then
  fail "$ADMIN_DETAIL must not stub Close/Reopen as non-submitting spans"
fi

# Full-bleed content (same as lists / admin docs compose).
if grep -nE 'max-width:\s*(720|820)px' "$DETAIL" "$NEW" "$ADMIN_DETAIL" >/dev/null 2>&1; then
  fail "issue compose/detail must not constrain content width (Concept full width)"
fi

# Meta strip: admin has 5 cells (incl. ORGANIZATION); fixed 4-col grids orphan UPDATED.
grep -A4 '\.vb-meta-grid {' styles.css | grep -q 'auto-fit' \
  || fail "styles.css .vb-meta-grid must use auto-fit so UPDATED stays on one row"

# Post-action redirects must land on the reply box. The portal scrolls inside
# .vb-scroll, not the window, so only a fragment brings the newest message
# into view after the 303.
ANCHOR="src/issue_anchor.rs"
[[ -f "$ANCHOR" ]] || fail "missing $ANCHOR"
grep -n 'ISSUE_REPLY_ANCHOR: &str = "issue-reply"' "$ANCHOR" >/dev/null \
  || fail "$ANCHOR must pin the reply anchor id"
grep -n 'fn with_reply_anchor' "$ANCHOR" >/dev/null \
  || fail "$ANCHOR must expose with_reply_anchor"
for f in "$DETAIL" "$ADMIN_DETAIL"; do
  grep -n 'with_reply_anchor' "$f" >/dev/null \
    || fail "$f post-action redirects must go through with_reply_anchor"
  grep -n 'id=(ISSUE_REPLY_ANCHOR)' "$f" >/dev/null \
    || fail "$f must anchor the reply box on ISSUE_REPLY_ANCHOR"
  # Resolved/Closed panels drop the reply form: they must carry the same
  # anchor id, otherwise close/reopen redirects resolve to nothing.
  grep -n 'id=(ISSUE_REPLY_ANCHOR)' "$f" >/dev/null \
    || fail "$f must anchor reply / resolved / closed panels on ISSUE_REPLY_ANCHOR"
  grep -n 'is_resolved\|is_closed' "$f" >/dev/null \
    || fail "$f must split Resolved vs Closed UI (is_resolved / is_closed)"
  if grep -nE 'see_other\(&format!\("/\{org_slug\}/issues/\{key\}' "$f" >/dev/null 2>&1; then
    fail "$f must not redirect to an unanchored detail URL"
  fi
done
grep -n 'fn admin_reply_target' "$ADMIN_DETAIL" >/dev/null \
  || fail "$ADMIN_DETAIL must build post-action targets via admin_reply_target"
# Plain list / navigation links stay anchor-free.
if grep -n 'with_reply_anchor' src/app/admin/issues/search_shard.rs >/dev/null 2>&1; then
  fail "list hrefs must not carry the reply anchor"
fi

echo "check_portal_issues: OK"
