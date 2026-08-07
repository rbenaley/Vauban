#!/usr/bin/env bash
# Structural invariants for admin release manager surface.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() {
  echo "check_admin_releases: $*" >&2
  exit 1
}

NEW="src/app/admin/releases/new.rs"
LIST="src/app/admin/releases.rs"
EDIT="src/app/admin/releases/release_id.rs"
STAGING="src/app/admin/releases/staging.rs"
CONFIRM="src/app/admin/releases/confirm.rs"
UI="src/ui.rs"
CSS="styles.css"

[[ -f "$NEW" ]] || fail "missing $NEW"
[[ -f "$EDIT" ]] || fail "missing $EDIT"
[[ -f "$STAGING" ]] || fail "missing $STAGING"
[[ -f "$CONFIRM" ]] || fail "missing $CONFIRM"

grep -n 'method="POST"' "$NEW" >/dev/null || fail "$NEW must POST compose form"
grep -n 'enctype="multipart/form-data"' "$NEW" >/dev/null \
  || fail "$NEW must use multipart/form-data for package upload"
grep -n 'name="package"' "$NEW" >/dev/null || fail "$NEW must include package file input"
grep -nE '#\[route\(POST' "$NEW" >/dev/null || fail "$NEW must define POST create route"
grep -n 'Multipart' "$NEW" >/dev/null || fail "$NEW must parse Multipart on create"
grep -n 'releases_manage' "$NEW" >/dev/null || fail "$NEW must gate on releases_manage"
grep -n 'toasty::create!(Release' "$NEW" >/dev/null || fail "$NEW must create Release rows"
grep -n 'RELEASE_STATUS_STAGING' "$NEW" >/dev/null \
  || fail "$NEW must create as RELEASE_STATUS_STAGING until the ceremony commits"
if grep -n 'RELEASE_STATUS_HIDDEN' "$NEW" >/dev/null; then
  fail "$NEW must not create HIDDEN rows (an unfinished publish is rolled back)"
fi
grep -n 'RELEASE_STATUS_PUBLISHED' "$NEW" >/dev/null \
  || fail "$NEW must publish as RELEASE_STATUS_PUBLISHED after package"
grep -n 'upsert_release_object' "$NEW" >/dev/null \
  || fail "$NEW must upsert storage_objects after package commit"
grep -n 'rollback_staged_release' "$NEW" >/dev/null \
  || fail "$NEW must roll back the staged row on every failed upload path"
grep -n 'sweep_staged_releases' "$NEW" >/dev/null \
  || fail "$NEW must sweep abandoned ceremonies before staging a new one"
grep -nE 'name="package" type="file" required=""' "$NEW" >/dev/null \
  || fail "$NEW package input must be required (no release without a binary)"
grep -n 'err=package' "$NEW" >/dev/null \
  || fail "$NEW must refuse a create without a package"
grep -n 'freebsd_pkg::inspect' "$NEW" >/dev/null \
  || fail "$NEW must inspect FreeBSD packages before staging"
grep -n 'err=not_pkg' "$NEW" >/dev/null \
  || fail "$NEW must refuse non-FreeBSD packages with err=not_pkg"
# Gate must run before the STAGING insert / put_begin (fail closed, no row).
# Match the create site (`status: RELEASE_STATUS_STAGING`), not the import.
INSPECT_LINE="$(grep -n 'freebsd_pkg::inspect' "$NEW" | head -1 | cut -d: -f1)"
STAGING_LINE="$(grep -n 'status: RELEASE_STATUS_STAGING' "$NEW" | head -1 | cut -d: -f1)"
PUT_BEGIN_LINE="$(grep -n 'put_begin_release' "$NEW" | head -1 | cut -d: -f1)"
[[ -n "$INSPECT_LINE" && -n "$STAGING_LINE" && -n "$PUT_BEGIN_LINE" ]] \
  || fail "$NEW must contain inspect, STAGING create, and put_begin"
[[ "$INSPECT_LINE" -lt "$STAGING_LINE" && "$INSPECT_LINE" -lt "$PUT_BEGIN_LINE" ]] \
  || fail "$NEW must call freebsd_pkg::inspect before STAGING/put_begin"

PKG_MOD="src/freebsd_pkg.rs"
[[ -f "$PKG_MOD" ]] || fail "missing $PKG_MOD"
grep -n 'pub fn inspect' "$PKG_MOD" >/dev/null \
  || fail "$PKG_MOD must export inspect"
grep -n 'pub fn format_pkg_info' "$PKG_MOD" >/dev/null \
  || fail "$PKG_MOD must export format_pkg_info"
grep -n 'pub fn craft_minimal_pkg\|pub fn craft_test_vauban_pkg' "$PKG_MOD" >/dev/null \
  || fail "$PKG_MOD must expose craft helpers for tests"
# No shell-out to pkg(8) / pkg-static.
if grep -nE 'Command::new\("(pkg|pkg-static)"\)|std::process::Command' "$PKG_MOD" >/dev/null; then
  fail "$PKG_MOD must not shell out to pkg(8)"
fi
for dep in tar zstd xz2 flate2 bzip2; do
  grep -nE "^${dep}( |=)" Cargo.toml >/dev/null \
    || fail "Cargo.toml must depend on ${dep} for pkg parsing"
done

grep -n 'format_pkg_info' "$CONFIRM" >/dev/null \
  || fail "$CONFIRM must render format_pkg_info"
grep -n 'vcp-pkg-info' "$CONFIRM" >/dev/null \
  || fail "$CONFIRM must expose #vcp-pkg-info for the package summary"
grep -n 'pkg_info' "$NEW" >/dev/null \
  || fail "$NEW must stash pkg_info on the pending ceremony"

grep -n 'rollback_staged_release' "$STAGING" >/dev/null \
  || fail "$STAGING must define rollback_staged_release"
grep -n 'orphan_staged_ids' "$STAGING" >/dev/null \
  || fail "$STAGING must derive orphans from live reservations"
grep -nE '#\[route\(POST "/admin/releases/confirm/cancel"\)' "$CONFIRM" >/dev/null \
  || fail "$CONFIRM must offer an explicit cancel route"
grep -n 'rollback_staged_release' "$CONFIRM" >/dev/null \
  || fail "$CONFIRM must roll back when the signature does not commit"
grep -n 'find_release_object' "$EDIT" >/dev/null \
  || fail "$EDIT must require storage row before publish"
grep -n 'delete_release' "$EDIT" >/dev/null \
  || fail "$EDIT must delete helper blob on release delete"
grep -n 'method="GET"' "$NEW" >/dev/null && fail "$NEW must not use method=GET on compose form"
if grep -nE 'max-width:\s*(720|820)px' "$NEW" >/dev/null 2>&1; then
  fail "$NEW must not constrain content width (Concept full width)"
fi

grep -nE '#\[route\(POST "/admin/releases/\{release_id\}/publish"\)' "$EDIT" >/dev/null \
  || fail "$EDIT must define publish route"
grep -nE '#\[route\(POST "/admin/releases/\{release_id\}/unpublish"\)' "$EDIT" >/dev/null \
  || fail "$EDIT must define unpublish route"
grep -nE '#\[route\(POST "/admin/releases/\{release_id\}/delete"\)' "$EDIT" >/dev/null \
  || fail "$EDIT must define delete route"
grep -n 'is_delete_confirm' "$EDIT" >/dev/null || fail "$EDIT must confirm delete"
grep -n 'releases_manage' "$EDIT" >/dev/null || fail "$EDIT must gate on releases_manage"
grep -n 'RELEASE_STATUS_PUBLISHED' "$EDIT" >/dev/null \
  || fail "$EDIT must set RELEASE_STATUS_PUBLISHED"
grep -n 'RELEASE_STATUS_HIDDEN' "$EDIT" >/dev/null \
  || fail "$EDIT must set RELEASE_STATUS_HIDDEN"
grep -n 'RELEASE_STATUS_STAGING' "$EDIT" >/dev/null \
  || fail "$EDIT must treat STAGING rows as absent (no edit/publish/delete)"
# Boolean selected=(…) omits the attr when false. String "" emits selected="" on
# every option and browsers keep the last one (wrong target org / channel on Save).
grep -nE 'selected=\(org\.id == org_id\)' "$EDIT" >/dev/null \
  || fail "$EDIT must use boolean selected=(org.id == org_id) for target org"
grep -n 'selected=(channel_stable)' "$EDIT" >/dev/null \
  || fail "$EDIT must use boolean selected=(channel_stable) for Channel"
if grep -nE 'selected=\(if .* \{ "selected" \} else \{ "" \}\)' "$EDIT" >/dev/null; then
  fail "$EDIT must not use string selected=\"\"/\"selected\" (boolean attrs only)"
fi

grep -n 'fn release_status_badge_class' "$UI" >/dev/null \
  || fail "$UI must define release_status_badge_class"
grep -n 'status-published' "$CSS" >/dev/null \
  || fail "$CSS must style .status-published"
grep -n 'status-hidden' "$CSS" >/dev/null \
  || fail "$CSS must style .status-hidden"

if [[ -f "$LIST" ]]; then
  grep -n 'releases_manage\|admin_view' "$LIST" >/dev/null \
    || fail "$LIST must gate on releases_manage / admin_view"
  # SSR list pagination + channel chips (same pattern as /{org}/builds).
  grep -nE 'LIST_PAGE_SIZE' "$LIST" >/dev/null \
    || fail "$LIST must use LIST_PAGE_SIZE"
  grep -n 'filter_row' "$LIST" >/dev/null \
    || fail "$LIST must use filter_row (channel chips + pager)"
  if grep -n 'list_toolbar' "$LIST" >/dev/null; then
    fail "$LIST must not use list_toolbar once channel chips are present"
  fi
  grep -n 'channel: Option<String>' "$LIST" >/dev/null \
    || fail "$LIST AdminReleasesQuery must include channel: Option<String>"
  grep -n 'page: Option<u32>' "$LIST" >/dev/null \
    || fail "$LIST AdminReleasesQuery must include page: Option<u32>"
  grep -n 'admin_releases_list_href' "$LIST" >/dev/null \
    || fail "$LIST must share admin_releases_list_href for chips/pager"
  grep -n 'CHANNEL_CHIPS' "$LIST" >/dev/null \
    || fail "$LIST must define CHANNEL_CHIPS (All/LTS/Stable/EOL)"
  grep -n 'vb-rel-head' "$LIST" >/dev/null \
    || fail "$LIST must use vb-rel-head catalog grid (not HTML table)"
  grep -n 'vb-rel-row' "$LIST" >/dev/null \
    || fail "$LIST must use vb-rel-row catalog grid"
  grep -n 'vb-catalog-wrap' "$LIST" >/dev/null \
    || fail "$LIST wrapper must be vb-catalog-wrap (fixed tracks scroll)"
  grep -n 'vb-rel-cols' "$CSS" >/dev/null \
    || fail "$CSS must pin --vb-rel-cols tracks"
  grep -n -- '--vb-catalog-gap' "$CSS" >/dev/null \
    || fail "$CSS must share --vb-catalog-gap with Builds"
  # Builds + releases share the same inter-column gap token.
  grep -n 'column-gap: var(--vb-catalog-gap)' "$CSS" >/dev/null \
    || fail "$CSS catalog grids must use var(--vb-catalog-gap)"
  # Shared columns must reuse the same rem tokens on both surfaces.
  for tok in version channel date size; do
    n="$(grep -c -- "var(--vb-col-$tok)" "$CSS" || true)"
    [[ "$n" -ge 2 ]] \
      || fail "$CSS --vb-col-$tok must be shared by Builds and Releases"
  done
  # Content-sized tracks make page 1 and page N drift apart; fractions with
  # constant rem floors do not.
  REL_TRACKS="$(awk '/--vb-rel-cols:/{f=1} f{print} f&&/;/{exit}' "$CSS")"
  if grep -qE '(^|[^-])(auto|min-content|max-content|fit-content)' \
    <<<"$REL_TRACKS"; then
    fail "$CSS releases columns must not size on content"
  fi
  REL_SHARED="$(grep -o 'var(--vb-col-' <<<"$REL_TRACKS" | wc -l | tr -d ' ')"
  [[ "$REL_SHARED" == "6" ]] \
    || fail "$CSS releases must reuse the 6 shared tokens (got $REL_SHARED)"
  grep -qE 'minmax\([0-9.]+rem, *1fr\)' <<<"$REL_TRACKS" \
    || fail "$CSS releases ACTIONS track must be minmax(<rem floor>, 1fr)"
  for tok in version channel target date size status; do
    grep -qE -- "--vb-col-$tok: *minmax\([0-9.]+rem, *1fr\)" "$CSS" \
      || fail "$CSS --vb-col-$tok must be minmax(<rem floor>, 1fr)"
  done
  # Unequal fractions pile the whole surplus width into the widest column,
  # which reads as a hole before SIZE / ACTIONS. Growth must be even.
  UNEVEN="$(awk '/--vb-col-|--vb-rel-cols:|--vb-build-cols:/,/;/' "$CSS" \
    | grep -oE '[0-9.]+fr' | grep -v '^1fr$' || true)"
  [[ -z "$UNEVEN" ]] \
    || fail "$CSS catalog columns must all grow by 1fr (got: $UNEVEN)"
  grep -n 'page_offset' "$LIST" >/dev/null \
    || fail "$LIST must use page_offset for SQL limit/offset"
  grep -n 'v_major().desc()' "$LIST" >/dev/null \
    || fail "$LIST must ORDER BY v_major.desc (SQL semver; status toggles must not reshuffle)"
  if grep -nE 'page_slice|cmp_version_desc' "$LIST" >/dev/null; then
    fail "$LIST must not page_slice or cmp_version_desc (SQL ORDER BY + limit/offset)"
  fi
  grep -n 'channel_badge_class' "$LIST" >/dev/null \
    || fail "$LIST must color channel badges via channel_badge_class"
  grep -n 'release_status_badge_class' "$LIST" >/dev/null \
    || fail "$LIST must color STATUS via release_status_badge_class"
  grep -n 'vb-row-actions' "$LIST" >/dev/null \
    || fail "$LIST must use vb-row-actions"
  grep -n 'vb-rel-actions' "$LIST" >/dev/null \
    || fail "$LIST must use vb-rel-actions for the ACTIONS track"
  grep -n 'vb-row-actions .vb-btn.outline.compact' "$CSS" >/dev/null \
    || fail "$CSS must equalize Publish/Unpublish width in vb-row-actions"
  grep -n 'flex-wrap: nowrap' "$CSS" >/dev/null \
    || fail "$CSS .vb-row-actions must nowrap (no stacked Edit/Unpublish)"
  grep -n 'RELEASE_STATUS_STAGING' "$LIST" >/dev/null \
    || fail "$LIST must exclude STAGING rows from count and page query"
  grep -n 'sweep_staged_releases' "$LIST" >/dev/null \
    || fail "$LIST must sweep abandoned ceremonies before listing"
  grep -n 'delete=' "$LIST" >/dev/null \
    || fail "$LIST must offer delete= confirm query"
  grep -n 'ico_trash' "$LIST" >/dev/null \
    || fail "$LIST must use ico_trash for Delete"
  grep -n 'Delete permanently' "$LIST" >/dev/null \
    || fail "$LIST must show delete confirm overlay"
  grep -n '+ New release' "$LIST" >/dev/null \
    || fail "$LIST CTA must be + New release"
  if grep -n 'vb-badge soft' "$LIST" | grep -q 'rel.channel'; then
    fail "$LIST must not hardcode vb-badge soft on rel.channel"
  fi
  # STATUS must be a badge span, not bare text only.
  grep -n 'status_badge' "$LIST" >/dev/null \
    || fail "$LIST STATUS cell must use status_badge class"
  # TARGET uses the shared catalog cell face (not a smaller vb-mono span).
  # Pin the exact grid cell — overlay uses `(target.version…)` elsewhere.
  if ! grep -nE '<div>\(target\)</div>' "$LIST" >/dev/null; then
    fail "$LIST TARGET cell must be plain <div>(target)</div>"
  fi
fi

BUILDS="src/app/org/builds.rs"
grep -n 'RELEASE_STATUS_PUBLISHED' "$BUILDS" >/dev/null \
  || fail "$BUILDS must filter customer builds on RELEASE_STATUS_PUBLISHED"

echo "check_admin_releases: OK"
