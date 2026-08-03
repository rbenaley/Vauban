#!/usr/bin/env bash
# Structural invariants for builds download entitlement surface.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() {
  echo "check_builds_entitlement: $*" >&2
  exit 1
}

DL="src/app/org/builds/download.rs"
BUILDS="src/app/org/builds.rs"
EPH="src/app/org/builds/ephemeral.rs"

[[ -f "$DL" ]] || fail "missing $DL"
[[ -f "$EPH" ]] || fail "missing $EPH"

grep -nE '#\[route\(POST' "$DL" >/dev/null || fail "$DL must expose POST download route"
grep -n 'builds_download' "$DL" >/dev/null || fail "$DL must gate on builds_download"
grep -n 'DOWNLOAD_UNAVAILABLE\|download unavailable' "$DL" >/dev/null \
  || fail "$DL must return stable DOWNLOAD_UNAVAILABLE when helper fails"
grep -n 'find_release_object' "$DL" >/dev/null \
  || fail "$DL must require storage_objects via find_release_object"
grep -n 'get_release' "$DL" >/dev/null \
  || fail "$DL must stream artifacts via get_release"
if grep -nE 'NOT_IMPLEMENTED|download not configured' "$DL" >/dev/null 2>&1; then
  fail "$DL must not return 501 / 'download not configured' (storage Phase 3)"
fi
grep -n 'require_org' "$DL" >/dev/null || fail "$DL must call require_org"
grep -n 'forbidden' "$DL" >/dev/null || fail "$DL must fail closed with forbidden when missing perm"

grep -n '/download' "$BUILDS" >/dev/null || fail "$BUILDS UI must post to download route"
grep -n 'builds_download' "$BUILDS" >/dev/null || fail "$BUILDS must consult builds_download"
grep -n 'release_visible_to_org\|load_releases_for_org' "$BUILDS" >/dev/null \
  || fail "$BUILDS must filter releases by org (GA or targeted)"
grep -n 'RELEASE_GA_ORG_ID\|organization_id' "$BUILDS" >/dev/null \
  || fail "$BUILDS must reference GA / organization_id targeting"
grep -n 'in_list' "$BUILDS" >/dev/null \
  || fail "$BUILDS must push organization_id.in_list SQL tenant net"
grep -n 'status().eq\|RELEASE_STATUS_PUBLISHED' "$BUILDS" >/dev/null \
  || fail "$BUILDS must filter PUBLISHED status in SQL"
grep -n 'find_visible_release_by_version' "$DL" >/dev/null \
  || fail "$DL must use find_visible_release_by_version (SQL tenant net) before storage get"
grep -n 'find_visible_release_by_version' "$EPH" >/dev/null \
  || fail "$EPH must use find_visible_release_by_version (SQL tenant net)"

# Concept fidelity: default-open + server mint + Topcoat signals (countdown/copy).
grep -n 'open=none' "$BUILDS" >/dev/null \
  || fail "$BUILDS must support open=none collapse (Concept)"
grep -n '5-minute download link' "$BUILDS" >/dev/null \
  || fail "$BUILDS must label Concept 5-minute download link"
grep -n 'Verify signature' "$BUILDS" >/dev/null \
  || fail "$BUILDS must include Verify signature"
grep -n 'channel_badge_class' "$BUILDS" >/dev/null \
  || fail "$BUILDS must color channel badges via channel_badge_class (Concept)"
if grep -n 'vb-badge soft' "$BUILDS" | grep -q 'rel.channel'; then
  fail "$BUILDS must not hardcode vb-badge soft on rel.channel"
fi
grep -n 'chan-lts' styles.css >/dev/null \
  && grep -n 'chan-stable' styles.css >/dev/null \
  && grep -n 'chan-eol' styles.css >/dev/null \
  || fail "styles.css must define chan-lts / chan-stable / chan-eol"
grep -n 'signal verify_open' "$BUILDS" >/dev/null \
  || fail "$BUILDS must toggle Verify via Topcoat signal verify_open"
grep -n 'data-verify-signature-panel\|vb-verify' "$BUILDS" >/dev/null \
  || fail "$BUILDS must render verify signature panel (vb-verify)"
grep -n 'PACKAGE SIGNATURE' "$BUILDS" >/dev/null \
  || fail "$BUILDS verify panel must title PACKAGE SIGNATURE"
# List shows the full digest (not a 7-char prefix + ellipsis).
if grep -nE 'take\(7\)' "$BUILDS" >/dev/null 2>&1; then
  fail "$BUILDS must not truncate sha256 with take(7)"
fi
grep -n 'vb-build-sig-hash' "$BUILDS" >/dev/null \
  || fail "$BUILDS must render full digest via vb-build-sig-hash"
grep -n -- '--vb-build-cols' styles.css >/dev/null \
  || fail "styles.css must share --vb-build-cols for uniform column tracks"
if grep -A2 'Verify signature' "$BUILDS" | grep -q 'vb-btn muted'; then
  fail "$BUILDS Verify signature must be a button, not muted span"
fi
# Verify panel body must not reintroduce ephemeral-only chrome.
VERIFY_SRC="$BUILDS"
awk '/data-verify-signature-panel|class="vb-ephemeral vb-verify"/,/ephemeral_link_panel|if let Some\(panel\)/' "$VERIFY_SRC" \
  | grep -q 'use_curl' \
  && fail "$BUILDS verify panel must not include fetch/cURL use_curl" || true
if awk '/vb-ephemeral vb-verify/,/if let Some\(panel\) = eph_panel/' "$BUILDS" | grep -q 'vb-ephemeral-revoke\|vb-ephemeral-countdown\|use_curl'; then
  fail "$BUILDS verify panel must not include countdown, revoke, or use_curl"
fi
# Verify and ephemeral share one slot: opening Verify hides EPHEMERAL DOWNLOAD LINK.
grep -n 'data-ephemeral-panel-host' "$BUILDS" >/dev/null \
  || fail "$BUILDS must wrap ephemeral_link_panel in data-ephemeral-panel-host"
EPH_HOST=$(awk '/if let Some\(panel\) = eph_panel/,/async fn ephemeral_link_panel/' "$BUILDS")
echo "$EPH_HOST" | grep -q 'verify_open.get()' \
  || fail "$BUILDS ephemeral host must gate visibility on verify_open"
echo "$EPH_HOST" | grep -q 'display:none' \
  || fail "$BUILDS ephemeral host must use display:none while verify is open"
# Inverted vs verify panel: verify shows when open; ephemeral hides when open.
echo "$EPH_HOST" | grep -q '{ "display:none" } else { "" }' \
  || fail "$BUILDS ephemeral host must hide when verify_open (not show)"
grep -n 'struct StorageObject' src/models/mod.rs >/dev/null \
  || fail "models must define StorageObject (digest SoT)"
RELEASE_BLOCK="$(awk '/^pub struct Release \{/,/^}/' src/models/mod.rs)"
echo "$RELEASE_BLOCK" | grep -qE 'sha256|size_mb' \
  && fail "Release must not declare sha256 or size_mb (live on StorageObject)" || true
grep -n 'pub sha256:' src/models/mod.rs >/dev/null \
  || fail "StorageObject must expose sha256"
grep -n 'release_blob_display' "$BUILDS" >/dev/null \
  || fail "$BUILDS must read digests via release_blob_display"
grep -n 'RENAME COLUMN "signature_prefix" TO "sha256"' toasty/migrations/0005_release_sha256.sql >/dev/null \
  || fail "migration 0005 must rename signature_prefix to sha256"
grep -n 'storage_objects' toasty/migrations/0013_storage_objects.sql >/dev/null \
  || fail "migration 0013 must introduce storage_objects"
grep -n 'upsert_acme_private_release' src/db.rs >/dev/null \
  || fail "src/db.rs must upsert Acme private hotfix (refresh legacy 7-char prefix)"
grep -nE '"b7e4d01[0-9a-fA-F]{57}"' src/db.rs >/dev/null \
  || fail "ACME_PRIVATE_SHA256 must be a 64-hex digest (legacy b7e4d01 prefix)"
grep -n 'version_for_package\|strip_prefix' src/release_pkg.rs >/dev/null \
  || fail "release_pkg must strip leading v for package names"
grep -n 'cmp_version_desc' src/release_pkg.rs >/dev/null \
  || fail "release_pkg must define cmp_version_desc"
grep -n 'fn version_sort_fields' src/release_pkg.rs >/dev/null \
  || fail "release_pkg must define version_sort_fields for SQL columns"
grep -n 'v_major().desc()' "$BUILDS" >/dev/null \
  || fail "$BUILDS must ORDER BY v_major.desc (SQL semver)"
grep -n 'load_releases_page_for_org' "$BUILDS" >/dev/null \
  || fail "$BUILDS must page via load_releases_page_for_org"
grep -n 'page_offset' "$BUILDS" >/dev/null \
  || fail "$BUILDS must use page_offset for SQL limit/offset"
if grep -nE 'fn sort_releases|cmp_version_desc\(' "$BUILDS" >/dev/null; then
  fail "$BUILDS must not Rust-sort releases on the hot path (SQL ORDER BY)"
fi
if grep -n 'page_slice(' "$BUILDS" >/dev/null; then
  fail "$BUILDS list must not page_slice (use SQL limit/offset)"
fi
# Dashboard uses the shared ordered loader.
grep -n 'load_releases_for_org' src/app/org.rs >/dev/null \
  || fail "org dashboard must load releases via load_releases_for_org (SQL-ordered)"
grep -n 'RESERVED_ORG_SLUG' "$BUILDS" >/dev/null \
  || fail "$BUILDS release visibility must special-case RESERVED_ORG_SLUG"
grep -n 'has_client_suffix' src/release_pkg.rs >/dev/null \
  || fail "release_pkg must prefer X.Y.Z-client above plain X.Y.Z"
grep -n '0008_release_version_sort.sql' toasty/history.toml >/dev/null \
  || fail "history.toml must list 0008_release_version_sort.sql"
grep -n 'resync_release_sort_keys' src/db.rs >/dev/null \
  || fail "db::connect must resync_release_sort_keys after migrations"
if grep -n 'Collapse' "$BUILDS" >/dev/null; then
  fail "$BUILDS must not include Collapse (extra vs Concept)"
fi
if grep -nE 'link=1|t=demo|04:58' "$BUILDS" >/dev/null; then
  fail "$BUILDS must not use SSR ?link=1 / demo token / static countdown"
fi
grep -n 'EPHEMERAL DOWNLOAD LINK\|vb-ephemeral' "$BUILDS" >/dev/null \
  || fail "$BUILDS must render SSR ephemeral panel"
grep -n 'Generate new link' "$BUILDS" >/dev/null \
  || fail "$BUILDS expired ephemeral state must offer Generate new link"
grep -n 'signal use_curl' "$BUILDS" >/dev/null \
  || fail "$BUILDS must switch fetch/cURL via Topcoat signal use_curl"
if grep -nE 'tool=fetch|tool=curl|\?tool=' "$BUILDS" >/dev/null; then
  fail "$BUILDS must not navigate for fetch/cURL tabs"
fi
grep -n 'signal remaining' "$BUILDS" >/dev/null \
  || fail "$BUILDS must use Topcoat signal remaining for countdown"
grep -n '@animationiteration' "$BUILDS" >/dev/null \
  || fail "$BUILDS must tick countdown via Topcoat @animationiteration"
grep -n 'navigator.clipboard.writeText' "$BUILDS" >/dev/null \
  || fail "$BUILDS must copy via Topcoat @click clipboard handlers"
grep -n 'current_target.inner' "$BUILDS" >/dev/null \
  || fail "$BUILDS clipboard @click must be a function using event.current_target (not bind-time this)"
if grep -nE '@click="navigator\.clipboard' "$BUILDS" >/dev/null; then
  fail "$BUILDS must not use bind-time clipboard statements (breaks Topcoat scan / fetch-cURL toggle)"
fi
grep -n 'use_curl.set(true)' "$BUILDS" >/dev/null \
  || fail "$BUILDS cURL tab must set use_curl via Topcoat @click"
grep -n 'use_curl.set(false)' "$BUILDS" >/dev/null \
  || fail "$BUILDS fetch tab must clear use_curl via Topcoat @click"
grep -n 'data-copy' "$BUILDS" >/dev/null \
  || fail "$BUILDS copy buttons must carry data-copy payload"
grep -n 'ico_copy' "$BUILDS" >/dev/null \
  || fail "$BUILDS must expose Concept cmd copy affordance (ico_copy)"

grep -nE '#\[route\(POST' "$EPH" >/dev/null || fail "$EPH must expose POST ephemeral routes"
grep -n 'EphemeralDownload' "$EPH" >/dev/null || fail "$EPH must persist EphemeralDownload"
grep -n 'Uuid::new_v4\|uuid::' "$EPH" >/dev/null || fail "$EPH must mint UUID tokens server-side"
grep -n 'ephemeral/revoke' "$EPH" >/dev/null || fail "$EPH must support revoke"
grep -n 'eph_public_url' "$EPH" >/dev/null \
  || fail "$EPH must build public URLs via eph_public_url"
grep -n 'public_origin' "$EPH" >/dev/null \
  || fail "$EPH must take public_origin (from server.public_origins)"
grep -n 'primary_public_origin' "$BUILDS" >/dev/null \
  || fail "$BUILDS must use Config::primary_public_origin for ephemeral links"
grep -n 'https://access.vauban.sh' config/vcp.conf >/dev/null \
  || fail "config/vcp.conf public_origins must include https://access.vauban.sh"
if grep -n 'ACCESS_PUBLIC_ORIGIN' src/models/mod.rs "$EPH" "$BUILDS" >/dev/null 2>&1; then
  fail "ACCESS_PUBLIC_ORIGIN must not remain; use server.public_origins"
fi

if [[ -f assets/vcp_builds_eph.js ]] || [[ -f assets/vcp_builds_eph_ui.js ]]; then
  fail "no first-party ephemeral JS assets (use Topcoat signals instead)"
fi
if grep -n 'vcp_builds_eph\|VCP_BUILDS_EPH' src/app.rs >/dev/null; then
  fail "src/app.rs must not wire a custom ephemeral script"
fi
grep -n 'EphemeralDownload' src/models/mod.rs >/dev/null \
  || fail "src/models/mod.rs must define EphemeralDownload"
grep -n 'EphemeralDownload' src/db.rs >/dev/null \
  || fail "src/db.rs must register EphemeralDownload"

# SSR pagination (10 per page, shareable ?page=) via shared list_page + filter_row.
LIST_PAGE="src/list_page.rs"
CHIPS="src/app/_components/chips.rs"
PAGER="src/app/_components/pager.rs"
[[ -f "$LIST_PAGE" ]] || fail "missing $LIST_PAGE"
grep -nE 'LIST_PAGE_SIZE:\s*usize\s*=\s*10' "$LIST_PAGE" >/dev/null \
  || fail "$LIST_PAGE LIST_PAGE_SIZE must be 10"
grep -n 'BUILDS_PAGE_SIZE' "$BUILDS" >/dev/null \
  || fail "$BUILDS must re-export BUILDS_PAGE_SIZE"
grep -n 'pub page:' "$BUILDS" >/dev/null \
  || fail "$BUILDS BuildsQuery must include page"
grep -n 'filter_row\|PagerLinks' "$BUILDS" >/dev/null \
  || fail "$BUILDS must use filter_row / PagerLinks"
grep -n 'vb-chip-group' "$CHIPS" >/dev/null \
  || fail "$CHIPS must render vb-chip-group"
grep -n 'vb-pager' "$PAGER" >/dev/null \
  || fail "$PAGER must render vb-pager markup"
grep -n 'vb-pager' styles.css >/dev/null \
  || fail "styles.css must define .vb-pager"
# filter_row before table in builds page body.
FILTER_LINE="$(grep -n 'filter_row' "$BUILDS" | head -1 | cut -d: -f1)"
TABLE_LINE="$(grep -n 'vb-table-wrap' "$BUILDS" | head -1 | cut -d: -f1)"
[[ -n "$FILTER_LINE" && -n "$TABLE_LINE" && "$FILTER_LINE" -lt "$TABLE_LINE" ]] \
  || fail "$BUILDS filter_row must sit before builds table"
# Channel chip hrefs omit page= (builds_list_href for chips uses channel only).
if grep -nE 'format!\("\{base\}\?channel=\{ch\}&page=|channel=\{ch\}&page=' "$BUILDS" >/dev/null; then
  fail "$BUILDS channel chip hrefs must not sticky-bind page="
fi
# Right-align + chip-height face (same padding as .vb-chip).
awk '/^\.vb-pager \{/,/^}/' styles.css | grep -qE 'margin:\s*0 0 0 auto|margin-left:\s*auto' \
  || fail "styles.css .vb-pager must right-align (margin-left auto)"
awk '/^a\.vb-pager-link \{/,/^}/' styles.css | grep -q 'padding: 6px 12px' \
  || fail "styles.css a.vb-pager-link must use chip padding 6px 12px"
if awk '/^a\.vb-pager-link \{/,/^}/' styles.css | grep -qE 'height:\s*40px|min-height:\s*40px'; then
  fail "styles.css a.vb-pager-link must match chip height (no fixed 40px)"
fi
if grep -nE 'pager|page_slice|BUILDS_PAGE_SIZE' "$BUILDS" | grep -qiE 'localStorage|history\.pushState'; then
  fail "$BUILDS must not use client JS for paging"
fi

echo "check_builds_entitlement: OK"
