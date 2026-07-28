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
grep -n 'download not configured' "$DL" >/dev/null \
  || fail "$DL must return stable 'download not configured' message"
grep -n 'NOT_IMPLEMENTED\|StatusCode::NOT_IMPLEMENTED' "$DL" >/dev/null \
  || fail "$DL must return 501 NOT_IMPLEMENTED when authorized"
grep -n 'require_org' "$DL" >/dev/null || fail "$DL must call require_org"
grep -n 'forbidden' "$DL" >/dev/null || fail "$DL must fail closed with forbidden when missing perm"

grep -n '/download' "$BUILDS" >/dev/null || fail "$BUILDS UI must post to download route"
grep -n 'builds_download' "$BUILDS" >/dev/null || fail "$BUILDS must consult builds_download"
grep -n 'release_visible_to_org\|load_releases_for_org' "$BUILDS" >/dev/null \
  || fail "$BUILDS must filter releases by org (GA or targeted)"
grep -n 'RELEASE_GA_ORG_ID\|organization_id' "$BUILDS" >/dev/null \
  || fail "$BUILDS must reference GA / organization_id targeting"
grep -n 'release_visible_to_org' "$DL" >/dev/null \
  || fail "$DL must enforce release_visible_to_org before 501"

# Concept fidelity: default-open + server mint + Topcoat signals (countdown/copy).
grep -n 'open=none' "$BUILDS" >/dev/null \
  || fail "$BUILDS must support open=none collapse (Concept)"
grep -n '5-minute download link' "$BUILDS" >/dev/null \
  || fail "$BUILDS must label Concept 5-minute download link"
grep -n 'Verify signature' "$BUILDS" >/dev/null \
  || fail "$BUILDS must include Verify signature"
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

echo "check_builds_entitlement: OK"
