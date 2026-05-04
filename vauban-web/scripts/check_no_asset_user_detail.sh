#!/usr/bin/env bash
# Issue #34 -- structural lint: forbid the user-zone asset DETAIL page
# from being re-introduced.
#
# The legacy `/assets/{uuid}` GET handler (`asset_user_view`) and its
# template (`templates/assets/asset_detail.html`) used to render
# `description`, `created_at`, `updated_at`, `ssh_host_key_fingerprint`,
# `group_uuid`, the asset UUID and the host name to ANY caller with
# `assets:read` -- including users who had not yet been granted access
# and were about to open the "Request Access" modal. The detail page
# was an information-disclosure surface and has been removed in favour
# of inlined modaux on the catalogue list page (`/assets`).
#
# This lint catches single-line regressions BEFORE `cargo test`:
#
#   1. Re-introducing the `asset_user_view` handler.
#   2. Re-introducing `templates/assets/asset_detail.html`.
#   3. Re-introducing the legacy `/assets/{uuid}#request-access` (or
#      `#justify`) hash-link navigation in `templates/assets/asset_list.html`.
#   4. Re-mounting the `GET /assets/{uuid}` route on anything other
#      than `gone_asset_user_view`.
#
# Companion of:
#   - vauban-web/tests/web/asset_modal_dataflow_test.rs
#     (source-grep pin tests covering the same invariants during
#     `cargo test`)
#   - vauban-web/tests/web/asset_user_zone_no_leak_test.rs
#     (E2E coverage: the route returns 410 with a constant body).
#
# Returns non-zero on the first violation so it plugs into CI directly.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

errors=0

# ---- 1. asset_user_view handler must be gone ----
HANDLER="${ROOT}/src/handlers/web/assets.rs"
if [[ ! -f "${HANDLER}" ]]; then
    echo "[lint] missing file: ${HANDLER}" >&2
    errors=1
elif sed 's|//.*$||' "${HANDLER}" | grep -qE 'pub async fn asset_user_view\('; then
    echo "[lint] forbidden: \`pub async fn asset_user_view(\` in ${HANDLER}"
    echo "       Issue #34 removed the user-zone /assets/{uuid} detail page."
    echo "       The route now serves a constant 410 via gone_asset_user_view;"
    echo "       the Request Access / Justification modaux are inlined on /assets."
    errors=1
fi

# ---- 2. asset_detail template must be gone ----
TEMPLATE="${ROOT}/templates/assets/asset_detail.html"
if [[ -f "${TEMPLATE}" ]]; then
    echo "[lint] forbidden: ${TEMPLATE} still exists"
    echo "       Issue #34 removed the user-zone detail page; do not"
    echo "       resurrect this template."
    errors=1
fi

MODULE="${ROOT}/src/templates/assets/asset_detail.rs"
if [[ -f "${MODULE}" ]]; then
    echo "[lint] forbidden: ${MODULE} still exists"
    echo "       Issue #34 removed the user-zone detail page; the Rust"
    echo "       template module went with it."
    errors=1
fi

# ---- 3. asset_list.html must NOT use the legacy hash-link nav ----
LIST="${ROOT}/templates/assets/asset_list.html"
if [[ -f "${LIST}" ]]; then
    # Strip Askama `{# ... #}` and HTML `<!-- ... -->` comments first
    # so the documentation comments can mention the legacy pattern.
    stripped="$(sed 's|<!--[^>]*-->||g; s|{#.*#}||g' "${LIST}")"
    if printf '%s' "${stripped}" | grep -qE 'href="/assets/\{\{ asset\.uuid \}\}#'; then
        echo "[lint] forbidden: legacy \`href=\"/assets/{{ asset.uuid }}#...\"\` in ${LIST}"
        echo "       Issue #34: the per-row Request / Connect buttons must open"
        echo "       the inlined Alpine modaux via @click=\"\$store.*.open(...)\""
        echo "       and NOT navigate to the now-removed detail page."
        errors=1
    fi
    if printf '%s' "${stripped}" | grep -qE '#request-access|#justify'; then
        echo "[lint] forbidden: legacy \`#request-access\`/\`#justify\` hash in ${LIST}"
        echo "       Issue #34: the hash router was removed; modaux open via"
        echo "       \$store.accessModal.open(...) and \$store.justificationModal.open(...)."
        errors=1
    fi
fi

# ---- 4. main.rs must mount /assets/{uuid} on gone_asset_user_view ----
MAIN="${ROOT}/src/main.rs"
if [[ ! -f "${MAIN}" ]]; then
    echo "[lint] missing file: ${MAIN}" >&2
    errors=1
else
    stripped_main="$(sed 's|//.*$||' "${MAIN}")"
    # Find the `.route("/assets/{uuid}",` line(s).
    if ! printf '%s' "${stripped_main}" | grep -qE '\.route\("/assets/\{uuid\}",[[:space:]]*get\(handlers::web::gone_asset_user_view\)\)'; then
        echo "[lint] forbidden: \`/assets/{uuid}\` GET route is not on gone_asset_user_view in ${MAIN}"
        echo "       Issue #34: this route must serve a constant 410 via"
        echo "       handlers::web::gone_asset_user_view (anti-enum, audit-grep)."
        errors=1
    fi
    if printf '%s' "${stripped_main}" | grep -qE 'handlers::web::asset_user_view'; then
        echo "[lint] forbidden: reference to \`handlers::web::asset_user_view\` in ${MAIN}"
        echo "       Issue #34: this handler is gone; use gone_asset_user_view."
        errors=1
    fi
fi

if [[ ${errors} -ne 0 ]]; then
    echo >&2
    echo "[lint] One or more issue #34 invariants violated: the user-zone" >&2
    echo "[lint] /assets/{uuid} detail page must remain removed and the" >&2
    echo "[lint] Request Access / Justification modaux must stay inlined" >&2
    echo "[lint] on /assets." >&2
    exit 1
fi

echo "[lint] issue #34: user-zone asset detail page is gone, modaux inlined"
