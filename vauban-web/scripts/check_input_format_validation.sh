#!/usr/bin/env bash
# Structural lint: closed-format inputs must be validated before every
# persisted write (July 2026 input-format hardening).
#
# Guards the seams pinned by tests/web/input_format_pin_test.rs so a
# single-line regression is caught before `cargo test`:
#
#   1. The slug web handlers (asset_groups, secret_groups,
#      vault_secrets) keep calling `validate_slug_format`.
#   2. manage_assets (web + API) keeps gating `status` with the strict
#      parser (`AssetStatus::parse_strict`) and the hostname charset.
#   3. The web users handlers keep the username/email format gates.
#   4. vauban-access keeps its fail-closed re-checks delegating to
#      `shared::validation` (single source of truth).
#   5. The slug inputs keep the canonical `pattern` attribute.
#
# Returns non-zero on the first missing seam.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REPO="$(cd "${ROOT}/.." && pwd)"

errors=0

# require <min_count> <needle> <file> <label>
require() {
    local min="$1" needle="$2" file="$3" label="$4"
    if [[ ! -f "${file}" ]]; then
        echo "[lint] missing file: ${file}" >&2
        errors=1
        return
    fi
    local count
    count=$(grep -cF -- "${needle}" "${file}" || true)
    if [[ "${count}" -lt "${min}" ]]; then
        echo "[lint] ${label}: expected >= ${min} occurrence(s) of '${needle}' in ${file#"${REPO}"/}, found ${count}" >&2
        errors=1
    fi
}

# --- 1. Web slug surfaces -------------------------------------------------
require 2 "validate_slug_format" "${ROOT}/src/handlers/web/asset_groups.rs" \
    "asset group create/update must gate the slug format"
require 2 "validate_slug_format" "${ROOT}/src/handlers/web/secret_groups.rs" \
    "secret group create/update must gate the slug format"
require 2 "validate_slug_format" "${ROOT}/src/handlers/web/vault_secrets.rs" \
    "vault secret create/update must gate the name format"
require 2 "validate_hex_color_format" "${ROOT}/src/handlers/web/asset_groups.rs" \
    "asset group create/update must gate the color format"
require 2 "validate_icon_choice" "${ROOT}/src/handlers/web/asset_groups.rs" \
    "asset group create/update must gate the icon catalog"

# --- 2. Asset status + hostname -------------------------------------------
require 2 "AssetStatus::parse_strict" "${ROOT}/src/handlers/web/manage_assets.rs" \
    "web asset create/update must strict-parse the status"
require 1 "AssetStatus::parse_strict" "${ROOT}/src/handlers/api/manage_assets.rs" \
    "API asset update must strict-parse the status"
require 2 "validate_hostname_format" "${ROOT}/src/handlers/web/manage_assets.rs" \
    "web asset create/update must gate the hostname charset"
require 2 "is_valid_hostname" "${ROOT}/src/handlers/api/manage_assets.rs" \
    "API asset create/update must gate the hostname charset"

# --- 3. Users web zone -----------------------------------------------------
require 2 "validate_username_format" "${ROOT}/src/handlers/web/users.rs" \
    "user create/update must gate the username charset"
require 2 "validate_email_format" "${ROOT}/src/handlers/web/users.rs" \
    "user create/update must gate the email format"
require 1 "RE_USERNAME.is_match" "${ROOT}/src/handlers/web/mod.rs" \
    "the web username helper must delegate to the API-zone RE_USERNAME"

# --- 4. vauban-access fail-closed re-checks --------------------------------
require 2 "validate_asset_group_formats(" "${REPO}/vauban-access/src/handlers.rs" \
    "vauban-access must re-check asset-group formats on create AND update"
require 1 "shared::validation::is_valid_slug" "${REPO}/vauban-access/src/handlers.rs" \
    "the vauban-access asset-group re-check must delegate to shared::validation"
require 2 "shared::validation::is_valid_slug" "${REPO}/vauban-access/src/secrets.rs" \
    "vauban-access must re-check the secret-group slug on create AND update"

# --- 5. Browser pattern attributes -----------------------------------------
SLUG_PATTERN='pattern="[a-z0-9]([a-z0-9_-]*[a-z0-9])?"'
for tpl in \
    "${ROOT}/templates/assets/manage/groups/create.html" \
    "${ROOT}/templates/assets/manage/groups/edit.html" \
    "${ROOT}/templates/secrets/group_create.html" \
    "${ROOT}/templates/secrets/group_edit.html" \
    "${ROOT}/templates/secrets/secret_create.html" \
    "${ROOT}/templates/secrets/secret_edit.html"; do
    require 1 "${SLUG_PATTERN}" "${tpl}" "slug input must carry the canonical pattern"
done

# --- 6. DB layer ------------------------------------------------------------
MIGRATION="${REPO}/vauban-db/migrations/20260717000000_input_format_constraints/up.sql"
require 1 "asset_groups_slug_format_chk" "${MIGRATION}" "asset group slug CHECK must exist"
require 1 "secret_groups_slug_format_chk" "${MIGRATION}" "secret group slug CHECK must exist"
require 1 "vault_secrets_name_format_chk" "${MIGRATION}" "vault secret name CHECK must exist"
require 1 "asset_groups_color_chk" "${MIGRATION}" "asset group color CHECK must exist"
require 1 "assets_status_chk" "${MIGRATION}" "asset status CHECK must exist"

if [[ ${errors} -ne 0 ]]; then
    echo >&2
    echo "[lint] Input-format validation seam missing. Every closed-format" >&2
    echo "[lint] field (slug, color, icon, status, hostname, username," >&2
    echo "[lint] email) must be validated BEFORE any DB/IPC write, with" >&2
    echo "[lint] shared::validation as the single source of truth." >&2
    echo "[lint] See tests/web/input_format_pin_test.rs and the plan in" >&2
    echo "[lint] .cursor/rules (input-format hardening, July 2026)." >&2
    exit 1
fi

echo "[lint] input-format validation seams present"
