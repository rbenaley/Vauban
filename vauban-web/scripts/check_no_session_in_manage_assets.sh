#!/usr/bin/env bash
# Issue #27 -- structural lint: forbid session-opening references in
# the admin asset zone.
#
# The admin handlers under `src/handlers/web/manage_assets.rs`,
# `src/handlers/api/manage_assets.rs` and the admin Askama templates
# under `templates/assets/manage/` MUST NEVER reference any path that
# opens or links to a session: `connect-rdp`, `connect_ssh`,
# `submit_access_request`, `request-access`, `/sessions/request`,
# WebSocket upgrade tokens, etc. The whole point of the asset zone
# split is that the admin sub-tree is *structurally* session-free.
#
# Companion of:
#   - vauban-web/tests/web/manage_assets_invariants_test.rs
#     (Rust source-level test enforcing the same invariant during
#     `cargo test`).
#   - vauban-web/scripts/check_no_handler_role_gates.sh
#     (analog lint for is_staff/is_superuser gates in handlers).
#
# Returns non-zero on the first forbidden token so it can plug into
# CI directly. Comment lines (Rust `//`, Askama `{# #}` and HTML
# `<!-- -->`) are EXCLUDED from the scan so the production source
# can legitimately document the architectural contract.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Files in scope. Each entry is "path:filetype" where filetype is
# rust|template (drives the comment-stripping mode).
SCOPED=(
    "${ROOT}/src/handlers/web/manage_assets.rs:rust"
    "${ROOT}/src/handlers/api/manage_assets.rs:rust"
    "${ROOT}/src/handlers/web/asset_groups.rs:rust"
    "${ROOT}/templates/assets/manage/list.html:template"
    "${ROOT}/templates/assets/manage/detail.html:template"
    "${ROOT}/templates/assets/manage/groups/list.html:template"
    "${ROOT}/templates/assets/manage/groups/create.html:template"
    "${ROOT}/templates/assets/manage/groups/detail.html:template"
    "${ROOT}/templates/assets/manage/groups/edit.html:template"
    "${ROOT}/templates/assets/manage/groups/add_asset.html:template"
)

# Forbidden tokens. Kept as basic strings (not regex) so the lint is
# grep-portable. We deliberately use TWO variants for `connect`
# (`connect-rdp` and `connect_ssh`) because the production codebase
# uses both the URL form and the function-name form.
FORBIDDEN=(
    "connect-rdp"
    "connect_ssh"
    "submit_access_request"
    "request-access"
    "/sessions/request"
    "wss://"
    "WebSocketUpgrade"
)

errors=0

# Strip line comments from a Rust source file.
strip_rust_comments() {
    # Remove anything from `//` to end of line. This is a coarse pass
    # that ignores string literals, but the forbidden tokens are
    # never legitimately needed inside string literals of admin
    # production code.
    sed 's|//.*$||'
}

# Strip Askama `{# ... #}` and HTML `<!-- ... -->` comments. Single
# pass per line is good enough for the admin templates which never
# embed a forbidden token outside a comment in practice.
strip_template_comments() {
    sed 's|<!--[^>]*-->||g; s|{#.*#}||g'
}

for entry in "${SCOPED[@]}"; do
    path="${entry%%:*}"
    kind="${entry##*:}"

    if [[ ! -f "${path}" ]]; then
        echo "[lint] missing file (admin asset zone may be misconfigured): ${path}" >&2
        errors=1
        continue
    fi

    # Strip the appropriate flavour of comments BEFORE grepping so the
    # source can document the contract in human-readable comments.
    case "${kind}" in
        rust)
            stripped="$(strip_rust_comments < "${path}")"
            ;;
        template)
            stripped="$(strip_template_comments < "${path}")"
            ;;
        *)
            echo "[lint] unknown file kind: ${kind}" >&2
            exit 2
            ;;
    esac

    # Drop everything from the first `#[cfg(test)]` onwards so test
    # fixtures inside the source can reference forbidden tokens in
    # their assertion strings without tripping the lint.
    stripped="${stripped%%#\[cfg(test)\]*}"

    for tok in "${FORBIDDEN[@]}"; do
        # `grep -F >/dev/null` (not `-q`): `-q` exits on the first match
        # and SIGPIPEs the upstream printf, which under pipefail can
        # INTERMITTENTLY flip a found-token pipeline to non-zero and
        # silently skip the violation.
        if printf '%s' "${stripped}" | grep -F "${tok}" >/dev/null; then
            echo "[lint] forbidden token \"${tok}\" found in ${path}"
            echo "       (the admin asset zone MUST be session-free -- issue #27)"
            errors=1
        fi
    done
done

if [[ ${errors} -ne 0 ]]; then
    echo >&2
    echo "[lint] Admin asset zone leaked a session-opening reference." >&2
    echo "[lint] These tokens are reserved for the user zone (/assets/*)" >&2
    echo "[lint] which is the only place sessions may be opened. Move the" >&2
    echo "[lint] offending logic out of manage_assets.rs / manage/." >&2
    exit 1
fi

echo "[lint] no session-opening references in the admin asset zone"
