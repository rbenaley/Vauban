#!/usr/bin/env bash
# IACS / EWS structural lint: forbid direct reads of
# `state.config.industrial.enabled` (the kill-switch) from inside the
# request-handling layer.
#
# The kill-switch must be enforced exactly ONCE -- inside
# `PermissionContext::load`, where it collapses every `iacs_*` flag to
# `false` when `[industrial].enabled = false`. Every downstream layer
# (handlers, templates, sidebar, websockets) MUST gate on
# `perms.iacs_request` / `perms.iacs_read` / `perms.iacs_manage`. Reading
# the boolean directly anywhere else creates a parallel decision path
# that can drift from the canonical Casbin gate.
#
# Allowed locations (whitelisted because they are the source of truth):
#
#   - `vauban-web/src/auth/permissions.rs`
#     (the Casbin loader that propagates the flag).
#   - `vauban-web/src/services/iacs.rs`
#     (the in-tx authoritative checks read `state.config.industrial.*`
#     for the cap; the *enabled* flag still must NOT be read here).
#   - `vauban-web/src/main.rs`
#     (routing wiring may legitimately read the field for diagnostic
#     log lines, kept under the same whitelist for symmetry).
#   - test files (`tests/**` and `#[cfg(test)] mod tests` blocks).
#
# Layer-2 DB-filter whitelist. The IACS kill-switch is not purely a
# Casbin gate: a `read_all` admin would still SEE IACS rows in list
# queries if the DB query did not also drop them. These handlers
# therefore read `industrial.enabled` directly to add a
# `.filter(... .ne(iacs))` clause to their list queries (assets) or
# to exclude IACS sessions from the operational `/sessions` +
# `/sessions/active` surfaces (sessions). This is NOT a parallel
# *decision* path (the Casbin gate still fences the entry-points);
# it is the data-visibility layer that complements it. Pinned by
# `tests/web/iacs_kill_switch_test.rs` (assets) and
# `tests/web/iacs_sessions_kill_switch_test.rs` (sessions).
#
#   - `vauban-web/src/handlers/web/assets.rs`
#   - `vauban-web/src/handlers/api/assets.rs`
#   - `vauban-web/src/handlers/web/sessions.rs`
#   - `vauban-web/src/handlers/websocket.rs`
#   - `vauban-web/src/handlers/api/sessions.rs`
#   - `vauban-web/src/handlers/web/users.rs`
#
# Returns non-zero on the first forbidden read so it plugs into CI.
# Companion of:
#   - `tests/web/iacs_kill_switch_test.rs` (runtime invariant: routes
#     return 404 when the kill-switch is off).
#   - `.cursor/rules/casbin-permissions.mdc` (rule prose).

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Files allowed to read `industrial.enabled`. Anything else should
# delegate to `PermissionContext`.
ALLOWED=(
    "src/auth/permissions.rs"
    "src/main.rs"
    "scripts/check_iacs_kill_switch.sh"
    # Layer-2 DB-filter readers (see header comment).
    "src/handlers/web/assets.rs"
    "src/handlers/api/assets.rs"
    "src/handlers/web/sessions.rs"
    "src/handlers/websocket.rs"
    "src/handlers/api/sessions.rs"
    "src/handlers/web/users.rs"
    # Shared terminate core: `broadcast_session_list_updates` forwards
    # the flag to `tasks::dashboard::push_*_update` (the same layer-2
    # list-visibility filter its callers -- api/sessions.rs and
    # web/users.rs above -- performed inline before the extraction).
    "src/services/session_termination.rs"
    # Layer-4 kill-switch enforcers (documented in each file's inline
    # comments): refuse creating/updating IACS assets or granting IACS
    # protocols on access rules while the master switch is off,
    # anti-enumeration 404 on IACS asset detail, frozen-but-preserved
    # IACS protocols on rule edit, and `AssetType::select_options`
    # gating of the type dropdown. These reads were always present but
    # invisible to this lint until the `grep -q` SIGPIPE bug (see the
    # comment in the scan loop below) was fixed: `-q` exited on the
    # first match, killed the upstream sed and the pipefail status flip
    # silently skipped the finding. Pinned by
    # `tests/web/iacs_kill_switch_test.rs` and
    # `access_rule_edit_preserves_existing_iacs_protocols_under_kill_switch`.
    "src/handlers/web/access_rules.rs"
    "src/handlers/web/manage_assets.rs"
    "src/handlers/api/manage_assets.rs"
)

errors=0

# Walk every Rust source file under `src/handlers/`, `src/templates/`,
# `src/services/`, `src/middleware/`, and check that none of them
# reference `industrial.enabled`.
SCAN_DIRS=(
    "src/handlers"
    "src/templates"
    "src/services"
    "src/middleware"
)

# Strip Rust line comments and `#[cfg(test)] mod tests { ... }` blocks
# so production reads are isolated from test fixtures and inline docs.
strip_rust() {
    # Drop everything from the first `#[cfg(test)]` onwards (matches the
    # convention used throughout this codebase for inline tests). Then
    # strip line comments.
    sed -e 's|//.*$||' "${1}" | awk '
        BEGIN { skip=0 }
        /^#\[cfg\(test\)\]/ { skip=1 }
        skip == 0 { print }
    '
}

for dir in "${SCAN_DIRS[@]}"; do
    abs="${ROOT}/${dir}"
    if [[ ! -d "${abs}" ]]; then continue; fi
    while IFS= read -r -d '' path; do
        rel="${path#${ROOT}/}"
        # Whitelist gate.
        for allowed in "${ALLOWED[@]}"; do
            if [[ "${rel}" == "${allowed}" ]]; then
                continue 2
            fi
        done
        # `grep -E >/dev/null` (not `-q`): `-q` exits on the first match
        # and SIGPIPEs the upstream sed, which under pipefail can
        # INTERMITTENTLY flip a found-token pipeline to non-zero and
        # silently skip the violation.
        if strip_rust "${path}" | grep -E 'config\.industrial\.enabled' >/dev/null; then
            echo "[lint] forbidden read of \`config.industrial.enabled\` in ${rel}"
            echo "       gate on \`perms.iacs_*\` instead -- the kill-switch is"
            echo "       enforced once in \`PermissionContext::load\`."
            errors=1
        fi
    done < <(find "${abs}" -type f -name '*.rs' -print0)
done

if [[ ${errors} -ne 0 ]]; then
    echo >&2
    echo "[lint] IACS kill-switch leaked outside the canonical loader." >&2
    echo "[lint] See .cursor/rules/casbin-permissions.mdc and" >&2
    echo "[lint] vauban-web/src/auth/permissions.rs (search for" >&2
    echo "[lint] \`industrial.enabled\`)." >&2
    exit 1
fi

echo "[lint] IACS kill-switch is read only from the canonical loader"
