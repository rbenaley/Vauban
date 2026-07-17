#!/usr/bin/env bash
# BAC hardening (July 2026) -- structural lint: every public web
# handler must be Casbin-gated or explicitly allowlisted.
#
# Production incident: `asset_group_list`, `user_list`, `group_list`,
# `access_rules_list` (and friends) rendered full admin data to any
# authenticated `role:user` because nothing in the handler body read
# the `PermissionContext`. This lint makes the *absence* of a gate a
# CI failure so the class of bug cannot come back:
#
#   For each `pub async fn` in `src/handlers/web/*.rs`, the handler
#   body MUST either:
#     (a) read a `perms.<flag>` (Casbin gate or scope decision), or
#     (b) carry a `// allow-ungated: <reason>` annotation on the
#         line(s) immediately preceding the declaration (self-service
#         surfaces: profile, login, MFA, connect, my-requests, ...).
#
# The route_layer nests (`require_assets_manage`, `require_users_read`,
# `require_groups_read`, `require_access_rules_read`, ...) are the
# OUTER defence layer; this lint enforces the INNER one (rule
# casbin-permissions: the two layers are redundant by design).
#
# Companion of:
#   - vauban-web/tests/web/bac_source_invariants_test.rs (Rust pin
#     that runs this script during `cargo test`).
#   - vauban-web/scripts/check_no_handler_role_gates.sh (forbids
#     is_staff/is_superuser gates; this lint mandates Casbin ones).

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HANDLERS_DIR="${ROOT}/src/handlers/web"

errors=0

for file in "${HANDLERS_DIR}"/*.rs; do
    base="$(basename "${file}")"
    # `tests.rs` carries no production handler; `mod.rs` holds shared
    # helpers whose `pub async fn` are wrappers (checked separately by
    # the allow-ungated mechanism if any exist).
    if [[ "${base}" == "tests.rs" ]]; then
        continue
    fi

    # Drop the `#[cfg(test)]` tail so test fixtures do not trip the
    # parser, then walk the remaining `pub async fn` declarations.
    production="$(awk '/^#\[cfg\(test\)\]/{exit} {print}' "${file}")"

    # Collect declaration line numbers and names.
    while IFS=: read -r lineno name; do
        [[ -z "${lineno}" ]] && continue

        # (b) allowlist annotation on one of the 3 lines above the
        # declaration (doc comments may sit between the annotation
        # and the fn).
        start=$(( lineno > 3 ? lineno - 3 : 1 ))
        context="$(printf '%s\n' "${production}" | sed -n "${start},${lineno}p")"
        # `grep >/dev/null` (not `-q`): `-q` exits on the first match
        # and SIGPIPEs the upstream printf, which under pipefail can
        # INTERMITTENTLY flip the pipeline status (same rationale as
        # check_no_session_in_manage_assets.sh).
        if printf '%s' "${context}" | grep "allow-ungated:" >/dev/null; then
            continue
        fi

        # (a) the handler body reads `perms.` -- scan from the
        # declaration to the next `pub async fn` (or EOF). The awk
        # program deliberately consumes its whole input (no `exit`)
        # so the upstream printf can never receive SIGPIPE, which
        # under `set -o pipefail` would abort the whole lint.
        body="$(printf '%s\n' "${production}" | awk -v s="${lineno}" '
            NR < s { next }
            NR > s && /^pub async fn / { stop = 1 }
            !stop { print }
        ')"
        if printf '%s' "${body}" | grep "perms\." >/dev/null; then
            continue
        fi

        echo "[lint] ${base}:${lineno}: handler \`${name}\` has no \`perms.<flag>\` gate"
        echo "       and no \`// allow-ungated: <reason>\` annotation."
        errors=1
    done < <(printf '%s\n' "${production}" | grep -n '^pub async fn ' \
        | sed 's/^\([0-9]*\):pub async fn \([a-zA-Z0-9_]*\).*/\1:\2/')
done

if [[ ${errors} -ne 0 ]]; then
    echo >&2
    echo "[lint] Broken Access Control guard: every public web handler MUST" >&2
    echo "[lint] read its Casbin permission (\`if !perms.<flag> { ... }\`) or" >&2
    echo "[lint] be explicitly allowlisted with \`// allow-ungated: <reason>\`" >&2
    echo "[lint] immediately above the declaration. See the July 2026 BAC" >&2
    echo "[lint] hardening (asset groups / users / groups / access rules" >&2
    echo "[lint] leaked to role:user)." >&2
    exit 1
fi

echo "[lint] every web handler is Casbin-gated or explicitly allowlisted"
