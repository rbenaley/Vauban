#!/usr/bin/env bash
# Structural lint: forbid is_staff/is_superuser usage as authorization
# gates inside Axum handlers.
#
# Companion of `check_no_template_role_gates.sh`: the templates lint
# guards the Askama rendering layer, this one guards the server-side
# handler logic. Both must stay green so the policy/code/template stack
# is uniformly driven by the Casbin-backed `PermissionContext`.
#
# Permitted usages (passing data, not gating decisions) require an
# explicit opt-out via a `// allow-role-gate: <reason>` annotation on
# the same line OR on the line immediately above. Typical reasons:
#
#   - Generating a JWT claim from the User row (auth.rs).
#   - Populating a `UserContext` for templates, where the boolean is a
#     display attribute, not a gate.
#   - Persisting the `is_staff` / `is_superuser` columns from a form.
#
# Returns non-zero on the first offending occurrence so it can plug
# into CI alongside the templates lint.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HANDLER_DIR="${ROOT}/src/handlers"

if [[ ! -d "${HANDLER_DIR}" ]]; then
    echo "[lint] handler directory not found: ${HANDLER_DIR}" >&2
    exit 2
fi

# Patterns we treat as a "role gate":
#
#   - `auth_user.is_staff`  / `auth_user.is_superuser`
#   - `user.is_staff`       / `user.is_superuser`
#
# These cover both `let user: AuthUser = ...` and the `auth_user`
# convention used in web handlers. The grep pattern is intentionally
# loose; legitimate non-gating usages opt out via the allowlist
# annotation.
PATTERN='\b(auth_user|user)\.(is_staff|is_superuser)\b'

# `tests.rs` stores the forbidden patterns as string literals (anti-
# regression contracts on the source of nearby handlers). Excluding it
# avoids false positives on those test fixtures; the test bodies do not
# themselves perform any role gating.
EXCLUDE_PATTERN='/tests\.rs$'

errors=0

# Stream every match; for each, check whether the same line OR the line
# immediately above carries `// allow-role-gate: <reason>`. Matches
# without an opt-out are reported.
while IFS= read -r match; do
    # `grep -REn` emits `path:line:content`. Split on the first two
    # colons only so the content keeps any embedded ones.
    file="${match%%:*}"
    rest="${match#*:}"
    line="${rest%%:*}"
    content="${rest#*:}"

    case "${file}" in
        *${EXCLUDE_PATTERN##/}|*tests.rs)
            continue
            ;;
    esac

    # Same-line opt-out.
    if [[ "${content}" == *"allow-role-gate:"* ]]; then
        continue
    fi

    # Previous-line opt-out (handles multi-line gates and nicely
    # documented exceptions).
    if [[ "${line}" -gt 1 ]]; then
        prev_line=$((line - 1))
        prev_content=$(sed -n "${prev_line}p" "${file}")
        if [[ "${prev_content}" == *"allow-role-gate:"* ]]; then
            continue
        fi
    fi

    echo "${match}"
    errors=1
done < <(grep -REn --include='*.rs' "${PATTERN}" "${HANDLER_DIR}" || true)

if [[ ${errors} -ne 0 ]]; then
    echo >&2
    echo "[lint] Forbidden is_staff / is_superuser access in a handler." >&2
    echo "[lint] Use the request-scoped PermissionContext extractor and" >&2
    echo "[lint] gate on perms.<resource>_<action>. If the access is a" >&2
    echo "[lint] legitimate data-only read (JWT claim, template display," >&2
    echo "[lint] DB persistence), opt out via:" >&2
    echo "[lint]   // allow-role-gate: <short justification>" >&2
    echo "[lint] on the same line or the line immediately above." >&2
    exit 1
fi

echo "[lint] no forbidden role-based handler gates detected"
