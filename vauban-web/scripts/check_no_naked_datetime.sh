#!/usr/bin/env bash
# Structural lint: forbid naked `DateTime<Utc>` rendering in Askama
# templates. Every server-side date rendered to HTML MUST go through
# the `|local(...)` / `|local_seconds(...)` filter so the user's
# browser timezone is honored (see
# `docs/runbooks/timezone_localization.md`). The UTC suffix is reserved
# for logs / DB / IPC where the wire format is fixed.
#
# This lint catches four classes of regression:
#
#   1. `{{ x.<field>.format(...) }}` -- direct call to `chrono::format`
#      bypasses the filter entirely. Use `{{ x.<field>|local(tz) }}`
#      instead.
#   2. `{{ x.<field> }}` (bare display) on a known datetime accessor
#      -- relies on `Display for DateTime<Utc>` which prints UTC
#      offset. Use `{{ x.<field>|local(tz) }}` instead.
#   3. Handler-side `format!("...UTC...")` literals inside
#      `src/handlers/**.rs` (UTC string pre-formatted in Rust).
#   4. Rust-side naked clock-time `.format("%H...")` anywhere in
#      `src/**.rs`. Localised display MUST go through
#      `crate::utils::format_local*` (which carry `%Z`). Escape hatches:
#      (a) the format literal itself carries `%Z`/`%z` (already
#      tz-aware -- this is exactly what `format_local*` and the Apache
#      audit log do); (b) an inline `// allow-naked-datetime: <reason>`
#      annotation on the same line or the line immediately above
#      (datetime-local form inputs, UTC round-trip tests, ...). Date-only
#      formats (`%Y`, `%m`, `%d` storage paths) never match -- the rule
#      only triggers on the clock specifiers %H %M %S %T %R %I %r %X.
#
# A non-zero exit code blocks CI on the first offending occurrence.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TEMPLATE_DIR="${ROOT}/templates"

if [[ ! -d "${TEMPLATE_DIR}" ]]; then
    echo "[lint] template directory not found: ${TEMPLATE_DIR}" >&2
    exit 2
fi

errors=0

# Catalogue of canonical datetime accessors. Every match against
# `<field>.format(` or naked `<field> }}` (without a `|` filter) is
# flagged as a regression. Ordered most-specific first.
DATETIME_FIELDS=(
    "created_at"
    "updated_at"
    "connected_at"
    "disconnected_at"
    "expires_at"
    "valid_from"
    "valid_until"
    "approved_at"
    "rejected_at"
    "decided_at"
    "deleted_at"
    "disabled_at"
    "offboarded_at"
    "started_at"
    "ended_at"
    "last_activity"
    "last_used_at"
    "last_login_at"
    "last_login"
    "last_synced"
    "recording_finalized_at"
    "finalized_at"
    "computed_at"
    "timestamp"
)

# Files exempt from the lint. The `dashboard/widgets/active_sessions.html`
# tile uses `started_at` to render a *duration* (signed_duration_since), not
# an absolute timestamp -- not localised. The iframe-only RDP/SSH viewers
# do not display dates.
EXEMPT_FILES=()

is_exempt() {
    local path="$1"
    if (( ${#EXEMPT_FILES[@]} == 0 )); then
        return 1
    fi
    for ex in "${EXEMPT_FILES[@]}"; do
        if [[ "${path}" == *"${ex}"* ]]; then
            return 0
        fi
    done
    return 1
}

# Rule 1: forbid `.format(` chained on a datetime field within a
# template expression. `<time datetime="...Z">` ISO 8601 markers are
# allowed (machine-readable for accessibility / SEO).
while IFS= read -r -d '' file; do
    is_exempt "${file}" && continue
    # Strip lines whose `.format(` argument is an ISO 8601 literal
    # (`%Y-%m-%dT%H:%M:%SZ`); those feed `<time datetime="...">` and
    # are required by the HTML5 spec.
    while IFS=: read -r line_no line; do
        if [[ "${line}" =~ format\(\"%Y-%m-%dT%H:%M:%SZ\"\) ]]; then
            continue
        fi
        echo "[lint] ${file}:${line_no} -- naked .format(...) on a datetime field; use |local(tz) instead" >&2
        echo "    > ${line}" >&2
        errors=$((errors + 1))
    done < <(grep -nE "\b(($(IFS='|'; echo "${DATETIME_FIELDS[*]}")))\.format\(" "${file}" || true)
done < <(find "${TEMPLATE_DIR}" -type f -name "*.html" -print0)

# Rule 2 was intentionally dropped: most "naked" `{{ x.created_at }}`
# accessors in the current codebase point at `String` fields whose
# handler already pre-formats via `crate::utils::format_local*`. A
# bash grep cannot distinguish `DateTime<Utc>` from `String` so the
# rule produced too many false positives and would have been
# routinely overridden -- a worse outcome than not having the rule
# at all. The combination of Rule 1 (`.format(...)` chain ban) and
# Rule 3 (`format!("...UTC")` ban in handlers) is enough to trap
# every UTC leakage observed during the May 2026 audit.

# Rule 3: handler-side `format!("...UTC")` is forbidden. Logs /
# tracing remain free to use UTC; the lint is scoped to
# `vauban-web/src/handlers/**/*.rs` only.
while IFS= read -r -d '' file; do
    while IFS=: read -r line_no line; do
        # Skip macros we know are tracing (`info!`, `warn!`, etc.) and
        # comments.
        if [[ "${line}" =~ ^[[:space:]]*// ]]; then
            continue
        fi
        if [[ "${line}" =~ (info!|warn!|error!|debug!|trace!) ]]; then
            continue
        fi
        echo "[lint] ${file}:${line_no} -- pre-formatting a UTC string in a handler; use crate::utils::format_local* with browser_tz.0" >&2
        echo "    > ${line}" >&2
        errors=$((errors + 1))
    done < <(grep -nE 'format!\("[^"]*UTC[^"]*"' "${file}" || true)
done < <(find "${ROOT}/src/handlers" -type f -name "*.rs" -print0)

# Rule 4: forbid naked clock-time `.format("%H...")` anywhere in
# `src/**.rs`. Localised display MUST go through
# `crate::utils::format_local*` (which carry `%Z`). The awk pass below
# triggers ONLY on clock specifiers (%H %M %S %T %R %I %r %X) so that
# date-only storage paths (`%Y`, `%m`, `%d`) are never flagged. Two
# escape hatches: a format literal that already carries `%Z`/`%z`
# (tz-aware), or a `// allow-naked-datetime: <reason>` annotation on the
# same line or the line immediately above.
while IFS= read -r -d '' file; do
    while IFS= read -r offending; do
        echo "[lint] ${offending}" >&2
        echo "    > use crate::utils::format_local* (browser_tz) or annotate with '// allow-naked-datetime: <reason>'" >&2
        errors=$((errors + 1))
    done < <(awk -v f="${file}" '
        BEGIN { ann = -1 }
        /allow-naked-datetime/ { ann = NR }
        {
            if ($0 ~ /\.format\(&?"[^"]*%[HMSTRIrX][^"]*"/ && $0 !~ /%[Zz]/) {
                # Tracing/log macros stay UTC by contract (mirrors
                # Rule 3). A single-line `info!(... dt.format("%H..."))`
                # is exempt; the multi-line form needs the annotation.
                if ($0 ~ /(info!|warn!|error!|debug!|trace!)/) next
                if ($0 ~ /allow-naked-datetime/) next
                if (ann == NR - 1) next
                printf "%s:%d: %s\n", f, NR, $0
            }
        }
    ' "${file}")
done < <(find "${ROOT}/src" -type f -name "*.rs" -print0)

if (( errors > 0 )); then
    echo "[lint] ${errors} naked-datetime / UTC-format violation(s) found." >&2
    exit 1
fi

echo "[lint] no naked datetime accessor in templates."
