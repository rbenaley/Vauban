#!/usr/bin/env bash
# Structural lint: every Askama template struct that exposes a
# `DateTime<Utc>` field (or an `Option<DateTime<Utc>>`) MUST also
# carry the canonical browser-timezone field so the rendered HTML
# can format that datetime via the `|local(...)` filter.
#
# Two equivalent contracts satisfy this rule:
#   1. The struct holds `pub vauban: VaubanConfig` (the
#      `BaseTemplate` family). `VaubanConfig` carries `pub tz:
#      chrono_tz::Tz` since Vauban v0.7.7.
#   2. The struct holds `pub tz: chrono_tz::Tz` directly. Used by
#      pusher tile templates that are rendered standalone (no
#      `BaseTemplate` wrapper).
#
# A struct that carries datetime fields but neither `vauban` nor
# `tz` is a hard error: there is no way to honor the caller's
# timezone preference inside the template.
#
# CI exit code is non-zero on the first offending struct.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TEMPLATES_DIR="${ROOT}/src/templates"

if [[ ! -d "${TEMPLATES_DIR}" ]]; then
    echo "[lint] template-struct directory not found: ${TEMPLATES_DIR}" >&2
    exit 2
fi

errors=0

# Walk every Rust template module. Inside each file we extract every
# `#[derive(..., Template, ...)] pub struct Foo { ... }` block and
# check whether it carries a `DateTime<Utc>` (or
# `Option<DateTime<Utc>>` / `chrono::DateTime<chrono::Utc>`) field
# AND whether it also carries either `vauban: VaubanConfig` or `tz:
# chrono_tz::Tz`. Awk does the structural parsing; bash drives the
# loop.
while IFS= read -r -d '' file; do
    awk -v file="${file}" '
        /#\[derive\(.*Template.*\)\]/ { tagged = 1; next }
        tagged && /^[[:space:]]*pub struct[[:space:]]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]*\{/ {
            # Extract struct name.
            match($0, /pub struct[[:space:]]+[A-Za-z_][A-Za-z0-9_]*/)
            struct_name = substr($0, RSTART, RLENGTH)
            sub(/^pub struct[[:space:]]+/, "", struct_name)
            in_struct = 1
            depth = 1
            has_dt = 0
            has_tz = 0
            tagged = 0
            start_line = NR
            next
        }
        in_struct {
            depth += gsub(/\{/, "{")
            depth -= gsub(/\}/, "}")
            if ($0 ~ /DateTime<[[:space:]]*(chrono::)?Utc[[:space:]]*>/ ) { has_dt = 1 }
            if ($0 ~ /:[[:space:]]*VaubanConfig/) { has_tz = 1 }
            if ($0 ~ /tz[[:space:]]*:[[:space:]]*(chrono_tz::)?Tz/) { has_tz = 1 }
            if (depth <= 0) {
                in_struct = 0
                if (has_dt && !has_tz) {
                    printf("[lint] %s:%d -- struct %s carries DateTime<Utc> but neither `vauban: VaubanConfig` nor `tz: chrono_tz::Tz`\n", file, start_line, struct_name) > "/dev/stderr"
                    print "FAIL"
                }
            }
        }
        # Reset the derive-tag if a non-struct line follows.
        tagged && !/^[[:space:]]*pub struct/ {
            if ($0 ~ /^[[:space:]]*$/) next
            if ($0 ~ /^[[:space:]]*\/\//) next
            tagged = 0
        }
    ' "${file}" | while IFS= read -r line; do
        if [[ "${line}" == "FAIL" ]]; then
            errors=$((errors + 1))
            echo "${errors}" > /tmp/__check_template_carries_tz_err
        fi
    done
done < <(find "${TEMPLATES_DIR}" -type f -name "*.rs" -print0)

if [[ -f /tmp/__check_template_carries_tz_err ]]; then
    errors=$(cat /tmp/__check_template_carries_tz_err)
    rm -f /tmp/__check_template_carries_tz_err
fi

if (( errors > 0 )); then
    echo "[lint] ${errors} template struct(s) lack a tz field." >&2
    exit 1
fi

echo "[lint] every template struct with a DateTime<Utc> carries a tz field."
