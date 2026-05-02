#!/usr/bin/env bash
#
# check_dashboard_user_scoping.sh
#
# Bastion Watch isolation -- L4 (CI lint).
#
# Forbid any function in `vauban-web/src/services/dashboard/` that
# touches `proxy_sessions::table` without going through the scope
# contract:
#
# - The function MUST accept a `scope: DashboardScope` parameter
#   (caller is forced to think about Global vs User), AND
# - The function MUST either (a) match on `scope` to apply
#   `proxy_sessions::user_id.eq(_)`, or (b) carry an explicit
#   `// allow-global-scope: <reason>` annotation acknowledging that
#   the data is gouvernance-wide and not user-scopable.
#
# Pre-existing helpers that are intrinsically global by design
# (e.g. `load_access_posture` aggregates over `users`/`access_rules`,
# never `proxy_sessions`) are out of scope automatically: they don't
# match the `proxy_sessions::table` grep.
#
# Pin tests in `vauban-web/tests/web/bastion_watch_test.rs` provide
# Rust-side coverage; this lint catches single-line regressions
# before `cargo test` even runs.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET_DIR="${ROOT}/src/services/dashboard"

if [ ! -d "${TARGET_DIR}" ]; then
    echo "ERROR: ${TARGET_DIR} not found" >&2
    exit 2
fi

# Step 1: collect every line that mentions `proxy_sessions::table`
# inside the dashboard service tree (the surface gated by this rule).
# Bash 3.2 (macOS default) lacks `mapfile`; use a tmpfile-driven loop
# instead.
RAW_FILE=$(mktemp)
trap 'rm -f "${RAW_FILE}"' EXIT
grep -REn 'proxy_sessions::table' "${TARGET_DIR}" \
    --include='*.rs' \
    > "${RAW_FILE}" || true

if [ ! -s "${RAW_FILE}" ]; then
    # No usage at all -- the rule trivially holds.
    exit 0
fi

violations=0

while IFS= read -r line; do
    [ -z "${line}" ] && continue
    file="${line%%:*}"
    rest="${line#*:}"
    lineno="${rest%%:*}"
    content="${rest#*:}"

    # Skip the line itself if it is annotated. The annotation may
    # appear on the same line OR on the line immediately above
    # (handlers prefer the latter for readability).
    if echo "${content}" | grep -q 'allow-global-scope'; then
        continue
    fi
    if [ "${lineno}" -gt 1 ]; then
        prev=$(sed -n "$((lineno - 1))p" "${file}")
        if echo "${prev}" | grep -q 'allow-global-scope'; then
            continue
        fi
    fi

    # Find the enclosing function signature by walking backwards
    # from the offending line until we hit `fn `. We then check
    # that the signature carries `scope: DashboardScope` (or a
    # by-ref/by-value variant) and that the body either matches
    # on `scope` or calls a helper that does.
    sig_line=$(
        awk -v target="${lineno}" '
            /fn / { last_fn = NR; last_sig = $0 }
            NR == target { print last_fn ":" last_sig; exit }
        ' "${file}"
    )

    if [ -z "${sig_line}" ]; then
        echo "VIOLATION: ${file}:${lineno} touches proxy_sessions::table"
        echo "           but the enclosing function could not be located."
        echo "           Add an explicit '// allow-global-scope: <reason>'"
        echo "           annotation on the line above, or factor the call"
        echo "           into a function that takes 'scope: DashboardScope'."
        violations=$((violations + 1))
        continue
    fi

    sig_text="${sig_line#*:}"
    if ! echo "${sig_text}" | grep -q 'scope'; then
        # The signature might be multi-line. Grab a 5-line window
        # starting at the fn declaration so a parameter on the next
        # line still matches.
        sig_no="${sig_line%%:*}"
        window=$(sed -n "${sig_no},$((sig_no + 6))p" "${file}")
        if ! echo "${window}" | grep -q 'scope'; then
            echo "VIOLATION: ${file}:${lineno} touches proxy_sessions::table"
            echo "           but the enclosing function does not accept a"
            echo "           'scope: DashboardScope' parameter."
            echo "           Either wire the scope or carry an explicit"
            echo "           '// allow-global-scope: <reason>' on the line"
            echo "           above the proxy_sessions::table reference."
            violations=$((violations + 1))
        fi
    fi
done < "${RAW_FILE}"

if [ "${violations}" -gt 0 ]; then
    echo ""
    echo "FAILED: ${violations} dashboard scope violation(s)."
    echo "See .cursor/rules/dashboard-passivity.mdc (User-scope isolation)"
    echo "for the rationale and the canonical scope-application pattern."
    exit 1
fi

exit 0
