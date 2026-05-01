#!/usr/bin/env bash
# Lint guard: WebSocket logging convention.
#
# Why: the audit (May 2026) found that WS lifecycle logs were
# inconsistent across handlers -- the Notifications channel emitted
# its close-cause at `debug!` while every other channel used `info!`,
# making the close reason invisible at the default log level. The
# unified convention is documented in
# `.cursor/rules/websocket-logging.mdc`. This script pins the convention
# at the source level so a future PR cannot silently regress.
#
# Companion enforcers:
#   - vauban-web/tests/web/websocket_logging_test.rs       (pin tests)
#   - vauban-web/src/services/broadcast.rs::tests          (cardinality)
#
# What we forbid in `src/handlers/websocket.rs`:
#
#   1. Legacy free-form lifecycle wordings -- replaced by the canonical
#      `WebSocket connection requested` / `WebSocket connected` /
#      `WebSocket closed` / `WebSocket disconnected` quartet.
#
#   2. A lifecycle message emitted by `debug!`/`warn!`/`error!` (must
#      always be `info!`).
#
#   3. A `WebSocket connected` line that does NOT carry the `channel = `
#      structured field.
#
#   4. A `WebSocket closed` line that does NOT carry the `cause = `
#      structured field.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HANDLERS_FILE="${ROOT}/src/handlers/websocket.rs"

if [[ ! -f "${HANDLERS_FILE}" ]]; then
    echo "[lint] WebSocket handlers file not found: ${HANDLERS_FILE}" >&2
    exit 2
fi

fail=0

# ---- 1. Legacy wordings ----------------------------------------------------
# Each of these used to live in `handlers/websocket.rs` and contributed
# to the inconsistent logging surface. The post-audit unification folds
# them all into the canonical four-event lifecycle.
LEGACY_WORDINGS=(
    '"Client requested close"'
    '"WebSocket stream ended"'
    '"Session WS close requested"'
    '"RDP client requested close"'
    '"RDP WebSocket stream ended"'
    '"Dashboard WebSocket connected"'
    '"Dashboard WebSocket disconnected"'
    '"Notifications WebSocket connected with personalized session support"'
    '"Notifications WebSocket disconnected"'
    '"Active sessions list WebSocket connected"'
    '"Active sessions list WebSocket disconnected"'
    '"Session list WebSocket connected"'
    '"Session list WebSocket disconnected"'
    '"Session WebSocket connected"'
    '"Session WebSocket disconnected"'
    '"Terminal WebSocket connected"'
    '"Terminal WebSocket disconnected"'
    '"RDP WebSocket connected"'
    '"RDP WebSocket disconnected"'
    '"WebSocket error"'
)
for wording in "${LEGACY_WORDINGS[@]}"; do
    # `grep -F` for literal string match; `|| true` keeps `set -e` happy
    # on no-match.
    hits=$(grep -Fn "${wording}" "${HANDLERS_FILE}" || true)
    if [[ -n "${hits}" ]]; then
        echo "[lint] Legacy WS log wording forbidden: ${wording}" >&2
        echo "${hits}" >&2
        fail=1
    fi
done

# ---- 2. Lifecycle events at non-info! levels -------------------------------
# Match `<macro>!(...)` opening lines (multi-line tracing macro
# arguments are caught by the pin tests; this script catches the
# common single-line case).
for level in debug warn error trace; do
    # Examples flagged: debug!(... "WebSocket closed");
    pattern="${level}!\\([^)]*\"WebSocket (connected|disconnected|closed|connection requested)\""
    hits=$(grep -REn --include='*.rs' -E "${pattern}" "${HANDLERS_FILE}" || true)
    if [[ -n "${hits}" ]]; then
        echo "[lint] Lifecycle WS log emitted at ${level}! level (must be info!):" >&2
        echo "${hits}" >&2
        fail=1
    fi
done

# ---- 3. `WebSocket connected` lines must carry channel = -------------------
# We enforce this at the test layer (websocket_logging_test) where we
# can correlate multi-line macros. The bash variant catches the
# single-line case which is the most common regression vector.
single_line_connected=$(grep -nE 'info!\([^)]*"WebSocket connected"' "${HANDLERS_FILE}" || true)
if [[ -n "${single_line_connected}" ]]; then
    while IFS= read -r line; do
        if ! echo "${line}" | grep -q 'channel = '; then
            echo "[lint] Single-line \`WebSocket connected\` info!() must carry the \`channel = \` field:" >&2
            echo "${line}" >&2
            fail=1
        fi
    done <<<"${single_line_connected}"
fi

# ---- 4. `WebSocket closed` lines must carry cause = ------------------------
single_line_closed=$(grep -nE 'info!\([^)]*"WebSocket closed"' "${HANDLERS_FILE}" || true)
if [[ -n "${single_line_closed}" ]]; then
    while IFS= read -r line; do
        if ! echo "${line}" | grep -q 'cause = '; then
            echo "[lint] Single-line \`WebSocket closed\` info!() must carry the \`cause = \` field:" >&2
            echo "${line}" >&2
            fail=1
        fi
    done <<<"${single_line_closed}"
fi

if [[ ${fail} -ne 0 ]]; then
    echo >&2
    echo "[lint] WebSocket logging convention violated -- see" >&2
    echo "[lint]   .cursor/rules/websocket-logging.mdc" >&2
    echo "[lint] for the canonical lifecycle, structured fields, and" >&2
    echo "[lint] level matrix. The pin tests in" >&2
    echo "[lint]   vauban-web/tests/web/websocket_logging_test.rs" >&2
    echo "[lint] cover the multi-line cases this bash lint cannot." >&2
    exit 1
fi

echo "[lint] WebSocket logging convention OK (legacy wordings absent, lifecycle at info!, channel/cause fields present)"
