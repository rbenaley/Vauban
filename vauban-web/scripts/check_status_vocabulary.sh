#!/usr/bin/env bash
# Lint guard: closed proxy_sessions status vocabulary.
#
# Why: the July 2026 status audit found phantom statuses ('completed'
# written only by the demo seeder, 'consumed' written by nothing at
# all) and select options drifting away from the statuses actually
# written to the column ('/sessions' offered no 'expired' option and
# a dead 'pending' one). The canonical vocabulary lives in
# `SessionStatus::ALL` (src/models/session.rs) and is sealed at the
# DB level by the `proxy_sessions_status_chk` CHECK (migration
# 20260718000000_proxy_sessions_status_chk). This script pins the
# source level: any literal proxy-session status outside the list
# below fails CI before the DB constraint would blow up at runtime.
#
# Companion enforcers:
#   - vauban-web/tests/web/status_vocab_drift_test.rs (pins the list
#     below against SessionStatus::ALL and the migration CHECK)
#   - vauban-web/tests/web/status_vocab_proptest.rs   (invariants)
#
# The CANONICAL list must stay a single space-separated line: the
# drift test parses it.

set -euo pipefail
cd "$(dirname "$0")/.."

CANONICAL="pending approved rejected revoked expired orphaned connecting active disconnected terminated failed waiting_client ews_connected tunnel_active"

# Files that INSERT proxy_sessions rows with a literal status (the
# struct-literal `status: "..."` pattern is too generic to scan
# repo-wide: assets, email outbox and recording fixtures also carry a
# `status:` field).
INSERT_FILES=(
    "src/handlers/web/rdp.rs"
    "src/handlers/web/ssh.rs"
    "src/handlers/web/iacs_tunnel.rs"
    "src/handlers/web/sessions.rs"
    "src/handlers/api/sessions.rs"
    "src/ipc/admin.rs"
    "src/models/session.rs"
)

fail=0

is_canonical() {
    local needle="$1"
    for v in $CANONICAL; do
        if [ "$v" = "$needle" ]; then
            return 0
        fi
    done
    return 1
}

# 1) Literals compared against / assigned to the status column
#    (covers filters, UPDATE ... SET and eq_any member checks).
while IFS= read -r hit; do
    value="$(printf '%s' "$hit" | sed -E 's/.*"([a-z_]+)".*/\1/')"
    location="${hit%%:status*}"
    if ! is_canonical "$value"; then
        echo "FORBIDDEN: non-canonical proxy_sessions status '\"$value\"' at $location"
        echo "           (canonical vocabulary: $CANONICAL)"
        fail=1
    fi
done < <(grep -rnoE '(proxy_sessions::|ps::|dsl::)status\.eq\("[a-z_]+"' src --include='*.rs' \
    | sed -E 's/(proxy_sessions::|ps::|dsl::)status/status/')

# 2) Struct-literal inserts in the known proxy-session INSERT sites.
#    A `status:` literal that does NOT target proxy_sessions (asset
#    seed rows, recording view-models, ...) opts out with an
#    `// allow-status-vocab: <reason>` annotation on the same line or
#    the line immediately above (same convention as allow-role-gate).
while IFS= read -r hit; do
    file="${hit%%:*}"
    rest="${hit#*:}"
    lineno="${rest%%:*}"
    value="$(printf '%s' "$hit" | sed -E 's/.*"([a-z_]+)".*/\1/')"
    line_text="$(sed -n "${lineno}p" "$file")"
    prev_text="$(sed -n "$((lineno - 1))p" "$file")"
    if printf '%s\n%s' "$line_text" "$prev_text" | grep -q 'allow-status-vocab'; then
        continue
    fi
    if ! is_canonical "$value"; then
        echo "FORBIDDEN: non-canonical proxy_sessions status '\"$value\"' at $file:$lineno"
        echo "           (canonical vocabulary: $CANONICAL)"
        fail=1
    fi
done < <(grep -rnoE 'status: "[a-z_]+"' "${INSERT_FILES[@]}")

if [ "$fail" -ne 0 ]; then
    echo ""
    echo "check_status_vocabulary: FAILED"
    echo "Add the new status to SessionStatus::ALL, the"
    echo "proxy_sessions_status_chk migration AND the CANONICAL list of"
    echo "this script (the drift test keeps the three in lock-step)."
    exit 1
fi

echo "check_status_vocabulary: OK"
