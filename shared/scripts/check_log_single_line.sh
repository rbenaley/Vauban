#!/usr/bin/env bash
#
# Lint: every service writes its log through `shared::log_line::SingleLine`.
#
# A service logs text supplied by another process or the network. With
# the plain formatter a line feed in such a value starts a new line that
# reads like an entry of the service itself. `SingleLine` escapes it for
# every call site at once; a service that builds its subscriber without
# it is unprotected.
#
# Rule: in every Rust source outside tests, each `tracing_subscriber::fmt()`
# and `tracing_subscriber::fmt::layer()` is followed by
# `.with_writer(shared::log_line::SingleLine)` (or `SingleLineStderr`) in
# the same expression, and no other `.with_writer(...)` replaces it.
#
# Usage: bash shared/scripts/check_log_single_line.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

status=0
found=0

while IFS= read -r file; do
    # shared/src/log_line.rs builds subscribers on a test sink.
    case "${file}" in
        */shared/src/log_line.rs) continue ;;
    esac
    while IFS= read -r hit; do
        found=$((found + 1))
        line="${hit%%:*}"
        # The builder call and the two lines after it (rustfmt may wrap).
        window="$(sed -n "${line},$((line + 2))p" "${file}" | tr -d ' \n')"
        case "${window}" in
            *"tracing_subscriber::fmt().with_writer(shared::log_line::SingleLine"* | \
            *"tracing_subscriber::fmt::layer().with_writer(shared::log_line::SingleLine"*) ;;
            *)
                echo "ERROR: ${file#"${REPO_DIR}/"}:${line}: subscriber built without shared::log_line::SingleLine"
                status=1
                ;;
        esac
    done < <(grep -n -E 'tracing_subscriber::fmt(::layer)?\(\)' "${file}" || true)
    # A later `.with_writer(...)` replaces the first one.
    while IFS= read -r hit; do
        echo "ERROR: ${file#"${REPO_DIR}/"}:${hit%%:*}: a writer other than shared::log_line replaces SingleLine"
        status=1
    done < <(grep -n -E '\.with_writer\(' "${file}" | grep -v 'shared::log_line::SingleLine' || true)
done < <(find "${REPO_DIR}" \
    \( -path "${REPO_DIR}/target" -o -path "${REPO_DIR}/target-rdp" -o -path "${REPO_DIR}/.git" \
       -o -path "${REPO_DIR}/.cursor" -o -path "${REPO_DIR}/.claude" -o -path '*/tests' \) -prune \
    -o -name '*.rs' -path '*/src/*' -print | sort)

# Other ways to build a subscriber or swap its writer. None is used; one
# appearing would not be seen by the rule above.
while IFS= read -r hit; do
    case "${hit}" in
        */shared/src/log_line.rs:*) continue ;;
    esac
    echo "ERROR: ${hit#"${REPO_DIR}/"}: build the subscriber with tracing_subscriber::fmt() or fmt::layer() and shared::log_line::SingleLine"
    status=1
done < <(grep -rn -E 'tracing_subscriber::fmt::(init|try_init|Subscriber|SubscriberBuilder|Layer|format)\b|use tracing_subscriber::fmt\b|\.map_writer\(|set_global_default\(' \
    --include='*.rs' "${REPO_DIR}" 2>/dev/null \
    | grep -v -E '/(target|target-[^/]*|\.git|\.cursor|\.claude|tests)/' || true)

if [ "${found}" -eq 0 ]; then
    echo "ERROR: no tracing_subscriber::fmt() call found; the lint looks at nothing"
    status=1
fi

if [ "${status}" -eq 0 ]; then
    echo "OK: ${found} log subscribers write through shared::log_line::SingleLine"
fi
exit "${status}"
