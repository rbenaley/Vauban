#!/usr/bin/env bash
# Every users.is_active = true filter must also exclude tombstones.
# Uses grep (not rg) so cargo-test sandboxes without ripgrep still pass.
# Bash 3.2 (macOS default) lacks `mapfile`; use a tmpfile-driven loop.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/src"

fail() {
    echo "check_users_usable_filters.sh: $*" >&2
    exit 1
}

if [[ ! -d "$SRC" ]]; then
    fail "missing $SRC"
fi

# Lines that enable a user row by is_active. api_keys / access_rules / vault
# secrets use the same method name and must not be scanned.
RAW_FILE=$(mktemp)
trap 'rm -f "${RAW_FILE}"' EXIT
grep -REn --include='*.rs' \
    -e '(users|u)::is_active\.eq\(true\)' "$SRC" \
    > "${RAW_FILE}" || true

if [[ ! -s "${RAW_FILE}" ]]; then
    fail "no users::is_active.eq(true) hits -- predicate renamed?"
fi

hits=0
while IFS= read -r hit; do
    [ -z "${hit}" ] && continue
    hits=$((hits + 1))
    file="${hit%%:*}"
    rest="${hit#*:}"
    line="${rest%%:*}"
    start=$((line - 20))
    if [[ "$start" -lt 1 ]]; then
        start=1
    fi
    end=$((line + 5))
    window="$(sed -n "${start},${end}p" "$file")"
    if ! echo "$window" | grep -Eq 'is_deleted\.eq\(false\)'; then
        fail "$file:$line users is_active=true without is_deleted=false in ±20 lines"
    fi
done < "${RAW_FILE}"

echo "check_users_usable_filters.sh: OK (${hits} sites)"
