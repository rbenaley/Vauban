#!/usr/bin/env bash
# Structural invariants for admin client companies surface.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() {
  echo "check_admin_companies: $*" >&2
  exit 1
}

NEW="src/app/admin/companies/new.rs"
SEATS="src/seats.rs"
MODELS="src/models/mod.rs"

[[ -f "$NEW" ]] || fail "missing $NEW"
[[ -f "$SEATS" ]] || fail "missing $SEATS"

grep -n 'method="POST"' "$NEW" >/dev/null || fail "$NEW must POST compose form"
grep -nE '#\[route\(POST' "$NEW" >/dev/null || fail "$NEW must define POST create route"
grep -n 'companies_manage' "$NEW" >/dev/null || fail "$NEW must gate on companies_manage"
grep -n 'toasty::create!(Organization' "$NEW" >/dev/null || fail "$NEW must create Organization"
grep -n 'MAX_USERS_PER_COMPANY' "$NEW" >/dev/null || fail "$NEW must surface seat limit"
grep -n 'method="GET"' "$NEW" >/dev/null && fail "$NEW must not use method=GET"
if grep -nE 'max-width:\s*(720|820)px' "$NEW" >/dev/null 2>&1; then
  fail "$NEW must not constrain content width (Concept full width)"
fi

grep -n 'MAX_USERS_PER_COMPANY' "$MODELS" >/dev/null || fail "$MODELS must define MAX_USERS_PER_COMPANY"
grep -n 'can_add_member' "$SEATS" >/dev/null || fail "$SEATS must define can_add_member"
grep -n 'membership_count' "$SEATS" >/dev/null || fail "$SEATS must define membership_count"

echo "check_admin_companies: OK"
