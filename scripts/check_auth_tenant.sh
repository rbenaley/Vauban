#!/usr/bin/env bash
# Structural invariants for auth / tenant / Casbin surfaces.
# Uses grep (POSIX-ish) so `cargo test` / CI work without ripgrep on PATH.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() {
  echo "check_auth_tenant: $*" >&2
  exit 1
}

# No staff/superuser/admin boolean role gates in application code.
if grep -REn --include='*.rs' \
  -e '\bis_admin\b' \
  -e '\bis_staff\b' \
  -e '\bis_superuser\b' \
  -e 'role[[:space:]]*==[[:space:]]*"admin"' \
  -e "role[[:space:]]*==[[:space:]]*'admin'" \
  src/ >/dev/null 2>&1; then
  grep -REn --include='*.rs' \
    -e '\bis_admin\b' \
    -e '\bis_staff\b' \
    -e '\bis_superuser\b' \
    -e 'role[[:space:]]*==[[:space:]]*"admin"' \
    -e "role[[:space:]]*==[[:space:]]*'admin'" \
    src/ >&2 || true
  fail "found forbidden role-string / is_* gates (use Casbin PermissionContext)"
fi

# Tenant isolation helper must stay fail-closed to 404.
if ! grep -n 'ok_or_else(not_found)' src/auth.rs >/dev/null; then
  fail "src/auth.rs must map missing org/membership to not_found"
fi

# Admin nest must consult admin_view.
if ! grep -REn --include='*.rs' 'admin_view' src/app/org/admin.rs src/app/org/admin >/dev/null 2>&1; then
  fail "admin nest must check admin_view"
fi

# Policy catalogue file must exist and mention admin view.
POLICY="config/access/default_policy.csv"
[[ -f "$POLICY" ]] || fail "missing $POLICY"
grep -nE 'admin,[[:space:]]*view' "$POLICY" >/dev/null || fail "$POLICY must grant admin,view"

echo "check_auth_tenant: OK"
