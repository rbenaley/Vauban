#!/usr/bin/env bash
# Structural invariants for auth / tenant / Casbin surfaces.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() {
  echo "check_auth_tenant: $*" >&2
  exit 1
}

# No staff/superuser/admin boolean role gates in application code.
if rg -n --glob 'src/**/*.rs' \
  -e '\bis_admin\b' \
  -e '\bis_staff\b' \
  -e '\bis_superuser\b' \
  -e 'role\s*==\s*"admin"' \
  -e "role\s*==\s*'admin'" \
  .; then
  fail "found forbidden role-string / is_* gates (use Casbin PermissionContext)"
fi

# Tenant isolation helper must stay fail-closed to 404.
if ! rg -n --glob 'src/auth.rs' 'ok_or_else\(not_found\)' . >/dev/null; then
  fail "src/auth.rs must map missing org/membership to not_found"
fi

# Admin nest must consult admin_view.
if ! rg -n 'admin_view' src/app/org/admin.rs src/app/org/admin/*.rs >/dev/null; then
  fail "admin nest must check admin_view"
fi

# Policy catalogue file must exist and mention admin view.
POLICY="config/access/default_policy.csv"
[[ -f "$POLICY" ]] || fail "missing $POLICY"
rg -n 'admin,\s*view' "$POLICY" >/dev/null || fail "$POLICY must grant admin,view"

echo "check_auth_tenant: OK"
