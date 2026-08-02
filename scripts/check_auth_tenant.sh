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

# Org context must be request-memoized (layout + page share one lookup).
if ! grep -nE '#\[memoize\]' src/auth.rs >/dev/null; then
  fail "src/auth.rs must use #[memoize]"
fi
if ! awk '/#\[memoize\]/{m=1; next} m && /async fn org_context/{found=1; exit} /^pub |^async |^fn /{m=0} END{exit !found}' src/auth.rs; then
  fail "#[memoize] must annotate org_context (backing require_org)"
fi
if ! grep -n 'org_context(cx, slug)' src/auth.rs >/dev/null; then
  fail "require_org must call memoized org_context"
fi

# Admin compose forms must POST (OriginLayer / PRG), not GET stubs.
# Companies compose markup lives in form.rs (shared by new + edit).
for f in \
  src/app/admin/docs/new.rs \
  src/app/admin/releases/new.rs \
  src/app/admin/companies/form.rs
do
  if grep -n 'method="GET"' "$f" >/dev/null 2>&1; then
    fail "$f must not use method=GET on compose forms"
  fi
  if ! grep -n 'method="POST"' "$f" >/dev/null 2>&1; then
    fail "$f must use method=POST on compose forms"
  fi
done

# Admin nest must gate via require_staff (which enforces admin_view).
if ! grep -n 'require_staff' src/app/admin.rs >/dev/null; then
  fail "src/app/admin.rs layout must call require_staff"
fi
if ! grep -n 'require_admin_view' src/auth.rs >/dev/null; then
  fail "require_staff must call require_admin_view"
fi
# /admin/* must not leak via 403 for clients / anonymous (anti-enumeration).
if ! awk '
  /pub async fn require_staff/ { in_fn=1 }
  in_fn && /portal_role != PORTAL_ROLE_ADMIN/ { saw_role=1 }
  in_fn && saw_role && /not_found\(\)/ { found=1; exit }
  in_fn && /^pub async fn |^pub fn / && !/require_staff/ { in_fn=0; saw_role=0 }
  END { exit !found }
' src/auth.rs; then
  fail "require_staff must map non-staff to not_found (not forbidden)"
fi
if awk '
  /pub async fn require_staff/ { in_fn=1 }
  in_fn && /forbidden\(\)/ { bad=1; exit }
  in_fn && /^pub async fn |^pub fn / && !/require_staff/ { in_fn=0 }
  END { exit !bad }
' src/auth.rs; then
  fail "require_staff must not return forbidden (anti-enumeration)"
fi

# Policy catalogue file must exist and mention admin view.
POLICY="config/access/default_policy.csv"
[[ -f "$POLICY" ]] || fail "missing $POLICY"
grep -nE 'admin,[[:space:]]*view' "$POLICY" >/dev/null || fail "$POLICY must grant admin,view"

# Authenticated entry must redirect to portal home (no continue-button chrome).
if grep -REn --include='*.rs' -e 'Continue to portal' src/app/ >/dev/null 2>&1; then
  fail "src/app must not render a Continue to portal button (redirect instead)"
fi
if ! grep -n 'home_org_slug' src/app.rs >/dev/null; then
  fail "GET / must call home_org_slug for session landing"
fi
if ! grep -n 'home_org_slug' src/app/login.rs >/dev/null; then
  fail "GET /login must call home_org_slug when a session is present"
fi
if ! grep -nE 'Err\(redirect\(' src/app/login.rs >/dev/null; then
  fail "GET /login must Err(redirect(...)) for authenticated sessions"
fi
if ! grep -n 'fn resolve_home_org_slug' src/auth.rs >/dev/null; then
  fail "src/auth.rs must expose resolve_home_org_slug (pure landing decision)"
fi

# Navigational GET hubs use redirect (307), not see_other (303 PRG).
if ! grep -A10 'async fn root' src/app.rs | grep -q 'Err(redirect('; then
  fail "GET / (root) must Err(redirect(...))"
fi
if grep -A10 'async fn root' src/app.rs | grep -q 'see_other'; then
  fail "GET / must not use see_other"
fi
if ! grep -A8 'async fn admin_index' src/app/admin.rs | grep -q 'Err(redirect('; then
  fail "GET /admin must Err(redirect(...))"
fi
if ! grep -A3 'async fn redirect_reserved_issues_list' src/app/org/issues.rs \
  | grep -q 'Err(redirect('; then
  fail "GET /vauban/issues must Err(redirect(...))"
fi
if ! grep -A3 'async fn redirect_reserved_issues_create' src/app/org/issues.rs \
  | grep -q 'see_other'; then
  fail "POST /vauban/issues alias must keep see_other"
fi

# Capability entry denials must use capability_denied (404), not forbidden.
if ! grep -n 'fn capability_denied' src/auth.rs >/dev/null; then
  fail "src/auth.rs must expose capability_denied"
fi
# Entry-gate forbidden() only allowed on download / ephemeral action paths.
if grep -REn --include='*.rs' -e 'forbidden\(\)' src/app/ \
  | grep -v 'builds/download\.rs' \
  | grep -v 'builds/ephemeral\.rs' \
  >/dev/null 2>&1; then
  grep -REn --include='*.rs' -e 'forbidden\(\)' src/app/ \
    | grep -v 'builds/download\.rs' \
    | grep -v 'builds/ephemeral\.rs' >&2 || true
  fail "entry gates must use capability_denied (404); only download/ephemeral may forbidden()"
fi

# Reserved org is staff-only inside org_context.
if ! grep -n 'RESERVED_ORG_SLUG' src/auth.rs >/dev/null; then
  fail "org_context must reference RESERVED_ORG_SLUG"
fi
if ! awk '
  /async fn org_context/ { in_fn=1 }
  in_fn && /is_reserved/ { saw=1 }
  in_fn && saw && /portal_role != PORTAL_ROLE_ADMIN/ { found=1; exit }
  in_fn && /^pub async fn |^pub fn / && !/org_context/ { in_fn=0 }
  END { exit !found }
' src/auth.rs; then
  fail "org_context must deny reserved org for non-staff"
fi

# require_org_admin must not remap require_org failure to forbidden.
if awk '
  /pub async fn require_org_admin/ { in_fn=1 }
  in_fn && /forbidden\(\)/ { bad=1; exit }
  in_fn && /^pub async fn |^pub fn / && !/require_org_admin/ { in_fn=0 }
  END { exit !bad }
' src/auth.rs; then
  fail "require_org_admin must not return forbidden (anti-enumeration)"
fi

# OriginLayer CSRF must stay enabled (no config / API bypass).
if grep -REn --include='*.rs' --include='*.toml' --include='*.conf' \
  -e 'dangerous_disable_origin_verification' \
  src/ config/ >/dev/null 2>&1; then
  fail "dangerous_disable_origin_verification must not appear in src/ or config/"
fi
if ! grep -n 'trust_origin' src/app.rs >/dev/null; then
  fail "router must trust_origin from server.public_origins"
fi

# Login must always verify (dummy hash path) and use the rate limiter.
if ! grep -n 'verify_login_password' src/app/login.rs >/dev/null; then
  fail "login must call verify_login_password (dummy Argon2 path)"
fi
if ! grep -n 'LoginRateLimiter' src/app/login.rs >/dev/null; then
  fail "login must use LoginRateLimiter"
fi
if ! grep -n 'LoginRateLimiter' src/app.rs >/dev/null; then
  fail "router must install LoginRateLimiter in app_context"
fi
for f in config/default.toml config/development.toml config/vcp.conf; do
  grep -n 'max_attempts' "$f" >/dev/null || fail "$f must define [login] max_attempts"
  grep -n 'window_secs' "$f" >/dev/null || fail "$f must define [login] window_secs"
  grep -n 'lockout_secs' "$f" >/dev/null || fail "$f must define [login] lockout_secs"
done
# Testing uses an elevated ceiling so suite login floods do not lock out.
grep -n 'max_attempts' config/testing.toml >/dev/null || fail "config/testing.toml must define [login] max_attempts"

echo "check_auth_tenant: OK"
