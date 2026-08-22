#!/usr/bin/env bash
# Structural invariants for /{org}/account company-fiche parity.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() {
  echo "check_org_account: $*" >&2
  exit 1
}

PAGE="src/app/org/account.rs"

[[ -f "$PAGE" ]] || fail "missing $PAGE"

grep -n 'account_read' "$PAGE" >/dev/null \
  || fail "$PAGE must gate on account_read"
grep -n 'require_org' "$PAGE" >/dev/null \
  || fail "$PAGE must call require_org"
grep -n 'capability_denied' "$PAGE" >/dev/null \
  || fail "$PAGE must deny missing capability"
grep -n 'account_address_display' "$PAGE" >/dev/null \
  || fail "$PAGE must display address via account_address_display"
grep -n 'org.address' "$PAGE" >/dev/null \
  || fail "$PAGE must read org.address"
grep -n 'data-vcp-build' "$PAGE" >/dev/null \
  || fail "$PAGE must mark the reserved-tenant build on data-vcp-build"
HELPERS="src/companies_accounts.rs"
grep -n 'fn account_address_display' "$HELPERS" >/dev/null \
  || fail "$HELPERS must define account_address_display"
grep -n 'fn product_label' src/build_info.rs >/dev/null \
  || fail "src/build_info.rs must define product_label"
grep -n 'VCP_GIT_HASH' build.rs >/dev/null \
  || fail "build.rs must emit VCP_GIT_HASH"
grep -n 'org.vat' "$PAGE" >/dev/null \
  || fail "$PAGE must render org.vat"
grep -n 'lts_subscriptions' "$PAGE" >/dev/null \
  || fail "$PAGE must render lts_subscriptions"
grep -n 'industrial_lts_subscriptions' "$PAGE" >/dev/null \
  || fail "$PAGE must render industrial_lts_subscriptions"
grep -n 'USER ACCOUNTS' "$PAGE" >/dev/null \
  || fail "$PAGE must show USER ACCOUNTS section"
grep -n 'vb-account-pill\|member_emails' "$PAGE" >/dev/null \
  || fail "$PAGE must list member emails"
grep -n 'Membership::all' "$PAGE" >/dev/null \
  || fail "$PAGE must load memberships for account pills"
grep -n 'account_member_pill_class\|is-you' "$PAGE" >/dev/null \
  || fail "$PAGE must highlight the session member pill in USER ACCOUNTS"
grep -n 'ctx.user.email' "$PAGE" >/dev/null \
  || fail "$PAGE must read ctx.user.email to mark the session pill"
grep -nE 'SESSION|Signed in as|data-account-signed-in' "$PAGE" >/dev/null \
  && fail "$PAGE must not show a SESSION / Signed in as block (pill highlight only)"
# Legacy Concept mockup label.
grep -n 'SIGNED-IN USER' "$PAGE" >/dev/null \
  && fail "$PAGE must not use the SIGNED-IN USER mockup label"
grep -nE 'Supported builds|supported_builds' "$PAGE" >/dev/null \
  && fail "$PAGE must not show supported_builds in SUBSCRIPTION"
# No hardcoded Acme mockup copy.
if grep -nE 'Acme Infrastructure|l\.martin@acme' "$PAGE" >/dev/null; then
  fail "$PAGE must not hardcode Acme mockup fixtures"
fi
LOGIN="src/app/login.rs"
grep -n 'acme-infrastructure' "$LOGIN" >/dev/null \
  && fail "$LOGIN must not hardcode acme-infrastructure as login landing fallback"
grep -n 'fn is_signed_in_member' "$HELPERS" >/dev/null \
  || fail "$HELPERS must define is_signed_in_member"
grep -n 'fn account_member_pill_class' "$HELPERS" >/dev/null \
  || fail "$HELPERS must define account_member_pill_class"
CSS="styles.css"
grep -n 'vb-account-pill.is-you' "$CSS" >/dev/null \
  || fail "$CSS must style .vb-account-pill.is-you"

echo "check_org_account: OK"
