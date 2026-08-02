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
grep -n 'org.address' "$PAGE" >/dev/null \
  || fail "$PAGE must render org.address"
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
grep -n 'SIGNED-IN USER' "$PAGE" >/dev/null \
  && fail "$PAGE must not show SIGNED-IN USER mockup block (company fiche only)"
grep -nE 'Supported builds|supported_builds' "$PAGE" >/dev/null \
  && fail "$PAGE must not show supported_builds in SUBSCRIPTION"
# No hardcoded Acme mockup copy.
if grep -nE 'Acme Infrastructure|l\.martin@acme' "$PAGE" >/dev/null; then
  fail "$PAGE must not hardcode Acme mockup fixtures"
fi
LOGIN="src/app/login.rs"
grep -n 'acme-infrastructure' "$LOGIN" >/dev/null \
  && fail "$LOGIN must not hardcode acme-infrastructure as login landing fallback"

echo "check_org_account: OK"
