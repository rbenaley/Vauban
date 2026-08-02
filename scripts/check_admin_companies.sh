#!/usr/bin/env bash
# Structural invariants for admin client companies surface.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() {
  echo "check_admin_companies: $*" >&2
  exit 1
}

LIST="src/app/admin/companies.rs"
SHARD="src/app/admin/companies/search_shard.rs"
NEW="src/app/admin/companies/new.rs"
EDIT="src/app/admin/companies/company_id.rs"
FORM="src/app/admin/companies/form.rs"
SEATS="src/seats.rs"
ACCOUNTS="src/companies_accounts.rs"
MODELS="src/models/mod.rs"
CONFIG="src/config.rs"

[[ -f "$LIST" ]] || fail "missing $LIST"
[[ -f "$SHARD" ]] || fail "missing $SHARD"
[[ -f "$NEW" ]] || fail "missing $NEW"
[[ -f "$EDIT" ]] || fail "missing $EDIT"
[[ -f "$FORM" ]] || fail "missing $FORM"
[[ -f "$SEATS" ]] || fail "missing $SEATS"
[[ -f "$ACCOUNTS" ]] || fail "missing $ACCOUNTS"

grep -n 'method="POST"' "$FORM" >/dev/null || fail "$FORM must POST compose form"
grep -nE '#\[route\(POST' "$NEW" >/dev/null || fail "$NEW must define POST create route"
grep -n 'companies_manage' "$NEW" >/dev/null || fail "$NEW must gate on companies_manage"
grep -n 'toasty::create!(Organization' "$NEW" >/dev/null || fail "$NEW must create Organization"
grep -n 'max_accounts_per_org\|sync_org_accounts' "$NEW" >/dev/null \
  || fail "$NEW must use configurable seat cap / sync accounts"
grep -n 'see_other' "$NEW" >/dev/null || fail "$NEW save must use see_other (303 PRG)"
grep -nE 'Err\(redirect\(' "$NEW" >/dev/null \
  && fail "$NEW must not Err(redirect) on POST (307 re-POSTs / empties download)"
grep -n 'method="GET"' "$NEW" >/dev/null && fail "$NEW must not use method=GET"
if grep -nE 'max-width:\s*(720|820)px' "$NEW" "$EDIT" "$FORM" >/dev/null 2>&1; then
  fail "company compose must not constrain content width (Concept full width)"
fi
if grep -nE 'type="password"' "$NEW" "$EDIT" "$FORM" >/dev/null 2>&1; then
  fail "company forms must be email-only (no password fields)"
fi

grep -nE '#\[route\(POST "/admin/companies/\{company_id\}"\)' "$EDIT" >/dev/null \
  || fail "$EDIT must expose POST update route"
grep -nE '#\[route\(POST "/admin/companies/\{company_id\}/delete"\)' "$EDIT" >/dev/null \
  || fail "$EDIT must expose POST delete route"
grep -n 'sync_org_accounts' "$EDIT" >/dev/null || fail "$EDIT must sync accounts"
grep -n 'see_other' "$EDIT" >/dev/null || fail "$EDIT save/delete must use see_other (303 PRG)"
grep -nE 'Err\(redirect\(' "$EDIT" >/dev/null \
  && fail "$EDIT must not Err(redirect) on POST (307 re-POSTs / empties download)"
grep -n 'USER ACCOUNTS' "$FORM" >/dev/null || fail "$FORM must show USER ACCOUNTS section"
grep -n 'fn company_form_response' "$FORM" >/dev/null \
  || fail "$FORM must wrap POST re-renders via company_form_response"
grep -n 'fn render_admin_page' src/app/admin.rs >/dev/null \
  || fail "admin.rs must expose render_admin_page for POST shell wrap"
grep -nE 'name=\(field\)|email_' "$FORM" >/dev/null || fail "$FORM must collect indexed email_N fields"
grep -n 'account_rows' "$FORM" >/dev/null || fail "$FORM must send account_rows"
grep -n 'compose_action' "$FORM" >/dev/null || fail "$FORM must use compose_action"

grep -n '\+ New company' "$LIST" >/dev/null || fail "$LIST CTA must be + New company"
grep -n 'max_accounts_per_org' "$LIST" >/dev/null || fail "$LIST must read max_accounts_per_org"
grep -n 'COMPANIES_PAGE_SIZE' "$LIST" >/dev/null || fail "$LIST must use COMPANIES_PAGE_SIZE"
grep -n 'list_toolbar' "$LIST" >/dev/null || fail "$LIST must use list_toolbar pager"
grep -n 'page: Option<u32>' "$LIST" >/dev/null || fail "$LIST AdminCompaniesQuery must include page"
grep -n 'with_page_param' "$LIST" >/dev/null || fail "$LIST pager must use with_page_param"
grep -n 'admin_companies_search_results' "$LIST" >/dev/null \
  || fail "$LIST must invoke live search shard"
grep -n 'type="search"' "$LIST" >/dev/null || fail "$LIST must expose search input"
grep -n 'USER ACCOUNTS' "$SHARD" >/dev/null || fail "$SHARD cards must show USER ACCOUNTS"
grep -n 'vb-account-pill' "$SHARD" >/dev/null || fail "$SHARD must render account pills"
grep -n '/admin/companies/{}' "$SHARD" >/dev/null \
  || fail "$SHARD Edit links must use company id"
grep -n 'delete=' "$SHARD" >/dev/null || fail "$SHARD must open delete confirm"
grep -n 'ico_trash' "$SHARD" >/dev/null || fail "$SHARD must use ico_trash"
grep -n 'load_company_cards_page' "$SHARD" >/dev/null \
  || fail "$SHARD must page via load_company_cards_page (SQL limit/offset)"
LOAD="src/app/admin/companies/load.rs"
grep -n 'COMPANIES_PAGE_SIZE' "$LOAD" >/dev/null \
  || fail "$LOAD must use COMPANIES_PAGE_SIZE"
grep -nE 'limit\(|offset\(' "$LOAD" >/dev/null \
  || fail "$LOAD must SQL page with limit/offset"
if grep -nE '@click|::bind' "$LIST" >/dev/null 2>&1; then
  fail "$LIST must not use @click / :bind for pagination"
fi
bash scripts/check_admin_companies_search_shard.sh

grep -n 'MAX_USERS_PER_COMPANY' "$MODELS" >/dev/null || fail "$MODELS must define MAX_USERS_PER_COMPANY"
grep -n 'max_accounts_per_org' "$CONFIG" >/dev/null || fail "$CONFIG must define max_accounts_per_org"
grep -n 'struct OrgConfig' "$CONFIG" >/dev/null || fail "$CONFIG must define OrgConfig"
grep -n 'can_add_member' "$SEATS" >/dev/null || fail "$SEATS must define can_add_member"
grep -n 'membership_count' "$SEATS" >/dev/null || fail "$SEATS must define membership_count"
grep -n '\.count()' "$SEATS" >/dev/null \
  || fail "$SEATS membership_count must use Toasty .count()"
if grep -n 'rows\.len()' "$SEATS" >/dev/null; then
  fail "$SEATS must not use rows.len() for membership_count"
fi
grep -n 'fn normalize_emails' "$ACCOUNTS" >/dev/null || fail "$ACCOUNTS must define normalize_emails"
grep -n 'fn parse_portal_email' "$ACCOUNTS" >/dev/null || fail "$ACCOUNTS must define parse_portal_email"
grep -n 'fn normalize_contact_email' "$ACCOUNTS" >/dev/null \
  || fail "$ACCOUNTS must define normalize_contact_email"
grep -n 'fn format_technical_contact' "$ACCOUNTS" >/dev/null \
  || fail "$ACCOUNTS must define format_technical_contact"
grep -n 'Mailbox::new' "$ACCOUNTS" >/dev/null || fail "$ACCOUNTS must validate via Mailbox::new"
grep -n 'Result<Vec<String>, String>' "$ACCOUNTS" >/dev/null \
  || fail "$ACCOUNTS normalize_emails must return Result (fail-closed)"
grep -n 'fn sync_org_accounts' "$ACCOUNTS" >/dev/null || fail "$ACCOUNTS must define sync_org_accounts"
grep -n 'normalize_emails(emails_raw)?' "$NEW" >/dev/null \
  || fail "$NEW must propagate normalize_emails errors"
grep -n 'normalize_emails(emails_raw)?' "$EDIT" >/dev/null \
  || fail "$EDIT must propagate normalize_emails errors"
grep -n 'normalize_contact_email' "$NEW" >/dev/null \
  || fail "$NEW must validate contact email via normalize_contact_email"
grep -n 'normalize_contact_email' "$EDIT" >/dev/null \
  || fail "$EDIT must validate contact email via normalize_contact_email"
grep -n 'name="contact_name"' "$FORM" >/dev/null \
  || fail "$FORM must expose contact_name field"
grep -n 'name="contact_email"' "$FORM" >/dev/null \
  || fail "$FORM must expose contact_email field"
grep -n 'name="contact"' "$FORM" >/dev/null \
  && fail "$FORM must not use legacy single contact field"
grep -n 'technical_contact_name' "$MODELS" >/dev/null \
  || fail "$MODELS must define technical_contact_name"
grep -n 'technical_contact_email' "$MODELS" >/dev/null \
  || fail "$MODELS must define technical_contact_email"
grep -n 'technical_contact:' "$MODELS" >/dev/null \
  && fail "$MODELS must not keep legacy technical_contact field"
[[ -f toasty/migrations/0006_technical_contact_name_email.sql ]] \
  || fail "missing toasty/migrations/0006_technical_contact_name_email.sql"
grep -n 'technical_contact_name' toasty/migrations/0006_technical_contact_name_email.sql >/dev/null \
  || fail "migration 0006 must introduce technical_contact_name"
grep -n 'technical_contact_email' toasty/migrations/0006_technical_contact_name_email.sql >/dev/null \
  || fail "migration 0006 must introduce technical_contact_email"
grep -n 'DROP COLUMN "technical_contact"' toasty/migrations/0006_technical_contact_name_email.sql \
  >/dev/null && fail "migration 0006 must not drop technical_contact without rename"

grep -n 'max_accounts_per_org' config/default.toml >/dev/null \
  || fail "config/default.toml must set org.max_accounts_per_org"
grep -n 'max_accounts_per_org' config/vcp.conf >/dev/null \
  || fail "config/vcp.conf must set org.max_accounts_per_org"
grep -nE 'features\s*=\s*\[.*"mail"' Cargo.toml >/dev/null \
  || fail "Cargo.toml must enable topcoat mail feature"
grep -n 'FileTransport' src/app.rs >/dev/null || fail "src/app.rs must register FileTransport MailConfig"
grep -n 'RouterBuilderMailExt\|\.mail(' src/app.rs >/dev/null \
  || fail "src/app.rs must wire .mail(MailConfig…)"

echo "check_admin_companies: OK"
