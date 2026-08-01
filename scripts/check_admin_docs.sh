#!/usr/bin/env bash
# Structural invariants for admin documentation editor surface.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() {
  echo "check_admin_docs: $*" >&2
  exit 1
}

NEW="src/app/admin/docs/new.rs"
DOC="src/app/admin/docs/doc.rs"
LIST="src/app/admin/docs.rs"
CLIENT="src/app/org/docs.rs"
CLIENT_DOC="src/app/org/docs/doc.rs"

[[ -f "$NEW" ]] || fail "missing $NEW"
[[ -f "$DOC" ]] || fail "missing $DOC"

grep -n 'method="POST"' "$NEW" >/dev/null || fail "$NEW must POST compose form"
grep -nE '#\[route\(POST' "$NEW" >/dev/null || fail "$NEW must define POST create route"
grep -n 'docs_write' "$NEW" >/dev/null || fail "$NEW must gate on docs_write"

grep -nE '#\[route\(POST' "$DOC" >/dev/null || fail "$DOC must define POST update/publish routes"
grep -n '/publish' "$DOC" >/dev/null || fail "$DOC must expose publish route"
grep -n '/unpublish' "$DOC" >/dev/null || fail "$DOC must expose unpublish route"
grep -n 'docs_write' "$DOC" >/dev/null || fail "$DOC must gate on docs_write"
grep -n 'docs_write' "$LIST" >/dev/null || fail "$LIST must gate on docs_write"

# Client list must filter PUBLISHED at the Toasty query (not all() alone).
grep -n 'DOC_STATUS_PUBLISHED' "$CLIENT" >/dev/null \
  || fail "$CLIENT must filter DOC_STATUS_PUBLISHED"
grep -n 'fields().status()' "$CLIENT" >/dev/null \
  || fail "$CLIENT load_filtered_docs must filter via fields().status()"
grep -n 'DOC_STATUS_PUBLISHED' "$CLIENT_DOC" >/dev/null \
  || fail "$CLIENT_DOC must require PUBLISHED status"

# DB-backed dialect bodies — no Concept HTML bypass in the client modal.
if grep -n 'quick_start_blocks\|is_seed_placeholder_or_outline\|placeholder_blocks' "$CLIENT_DOC" >/dev/null 2>&1; then
  fail "$CLIENT_DOC must not bypass DB body with hardcoded HTML helpers"
fi
grep -n 'docs_body::parse\|docs_body::' "$CLIENT_DOC" >/dev/null \
  || fail "$CLIENT_DOC must render via docs_body::parse"
test -f src/docs_body.rs || fail "src/docs_body.rs dialect parser must exist"
grep -n 'pub fn parse' src/docs_body.rs >/dev/null \
  || fail "docs_body.rs must export parse"
grep -n 'pub fn escape_html' src/docs_body.rs >/dev/null \
  || fail "docs_body.rs must export escape_html"

# Versioning UX: Save redirects to list; published save bumps version.
grep -nE 'see_other\("/admin/docs"\)|see_other\(&list\)' "$DOC" >/dev/null \
  || fail "$DOC Save must redirect to /admin/docs list"
grep -n 'bump_version' "$DOC" >/dev/null \
  || fail "$DOC must bump version when saving a published article"
grep -n 'unpublish_other_published' "$DOC" >/dev/null \
  || fail "$DOC must unpublish sibling published rows for the same slug"
grep -n 'Publish new version' "$DOC" >/dev/null \
  || fail "$DOC must label published save as Publish new version"
grep -n 'article.id' "$LIST" >/dev/null \
  || fail "$LIST Edit links must use article id"
grep -nE 'sort_by(_key)?' "$LIST" >/dev/null \
  || fail "$LIST must sort by updated_at"
grep -n 'updated_at' "$LIST" >/dev/null \
  || fail "$LIST sort must use updated_at"
grep -n 'cmp_version_desc' "$LIST" >/dev/null \
  || fail "$LIST must tie-break sort with cmp_version_desc"
# Exclusivity demotion must not stamp timestamps (keeps new version above old).
if grep -A20 'pub async fn unpublish_other_published' src/docs_version.rs \
  | grep -v '^[[:space:]]*//' | grep -v '^[[:space:]]*\*' | grep -q 'updated_at'; then
  fail "unpublish_other_published must not bump updated_at"
fi
grep -n 'Unpublish' "$LIST" >/dev/null \
  || fail "$LIST must expose Unpublish action"
grep -n 'Publish' "$LIST" >/dev/null \
  || fail "$LIST must expose Publish action"
grep -n 'doc_status_badge_class' "$LIST" >/dev/null \
  || fail "$LIST must color STATUS via doc_status_badge_class"
if grep -n 'vb-badge soft' "$LIST" | grep -q 'article.status'; then
  fail "$LIST must not hardcode vb-badge soft on article.status"
fi
grep -n 'fn doc_status_badge_class' src/ui.rs >/dev/null \
  || fail "src/ui.rs must define doc_status_badge_class"
grep -n 'delete=' "$LIST" >/dev/null \
  || fail "$LIST Delete must open ?delete= confirm"
grep -n 'ico_trash\|Delete permanently' "$LIST" >/dev/null \
  || fail "$LIST must include delete confirm UI"
# SSR list pagination (shared list_page + toolbar pager).
grep -nE 'LIST_PAGE_SIZE' "$LIST" >/dev/null \
  || fail "$LIST must use LIST_PAGE_SIZE"
grep -n 'list_toolbar' "$LIST" >/dev/null \
  || fail "$LIST must use list_toolbar for pager"
grep -n 'page: Option<u32>' "$LIST" >/dev/null \
  || fail "$LIST AdminDocsQuery must include page: Option<u32>"
grep -n 'page_slice' "$LIST" >/dev/null \
  || fail "$LIST must slice rows with page_slice"
grep -n 'sort_by_key' "$CLIENT" >/dev/null \
  || fail "$CLIENT load_filtered_docs must sort by updated_at"
test -f src/docs_version.rs || fail "src/docs_version.rs must exist"
grep -n 'pub fn bump_version' src/docs_version.rs >/dev/null \
  || fail "docs_version.rs must export bump_version"
grep -n 'pub fn is_delete_confirm' src/docs_version.rs >/dev/null \
  || fail "docs_version.rs must export is_delete_confirm"
grep -nE '/delete' "$DOC" >/dev/null \
  || fail "$DOC must expose POST delete route"
grep -n 'is_delete_confirm' "$DOC" >/dev/null \
  || fail "$DOC delete must validate type-delete confirm"
if grep -n 'max-width: 720px' "$NEW" "$DOC" >/dev/null 2>&1; then
  fail "compose/edit must not use max-width: 720px (Concept full width)"
fi
grep -n 'Compose article' "$NEW" >/dev/null \
  || fail "$NEW title must be Compose article"
grep -n 'Compose article' "$DOC" >/dev/null \
  || fail "$DOC title must be Compose article"
grep -n 'vb-form-grid2' "$NEW" >/dev/null \
  || fail "$NEW must use Category|Excerpt grid"
grep -n 'vb-form-grid2' "$DOC" >/dev/null \
  || fail "$DOC must use Category|Excerpt grid"
grep -n 'ico_trash' src/app/_components/icons.rs >/dev/null \
  || fail "ico_trash SVG helper must exist"

echo "check_admin_docs: OK"
