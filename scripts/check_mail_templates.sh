#!/usr/bin/env bash
# Structural pins for transactional HTML email templates.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() { echo "check_mail_templates: $*" >&2; exit 1; }

for f in email/user-join.html email/user-login.html email/user-leave.html email/issue-event.html; do
  [[ -f "$f" ]] || fail "missing $f"
  grep -q 'cid:vauban-logo' "$f" || fail "$f must use cid:vauban-logo"
  if grep -q 'data:image' "$f"; then
    fail "$f must not embed base64 data: URIs"
  fi
  grep -q '__FROM_ADDRESS__' "$f" || fail "$f must carry __FROM_ADDRESS__"
done

grep -q '__ORG_NAME__' email/user-join.html || fail "join must carry __ORG_NAME__"
grep -q '__MAGIC_URL__' email/user-join.html || fail "join must carry __MAGIC_URL__"
grep -q '__TTL_MINUTES__' email/user-join.html || fail "join must carry __TTL_MINUTES__"
grep -q '__MAGIC_URL__' email/user-login.html || fail "login must carry __MAGIC_URL__"
grep -q '__TTL_MINUTES__' email/user-login.html || fail "login must carry __TTL_MINUTES__"
if grep -q '__ORG_NAME__' email/user-login.html; then
  fail "login must not carry __ORG_NAME__"
fi
grep -q '__ORG_NAME__' email/user-leave.html || fail "leave must carry __ORG_NAME__"
if grep -q '__MAGIC_URL__' email/user-leave.html; then
  fail "leave must not carry __MAGIC_URL__"
fi

[[ -f email/vauban-logo.png ]] || fail "missing email/vauban-logo.png"
[[ -f email/design-tokens.json ]] || fail "missing email/design-tokens.json"
[[ -f email/README.md ]] || fail "missing email/README.md"

MAILER=src/mailer.rs
TMPL=src/mail_templates.rs
VIEWS=src/mail_views.rs
grep -n 'mail!' "$MAILER" >/dev/null \
  || fail "$MAILER must send via mail!"
grep -n 'deliver_branded' "$MAILER" >/dev/null \
  || fail "$MAILER must deliver via deliver_branded"
if grep -n 'Unescaped' "$MAILER" >/dev/null; then
  fail "$MAILER must not use Unescaped on the send path"
fi
grep -n 'login_mail_html\|join_mail_html\|leave_mail_html\|issue_mail_html' "$MAILER" >/dev/null \
  || fail "$MAILER must render view! mail bodies"
grep -n 'Attachment::inline' "$MAILER" >/dev/null \
  || fail "$MAILER must attach cid logo via Attachment::inline"
grep -n 'cid:vauban-logo' "$VIEWS" >/dev/null \
  || fail "$VIEWS must reference cid:vauban-logo"
if grep -n 'data:image' "$VIEWS" >/dev/null; then
  fail "$VIEWS must not embed base64 data: URIs"
fi
grep -n 'include_str!' "$TMPL" >/dev/null \
  || fail "$TMPL must include_str email HTML fixtures"
grep -n 'include_bytes!' "$TMPL" >/dev/null \
  || fail "$TMPL must include_bytes vauban-logo.png"

echo "check_mail_templates: OK"
