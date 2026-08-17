# Transactional email HTML (Vauban PAM)

Send-ready HTML bodies for every notification Vauban queues. Branding
matches the Vauban Customer Portal mail set (`../VCP/email`): fluid
card (`width:100%`, `max-width:720px`, Outlook MSO ghost table),
inline styles, star-fort logo via `cid:vauban-logo`, wordmark
driven by `__BRAND__`.

These files are **not** Askama templates. They are embedded with
`include_str!` from `vauban-web/src/services/mail_templates.rs` and
live under `vauban-web/email/` so
`scripts/check_responsive_templates.sh` (which requires
`overflow-x-auto` around every `<table>`) does not scan them.

## Catalogue

| Event kind | Recipients (live producer) | File |
|---|---|---|
| `access_request.submitted` | staff ∪ superuser usable (`load_approver_contacts`) | `access_request_submitted.html` |
| `access_request.approved` | requester | `access_request_approved.html` |
| `access_request.rejected` | requester | `access_request_rejected.html` |
| `access_request.revoked` | requester | `access_request_revoked.html` |
| `access_request.expired` | no producer yet | `access_request_expired.html` |
| `user.created` | no producer yet | `user_created.html` |
| `user.password_reset_requested` | no producer yet | `user_password_reset_requested.html` |
| `user.locked_after_failed_attempts` | no producer yet | `user_locked.html` |
| `user.mfa_reset_by_admin` | no producer yet | `user_mfa_reset.html` |
| `security.mono_admin_detected` | no producer yet | `security_mono_admin.html` |
| `iacs.onboard_submitted` | staff ∪ superuser usable (`load_approver_contacts`) | `iacs_onboard_submitted.html` |
| `iacs.onboard_approved` | requester | `iacs_onboard_approved.html` |
| `iacs.onboard_rejected` | requester | `iacs_onboard_rejected.html` |
| `iacs.offboarded` | EWS owner | `iacs_offboarded.html` |

Dormant producers: [docs/runbooks/email_html_dormant_events.md](../../docs/runbooks/email_html_dormant_events.md).

## Placeholders

| Token | Escaped? | Meaning |
|---|---|---|
| `__BRAND__` | yes | `[product.brand].name` / `from_brand` |
| `__BASE_URL__` | yes | Mailer `base_url` |
| `__REQUESTER__`, `__ASSET__`, `__PROTOCOL__`, `__APPROVER__`, `__USERNAME__`, `__CREATED_BY__`, `__ADMIN__`, `__EWS__`, `__FINGERPRINT__`, `__ATTEMPTS__` | yes | Event fields |
| `__FACTS_BLOCK__` | pre-composed | Label/value table |
| `__NOTICE_BLOCK__` / `__INFO_BLOCK__` / `__DANGER_BLOCK__` | pre-composed | Status callouts |
| `__CTA_BLOCK__` | pre-composed | Bulletproof button + raw URL |

Logo: `src="cid:vauban-logo"` (`shared::smtp::EMAIL_LOGO_CID`). The
PNG is compiled into `vauban-mailer` and attached only when the HTML
references that CID.

## Conventions

- Nested `<table role="presentation">`, fluid single column
  (`width:100%` / `max-width:720px`, MSO wrapper `width="720"`).
- Every style is inline. No `<style>` block (except the mso
  conditional comment), no JavaScript, no web fonts, no `data:` images.
- Lines stay under 998 characters (RFC 5321 DATA limit).
- Plain-text alternatives stay in `services/mailer.rs::render_*`.
