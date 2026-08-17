# Runbook -- branded HTML mail rendering smoke test

> Manual validation after shipping **HTML transactional mail**
> (Vauban branding, inline `cid:vauban-logo`, `multipart/related`).
> CI covers MIME shape, injection properties, and outbox persistence;
> staging proves the logo and callouts render on real MUAs.
>
> Audience: release / staging operators.
> Severity: **BLOCKING** for the HTML-mail lot. Do not ship without A–C
> on the eight events that have a live producer.
>
> This runbook is also the **client-validation gate** for the pilot
> carcass (`access_request.rejected`) before treating the other
> thirteen templates as visually signed-off.

Related:

- [vauban-web/email/README.md](../../vauban-web/email/README.md)
- [email_html_dormant_events.md](email_html_dormant_events.md)
- [evidence_mailer_extract_smoke_test.md](evidence_mailer_extract_smoke_test.md)
- Lints: `vauban-web/scripts/check_mailer_sealed.sh`

## Automated prerequisites

```bash
rtk cargo fmt --all -- --check
rtk cargo clippy -p shared -p vauban-mailer -p vauban-web --all-targets -- -D warnings
bash vauban-web/scripts/check_mailer_sealed.sh
bash vauban-web/scripts/check_responsive_templates.sh
rtk cargo test -p vauban-mailer -- outbox -- --test-threads=1
rtk cargo test -p vauban-web -- mail -- --test-threads=1
# hand-off:
rtk cargo test --workspace -- --test-threads=1
rtk cargo test --manifest-path vauban-proxy-rdp/Cargo.toml --target-dir target -- --test-threads=1
```

## Lab prerequisites

- Mailer enabled (`[mailer] enabled = true`) with a reachable SMTP sink
  (staging MTA or a catch-all inbox you control). `smtp_host =
  "localhost"` is valid when the sink listens on IPv4 only: the
  supervisor broker tries every resolved address (`::1` then
  `127.0.0.1`).
- At least one usable staff or superuser with a real mailbox
  (`load_approver_contacts`).
- Ability to open the same message in Gmail, Outlook on the web,
  Apple Mail, and a text-only client (`mutt` / `mail`).

## A -- Pilot carcass (access denied)

1. As a requester, submit a JIT access request.
2. As an approver, deny it with a short reason.
3. Open the requester's mail.

Pass:

- Star-fort logo visible **without** clicking "display images"
  (CID inline, not a remote `https://` fetch).
- Wordmark matches `[product.brand].name`.
- Gold/ink card on `#f2f1ee` page; danger callout shows the reason.
- Plain-text alternative is readable in the text-only client.
- No broken-image box, no unexpected attachment named `vauban-logo.png`
  listed as a download (Outlook must treat it as inline).

## B -- Approver request (JIT + IACS)

1. Submit a JIT access request and an IACS onboard request.
2. Confirm each usable staff ∪ superuser in the approver pool received
   **one** mail (`access_request.submitted`, `iacs.onboard_submitted`).
3. Click the bulletproof button; confirm it lands on the review URL.
4. Copy the raw-URL fallback into a browser; same landing.

Pass: both submitted mails render the facts table (requester / asset
or EWS / fingerprint) and the CTA works from Gmail and Outlook.

## C -- Decision mails (approve / reject / revoke / offboard)

1. Approve one JIT request; reject another; revoke an approved grant.
2. Approve one IACS request; reject another; offboard an EWS.
3. Open each requester (or EWS owner) mail.

Pass: eight live events render consistently. Approved mails show the
session / my-requests CTA. Rejected / revoked / offboarded mails show
the danger callout. Text fallback remains coherent.

## Events waiting for a producer

Do **not** expect mail for:

- `access_request.expired`
- `user.created`
- `user.password_reset_requested`
- `user.locked_after_failed_attempts`
- `user.mfa_reset_by_admin`
- `security.mono_admin_detected`

See [email_html_dormant_events.md](email_html_dormant_events.md).
Add a section here when each producer ships.

## Rollback notes

- `body_html` NULL keeps `build_envelope` on `text/plain` (pre-lot
  behaviour). Disabling HTML is a renderer change, not a schema change.
- Removing `cid:vauban-logo` from a template drops the related wrapper
  and the inline image; do not attach the PNG unconditionally.
