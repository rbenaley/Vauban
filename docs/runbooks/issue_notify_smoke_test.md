# Runbook -- Issue notification mail

> Manual validation of Support / company issue emails after shipping
> the outbox drain. CI covers unit / invariants / proptest / battle /
> in-process E2E against `vcp_test` + `MemoryTransport`; staging proves
> TEM / Mailpit delivery.
>
> Audience: ops / Support.
> Severity: **BLOCKING** for this surface.

Related:

- [README](../../README.md)
- Lint: `scripts/check_issue_notify.sh`
- Filter: `cargo test --test integration_tests -- issue_notify -- --test-threads=1`
- Issue tracker: [`portal_issues_smoke_test.md`](portal_issues_smoke_test.md)

## Automated prerequisites

```bash
bash scripts/setup_test_db.sh   # or: just db-create-test
rtk cargo fmt --all -- --check
rtk cargo clippy --all-targets -- -D warnings
bash scripts/check_issue_notify.sh
rtk cargo test --test integration_tests -- issue_notify -- --test-threads=1
rtk cargo test --lib -- issue_notify -- --test-threads=1
```

## Lab prerequisites

- `VCP_ENVIRONMENT=development` + `just run`.
- Mailpit (`localhost:1025`) or staging TEM.
- At least two Support accounts (`portal_role=admin`) and one client
  company with two user accounts.
- `[issues.notify] enabled = true` in the loaded overlay.

## A -- Create / comments / status

1. Sign in as a company user. Create an issue.
   - **Pass:** every *other* Support inbox receives `[VBN-…] New issue`.
     The creator has no self-mail. From / reply-to match `[magiclinks]`.
     Link opens `/admin/issues/{key}?org={slug}` for Support.
2. Same company user posts a comment.
   - **Pass:** Support only. Sibling company accounts get nothing.
3. A different Support user comments from `/admin/issues/…`.
   - **Pass:** other Support + all other company accounts on that org.
     The commenter has no self-mail. Company link is `/{slug}/issues/{key}`.
4. Support (or the company user) advances status (Start analysis / Close).
   - **Pass:** Support only. Company inboxes stay empty. Actor has no
     self-mail. Subject like `[VBN-…] Status: In analysis`.

## B -- Soft-delete and disable

1. Soft-delete a company account. Repeat a Support comment.
   - **Pass:** the deleted mailbox gets 0 mail.
2. Set `issues.notify.enabled = false`, restart the portal, create +
   comment + FSM.
   - **Pass:** issue/comment/status persist; 0 mail; no new outbox rows.

## C -- Drain after TEM outage

1. Stop Mailpit / TEM. Create an issue (HTTP 303 still succeeds).
2. Confirm `issue_mail_outbox.sent_at = 0` for the new rows.
3. Restore TEM. Wait `drain_interval_secs` or trigger another issue
   write (request drain).
   - **Pass:** pending rows flip to `sent_at > 0`; inboxes match matrix A.
   - **Fail:** HTTP 500 because TEM is down, or duplicate mails after
     restore.

## Fail if

- The actor of the event receives mail.
- Company accounts receive create / company-comment / status mail.
- Soft-deleted users receive mail.
- Comment bodies appear unbounded or unescaped in HTML.
- `vcp-store` / `vcp_storage_*` targets appear in notify logs (must be
  `vcp::issue_notify`).
