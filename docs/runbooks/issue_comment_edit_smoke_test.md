# Runbook -- Support comment edit

> Manual check that Vauban Support can correct their own comments, and
> that company users cannot edit anyone’s comments.
>
> Audience: Support / staging operators.
> Severity: **BLOCKING** for this surface.

Related:

- Issue tracker: [`portal_issues_smoke_test.md`](portal_issues_smoke_test.md)
- Lint: `scripts/check_issue_comment_edit.sh`
- Filter: `cargo test --test integration_tests -- issue_comment_edit -- --test-threads=1`

## Automated prerequisites

```bash
bash scripts/setup_test_db.sh
rtk cargo fmt --all -- --check
rtk cargo clippy --all-targets -- -D warnings
bash scripts/check_issue_comment_edit.sh
just test -- --test integration_tests -- issue_comment_edit
```

## Lab

1. Sign in as Support. Open `/admin/issues/{key}?org={slug}`.
2. Post a Support reply, then click **Edit** on that bubble.
   - **Pass:** textarea prefills; Save updates the body; “Edited · …” appears.
   - Company detail `/{slug}/issues/{key}` shows the new text and **no** Edit.
3. Click Edit on a company (reporter) comment.
   - **Pass:** no Edit control. Crafted POST `/admin/issues/…/edit-comment` for a reporter row → 404, body unchanged.
4. Status timeline rows (“Resolved”, “Moved to analysis”) have no Edit.

## Fail if

- Company accounts see or can POST an edit.
- FSM / reporter comments are editable.
- Save fails while TEM is down (edit must not depend on mail).
