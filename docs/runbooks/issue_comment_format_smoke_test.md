# Runbook -- Issue comment formatting

> Manual check that issue **comment bodies** use the same docs dialect as
> `/admin/docs`, while **titles** and **notification mail** stay raw.
>
> Audience: Support / staging operators.
> Severity: **BLOCKING** for this surface.

Related:

- Docs dialect: [`admin_docs_smoke_test.md`](admin_docs_smoke_test.md)
- Issues: [`portal_issues_smoke_test.md`](portal_issues_smoke_test.md)
- Mail: [`issue_notify_smoke_test.md`](issue_notify_smoke_test.md)
- Lint: `scripts/check_issue_comment_format.sh`
- Filter: `cargo test --test integration_tests -- issue_comment_format -- --test-threads=1`

## Automated prerequisites

```bash
bash scripts/setup_test_db.sh
rtk cargo fmt --all -- --check
rtk cargo clippy --all-targets -- -D warnings
bash scripts/check_issue_comment_format.sh
just test -- --test integration_tests -- issue_comment_format
```

## Lab

1. On a ticket, reply with a fenced block and inline code:

   ```
   See:

   ```
   ssh allow
   ```

   Use `PermitRootLogin`.
   ```

   - **Pass (page):** `<pre class="vb-pre">` and a `.vb-inline-code` chip.
   - **Pass (title):** a title like `## not a heading` stays plain in the `<h1>`.
2. Open the same ticket as company and as Support.
   - **Pass:** both pages format the comment the same way.
3. Trigger a comment notification (Mailpit / TEM).
   - **Pass:** the excerpt still shows the backticks as characters, not a styled block.

## Fail if

- Comment fences stay as raw ``` on the issue page.
- The issue title is parsed as a heading / chips.
- The mail HTML grows a `<pre>` / docs renderer.
