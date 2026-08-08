# Runbook -- Release notes inline ``code`` chips

> Manual validation after shipping **paired-backtick** rendering in client
> Builds changelogs and the org dashboard **Latest certified build** panel.
> CI covers unit / invariants / proptest / battle / in-process E2E against
> `vcp_test`; staging proves browser HTTPS chrome.

Audience: release / staging operators.
Severity: **ADVISORY** for visual polish; **BLOCKING** if backticks show
raw or XSS-looking markup appears unescaped.

Related:

- Lint: `scripts/check_release_notes_inline.sh`
- Pyramid: `.cursor/rules/vcp-test-pyramid.mdc`
- Filter: `cargo test --test integration_tests -- release_notes_inline -- --test-threads=1`
- Builds chrome: [`builds_entitlement_smoke_test.md`](builds_entitlement_smoke_test.md)

## Automated prerequisites

```bash
bash scripts/setup_test_db.sh   # or: just db-create-test
rtk cargo fmt --all -- --check
rtk cargo clippy -p vcp --all-targets -- -D warnings
bash scripts/check_release_notes_inline.sh
rtk cargo test -p vcp release_notes -- --test-threads=1
rtk cargo test --test integration_tests -- release_notes_inline -- --test-threads=1
```

## Lab prerequisites

- `VCP_ENVIRONMENT=development` + `just run` (HTTPS).
- A published GA release whose notes contain at least one paired span, e.g.
  `FIX: Prefer \`config/\` over workspace`.
- Member login on an org that can see that release (e.g. `vauban` / Acme).

## Pass / Fail

| Step | Action | Pass | Fail |
|------|--------|------|------|
| A | Open `/{org}/builds` and expand a version whose notes include `` `…` `` | Chip uses monospace + light gray background/border; backticks not visible as delimiters | Raw backticks remain, or text looks like surrounding prose |
| B | Open `/{org}` **Latest certified build** | Same chip styling for the same tokens | Dashboard still shows raw backticks |
| C | Notes with an unpaired `` ` `` | Remainder stays plain text; no empty/broken chip | Spurious empty gray box |
| D | View-source / inspector on a chip | Element is `<code class="vb-inline-code">…</code>`; note body text is escaped (no raw HTML injection) | Raw HTML from notes executes or breaks layout |
| E | Open a published KB article with paired `` `…` `` in the body | Same chip styling on the docs modal (shared helper) | Docs still show raw backticks |

## Related links

- Helper: `src/release_notes.rs`
- Component: `src/app/_components/note_inline.rs`
- CSS: `.vb-inline-code` in `styles.css`
- KB modal: `src/app/org/docs/doc.rs` (also covered by [`admin_docs_smoke_test.md`](admin_docs_smoke_test.md) §D)
