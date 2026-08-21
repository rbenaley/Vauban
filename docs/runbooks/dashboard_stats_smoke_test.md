# Runbook -- Org dashboard issue stats (single-load aggregation)

> Manual validation after changing org home dashboard issue tiles /
> `dashboard_stats` helpers. Auth denials stay in
> [`auth_tenant_smoke_test.md`](auth_tenant_smoke_test.md).
>
> Audience: release / staging operators.
> Severity: **BLOCKING** for dashboard issue-counter changes.

Related:

- [README](../../README.md)
- Capacity notes: `.cursor/audits/vcp_capacity_gisco_freebsd_2026-08-02.md` §3.2 / §7
- Lint: `scripts/check_dashboard_stats.sh`, `scripts/check_toasty_filters.sh`
- Pyramid: `.cursor/rules/vcp-test-pyramid.mdc`
- Filter: `cargo test --test integration_tests -- dashboard_stats -- --test-threads=1`
- Shell chrome: [`portal_shell_smoke_test.md`](portal_shell_smoke_test.md)

## Automated prerequisites

```bash
bash scripts/setup_test_db.sh   # or: just db-create-test
just fmt-check
rtk cargo clippy --all-targets -- -D warnings
bash scripts/check_dashboard_stats.sh
bash scripts/check_toasty_filters.sh
rtk cargo test --test integration_tests -- dashboard_stats -- --test-threads=1
rtk cargo test --lib dashboard_stats -- --test-threads=1
```

## Lab prerequisites

- `VCP_ENVIRONMENT=development` + `just run` (HTTPS `https://127.0.0.1:3000`).
- Seed client: `l.martin@acme.example` / `password` → `/acme-infrastructure`.
- Optional: create a few issues with mixed statuses under that org.

## A -- Stat tiles match Issues list

1. Sign in as the client user; open `/{org}` dashboard.
2. Note **OPEN ISSUES** and **IN ANALYSIS** tile values.
3. Open `/{org}/issues` and count rows with status **Open** and rows
   with status **In analysis** (Resolved / Closed are excluded from both
   tiles; do not treat "not closed" as Open).
4. Expect dashboard tiles to match those FSM status counts (org-scoped).

Pass: tiles equal org Issues list aggregates; no foreign-org inflation.

## B -- Latest activity is newest `updated_at`

1. On the dashboard Recent activity (issues), note the issue key shown.
2. Touch / reply on a different open issue so its `updated_at` advances.
3. Reload dashboard — activity key should follow the newest update.

Pass: activity prefers newest org issue, not insert order alone. The
activity lines show key + copy only — **no** relative clock (`3h ago`)
and **no** calendar date. **RECENT ACTIVITY** and **LATEST CERTIFIED
BUILD** share the row equally (`vb-grid-2` = `1fr 1fr`); they stack
below 960 px.

## C -- SQL shape (DEBUG)

1. Enable DEBUG logs; reload `/{org}` once.
2. Expect **one** org-scoped `issues` SELECT (limit capped), **not** four
   separate `COUNT(*)` statements for open / resolved / closed /
   in-analysis tiles.
3. Docs tile may still use a published-docs `COUNT(*)`.

Pass: single issues load + docs COUNT; no multi-COUNT issue fan-out.

## Related automated coverage

| Layer | Filter / artifact |
|-------|-------------------|
| Unit | `summarize_open_excludes_in_analysis_and_terminal` (16/3/1/1), `issue_activity_copy_has_no_clock` |
| Invariants | `inv_dashboard_open_tile_counts_fsm_open_not_non_closed`, `inv_dashboard_activity_is_dateless_equal_panels`, `check_dashboard_stats.sh` |
| Proptest | `prop_open_and_analysis_are_disjoint_fsm_counts`, `prop_activity_copy_never_looks_like_a_clock` |
| Battle | `battle_parallel_dashboard_gets_with_issue_stats` (tiles + dateless activity) |
| E2E | `e2e_dashboard_open_tile_excludes_in_analysis`, `e2e_dashboard_issue_stats_from_org_rows` (no clock, `vb-grid-2`) |
