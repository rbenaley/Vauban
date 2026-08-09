# Runbook -- Admin client companies

> Manual validation after shipping **Concept companies** (list/edit,
> email-only accounts, dual technical contact name + Mailbox-validated email,
> configurable `org.max_accounts_per_org`, default 5; 
> `org.max_lts_subscriptions`, default 99), **LTS steppers**, **magic-link
> invite/revoke** for fiche accounts, **card pagination (3/page)**, and
> **live search shard**. CI covers unit / invariants / proptest / battle /
> in-process E2E against `vcp_test`; staging proves browser HTTPS and
> denial paths.
>
> Audience: release / staging operators.
> Severity: **BLOCKING** for this surface. Do not ship without A–D.

Related:

- [README](../../README.md) (magic-link login, route map)
- Magic links / Mailpit: [`magic_links_smoke_test.md`](magic_links_smoke_test.md)
- Lint: `scripts/check_admin_companies.sh`,
  `scripts/check_admin_companies_search_shard.sh`
- Pyramid: `.cursor/rules/vcp-test-pyramid.mdc`
- Filter: `just test --test integration_tests -- admin_companies -- --test-threads=1`
- Auth denials: [`auth_tenant_smoke_test.md`](auth_tenant_smoke_test.md)

## Automated prerequisites

```bash
bash scripts/setup_test_db.sh   # or: just db-create-test
rtk cargo fmt --all -- --check
rtk cargo clippy --all-targets -- -D warnings
bash scripts/check_admin_companies.sh
bash scripts/check_admin_companies_search_shard.sh
just test --test integration_tests -- admin_companies -- --test-threads=1
```

## Lab prerequisites

- `VCP_ENVIRONMENT=development` + `just run` (HTTPS `https://127.0.0.1:3000`).
- Browser or `curl -k` willing to accept the local self-signed cert.
- Browser DevTools Network panel (filter `shards`) for live search checks.
- Mailpit (or TEM) for magic-link delivery. Staff: request a link for
  `magiclinks.vcp_admin` (default `support@vauban.sh`) → `/vauban`.
- Demo client `l.martin@acme.example` signs in via magic link after seed.

## A -- Happy path

1. Sign in as `support@vauban.sh` via magic link (Mailpit).
2. Open `/admin/companies` — expect Concept cards (contact, ADDRESS/VAT,
   USER ACCOUNTS pills, Edit + trash). No reserved `vauban` card.
3. Click **+ New company**; fill **Technical contact — full name** and
   **Technical contact — email** (two fields). For **Company address**, enter
   multi-line text (e.g. street / city / country on separate lines) — the
   `/admin/companies` card and `/{org}/account` must show those lines joined
   with the same ` · ` separator as technical contact (name · email), not raw
   newlines. Set **Vauban LTS** /
   **Industrial LTS** steppers with `+` / `-` (client-side signals: no
   page reload per click; values post on Save only; 0..N, start at 0),
   plus up to seat-cap email-only USER ACCOUNTS (no password fields).
   Save — invitation mail is sent for each new account.
4. Confirm list meta row has ADDRESS / VAT / SUBSCRIPTIONS columns; the
   subscriptions column label is
   `SUBSCRIPTIONS (VAUBAN LTS / VAUBAN INDUSTRIAL LTS)` with ratio `2/1`
   below in the same mono style as VAT; open Edit; confirm steppers +
   contact fields; add/remove an account email; Save (invite on add,
   revocation mail on remove, including multi-org users).
5. Sign out; sign in as a fiche account via its invitation / login magic
   link; open `/{org}` and `/{org}/account` — expect address, VAT, LTS
   counts, and user-account pills from the company fiche.
6. Delete via trash + type `delete`.
7. Confirm slug/name `Vauban` is rejected on create.

Pass: surface matches Concept; seat + LTS caps from config; fiche users
reach `/{org}` via magic link.

## B -- Denial paths

1. As `l.martin@acme.example`, confirm `/admin/companies` returns **404**.
2. While authenticated, open a non-member org slug — expect **404**.
3. Anonymous / expired session must not leak tenant data.
4. On **+ New company**, enter a USER ACCOUNTS value like `not-an-email`
   and Save — expect form error `Invalid email address`, no new card.
5. On **+ New company**, set a valid account email but technical contact
   email `not-an-email` — expect the same Mailbox error, no new card.

Pass: Casbin + tenant fail-closed; Mailbox syntax validation fail-closed
for USER ACCOUNTS and technical contact email.

## C -- Pagination

SSR list paging (**3** cards per page via `COMPANIES_PAGE_SIZE`, shareable
`?page=`).

1. With **4+** matching client companies on `/admin/companies`, expect at
   most **3** `vb-company-card` rows and a right-aligned **toolbar pager**
   above the list (no chip row on this surface).
2. Follow **Next** (or `?page=2`) — expect the remainder only.
3. Confirm pager links keep `q=` when searching, stay on
   `/admin/companies?…&page=N`, and do not sticky `delete=` / `err=`
   overlay params.

Pass: 3 max per page; toolbar pager; overlay query not sticky.

## D -- Live search shard

1. Open DevTools → Network; filter on `/_topcoat/shards`.
2. Type into **Search companies…** — confirm POSTs return **200** and
   the card list filters without a full reload (name, slug, contact, VAT,
   address, or account email).
3. Clear the field — broader list returns.
4. Confirm server logs show no shard / path-param panics.
5. Same shard POST without cookie → **404**.
6. As `l.martin@acme.example`, POST to a captured shard path → **404**
   without leaking company names.

Pass: shard POSTs stay 200 for staff; fail-closed for anon / member.
Search is **SQL two-phase** (org-field `ilike` OR membership/user email
`ilike` → union of org ids → page hydration via `in_list`). Seat checks
use SQL `COUNT(*)` (`membership_count`), not `rows.len()` after a full
membership load.

## Related automated coverage

| Layer | Filter / artifact |
|-------|-------------------|
| Unit | `companies_search_*` in `src/companies_search.rs` |
| Invariants | `inv_`, `scripts/check_admin_companies.sh`, `scripts/check_admin_companies_search_shard.sh` |
| Proptest | `prop_` |
| Battle | `battle_` |
| E2E | `e2e_` (`--test integration_tests`) |
