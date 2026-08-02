# Runbook -- Builds download entitlement

> Manual validation after shipping **authorized 501 download stub**,
> **GA vs org-private release visibility**, and **Concept Builds chrome**
> (default-open latest + **server-side** ephemeral download links via
> Topcoat POST/PRG). CI covers unit / invariants / proptest / battle /
> in-process E2E against `vcp_test`; staging proves browser HTTPS and
> denial paths.
>
> Audience: release / staging operators.
> Severity: **BLOCKING** for this surface. Do not ship without A–F.

Related:

- [README](../../README.md) (seed login, route map)
- Lint: `scripts/check_builds_entitlement.sh`
- Pyramid: `.cursor/rules/vcp-test-pyramid.mdc`
- Filter: `cargo test --test integration_tests -- builds_entitlement -- --test-threads=1`
- Auth denials: [`auth_tenant_smoke_test.md`](auth_tenant_smoke_test.md)

## Automated prerequisites

```bash
bash scripts/setup_test_db.sh   # or: just db-create-test
rtk cargo fmt --all -- --check
rtk cargo clippy --all-targets -- -D warnings
bash scripts/check_builds_entitlement.sh
rtk cargo test --test integration_tests -- builds_entitlement -- --test-threads=1
```

## Lab prerequisites

- `VCP_ENVIRONMENT=development` + `just run` (HTTPS `https://127.0.0.1:3000`).
- Browser or `curl -k` willing to accept the local self-signed cert.
- Seed users: staff `support@vauban.sh` / `password`; client
  `l.martin@acme.example` / `password` on `acme-infrastructure`.
- Seed includes GA releases plus an Acme-private hotfix (`v0.8.6-acme1`).
- Schema includes `ephemeral_downloads` (apply migrations / `just db-reset` if needed).

## A -- Happy path + Concept chrome

1. Sign in as `l.martin@acme.example` / `password`.
2. Open `/acme-infrastructure/builds` — expect the **highest version**
   panel open by default (release notes visible). Order is by version
   number descending (ignore release dates). For the same `X.Y.Z`,
   `X.Y.Z-client` rows sit above plain `X.Y.Z`, A→Z by client name.
   SIGNATURE column shows the **full** 64-hex SHA-256 (not a 7-char
   prefix). Column gaps look even across VERSION…SIZE.
3. Action row: **Download (size)**, **5-minute download link**,
   **Verify signature** (no Collapse).
4. Submit **5-minute download link** — server issues a UUID token and
   redirects back; panel shows Concept URL, live countdown (Topcoat
   signal), Copy / SVG copy, Revoke, and fetch/cURL tabs (client signal,
   no navigation).
5. Click **cURL** then **fetch** — command bin and active tab must switch
   without a page reload. CI covers the Topcoat `@click` bind contract
   (handlers must be function expressions); this step is the real DOM
   toggle that in-process E2E cannot drive.
6. Regenerate / Revoke via POST forms. After expiry, expect
   **Generate new link** (no custom JS asset — Topcoat runtime only).
7. Download POST on a visible version returns **501**
   (`download not configured`) until artifact storage ships.
8. As `support@vauban.sh` on `/vauban/builds`, confirm **all published**
   `X.Y.Z-client` private builds are visible (not only GA). `HIDDEN` rows stay
   off the Builds list (admin-only).

Pass: Concept chrome + server ephemeral tokens; download remains 501.

## B -- Org-private isolation

1. As staff, publish (or confirm) a release targeted at another org only.
2. As `l.martin@acme.example`, confirm that private build does **not**
   appear under `/acme-infrastructure/builds`.
3. Direct detail/download URL for a foreign private version → **404**.

Pass: `organization_id` targeting is enforced on list/detail/download.
The list/detail/download loaders apply a **SQL** net
(`status = published` + `organization_id in (GA, org)` for client orgs;
published-only for reserved `vauban`) before Rust defense-in-depth
`release_visible_to_org`.

## C -- Collapse without re-open loop

1. On the list with latest open, click the open row — expect collapse
   (`?open=none`) with no panel.
2. Click a version again — panel opens for that version.

Pass: Concept-style collapse works with default-open.

## D -- Denial paths

1. As client, confirm `/admin/releases` returns **404**.
2. While authenticated, open a non-member org slug — expect **404**.
3. Anonymous / expired session must not leak tenant data.

Pass: Casbin + tenant fail-closed.

## E -- Verify signature

Client-only Topcoat panel (no POST / no countdown / no Revoke). Verify and
the live ephemeral panel share **one** slot (mutually exclusive).

1. On an open build with download entitlement, generate a 5-minute link so
   **EPHEMERAL DOWNLOAD LINK** is visible.
2. Click **Verify signature**.
3. Expect **only** **PACKAGE SIGNATURE** (same body chrome as the
   ephemeral zone): full SHA-256 + Copy, and `$ sha256 vauban-…pkg` +
   command copy. LTS packages use `+LTS`; Stable/EOL omit it. DB versions
   keep a leading `v`; package names do not.
4. Confirm **EPHEMERAL DOWNLOAD LINK** is **not** visible at the same time
   (no fetch/cURL, countdown, or Revoke while Verify is open).
5. Click **Verify signature** again — PACKAGE SIGNATURE collapses and the
   ephemeral panel reappears if the token is still live.

Pass: verify toggles locally; never stacked with the ephemeral panel.

## F -- Pagination

SSR list paging (10 rows per page, shareable `?page=`).

1. With **11+** visible builds for the org, open `/{org}/builds` — expect
   at most **10** rows, pager (**Prev** / page numbers / **Next**) on the
   **same row as the channel chips** (chips left, pager right; same chip
   height), and the highest version open by default on page 1.
2. Follow **Next** (or `?page=2`) — expect the remainder only; no
   default-open panel on page 2. Pager stays on the chip row (does not
   jump with the open panel).
3. From page 2, click a **channel** chip (or **All**) — URL must **not**
   keep `page=` (reset to page 1).
4. Deep-link `/{org}/builds/{version}` for a version that sits on page 2
   — expect that version open on the correct page (not missing from the
   slice).

Pass: 10 max per page; chip-row pager; next/prev; channel resets page;
deep-link keeps the open build on-page.

## Related automated coverage

| Layer | Filter / artifact |
|-------|-------------------|
| Invariants | `inv_`, `scripts/check_builds_entitlement.sh` |
| Proptest | `prop_` |
| Battle | `battle_` |
| E2E | `e2e_` (`--test integration_tests`) |
