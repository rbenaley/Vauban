# Runbook -- Builds download entitlement

> Manual validation after shipping **authorized 501 download stub**,
> **GA vs org-private release visibility**, and **Concept Builds chrome**
> (default-open latest + **server-side** ephemeral download links via
> Topcoat POST/PRG). CI covers unit / invariants / proptest / battle /
> in-process E2E against `vcp_test`; staging proves browser HTTPS and
> denial paths.
>
> Audience: release / staging operators.
> Severity: **BLOCKING** for this surface. Do not ship without A–D.

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
2. Open `/acme-infrastructure/builds` — expect the **latest** build panel
   open by default (release notes visible).
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

Pass: Concept chrome + server ephemeral tokens; download remains 501.

## B -- Org-private isolation

1. As staff, publish (or confirm) a release targeted at another org only.
2. As `l.martin@acme.example`, confirm that private build does **not**
   appear under `/acme-infrastructure/builds`.
3. Direct detail/download URL for a foreign private version → **404**.

Pass: `organization_id` targeting is enforced on list/detail/download.

## C -- Collapse without re-open loop

1. On the list with latest open, click the open row — expect collapse
   (`?open=none`) with no panel.
2. Click a version again — panel opens for that version.

Pass: Concept-style collapse works with default-open.

## D -- Denial paths

1. As client, confirm `/admin/releases` returns **403**.
2. While authenticated, open a non-member org slug — expect **404**.
3. Anonymous / expired session must not leak tenant data.

Pass: Casbin + tenant fail-closed.

## Related automated coverage

| Layer | Filter / artifact |
|-------|-------------------|
| Invariants | `inv_`, `scripts/check_builds_entitlement.sh` |
| Proptest | `prop_` |
| Battle | `battle_` |
| E2E | `e2e_` (`--test integration_tests`) |
