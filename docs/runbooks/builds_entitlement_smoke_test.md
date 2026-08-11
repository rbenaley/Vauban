# Runbook -- Builds download entitlement

> Manual validation after shipping **storage-backed artifact download**,
> **GA vs org-private release visibility**, **LTS / LTS.industrial /
> Stable subscription entitlement**, and **Concept Builds chrome**
> (default-open latest + **server-side** ephemeral download links via
> Topcoat POST/PRG). CI covers unit / invariants / proptest / battle /
> in-process E2E against `vcp_test`; staging proves browser HTTPS and
> denial paths.
>
> Audience: release / staging operators.
> Severity: **BLOCKING** for this surface. Do not ship without A–F.

Related:

- [README](../../README.md) (seed login, route map)
- Lint: `scripts/check_builds_entitlement.sh`, `scripts/check_storage.sh`
- Storage helper: [`storage_helper_smoke_test.md`](storage_helper_smoke_test.md)
- Pyramid: `.cursor/rules/vcp-test-pyramid.mdc`
- Filter: `cargo test --test integration_tests -- builds_entitlement -- --test-threads=1`
- Auth denials: [`auth_tenant_smoke_test.md`](auth_tenant_smoke_test.md)
- Changelog ``code`` chips: [`release_notes_inline_smoke_test.md`](release_notes_inline_smoke_test.md)

## Automated prerequisites

```bash
bash scripts/setup_test_db.sh   # or: just db-create-test
rtk cargo fmt --all -- --check
rtk cargo clippy --all-targets -- -D warnings
bash scripts/check_builds_entitlement.sh
bash scripts/check_storage.sh
rtk cargo test --test integration_tests -- builds_entitlement -- --test-threads=1
```

## Lab prerequisites

- `VCP_ENVIRONMENT=development` + `just run` (HTTPS `https://127.0.0.1:3000`).
- Browser or `curl -k` willing to accept the local self-signed cert.
- Demo client `l.martin@acme.example` on `acme-infrastructure` (empty-DB boot
  seed); staff via magic link (`magiclinks.vcp_admin`).
- Full Builds catalog (GA + Acme-private `v0.8.6-acme1`): run `just seed-data`
  after `just db-reset` / empty boot (boot alone does **not** upsert releases).
- Schema includes `ephemeral_downloads` (apply migrations / `just db-reset` if needed).

## A -- Happy path + Concept chrome

1. Sign in as `l.martin@acme.example` / `password`.
2. Open `/acme-infrastructure/builds` — expect the **highest version**
   panel open by default (release notes visible). Order is SQL semver
   (`v_major`…`client_suffix` columns; ignore release dates). For the
   same `X.Y.Z`, `X.Y.Z-client` rows sit above plain `X.Y.Z`, A→Z by
   client name. Pager must not reshuffle when toggling publish.
   SIGNATURE column shows the **full** 64-hex SHA-256 (not a 7-char
   prefix). VERSION omits track markers (`+LTS` / `+LTS.industrial`;
   channel badge carries the track). Basenames keep
   `vauban-…+LTS.pkg` / `vauban-…+LTS.industrial.pkg`. When both LTS and
   industrial twins share `X.Y.Z`, industrial sorts **above** LTS.
   Channel chips: All / LTS / LTS.industrial / Stable / EOL.
   Dashboard `/{org}` CURRENT BUILD / latest must also omit markers and
   respect the subscription matrix.
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
7. Download POST on a visible version with a `storage_objects` row + blob
   returns **200** and the package bytes. Any failure (missing storage row,
   helper down, digest drift) keeps the visitor **on Builds**: **303** back to
   `/{org}/builds/{version}?…&dl_error=…` and a Concept modal — never a
   plain-text `download unavailable` page. See § G.
8. As `support@vauban.sh` on `/vauban/builds`, confirm **all published**
   `X.Y.Z-client` private builds are visible (not only GA). `HIDDEN` rows stay
   off the Builds list (admin-only).

Pass: Concept chrome + server ephemeral tokens; authorized download streams.

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

## B2 -- Subscription matrix (LTS / Industrial LTS)

Seed (or admin-publish) three GA packages sharing a core when needed:
`vauban-X.Y.Z.pkg` (Stable), `…+LTS.pkg`, `…+LTS.industrial.pkg`.

| Org counters (admin Companies) | Expect on `/{org}/builds` + download |
|---|---|
| LTS=0, Industrial=0 | `/{org}/builds` **404**; Builds rail item **absent**; download **404** |
| LTS≥1, Industrial=0 | Stable + LTS only; chips All/LTS/Stable/EOL (no Industrial); industrial **404** |
| LTS=0, Industrial≥1 | Industrial only; chips All/LTS Industrial/EOL (no LTS/Stable); Stable/LTS **404** |
| LTS≥1 and Industrial≥1 | All three; all chips; industrial twin **above** LTS |
| Reserved `/vauban` (even 0/0) | All published tracks; all chips; Builds stays in rail |

Pass / Fail: list HTML, chip set, rail presence, and download POST match the
table; dashboard never links Builds when counters are 0/0.

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
   keep a leading `v`; package names do not. Industrial packages use
   `+LTS.industrial` in the sha256 command basename.
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

## G -- Download failure modal (Pass / Fail)

The session POST is PRG: a failure returns to the same view with a
`dl_error` code and raises the `vb-confirm` modal. Codes and titles:

| Cause | `dl_error` | Modal title |
|---|---|---|
| Visible release with no artifact | `missing` | Package not available |
| Helper down / blob unreadable | `unavailable` | Download unavailable |
| Mirror / SoT / disk digest drift | `integrity` | Signature check failed |

1. Pick a published build with **no** `storage_objects` row (or stop
   `vcp-store` for the `unavailable` case) and submit **Download**.
2. Expect the browser to stay on `/{org}/builds/{version}` with the channel
   filter preserved, the release panel still open, and the modal on top.
3. Click **Close** — modal disappears without a reload; the URL fallback
   (JS disabled) reloads the same view without `dl_error`.
4. Hand-edit the URL to `?dl_error=nope` (or inject markup) — no modal, no
   reflected text.
5. Fix the cause (restart helper / attach artifact) and retry — **200** and
   the package bytes.

| Result | Criteria |
|--------|----------|
| **Pass** | 303 back to Builds, matching modal title, Close dismisses, unknown codes ignored, retry serves bytes. |
| **Fail** | Navigation to a plain-text `download unavailable` page, blank page, modal on a clean URL, reflected query text, or partial bytes on failure. |

## Related automated coverage

| Layer | Filter / artifact |
|-------|-------------------|
| Invariants | `inv_`, `scripts/check_builds_entitlement.sh`, `scripts/check_storage.sh` |
| Proptest | `prop_` |
| Battle | `battle_` |
| E2E | `e2e_` (`--test integration_tests`) |
