# Runbook -- Portal issue tracker

> Manual validation after shipping **client issues + staff aggregate**.
> CI covers unit / invariants / proptest / battle / in-process E2E against
> `vcp_test`; staging proves browser HTTPS and denial paths.
>
> Audience: release / staging operators.
> Severity: **BLOCKING** for this surface. Do not ship without A–C.

Related:

- [README](../../README.md) (seed login, route map)
- Lint: `scripts/check_portal_issues.sh`
- Pyramid: `.cursor/rules/vcp-test-pyramid.mdc`
- Filter: `cargo test --test integration_tests -- portal_issues -- --test-threads=1`
- Auth denials: [`auth_tenant_smoke_test.md`](auth_tenant_smoke_test.md)
- Image upload helper: [`storage_helper_smoke_test.md`](storage_helper_smoke_test.md) (§ B + gallery follow-on)

## Automated prerequisites

```bash
bash scripts/setup_test_db.sh   # or: just db-create-test
rtk cargo fmt --all -- --check
rtk cargo clippy --all-targets -- -D warnings
bash scripts/check_portal_issues.sh
rtk cargo test --test integration_tests -- portal_issues -- --test-threads=1
```

## Lab prerequisites

- `VCP_ENVIRONMENT=development` + `just run` (HTTPS `https://127.0.0.1:3000`).
- Browser or `curl -k` willing to accept the local self-signed cert.
- Demo client `l.martin@acme.example` on `acme-infrastructure` (empty-DB boot).
- Sample issues (`VBN-214`, `VBN-208`): require `just seed-data` after reset
  (boot alone does **not** insert issues).
- Staff: magic link for `magiclinks.vcp_admin`.

## A -- Client happy path

1. Sign in as `l.martin@acme.example` (magic link).
2. Open `/acme-infrastructure/issues/VBN-214` and confirm discussion
   comments / status dividers come from the DB.
3. Confirm support replies display as **Vauban Support**.
4. Post a reply; confirm it persists after reload.
5. On an open issue, click **Close issue** — status becomes Closed, a
   timeline divider `Closed` appears, and the reply form is replaced by
   the closed panel.
6. Attempting a reply while closed must not add a comment (no reply form;
   forged POST must not persist).
7. Click **Reopen issue** — status returns to Open; post a reply and
   confirm it persists.

Pass: client issue timeline, replies, close, and reopen work under the org slug.

## A2 -- Landing position after a post (Pass / Fail)

Use a thread long enough to overflow the viewport (roughly ten comments,
or a narrow window), otherwise there is nothing to scroll and the check
proves nothing.

1. Scroll to the bottom, post a reply, and let the redirect settle. The
   view must show the reply box and the newest comment — **not** the
   issue title. The address bar ends with `#issue-reply`.
2. Repeat on a **closed** issue: after **Close issue**, the browser must
   land on the "This issue is closed" panel, not at the top. Same after
   **Reopen issue**.
3. Submit an empty reply (whitespace only): the no-op redirect must land
   at the bottom too, not at the header.
4. Repeat step 1 as staff on `/admin/issues/{key}?org=…` — the `?org=`
   hint must survive and the fragment stay last in the URL.

| Result | Criteria |
|--------|----------|
| **Pass** | Every reply / close / reopen lands on the reply box or closed panel; URL ends with `#issue-reply`; any `?org=` / `?err=` stays before the `#`. |
| **Fail** | The page reappears at the title after posting; the fragment is missing or sits before the query string; the closed panel is reachable only by manual scrolling. |

## B -- Staff aggregate

1. Sign in as `support@vauban.sh` / `password`.
2. Open `/admin/issues` — expect aggregated list (optional org filter).
3. Open an issue detail under `/admin/issues/{key}` and post a staff reply.
4. Close the issue from admin, confirm Closed + blocked reply, then Reopen.
5. Open `/vauban/issues` — expect redirect to `/admin/issues`.

Pass: staff issues live under `/admin/issues`; reserved org issues redirect;
staff close/reopen works.

## C -- Denial paths

1. As `l.martin@acme.example`, GET `/admin/issues` — expect **404**.
2. As the same client member, POST `/admin/issues/{key}/close` — expect **404**.
3. While authenticated, open a non-member org slug — expect **404**.
4. Anonymous / expired session must not leak tenant data.

Pass: Casbin + tenant fail-closed.

## D -- Pagination (brief)

Client `/{org}/issues` uses the same SSR pager as the org issues search
shard (10/page, status chips omit `page=`). See
[`org_issues_search_shard_smoke_test.md`](org_issues_search_shard_smoke_test.md)
§ C for the full checklist.

## E -- Concurrent report (double submit)

1. As a client member with `issues_write`, open `/…/issues/new`.
2. Submit the same report twice quickly (double-click or two tabs), or
   open two compose tabs and submit nearly together.
3. Confirm each success lands on a **distinct** `VBN-*` detail URL that
   loads (200) with the title/details — never a 404 after an apparent
   success redirect.
4. If create fails after retries, the redirect is
   `/{org}/issues?err=create` (list), not a ghost detail key.

Pass: no lost ticket; no redirect to a missing detail after “success”.

Fail: two submits share one key, or Location points at a 404 detail.

## F -- Screenshot attachments (Pass / Fail)

Prerequisites: `vcp-store` running (same as
[`storage_helper_smoke_test.md`](storage_helper_smoke_test.md) § B).

1. As org member with `issues_write`, open `/{org}/issues/new`.
2. Choose up to `issues.max_attachments_per_comment` PNGs (default 5)
   via the screenshot control (native file input / multipart submit —
   no custom upload JS). There is no separate Upload step: files ride
   with **Submit report**.
3. Before submit, choosing files must show previews (Topcoat `@change`,
   not a custom `.js` asset). Submit the report: thumbs appear **inside**
   the opener bubble; `src` = `/{org}/images/<uuid>.<ext>` (200).
4. **Repeat picks accumulate.** Choose one image, then open the file
   dialog again and choose a second: both previews stay, and the status
   line reads `2 of 5 attached`. Repeat up to the cap — the trigger then
   dims (`aria-disabled`) and further picks report `… ignored (limit 5)`.
   Remove one via its × and the trigger becomes active again. Submit and
   confirm **every** kept screenshot reaches the bubble (a browser that
   replaced the selection on the second pick is a Fail).
5. Click a thumb: the `#issue-lb` `<dialog>` opens centered over the
   viewport (dimmed backdrop only around the image — no page-height grey
   slab) without leaving the page. The × overlays the image's top-right
   corner at a fixed 12px inset **on the pixels**, never in the grey
   backdrop. Verify with at least: a wide landscape screenshot, a tall
   portrait one (height-constrained — this is where a drifting × shows
   up), and a small thumbnail-sized image. Resize the window with the
   dialog open: the × must re-anchor to the new image corner. It is
   translucent, so the pixels under it stay readable, and it must remain
   legible over both a dark and a light screenshot. Closing works three
   ways: the ×, a click on the backdrop, and `Escape`. There is **no**
   remove (×) control on published thumbs.
6. **Multi-image loop.** On a comment (or opener) with **two or more**
   screenshots, open any thumb: left/right chevrons appear at the
   viewport edges. Click next through the last image → first; previous
   through the first → last. Keyboard `ArrowRight` / `ArrowLeft` must
   mirror the chevrons. A **single**-image comment must **not** show
   chevrons. Navigation stays inside that comment's strip (another
   comment's images must not enter the gallery).
7. On an open issue, attach + reply: thumbs sit **in that reply bubble**
   (another up-to-cap set is allowed on that comment).
8. As **Vauban Support** on `/admin/issues/{key}`, the same image URLs
   load (Casbin `admin_view` + issues access; no client membership), and
   the reply picker accumulates exactly as in step 4.
9. Selecting more than the configured cap on create → redirect
   `?err=attach` (no issue).

| Result | Criteria |
|--------|----------|
| **Pass** | Previews + lightbox; successive picks accumulate to the cap; status line tracks the count; × stays inset on the image at every aspect ratio and after resize; multi-image comments loop with ←/→ (chevrons + keys) scoped to that strip; single-image strips hide chevrons; thumbs in the owning bubble; first-party URLs for member + staff; per-comment cap from config; no post-publish remove; no first-party JS asset. |
| **Fail** | A second pick drops the first file; status line stuck or wrong; × lands in the backdrop or off the image; flat end-of-thread gallery; navigate-away on click; gallery mixes another comment's images; arrows do not wrap or appear on a single image; 404 on staff view; custom JS file; markdown URLs; remove × after publish; or over-cap links persist. |

## Related automated coverage

| Layer | Filter / artifact |
|-------|-------------------|
| Invariants | `inv_`, `scripts/check_portal_issues.sh` |
| Proptest | `prop_` (incl. attachment token round-trip) |
| Battle | `battle_` (incl. `battle_parallel_attach_respects_cap`) |
| E2E | `e2e_` (`--test integration_tests`, incl. image gallery) |
