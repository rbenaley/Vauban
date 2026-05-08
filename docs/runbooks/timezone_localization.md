# Runbook -- Browser timezone localization

> Server-rendered HTML displays every date/time in the operator's
> browser timezone via the `vbn_tz` cookie pipeline introduced in
> v0.7.7. Database, IPC, logs, audit and `/api/v1/*` JSON stay UTC
> end-to-end.
>
> Audience: on-call operators, frontend / web reviewers, security
> auditors investigating cookie-related anomalies.
> Severity: LOW for "I see UTC in the UI on first hit" (the
> bootstrap reload is the cure); MEDIUM if every page renders UTC
> for a known-good Paris/NY laptop; HIGH if `vbn_tz` carries a
> non-IANA payload that round-trips into the response (security
> incident).

## Topology at a glance

```
Browser -> Intl.DateTimeFormat -> document.cookie vbn_tz=Europe/Paris
   |                                     |
   v                                     v
GET /any-html-page -- Cookie: vbn_tz=Europe/Paris
                                         |
                                         v
                  BrowserTz extractor (Tz::from_str + 64-byte cap)
                                         |
                                         v
                  BaseTemplate::new(title, user, browser_tz.0)
                                         |
                                         v
                  Askama: {{ x.created_at|local(tz) }} -> "2026-05-08 22:14 CEST"
```

DB / logs / IPC / audit columns are NEVER touched: they keep
emitting `2026-05-08T20:14:00Z` (UTC) regardless of the cookie.

## Background

| Plane | Timezone | Format |
|---|---|---|
| Postgres `TIMESTAMPTZ` columns | UTC | RFC 3339 (`2026-01-15T10:30:00Z`) |
| `tracing` / structured logs | UTC | RFC 3339 |
| `/api/v1/*` JSON responses | UTC | RFC 3339 |
| IPC payloads (`shared::messages`) | UTC | RFC 3339 |
| Audit ledger | UTC | RFC 3339 |
| Server-rendered HTML (Askama) | **caller's browser timezone** | `YYYY-MM-DD HH:MM ZZZ` (or `:SS`) |
| `<time datetime="...">` attribute | UTC | ISO 8601 (`2026-01-15T10:30:00Z`) |

A 44-line vanilla JS bootstrap (`vauban-web/static/js/vbn-tz.js`)
reads `Intl.DateTimeFormat().resolvedOptions().timeZone`, posts it
to the `vbn_tz` cookie (`Path=/; SameSite=Lax; Max-Age=31536000`,
plus `Secure` over HTTPS) and -- on the first hit only -- triggers
a silent `location.replace()` so the very first paint already comes
localized.

The Axum extractor `BrowserTz` (in
`vauban-web/src/middleware/browser_tz.rs`) parses the cookie:
empty / oversized / characters outside `[A-Za-z0-9_/+-]` /
unknown IANA name all collapse to `Tz::UTC`. The extractor is
**infallible** so handlers always see a `Tz`.

## Operator surface

There is no admin page for timezone state: the cookie lives on
the browser and is opaque to the server outside the request that
carries it. Diagnostics happen in three places:

1. **The browser's DevTools** -- inspect the `vbn_tz` cookie under
   `Application -> Cookies -> https://<your-vauban>/`.
2. **The server response body** -- `curl -k -b 'access_token=...; vbn_tz=Europe/Paris'`
   to confirm the same render path you'd get in a browser.
3. **The CSP report endpoint / browser console** -- a missing or
   blocked `vbn-tz.js` will leave the cookie absent and every page
   stuck on UTC.

## Standard diagnostic flows

> Replace placeholders in `{…}`. The session token is the JWT
> from `Set-Cookie: access_token=...` after login.

### Verify the bootstrap script is being served

```sh
curl -ksI 'https://{host}/static/js/vbn-tz.js' | head -5
```

Expect `HTTP/2 200` with `Content-Type: text/javascript; charset=utf-8`
or similar. A 404 means the static-assets layer was misconfigured
or the file was not deployed.

### Verify a date renders in the browser timezone

```sh
# UTC fallback (no cookie):
curl -ks -H "Cookie: access_token={token}" \
  'https://{host}/accounts/profile' | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} [A-Z]+'

# Localized to Paris:
curl -ks -H "Cookie: access_token={token}; vbn_tz=Europe/Paris" \
  'https://{host}/accounts/profile' | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} [A-Z]+'
```

Expect the second call to differ from the first by the Paris
offset (CEST in summer, CET in winter). If both calls produce
`UTC`, the extractor is rejecting the cookie -- jump to the
"Triage: Paris cookie not honored" section.

### Reproduce a known-good display

`vauban-web/tests/web/timezone_e2e_test.rs` pins five canonical
cookie scenarios against a fixed `2026-01-15 10:30:00Z` source
date. Run them locally to validate the build:

```sh
cargo test -p vauban-web --test mod timezone -- --test-threads=1
```

Expect 20 passed across `timezone_e2e_test`, `timezone_lints_test`
and `timezone_snippet_test`.

## Triage: operator reports times in the wrong timezone

The render path has a single decision point (the cookie). Walk
through these in order:

1. **Open DevTools -> Application -> Cookies** on the affected
   page. Is `vbn_tz` present?
   - **No** -> the bootstrap never ran. Check the browser console
     for a CSP or 404 error on `/static/js/vbn-tz.js`. Confirm
     `<head>` of any page references the script BEFORE `<title>`.
   - **Yes, but blank** -> cookie was reset. The next page load
     should re-post it; if it doesn't, the snippet was modified
     and no longer writes the cookie.
2. **Read the cookie value**.
   - It MUST be a URL-encoded IANA name. Examples that pass:
     `Europe%2FParis`, `America%2FNew_York`, `Asia%2FCalcutta`.
   - Anything else -> the extractor falls back to `Tz::UTC` (by
     design, fail-closed). Common causes: a proxy strips the
     cookie value, a competing JS library overwrites it, the OS
     reports a non-IANA tz on a heavily-restricted browser
     (Chromium with `--time-zone-for-testing`).
3. **Reproduce the request server-side** with `curl` (see above).
   Same timezone? Bug is upstream of the server. Different
   timezone? Inspect the request that reached the server vs. the
   one the browser sent (a reverse proxy may be rewriting
   `Cookie:`).
4. **Confirm the page actually uses the filter.** Run the lint:
   ```sh
   bash vauban-web/scripts/check_no_naked_datetime.sh
   ```
   A regression that bypasses `|local(tz)` will print the file +
   line and exit non-zero.

## Triage: cookie collapses to UTC despite valid IANA name

This is rare; the extractor's whitelist accepts every IANA tzdb
name plus `Etc/GMT±N`. Verify:

```rust
// vauban-web/src/middleware/browser_tz.rs
parse_browser_tz("Europe/Paris")  // Some(Tz::Europe__Paris)
parse_browser_tz("Foo/Bar")       // None  (returns Tz::UTC at extractor)
```

If the cookie was set by a non-Vauban issuer (a previous
deployment, a misconfigured reverse proxy injecting it), it might
exceed 64 bytes. The 64-byte ceiling is enforced both client-side
(`vbn-tz.js`) and server-side (`VBN_TZ_COOKIE_MAX_LEN`). Reset
the cookie:

```js
// In the browser console:
document.cookie = 'vbn_tz=; Path=/; Max-Age=0';
location.reload();
```

The bootstrap will re-post a clean value.

## Triage: page mixes UTC and localized timestamps

If a single page shows some dates in UTC and others in CEST, the
template has a `String`-typed field that was pre-formatted with a
hardcoded UTC suffix in the handler instead of going through
`crate::utils::format_local*`. Run:

```sh
bash vauban-web/scripts/check_no_naked_datetime.sh
```

The lint refuses `format!("...UTC...")` literals inside
`vauban-web/src/handlers/**`. A tracing macro is exempt -- if you
see a hit on a `tracing::info!` line, the lint matched a false
positive and the line is fine.

## Triage: append-only XSS attempt via cookie

If a security alert flags a cookie value containing `<`, `>`, `;`,
`"` or any character outside `[A-Za-z0-9_/+-]`:

1. The extractor will have already collapsed the cookie to
   `Tz::UTC` -- the payload never reaches the template.
2. Confirm by running the response through the diagnostic
   `curl` above and grepping for the payload; it MUST NOT appear.
3. Treat the source IP as a probe and follow the security
   incident protocol (snapshot the access logs, correlate with
   `request_id` if the attacker carried Auth, escalate).

The matching unit test
(`browser_tz::tests::extractor_falls_back_when_cookie_xss_attempt`)
asserts this behavior; the E2E test
(`timezone_e2e_test::timezone_e2e_cookie_xss_probe_does_not_round_trip`)
asserts the payload absence in a real response.

## DST transitions

`chrono_tz` handles DST automatically; no operator action is
needed at the boundary. Pinned regressions:

- 2026-03-29 02:30 Paris (spring-forward, the local time `02:30`
  doesn't exist; chrono interprets the UTC source unambiguously).
- 2026-10-25 02:30 Paris (fall-back, the local time `02:30` is
  ambiguous; chrono emits the post-transition tz).

Both transitions are pinned by `vauban-web/src/utils.rs::tests`
and reproducible with `cargo test format_local_handles_paris_dst`.

## Recovery: bulk cookie reset after a wire-format change

If a future major version changes the cookie wire format
(unlikely, but possible), the rollout strategy is:

1. Bump `VBN_TZ_COOKIE_NAME` (e.g. `vbn_tz` -> `vbn_tz_v2`) and
   ship a code change that ignores the legacy name.
2. Browsers will see no cookie under the new name -> the
   bootstrap reposts via the standard first-hit reload path.
3. The legacy `vbn_tz` cookie ages out via `Max-Age` (one year)
   or can be expired by the operator with a single deploy that
   sets `Set-Cookie: vbn_tz=; Path=/; Max-Age=0` from any 200
   response.

## Related

- Source: `vauban-web/src/middleware/browser_tz.rs`,
  `vauban-web/src/utils.rs`,
  `vauban-web/static/js/vbn-tz.js`,
  `vauban-web/templates/base.html`.
- Lints: `vauban-web/scripts/check_no_naked_datetime.sh`,
  `vauban-web/scripts/check_template_carries_tz.sh`.
- Tests: `vauban-web/tests/web/timezone_e2e_test.rs`,
  `vauban-web/tests/web/timezone_lints_test.rs`,
  `vauban-web/tests/web/timezone_snippet_test.rs`.
- Rule: [`.cursor/rules/timezone-localization.mdc`](../../.cursor/rules/timezone-localization.mdc).
