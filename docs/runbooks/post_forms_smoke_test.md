# POST forms smoke test (pages, rewrite, PRG)

**Audience:** Vauban Support staff validating a staging build after the
Topcoat 0.8.1 exploit lots.
**Severity:** medium — a wrong redirect style either leaks `?err=` state
into shareable URLs or, worse, re-POSTs a mutation on refresh.

Companion of [`topcoat_0_8_1_smoke_test.md`](topcoat_0_8_1_smoke_test.md)
(pin + trailing slash). This sheet covers the three form shapes.

## Automated prerequisites

- `just validate` green (or at least
  `cargo test --test integration_tests -- admin_companies admin_releases storage_e2e http_edge -- --test-threads=1`).
- Staff session on staging with `companies_manage`, `releases_manage`,
  `key_manage`.

## Pass / Fail

| Check | Pass | Fail |
|-------|------|------|
| Company create, invalid email | `POST /admin/companies/new` answers **200** with the form, the error copy, rail + topbar chrome; address bar stays `/admin/companies/new` | Bare form without rail, 303 to `?err=`, or 5xx |
| Company create, valid | **303** to `/admin/companies`; F5 on the list does not re-POST | 200 on the list URL, duplicate company on refresh |
| Release create without date | **200**, compose page with "A release date is required"; address bar `/admin/releases/new` with **no** `?err=` | 303 to `/admin/releases/new?err=date` or 500 |
| Release create, not a `.pkg` | **200**, compose page with the not-pkg modal open | Redirect with `?err=not_pkg` |
| Release create, valid | **303** to the WebAuthn confirm page (`token=` stays in the URL: ceremony state) | Rewrite / 200 |
| F5 after a failed create | Browser asks to resubmit (expected: the response was rendered on the POST); resubmitting shows the same error, creates nothing | Silent duplicate row |
| Key enrol, empty label | **200**, `/admin/key` with "Key label is required" callout; no `?err=label` | 303 with `?err=` |
| Key enrol, valid | **303** to `/admin/key?enrolled=<fp>` (deep-link highlight kept) | 200 or missing `enrolled=` |
| Key revoke without the confirm word | **200**, `/admin/key` re-rendered (modal reopens when the credential exists) | 303 with `err=confirm` |
| Choose-org picker (`/choose-org`, multi-org user) | Splash chrome (fonts, stylesheet) present; single-org / staff users get **307** | Unstyled picker, 303 |
| Docs detail with slug `new` | Docs rail item active, crumb "documentation" | Crumb "issues / new" or Home |

## Related

- `.cursor/skills/topcoat/references/UPGRADE-0.8.1.md` (Exploit lots, rewrite gotchas)
- `.cursor/skills/web-stack/SKILL.md` (Form handlers pattern)
- [`topcoat_0_8_1_smoke_test.md`](topcoat_0_8_1_smoke_test.md)
- [`org_account_smoke_test.md`](org_account_smoke_test.md)
