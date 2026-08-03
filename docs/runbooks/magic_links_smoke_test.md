# Smoke test: magic links + SMTP mail

**Audience:** operators / developers validating passwordless login and company
invite/revoke mail on a staging or local host.

**Severity:** High (auth + onboarding).

## Prerequisites

- VCP running with `VCP_ENVIRONMENT=development` (or staging with TEM).
- SMTP catch-all reachable per `[mail]`:
  - Local: [Mailpit](https://github.com/axllent/mailpit) on `localhost:1025`
    (`smtp_encryption = "plaintext"`). UI on `localhost:8025`.
    MacPorts: install `mailpit +ui` so `/dist/app.css` / `app.js` are embedded.
  - Staging/prod: Scaleway TEM (`smtp.tem.scaleway.com`, `starttls` / `tls`);
    `smtp_username` = Project ID, `smtp_password` = IAM secret (host secret).
- `[magiclinks]` configured: `vcp_admin`, `from_address`, `token_ttl_secs = 300`.
- Browser can open `server.public_origins[0]` (HTTPS) with Topcoat runtime
  enabled (no progressive-enhancement POST fallback on `/login`).

Automated coverage (CI): `cargo test --test integration_tests -- magic_link companies_magic_mail choose_org -- --test-threads=1`.

## Pass / Fail

### 1. Staff JIT (`vcp_admin`)

1. Open `/login` — email field only (no password, no seed banner).
2. Submit `magiclinks.vcp_admin` (e.g. `support@vauban.sh`).
3. Confirm the page stays on `/login` and swaps in-place to **Check your email**
   (no redirect to `/login/check-email`). The typed address is recalled; **Resend
   in MM:SS** starts at `05:00` when `token_ttl_secs = 300` (button disabled).
4. In Mailpit/TEM: receive “Sign in to Vauban Customer Portal” with link
   `/login/magic?token=…`.
5. Open link within 300 seconds → land on `/vauban` as admin (`/admin` works).
6. Reuse the same link → rejected to `/login?error=link` with the generic banner
   (“This sign-in link is invalid or has expired. Request a new one.”) — same
   copy for expired / already-used / garbage tokens (no cause-specific text).
7. Optional: wait until cooldown hits `00:00`, click **Resend** → a new mail
   arrives and cooldown restarts; **Use a different email** returns to the form
   without a navigation.

**Fail if:** password field present; full-page redirect to check-email; mail
missing; landing not `/vauban`; reuse succeeds without error banner; distinct
messages for expired vs used; plaintext SMTP accepted when
`environment = production`.

### 2. Company invitation + revoke

1. As staff, create a company with one account email → invitation mail arrives.
2. Recipient opens magic link → lands on `/{org}`.
3. Remove that email from the company fiche and save → revocation mail
   (no sign-in link); user cannot obtain a new session when that was their
   only membership.
4. (Optional multi-org) User also member of another company: remove from one
   fiche and save → still receives org-scoped revocation mail; can still
   sign in via the remaining membership.
5. Re-add the same email → invitation again; same user id (revive); prior
   issues still show the opener display name.

**Fail if:** hard-deleted user breaks issue detail; orphan revoke still allows
login; multi-org remove skips the revocation mail; revive creates a second
user row.

### 3. Anti-enumeration

1. Submit an unknown email on `/login`.
2. Same in-page **Check your email** panel; **no** outbound message in Mailpit
   for that address.

### 4. Multi-org picker

1. Provision the same email on two client companies (admin companies UI).
2. Request a magic link for that email and open it.
3. Land on `/choose-org` listing both organization names/slugs (not auto-routed
   to an arbitrary first membership).
4. Open one org link → dashboard for that tenant works; a third unrelated slug
   stays 404.
5. Visit `/` while still logged in → redirect back to `/choose-org`.

**Fail if:** magic link skips the picker with two memberships; picker lists
orgs the user is not a member of; staff accounts are forced through the picker.

## Related

- [`admin_companies_smoke_test.md`](admin_companies_smoke_test.md)
- `[mail]` / `[magiclinks]` in `config/development.toml` and `config/vcp.conf`
