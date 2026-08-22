# Smoke test: magic links + SMTP mail

**Audience:** operators / developers validating passwordless login and company
invite/revoke mail on a staging or local host.

**Severity:** High (auth + onboarding).

## Prerequisites

- VCP running with `VCP_ENVIRONMENT=development` (or staging with TEM).
- SMTP catch-all reachable per `[mail]`:
  - Local (dev/testing): [Mailpit](https://github.com/axllent/mailpit) (or
    equivalent) on `localhost:1025` with `smtp_encryption = "starttls"` and
    `smtp_accept_invalid_certs = true` (self-signed). UI often on
    `localhost:8025`. MacPorts: install `mailpit +ui` so `/dist/app.css` /
    `app.js` are embedded.
  - Staging/prod TEM: Scaleway (`smtp.tem.scaleway.com`, `starttls` / `tls`);
    `smtp_username` = Project ID, `smtp_password` = IAM secret (host secret);
    keep `smtp_accept_invalid_certs = false`.
  - Other self-signed submission: same starttls/tls + `smtp_accept_invalid_certs
    = true` (forbidden with `plaintext`). VCP warns at transport build time;
    production allows the flag (unlike plaintext SMTP).
- `[magiclinks]` configured: `vcp_admin`, `from_address`, `token_ttl_secs = 300`,
  `token_retention_days` (dev `7`, prod `1`), `purge_interval_minutes = 60`.
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
4. In Mailpit/TEM: receive **HTML** “Sign in to Vauban Customer Portal”
   (Vauban branding, CID `vauban-logo`, no raw tokens in logs, bulletproof
   button) with link
   `/login/magic?token=…`, plus a plain-text alternative.
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

1. As staff, create a company with one account email → branded **HTML**
   invitation mail arrives (org name in title/body, magic-link button, CID
   logo). Plain-text alternative still present.
2. Recipient opens magic link → lands on `/{org}`.
3. Remove that email from the company fiche and save → branded **HTML**
   revocation mail (no sign-in link); user cannot obtain a new session when
   that was their only membership.
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
3. While the request is in flight, the submit button shows **Sending...** and
   stays disabled (no double-submit).

### 3b. Mail circuit / sign-in unavailable

Simulate SMTP down (stop Mailpit / TEM, or point `[mail]` at a closed port)
and retry until the process opens the mail circuit
(`circuit_failure_threshold`, default 3 consecutive send failures).

1. On the attempt that opens the circuit (3rd consecutive SMTP failure for a
   known address), the form must leave **Sending...** and show the alert:
   **Sign-in is temporarily unavailable. Please try again later.**
   (no Check-your-email panel, no stuck Sending button).
2. Immediately after, submit an **unknown** email — same alert (no oracle).
3. Restore SMTP; wait `circuit_open_secs` (default 60) or restart `vcp`, then
   confirm a known email returns to Check-your-email and mail arrives.

**Fail if:** known vs unknown show different copy while the circuit is open;
or the unavailable message appears for only one class of address.

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

### 5. Token table retention (ops)

1. After several login cycles, `SELECT count(*) FROM magic_link_tokens;` may grow
   briefly (consumed / superseded rows stay until purge).
2. The in-process job runs at boot then every `purge_interval_minutes` (60) and
   deletes rows with `expires_at < now - token_retention_days` (dev keeps 7 days
   for forensics; prod keeps 1 day).
3. Optional: wait one interval (or restart `just run`) and confirm the count
   drops for clearly expired rows.

**Fail if:** the table grows without bound across days with no deletes after
expiry + retention; or active (unexpired) tokens disappear mid-TTL.

### 6. Self-signed SMTP submission (`smtp_accept_invalid_certs`)

Use when the submission server presents a self-signed (or otherwise
untrusted) certificate. Mailpit plaintext does not need this flag.

1. Set in the effective config (e.g. `local.toml` / host `vcp.conf`):

   ```toml
   [mail]
   smtp_host = "localhost"
   smtp_port = 587
   smtp_encryption = "starttls"   # or "tls" on 465
   smtp_accept_invalid_certs = true
   ```

2. Restart `vcp`. Confirm a warn line about `smtp_accept_invalid_certs=true`.
3. Request a magic link for a known account.
4. Confirm the message arrives at the submission server / catch-all.

**Pass:** mail delivered with STARTTLS or implicit TLS against the self-signed
peer. **Fail if:** handshake fails while the flag is true; or
`smtp_encryption = "plaintext"` with the flag set (config must refuse to
load).

## Related

- [`admin_companies_smoke_test.md`](admin_companies_smoke_test.md)
- `[mail]` / `[magiclinks]` in `config/development.toml` and `config/vcp.conf`
