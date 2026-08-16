# Follow-up -- dormant email event producers

Six `EmailEvent` variants have HTML (and text) renderers but no
production call site that queues them. The branding lot does not
add those producers. Each is a behavioural change on an auth,
session-lifecycle, or IPC seam and needs its own pyramid.

Audience: maintainers picking up the next mailer lot.
Severity: **non-blocking** for HTML branding. Blocking for any
claim that "Vauban notifies on lockout / welcome / password reset".

Related: [email_html_rendering_smoke_test.md](email_html_rendering_smoke_test.md),
[vauban-web/email/README.md](../../vauban-web/email/README.md).

## Ranked by cost

### 1. `user.locked_after_failed_attempts`

Site: [`vauban-web/src/handlers/auth.rs`](../../vauban-web/src/handlers/auth.rs)
already computes `new_failed_attempts` and `locked_until_value` before
the UPDATE. Emit only when `locked_until_value.is_some()` (transition
into lockout, not every failed attempt).

Vivier to decide: user only, or user + `load_approver_contacts`.

### 2. `user.created`

Sites: `handlers/web/users.rs::create_user_web` and
`handlers/api/accounts.rs::create_user` both have `AppState` / `Mailer`.
Branch both to avoid UI/API asymmetry.

Vivier: the new user. Decide whether `AdminCommand::CreateUser` (CLI)
also notifies.

### 3. `access_request.expired`

Producer already runs in `tasks/cleanup.rs` via
`session_lifecycle::expire_stale_pending_requests_at`, which returns
only a `usize`. Switch to `.returning(...)` so requester, asset, and
protocol can be queued.

Vivier to decide: requester only, or requester + approver pool.

### 4. `user.mfa_reset_by_admin`

Only `AdminCommand::ResetMfa` exists; `handle_reset_mfa` receives a
`&DbPool` and no `Mailer`. Do not INSERT the outbox directly (that
bypasses `Mailer::queue` CRLF guards). Either thread the mailer into
`ipc/admin.rs` or add a web MFA-reset handler.

### 5. `security.mono_admin_detected`

Condition is the same count as `check_last_active_superuser`. No
watcher exists. Decide trigger (role-mutation edge vs periodic tick
with dedup) and vivier. The **body** correctly talks about superusers;
the destinataire pool is a separate decision (likely staff ∪ superuser).

### 6. `user.password_reset_requested`

No self-service forgot-password flow. `AdminCommand::ResetPassword`
sets a password from the CLI. The event carries `reset_url` +
`valid_until` and implies token mint, TTL, consume page, rate limit,
and session invalidation. Product lot, not a hook.
