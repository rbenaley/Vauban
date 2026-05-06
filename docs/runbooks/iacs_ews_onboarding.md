# Runbook -- IACS / EWS onboarding lifecycle

> Operator playbook for the **IACS / Engineering Workstation (EWS)**
> module: configuration kill-switch, onboarding-request lifecycle,
> EWS state transitions (disable / enable / offboard), audit queries
> against the append-only `ews_audit_log`, and recovery paths.
>
> Audience: on-call operators, IACS administrators, compliance
> reviewers.
> Severity: LOW for routine reads; MEDIUM when the kill-switch is
> toggled in production or when bulk-disabling EWS rows; HIGH if
> append-only invariants are reported violated.

## Background

IACS is the preliminary scaffolding for managing **Engineering
Workstations** -- operator laptops / desktops running the SSH client
that will reach future IACS assets through Vauban. The data model is
intentionally separated from the core `assets` table:

- `ews_onboarding_requests` -- the request lifecycle
  (`pending -> approved | rejected | cancelled`).
- `ews` -- approved workstations holding the active SSH public key,
  with reversible `disabled_at` and irreversible `offboarded_at`
  soft-delete columns.
- `ews_audit_log` -- append-only trail of every state transition.

Migration: [`20260506000000_iacs_ews_onboarding`](../../vauban-db/migrations/20260506000000_iacs_ews_onboarding/up.sql).

## URL surface

| URL | Verb | Casbin gate | Purpose |
|-----|------|-------------|---------|
| `/iacs/onboard` | GET | `iacs:request` | Render the onboarding form (key generation help + request form) |
| `/iacs/onboard` | POST | `iacs:request` | Submit a new request -> `pending` row, redirects to `/sessions/my-requests` |
| `/iacs/onboard/{uuid}/edit-form` | GET | `iacs:request` | Edit form (only while pending and only the requester) |
| `/iacs/onboard/{uuid}/edit` | POST | `iacs:request` | Save edits |
| `/iacs/onboard/{uuid}/cancel` | POST | `iacs:request` | Cancel a pending request |
| `/iacs/{uuid}/offboard-self` | POST | `iacs:request` | User-initiated offboarding of one of their approved EWS |
| `/iacs/admin` | GET | `iacs:manage` | Admin landing: pending requests + EWS list |
| `/iacs/admin/request/{uuid}` | GET | `iacs:manage` | Request detail page |
| `/iacs/admin/request/{uuid}/approve` | POST | `iacs:manage` | Approve a pending request -> creates the matching `ews` row |
| `/iacs/admin/request/{uuid}/reject` | POST | `iacs:manage` | Reject a pending request (reason >= 5 chars required) |
| `/iacs/admin/ews/{uuid}` | GET | `iacs:manage` | EWS detail page |
| `/iacs/admin/ews/{uuid}/disable` | POST | `iacs:manage` | Disable an active EWS (reversible) |
| `/iacs/admin/ews/{uuid}/enable` | POST | `iacs:manage` | Re-enable a disabled EWS |
| `/iacs/admin/ews/{uuid}/offboard` | POST | `iacs:manage` | Offboard an EWS (irreversible) |

The `/iacs/admin/*` sub-tree carries
`route_layer(require_iacs_manage)` so a non-admin gets **403 BEFORE
the handler runs** (anti-enumeration: a random UUID under the
sub-tree is rejected without a DB lookup). Each handler ALSO
re-checks `perms.iacs_manage` in its body for defence-in-depth.

## Kill-switch -- `[industrial].enabled`

The whole IACS surface is gated by a single config flag in
`vauban.conf`:

```toml
[industrial]
enabled = true            # set to false to fully hide the IACS surface
max_ews_per_user = 0      # 0 = no cap; otherwise a per-user EWS quota
```

Enforcement is centralised in
[`PermissionContext::load`](../../vauban-web/src/auth/permissions.rs)
(folded into every `iacs_*` flag). When `enabled = false`:

- the sidebar entry disappears,
- the IACS button on `/assets` is hidden,
- every `/iacs/*` URL collapses to 404 (user zone) or 403 (admin
  zone),
- already-issued JWTs see the new flag on the next request -- no
  cache, no warm-up window.

Source-level invariant pinned by
[`scripts/check_iacs_kill_switch.sh`](../../vauban-web/scripts/check_iacs_kill_switch.sh):
the `industrial.enabled` flag MUST NOT be read from anywhere except
the canonical loader and `main.rs` boot. Any handler / template
introducing a parallel decision path is flagged in CI.

Runtime invariant pinned by
[`tests/web/iacs_kill_switch_test.rs`](../../vauban-web/tests/web/iacs_kill_switch_test.rs).

### Toggling in production

1. Edit `vauban.conf` -> set `[industrial].enabled = false` (or
   `true`).
2. Reload the service:

   ```bash
   sudo systemctl reload vauban-web vauban-access
   ```

3. Verify from a browser logged in as a regular user: the **IACS**
   sidebar entry should be gone and `/iacs/onboard` should return
   404.
4. Existing `ews` and `ews_onboarding_requests` rows are NOT
   modified -- the kill-switch only hides the surface. Re-enabling
   restores access to the same data.

> Severity bump to MEDIUM: announce the toggle on the operator
> channel BEFORE flipping the switch. Active EWS owners will lose
> the "My Requests" UI for their EWS rows for the duration of the
> outage. The keys themselves remain valid (the proxy enforcement
> happens elsewhere); a flip is only a UI hide.

## Standard operator queries

> Run from the `vauban-web` PostgreSQL role (read-only on
> `ews_audit_log`). Replace placeholders in `{...}`.

### All onboarding events for a given EWS

```sql
SELECT created_at, event, actor_username, target_username,
       ews_name, public_key_fingerprint, decision_reason, actor_ip
FROM ews_audit_log
WHERE ews_uuid = '{ews_uuid}'
   OR request_uuid = (
       SELECT request_uuid FROM ews WHERE uuid = '{ews_uuid}'
   )
ORDER BY created_at ASC;
```

### All decisions made by a given admin over the last 30 days

```sql
SELECT created_at, event, target_username, ews_name,
       public_key_fingerprint, decision_reason, actor_ip
FROM ews_audit_log
WHERE actor_user_id = {admin_id}
  AND event IN ('approved', 'rejected', 'disabled', 'enabled', 'offboarded')
  AND created_at >= NOW() - INTERVAL '30 days'
ORDER BY created_at DESC;
```

### Currently active EWS rows (for a snapshot inventory)

```sql
SELECT e.uuid AS ews_uuid, u.username AS owner,
       e.name, e.key_algo, e.public_key_fingerprint,
       e.created_at
FROM ews e
INNER JOIN users u ON u.id = e.user_id
WHERE e.offboarded_at IS NULL
  AND e.disabled_at IS NULL
ORDER BY u.username, e.name;
```

### Pending requests older than 7 days (SLA breach detection)

```sql
SELECT r.uuid AS request_uuid, u.username AS requester,
       r.name AS ews_name, r.created_at,
       NOW() - r.created_at AS age
FROM ews_onboarding_requests r
INNER JOIN users u ON u.id = r.user_id
WHERE r.status = 'pending'
  AND r.created_at < NOW() - INTERVAL '7 days'
ORDER BY r.created_at ASC;
```

### Fingerprint provenance check

```sql
SELECT 'ews' AS source, e.uuid::text, e.name, u.username,
       e.created_at, e.disabled_at, e.offboarded_at
FROM ews e
INNER JOIN users u ON u.id = e.user_id
WHERE e.public_key_fingerprint = '{fingerprint_hex}'
UNION ALL
SELECT 'request' AS source, r.uuid::text, r.name, u.username,
       r.created_at, NULL, NULL
FROM ews_onboarding_requests r
INNER JOIN users u ON u.id = r.user_id
WHERE r.public_key_fingerprint = '{fingerprint_hex}'
ORDER BY created_at ASC;
```

The DB-level invariant
`ews_active_fingerprint_uniq` (partial unique index, see
[migration up.sql §2](../../vauban-db/migrations/20260506000000_iacs_ews_onboarding/up.sql))
guarantees that at most ONE non-offboarded `ews` row holds any given
fingerprint. The query above exists for forensic audits, not for
runtime checks.

## Lifecycle troubleshooting

### A user reports "EWS onboarding submitted" but no admin notification

1. Check `ews_audit_log` for the `submitted` event:

   ```sql
   SELECT * FROM ews_audit_log
   WHERE event = 'submitted'
     AND target_username = '{username}'
   ORDER BY created_at DESC LIMIT 5;
   ```

2. If the event is present, the request reached the DB. Inspect the
   mailer queue:

   ```sql
   SELECT * FROM email_events
   WHERE event_kind LIKE 'IacsOnboard%'
     AND created_at >= NOW() - INTERVAL '1 hour'
   ORDER BY created_at DESC;
   ```

3. If the event is absent, the request never reached `vauban-access`
   -- inspect `vauban-web` logs for the user's session at submit
   time, looking for `IacsError::Internal` or CSRF rejections.

### A user cannot self-offboard their EWS

The user must own the EWS. The handler maps `EwsDenyReason::NotOwner`
to a 404 to prevent enumeration -- so a 404 from
`/iacs/{uuid}/offboard-self` means either:

- the UUID does not exist, OR
- the UUID exists but the caller is not the owner.

Verify ownership with:

```sql
SELECT u.username AS owner
FROM ews e
INNER JOIN users u ON u.id = e.user_id
WHERE e.uuid = '{ews_uuid}';
```

Self-offboarding is also blocked when the EWS is already offboarded
(`EwsDenyReason::EwsAlreadyOffboarded`, surfaced as a flash message,
not a 404).

### "This SSH public key is already registered"

Surfaced as a flash message on the form (`EwsDenyReason::KeyAlreadyUsed`).

The conflict can come from:

- another active or disabled `ews` row carrying the same fingerprint,
- another pending request the requester does not own.

Run the **Fingerprint provenance check** query above. The user MUST
rotate their key (`ssh-keygen -t ed25519 -C VAUBAN -N ""`) and resubmit;
the form does not expose a way to "force" a conflicting key.

## Append-only invariant

`ews_audit_log` is append-only. The trigger
`block_ews_audit_log_mutation` raises on every `UPDATE` and `DELETE`
(except FK-cascaded `SET NULL` on `actor_user_id` /
`target_user_id`, which keeps the snapshot usernames intact).

Verify the invariant on a fresh database:

```sql
-- Both should raise check_violation:
UPDATE ews_audit_log SET event = 'edited' WHERE id = 1;
DELETE FROM ews_audit_log WHERE id = 1;
```

If either succeeds, the trigger has been dropped or the table has
been re-created without the trigger -- this is a HIGH-severity
incident. Restore the trigger from
[migration up.sql §4](../../vauban-db/migrations/20260506000000_iacs_ews_onboarding/up.sql)
and freeze IACS writes until a forensic review of recent rows.

## Recovery paths

### Cancelled-by-mistake request

A cancelled request stays in `ews_onboarding_requests` with
`status = 'cancelled'` and is NOT editable (the CHECK constraint
`ews_request_decision_consistency` forbids transitioning back to
`pending`). The user MUST submit a new request -- there is no
"un-cancel" button.

### Erroneous approval

There is no "un-approve" verb. If an admin approved a request that
should have been rejected:

1. **Disable** the EWS row immediately
   (`POST /iacs/admin/ews/{uuid}/disable`). This is reversible and
   keeps the fingerprint locked, preventing the user from
   re-submitting the same key.
2. Once the case is reviewed, **offboard** the EWS row
   (`POST /iacs/admin/ews/{uuid}/offboard`). This is irreversible
   and releases the fingerprint.
3. The audit trail now shows `submitted -> approved -> disabled
   -> offboarded`, with the actor / reason / IP for each
   transition.

### Erroneous rejection

A rejected request is final. The user must submit a new request
(with the same key + new justification). The original `rejected`
row stays for audit; the partial unique index does not block a
re-submission because rejected rows are not in the
`pending`-filtered index.

## Change log

| Version | Date | Notes |
|---------|------|-------|
| 0.7.4 | 2026-05-06 | Initial release: data model + user / admin handlers + kill-switch + audit log. |
