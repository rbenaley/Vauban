# Runbook — JIT approval audit & separation-of-duties

> Operator queries against `approval_audit_log`, CSV export, and recovery
> procedures introduced in migration
> `20260425000000_approval_audit_and_sod`.
>
> Audience: on-call operators, compliance reviewers, security auditors.
> Severity: LOW for routine reads; MEDIUM if SoD warnings recur; HIGH if
> append-only invariants are reported violated.

## Background

Every JIT access decision (approve or reject) writes one row to
`approval_audit_log`. The table is **append-only**: the trigger
`block_approval_audit_log_mutation` raises on every `UPDATE` and
`DELETE`, including FK cascades. Snapshot fields (`actor_username`,
`requester_username`, `asset_name`) are filled at decision time so a
later user soft-delete does not erase the trail.

Separation of Duties (SoD) is enforced at three layers:

- UI hides Approve/Reject controls for the viewer's own pending request.
- IPC `evaluate_eligibility` returns `SelfApproval` if attempted.
- Two `CHECK` constraints on `proxy_sessions`
  (`approval_separation_of_duties`, `rejection_separation_of_duties`)
  catch any path that bypasses the IPC layer.

See [IAM Architecture §15.9](../technical/Vauban_IAM_Architecture_EN(1.0).md#159-approval-audit--separation-of-duties)
for the threat model (T1–T9) and schema.

## Operator surface

The admin-only page **`/audit/approvals`** renders the table with
filters on actor, requester, asset, decision, and date range. Use it
for ad-hoc browsing. For exports or longer windows, run the SQL
queries below directly against the database.

## Standard queries

> Run these from the `vauban-web` PostgreSQL role (read-only on
> `approval_audit_log`). Replace placeholders in `{…}`.

### All decisions for a given actor over the last 30 days

```sql
SELECT created_at, decision, requester_username, asset_name,
       protocol, decision_reason, decision_ip
FROM approval_audit_log
WHERE actor_user_id = {actor_id}
  AND created_at >= NOW() - INTERVAL '30 days'
ORDER BY created_at DESC;
```

### All decisions for a given requester

```sql
SELECT created_at, decision, actor_username, asset_name,
       decision_reason, decision_ip
FROM approval_audit_log
WHERE requester_user_id = {requester_id}
ORDER BY created_at DESC;
```

### All decisions for a given asset

```sql
SELECT created_at, decision, actor_username, requester_username,
       protocol, decision_reason
FROM approval_audit_log
WHERE asset_uuid = '{asset_uuid}'
ORDER BY created_at DESC;
```

### Approval/rejection ratio per actor

```sql
SELECT actor_username,
       COUNT(*) FILTER (WHERE decision = 'approve') AS approves,
       COUNT(*) FILTER (WHERE decision = 'reject')  AS rejects,
       COUNT(*)                                     AS total
FROM approval_audit_log
WHERE created_at >= NOW() - INTERVAL '90 days'
GROUP BY actor_username
ORDER BY total DESC;
```

### Decisions correlated with a `request_id`

The audit middleware tags every HTTP request with a `request_id` and
threads it through to the audit row. Use it to join with HTTP and
syslog records:

```sql
SELECT created_at, decision, actor_username, requester_username,
       asset_name
FROM approval_audit_log
WHERE request_id = '{request_id}';
```

## CSV export

For a compliance review or a one-shot extraction, use
`psql --csv` directly:

```sh
psql "$DATABASE_URL" --csv -c "
  SELECT id, created_at, session_uuid, decision,
         actor_username, requester_username,
         asset_uuid, asset_name, protocol,
         duration_override_seconds, decision_reason,
         decision_ip, decision_user_agent, request_id
  FROM approval_audit_log
  WHERE created_at >= '{from_iso}'
    AND created_at <  '{to_iso}'
  ORDER BY created_at ASC
" > approval_audit_$(date -u +%Y%m%dT%H%M%SZ).csv
```

The export uses the snapshot columns, so the file is self-contained:
no later soft-delete or rename of users/assets will rewrite it.

## Mono-admin recovery

If the deployment has fewer than two administrators, SoD becomes
structurally impossible to satisfy: there is no second human to
approve a request raised by the sole administrator. `vauban-access`
detects this at boot and re-checks every 30 minutes; the indicator is
a `WARN` log line containing the keyword **`mono-admin`**:

```
WARN vauban_access::admin_count: mono-admin deployment detected
     (admins=1, threshold=2); separation-of-duties cannot be satisfied
     for that admin's own requests until a second administrator exists
```

Recovery (in order of preference):

1. **Promote a second administrator.** Use the user management UI to
   grant the `admin` role to a trusted user. The warning disappears
   on the next 30-minute tick (or restart `vauban-access` to re-check
   immediately).
2. **Use a break-glass account.** If no other trusted user exists yet,
   a documented break-glass account (out-of-band credentials, audited
   creation) can serve as the second approver until normal staffing
   is restored.
3. **Do not relax the invariant.** The `CHECK` constraints remain
   active in mono-admin mode; the sole admin's own JIT requests will
   correctly fail with `SelfApproval`. The right answer is to add an
   approver, not to disable the check.

## Triage: append-only trigger reported

If application logs surface a database error containing
**`approval_audit_log is append-only`**, an attempt was made to
`UPDATE` or `DELETE` an audit row. Possible causes:

- A FK cascade fired because someone tried to **hard-delete a user**
  that still has audit rows. This is the trigger doing its job; switch
  to soft-delete (`is_deleted = true`).
- A new code path inadvertently issues an `UPDATE` on the table; check
  the call site against the structural-pin tests
  (`t7_migration_check_constraint_names_match_handler_error_strings`).
- A deliberate compliance-archival workflow needs a separate, signed
  export rather than mutation; use the CSV export above.

## Recovery — corrupt or missing audit row

By design, audit rows cannot be repaired in place. If a decision was
recorded on `proxy_sessions` (status moved to `approved`/`rejected`)
but the audit insert failed, the transaction would have rolled both
back atomically. If you nevertheless observe a `proxy_sessions` row in
a decided state with no matching `approval_audit_log` entry, that
indicates a pre-migration row or a manual database edit and should be
treated as a security incident:

1. Lock the affected user account.
2. Snapshot `proxy_sessions` and any related logs.
3. Cross-reference with HTTP request logs by timestamp and IP.
4. Open an incident in the security tracker.

## Related

- [IAM Architecture §15.9](../technical/Vauban_IAM_Architecture_EN(1.0).md#159-approval-audit--separation-of-duties)
- [AccessGuard Architecture](../technical/Vauban_AccessGuard_Architecture_EN(1.0).md)
- [Virtual asset group runbook](virtual_asset_group.md)
- [IPC topology debugging](ipc_topology_debugging.md)
