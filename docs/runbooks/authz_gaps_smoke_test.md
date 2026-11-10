# Runbook -- Authorization gaps smoke test

> Manual validation after shipping the three authorization fences:
> owner-only interactive WebSockets, the superuser-target fence on the
> accounts API, and the bounded access request on the sessions API.
>
> Audience: release / staging operators.
> Severity: **BLOCKING** for the release that carries these fixes. Do
> not ship without A-C.

Related:

- Remediation note: [authz_shadowing_and_api_gaps.md](../remediation/authz_shadowing_and_api_gaps.md)
- [Approval audit](approval_audit.md)
- [IAM Architecture 1.1](../technical/Vauban_IAM_Architecture_EN(1.1).md)
- [Adversarial review](adversarial_review.md)
- Lints: `vauban-web/scripts/check_session_access_centralized.sh`,
  `vauban-web/scripts/check_no_handler_role_gates.sh`

## Automated prerequisites

```bash
rtk cargo fmt --all -- --check
rtk cargo clippy -p vauban-web --all-targets -- -D warnings
bash vauban-web/scripts/check_session_access_centralized.sh
bash vauban-web/scripts/check_no_handler_role_gates.sh
bash vauban-web/scripts/check_websocket_logging.sh
bash shared/scripts/check_security_claims.sh
rtk cargo test -p vauban-web --all-features --lib -- role_invariants access_request -- --test-threads=1
rtk cargo test -p vauban-web --all-features --test integration_tests -- authz_gaps -- --test-threads=1
```

## Lab prerequisites

- A supervisor-launched bastion with `[api].enabled = true`.
- Three accounts: `alice` (regular user), `sam` (staff, not
  superuser), `root2` (a second superuser, so the last-superuser fence
  is not what answers in section B).
- One SSH asset and one RDP asset that `alice` can open directly.
- One SSH asset behind an access rule with `require_approval = true`
  and `max_session_duration = 900`.
- An API key of scope `admin` for `sam`, and an API key for `alice`.
- `psql` access to the bastion database (read-only is enough).

## A -- Interactive WebSockets are owner-only

1. As `alice`, open an SSH session on the direct asset and leave the
   terminal open. Note the session UUID from the URL.
2. As `sam`, in another browser, open
   `/sessions/terminal/<uuid>` for that session.
3. As `sam`, with a WebSocket client and `sam`'s session cookie, open
   `wss://<bastion>/ws/terminal/<uuid>`.
4. Repeat steps 1-3 with the RDP asset and `wss://<bastion>/ws/rdp/<uuid>`.
5. As `sam`, open `wss://<bastion>/ws/session/<uuid>`.
6. Close every tab and client opened by `sam`.

Pass criteria:

- Steps 3 and 4: the handshake is refused with HTTP 404. `vauban-web`
  logs `WebSocket rejected: session not found / not owned`.
- Step 5: the handshake succeeds (the supervisor push feed is intact).
- At every step `alice`'s terminal and RDP canvas keep receiving
  output, and nothing typed by `sam` appears in them or in the
  recording.
- After step 6 the session row is still `active`:

  ```sql
  SELECT status, connected_at, expires_at, disconnected_at
  FROM proxy_sessions WHERE uuid = '<uuid>';
  ```

  `connected_at` and `expires_at` are identical before step 2 and after
  step 6.

## B -- Superuser accounts are fenced on the API

1. Note `root2`'s row:

   ```sql
   SELECT is_active, email FROM users WHERE username = 'root2';
   ```

2. With `sam`'s API key:

   ```bash
   rtk curl -sk -X PUT https://<bastion>/api/v1/accounts/<root2-uuid> \
     -H "Authorization: Bearer <sam-key>" -H "Content-Type: application/json" \
     -d '{"is_active": false}'
   ```

3. Same call with `-d '{"email": "probe@example.test"}'`.
4. Same call as step 3 against `alice`'s UUID.
5. Soft-delete a throwaway account from the web UI, then repeat step 3
   against its UUID with a superuser API key.

Pass criteria:

- Steps 2 and 3: HTTP 403, body contains `users:manage_admins`. The
  query of step 1 returns the same row. `root2` stays logged in.
- Step 4: HTTP 200 (staff still edits regular users).
- Step 5: HTTP 404, and the account stays `is_deleted = true`.

## C -- API access requests are bounded

1. With `alice`'s API key, on the approval-gated asset:

   ```bash
   rtk curl -sk -X POST https://<bastion>/api/v1/sessions \
     -H "Authorization: Bearer <alice-key>" -H "Content-Type: application/json" \
     -d '{"asset_id": "<asset-uuid>", "session_type": "ssh", "credential_id": "root", "justification": "Smoke test of the bounded request"}'
   ```

2. Repeat without the `justification` field.
3. Read the row created in step 1:

   ```sql
   SELECT status, credential_id, max_session_duration, client_ip, client_user_agent
   FROM proxy_sessions WHERE uuid = '<uuid-from-step-1>';
   ```

4. As a superuser, open `/sessions/approvals`, find the request, and
   approve it **without** entering a duration.
5. Read `expires_at` for the same row.

Pass criteria:

- Step 1: HTTP 200. Step 2: HTTP 400, no new row.
- Step 3: `status = pending`, `credential_id = pending`,
  `max_session_duration = 900`, `client_ip` is the caller's address
  (not `127.0.0.1` unless the call was made from the bastion itself),
  `client_user_agent` is the client's.
- Step 4: the request was listed, the approver received the
  notification email, and the audit trail holds an `ApprovalRequested`
  event for the request.
- Step 5: `expires_at` is about 900 seconds after the approval. It is
  not `NULL`.

## Rollback signal

Any failed criterion in A is a release blocker: the interactive data
plane is reachable by a non-owner. Do not work around it with a Casbin
policy change; revert the release.
