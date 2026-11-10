# Remediation: three authorization gaps in `vauban-web`

> Status: **fixed in the working tree, not committed**. Found during the
> analysis of 10 November 2026 (v0.9.48, commit `188d7d29`).
> Method: code reading, then attack tests through the real router. No
> staging run yet: see the
> [smoke runbook](../runbooks/authz_gaps_smoke_test.md).

| # | Gap | Severity | Who could use it |
|---|---|---|---|
| 1 | A holder of `sessions:supervise` could take over another user's live SSH / RDP session | **high** | the whole `staff` role |
| 2 | `PUT /api/v1/accounts/{uuid}` edited or deactivated a superuser without `users:manage_admins` | **high** | `staff` holding an `admin`-scope API key |
| 3 | `POST /api/v1/sessions` recorded an approval request with no duration cap: the approved access never expired | **medium to high** | any API caller with an access rule on the asset |

## 1. Session takeover through `/ws/terminal` and `/ws/rdp`

### 1.1 What was wrong

`ws_session_guard` fenced three routes with one rule: the session owner,
or anyone holding `sessions:supervise` (`role:staff` in
`config/access/default_policy.csv`). That rule fits `/ws/session/{id}`,
a broadcast push feed with no input. It does not fit the two interactive
routes, which are the data plane of one proxy session:

- every text or binary frame is relayed to the target as keystrokes or
  pointer events (`send_data`, `send_input`, `resize`);
- the output channel is single-consumer:
  `ProxySshClient::subscribe_session` replaces the previous sender, so a
  second socket takes the output stream away from the first;
- the socket teardown calls `close_session` and marks the row
  `disconnected`.

A staff user who opened `/ws/terminal/{id}` of someone else's session
therefore typed as the owner on an asset they had no access rule for,
took the output away from the owner, and ended the session by leaving.
The recording attributed everything to the owner.

The existing test `test_terminal_ws_allowed_for_admin` pinned this as
intended behavior. It is now
`attack_terminal_ws_admin_non_owner_is_rejected`.

A second defect sat on the same path: `activate_proxy_session` updated
the row by `uuid` alone, so every new socket on an `active` session
rewrote `connected_at` and pushed `expires_at` back by a full
`max_session_duration`.

### 1.2 Fix

- `WsSessionAudience` (`handlers/websocket.rs`) names the two
  audiences. `OwnerOnly.honors_supervise(_)` is `false`.
- `ws_session_owner_guard` is mounted on `/ws/terminal/{id}` and
  `/ws/rdp/{id}` in `main.rs` and in the test router. It goes through
  the same `services::session_access` seam (intent `ConsumeWs`) with the
  supervise override off, so a non-owner gets the collapsed 404.
- `ws_session_guard` keeps the supervise override and stays on
  `/ws/session/{id}`.
- `activate_proxy_session` filters on `status = 'connecting'`: it
  applies once per session.

### 1.3 Behavior change to review

`terminal_page` and `rdp_page` still render for a supervisor (intent
`OpenViewer`, pinned by `websocket_session_supervise_allowed_for_staff`),
but the socket behind them now answers 404 for a non-owner. Live
"watching" through those pages never worked as observation: it was the
takeover described above.

Decision for the product owner: either remove the supervise override
from the two HTML wrappers as well, or build a real read-only shadow
(fan the proxy output out to several subscribers, never relay input,
never close on leave, mark the observer in the audit trail). This note
does neither.

## 2. Superuser accounts on the accounts API

### 2.1 What was wrong

`update_user` (`handlers/api/accounts.rs`) checked `perms.users_write`
only. The web form refuses to edit a superuser without
`users:manage_admins` (`handlers/web/users.rs`,
`update_user_web`). Through the API, staff could deactivate any
superuser but the last one, which also revoked their sessions, and
change their email or phone.

The three queries of the handler did not filter `is_deleted`, so a
soft-deleted account could be edited and reactivated.

The existing test `cannot_deactivate_last_active_superuser_via_api`
drove the call as a staff operator and relied on the last-superuser
fence to stop it. It now asserts the earlier refusal and checks the
in-transaction fence directly.

### 2.2 Fix

- `check_superuser_target_edit` (`services/role_invariants.rs`) is a
  pure check: a superuser target needs `can_manage_admins`. New
  variant `RoleViolation::SuperuserEditRequiresManageAdmins`.
- `update_user` runs it on the pre-transaction snapshot (403
  `users:manage_admins`) and again on the snapshot re-read inside the
  SERIALIZABLE transaction, so a concurrent promotion of the target is
  still refused.
- The pre-transaction read, the in-transaction re-read and the `UPDATE`
  filter `is_deleted = false`. A soft-deleted account answers 404.

### 2.3 Left as is

- `update_user_web` keeps its own inline check; it was already correct.
  Moving it onto `check_superuser_target_edit` is a refactor.
- `list_users` accepts an unbounded `limit`.

## 3. Access requests created through the sessions API

### 3.1 What was wrong

A `proxy_sessions` row in status `pending` is an approval request.
`create_session` (`handlers/api/sessions.rs`) inserted one without the
guarantees of the web form `submit_access_request`:

| Field | Web form | API before the fix |
|---|---|---|
| `max_session_duration` | copied from the access rule | `None` |
| `credential_id` | `pending` placeholder | value from the payload |
| Justification | required, 10 characters, tag-stripped | optional, raw |
| `client_ip` | caller's address | hardcoded `127.0.0.1` |
| `client_user_agent` | request header | `None` |
| `ApprovalRequested` audit event | emitted | missing |
| Approver notification and emails | emitted | missing |

On approval without a duration override, `vauban-access` computes
`expires_at` from the row's `max_session_duration`
(`vauban-access/src/handlers.rs`, `Approve` branch). With `None` the
approved row had `expires_at = NULL`, which the connect handlers accept
(`expires_at IS NULL OR expires_at > now` in `handlers/web/ssh.rs` and
`handlers/web/rdp.rs`) and the expiry sweep never matches. The grant
was permanent.

### 3.2 Fix

- New `services/access_request.rs`: `normalize_justification`,
  `PENDING_CREDENTIAL`, `JUSTIFICATION_REQUIRED_MESSAGE`.
- New `announce_access_request` (`handlers/web/sessions.rs`): the single
  place that emits `ApprovalRequested`, the notification, the sidebar
  badge and the approver emails. Its JSON payloads are built with
  `serde_json` instead of `format!`.
- `submit_access_request` and `create_session` both use them.
- `create_session` now copies `access_result.max_session_duration`,
  stores the `pending` placeholder, requires a justification, and
  records the caller's address and user agent. The rule evaluation runs
  before the `sessions:bypass_access_rules` gate, so a matching rule's
  duration is copied even for a bypass caller. The justification is
  checked after authorization and the protocol guard, so the existing
  403 / 400 ordering of the endpoint is unchanged.
- `submit_access_request` now refuses a `session_type` that does not
  match the asset type (`SessionType::try_parse` plus `matches_asset`),
  after authorization. The API already had this guard. Found by the
  adversarial review: a caller with an SSH rule carrying a cap and an
  RDP rule without one could request `rdp` on the SSH asset and obtain
  an approval with no horizon.
- `CreateSessionRequest.credential_id` is optional and ignored.

Two small tightenings come with the shared helper, on both surfaces: a
justification made only of markup is refused, and the stored text is
trimmed after tag-stripping.

### 3.3 Left as is, with the reason

- **MFA on the API.** An API key always carries `mfa_verified = true`
  (VAU-007), so a rule with `require_mfa` is satisfied by any key. The
  web form asks for a fresh TOTP code. Closing this needs a product
  decision: accept a `totp_code` in the payload, or refuse API requests
  for `require_mfa` assets.
- **Rules without a duration.** An access rule may have no
  `max_session_duration`. Its approvals then have `expires_at = NULL`
  on both surfaces, by design. Refusing an approval without a duration
  in `vauban-access`, or dropping the `IS NULL` branch in the connect
  handlers, would change that contract and is not done here.
- **Bypass callers.** A holder of `sessions:bypass_access_rules`
  (superuser) with no matching rule gets a request with no cap, and
  `require_mfa` is not evaluated for them. That is the existing meaning
  of the bypass.
- **Grant lookup is not protocol-scoped.** `connect_ssh` and the RDP
  connect handler look an approved grant up by user, asset and status,
  not by `session_type`. The new form guard stops a mismatched request
  from being recorded; scoping the lookup as well would be defense in
  depth.
- **Notification sink.** The `jit-notification` payload is JSON, but
  `services/broadcast.rs` wraps it unescaped in an HTML fragment. It is
  not exploitable today because asset names and usernames are
  sanitized on write; the safety rests on every writer, not on the
  sink.
- **No cap on pending requests** per user and asset, on either surface.
- **Rows created before the fix.** Find them with:

  ```sql
  SELECT uuid, user_id, asset_id, approved_at, credential_id
  FROM proxy_sessions
  WHERE status = 'approved' AND expires_at IS NULL;
  ```

  A row whose `credential_id` is not `pending` was most likely created
  through the API. Revoke the ones that should have had a horizon.

## 4. Tests

All under `vauban-web/tests/security/`, plus unit tests next to the
code.

| Layer | Where |
|---|---|
| Unit | `services/role_invariants.rs`, `services/access_request.rs` (`mod tests`) |
| Invariants | `authz_gaps_invariants_test.rs` |
| Proptest | `authz_gaps_proptest.rs` |
| Battle | `authz_gaps_battle_test.rs` |
| E2E | `authz_gaps_e2e_test.rs` |
| Smoke runbook | [authz_gaps_smoke_test.md](../runbooks/authz_gaps_smoke_test.md) |

```bash
rtk cargo test -p vauban-web --all-features --test integration_tests -- authz_gaps -- --test-threads=1
```

What the tests do not prove: the WebSocket tests never complete an
upgrade, so the refusal is asserted on the handshake status only; the
E2E tests go through the test router (`tests/common/mod.rs`), and
`main.rs` is covered by a source pin; the in-transaction superuser
re-check is covered by a source pin, not by a concurrent promotion.

Existing tests changed because they pinned the vulnerable behavior, or
relied on it:

- `security_test::test_terminal_ws_allowed_for_admin` became
  `attack_terminal_ws_admin_non_owner_is_rejected`.
- `role_invariants_test::cannot_deactivate_last_active_superuser_via_api`
  now expects the `users:manage_admins` refusal.
- `access_control_test::test_session_creation_with_valid_access_rule`
  and `test_session_creation_superuser_bypass` now send a justification.
- `session_expired_presentation_test` now creates an RDP asset for its
  `rdp` request (it used an SSH asset).
- `handlers::web::sessions::tests::test_broadcast_approval_badge_called_after_submit`
  follows the call through `announce_access_request`.

## 5. Out of scope

This analysis did not cover the IPC layer in depth,
`vauban-proxy-iacs`, `vauban-supervisor` or `vauban-vault`. See also
[auth_ipc_fail_closed.md](auth_ipc_fail_closed.md).
