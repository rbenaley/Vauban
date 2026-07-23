# Runbook -- Policy eval 3→2 session-open manual smoke test

> Manual validation checklist after shipping **policy eval 3→2** in
> crates **0.9.27+** on the SSH/RDP connect path: early `IssueSessionToken`
> returns MFA/JIT/duration constraints; `can_access_asset` /
> `CheckAccessMulti` is removed from connect; `AccessGuard` remains the
> proxy re-check. CI covers wire shape, source invariants, and JIT
> discard-without-INSERT, but cannot prove log-level eval counts on a
> live FreeBSD deploy.
>
> Audience: release / staging operators.
> Severity: **BLOCKING** for the **0.9.27** release (enriched
> `SessionTokenIssued`, coordinated web + access deploy) and any later
> change that reintroduces a pre-mint `CheckAccessMulti` on connect.
> Do not ship without a full pass of sections A–D.

Related architecture:

- [AccessGuard Architecture 1.0](../technical/Vauban_AccessGuard_Architecture_EN(1.0).md) §1 / §2 / §6.4
- Architecture analysis §2.4 / §7.2 / §10.10 / §16.5
- Lint: `vauban-web/scripts/check_policy_eval_session_open.sh`

## Automated prerequisites (must be green BEFORE the manual pass)

```bash
rtk cargo fmt --all -- --check
rtk cargo clippy -p shared -p vauban-access -p vauban-web --all-targets -- -D warnings
bash vauban-web/scripts/check_policy_eval_session_open.sh
rtk cargo test -p shared -p vauban-access -p vauban-web -- policy_eval -- --test-threads=1
# before hand-off / merge:
rtk cargo test --workspace -- --test-threads=1
rtk cargo test --manifest-path vauban-proxy-rdp/Cargo.toml --target-dir target -- --test-threads=1
```

Suite highlights that must stay green:

| Layer | Examples |
|-------|----------|
| Invariants + lint | `policy_eval_session_open_invariants_test`, `check_policy_eval_session_open.sh` |
| Proptest | `policy_eval_session_open_proptest` |
| Battle | `policy_eval_session_open_battle_test`, access concurrent mint |
| E2E | `policy_eval_session_open_e2e_test`, existing `access_control_web_test` |
| Wire | `test_session_token_issued_wire_roundtrip_with_constraints` |

## Lab prerequisites

- Deployed binaries at **0.9.27+** with **coordinated** `vauban-web` +
  `vauban-access` (enriched `SessionTokenIssued` — mixed versions fail
  to decode).
- Staging user with a matching SSH (and RDP) access rule; second user
  with no rule; JIT rule (`require_approval=true`) without / with an
  approved grant.
- SSH asset with a pinned host key; RDP asset with a pinned server cert.
- Ability to read **vauban-access** logs (filter on `IssueSessionToken`,
  `CheckAccessByUuid`, `CheckAccessMulti`).

## A — Happy path SSH then RDP

1. As a user with an active rule **without** `require_approval`, open
   an SSH session to a pinned asset until the terminal loads (or until
   proxy open succeeds — proxy unavailable is OK if mint + INSERT ran).
2. Repeat for RDP.
3. In access logs for each open, expect:
   - **one** `IssueSessionToken` (or mint success path) for that
     `session_id`;
   - **one** `CheckAccessByUuid` from the proxy AccessGuard after
     SessionOpen;
   - **no** `CheckAccessMulti` attributed to that connect request.

Pass: session opens (or fails only for unrelated proxy/target reasons)
and the eval count is 2 policy trips (mint + AccessGuard).

## B — Deny without rule

1. As a user with **no** access rule, POST connect (HTMX) on a pinned
   SSH asset.
2. Expect toast / body containing `No access rule`.
3. Confirm **no** new `proxy_sessions` row with `status=connecting` for
   that user/asset.
4. Confirm **no** SessionOpen reached the proxy (no AccessGuard line
   for a new session_id).

Pass: deny message + zero connecting rows + no proxy authorize.

## C — JIT require_approval

1. Rule with `require_approval=true`, user in group, **no** approved
   grant.
2. HTMX connect → `HX-Trigger` contains `show-access-request-modal`
   with `require_mfa` from the rule.
3. Confirm **no** `connecting` row (token minted then discarded).
4. Create a valid approved grant; reconnect → open proceeds; AccessGuard
   `CheckAccessByUuid` appears once.

Pass: modal without INSERT; approved path reaches AccessGuard.

## D — Adjacent regressions

1. MFA login still fail-closed (WORM Ack / HOL budget unchanged).
2. SSH asset **without** pinned host key: refuse with
   `No SSH host key pinned` **after** policy mint deny-or-allow
   (user without rule still hears `No access rule` first).
3. Diagnostic host-key fetch (`assets:manage`) still works via
   `IssueDiagnosticToken` (inert constraints).

## What *not* to re-litigate

- Do not remove AccessGuard to “save” the second eval.
- Do not reintroduce `can_access_asset` on `connect_ssh` / `connect_rdp`.
- Do not ship web without access (or the reverse) across the
  `SessionTokenIssued` field addition.
