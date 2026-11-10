# Runbook -- Auth IPC fail-closed smoke test

> Manual validation after shipping **fail-closed auth IPC**:
> vauban-web refuses to start without a channel to vauban-auth, and
> no user password is hashed or verified in the web process.
>
> Audience: release / staging operators.
> Severity: **BLOCKING** for the release that removes the local Argon2
> fallback. Do not ship without A–C.

Related:

- [IPC topology debugging](ipc_topology_debugging.md)
- [Privilege separation 1.3](../technical/Vauban_Privsep_Architecture_EN(1.3).md)
- Remediation note: [auth_ipc_fail_closed.md](../remediation/auth_ipc_fail_closed.md)
- Lint: `vauban-web/scripts/check_auth_ipc_mandatory.sh`

## Automated prerequisites

```bash
rtk cargo fmt --all -- --check
rtk cargo clippy -p vauban-web -p vauban-auth -p vauban-supervisor --all-targets -- -D warnings
bash vauban-web/scripts/check_auth_ipc_mandatory.sh
rtk cargo test -p vauban-web --bin vauban-web -- auth_ipc -- --test-threads=1
rtk cargo test -p vauban-web --lib -- password_via_auth -- --test-threads=1
rtk cargo test -p vauban-auth --bin vauban-auth -- argon2 -- --test-threads=1
rtk cargo test -p vauban-web --test integration_tests -- auth_ipc -- --test-threads=1
```

## Lab prerequisites

- A supervisor-launched bastion (the supported production shape).
- A local user whose password hash was minted by vauban-auth.
- Ability to read `vauban-web` and `vauban-supervisor` logs.
- A way to start `vauban-web` once with the auth descriptors removed
  or replaced (a throwaway unit, not the live one).

## A -- Supervised boot

1. Start the bastion under `vauban-supervisor` with the stock topology.
2. Confirm `vauban-web` logs `Auth IPC client initialized` and
   `Auth IPC processing task started`, then binds HTTPS.
3. Log in as the local user.

Pass: the process stays up and the login succeeds. Web logs do not
contain `Password hashing failed` or `auth IPC client is not configured`.

## B -- Missing channel

1. Start `vauban-web` with `VAUBAN_AUTH_IPC_READ` and
   `VAUBAN_AUTH_IPC_WRITE` unset (leave the access channel intact so
   the failure is specifically the auth one).
2. Read the process exit and the log line.

Pass: the process exits before it listens. The log contains
`VAUBAN_AUTH_IPC_READ is not set`. No HTTPS socket is open.

## C -- Invalid descriptor

1. Start `vauban-web` with `VAUBAN_AUTH_IPC_READ=abc` and
   `VAUBAN_AUTH_IPC_WRITE` set to a numeric descriptor.
2. Read the process exit and the log line.

Pass: the process exits before it listens. The log contains
`VAUBAN_AUTH_IPC_READ must be a valid file descriptor`. No password
hash is computed in the web process.
