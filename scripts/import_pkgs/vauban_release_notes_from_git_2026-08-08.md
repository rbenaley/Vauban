# Vauban release notes draft (from `../Vauban` git)

Source: commit ranges between workspace `Cargo.toml` version bumps in
[`../Vauban`](../../../Vauban). Ordering matches `/admin/releases` (semver
descending: `v_major` / `v_minor` / `v_patch`).

Format: one section per package; each body is 4–6 lines of `TAG: text`
suitable for the admin **Release notes** field (`FIX` / `FEAT` / `NEW` /
`SECURITY` / `RBAC`).

Packages covered:

`vauban-0.9.37.pkg` … `vauban-0.2.0.pkg` (list supplied by operator).

---

### v0.9.37 (17-08-2026)

FEAT: Add ADR 006 IACS profiles (EtherNet/IP, BACnet/SC, DNP3, IEC 61850 MMS) with prefix-based access matching.
SECURITY: Pin the WORM verify key out of band and allowlist LDAP bind DNs (reject RFC 4514 specials).
FEAT: Render branded HTML transactional mail with an inline star-fort logo (text part unchanged).
FIX: Close soft-delete tombstone holes so deleted users lose login, API keys, and approval mail.
FIX: Summarize mailer queue/drain on one line and surface permanent SMTP 5xx without aborting the batch.
FIX: Pre-open the mailer Postgres pool before Capsicum seal so FreeBSD drain ticks no longer fail to connect (0.9.36 line).

### v0.9.36 (15-08-2026)

FIX: Declare mailer `fd_passing` as FdReceiver only so Capsicum seal no longer hits ConflictingFdRights.
FIX: Stop listing the SCM_RIGHTS socket in `ipc_fds` to end FreeBSD mailer crash-loops.
FEAT: Add `MAILER_KINDS` and pyramid coverage for the mailer FD-passing contract.
FIX: Raise newsyslog rotation of `/var/log/vauban.log` to 1048576 KiB (1 GiB).

### v0.9.35 (30-07-2026)

FIX: Prefer the system config path over the workspace `config/` tree in production builds.
FEAT: Add configurable LDAPS login credential length floors.
SECURITY: Extend LDAPS login-floor coverage with proptest, invariants, and battle tests.
FIX: Raise MSRV to Rust 1.93 and tighten std hygiene on the 0.9.32 line.
RBAC: Keep privsep / IAM / Vault docs aligned with the shipped startup sequence.

### v0.9.31 (24-07-2026)

FEAT: Pass the Kerberos KDC connection to the RDP proxy via SCM_RIGHTS (0.9.30).
FIX: Align RBAC and Supervisor IPC clients on the shared `CorrelatedIpc` stack.
FEAT: Reduce cross-service IPC boilerplate for correlated request/response peers.
RBAC: Keep policy evaluation clients on the same FD and framing contract as Supervisor.
FIX: Stabilize RDP Kerberos handoff when the helper opens the KDC before Capsicum.

### v0.9.29 (24-07-2026)

FEAT: Extract evidence and mailer paths; record proxy traffic through delegated FDs.
FEAT: Merge SSH/RDP access policy evaluation into fewer round-trips via early mint.
SECURITY: Open the signed WORM audit log eagerly at boot and always fail closed.
FIX: Offload IACS `ChannelEnd` gzip to a dedicated audit worker thread.
FEAT: Drop recording-lossy integrity pins that blocked nullability checks in CI.

### v0.9.24 (22-07-2026)

FIX: Unblock MFA fail-closed acknowledgements on the WORM audit path.
FIX: Make recording hydration UI refresh race-safe under concurrent live updates.
FEAT: Clean up proxy-ssh architecture notes and document `recording_lossy` semantics.
FIX: Share vault envelope shape predicates in `shared` instead of duplicating checks.
SECURITY: Keep MFA denial paths from hanging when the audit ack channel stalls.

### v0.9.20 (21-07-2026)

FEAT: Extract `CorrelatedIpcCore` for AsyncFd-backed web IPC peers.
FEAT: Add IACS status vocabulary helpers, inspect dissectors, and audit health signals.
FEAT: Support proxy-only IACS tunnels with boot snapshot resync and gzip’d audit trails.
FIX: Gate IACS inspect on `ews_connected` and emit zero-channel audit when idle.
RBAC: Keep IACS lifecycle vocabulary consistent across SessionLive WebSocket events.

### v0.9.16 (19-07-2026)

FEAT: Emit periodic IACS `tunnel_stats` with per-login byte accounting.
FEAT: Show a waiting-client countdown on the IACS tunnel status page.
FIX: Unify SessionLive WebSocket vocabulary and stop the countdown on activation.
FIX: Replace CSP-dead inline `onsubmit` confirms with HTMX-driven modals.
SECURITY: Keep destructive confirms off inline script so CSP can stay strict.

### v0.9.12 (19-07-2026)

FIX: Purge ghost group memberships left by soft-deleted users.
FEAT: Factorize list filters and status vocabularies across admin tables.
FIX: Forbid revoking the operator’s own current login session.
FEAT: Show VAUBAN user → technical account mapping on session lists.
SECURITY: Harden admin BAC checks and enforce slug / constrained-field input formats.
FIX: Render expired JIT requests truthfully instead of implying they are still actionable.

### v0.9.4 (16-07-2026)

FEAT: Migrate the RDP stack to IronRDP 0.17 and harden the connection sequence.
FIX: Release stuck modifier keys on focus loss and resync lock-key state.
FEAT: Ship Vault Secrets (beta) with org secrets manager and M2M API provenance.
SECURITY: Add a global client IP ACL (`allowed_client_networks`).
FEAT: Instant JIT grant revocation and in-place duration modification.
FIX: Disconnect idle SSH/RDP tabs at the access-token horizon.

### v0.8.7 (19-06-2026)

FIX: Self-heal CSRF tokens on login after an expired session cookie.
SECURITY: Avoid leaving operators stuck on a stale CSRF failure after re-auth.
FIX: Keep the login form usable when the previous session was purged server-side.
FEAT: Preserve redirect intent through the CSRF recovery path when safe.
RBAC: Do not widen anonymous surface while repairing the login CSRF handshake.

### v0.8.6 (15-06-2026)

SECURITY: Remove Redis session storage and add session-creation rate limits.
SECURITY: Tighten CSP (`connect-src 'self'`, block `object-src`) and allowlist CORS Origins.
FEAT: Self-host front-end assets and drop runtime CDN dependencies.
SECURITY: Add signed WORM audit logging with broad web audit emission.
FEAT: Add LDAPS/AD directory authentication and RDP server-certificate TOFU pinning.
FIX: Keep interactive sessions alive during SSH/RDP activity; close sandbox FD leak gaps.

### v0.7.16 (18-05-2026)

FEAT: Split industrial tunneling into `vauban-proxy-iacs` with per-asset targets.
FEAT: Server-side timezone localization for wall-clock HTML rendering.
FIX: Resolve FreeBSD IACS crash-loops on boot/respawn and Capsicum FD ordering.
FIX: Unblock multi-channel `ssh -L` over IACS tunnels.
FEAT: Active-sessions visibility and robust terminate for OT tunnels.
SECURITY: Grant only the Capsicum rights the IACS listener needs (`READ`/`WRITE`/`GETPEERNAME`).

### v0.7.4 (05-05-2026)

FIX: Close two SSH host-key regressions and harden the verification path end-to-end.
FIX: Isolate Bastion Watch dashboard data per authenticated user.
SECURITY: Reject mismatched or recycled host keys before the SSH proxy proceeds.
FEAT: Keep dashboard LIVE views from leaking another operator’s session telemetry.
FIX: Stabilize SSH host-key storage lookups used by the connect workflow.

### v0.7.2 (02-05-2026)

FEAT: Ship the mailer notification system and User Zone sidebar labeling.
FEAT: Recording details page with an event-driven integrity hydrator.
FEAT: Split the asset catalogue (user) from the admin manage zone.
FIX: Wire HTTP rate middleware and the LIVE sparkline on the dashboard.
RBAC: Eradicate `is_superuser` / `is_staff` handler gates in favor of Casbin permissions.
SECURITY: Cryptographic session-token binding between the TCP broker and SessionOpen.

### v0.6.6 (15-04-2026)

SECURITY: Restrict TOTP acceptance to the current time window only.
SECURITY: Enforce MFA on all web routes and remove residual VNC support.
FIX: Centralize session status badge colors and drop Terminate from `/sessions`.
FEAT: Surface the packaged version in the authenticated UI chrome.
RBAC: Keep MFA enrolment required before privileged admin surfaces are reachable.

### v0.6.3 (07-04-2026)

SECURITY: Rotate the insecure default database password on package install.
FIX: Fail closed when the installer would otherwise leave the stock DB secret.
FEAT: Document the password rotation step in the pkg install path.
SECURITY: Avoid shipping a known bootstrap credential into production deploys.
FIX: Keep post-install DB grants aligned after the forced password change.

### v0.6.2 (04-04-2026)

FEAT: Fix the active sessions page with real-time updates and session cleanup.
FIX: Force-close the admin WebSocket on terminate and allow JIT reconnection.
FEAT: Dynamic Request/Connect asset buttons driven by live WS updates.
FEAT: Paginate large admin lists (30 rows per page) with live refresh.
FIX: Resolve JIT approval `422` when `duration_value` is empty.
FEAT: Add `connection_username` on assets and correct JIT approval expiration.

### v0.6.0 (29-03-2026)

FEAT: Implement the Just-In-Time access approval workflow.
FEAT: Paginate access-list IPC and harden drain helpers for stable framing.
FIX: Extract the shared Diesel schema into the `vauban-db` crate.
FEAT: Replace raw SQL supervisor admin commands with Diesel DSL.
RBAC: Keep JIT approvals on the access service boundary instead of the web process.
FIX: Align FreeBSD pkg account naming (`vb-*`) with the privsep runtime users.

### v0.5.0 (17-03-2026)

FEAT: Record SSH sessions as asciicast v2 with optional input redaction.
FEAT: Deliver instance-level access control with stronger service isolation (0.4 line).
FIX: Ship RBAC `model.conf` / `policy.csv` inside the FreeBSD package.
FIX: Raise IPC `MAX_MESSAGE_SIZE` from 128 KiB to 256 KiB for larger policy payloads.
SECURITY: Keep keystroke redaction on the recording path before durable storage.
RBAC: Document the IAM split between `vauban-auth` and `vauban-access`.

### v0.3.0 (10-03-2026)

FEAT: Migrate authentication and RBAC into dedicated privsep services.
FIX: Extract the package version from workspace `Cargo.toml` instead of hardcoding.
FEAT: Move the startup banner to the supervisor process.
RBAC: Keep policy evaluation off the web front-end UID after the privsep split.
FIX: Refresh README links for the new auth/RBAC service layout.
SECURITY: Narrow the web process so it no longer owns directory bind credentials.

### v0.2.1 (08-03-2026)

FEAT: Segment RDP recordings as fMP4 with DASH playback.
SECURITY: Serve TLS certificates from the supervisor over IPC and zeroize private keys.
FIX: Harden FreeBSD pkg ACL handling (NFSv4 `setfacl`, post-`sed` ACL restore).
FEAT: Have the supervisor bind `:443` and pass the listener to `vauban-web` via SCM_RIGHTS.
FIX: Install `vauban.conf` directly, replace placeholder secrets, and grant DB permissions.
FIX: Install the rustls `CryptoProvider` before ACME workflows in the supervisor.

### v0.2.0 (01-03-2026)

FEAT: Delegate recording file creation to the supervisor via SCM_RIGHTS.
SECURITY: Keep recording path open rights in the supervisor, not in proxy workers.
FIX: Stabilize the FD handoff so proxies inherit a usable recording file descriptor.
FEAT: Lay the groundwork for supervisor-owned durable session artifacts.
RBAC: Leave authorization decisions on the access path while I/O stays privileged.
FIX: Align early recording bootstrap with the privsep file-broker model.
