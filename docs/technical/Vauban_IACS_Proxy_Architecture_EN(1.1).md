# Vauban IACS Proxy Architecture

**Version:** 1.1  
**Date:** 21 July 2026  
**Author:** Richard Ben Aleya

> Supersedes
> [Vauban_IACS_Proxy_Architecture_EN(1.0).md](Vauban_IACS_Proxy_Architecture_EN(1.0).md).

---

## Table of Contents

1. [Purpose](#1-purpose)
2. [Position in the Vauban architecture](#2-position-in-the-vauban-architecture)
3. [Per-asset target resolution contract](#3-per-asset-target-resolution-contract)
4. [Process model and sandboxing](#4-process-model-and-sandboxing)
5. [IPC surface](#5-ipc-surface)
6. [Three-layer authorization](#6-three-layer-authorization)
7. [Anti-SSRF guards on the supervisor TCP broker](#7-anti-ssrf-guards-on-the-supervisor-tcp-broker)
8. [Lifecycle of an IACS tunnel session](#8-lifecycle-of-an-iacs-tunnel-session)
9. [Revocation watchdog (DB-driven, IPC-dispatched)](#9-revocation-watchdog-db-driven-ipc-dispatched)
10. [Real-time status fan-out (WebSocket)](#10-real-time-status-fan-out-websocket)
11. [Threat model](#11-threat-model)
12. [Test coverage](#12-test-coverage)
13. [Source of truth](#13-source-of-truth)
14. [Protocol recognition](#14-protocol-recognition)
15. [Test coverage (protocol recognition)](#15-test-coverage-protocol-recognition)

---

## 1. Purpose

`vauban-proxy-iacs` is a dedicated, sandboxed russh sshd that serves as the bastion-side endpoint for **Engineering Workstations (EWS)** opening tunnels to **IACS assets** (Modbus, OPC-UA, DNP3, IEC-104, BACnet/SC, MQTT/TLS, Profinet IO). It replaces the pre-v0.7.8 in-process IACS sshd that ran inside `vauban-web`.

The split delivers three things the in-process design could not:

1. **Per-asset target resolution.** Every IACS tunnel session pins a per-session `(asset.hostname, asset.port)` target derived from the asset row at session-creation time. The pre-v0.7.8 implementation hard-coded `127.0.0.1:4321` as the upstream, ignoring the asset's `Hostname` and `Port` columns -- a single-asset MVP shortcut that needed to be removed before the IACS surface could go to production.
2. **Capsicum-grade sandboxing.** The proxy never holds a database connection, never mints a session token, never re-evaluates Casbin policy. It accepts EWS SSH handshakes and relays bytes between the operator's `direct-tcpip` channel and the upstream TCP socket brokered by the supervisor. Everything else is upstream of the pipe boundary.
3. **Privilege separation symmetry with SSH and RDP.** The IACS surface now follows the same `vauban-web -> vauban-access (mint) -> vauban-supervisor (broker) -> vauban-proxy-* (relay)` pattern as the existing `vauban-proxy-ssh` and `vauban-proxy-rdp`. The same audit, the same key dissemination, the same `AccessGuard` re-check.

## 2. Position in the Vauban architecture

```mermaid
flowchart LR
    subgraph supervisor [vauban-supervisor]
        S[Pre-bind listener FD<br/>SCM_RIGHTS broker<br/>Anti-SSRF guards]
    end

    subgraph web [vauban-web]
        WUI[Web UI / IACS handler<br/>Asset CRUD / EWS approval]
        Watchdog[Revocation watchdog]
    end

    subgraph access [vauban-access]
        Casbin[Casbin policy]
        TokenMint[SessionToken mint]
    end

    subgraph proxy [vauban-proxy-iacs]
        Sshd[russh sshd<br/>per-asset validate_target]
        Relay[direct-tcpip relay]
    end

    EWS[Engineering Workstation]
    Asset[IACS asset]

    EWS -->|TCP| supervisor
    supervisor -. inherited listener FD .-> proxy
    WUI -->|IacsTunnelOpen| proxy
    WUI -->|IssueSessionToken| TokenMint
    proxy -->|TcpConnectRequest| supervisor
    supervisor -->|connect + SCM_RIGHTS| Asset
    proxy -->|CheckAccessByUuid| Casbin
    proxy -.->|IacsTunnelStatusUpdate/Closed| WUI
    Watchdog -->|IacsTunnelTerminate| proxy
    EWS <-->|relay| Asset
```

`vauban-proxy-iacs` sits in the proxy tier alongside `vauban-proxy-ssh` and `vauban-proxy-rdp`. It speaks only to: the supervisor (broker + listener FD), `vauban-access` (RBAC re-check), `vauban-audit` (session events), and `vauban-web` (IACS tunnel open / terminate / status fan-out). It never touches the database or external networks directly.

## 3. Per-asset target resolution contract

The pre-v0.7.8 contract was: every IACS tunnel relayed traffic to a fixed `target_addr` declared in `vauban.conf` (default `127.0.0.1:4321`). The post-v0.7.8 contract is:

> Every IACS tunnel relays traffic to **the per-asset `(asset.hostname, asset.port)`** captured at session creation time. The pinned target travels end-to-end through three layers, and each layer enforces it independently.

| Layer | Storage / wire | Enforced by |
|---|---|---|
| Persistence | `proxy_sessions.tunnel_target_addr = format!("{}:{}", asset.hostname, asset.port)` | Set in `handlers/web/iacs_tunnel.rs` at the only `NewProxySession` build site. |
| Cryptographic binding | `SessionToken { host, port, target_service: ProxyIacs, protocol: "iacs_tunnel" }` | Minted by `vauban-access` on `IssueSessionToken`; verified at the supervisor (`Verifier::Supervisor`) and at the proxy (`Verifier::Proxy`). |
| Per-session pin | `IacsTunnelOpenRequest { asset_host, asset_port }` -> `PendingTunnel { asset_host, asset_port }` | Stored in `vauban-proxy-iacs::auth::PendingSessions` keyed by session UUID. |
| Runtime enforcement | `relay::validate_target(requested_host, requested_port, expected_host, expected_port)` | Called on every `channel_open_direct_tcpip` before the supervisor broker is invoked. Loopback-equivalence is permitted only when BOTH sides are loopback. |
| Network enforcement | Anti-SSRF guards on `Service::ProxyIacs` targets | See §7. |

A regression that reintroduces a process-wide `target_addr` is caught at compile time by the structural pin tests (`vauban-proxy-iacs/tests/per_asset_target_test.rs`) and at lint time by `vauban-proxy-iacs/scripts/check_no_hardcoded_target.sh`.

### 3.1 Privileged-port unprivilegisation (EWS-side concern)

The bastion-side per-asset target contract above pins the **upstream** `(asset_host, asset_port)`. There is a complementary **EWS-side** contract that decouples the operator's local-bind port (the LHS of `ssh -L LP:asset:AP`) from the upstream port: most IACS protocols listen on `< 1024` (Modbus 502, MMS 102) and binding privileged ports requires root on Unix and "increased priority" on Windows. Forcing every operator to run `ssh` as root is not acceptable.

Helper [`derive_local_forward_port`](mdc:vauban-web/src/services/iacs_tunnel/port_mapping.rs):

```text
local_forward_port = asset_port            if asset_port >= 1024
                   = 50_000 + asset_port   if asset_port <  1024
```

The mapping is deterministic, injective on the privileged range, collision-free, and stable across releases (operator muscle memory: "Modbus -> :50502" must keep working). The status template renders three independent fields (`local_forward_port`, `target_host`, `target_port`) so the SSH command is `ssh -L <LP>:<asset_host>:<asset_port>` (NOT the legacy `ssh -L <port>:127.0.0.1:<port>`). The bastion's `validate_target` does NOT participate in the rewrite -- it only validates the upstream pair.

Pinned end-to-end by [`vauban-web/tests/web/iacs_local_forward_port_test.rs`](mdc:vauban-web/tests/web/iacs_local_forward_port_test.rs) (Modbus 502 -> 50502, OPC-UA 4840 unchanged, IPv6 host preserved verbatim, boundary 1023/1024, malformed `tunnel_target_addr` defensive fallback).

## 4. Process model and sandboxing

`vauban-proxy-iacs` follows the standard Vauban privsep boot sequence:

1. **Supervisor pre-fork**:
   - Read `industrial.iacs_tunnel.bind_addr` from `vauban.conf`.
   - `bind(2)` a TCP listening socket. The privileged `bind` step lives here so the proxy can stay sandboxed.
   - `mem::forget` the `TcpListener` so the kernel keeps the FD open across the `forget`; export the raw FD via `VAUBAN_IACS_LISTENER_FD`.
2. **Supervisor fork** the proxy as `vauban_iacs:vauban_iacs` (uid 908, gid 908).
3. **Proxy boot**:
   - Read `VAUBAN_IACS_LISTENER_FD` BEFORE `cap_enter`.
   - Initialize `shared::session_token::proxy_gate::init_from_env` (consumes and clears `VAUBAN_SESSION_TOKEN_KEY_*`).
   - Initialize `shared::access_guard::AccessGuard::from_env(PROTOCOL_IACS_TUNNEL, state)` (consumes and clears `VAUBAN_ACCESS_IPC_*`).
   - Call `shared::capsicum::setup_service_sandbox_with_listeners(...)` to grant the listener FD `cap_listen | cap_accept` and enter Capsicum capability mode.
4. **Steady state**:
   - The russh sshd accepts on the inherited listener FD. No `bind()`, no `socket()`, no `connect()` -- all forbidden by Capsicum on FreeBSD production.
   - Every upstream TCP goes through `SupervisorBrokerOpener` (a `TcpConnectRequest` over the supervisor pipe with the session-bound token, answered by an `OwnedFd` over `SCM_RIGHTS`).

On Linux/macOS dev hosts the sandbox is a no-op (`cap_enter` is skipped); the proxy still goes through the same broker and pin-test contracts so CI exercises the production path identically.

## 5. IPC surface

The proxy exposes four message variants (`shared::messages::Message`):

| Verb | Direction | Purpose |
|---|---|---|
| `IacsTunnelOpen` | `web -> proxy_iacs` | Open a pending session on the proxy. Payload: `session_id`, `user_uuid`, `asset_uuid`, `ews_uuid`, `ews_pubkey_fp`, `asset_host`, `asset_port`, `industrial_protocol`, `ttl_seconds`, `session_token`. |
| `IacsTunnelOpened` | `proxy_iacs -> web` | Acknowledge / refuse. `success`, optional `error`. |
| `IacsTunnelStatusUpdate` | `proxy_iacs -> web` | State machine transition (`waiting_client -> tunnel_active -> terminated`); fan-out to the WebSocket layer. |
| `IacsTunnelClosed` | `proxy_iacs -> web` | Final close event (cause, total bytes). |
| `IacsTunnelTerminate` | `web -> proxy_iacs` | Force-close a session (revocation watchdog or admin kill). |

The proxy also speaks the existing supervisor surface (`TcpConnectRequest` / `TcpConnectResponse`) for upstream brokering, and the existing `CheckAccessByUuid` surface against `vauban-access` for the re-check.

## 6. Three-layer authorization

Three independent layers gate every IACS tunnel session:

1. **Casbin / `PermissionContext`** (functional capability). `vauban-web`'s IACS handler is gated by Casbin permissions through the `PermissionContext` middleware. A user without the `iacs:request` permission can never reach the handler.
2. **Cryptographic session-token gate**. `vauban-web` mints a BLAKE3-keyed token bound to `(session_id, user_uuid, asset_uuid, host, port, protocol="iacs_tunnel", target_service=ProxyIacs)`. The supervisor verifies the token before any DNS / connect (`Verifier::Supervisor`); the proxy verifies it again on `IacsTunnelOpen` (`Verifier::Proxy`). A token minted for SSH cannot be replayed on the IACS surface (the protocol binding rejects it). A token minted for asset A cannot be replayed against asset B (the `(host, port)` binding rejects it).
3. **AccessGuard re-check**. After the token verifies, `vauban-proxy-iacs` runs `AccessGuard::authorize(&user_uuid, &asset_uuid)` against `vauban-access`. This re-checks the access-rule layer (a Casbin grant is necessary but not sufficient: an access rule restricts *which assets* the user can reach with the IACS protocol). A mid-flight access-rule revoke between token mint and `IacsTunnelOpen` is caught here.

The three layers are checked in order, fail-closed; any failure refuses the tunnel.

## 7. Anti-SSRF guards on the supervisor TCP broker

The supervisor's `handle_tcp_connect_request` enforces TWO additional guards on every request that targets `Service::ProxyIacs`:

- **Anti-self-listener.** A request whose `(target_host, target_port)` equals the IACS sshd's own listening address is rejected. Without this guard, an EWS owner could ask the proxy to tunnel back to itself, creating an infinite SSH-in-SSH loop and exhausting fds. Pinned by `tests::test_iacs_broker_anti_self_listener_guard_exists`.
- **Anti-loopback (default-deny).** A request whose resolved IP is loopback (`127.0.0.0/8`, `::1`) is rejected unless `industrial.iacs_tunnel.allow_loopback_targets = true`. Loopback assets give an EWS oracular access to colocated services (e.g. PostgreSQL on the bastion host); production deployments MUST keep this knob `false`. Pinned by `tests::test_iacs_broker_anti_loopback_guard_exists`.

Both guards log a structured `target_resolved_ip` field so an operator can pivot on `journalctl -u vauban-supervisor -g target_resolved_ip` to triage a denied tunnel. Guards are constructed once per spawn from `IacsTunnelGuards::from_config(&config.industrial.iacs_tunnel)` and threaded through `process_service_messages`.

## 8. Lifecycle of an IACS tunnel session

```mermaid
sequenceDiagram
    participant U as User (browser)
    participant W as vauban-web
    participant A as vauban-access
    participant S as vauban-supervisor
    participant P as vauban-proxy-iacs
    participant E as EWS (operator laptop)
    participant T as IACS asset

    U->>W: GET /assets/{uuid}/iacs-tunnel
    W->>W: Casbin gate (iacs:request) + EWS pinning
    W->>W: insert proxy_sessions row<br/>(tunnel_target_addr = asset.hostname:asset.port)
    W->>A: IssueSessionToken { user, asset, "iacs_tunnel", host, port, ProxyIacs }
    A-->>W: SessionToken (BLAKE3)
    W->>P: IacsTunnelOpen { ... session_token ... }
    P->>P: session_token_gate::verify_proxy
    P->>A: CheckAccessByUuid (AccessGuard re-check)
    A-->>P: Allow
    P-->>W: IacsTunnelOpened { success }
    W-->>U: render status page (waiting_client)

    Note over E,P: out-of-band: operator runs<br/>ssh -i ~/.ssh/id_VAUBAN -L <localport>:127.0.0.1:<localport> ...

    E->>P: SSH handshake on inherited listener FD
    P->>P: publickey auth: match (session_uuid, EWS pubkey)
    E->>P: channel_open_direct_tcpip(host, port)
    P->>P: relay::validate_target(host, port, asset_host, asset_port)
    P->>S: TcpConnectRequest { ProxyIacs, asset_host, asset_port, session_token }
    S->>S: token gate (Verifier::Supervisor) + anti-SSRF guards
    S->>T: connect(asset_host:asset_port)
    S-->>P: SCM_RIGHTS upstream FD
    P-->>W: IacsTunnelStatusUpdate { tunnel_active }
    P->>E: relay bytes
    P->>T: relay bytes
    Note over P: ... bidirectional relay ...
    E->>P: SSH disconnect (or peer close)
    P-->>W: IacsTunnelClosed { cause, bytes_in, bytes_out }
```

### 8.1 Boot resync (web restart, proxy still alive)

When `vauban-web` restarts alone, `proxy_sessions` may disagree with the
in-memory tunnels still held by `vauban-proxy-iacs`. Boot order:

1. `init_iacs_proxy_client()`
2. Spawn `ProxyIacsClient::process_incoming_with_state` (IPC pump)
3. `reconcile_iacs_from_proxy_snapshot` — web sends
   `IacsTunnelSnapshotRequest`; proxy replies with
   `IacsTunnelSnapshotResponse { entries }` built from the union of
   `PendingSessions` (phase 0), authenticated `SessionHandles` (phase 1),
   and `TunnelRegistry` (phase 2). Entries never carry `session_token`
   or `ews_pubkey_fp`.
4. Pure planner `reconcile_iacs_boot` (proxy = authority for "alive"):
   rehydrate matching DB rows (including previously `terminated`),
   `TerminateDb` for live rows missing from the proxy, `TerminateProxy`
   (`boot_orphan`) for proxy UUIDs with no DB row.
5. Spawn the revocation watchdog.

Snapshot timeout / IPC error is fail-closed: treat the snapshot as empty
(terminate every live DB row) and log at `error!`.

## 9. Revocation watchdog (DB-driven, IPC-dispatched)

The watchdog still lives inside `vauban-web` (DB-resident logic) but no longer manipulates an in-process registry. The Lot 5 refactor introduced `services::iacs_tunnel::revocation::spawn_watchdog_with_proxy_iacs` which takes an `Option<Arc<ProxyIacsClient>>`. Each tick:

1. Query the DB for sessions whose anchor (`ews`, `users`, `access_rules`) has been revoked or whose `waiting_client` TTL is exceeded.
2. For every session that must die, send an `IacsTunnelTerminate` IPC to the proxy.
3. The proxy's `direct-tcpip` relay tasks read the broadcast cancellation, drain the relay, persist the closed state, and emit `IacsTunnelClosed`.
4. The watchdog updates the `proxy_sessions` row to `terminated` (or `expired` for TTL-based transitions) and appends a `tunnel_closed` row to `ews_audit_log`.

Operator triage when "an offboarded EWS still has an open tunnel" lives in [docs/runbooks/iacs_ews_onboarding.md](../runbooks/iacs_ews_onboarding.md).

## 10. Real-time status fan-out (WebSocket)

`vauban-web` runs a dedicated task that pumps `IacsTunnelStatusUpdate` and `IacsTunnelClosed` from the proxy into the `BroadcastService`:

- `notifications` channel (low cardinality) for the supervisor admin views;
- `session:<uuid>` channel (high cardinality) for the per-tunnel detail page.

The pump is `ProxyIacsClient::process_incoming_with_broadcast(b)` and is spawned once on `AppState` initialization. Cardinality routing follows the [`websocket-logging`](../../.cursor/rules/websocket-logging.mdc) convention: status updates on the singleton `notifications` channel log at `info!`; per-session updates on `session:<uuid>` log at `debug!`.

## 11. Threat model

| Threat | Mitigation | Pinned by |
|---|---|---|
| Multi-channel exfil: a malicious EWS opens many concurrent `direct-tcpip` channels to fan-out traffic. | Per-login bounded counter (`live_channels: AtomicUsize`), capped by `IacsTunnelConfig::max_concurrent_channels_per_session` (default 16, `0` = unlimited). Every channel still validates the SAME pinned `(asset_host, asset_port)`, so multi-channel does NOT widen the reachable target set -- it only widens in-flight TCP sockets. | `enforces_per_login_concurrent_channel_cap` (web E2E) + `channel_open_direct_tcpip_uses_bounded_counter_not_single_shot_atomicbool` (proxy structural pin). |
| Multi-client `ssh -L` (operator legitimate use): a single SSH login serves several local TCP clients simultaneously, each via a separate `direct-tcpip`. | Bounded counter (above) accepts every channel up to the cap and releases the slot when the relay task ends, so closed channels return their slot. The pre-fix `AtomicBool::swap(true)` made the login single-shot and broke this workflow on every IACS asset. | `accepts_multiple_sequential_direct_tcpip_on_same_session`, `accepts_multiple_concurrent_direct_tcpip_on_same_session`. |
| Compromised `vauban-web` mints `IacsTunnelOpen` for a forbidden asset. | Cryptographic session-token gate on the proxy boundary (`Verifier::Proxy`). The token's `(host, port, asset_uuid)` binding is set by `vauban-access`, NOT by `vauban-web`. | `iacs_handler_mints_session_token_with_per_asset_binding` (web pin) + `iacs_tunnel_open_handler_verifies_session_token` (proxy pin). |
| Cross-asset target swap. EWS opens `direct-tcpip` to `10.0.0.2:502` on a session minted for `10.0.0.1:502`. | `relay::validate_target` rejects the open before brokering. | `cross_asset_target_swap_rejected`. |
| Cross-protocol replay. Token minted for SSH replayed on IACS. | Token's `protocol` field bound at mint and re-verified at proxy boundary. | Same gate, different label. |
| EWS asks the proxy to tunnel to itself. | Supervisor anti-self-listener guard on `Service::ProxyIacs`. | `test_iacs_broker_anti_self_listener_guard_exists`. |
| EWS asks for a loopback target on the bastion host. | Supervisor anti-loopback guard (default-deny). | `test_iacs_broker_anti_loopback_guard_exists`. |
| Mid-session access-rule revoke. | DB-driven watchdog dispatches `IacsTunnelTerminate` to the proxy within `revocation_poll_interval_seconds`. | `iacs_revocation_watchdog_test::watchdog_closes_tunnels_when_*`. |
| Compromised proxy attempts a direct `connect()`. | Capsicum `cap_enter` post-listener-fd setup; every outbound goes through the supervisor broker. Lint catches `TcpStream::connect(` / `TcpListener::bind(` in `vauban-proxy-iacs/src/`. | `proxy_iacs_does_not_call_socket_or_bind`. |
| Anti-replay of a captured `TcpConnectRequest`. | For SSH/RDP (single-shot): token's `(session_id, nonce)` is consumed by the supervisor's bounded `replay_cache` on first use. For IACS (multi-use): the cache is **deliberately bypassed** (see §13); compensating controls are the per-asset crypto binding, the anti-self-listener / anti-loopback guards (§7), and the revocation watchdog (§9). | `test_supervisor_tcp_broker_records_replay` + `test_supervisor_tcp_broker_bypasses_replay_cache_for_iacs`. |
| Legacy in-process IACS sshd reintroduced into `vauban-web`. | Module deleted (Lot 5); connect path fail-closed without `proxy_iacs`; pin + lint assert absence of `mod server` / `russh` in web. | `in_process_iacs_sshd_module_is_absent` + `vauban_web_cargo_toml_has_no_russh`. |

## 11.1 Per-target_service token TTL (`shared::session_token::token_ttl_for`)

The cryptographic [`SessionToken`](mdc:shared/src/session_token/mod.rs) carries an `expires_at` field set at mint time. Until v0.7.10 every token shared a single 30 s TTL (`TOKEN_TTL_SECONDS`), which was correct for SSH and RDP -- those proxies open exactly **one** upstream TCP per session, so a single `TcpConnectRequest` reaches the supervisor and the 30 s window is the right tradeoff between latency budget and replay surface.

IACS does NOT match that single-shot model. A single operator `ssh -L LP:asset:AP ... -N` session multiplexes **many** `direct-tcpip` channels over its lifetime: every TCP `accept()` on the EWS-side forwarded port spawns a new SSH channel which `vauban-proxy-iacs` upgrades into a fresh `TcpConnectRequest` to the supervisor. Each of those requests carries the **same** `session_token` bytes (`PendingTunnel::session_token` is captured once at `IacsTunnelOpen` and reused per channel; there is no per-channel re-mint round-trip with `vauban-access`).

Two consequences fall out of that:

1. The token must verify for the full duration of the operator session, not just the first channel-open. `TOKEN_TTL_SECONDS` (30 s) is too short -- after 30 s every subsequent channel collapses with `session token rejected: token expired; fail-closed deny` at the supervisor and the EWS sees `channel 2: open failed: administratively prohibited: Rejected`.
2. The supervisor's anti-replay [`replay_cache`](mdc:shared/src/session_token/replay_cache.rs), keyed on `(session_id, nonce)`, MUST NOT reject the second channel. It would, because the proxy re-presents the identical `(session_id, nonce)` for every channel.

The fix is two coupled changes, both narrowly scoped to `Service::ProxyIacs`:

- **Long-lived TTL.** [`token_ttl_for`](mdc:shared/src/session_token/mod.rs) returns `TOKEN_TTL_SECONDS_IACS_TUNNEL = 12 * 3600` for `Service::ProxyIacs`, and `TOKEN_TTL_SECONDS = 30` for every other variant. 12 h covers a full operator shift (8 h + handover + lunch + debug spillover) without forcing re-authentication mid-session, and remains shorter than any reasonable `proxy_sessions.expires_at`. The constant is documented in the file with the exhaustive `match` expectation: a new `Service::*` variant falls back to the safe single-shot default until explicitly opted-in.
- **Replay cache bypass.** `vauban-supervisor::handle_tcp_connect_request` skips the replay cache when `target_service == Service::ProxyIacs`. The bypass is gated by an explicit `!matches!(target_service, Service::ProxyIacs)` so a second variant cannot be added by accident; pinned by `test_supervisor_tcp_broker_bypasses_replay_cache_for_iacs`.

The compensating controls that keep the IACS multi-use window safe are the **same three** that already gate every IACS request:

| Control | Where | Why it bounds the multi-use blast radius |
|---|---|---|
| Crypto `(host, port, target_service=ProxyIacs, session_id)` binding | `Verifier::Supervisor` in `handle_tcp_connect_request` | A leaked token cannot pivot to a different asset, port, or session -- the verifier rejects on any field mismatch. |
| Anti-loopback / anti-self-listener guards | §7 | Even within the long TTL, the supervisor will not connect to the bastion host's loopback or to the IACS sshd's own port. |
| Revocation watchdog | §9 | DB-driven `IacsTunnelTerminate` closes the SSH login the moment the access rule, EWS row, or user is revoked, well within the 12 h TTL. |

The 12 h figure is intentionally conservative: making the IACS TTL longer than the `proxy_sessions` row is unsafe (the watchdog model assumes the token cannot outlive its session), and shorter values force operators to reconnect mid-shift. The constant is unit-pinned (`iacs_token_ttl_is_long_lived`, `iacs_token_still_valid_after_default_ttl_window`, `iacs_token_eventually_expires`, `non_iacs_tokens_keep_short_single_shot_ttl`, `token_ttl_for_helper_is_exhaustive_match`) so a future tune cannot silently regress to 30 s and re-introduce the May 2026 production bug.

## 12. Test coverage

| Scope | File | What it pins |
|---|---|---|
| Per-asset target unit | `vauban-proxy-iacs/tests/per_asset_target_test.rs` | `validate_target` matches per-session pin; cross-asset swap rejected; legacy fixed target rejected for remote asset; loopback-equivalence semantics. |
| Per-asset target structural | same | Source-grep pins on `validate_target`, `Service::ProxyIacs`, `Message::TcpConnectRequest`, `verify_proxy`, `access_guard.authorize`, `VAUBAN_IACS_LISTENER_FD`, `setup_service_sandbox_with_listeners`. Lint pin: no `TcpStream::connect` / `TcpListener::bind` anywhere in `src/`. |
| Per-asset target lint | `vauban-proxy-iacs/scripts/check_no_hardcoded_target.sh` | No `127.0.0.1:4321` literal anywhere in `vauban-proxy-iacs/src/`. |
| Web wiring structural | `vauban-web/tests/web/iacs_per_asset_target_pin_test.rs` | `tunnel_target_addr` derived from `asset.hostname:asset.port`; `SessionTokenParams` carries per-asset binding; IPC `IacsTunnelOpenRequest` carries `asset_host` / `asset_port`; rollback on token mint / proxy refusal; in-process sshd module absent; watchdog uses proxy-iacs-aware spawn; broadcast pump forwards lifecycle IPC. Boot resync: `iacs_boot_resync_e2e_test.rs` + `iacs_boot_reconcile_proptest.rs`. |
| Supervisor anti-SSRF | `vauban-supervisor/src/main.rs::tests::test_iacs_broker_*` | Anti-self-listener and anti-loopback guards exist, log `target_resolved_ip`, threaded through `process_service_messages`. |
| Watchdog | `vauban-web/tests/web/iacs_revocation_watchdog_test.rs` | EWS disabled / offboarded / user deactivated / TTL expired -> tunnel killed; user A's revoke does not touch user B's tunnel; `tunnel_closed` audit row appended. |
| Adversarial sshd | `vauban-proxy-iacs/tests/iacs_server_handshake_test.rs` | publickey-only auth against production `IacsTunnelServer`; refused surfaces and wrong-target opens exercised on the Capsicum proxy binary (Lot 5 moved coverage out of `vauban-web`). |
| Drift | `vauban-web/tests/web/iacs_drift_test.rs` | Asset-type CHECK matches Rust `AssetType::ALL`; `proxy_sessions_iacs_consistency` CHECK exists; `ews_audit_log_event_chk` admits IACS events; `all_iacs` virtual asset_group seeded. |
| Protocol recognition unit | `shared/src/iacs_protocol/` (`--features iacs-protocol`) | Peek classifiers for Modbus / OPC UA / IEC 104 / PROFINET; conformity matrix; drift pin on `WireProtocol` catalogue. |
| Protocol recognition auth | `vauban-access/src/handlers.rs` | `iacs_tunnel_rule_includes_asset_type` binds `asset.asset_type` to granting `allowed_protocols`; cross-type and non-IACS deny tests. |
| Protocol recognition E2E auth | `vauban-web/tests/web/iacs_protocol_auth_e2e_test.rs` | `POST /assets/{uuid}/connect-iacs` denies modbus-only rule + profinet asset; grants matching modbus asset. |
| Protocol recognition gate lint | `vauban-proxy-iacs/scripts/check_iacs_protocol_gate.sh` | EWS -> asset leg MUST use `filtered_copy_with_counter`; `industrial_protocol` MUST reach the gate. |
| Protocol recognition structural | `vauban-proxy-iacs/tests/protocol_gate_adversarial_test.rs`, `per_asset_target_test.rs` | Source-grep pins on `filtered_copy_with_counter`, `ExpectedProfile::from_industrial_label`. |
| Protocol recognition runtime | `vauban-proxy-iacs/src/protocol_gate.rs` | Modbus pass / OPC UA reject on Modbus profile; passthrough profile accepts arbitrary bytes. |

## 13. Source of truth

- `vauban-proxy-iacs/` -- the proxy crate (russh sshd + relay + supervisor broker glue + per-session pinning)
- `vauban-supervisor/src/main.rs` -- `IacsTunnelGuards`, listener pre-bind (`VAUBAN_IACS_LISTENER_FD`), `Service::ProxyIacs` routing in `handle_tcp_connect_request`
- `vauban-supervisor/src/config.rs` -- `IacsTunnelSupervisorConfig { enabled, bind_addr, allow_loopback_targets }`
- `vauban-web/src/handlers/web/iacs_tunnel.rs` -- per-asset `tunnel_target_addr` + token mint + `IacsTunnelOpenRequest` dispatch
- `vauban-web/src/ipc/proxy_iacs.rs` -- `ProxyIacsClient` (`open_tunnel`, `terminate_tunnel`, `snapshot_tunnels`, `process_incoming_with_state`)
- `vauban-web/src/services/iacs_tunnel/boot_reconcile.rs` -- boot Snapshot resync (pure plan + apply)
- `vauban-web/src/services/iacs_tunnel/revocation.rs` -- `spawn_watchdog_with_proxy_iacs`
- `shared/src/messages.rs` -- `Service::ProxyIacs` + `IacsTunnel*` message variants (incl. Snapshot)
- `shared/src/access_guard.rs` -- `PROTOCOL_IACS_TUNNEL`
- `shared/src/iacs_protocol/` -- peek classifiers + conformity (`--features iacs-protocol`)
- `shared/src/session_token/proxy_gate.rs` -- factorized `init_from_env` / `verify_proxy` consumed verbatim by the proxy
- `config/default.toml`, `config/vauban.conf` -- `[services.proxy_iacs]` + `[industrial.iacs_tunnel] allow_loopback_targets`
- `docs/runbooks/iacs_ews_onboarding.md` -- operator runbook (kill-switch, audit queries, lifecycle troubleshooting, recovery paths, IACS proxy section).

## 14. Protocol recognition

Typed IACS assets (`iacs_modbus`, `iacs_opcua`, `iacs_profinet`, `iacs_iec104`) are no longer labels identical to `iacs_tcp`. Two independent layers enforce the contract:

### 14.1 Authorization binding (`vauban-access`)

When `CheckAccessByUuid(protocol="iacs_tunnel")` runs:

1. Non-IACS assets (`ssh`, `rdp`) are denied immediately.
2. Among granting access rules, at least one MUST list the asset's exact `asset_type` in `allowed_protocols` (e.g. rule `iacs_modbus` + asset `iacs_modbus`). A modbus-only rule MUST NOT grant a tunnel to an `iacs_profinet` asset in the same group.

The transport-meta token mint (`SessionToken.protocol = "iacs_tunnel"`) is unchanged.

### 14.2 Wire gate (`vauban-proxy-iacs`)

On every `direct-tcpip` channel, the EWS -> asset relay leg peeks the first frames via `shared::iacs_protocol`:

- **Typed profile** -- confirm the wire family matches `PendingTunnel.industrial_protocol`, then switch to full passthrough (no command filtering).
- **Foreign protocol** (e.g. OPC UA `HEL` on a Modbus asset) -- close the channel; log `iacs_protocol_mismatch`.
- **`iacs_tcp` / `tcp` label** -- passthrough unchanged (Generic TCP).

Constants (v1, not configurable): `CLASSIFY_MAX_BYTES = 4096`, `CLASSIFY_TIMEOUT = 5 s`.

### 14.3 Explicit non-goals

- No configurable command policies (Modbus FC allow/deny, IEC 104 type IDs, OPC UA NodeIds).
- No MITM / inspection of encrypted OPC UA payloads.
- No L2 PROFINET IO enforcement (tunnel is TCP-only).

## 15. Test coverage (protocol recognition)

| Layer | Artifact | Command |
|---|---|---|
| L1 lint | `vauban-proxy-iacs/scripts/check_iacs_protocol_gate.sh` | `bash vauban-proxy-iacs/scripts/check_iacs_protocol_gate.sh` |
| L2 structural pins | `protocol_gate_adversarial_test.rs`, `iacs_per_asset_target_pin_test.rs` | `cargo test -p vauban-proxy-iacs protocol_gate` |
| L3 unit | `shared/src/iacs_protocol/` | `cargo test -p shared --features iacs-protocol iacs_protocol` |
| L3 auth integration | `vauban-access` handlers tests | `cargo test -p vauban-access denied_when_rule_modbus` |
| L3 E2E web | `iacs_protocol_auth_e2e_test.rs` | `cargo test -p vauban-web iacs_protocol` |

---

## Change log

| Version | Date | Notes |
|---------|------|-------|
| 1.1 | 2026-07-21 | Document revision. Boot Snapshot resync (§8.1): `IacsTunnelSnapshotRequest` / `Response`, pure `reconcile_iacs_boot`, proxy authority for "alive" after web-only restart. Lot 5: remove in-process IACS sshd from `vauban-web` (fail-closed without `proxy_iacs`; IPC-only watchdog). Updated source-of-truth and pins. Baseline also includes May 2026 amendments previously logged under the 1.0 filename: §11.1 token TTL / replay bypass (2026-05-16) and §14-15 protocol recognition (2026-05-23). |
| 1.0 | 2026-05-15 | Initial release: per-asset target resolution, three-layer authorization, anti-SSRF guards, supervisor broker via SCM_RIGHTS, DB-driven IPC-dispatched revocation watchdog, real-time WebSocket fan-out. |
