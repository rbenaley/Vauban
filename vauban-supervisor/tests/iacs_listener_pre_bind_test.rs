//! Pin tests for the IACS sshd listener pre-bind pattern.
//!
//! The russh sshd that EWS hosts connect to may listen on a
//! privileged TCP port (< 1024). Following the same model as the
//! HTTPS listener for vauban-web, the SUPERVISOR (which boots with
//! root or `CAP_NET_BIND_SERVICE`) is the only process allowed to
//! `bind()` that port. The raw FD is then inherited by
//! `vauban-proxy-iacs` across `fork+execv` (env
//! `VAUBAN_IACS_LISTENER_FD`); the proxy only needs `accept()` after
//! `cap_enter`.
//!
//! These tests ensure:
//!
//! 1. `vauban-supervisor/src/main.rs` calls
//!    `TcpListener::bind(&config.industrial.iacs_tunnel.bind_addr)`
//!    BEFORE entering the spawn loop / fork.
//! 2. No file under `vauban-proxy-iacs/src/**.rs` calls
//!    `TcpListener::bind` -- the proxy is structurally a pure
//!    `accept()`-only consumer of the inherited FD.
#![allow(clippy::unwrap_used, clippy::expect_used)]

const SUPERVISOR_MAIN: &str = include_str!("../src/main.rs");
const PROXY_MAIN: &str = include_str!("../../vauban-proxy-iacs/src/main.rs");
const PROXY_SERVER: &str = include_str!("../../vauban-proxy-iacs/src/server.rs");
const PROXY_RELAY: &str = include_str!("../../vauban-proxy-iacs/src/relay.rs");
const PROXY_REGISTRY: &str = include_str!("../../vauban-proxy-iacs/src/registry.rs");
const PROXY_AUTH: &str = include_str!("../../vauban-proxy-iacs/src/auth.rs");
const PROXY_IPC: &str = include_str!("../../vauban-proxy-iacs/src/ipc.rs");
const PROXY_UPSTREAM: &str = include_str!("../../vauban-proxy-iacs/src/upstream.rs");

/// The supervisor MUST `TcpListener::bind` on
/// `industrial.iacs_tunnel.bind_addr` AND that bind MUST happen
/// before any `spawn_child(` invocation.
#[test]
fn supervisor_pre_binds_iacs_listener_before_spawn() {
    // Locate the bind site. We accept either a literal `&config.industrial.iacs_tunnel.bind_addr`
    // capture in a `let addr = ...; let listener = TcpListener::bind(addr)` pattern.
    let bind_pos = SUPERVISOR_MAIN
        .find("TcpListener::bind(addr)")
        .or_else(|| {
            SUPERVISOR_MAIN.find("TcpListener::bind(&config.industrial.iacs_tunnel.bind_addr)")
        })
        .expect(
            "vauban-supervisor MUST call TcpListener::bind on the IACS \
             listener (industrial.iacs_tunnel.bind_addr).",
        );

    // The bind site must reference the IACS bind_addr in a window
    // around it (this disambiguates from the HTTPS bind that uses
    // `config.server.host`/`config.server.port`).
    let win_start = bind_pos.saturating_sub(800);
    let win_end = (bind_pos + 200).min(SUPERVISOR_MAIN.len());
    let window = &SUPERVISOR_MAIN[win_start..win_end];
    assert!(
        window.contains("industrial.iacs_tunnel.bind_addr"),
        "The IACS TcpListener::bind site MUST reference \
         industrial.iacs_tunnel.bind_addr (anti-confusion with the \
         HTTPS listener)."
    );

    // The first `spawn_child(` callsite (i.e. ignoring the function
    // definition `fn spawn_child(`) MUST come AFTER the bind.
    let first_spawn_call = SUPERVISOR_MAIN
        .match_indices("spawn_child(")
        .find(|(pos, _)| {
            let before = &SUPERVISOR_MAIN[pos.saturating_sub(3)..*pos];
            !before.ends_with("fn ")
        })
        .map(|(pos, _)| pos)
        .expect("at least one spawn_child callsite");

    assert!(
        bind_pos < first_spawn_call,
        "INVARIANT BROKEN: TcpListener::bind for IACS ({}) must \
         appear BEFORE the first spawn_child callsite ({}). The \
         supervisor must hold the bound FD before forking proxy_iacs.",
        bind_pos,
        first_spawn_call
    );
}

/// SECURITY (FreeBSD/Capsicum): the supervisor MUST mark the IACS
/// listener non-blocking BEFORE the spawn loop, while it still holds
/// the unsandboxed file descriptor. Post-`cap_enter`, the proxy
/// cannot call `set_nonblocking()` on the inherited FD because
/// `fcntl(F_GETFL/F_SETFL)` requires `CAP_FCNTL` rights that the
/// sandbox does not grant -- the historical bug surfaced as
/// "Capabilities insufficient (os error 93)" right after
/// "Entered Capsicum sandbox" in the proxy's startup log.
///
/// This pin guarantees:
///   * the supervisor calls `set_nonblocking(true)` on the bound
///     listener (pinned by source-grep),
///   * AND that call sits BEFORE the first `spawn_child(` invocation
///     (i.e. before any fork+execv that ships the FD to a child),
///   * AND no file under `vauban-proxy-iacs/src/**.rs` ever calls
///     `set_nonblocking` post-Capsicum on the inherited listener.
#[test]
fn supervisor_sets_nonblocking_before_execv() {
    // Locate the supervisor's set_nonblocking call on the IACS listener.
    let nb_pos = SUPERVISOR_MAIN
        .find("listener.set_nonblocking(true)")
        .expect(
            "vauban-supervisor MUST call listener.set_nonblocking(true) \
             on the IACS listener BEFORE fork (Capsicum forbids fcntl \
             on the inherited FD without CAP_FCNTL).",
        );

    let bind_pos = SUPERVISOR_MAIN
        .find("TcpListener::bind(addr)")
        .expect("supervisor must bind the IACS listener");
    assert!(
        bind_pos < nb_pos,
        "set_nonblocking({}) must come AFTER TcpListener::bind({}); \
         the bound listener is the receiver of the call.",
        nb_pos,
        bind_pos
    );

    let first_spawn_call = SUPERVISOR_MAIN
        .match_indices("spawn_child(")
        .find(|(pos, _)| {
            let before = &SUPERVISOR_MAIN[pos.saturating_sub(3)..*pos];
            !before.ends_with("fn ")
        })
        .map(|(pos, _)| pos)
        .expect("at least one spawn_child callsite");
    assert!(
        nb_pos < first_spawn_call,
        "INVARIANT BROKEN: set_nonblocking on the IACS listener ({}) \
         must appear BEFORE the first spawn_child callsite ({}); \
         post-Capsicum the proxy cannot toggle O_NONBLOCK without \
         CAP_FCNTL.",
        nb_pos,
        first_spawn_call
    );

    // The window around the call must mention the IACS listener
    // (anti-confusion with the HTTPS listener which is also bound by
    // the supervisor).
    let win_start = nb_pos.saturating_sub(1500);
    let win_end = (nb_pos + 200).min(SUPERVISOR_MAIN.len());
    let window = &SUPERVISOR_MAIN[win_start..win_end];
    assert!(
        window.contains("industrial.iacs_tunnel.bind_addr"),
        "The set_nonblocking site must be the IACS listener (window \
         must reference industrial.iacs_tunnel.bind_addr)."
    );
}

/// The proxy MUST NOT call `set_nonblocking` on the **inherited
/// listener** (whose FD comes from `VAUBAN_IACS_LISTENER_FD`) inside
/// `vauban-proxy-iacs/src/main.rs`. The supervisor sets the flag
/// before fork; a redundant call here would re-introduce the
/// errno-93 ("Capabilities insufficient") boot loop on FreeBSD,
/// because the inherited listener does not carry the `CAP_IOCTL`
/// rights that Rust's `TcpListener::set_nonblocking` needs
/// post-`cap_enter` (it goes through `ioctl(FIONBIO, ...)` on BSD
/// targets).
///
/// Note: brokered TCP stream FDs received by `upstream.rs` via
/// SCM_RIGHTS are a DIFFERENT story (per-connection, not the
/// listener) and are intentionally exempt from this pin -- this
/// test only constrains `main.rs` between `Entered Capsicum
/// sandbox` and the end of the listener setup block.
#[test]
fn proxy_iacs_never_calls_set_nonblocking_on_inherited_listener() {
    let cap_pos = PROXY_MAIN
        .find("Entered Capsicum sandbox")
        .expect("Capsicum entry log line must be present");
    let from_raw_pos = PROXY_MAIN[cap_pos..]
        .find("TcpListener::from_raw_fd")
        .map(|i| cap_pos + i)
        .expect("post-Capsicum listener wrap must be present");
    // Window from Capsicum entry to ~600 bytes after the
    // from_raw_fd call: that is the listener setup block.
    let win_end = (from_raw_pos + 600).min(PROXY_MAIN.len());
    let window = &PROXY_MAIN[cap_pos..win_end];

    // The lint allows the literal `set_nonblocking` only inside
    // `//` comment lines (we keep an explanation in the source).
    // Strip comment-prefixed lines and assert the residue contains
    // no actual call site `.set_nonblocking(`.
    let code_only: String = window
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !code_only.contains(".set_nonblocking("),
        "vauban-proxy-iacs/src/main.rs MUST NOT call \
         .set_nonblocking() on the inherited listener post-Capsicum: \
         the supervisor sets O_NONBLOCK pre-fork (file table flag \
         is inherited across execv); a post-`cap_enter` call would \
         issue ioctl(FIONBIO) which needs CAP_IOCTL on the FD, \
         a right the sandbox does not grant -> errno 93 boot-loop. \
         Offending window:\n{}",
        code_only
    );
}

/// `vauban-proxy-iacs` MUST NOT call `TcpListener::bind` anywhere in
/// its source. Capsicum forbids bind() post-`cap_enter`; even
/// pre-Capsicum, allowing the proxy to bind would re-introduce the
/// privileged-port escalation that the supervisor pre-bind eliminates.
#[test]
fn proxy_iacs_never_binds_a_tcp_listener() {
    for (name, src) in [
        ("main.rs", PROXY_MAIN),
        ("server.rs", PROXY_SERVER),
        ("relay.rs", PROXY_RELAY),
        ("registry.rs", PROXY_REGISTRY),
        ("auth.rs", PROXY_AUTH),
        ("ipc.rs", PROXY_IPC),
        ("upstream.rs", PROXY_UPSTREAM),
    ] {
        assert!(
            !src.contains("TcpListener::bind"),
            "vauban-proxy-iacs/src/{} MUST NOT call TcpListener::bind. \
             The supervisor pre-binds the listener and inherits the \
             FD via VAUBAN_IACS_LISTENER_FD; the proxy is a pure \
             accept()-only consumer.",
            name
        );
    }
}
