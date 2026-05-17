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
        .or_else(|| SUPERVISOR_MAIN.find("TcpListener::bind(&config.industrial.iacs_tunnel.bind_addr)"))
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
