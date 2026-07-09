//! Pin tests for the global client IP ACL gate on the IACS sshd
//! accept loop (`[security] allowed_client_networks`).
//!
//! Contract:
//!
//! 1. `VAUBAN_CLIENT_ACL_NETWORKS` is parsed BEFORE
//!    `setup_service_sandbox_with_listeners` (same Capsicum ordering
//!    rule as the host key / AsyncIpcChannel pins: the env read costs
//!    nothing post-sandbox, but keeping every env consumption grouped
//!    pre-`cap_enter` is the established hygiene, and the fail-closed
//!    `bail!` must abort the boot before the sandbox seals).
//! 2. The env var is removed after parsing (defence-in-depth, exactly
//!    like every other VAUBAN_* env consumed by this binary).
//! 3. The accept loop gates the peer with `permits()` STRICTLY BEFORE
//!    `Server::new_client` / `run_stream`, so a denied peer never
//!    receives a single SSH byte (no banner, no protocol hint --
//!    stealth deny).
//! 4. Parsing is fail-closed: a malformed value must abort the boot
//!    (`from_env_string` + error propagation), never degrade to
//!    allow-all.
//!
//! Pure source-greps on `vauban-proxy-iacs/src/main.rs`, modelled on
//! `host_key_loaded_before_capsicum_test.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

const MAIN_RS: &str = include_str!("../src/main.rs");

/// The ACL env var MUST be parsed strictly before the Capsicum gate,
/// so a malformed value aborts the boot pre-sandbox (fail-closed).
#[test]
fn client_acl_parsed_strictly_before_cap_enter() {
    let parse_pos = MAIN_RS
        .find("VAUBAN_CLIENT_ACL_NETWORKS")
        .expect("main.rs must read VAUBAN_CLIENT_ACL_NETWORKS (supervisor contract)");
    let cap_enter_pos = MAIN_RS
        .find("setup_service_sandbox_with_listeners(")
        .expect("setup_service_sandbox_with_listeners must be called in main.rs");
    assert!(
        parse_pos < cap_enter_pos,
        "INVARIANT BROKEN: VAUBAN_CLIENT_ACL_NETWORKS (byte {}) must be \
         parsed BEFORE setup_service_sandbox_with_listeners (byte {}), \
         so an invalid ACL aborts the boot before the sandbox seals.",
        parse_pos,
        cap_enter_pos
    );
}

/// The ACL is parsed with the SHARED matcher (`shared::client_acl`),
/// never a local reimplementation, so the accepted CIDR grammar can
/// never drift from vauban-web / vauban-supervisor.
#[test]
fn client_acl_uses_the_shared_matcher() {
    assert!(
        MAIN_RS.contains("shared::client_acl::ClientAcl::from_env_string"),
        "main.rs must parse the ACL via shared::client_acl::ClientAcl::from_env_string \
         (single source of truth; a local parser would drift from vauban-web)."
    );
}

/// The env var MUST be cleared after parsing (defence-in-depth,
/// matching every other VAUBAN_* env consumed by this binary).
#[test]
fn client_acl_env_var_is_removed_after_parse() {
    assert!(
        MAIN_RS.contains("remove_var(\"VAUBAN_CLIENT_ACL_NETWORKS\")"),
        "main.rs must remove_var(VAUBAN_CLIENT_ACL_NETWORKS) after parsing \
         so the value does not leak into descendants."
    );
}

/// The accept loop MUST gate the peer with `permits()` STRICTLY BEFORE
/// handing the stream to russh (`Server::new_client` then
/// `run_stream`). A denied peer must never receive an SSH banner.
#[test]
fn accept_loop_gates_on_permits_before_new_client() {
    let permits_pos = MAIN_RS
        .find(".permits(peer.ip())")
        .expect("the accept loop must call permits(peer.ip())");
    // Match the CALL SITES (not the doc comments mentioning them).
    let new_client_pos = MAIN_RS
        .find("Server::new_client(&mut server")
        .expect("the accept loop must call Server::new_client");
    let run_stream_pos = MAIN_RS
        .find("run_stream(cfg")
        .expect("the accept loop must call run_stream");
    assert!(
        permits_pos < new_client_pos,
        "INVARIANT BROKEN: permits(peer.ip()) (byte {}) must be checked \
         BEFORE Server::new_client (byte {}); otherwise a denied peer \
         reaches the russh handshake and can fingerprint the bastion.",
        permits_pos,
        new_client_pos
    );
    assert!(
        permits_pos < run_stream_pos,
        "permits(peer.ip()) must also precede run_stream (no SSH byte \
         may be exchanged with a denied peer)."
    );
}

/// The denial path must `continue` after dropping the stream (silent
/// drop, no response written), and stay at debug! level so a scanner
/// sweep cannot flood the operator's terminal.
#[test]
fn denied_peer_is_dropped_silently() {
    let gate_start = MAIN_RS
        .find(".permits(peer.ip())")
        .expect("accept-loop ACL gate");
    let window = &MAIN_RS[gate_start..gate_start + 600];
    assert!(
        window.contains("drop(stream)"),
        "the denied-peer branch must drop(stream) explicitly (silent close)"
    );
    assert!(
        window.contains("continue"),
        "the denied-peer branch must continue the accept loop"
    );
    assert!(
        !window.contains("info!") && !window.contains("warn!") && !window.contains("error!"),
        "the denial log must stay at debug! (a port sweep from a denied \
         range must not flood the operator's terminal)"
    );
}

/// Fail-closed boot: the parse error must be propagated (refusing to
/// start), never swallowed with unwrap_or_default / ok().
#[test]
fn client_acl_parse_is_fail_closed() {
    let parse_pos = MAIN_RS
        .find("shared::client_acl::ClientAcl::from_env_string")
        .expect("shared matcher call site");
    let window = &MAIN_RS[parse_pos..parse_pos + 700];
    assert!(
        window.contains("refusing to start"),
        "the ACL parse error context must state that the proxy refuses to \
         start (fail-closed); a silent fallback to allow-all is forbidden."
    );
    // The parse Result must be propagated with `?` (map_err + `?`), never
    // discarded with `.ok()` -- note the inner `unwrap_or_default()` on
    // `std::env::var` is fine (ABSENT var = ACL disabled by design); what
    // is forbidden is defaulting a PRESENT-but-malformed value.
    assert!(
        window.contains("map_err") && window.contains(")?;"),
        "the from_env_string Result must be propagated (map_err + `?`), \
         aborting the boot on a malformed value."
    );
}
