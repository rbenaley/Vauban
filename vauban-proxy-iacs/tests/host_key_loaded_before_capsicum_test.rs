//! Pin tests for the IACS host key load order.
//!
//! Background: under FreeBSD Capsicum, post-`cap_enter` `open()` on
//! an absolute path returns errno 94 ("Not permitted in capability
//! mode"). The pre-fix bug was that vauban-proxy-iacs called
//! `load_or_generate_host_key(path)` AFTER `setup_service_sandbox_with_listeners`,
//! which crashed the process at boot on FreeBSD and triggered an
//! infinite respawn loop in the supervisor.
//!
//! Fix: the supervisor pre-loads the key BEFORE fork
//! (`shared::iacs_host_key::prepare_host_key_fd`) and inherits the
//! read-only FD via `VAUBAN_IACS_HOST_KEY_FD`; the proxy consumes
//! the FD with `read_host_key_from_fd` BEFORE entering Capsicum.
//!
//! These tests are pure source-greps: they read
//! `vauban-proxy-iacs/src/main.rs` and pin the invariant in the
//! source so a future refactor that re-introduces the bug fails CI
//! immediately.

#![allow(clippy::unwrap_used, clippy::expect_used)]

const MAIN_RS: &str = include_str!("../src/main.rs");
const SERVER_RS: &str = include_str!("../src/server.rs");

/// The host key MUST be read STRICTLY before
/// `setup_service_sandbox_with_listeners`. Otherwise Capsicum breaks
/// the read.
#[test]
fn host_key_is_read_strictly_before_cap_enter() {
    let read_pos = MAIN_RS
        .find("read_host_key_from_fd(")
        .expect("read_host_key_from_fd must be called in main.rs");
    let cap_enter_pos = MAIN_RS
        .find("setup_service_sandbox_with_listeners(")
        .expect("setup_service_sandbox_with_listeners must be called in main.rs");
    assert!(
        read_pos < cap_enter_pos,
        "INVARIANT BROKEN: read_host_key_from_fd ({}) must appear \
         BEFORE setup_service_sandbox_with_listeners ({}). \
         Otherwise FreeBSD Capsicum (cap_enter) returns errno 94 on \
         the file open and vauban-proxy-iacs crash-loops at boot.",
        read_pos,
        cap_enter_pos
    );
}

/// The proxy MUST NOT call `load_or_generate_host_key` any more --
/// that helper now lives in `shared::iacs_host_key` and is invoked
/// only by the supervisor (BEFORE fork).
#[test]
fn proxy_does_not_call_load_or_generate_host_key() {
    assert!(
        !MAIN_RS.contains("load_or_generate_host_key("),
        "load_or_generate_host_key must NOT be called in vauban-proxy-iacs/src/main.rs \
         any more. The supervisor pre-loads the host key via \
         shared::iacs_host_key::prepare_host_key_fd and the proxy reads \
         the inherited FD via shared::iacs_host_key::read_host_key_from_fd \
         BEFORE Capsicum."
    );
    assert!(
        !SERVER_RS.contains("fn load_or_generate_host_key"),
        "load_or_generate_host_key must NOT be re-defined in \
         vauban-proxy-iacs/src/server.rs. The single source of truth \
         lives in shared::iacs_host_key."
    );
}

/// The proxy MUST NOT read the legacy `VAUBAN_IACS_HOST_KEY_PATH`
/// env var any more. Reading it would either be dead code (if the
/// supervisor stops setting it) or, worse, an invitation to fall
/// back to a post-Capsicum `open()` -- forbidden by the very bug
/// this module fixes.
#[test]
fn proxy_does_not_consume_legacy_host_key_path_env() {
    assert!(
        !MAIN_RS.contains("VAUBAN_IACS_HOST_KEY_PATH"),
        "VAUBAN_IACS_HOST_KEY_PATH must NOT be read by \
         vauban-proxy-iacs/src/main.rs any more. The supervisor passes \
         the host key as a read-only FD via VAUBAN_IACS_HOST_KEY_FD."
    );
}

/// The proxy MUST read `VAUBAN_IACS_HOST_KEY_FD` (case-sensitive)
/// from the env -- that is the supervisor's contract.
#[test]
fn proxy_reads_host_key_fd_env_var() {
    assert!(
        MAIN_RS.contains("VAUBAN_IACS_HOST_KEY_FD"),
        "vauban-proxy-iacs/src/main.rs MUST read \
         VAUBAN_IACS_HOST_KEY_FD; the supervisor pre-loads the host \
         key and inherits the FD via this env var."
    );
}

/// The proxy MUST NOT bind any TCP listener of its own. Binding is
/// the supervisor's job (privileged-port < 1024 supported, same
/// pattern as the HTTPS listener); under Capsicum, `bind()` is
/// forbidden anyway. This pin test catches a future regression that
/// would add a "fall back to direct bind" path on the IACS sshd.
#[test]
fn proxy_does_not_call_tcp_listener_bind() {
    let server = SERVER_RS;
    assert!(
        !MAIN_RS.contains("TcpListener::bind"),
        "vauban-proxy-iacs/src/main.rs MUST NOT call TcpListener::bind; \
         the supervisor pre-binds the listener and inherits the FD via \
         VAUBAN_IACS_LISTENER_FD."
    );
    assert!(
        !server.contains("TcpListener::bind"),
        "vauban-proxy-iacs/src/server.rs MUST NOT call TcpListener::bind; \
         see main.rs invariant above."
    );
}
