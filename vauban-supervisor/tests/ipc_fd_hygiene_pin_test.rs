//! Source-grep pin tests for the VAU-005 IPC FD cloisonnement.
//!
//! These run via `cargo test` on every platform (they only read source
//! text, no syscalls), so they hold on the FreeBSD integration server and
//! on developer machines alike. They lock the four invariants behind the
//! fix so a refactor cannot silently re-open the cross-service FD leak:
//!
//! - INV-1: `IpcChannel::pair()` stamps every pipe end FD_CLOEXEC.
//! - INV-2: `shared::ipc::clear_cloexec` is the SINGLE door that makes an
//!   IPC fd inheritable; no raw `F_SETFD(FdFlag::empty())` lives in the
//!   supervisor anymore.
//! - INV-3: `spawn_child` de-CLOEXECs exactly the supervisor channel and
//!   this service's topology pipe ends (outgoing + incoming).
//! - The whole fork+execv surface goes through `spawn_child` (one `fork()`,
//!   one `execv(`), so the allowlist above is exhaustive.
//!
//! Behavioral proof (real fork+execv, EBADF on foreign fds) lives in
//! `shared/tests/ipc_cloexec_e2e_test.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

const SUPERVISOR_MAIN: &str = include_str!("../src/main.rs");
const SHARED_IPC: &str = include_str!("../../shared/src/ipc.rs");

/// Extract the body of a top-level `fn <name>(` from `src` up to the next
/// top-level `\nfn ` (good enough for these single-function greps).
fn fn_body<'a>(src: &'a str, signature: &str) -> &'a str {
    let start = src
        .find(signature)
        .unwrap_or_else(|| panic!("`{signature}` must exist in source"));
    let rest = &src[start..];
    let end = rest[1..].find("\nfn ").map(|i| i + 1).unwrap_or(rest.len());
    &rest[..end]
}

/// INV-1: `IpcChannel::pair()` stamps FD_CLOEXEC on the pipe ends.
#[test]
fn pair_sets_fd_cloexec() {
    let body = fn_body(SHARED_IPC, "pub fn pair()");
    assert!(
        body.contains("F_SETFD(FdFlag::FD_CLOEXEC)"),
        "IpcChannel::pair() MUST set FD_CLOEXEC on the pipe ends (INV-1)."
    );
}

/// INV-2 (definition side): `clear_cloexec` exists, is public, and is the
/// thing that actually clears the flag.
#[test]
fn clear_cloexec_is_the_single_door_definition() {
    let body = fn_body(SHARED_IPC, "pub fn clear_cloexec(");
    assert!(
        body.contains("F_SETFD(FdFlag::empty())"),
        "clear_cloexec MUST clear FD_CLOEXEC via F_SETFD(FdFlag::empty())."
    );
}

/// INV-3: `spawn_child` re-enables inheritance for the supervisor channel
/// (read + write) AND iterates this service's topology pipe ends
/// (outgoing + incoming), all via the single door.
#[test]
fn spawn_child_decloexecs_supervisor_channel_and_topology() {
    let body = fn_body(SUPERVISOR_MAIN, "fn spawn_child(");

    assert!(
        body.contains("for fd in [read_fd, write_fd]"),
        "spawn_child MUST de-CLOEXEC the supervisor channel (read_fd + write_fd)."
    );
    assert!(
        body.contains("pipes.outgoing.iter().chain(pipes.incoming.iter())"),
        "spawn_child MUST iterate this service's outgoing AND incoming topology pipe ends."
    );
    // All de-CLOEXEC in spawn_child go through the single door.
    assert!(
        body.contains("shared::ipc::clear_cloexec"),
        "spawn_child MUST use shared::ipc::clear_cloexec (the single door, INV-2)."
    );
}

/// INV-2 (drift guard): no raw `F_SETFD(FdFlag::empty())` anywhere in the
/// supervisor -- every de-CLOEXEC must funnel through clear_cloexec.
#[test]
fn single_door_no_raw_fsetfd_empty_outside_clear_cloexec() {
    assert!(
        !SUPERVISOR_MAIN.contains("F_SETFD(FdFlag::empty())"),
        "The supervisor MUST NOT clear FD_CLOEXEC inline; route through \
         shared::ipc::clear_cloexec (INV-2). Found a raw F_SETFD(FdFlag::empty())."
    );
}

/// The fork+execv surface is funneled through `spawn_child`: exactly one
/// `fork()` and one `execv(` in the whole supervisor, so the de-CLOEXEC
/// allowlist in spawn_child is exhaustive (no other path spawns a service
/// with a different, unguarded FD set).
#[test]
fn all_spawn_paths_go_through_spawn_child() {
    let fork_calls = SUPERVISOR_MAIN.matches("unsafe { fork() }").count();
    assert_eq!(
        fork_calls, 1,
        "Expected exactly one `unsafe {{ fork() }}` (inside spawn_child); \
         found {fork_calls}. A new fork path must also de-CLOEXEC via clear_cloexec."
    );

    // `execv(` appears once as the real call; the doc-comment mentions of
    // execv() use `execv()` with parens-and-text, so match the call form.
    let execv_calls = SUPERVISOR_MAIN.matches("execv(&c_path").count();
    assert_eq!(
        execv_calls, 1,
        "Expected exactly one `execv(&c_path ...)` call (inside spawn_child); found {execv_calls}."
    );
}
