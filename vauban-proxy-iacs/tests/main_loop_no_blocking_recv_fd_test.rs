//! Pin tests for the safety invariant that
//! `receive_fd_with_retry` (in `vauban-proxy-iacs/src/main.rs`) NEVER
//! falls through to a blocking `recv_fd(socket_fd)` syscall on the
//! FD-passing socket once all polling retries are exhausted.
//!
//! Background (regression caught in 0.7.x):
//! ----------------------------------------
//! The supervisor used to send TWO `TcpConnectResponse` messages to
//! `proxy_iacs` for a single `Service::ProxyIacs` broker request: one
//! through `target_state.channel.send(&fd_info)` (step 4) and one
//! through `requesting_channel.send(&response)` (step 5), because for
//! self-targeting brokers `target_state.channel == requesting_channel`.
//!
//! Only the first message had a matching SCM_RIGHTS file descriptor on
//! the FD-passing socket. The second message would arrive in the
//! proxy's main_loop, dispatch into `handle_supervisor_message`, and
//! call `receive_fd_with_retry`. After 10 polling retries on an empty
//! socket, the function fell through to a synchronous, BLOCKING
//! `recv_fd(socket_fd)` -- which parked the calling tokio worker
//! indefinitely (the socket is created with `SockFlag::empty()` in
//! `socketpair_for_fd_passing`, so `recvmsg(2)` blocks). The wedged
//! worker starved `main_loop`'s `tokio::select!`, the proxy stopped
//! answering supervisor heartbeats, and ~15-18 s later the supervisor
//! force-restarted it.
//!
//! The supervisor side is fixed in
//! `handle_tcp_connect_request` (skip step 5 when
//! `target_key == requesting_service_key`, see
//! `vauban-supervisor` `mod tests`
//! `test_supervisor_iacs_broker_skips_duplicate_response_to_self`).
//!
//! These tests pin the proxy-side defence-in-depth: even if a
//! malformed / extra `TcpConnectResponse` ever lands on the IPC pipe
//! (supervisor regression, fault injection, future refactor), the
//! proxy MUST fail closed with a `TimedOut` IpcError instead of
//! parking on a blocking syscall.

#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

const SRC: &str = "src";

fn read_src(rel: &str) -> String {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(SRC)
        .join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {}", p.display(), e))
}

/// Extract the body of `async fn receive_fd_with_retry(...)` from
/// `main.rs`. We cut from the `fn receive_fd_with_retry(` declaration
/// to the matching closing brace at column 0 (the function lives at
/// the file's top level), which is robust to surrounding helpers
/// being added or reordered.
fn extract_receive_fd_with_retry_body() -> String {
    let src = read_src("main.rs");
    let start = src
        .find("async fn receive_fd_with_retry(")
        .expect("receive_fd_with_retry must exist in main.rs");
    let after_signature = &src[start..];
    let end_rel = after_signature
        .find("\n}\n")
        .expect("receive_fd_with_retry must terminate with a column-0 `}`");
    after_signature[..end_rel + 2].to_string()
}

/// Strip line comments (`// ...`) from a Rust snippet so structural
/// assertions key on actual code rather than commentary that
/// references syscall names. Block comments and rustdoc are not
/// produced inside the function body so we don't need to handle them.
fn strip_line_comments(src: &str) -> String {
    src.lines()
        .map(|l| match l.find("//") {
            Some(idx) => &l[..idx],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The function MUST NOT contain a fall-through `recv_fd(socket_fd)`
/// outside of the `poll_readable` success arm: any such tail call
/// would block the tokio worker indefinitely on `recvmsg(2)`.
///
/// We allow ONE `recv_fd(socket_fd)` -- the one inside the
/// `Ok(ready) if !ready.is_empty()` poll-success arm, which is gated
/// on `poll_readable` having returned a ready FD. A second occurrence
/// (the historical fallback at the very end of the function) MUST
/// stay deleted.
#[test]
fn fallback_returns_error_after_all_retries() {
    let body = extract_receive_fd_with_retry_body();
    let code = strip_line_comments(&body);

    let recv_fd_call_count = code.matches("recv_fd(socket_fd)").count();
    assert_eq!(
        recv_fd_call_count, 1,
        "receive_fd_with_retry MUST call `recv_fd(socket_fd)` exactly \
         ONCE -- inside the `poll_readable` success arm. A second call \
         (fall-through after exhausting retries) blocks the tokio \
         worker on recvmsg(2) and starves main_loop's heartbeats. \
         Found {} occurrences in code (comments stripped):\n{}",
        recv_fd_call_count, code
    );

    // The single allowed call site is the `return recv_fd(socket_fd);`
    // inside the `Ok(ready) if !ready.is_empty()` arm.
    assert!(
        code.contains("return recv_fd(socket_fd);"),
        "the single `recv_fd(socket_fd)` call MUST be a `return` \
         inside the `poll_readable` success arm. Body:\n{}",
        code
    );

    assert!(
        code.contains("ErrorKind::TimedOut"),
        "receive_fd_with_retry MUST return a `TimedOut` IpcError when \
         all polling retries are exhausted (fail closed). Body:\n{}",
        code
    );

    let last_recv_fd = code
        .rfind("recv_fd(socket_fd)")
        .expect("we just asserted recv_fd_call_count >= 1");
    let safety_err = code
        .rfind("Err(shared::ipc::IpcError::Io(std::io::Error::new(")
        .expect("receive_fd_with_retry must terminate with an explicit Err return");
    assert!(
        safety_err > last_recv_fd,
        "the explicit `Err(... TimedOut ...)` return MUST come AFTER \
         the last `recv_fd(socket_fd)` call so the function can never \
         fall through to a blocking syscall. Body:\n{}",
        code
    );
}

/// The safety invariant MUST be documented in the function's doc
/// comment so future contributors do not accidentally restore the
/// blocking fallback while "cleaning up" the error path.
#[test]
fn safety_invariant_is_documented() {
    let src = read_src("main.rs");
    let doc_start = src
        .find("/// Receive a file descriptor with retry and async polling.")
        .expect("receive_fd_with_retry doc comment must exist");
    let signature = src[doc_start..]
        .find("async fn receive_fd_with_retry(")
        .expect("doc must immediately precede the signature");
    let doc_block = &src[doc_start..doc_start + signature];

    assert!(
        doc_block.contains("MUST NOT make a blocking syscall"),
        "receive_fd_with_retry doc comment MUST state the no-blocking \
         invariant explicitly. Found:\n{}",
        doc_block
    );
    assert!(
        doc_block.contains("SCM_RIGHTS"),
        "receive_fd_with_retry doc comment MUST mention SCM_RIGHTS so \
         the failure mode is searchable from grep / git blame."
    );
}
