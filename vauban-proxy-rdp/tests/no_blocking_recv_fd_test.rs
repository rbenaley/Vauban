//! Pin tests for the safety invariant that `receive_fd_with_retry`
//! (in `vauban-proxy-rdp/src/main.rs`) NEVER falls through to a blocking
//! `recv_fd(socket_fd)` syscall on the FD-passing socket once all polling
//! retries are exhausted.
//!
//! Same invariant (and same regression class) as proxy-iacs: the
//! FD-passing socket is created blocking (`socketpair_for_fd_passing` --
//! `SockFlag::empty()`), so a tail `recv_fd(socket_fd)` after the polls
//! returned "not ready" parks the calling tokio worker indefinitely on
//! `recvmsg(2)`, starves the main loop's heartbeats and gets the service
//! force-restarted by the supervisor. See
//! `vauban-proxy-iacs/tests/main_loop_no_blocking_recv_fd_test.rs` for the
//! full historical background.

#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

const SRC: &str = "src";

fn read_src(rel: &str) -> String {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(SRC)
        .join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {}", p.display(), e))
}

/// Extract the body of `async fn receive_fd_with_retry(...)` from
/// `main.rs` (declaration to the matching column-0 closing brace).
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

/// Strip line comments so the structural assertions key on actual code.
fn strip_line_comments(src: &str) -> String {
    src.lines()
        .map(|l| match l.find("//") {
            Some(idx) => &l[..idx],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The function MUST contain exactly ONE `recv_fd(socket_fd)` call -- the
/// one inside the `poll_readable` success arm -- and MUST terminate with
/// an explicit `TimedOut` error instead of a blocking fallback.
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
         worker on recvmsg(2). Found {} occurrences in code (comments \
         stripped):\n{}",
        recv_fd_call_count, code
    );

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

/// The safety invariant MUST be documented in the function's doc comment.
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
