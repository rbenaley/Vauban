//! Source-grep pin tests for the VAU-006 recording-file path confinement.
//!
//! These run via `cargo test` on every platform (they only read source
//! text, no syscalls), so they hold on the FreeBSD integration server and
//! on developer machines alike. They lock the invariants behind the fix so
//! a refactor cannot silently re-open the path-traversal primitive:
//!
//! - INV-2 (fail-closed, pre-syscall): the path is resolved BEFORE any
//!   `File::open` / `File::create` / `create_dir_all` in the handler.
//! - INV-3 (single seam): the handler resolves through
//!   `shared::recording_paths::resolve_recording_file_target`, and no naked
//!   `Path::new(storage_base).join(relative_path)` survives.
//!
//! Behavioral proof (real tempdir, real symlink escape) lives in
//! `recording_path_traversal_test.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

const SUPERVISOR_MAIN: &str = include_str!("../src/main.rs");

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

/// INV-3: the broker resolves the target through the shared seam.
#[test]
fn broker_resolves_via_shared_seam() {
    let body = fn_body(SUPERVISOR_MAIN, "fn handle_recording_file_request(");
    assert!(
        body.contains("shared::recording_paths::resolve_recording_file_target"),
        "handle_recording_file_request MUST resolve the path via \
         shared::recording_paths::resolve_recording_file_target (INV-3)."
    );
}

/// INV-2/INV-3 (drift guard): the naked join that caused VAU-006 is gone.
#[test]
fn broker_has_no_naked_join() {
    let body = fn_body(SUPERVISOR_MAIN, "fn handle_recording_file_request(");
    assert!(
        !body.contains("Path::new(storage_base).join(relative_path)"),
        "handle_recording_file_request MUST NOT join storage_base with the \
         untrusted relative_path directly (VAU-006 regression)."
    );
}

/// INV-2 (pre-syscall order): the path resolution happens before every
/// filesystem syscall in the handler.
///
/// Write opens use `OpenOptions` (O_RDWR + create) so audit can later
/// gzip the raw IACS `.pcap` on the same FD -- not bare `File::create`.
#[test]
fn broker_validates_before_fs_calls() {
    let body = fn_body(SUPERVISOR_MAIN, "fn handle_recording_file_request(");

    let resolve_at = body
        .find("resolve_recording_file_target")
        .expect("resolve seam must be present");

    for syscall in ["File::open", "OpenOptions::new", "create_dir_all"] {
        let at = body
            .find(syscall)
            .unwrap_or_else(|| panic!("`{syscall}` must be present in the handler"));
        assert!(
            resolve_at < at,
            "Path resolution MUST precede `{syscall}` (INV-2, fail-closed pre-syscall)."
        );
    }

    assert!(
        body.contains(".create(true)")
            && body.contains(".read(true)")
            && body.contains(".write(true)"),
        "write path MUST open O_RDWR via OpenOptions (audit gzip on same FD)."
    );
    assert!(
        !body.contains("File::create"),
        "write path MUST NOT use bare File::create (O_WRONLY would break audit gzip)."
    );
}
