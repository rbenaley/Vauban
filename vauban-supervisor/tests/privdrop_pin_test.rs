//! Source-grep pin tests for the VAU-009 privilege-drop group purge.
//!
//! These run via `cargo test` on every platform (they only read source
//! text, no syscalls), so they hold on the FreeBSD integration server and
//! on developer machines alike. They lock the invariants behind the fix so
//! a refactor cannot silently re-open the "supplementary groups not purged"
//! gap:
//!
//! - INV-1 (purge): `shared::privdrop::drop_privileges` calls `setgroups(&[])`.
//! - INV-2 (order): `setgroups` BEFORE `setgid` BEFORE `setuid`.
//! - INV-3a (seam): `spawn_child` drops privileges via
//!   `shared::privdrop::drop_privileges(`.
//! - INV-3b (single door / drift guard): no raw `setgroups(`/`setgid(`/
//!   `setuid(` survives in the supervisor `main.rs` outside comments.
//!
//! Behavioral proof (real fork+execv, empty `getgroups()` + target
//! euid/egid) lives in `shared/tests/privdrop_e2e_test.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

const SUPERVISOR_MAIN: &str = include_str!("../src/main.rs");
const SHARED_PRIVDROP: &str = include_str!("../../shared/src/privdrop.rs");

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

/// Strip `//` line comments so drift guards do not false-positive on a token
/// that only appears in explanatory prose.
fn strip_line_comments(src: &str) -> String {
    src.lines()
        .map(|line| match line.find("//") {
            Some(i) => &line[..i],
            None => line,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// INV-1: the primitive purges the supplementary groups with an empty list.
#[test]
fn drop_privileges_purges_supplementary_groups() {
    let body = fn_body(SHARED_PRIVDROP, "pub fn drop_privileges(");
    assert!(
        body.contains("setgroups(0"),
        "drop_privileges MUST purge supplementary groups via setgroups(0, NULL) (INV-1)."
    );
}

/// INV-2: the canonical order is setgroups -> setgid -> setuid. Purge happens
/// while still root (before setuid drops CAP_SETGID), gid before uid.
#[test]
fn drop_order_is_setgroups_then_setgid_then_setuid() {
    let body = fn_body(SHARED_PRIVDROP, "pub fn drop_privileges(");
    let groups = body
        .find("setgroups(")
        .expect("drop_privileges MUST call setgroups (INV-1/INV-2).");
    let gid = body
        .find("setgid(")
        .expect("drop_privileges MUST call setgid.");
    let uid = body
        .find("setuid(")
        .expect("drop_privileges MUST call setuid.");
    assert!(
        groups < gid && gid < uid,
        "Order MUST be setgroups -> setgid -> setuid (INV-2); got setgroups@{groups}, \
         setgid@{gid}, setuid@{uid}."
    );
}

/// INV-3a: the supervisor drops privileges exclusively through the primitive.
#[test]
fn spawn_child_drops_via_primitive_seam() {
    let body = fn_body(SUPERVISOR_MAIN, "fn spawn_child(");
    assert!(
        body.contains("shared::privdrop::drop_privileges("),
        "spawn_child MUST drop privileges via shared::privdrop::drop_privileges (INV-3a)."
    );
}

/// INV-3b (drift guard): no raw setgroups/setgid/setuid call survives in the
/// supervisor main.rs (comments excluded) -- the only drop is the primitive.
#[test]
fn supervisor_has_no_raw_privilege_syscalls() {
    let code = strip_line_comments(SUPERVISOR_MAIN);
    for forbidden in ["setgroups(", "setgid(", "setuid("] {
        assert!(
            !code.contains(forbidden),
            "The supervisor MUST NOT call `{forbidden}` inline; route the drop through \
             shared::privdrop::drop_privileges (INV-3b single door)."
        );
    }
}
