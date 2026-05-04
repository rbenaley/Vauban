//! Issue #34 -- structural pin tests for the SSH host-key surface.
//!
//! These tests are source-grep assertions that complement the runtime
//! coverage in `ssh_host_key_e2e_test.rs` and the in-proxy behavioural
//! tests in `vauban-proxy-ssh/src/session.rs::host_key_behavioural_tests`.
//! They pin invariants that are easier (and faster) to enforce at the
//! source level than to drive end-to-end:
//!
//!   - `verify_ssh_host_key` MUST NOT render the green
//!     `_ssh_host_key_fragment.html` from any code path that does not
//!     compare the live remote key against the stored one.
//!   - `connect_ssh` MUST emit the two strict-pin refusal messages
//!     ("No SSH host key pinned" and "SSH host key mismatch detected
//!     on previous connection") and they MUST sit before any
//!     downstream session-creation work.
//!   - `verify_ssh_host_key` MUST read `perms.assets_manage` and
//!     forward it to `HostKeyFetchIdentity` so admins reach the
//!     diagnostic-token verb (issue #34 Lot 2).
//!   - `fetch_ssh_host_key` (admin endpoint) MUST do the same.

const SSH_HANDLER: &str = include_str!("../../src/handlers/web/ssh.rs");

/// The green "Verified" fragment must only appear AFTER a comparison
/// between the live remote key and the stored one. Concretely: every
/// occurrence of the include line must be preceded (within the same
/// function) by `old_key == remote_key`. We enforce a slightly
/// stronger invariant here -- every include of the green fragment in
/// `ssh.rs` must sit inside a block whose preceding source contains
/// the `old_key == remote_key` literal.
#[test]
fn verify_ssh_host_key_never_renders_green_outside_match_branch() {
    // The green fragment may legitimately appear in TWO places:
    //
    //   1. `verify_ssh_host_key` -- ONLY when `old_key == remote_key`
    //      (the regression we are guarding against).
    //   2. `fetch_ssh_host_key` -- the admin has just persisted the
    //      live key, so the act of rendering green confirms what was
    //      written; no comparison is needed (or possible).
    //
    // We therefore extract the body of `verify_ssh_host_key` and
    // assert that every green-fragment include WITHIN that body sits
    // after a `old_key == remote_key` comparison.
    let verify_start = SSH_HANDLER
        .find("pub async fn verify_ssh_host_key")
        .expect("verify_ssh_host_key handler must still exist");
    let after_start = &SSH_HANDLER[verify_start..];
    let verify_end_offset = after_start
        .find("\npub async fn ")
        .or_else(|| after_start.find("\npub fn "))
        .unwrap_or(after_start.len());
    let verify_body = &SSH_HANDLER[verify_start..verify_start + verify_end_offset];

    let needle = "_ssh_host_key_fragment.html";
    let local_occurrences: Vec<usize> = verify_body
        .match_indices(needle)
        .map(|(idx, _)| idx)
        .collect();

    assert!(
        !local_occurrences.is_empty(),
        "verify_ssh_host_key must STILL include the green fragment in \
         the keys-match branch. Found 0 occurrences in the function \
         body -- did the green fragment file get renamed, or did the \
         match branch get refactored away?"
    );

    for idx in &local_occurrences {
        // Look back at most ~800 bytes for the match-comparison
        // sentinel. If we never find it, the include sits in a path
        // that did NOT establish that the live key matches -- exactly
        // the issue #34 silent green regression.
        let window_start = idx.saturating_sub(800);
        let window = &verify_body[window_start..*idx];
        assert!(
            window.contains("old_key == remote_key"),
            "vauban-web/src/handlers/web/ssh.rs: every include of \
             `_ssh_host_key_fragment.html` INSIDE verify_ssh_host_key \
             must sit in a branch that established `old_key == \
             remote_key`. Found an occurrence at offset {idx} (within \
             the function body) whose preceding {} bytes do NOT \
             contain that comparison. This is the issue #34 silent \
             green regression: the green fragment must NEVER be \
             emitted from a fallback / Err / proxy-unavailable \
             branch.",
            idx - window_start
        );
    }

    // Drift sanity: also pin the total occurrence count across the
    // whole file so a future refactor that copies the green fragment
    // include into a new function path is forced to update this
    // test (and this comment) deliberately.
    let total = SSH_HANDLER.matches(needle).count();
    assert!(
        total <= 2,
        "ssh.rs uses `{needle}` more than 2 times ({total}). The \
         expected sites are: (a) verify_ssh_host_key keys-match \
         branch, (b) fetch_ssh_host_key post-store. Adding a third \
         site MUST be intentional -- if the new site is also gated \
         on a comparison, raise this bound."
    );
}

/// The amber unverified fragment must be reachable from `ssh.rs`.
/// This protects against a future cleanup pass that deletes the
/// fallback fragment without rerouting the two Err / proxy-unavailable
/// branches: if the include line disappears, those branches would
/// fail to compile, but the test catches the intent more directly.
#[test]
fn verify_ssh_host_key_includes_unverified_fragment_for_fallback() {
    let needle = "_ssh_host_key_unverified_fragment.html";
    let count = SSH_HANDLER.matches(needle).count();
    assert!(
        count >= 2,
        "vauban-web/src/handlers/web/ssh.rs: the amber \"Could not \
         verify\" fragment must be included at least twice (proxy \
         unavailable AND fetch_host_key Err). Found {count} \
         occurrence(s). Removing one of them re-opens the issue #34 \
         silent green regression."
    );
}

/// `connect_ssh` must carry the strict-pin refusal message for the
/// "no key pinned" case. The literal is also pinned by the CI lint
/// script (`scripts/check_ssh_host_key_paths.sh`); this test is the
/// fast in-IDE counterpart.
#[test]
fn connect_ssh_emits_no_pinned_key_refusal() {
    let needle = "No SSH host key pinned";
    assert!(
        SSH_HANDLER.contains(needle),
        "vauban-web/src/handlers/web/ssh.rs must contain the literal \
         \"{needle}\" -- it is the issue #34 strict-pin gate user \
         message. Removing it silently re-opens the TOFU window the \
         pre-flight check was designed to close."
    );
}

/// `connect_ssh` must carry the explicit MITM-warning refusal for the
/// "mismatch flag set" case.
#[test]
fn connect_ssh_emits_mismatch_refusal() {
    let needle = "SSH host key mismatch detected on previous connection";
    assert!(
        SSH_HANDLER.contains(needle),
        "vauban-web/src/handlers/web/ssh.rs must contain the literal \
         \"{needle}\" -- it is the issue #34 pre-flight gate user \
         message for the persisted mismatch case. Removing it would \
         silently let users retry connecting to a suspected MITM \
         target."
    );
}

/// The two pre-flight refusal messages must sit BEFORE the
/// `proxy_client.open_session` (or equivalent session-creation) call
/// in `connect_ssh`. We assert a structural invariant: the indices of
/// both refusal literals come BEFORE the first `proxy_sessions::table`
/// insert in the file. A drift here would mean the gate runs after
/// session creation -- still a refusal at HTTP level, but with a
/// dangling row in DB.
#[test]
fn connect_ssh_pre_flight_runs_before_session_creation() {
    let no_key = SSH_HANDLER
        .find("No SSH host key pinned")
        .expect("\"No SSH host key pinned\" literal must exist (covered by sibling test)");
    let mismatch = SSH_HANDLER
        .find("SSH host key mismatch detected on previous connection")
        .expect("mismatch refusal literal must exist (covered by sibling test)");
    // The first session-creation site after the pre-flight is the
    // INSERT into `proxy_sessions`. The literal `proxy_sessions::table`
    // appears at every diesel call site; the very first one in the
    // file is the one we want.
    let first_session_insert = SSH_HANDLER
        .find("insert_into(proxy_sessions::table)")
        .expect(
            "ssh.rs must still INSERT into proxy_sessions::table \
             somewhere -- otherwise the connect flow is broken",
        );
    assert!(
        no_key < first_session_insert,
        "the \"No SSH host key pinned\" refusal must sit BEFORE \
         insert_into(proxy_sessions::table). Found no_key={no_key}, \
         first_session_insert={first_session_insert}. Otherwise the \
         pre-flight runs too late and dangling rows are created."
    );
    assert!(
        mismatch < first_session_insert,
        "the mismatch refusal must sit BEFORE \
         insert_into(proxy_sessions::table). Found mismatch={mismatch}, \
         first_session_insert={first_session_insert}."
    );
}

/// `verify_ssh_host_key` must read `perms.assets_manage` and forward
/// it through `HostKeyFetchIdentity::caller_has_assets_manage` so the
/// IPC layer routes admin callers to the diagnostic-token verb. This
/// is what closes the original issue #34 root cause: pre-fix every
/// caller went through `IssueSessionToken`, which silently denied
/// admins without an explicit access rule.
#[test]
fn verify_ssh_host_key_threads_assets_manage_to_identity() {
    // Locate the verify handler block by chunking on the function
    // signature and the next `pub async fn` / end of file. We do not
    // attempt to parse Rust here; a simple substring window is enough.
    let start = SSH_HANDLER
        .find("pub async fn verify_ssh_host_key")
        .expect("verify_ssh_host_key handler must still exist in ssh.rs");
    let after = &SSH_HANDLER[start..];
    let end = after
        .find("\npub async fn ")
        .map(|next| start + next)
        .or_else(|| after.find("\npub fn ").map(|next| start + next))
        .unwrap_or(SSH_HANDLER.len());
    let body = &SSH_HANDLER[start..end];

    assert!(
        body.contains("perms.assets_manage"),
        "verify_ssh_host_key body must read `perms.assets_manage`. \
         Issue #34 introduced the diagnostic-token verb so admins \
         without an explicit access rule reach the host-key fetch \
         path; verify_ssh_host_key must opt them in by forwarding \
         this flag. Body slice: {} bytes",
        body.len()
    );
    assert!(
        body.contains("caller_has_assets_manage"),
        "verify_ssh_host_key body must construct \
         `HostKeyFetchIdentity` with `caller_has_assets_manage` set. \
         Without it the IPC layer falls back to the legacy session-\
         token verb and the regression returns. Body slice: {} bytes",
        body.len()
    );
}

/// Same invariant for the admin-only `fetch_ssh_host_key` endpoint.
/// The function is gated on `assets:manage` so the bool is
/// structurally `true` at the call site, but we still pin the read +
/// forward to make the contract explicit and resistant to refactors.
#[test]
fn fetch_ssh_host_key_threads_assets_manage_to_identity() {
    let start = SSH_HANDLER
        .find("pub async fn fetch_ssh_host_key")
        .expect("fetch_ssh_host_key handler must still exist in ssh.rs");
    let after = &SSH_HANDLER[start..];
    let end = after
        .find("\npub async fn ")
        .map(|next| start + next)
        .or_else(|| after.find("\npub fn ").map(|next| start + next))
        .unwrap_or(SSH_HANDLER.len());
    let body = &SSH_HANDLER[start..end];

    assert!(
        body.contains("perms.assets_manage"),
        "fetch_ssh_host_key body must read `perms.assets_manage`."
    );
    assert!(
        body.contains("caller_has_assets_manage"),
        "fetch_ssh_host_key body must construct \
         `HostKeyFetchIdentity` with `caller_has_assets_manage` set."
    );
}

/// `HostKeyFetchIdentity` must carry the `caller_has_assets_manage`
/// field. A drift here would silently revert the issue #34 fix:
/// callers could keep filling the struct without the flag and the
/// IPC layer would default to the session-token verb.
#[test]
fn host_key_fetch_identity_carries_assets_manage_flag() {
    let body = include_str!("../../src/ipc/proxy_ssh.rs");
    assert!(
        body.contains("pub caller_has_assets_manage"),
        "vauban-web/src/ipc/proxy_ssh.rs: HostKeyFetchIdentity must \
         expose `pub caller_has_assets_manage: bool`. Without it, \
         every host-key fetch falls back to the legacy session-token \
         verb and admins without an explicit access rule see the \
         issue #34 silent green fragment again."
    );
    assert!(
        body.contains("issue_diagnostic_token"),
        "vauban-web/src/ipc/proxy_ssh.rs must call \
         `issue_diagnostic_token` for `caller_has_assets_manage = \
         true` callers (issue #34 Lot 2)."
    );
}

/// The shared IPC enum must keep the `IssueDiagnosticToken` variant.
/// Removing it would break the bincode wire-format compatibility
/// promise and re-open issue #34 immediately.
#[test]
fn shared_messages_carries_issue_diagnostic_token_variant() {
    let body = include_str!("../../../shared/src/messages.rs");
    assert!(
        body.contains("IssueDiagnosticToken"),
        "shared/src/messages.rs must keep the \
         `AccessRequest::IssueDiagnosticToken` variant (issue #34 \
         Lot 2). It is wire-compatible with IssueSessionToken and \
         removing it breaks the host-key verify/fetch path for \
         admins."
    );
    assert!(
        body.contains("caller_has_assets_manage"),
        "shared/src/messages.rs: the IssueDiagnosticToken variant \
         must carry the `caller_has_assets_manage` field so vauban-\
         access can gate the bypass on it."
    );
}
