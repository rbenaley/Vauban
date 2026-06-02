//! VAU-001 -- structural pin tests for the RDP server-certificate
//! surface. Strict mirror of `ssh_host_key_no_silent_green_test.rs`.
//!
//! These source-grep assertions complement the runtime coverage in
//! `rdp_cert_pin_e2e_test.rs` and the in-proxy behavioural tests in
//! `vauban-proxy-rdp/src/session.rs::rdp_cert_behavioural_tests`. They
//! pin invariants that are easier (and faster) to enforce at the
//! source level than to drive end-to-end:
//!
//!   - `verify_rdp_server_cert` MUST NOT render the green
//!     `_rdp_server_cert_fragment.html` from any code path that does
//!     not compare the live remote SPKI against the stored one.
//!   - `connect_rdp` MUST emit the two strict-pin refusal messages
//!     ("No RDP server certificate pinned for this asset" and "RDP
//!     server certificate mismatch detected on previous connection")
//!     and they MUST sit before any session-creation work.
//!   - `verify_rdp_server_cert` / `fetch_rdp_server_cert` MUST read
//!     `perms.assets_manage` and forward it to `CertFetchIdentity` so
//!     admins reach the diagnostic-token verb.

const RDP_HANDLER: &str = include_str!("../../src/handlers/web/rdp.rs");

/// The green "Verified" fragment must only appear AFTER a comparison
/// between the live remote SPKI and the stored one inside
/// `verify_rdp_server_cert`.
#[test]
fn verify_rdp_server_cert_never_renders_green_outside_match_branch() {
    let verify_start = RDP_HANDLER
        .find("pub async fn verify_rdp_server_cert")
        .expect("verify_rdp_server_cert handler must still exist");
    let after_start = &RDP_HANDLER[verify_start..];
    let verify_end_offset = after_start
        .find("\npub async fn ")
        .or_else(|| after_start.find("\npub fn "))
        .unwrap_or(after_start.len());
    let verify_body = &RDP_HANDLER[verify_start..verify_start + verify_end_offset];

    let needle = "_rdp_server_cert_fragment.html";
    let local_occurrences: Vec<usize> = verify_body
        .match_indices(needle)
        .map(|(idx, _)| idx)
        .collect();

    assert!(
        !local_occurrences.is_empty(),
        "verify_rdp_server_cert must STILL include the green fragment in \
         the SPKI-match branch. Found 0 occurrences in the function body \
         -- did the green fragment file get renamed, or did the match \
         branch get refactored away?"
    );

    for idx in &local_occurrences {
        let window_start = idx.saturating_sub(800);
        let window = &verify_body[window_start..*idx];
        assert!(
            window.contains("old_spki == remote_spki"),
            "vauban-web/src/handlers/web/rdp.rs: every include of \
             `_rdp_server_cert_fragment.html` INSIDE \
             verify_rdp_server_cert must sit in a branch that \
             established `old_spki == remote_spki`. Found an occurrence \
             at offset {idx} whose preceding {} bytes do NOT contain \
             that comparison. This is the VAU-001 silent green \
             regression: the green fragment must NEVER be emitted from a \
             fallback / Err / proxy-unavailable branch.",
            idx - window_start
        );
    }

    // Drift sanity: pin the total occurrence count across the whole
    // file so a future refactor that copies the green include into a
    // new path is forced to update this test deliberately. Expected
    // sites: (a) verify_rdp_server_cert SPKI-match branch,
    // (b) fetch_rdp_server_cert post-store.
    let total = RDP_HANDLER.matches(needle).count();
    assert!(
        total <= 2,
        "rdp.rs uses `{needle}` more than 2 times ({total}). The \
         expected sites are the verify match branch and the fetch \
         post-store. Adding a third site MUST be intentional."
    );
}

/// The amber unverified fragment must be reachable from `rdp.rs` in at
/// least two branches (proxy unavailable AND fetch Err). Removing one
/// re-opens the silent green regression.
#[test]
fn verify_rdp_server_cert_includes_unverified_fragment_for_fallback() {
    let needle = "_rdp_server_cert_unverified_fragment.html";
    let count = RDP_HANDLER.matches(needle).count();
    assert!(
        count >= 2,
        "vauban-web/src/handlers/web/rdp.rs: the amber \"Could not \
         verify\" fragment must be included at least twice (proxy \
         unavailable AND fetch_server_cert Err). Found {count} \
         occurrence(s)."
    );
}

#[test]
fn connect_rdp_emits_no_pinned_cert_refusal() {
    let needle = "No RDP server certificate pinned for this asset";
    assert!(
        RDP_HANDLER.contains(needle),
        "vauban-web/src/handlers/web/rdp.rs must contain the literal \
         \"{needle}\" -- it is the VAU-001 strict-pin gate user \
         message. Removing it silently re-opens the MITM window the \
         pre-flight check was designed to close."
    );
}

#[test]
fn connect_rdp_emits_mismatch_refusal() {
    let needle = "RDP server certificate mismatch detected on previous connection";
    assert!(
        RDP_HANDLER.contains(needle),
        "vauban-web/src/handlers/web/rdp.rs must contain the literal \
         \"{needle}\" -- it is the VAU-001 pre-flight gate message for \
         the persisted mismatch case."
    );
}

/// Both pre-flight refusal literals must sit BEFORE the first INSERT
/// into `proxy_sessions::table`, otherwise the gate runs too late and
/// dangling rows are created.
#[test]
fn connect_rdp_pre_flight_runs_before_session_creation() {
    let no_key = RDP_HANDLER
        .find("No RDP server certificate pinned for this asset")
        .expect("no-pin literal must exist (covered by sibling test)");
    let mismatch = RDP_HANDLER
        .find("RDP server certificate mismatch detected on previous connection")
        .expect("mismatch refusal literal must exist (covered by sibling test)");
    let first_session_insert = RDP_HANDLER
        .find("insert_into(proxy_sessions::table)")
        .expect("rdp.rs must still INSERT into proxy_sessions::table");
    assert!(
        no_key < first_session_insert,
        "the no-pin refusal must sit BEFORE \
         insert_into(proxy_sessions::table). Found no_key={no_key}, \
         first_session_insert={first_session_insert}."
    );
    assert!(
        mismatch < first_session_insert,
        "the mismatch refusal must sit BEFORE \
         insert_into(proxy_sessions::table). Found mismatch={mismatch}, \
         first_session_insert={first_session_insert}."
    );
}

#[test]
fn verify_rdp_server_cert_threads_assets_manage_to_identity() {
    let start = RDP_HANDLER
        .find("pub async fn verify_rdp_server_cert")
        .expect("verify_rdp_server_cert handler must still exist in rdp.rs");
    let after = &RDP_HANDLER[start..];
    let end = after
        .find("\npub async fn ")
        .map(|next| start + next)
        .or_else(|| after.find("\npub fn ").map(|next| start + next))
        .unwrap_or(RDP_HANDLER.len());
    let body = &RDP_HANDLER[start..end];

    assert!(
        body.contains("perms.assets_manage"),
        "verify_rdp_server_cert body must read `perms.assets_manage` so \
         admins without an explicit access rule reach the cert fetch \
         path. Body slice: {} bytes",
        body.len()
    );
    assert!(
        body.contains("caller_has_assets_manage"),
        "verify_rdp_server_cert body must construct `CertFetchIdentity` \
         with `caller_has_assets_manage` set. Body slice: {} bytes",
        body.len()
    );
}

#[test]
fn fetch_rdp_server_cert_threads_assets_manage_to_identity() {
    let start = RDP_HANDLER
        .find("pub async fn fetch_rdp_server_cert")
        .expect("fetch_rdp_server_cert handler must still exist in rdp.rs");
    let after = &RDP_HANDLER[start..];
    let end = after
        .find("\npub async fn ")
        .map(|next| start + next)
        .or_else(|| after.find("\npub fn ").map(|next| start + next))
        .unwrap_or(RDP_HANDLER.len());
    let body = &RDP_HANDLER[start..end];

    assert!(
        body.contains("perms.assets_manage"),
        "fetch_rdp_server_cert body must read `perms.assets_manage`."
    );
    assert!(
        body.contains("caller_has_assets_manage"),
        "fetch_rdp_server_cert body must construct `CertFetchIdentity` \
         with `caller_has_assets_manage` set."
    );
}

/// `CertFetchIdentity` must carry the `caller_has_assets_manage` field
/// and the IPC layer must route admin callers through the
/// diagnostic-token verb.
#[test]
fn cert_fetch_identity_carries_assets_manage_flag() {
    let body = include_str!("../../src/ipc/proxy_rdp.rs");
    assert!(
        body.contains("pub caller_has_assets_manage"),
        "vauban-web/src/ipc/proxy_rdp.rs: CertFetchIdentity must expose \
         `pub caller_has_assets_manage: bool`."
    );
    assert!(
        body.contains("issue_diagnostic_token"),
        "vauban-web/src/ipc/proxy_rdp.rs must call `issue_diagnostic_token` \
         for `caller_has_assets_manage = true` callers."
    );
}

/// The shared IPC enum must keep the RDP cert variants and the pin
/// field, otherwise the cert-pinning wire format breaks.
#[test]
fn shared_messages_carries_rdp_cert_variants() {
    let body = include_str!("../../../shared/src/messages.rs");
    for needle in [
        "RdpFetchServerCert",
        "RdpServerCertResult",
        "expected_cert_fingerprint",
    ] {
        assert!(
            body.contains(needle),
            "shared/src/messages.rs must keep `{needle}` (VAU-001 wire \
             format)."
        );
    }
}
