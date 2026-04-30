//! Issue #27 — pin the SSH host-key mismatch kill-switch.
//!
//! User-zone connect (`POST /assets/{uuid}/connect`) MUST refuse to
//! open a session when the remote SSH host key does not match the
//! pinned `ssh_host_key`. This is the load-bearing security property
//! the issue's user request reiterated explicitly:
//!
//!   "par contre, si la clé SSH host n'est pas bonne, il faut
//!    continuer à refuser l'ouverture de session"
//!
//! Two layers must stay healthy:
//!
//! 1. `connect_ssh` must SET `connection_config.ssh_host_key_mismatch
//!    = true` whenever a connection attempt fails because the remote
//!    fingerprint diverges from the stored one. Without this write,
//!    the next call to `verify_ssh_host_key` cannot surface the
//!    "stored mismatch" fragment and the operator UI silently allows
//!    the user to retry.
//!
//! 2. `verify_ssh_host_key` must READ `connection_config
//!    .ssh_host_key_mismatch` to gate the response. Without this read,
//!    a previously-detected MITM is forgotten on the next page load.
//!
//! These tests are source-level grep assertions: they pin the
//! invariant without depending on a real SSH endpoint (which is
//! impossible in CI). The `asset_protocol_test.rs` suite already
//! covers the storage-side invariants via real DB writes.

#[test]
fn connect_ssh_writes_mismatch_flag_on_failure() {
    let body = include_str!("../../src/handlers/web/ssh.rs");

    // We require BOTH the assignment AND the surrounding
    // `ssh_host_key_mismatch` write context appear in connect_ssh.
    // Constructed via format! so this test cannot self-match if it
    // is ever included in a future grep.
    let needle = format!("config[\"{}\"] = serde_json::Value::Bool(true)", "ssh_host_key_mismatch");
    let count = body.matches(needle.as_str()).count();
    assert!(
        count >= 2,
        "vauban-web/src/handlers/web/ssh.rs: the SSH host-key mismatch \
         kill-switch (write `ssh_host_key_mismatch = true` after a \
         failed connection) must appear at least twice (once in the \
         password path, once in the key path). Found {count} \
         occurrence(s). Removing this write would silently re-allow \
         a user to retry connecting to a suspected MITM target."
    );
}

#[test]
fn verify_ssh_host_key_reads_mismatch_flag() {
    let body = include_str!("../../src/handlers/web/ssh.rs");

    // The verify handler must consult the persisted flag so a previous
    // MITM detection is honoured across page reloads.
    let read_needle = format!(".get(\"{}\")", "ssh_host_key_mismatch");
    assert!(
        body.contains(read_needle.as_str()),
        "vauban-web/src/handlers/web/ssh.rs: `verify_ssh_host_key` (or \
         a sibling helper) must read `ssh_host_key_mismatch` from the \
         persisted connection_config so a previously-detected mismatch \
         survives across page reloads. Without it, the operator could \
         dismiss the warning fragment by reloading."
    );
}

#[test]
fn ssh_host_key_no_key_fragment_points_at_admin_endpoint() {
    // The user-zone fragment that prompts the operator to fetch the
    // host key MUST point at the admin-only endpoint (issue #27).
    // Otherwise a regular user could trigger a host-key write — a
    // privileged operation that requires `assets:manage`.
    let body = include_str!(
        "../../templates/assets/_ssh_host_key_no_key_fragment.html"
    );

    let admin_path = format!("/assets/{}/{{}}/fetch-host-key", "manage");
    let admin_path_unescaped = admin_path.replace("{}", "__ASSET_UUID__");
    assert!(
        body.contains(&admin_path_unescaped),
        "templates/assets/_ssh_host_key_no_key_fragment.html: the \
         `Fetch Host Key` button must point at the admin endpoint \
         `/assets/manage/__ASSET_UUID__/fetch-host-key`. A drift here \
         would either 404 (path no longer exists) or — worse — call \
         a user-zone endpoint that bypasses the `assets:manage` gate."
    );
}

#[test]
fn ssh_host_key_mismatch_fragment_points_at_admin_endpoint() {
    let body = include_str!(
        "../../templates/assets/_ssh_host_key_mismatch_fragment.html"
    );

    let admin_path = "/assets/manage/__ASSET_UUID__/fetch-host-key";
    assert!(
        body.contains(admin_path),
        "templates/assets/_ssh_host_key_mismatch_fragment.html: the \
         `Fetch Host Key` action must call the admin endpoint at \
         `{}`. Mismatch acceptance is a privileged operation.",
        admin_path
    );
}

#[test]
fn ssh_host_key_stored_mismatch_fragment_points_at_admin_endpoint() {
    let body = include_str!(
        "../../templates/assets/_ssh_host_key_stored_mismatch_fragment.html"
    );

    let admin_path = "/assets/manage/__ASSET_UUID__/fetch-host-key";
    assert!(
        body.contains(admin_path),
        "templates/assets/_ssh_host_key_stored_mismatch_fragment.html: \
         the `Refresh` action must re-fetch via the admin endpoint at \
         `{}`. Without this, the user could keep retrying via a \
         user-zone endpoint that no longer exists.",
        admin_path
    );
}
