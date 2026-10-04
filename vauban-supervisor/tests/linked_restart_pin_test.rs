//! Source-shape pins for the linked-restart / PipeStore contract (0.9.43).
//!
//! A first-match `get_linked_services` plus a local `new_pipes` HashMap
//! that is dropped at the end of `respawn_linked_group` is the production
//! incident class (stale fd numbers, SSH+RDP dead after the second
//! restart). These greps keep the repair from drifting.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

const SUPERVISOR_MAIN: &str = include_str!("../src/main.rs");

fn prod_source() -> &'static str {
    SUPERVISOR_MAIN
        .split("#[cfg(test)]")
        .next()
        .expect("production source before cfg(test)")
}

fn fn_body<'a>(src: &'a str, signature: &str) -> &'a str {
    let start = src
        .find(signature)
        .unwrap_or_else(|| panic!("`{signature}` must exist in source"));
    let rest = &src[start..];
    let end = rest[1..].find("\nfn ").map(|i| i + 1).unwrap_or(rest.len());
    &rest[..end]
}

#[test]
fn no_first_match_get_linked_services() {
    let prod = prod_source();
    assert!(
        !prod.contains("fn get_linked_services"),
        "get_linked_services (first-match) must not exist; use linked_closure"
    );
    assert!(
        !prod.contains(".find(|group|"),
        "linked-group lookup must not first-match with .find(|group|"
    );
}

#[test]
fn respawn_linked_group_takes_pipe_store() {
    let body = fn_body(SUPERVISOR_MAIN, "fn respawn_linked_group(");
    assert!(
        body.contains("pipe_store: &mut PipeStore"),
        "respawn_linked_group must take &mut PipeStore"
    );
    assert!(
        !body.contains("HashMap<(Service, Service), (IpcChannel, IpcChannel)>"),
        "main.rs must not allocate a local topology HashMap"
    );
}

#[test]
fn service_pipes_only_via_derive() {
    let run = fn_body(SUPERVISOR_MAIN, "fn run_supervisor(");
    assert!(
        run.contains("derive_service_pipes("),
        "run_supervisor must build service_pipes via derive_service_pipes"
    );
    let linked = fn_body(SUPERVISOR_MAIN, "fn respawn_linked_group(");
    assert!(
        linked.contains("derive_service_pipes("),
        "respawn_linked_group must rebuild via derive_service_pipes"
    );
    assert!(
        !linked.contains("service_pipes.insert("),
        "respawn_linked_group must not insert hand-built ServicePipes"
    );
}

#[test]
fn respawn_decision_references_exit_code_respawn() {
    let body = fn_body(SUPERVISOR_MAIN, "fn respawn_decision(");
    assert!(
        body.contains("EXIT_CODE_RESPAWN"),
        "respawn_decision must use EXIT_CODE_RESPAWN, not a bare 100"
    );
}

#[test]
fn web_linked_group_contains_proxy_mcp() {
    let prod = prod_source();
    assert!(
        prod.contains("&[\"web\", \"proxy_mcp\"]"),
        "LINKED_RESTART_GROUPS must pair web with proxy_mcp"
    );
}

/// A linked restart re-pushes the identity loaded from disk; it never
/// mints a new key while the files are present and valid, so the SPKI
/// the shim pinned survives any number of restarts. The 20-restart
/// runtime battle is `battle_twenty_linked_restarts_keep_one_spki`.
#[test]
fn linked_restart_reuses_the_tunnel_identity_on_disk() {
    let linked = fn_body(SUPERVISOR_MAIN, "fn respawn_linked_group(");
    assert!(linked.contains("send_mcp_tunnel_identity(proxy, web, &config.server.tls.cert_path)"));
    let ensure = fn_body(SUPERVISOR_MAIN, "fn ensure_mcp_tunnel_identity(");
    assert!(
        ensure.contains("if missing || expired {"),
        "a new key is generated only when the files are missing or expiring"
    );
    assert!(
        ensure.contains("KeyPair::from_pem(&pem)"),
        "a re-issue keeps the existing key, hence the SPKI"
    );
    assert!(SUPERVISOR_MAIN.contains("fn battle_twenty_linked_restarts_keep_one_spki"));
}

#[test]
fn watchdog_uses_linked_group_keys() {
    let body = fn_body(SUPERVISOR_MAIN, "fn watchdog_loop(");
    assert!(
        body.contains("linked_group_keys("),
        "watchdog_loop must resolve the transitive closure"
    );
    assert!(
        body.contains("pipe_store: &mut PipeStore"),
        "watchdog_loop must take &mut PipeStore"
    );
}
