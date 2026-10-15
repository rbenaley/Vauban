//! Cutting events: every change that takes access away must reach the
//! proxies at once.
//!
//! The proxies (SSH, RDP, IACS, MCP) only stop relaying when vauban-web
//! tells them over IPC. A handler that only writes the database leaves the
//! visit running: deleting an asset once left MCP visits alive until their
//! ticket expired. These pins keep the single list of such events
//! ([`CUTTING_EVENTS`]) and check that each one calls a shared seam, and
//! that no handler removes access without one.

use std::path::{Path, PathBuf};

/// Shared seams that end or tighten live sessions in DB **and** proxy.
const SEAMS: [&str; 8] = [
    "terminate_live_session",
    "api::sessions::terminate_session(",
    "terminate_open_sessions_on_asset",
    "end_visits_on_reconfigured_asset",
    "notify_policy_changed",
    "deactivate_user(",
    "after_api_key_invalidated(",
    "cascade_terminate_grant_sessions(",
];

/// The single list of events that take access away: (source file under
/// `src/`, function, what it removes).
const CUTTING_EVENTS: &[(&str, &str, &str)] = &[
    (
        "handlers/web/users.rs",
        "update_user_web",
        "deactivating an account",
    ),
    (
        "handlers/web/users.rs",
        "delete_user_web",
        "soft-deleting an account",
    ),
    (
        "handlers/web/users.rs",
        "deactivate_user",
        "the account sweep itself",
    ),
    (
        "handlers/web/users.rs",
        "revoke_api_key",
        "revoking an API key",
    ),
    (
        "handlers/web/groups.rs",
        "remove_group_member_web",
        "removing a group member",
    ),
    (
        "handlers/web/groups.rs",
        "add_group_member_web",
        "adding a member (Allow intersection shrinks)",
    ),
    (
        "handlers/web/sessions.rs",
        "revoke_access_request",
        "revoking a JIT grant",
    ),
    (
        "handlers/web/sessions.rs",
        "terminate_session_web",
        "an administrator ending a session",
    ),
    (
        "handlers/api/sessions.rs",
        "terminate_session",
        "the API ending a session",
    ),
    (
        "handlers/web/access_rules.rs",
        "create_access_rule_web",
        "creating a rule",
    ),
    (
        "handlers/web/access_rules.rs",
        "update_access_rule_web",
        "editing a rule",
    ),
    (
        "handlers/web/access_rules.rs",
        "delete_access_rule_web",
        "deleting a rule",
    ),
    (
        "handlers/api/access_rules.rs",
        "create_access_rule",
        "creating a rule over the API",
    ),
    (
        "handlers/api/access_rules.rs",
        "update_access_rule",
        "editing a rule over the API",
    ),
    (
        "handlers/api/access_rules.rs",
        "delete_access_rule",
        "deleting a rule over the API",
    ),
    (
        "handlers/web/mcp_access.rs",
        "create_mcp_access_rule_web",
        "creating an MCP rule",
    ),
    (
        "handlers/web/mcp_access.rs",
        "update_mcp_access_rule_web",
        "editing MCP tool modes",
    ),
    (
        "handlers/web/mcp_access.rs",
        "delete_mcp_access_rule_web",
        "deleting an MCP rule",
    ),
    (
        "handlers/web/manage_assets.rs",
        "delete_asset_web",
        "deleting an asset",
    ),
    (
        "handlers/web/manage_assets.rs",
        "update_asset_web",
        "moving an MCP upstream (address, transport, pin)",
    ),
    (
        "handlers/api/manage_assets.rs",
        "update_asset",
        "moving an MCP upstream over the API",
    ),
    (
        "handlers/web/asset_groups.rs",
        "asset_group_add_asset",
        "adding an asset to a group (Allow intersection shrinks)",
    ),
    (
        "handlers/web/asset_groups.rs",
        "asset_group_remove_asset",
        "removing an asset from a group",
    ),
    (
        "handlers/web/asset_groups.rs",
        "delete_asset_group_web",
        "deleting an asset group",
    ),
];

fn src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(src_dir().join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

/// Production part of a source file (before its `#[cfg(test)] mod`).
fn prod(src: &str) -> &str {
    src.split("#[cfg(test)]\nmod ").next().unwrap_or(src)
}

/// Body of `fn name` up to the next top-level item.
fn fn_body<'a>(src: &'a str, name: &str) -> Option<&'a str> {
    let start = [
        format!("pub async fn {name}("),
        format!("async fn {name}("),
        format!("pub fn {name}("),
    ]
    .iter()
    .find_map(|n| src.find(n.as_str()))?;
    let rest = &src[start + 1..];
    let end = [
        "\npub async fn ",
        "\nasync fn ",
        "\npub fn ",
        "\nfn ",
        "\n#[cfg(test)]",
    ]
    .iter()
    .filter_map(|m| rest.find(m))
    .min()
    .unwrap_or(rest.len());
    Some(&src[start..start + 1 + end])
}

fn reaches_a_seam(body: &str) -> bool {
    SEAMS.iter().any(|s| body.contains(s))
}

fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let p = entry.path();
        if p.is_dir() {
            rs_files(&p, out);
        } else if p.extension().is_some_and(|e| e == "rs") {
            out.push(p);
        }
    }
}

/// Lines that take access away: a soft-delete tombstone, a terminate
/// flip, or deleting a row that grants access.
fn removes_access(src: &str) -> Vec<String> {
    let lines: Vec<&str> = src.lines().collect();
    let mut hits = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let t = line.trim();
        if t.starts_with("//") {
            continue;
        }
        let next = lines.get(i + 1).copied().unwrap_or("");
        let grant_row_delete = t.contains("diesel::delete(")
            && [
                "asset_asset_groups",
                "user_groups",
                "api_keys",
                "access_rules",
            ]
            .iter()
            .any(|table| t.contains(table) || next.contains(table));
        if t.ends_with("is_deleted.eq(true),")
            || t.contains(r#"status.eq("terminated")"#)
            || grant_row_delete
        {
            hits.push(format!("{}: {t}", i + 1));
        }
    }
    hits
}

#[test]
fn every_cutting_event_calls_a_shared_seam() {
    for (file, func, what) in CUTTING_EVENTS {
        let src = read(file);
        let body = fn_body(prod(&src), func).unwrap_or_else(|| {
            panic!("{file}: `{func}` ({what}) not found; update CUTTING_EVENTS")
        });
        assert!(
            reaches_a_seam(body),
            "{file}::{func} ({what}) takes access away but never tells the proxies; \
             call one of {SEAMS:?}"
        );
    }
}

#[test]
fn no_handler_takes_access_away_without_a_seam() {
    let mut files = Vec::new();
    rs_files(&src_dir().join("handlers"), &mut files);
    assert!(!files.is_empty(), "no handler sources found");
    for path in files {
        let src = std::fs::read_to_string(&path).expect("read handler");
        let body = prod(&src);
        let hits = removes_access(body);
        if hits.is_empty() {
            continue;
        }
        assert!(
            reaches_a_seam(body),
            "{} removes access without a shared seam ({SEAMS:?}): {hits:?}",
            path.display()
        );
    }
}

#[test]
fn every_handler_that_removes_access_is_in_the_inventory() {
    let mut files = Vec::new();
    rs_files(&src_dir().join("handlers"), &mut files);
    let root = src_dir();
    for path in files {
        let src = std::fs::read_to_string(&path).expect("read handler");
        let body = prod(&src);
        if removes_access(body).is_empty() {
            continue;
        }
        let rel = path
            .strip_prefix(&root)
            .expect("under src")
            .to_string_lossy()
            .replace('\\', "/");
        assert!(
            CUTTING_EVENTS.iter().any(|(f, _, _)| *f == rel),
            "{rel} removes access but has no CUTTING_EVENTS entry"
        );
    }
}

#[test]
fn asset_delete_ends_every_open_session_on_every_protocol() {
    let assets = read("handlers/web/manage_assets.rs");
    let delete = fn_body(prod(&assets), "delete_asset_web").expect("delete_asset_web");
    assert!(
        delete.contains("session_termination::terminate_open_sessions_on_asset")
            && delete.contains("REASON_ASSET_DELETED"),
        "asset delete must end its open sessions through the shared seam"
    );
    assert!(
        !delete.contains(r#"status.eq("terminated")"#),
        "asset delete must not flip sessions to terminated by hand (no IPC)"
    );

    let core = read("services/session_termination.rs");
    let on_asset = fn_body(prod(&core), "terminate_open_sessions_on_asset").expect("on-asset seam");
    assert!(
        on_asset.contains("SessionStatus::OPEN_AS_STR")
            && on_asset.contains("terminate_live_session("),
        "the on-asset seam covers live AND suspended sessions and uses the terminate core"
    );
    assert!(core.contains(r#"REASON_ASSET_DELETED: &str = "asset_deleted""#));
    assert!(core.contains(r#"REASON_ASSET_RECONFIGURED: &str = "asset_reconfigured""#));
}

#[test]
fn lost_terminates_are_resent_by_the_safety_net() {
    let core = read("services/session_termination.rs");
    let net = fn_body(prod(&core), "resend_lost_terminates").expect("net");
    for verb in [
        "terminate_session(",
        "close_session(",
        "terminate_tunnel(",
        "is_deleted",
        "REASON_ASSET_RECONFIGURED",
        "ACTOR_MCP_RECHECK",
        "session_ttl_clamped",
    ] {
        assert!(net.contains(verb), "the safety net must use `{verb}`");
    }
    let loop_src = read("services/policy_recheck.rs");
    assert!(
        fn_body(prod(&loop_src), "spawn_policy_recheck")
            .is_some_and(|b| b.contains("recheck_tick(")),
        "the 30 s loop runs recheck_tick"
    );
    assert!(
        fn_body(prod(&loop_src), "recheck_tick")
            .is_some_and(|b| b.contains("resend_lost_terminates")),
        "the 30 s loop must resend lost terminates"
    );
    assert!(
        read("main.rs").contains("policy_recheck::spawn_policy_recheck("),
        "the 30 s safety net for SSH/RDP/IACS must actually be started"
    );
}

#[test]
fn a_cut_visit_takes_its_hitl_calls_with_it() {
    let client = read("ipc/proxy_mcp.rs");
    let terminate = fn_body(prod(&client), "terminate_session").expect("terminate_session");
    let drop_at = terminate
        .find("e.session_id != session_id")
        .expect("terminating a visit must drop its HITL pendings from the web queue");
    let send_at = terminate.find("send_fire_and_forget").expect("IPC send");
    assert!(
        drop_at < send_at,
        "drop the pendings before the IPC send, so a lost send cannot leave them approvable"
    );
}

#[test]
fn proxy_mcp_terminate_is_idempotent() {
    let proxy = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../vauban-proxy-mcp/src/main.rs"),
    )
    .expect("proxy-mcp main.rs");
    let guards = proxy.matches("Some(sess) if !sess.terminated =>").count();
    assert!(
        guards >= 2,
        "both proxy-mcp terminate paths must ignore an already-ended visit \
         (a resend must not finalize the recording twice); found {guards}"
    );
}
