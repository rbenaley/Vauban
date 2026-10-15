//! Source pins for the MCP architecture rules (MCP Arch, skill `mcp.md`).
//! Each test names the rule it guards; a failure means a refactor moved a
//! decision across a trust boundary, not that a string changed.
#![allow(clippy::expect_used, clippy::panic)]

const ACCESS_PDP: &str = include_str!("../../vauban-access/src/mcp_pdp.rs");
const PROXY_MAIN: &str = include_str!("../../vauban-proxy-mcp/src/main.rs");
const WEB_CONNECT: &str = include_str!("../../vauban-web/src/handlers/web/mcp.rs");
const WEB_API_OPEN: &str = include_str!("../../vauban-web/src/handlers/api/mcp_sessions.rs");
const WEB_DRIFT: &str = include_str!("../../vauban-web/src/services/mcp_drift.rs");
const LAB_LINT: &str = include_str!("../../vauban-proxy-mcp/scripts/check_mcp_no_lab_escape.sh");

/// Web sources that decide, open or relay MCP work.
const WEB_MCP: &[(&str, &str)] = &[
    ("handlers/web/mcp.rs", WEB_CONNECT),
    ("handlers/api/mcp_sessions.rs", WEB_API_OPEN),
    ("services/mcp_drift.rs", WEB_DRIFT),
    (
        "handlers/web/mcp_hitl.rs",
        include_str!("../../vauban-web/src/handlers/web/mcp_hitl.rs"),
    ),
    (
        "services/mcp_session.rs",
        include_str!("../../vauban-web/src/services/mcp_session.rs"),
    ),
    (
        "services/mcp_control.rs",
        include_str!("../../vauban-web/src/services/mcp_control.rs"),
    ),
    (
        "services/mcp_recheck.rs",
        include_str!("../../vauban-web/src/services/mcp_recheck.rs"),
    ),
    (
        "ipc/proxy_mcp.rs",
        include_str!("../../vauban-web/src/ipc/proxy_mcp.rs"),
    ),
];

/// Production part of a source file: everything before its test module.
fn prod(src: &str) -> &str {
    let cut = src
        .match_indices("#[cfg(test)]\nmod ")
        .find(|(i, _)| src[*i..].lines().nth(1).is_some_and(|l| l.ends_with('{')))
        .map_or(src.len(), |(i, _)| i);
    &src[..cut]
}

fn body<'a>(src: &'a str, start: &str, end: &str) -> &'a str {
    let from = src.find(start).unwrap_or_else(|| panic!("missing {start}"));
    let to = src[from..].find(end).map_or(src.len(), |n| from + n);
    &src[from..to]
}

#[test]
fn mcp_shared_sources_do_not_interpolate_untrusted_input() {
    for name in ["mcp_policy.rs", "mcp_mandate.rs", "mcp_drift_iam.rs"] {
        let src = match name {
            "mcp_policy.rs" => include_str!("../src/mcp_policy.rs"),
            "mcp_mandate.rs" => include_str!("../src/mcp_mandate.rs"),
            "mcp_drift_iam.rs" => include_str!("../src/mcp_drift_iam.rs"),
            _ => unreachable!(),
        };
        assert!(
            !src.contains("SELECT ") && !src.contains(".replace("),
            "{name} must not build a query or template from external input"
        );
    }
}

/// PDP in `vauban-access`, proxies are PEPs: the Mission Seal engine is
/// driven by access; the proxy asks it per call; web never evaluates a step.
#[test]
fn mission_seal_pdp_lives_in_access() {
    let pdp = prod(ACCESS_PDP);
    assert!(pdp.contains("check_step("), "access must run CheckStep");
    assert!(
        pdp.contains("seal_mandate("),
        "access must seal the mandate"
    );
    let pep = body(
        PROXY_MAIN,
        "async fn pdp_check_via_access(",
        "\n/// HITL / Mission Seal for `tools/call`.",
    );
    assert!(
        pep.contains(".check_step_authorized(&sess.session_id, name, &args_v, now)"),
        "the proxy PEP must ask access per tools/call"
    );
    for (name, src) in WEB_MCP {
        let src = prod(src);
        for engine in ["check_step(", "seal_mandate(", "commit_step_result("] {
            assert!(!src.contains(engine), "web {name} must not run {engine}");
        }
    }
}

/// Rule tool columns hold approved names only, and vauban-access is the
/// authority: every rule write takes the rule-tools lock, validates the
/// names against the approved catalogue, then writes the validated columns;
/// the prune takes the same lock; boot runs a full prune once the virtual
/// group is resolved.
#[test]
fn rule_tool_writes_are_validated_and_pruned_in_access() {
    let handlers = prod(include_str!("../../vauban-access/src/handlers.rs"));
    for (start, end) in [
        (
            "async fn handle_create_access_rule(",
            "\nfn rule_tool_columns(",
        ),
        (
            "async fn handle_update_access_rule(",
            "\nasync fn handle_delete_access_rule(",
        ),
    ] {
        let b = body(handlers, start, end);
        let lock = b
            .find("lock_rule_tools(conn)")
            .unwrap_or_else(|| panic!("{start} must lock"));
        let check = b
            .find("validate_rule_tools(conn, data.asset_group_id, &tool_cols)")
            .unwrap_or_else(|| panic!("{start} must validate"));
        let write = b
            .find("access_rules::mcp_allowed_tools.eq(allow)")
            .unwrap_or_else(|| panic!("{start} must write the validated columns"));
        assert!(
            lock < check && check < write,
            "{start}: lock, validate, then write"
        );
        assert!(
            !b.contains("pg_text_array(&data.mcp_"),
            "{start} must not write unvalidated tool columns"
        );
    }

    let rule_tools = prod(include_str!("../../vauban-access/src/mcp_rule_tools.rs"));
    let prune = body(
        rule_tools,
        "pub async fn prune_mcp_rule_tools(",
        "\npub async fn prune_at_boot(",
    );
    let lock = prune
        .find("lock_rule_tools(conn)")
        .expect("prune must lock");
    let load = prune
        .find("query.load(conn)")
        .expect("prune loads the rules");
    assert!(lock < load, "the prune reads the rules under the lock");
    assert!(prune.contains("prune_rule_tools(cols.clone(), &approved)"));
    assert!(rule_tools.contains("RULE_TOOLS_NOT_APPROVED"));

    let main = include_str!("../../vauban-access/src/main.rs");
    let virt = main
        .find("virtual_group::init_or_die(&pool)")
        .expect("access resolves the virtual group at boot");
    let boot = main
        .find("mcp_rule_tools::prune_at_boot(&pool)")
        .expect("access prunes rule tools at boot");
    assert!(virt < boot, "the boot prune needs the virtual group id");

    let policy = include_str!("../src/mcp_policy.rs");
    assert!(
        policy.contains("pub fn rule_tools_outside")
            && policy.contains("pub fn prune_rule_tools")
            && policy.contains("pub const RULE_TOOLS_NOT_APPROVED"),
        "the approved-only check lives in one shared copy"
    );
}

/// Recording E: the intent line is synced before any upstream byte, and a
/// failed sync refuses the call instead of relaying it.
#[test]
fn recording_intent_is_synced_before_the_relay() {
    let handler = body(
        PROXY_MAIN,
        "async fn handle_mcp(",
        "\nfn appliance_session_ttl_secs",
    );
    let intent = handler
        .find("record_tool_call_intent(")
        .expect("handle_mcp must record the intent");
    let relay = handler
        .find("post_json_on_brokered_fd(")
        .expect("handle_mcp relays on the brokered FD");
    assert!(intent < relay, "intent must be written before the relay");
    let refusal = &handler[intent..relay];
    assert!(
        refusal.contains("tools/call not sent") && refusal.contains("recording_sync_failed"),
        "a failed intent sync must refuse the call"
    );
}

/// Justification is always 10..1000 characters after trim, through one
/// seam for both hop-1 paths (Connect UI and `/api/v1`).
#[test]
fn justification_bounds_have_one_seam() {
    let api = prod(WEB_API_OPEN);
    assert!(api.contains("const JUSTIFICATION_MIN: usize = 10;"));
    assert!(api.contains("const JUSTIFICATION_MAX: usize = 1000;"));
    assert!(api.contains("raw.trim().chars().count()"));
    let connect = prod(WEB_CONNECT);
    assert!(connect.contains("mcp_justification_accepted(&justification)"));
    assert!(
        !connect.contains("justification.len()"),
        "byte length is not character length"
    );
}

/// IAM suspension after a perimeter drift removes group membership; it
/// never deactivates the account (that is the revocation knob).
#[test]
fn drift_suspension_removes_group_membership() {
    let src = prod(WEB_DRIFT);
    let suspend = body(src, "if iam == McpDriftIam::SuspendGroup {", "let mut conn");
    assert!(suspend.contains(".remove_group_member(*gid, session.user_id)"));
    assert!(!suspend.contains("is_active") && !suspend.contains("is_deleted"));
}

/// Revocation is a soft delete (tombstone + purge memberships); users are
/// never hard-deleted.
#[test]
fn drift_revocation_soft_deletes_the_user() {
    let src = prod(WEB_DRIFT);
    let revoke = body(
        src,
        "async fn apply_soft_delete_user(",
        "\nasync fn resolve_drift_iam(",
    );
    assert!(revoke.contains("users::is_deleted.eq(true)"));
    assert!(revoke.contains("diesel::delete(user_groups::table"));
    assert!(revoke.contains("check_last_active_superuser("));
    assert!(!src.contains("diesel::delete(users::table"));
}

/// `access_rules.priority` sorts lists; no MCP decision reads it
/// (Allow = intersection, HITL / plan = union, drift IAM = max severity).
#[test]
fn mcp_decisions_never_read_priority() {
    let deciders = [
        ("vauban-access/src/mcp_pdp.rs", prod(ACCESS_PDP)),
        (
            "shared/src/mcp_policy.rs",
            include_str!("../src/mcp_policy.rs"),
        ),
        (
            "shared/src/mcp_drift_iam.rs",
            include_str!("../src/mcp_drift_iam.rs"),
        ),
        ("vauban-web/src/services/mcp_drift.rs", prod(WEB_DRIFT)),
    ];
    for (name, src) in deciders {
        assert!(
            !src.contains("priority"),
            "{name} must not decide on priority"
        );
    }
    for (name, src) in WEB_MCP {
        assert!(
            !prod(src).contains("access_rules::priority"),
            "web {name} must not read access_rules.priority"
        );
    }
}

/// The lab auto-approve escape stays banned, and the lint that bans it
/// keeps its needle.
#[test]
fn lab_auto_approve_stays_forbidden() {
    assert!(LAB_LINT.contains("'MCP_LAB_AUTO_APPROVE'"));
    assert!(!PROXY_MAIN.contains(concat!("MCP_LAB_", "AUTO_APPROVE")));
    for (name, src) in WEB_MCP {
        assert!(
            !src.contains(concat!("MCP_LAB_", "AUTO_APPROVE")),
            "web {name}"
        );
    }
}

/// The MCP tool whitelist has one author, vauban-access: web asks it over
/// IPC and never recomputes the intersection itself.
#[test]
fn web_never_computes_the_mcp_whitelist() {
    for (name, src) in WEB_MCP {
        assert!(
            !prod(src).contains("effective_callable_tools"),
            "web {name} must ask vauban-access for the whitelist"
        );
    }
    let session = prod(include_str!("../../vauban-web/src/services/mcp_session.rs"));
    assert!(session.contains("compute_mcp_effective_tools"));
    for (name, src) in [
        ("handlers/web/mcp.rs", WEB_CONNECT),
        ("handlers/api/mcp_sessions.rs", WEB_API_OPEN),
    ] {
        assert!(
            prod(src).contains("effective_tools_from_access("),
            "{name} must pre-check tools through vauban-access"
        );
    }
}

/// Recording solution E: an MCP recording replays in the asciinema player
/// from its `session.cast` mirror, never in the RDP video player.
#[test]
fn mcp_recording_plays_in_the_asciinema_player() {
    let play_rs = prod(include_str!(
        "../../vauban-web/src/templates/sessions/recording_play.rs"
    ));
    let uses = body(play_rs, "pub fn uses_asciinema", "\n    }");
    assert!(
        uses.contains("is_mcp()") && uses.contains("is_ssh()"),
        "uses_asciinema must cover SSH and MCP"
    );
    assert!(body(play_rs, "pub fn is_mcp", "\n    }").contains("\"mcp\""));

    let play_html = include_str!("../../vauban-web/templates/sessions/recording_play.html");
    let player = body(play_html, "<!-- Player Container -->", "<video");
    assert!(
        player.contains("{% if recording.uses_asciinema() %}"),
        "the player branch must be chosen by uses_asciinema(), before any <video>"
    );
    assert!(player.contains("/session.cast"));

    let sessions = include_str!("../../vauban-web/src/handlers/web/sessions.rs");
    let serve = body(sessions, "pub async fn serve_ssh_recording", "\n}\n");
    assert!(serve.contains("session.cast"));
    assert!(
        !serve.contains("session_type"),
        "the cast route must serve MCP casts too (no SSH-only filter)"
    );
}
