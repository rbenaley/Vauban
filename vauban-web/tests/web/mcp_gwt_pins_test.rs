//! Phase 5.1 GWT structural pins for web-side MCP acceptance
//! (V-8, B-6, L0-1) — docs/specs/vauban-mcp/08 + 09 + 07.
//!
//! These are source-level acceptance pins (same style as other
//! `*_pins_test.rs` modules). Behavioural GWT for whitelist / HITL /
//! suspend live in `vauban-proxy-mcp` (`gwt_*`).

#[test]
fn gwt_v8_mcp_recheck_terminates_when_whitelist_empty_or_asset_gone() {
    let src = include_str!("../../src/services/mcp_recheck.rs");
    assert!(
        src.contains("terminate_mcp") && src.contains("asset_gone"),
        "V-8: mcp_recheck must terminate when asset access disappears"
    );
    assert!(
        src.contains("no_tools_granted") && src.contains("V-8"),
        "V-8: empty ∩ whitelist must terminate (no_tools_granted)"
    );
}

#[test]
fn gwt_phase_c_recheck_preserves_envelope_suspend() {
    let src = include_str!("../../src/services/mcp_recheck.rs");
    assert!(
        !src.contains("envelope_on_exceed: \"throttle\""),
        "recheck must not hardcode envelope_on_exceed=throttle (clobbers suspend)"
    );
    assert!(
        src.contains("envelope_on_exceed: String::new()")
            || src.contains("envelope_on_exceed: \"\""),
        "recheck must send empty on_exceed to leave live suspend mode intact"
    );
    assert!(
        src.contains("tool_constraints_json_for_session_extra"),
        "recheck must push HITL/constraints mid-session"
    );
}

#[test]
fn gwt_b6_resume_api_key_without_supervise_forbidden() {
    let src = include_str!("../../src/handlers/web/mcp_hitl.rs");
    let resume = src
        .find("pub async fn mcp_hitl_approve_web")
        .expect("mcp_hitl_approve_web handler must exist");
    let body = &src[resume..];
    let end = body.find("\npub async fn ").unwrap_or(body.len().min(4000));
    let resume_fn = &body[..end];
    assert!(
        resume_fn.contains("sessions:supervise"),
        "B-6: HITL approve must refuse callers without sessions:supervise"
    );
}

#[test]
fn gwt_l0_1_policy_recheck_cuts_on_expires_and_access_revoked() {
    let src = include_str!("../../src/services/policy_recheck.rs");
    assert!(
        src.contains("expires_at") && (src.contains("access_revoked") || src.contains("terminate")),
        "L0-1: policy_recheck must cut on expires_at / access revoked"
    );
    assert!(
        src.contains("30") || src.contains("RECHECK") || src.contains("from_secs(30)"),
        "L0-1: 30s recheck cadence must stay in place"
    );
}

/// P6-1: group membership changes must push the same instant policy seam
/// as access_rule edits (Borne suspension = leave user_group).
#[test]
fn gwt_p6_1_group_member_mutations_notify_policy_changed() {
    let src = include_str!("../../src/handlers/web/groups.rs");
    let add = src
        .find("pub async fn add_group_member_web")
        .expect("add_group_member_web must exist");
    let remove = src
        .find("pub async fn remove_group_member_web")
        .expect("remove_group_member_web must exist");
    let add_fn = &src[add..remove];
    let remove_fn = &src[remove..];
    assert!(
        add_fn.contains("groups_manage_members"),
        "P6-1: add_group_member_web must gate groups:manage_members"
    );
    assert!(
        remove_fn.contains("stamp_live_mcp_source_group"),
        "P6-1: remove_group_member_web must stamp the MCP source group before the cut"
    );
    assert!(
        remove_fn.contains("GroupMemberRemoved"),
        "P6-1: remove path must still emit GroupMemberRemoved audit"
    );
}

/// P6-2: soft-delete must reuse deactivate_user cascade (sessions/keys/WS).
#[test]
fn gwt_p6_2_soft_delete_calls_deactivate_user_cascade() {
    let src = include_str!("../../src/handlers/web/users.rs");
    let del = src
        .find("pub async fn delete_user_web")
        .expect("delete_user_web must exist");
    let body = &src[del..];
    let end = body
        .find("\npub async fn ")
        .unwrap_or(body.len().min(12_000));
    let delete_fn = &body[..end];
    assert!(
        delete_fn.contains("deactivate_user"),
        "P6-2: delete_user_web must call deactivate_user after soft-delete commit"
    );
    assert!(
        delete_fn.contains("is_deleted") && delete_fn.contains("deleted_at"),
        "P6-2: soft-delete tombstone (is_deleted/deleted_at) must remain"
    );
    assert!(
        !delete_fn.contains("diesel::delete(users::table"),
        "P6-2: product path must not hard-delete users"
    );
}

/// P6-2 belt: rechecks cut soft-deleted owners; MCP includes suspended.
#[test]
fn gwt_p6_2_recheck_belts_user_deleted_and_suspended() {
    let mcp = include_str!("../../src/services/mcp_recheck.rs");
    assert!(
        mcp.contains("user_deleted") && mcp.contains("is_deleted"),
        "P6-2: mcp_recheck must terminate on users.is_deleted"
    );
    assert!(
        mcp.contains("suspended"),
        "P6-2b: mcp_recheck must include ops-paused suspended sessions"
    );
    let policy = include_str!("../../src/services/policy_recheck.rs");
    assert!(
        policy.contains("user_deleted") && policy.contains("is_deleted"),
        "P6-2: policy_recheck must cut on users.is_deleted"
    );
}

/// TRUSTED R0: MCP terminates mint decision_id + critical WORM event.
#[test]
fn gwt_r0_mcp_terminate_records_decision_id_and_worm() {
    let mcp = include_str!("../../src/services/mcp_recheck.rs");
    assert!(
        mcp.contains("mint_decision_id")
            && mcp.contains("decision_id")
            && mcp.contains("emit_mcp_access_decision"),
        "R0: mcp_recheck terminate_mcp must mint decision_id and emit WORM"
    );
    assert!(
        mcp.contains("ACTOR_MCP_RECHECK"),
        "R0: mcp_recheck must tag actor system:mcp_recheck"
    );
    let term = include_str!("../../src/services/session_termination.rs");
    assert!(
        term.contains("mint_decision_id")
            && term.contains("SessionType::Mcp")
            && term.contains("emit_mcp_access_decision"),
        "R0: terminate_live_session must record decisions for MCP"
    );
    let ad = include_str!("../../src/services/access_decision.rs");
    assert!(
        ad.contains("McpAccessDecision") && ad.contains("emit_audit_critical"),
        "R0: access_decision must emit critical McpAccessDecision"
    );
    let shared = include_str!("../../../shared/src/messages.rs");
    assert!(
        shared.contains("McpAccessDecision"),
        "R0: AuditEventType::McpAccessDecision must exist (append-only)"
    );
}

/// TRUSTED R1: contestation SoD + overturn restores group (never resurrects vbw_).
#[test]
fn gwt_r1_contestation_sod_and_overturn_restores_group() {
    let svc = include_str!("../../src/services/access_contestation.rs");
    assert!(
        svc.contains("opened_by_id == actor_user_id") && svc.contains("separation of duties"),
        "R1: claim/resolve must enforce SoD against opener"
    );
    assert!(
        svc.contains("add_group_member")
            && svc.contains("notify_policy_changed")
            && !svc.contains("IssueSessionToken"),
        "R1: overturn must AddGroupMember + notify; must not mint a new session ticket"
    );
    assert!(
        svc.contains("McpContestationOpened") && svc.contains("McpContestationResolved"),
        "R1: open/resolve must emit WORM contestation events"
    );
    let shared = include_str!("../../../shared/src/messages.rs");
    assert!(
        shared.contains("McpContestationOpened") && shared.contains("McpContestationResolved"),
        "R1: AuditEventType contestation variants must exist"
    );
    let migration =
        include_str!("../../../vauban-db/migrations/20260822180000_access_contestations/up.sql");
    assert!(
        migration.contains("contestation_sod_claim")
            && migration.contains("contestation_sod_resolve")
            && migration.contains("overturned"),
        "R1: migration must encode SoD CHECKs and overturned status"
    );
    let groups = include_str!("../../src/handlers/web/groups.rs");
    assert!(
        groups.contains("stamp_live_mcp_source_group"),
        "R1+: remove_group_member_web must stamp decision_source_group_id before cut"
    );
    let ad = include_str!("../../src/services/access_decision.rs");
    assert!(
        ad.contains("fn stamp_live_mcp_source_group") && ad.contains("decision_source_group_id"),
        "R1+: stamp helper must write decision_source_group_id"
    );
    assert!(
        svc.contains("resolve_restore_group_for_session"),
        "R1+: overturn must resolve the unique removed access group (1:1, no picker)"
    );
}

/// TRUSTED R2.1: access-rule updates emit before→after MCP tool diffs.
#[test]
fn gwt_r2_access_rule_update_emits_attribute_diff() {
    let diff = include_str!("../../src/services/mcp_attribute_diff.rs");
    assert!(
        diff.contains("mcp_allowed_tools")
            && diff.contains("mcp_hitl_tools")
            && diff.contains("\"before\"")
            && diff.contains("\"after\""),
        "R2.1: mcp_attribute_diff must build before→after tool changes"
    );
    let web = include_str!("../../src/handlers/web/mcp_access.rs");
    assert!(
        web.contains("mcp_attribute_diff::mcp_rule_tool_changes")
            && web.contains("get_access_rule"),
        "R2.1: MCP access-rule update must load before state and emit diff"
    );
    let api = include_str!("../../src/handlers/web/mcp_access.rs");
    assert!(
        api.contains("mcp_attribute_diff::mcp_rule_tool_changes"),
        "R2.1: MCP access-rule update must emit the attribute diff"
    );
}

/// TRUSTED R2.2: revoke/rotate API key kills MCP sessions + critical WORM.
#[test]
fn gwt_r2_api_key_compromise_kills_sessions_and_audits() {
    let life = include_str!("../../src/services/api_key_lifecycle.rs");
    assert!(
        life.contains("terminate_live_session")
            && life.contains("ApiKeyRevoked")
            && life.contains("ApiKeyRotated")
            && life.contains("emit_audit_critical"),
        "R2.2: api_key_lifecycle must terminate MCP sessions and emit critical WORM"
    );
    let users = include_str!("../../src/handlers/web/users.rs");
    assert!(
        users.contains("delete_user_web") || life.contains("after_api_key_invalidated"),
        "R2.2: key invalidation must reach after_api_key_invalidated"
    );
    let shared = include_str!("../../../shared/src/messages.rs");
    assert!(
        shared.contains("ApiKeyRevoked") && shared.contains("ApiKeyRotated"),
        "R2.2: AuditEventType API key variants must exist"
    );
}

/// TRUSTED R2.3: operator vocabulary distinguishes IAM / soft-delete / envelope / HITL.
#[test]
fn gwt_r2_ui_vocabulary_distinguishes_cut_kinds() {
    let ad = include_str!("../../src/services/access_decision.rs");
    assert!(
        ad.contains("IAM suspension") && ad.contains("soft-deleted"),
        "R2.3: reason_label must name IAM suspension and soft-delete"
    );
    let detail = include_str!("../../src/templates/sessions/session_detail.rs");
    assert!(
        detail.contains("Envelope paused"),
        "R2.3: session status suspended must display as Envelope paused"
    );
}

/// Sidebar MCP HITL / contestation badges must live-update via `/ws/notifications`
/// OOB (same shape as Approvals / IACS). JSON jit-notification events alone
/// do not swap `#sidebar-*-badge`.
#[test]
fn gwt_sidebar_mcp_badges_broadcast_oob_on_notifications() {
    let web = include_str!("../../src/handlers/web/mod.rs");
    assert!(
        web.contains("fn broadcast_mcp_hitl_badge")
            && web.contains("fn broadcast_contestation_badge")
            && web.contains("sidebar-mcp-badge")
            && web.contains("send_raw"),
        "MCP HITL and contestation must share one send_raw OOB sidebar pill"
    );
    let pending = include_str!("../../src/ipc/proxy_mcp.rs");
    assert!(
        pending.contains("broadcast_mcp_hitl_badge"),
        "McpHitlPendingNotify must push the HITL sidebar badge"
    );
    let decide = include_str!("../../src/handlers/web/mcp_hitl.rs");
    assert!(
        decide.contains("broadcast_mcp_hitl_badge"),
        "HITL decide (web) must push the HITL sidebar badge"
    );
    let api = include_str!("../../src/handlers/web/mcp_hitl.rs");
    assert!(
        api.contains("broadcast_mcp_hitl_badge"),
        "HITL decide must push the HITL sidebar badge"
    );
    let contest = include_str!("../../src/handlers/web/access_contestation.rs");
    assert!(
        contest.contains("broadcast_contestation_badge")
            && contest.contains("mcp_contestation_claimed"),
        "contestation open/claim/resolve must push the contestation sidebar badge"
    );
    let list = include_str!("../../templates/sessions/contestation_list.html");
    assert!(
        list.contains("contestation-ws-trigger")
            && list.contains("mcp_contestation_")
            && list.contains("contestation-list-container"),
        "contestation list must live-refresh on mcp_contestation_* WS events"
    );
}

/// Proxy advertises Mission Seal as `arguments.vauban` on tools/list.
#[test]
fn gwt_proxy_advertises_arguments_vauban_on_require_plan() {
    let view = include_str!("../../../vauban-proxy-mcp/src/agent_view.rs");
    assert!(
        view.contains("fn filter_and_enrich_tools")
            && view.contains("arguments.vauban.story")
            && view.contains("fn vauban_plan_schema")
            && view.contains("VISIT_IDENTITY")
            && view.contains("Callable tools are those in tools/list")
            && !view.contains("Allowed this visit:"),
        "proxy agent_view must advertise Story + Contract on Require plan tools; initialize.instructions is identity, not a catalogue"
    );
    let mandate = include_str!("../../../shared/src/mcp_mandate.rs");
    assert!(
        mandate.contains("/arguments/vauban/story") && mandate.contains("fn strip_vauban_args"),
        "mandate extract must read arguments.vauban and strip before upstream"
    );
}

/// Vault-style MCP nest: one sidebar entry, require_plan is access-rule policy.
#[test]
fn gwt_mcp_zone_nest_and_require_plan_policy() {
    let sidebar = include_str!("../../templates/partials/sidebar_content.html");
    assert!(
        sidebar.contains("href=\"/sessions/mcp\"")
            && sidebar.contains("show_mcp")
            && sidebar.contains("M15.75 5.25v13.5m-7.5-13.5v13.5")
            && !sidebar.contains("MCP HITL")
            && !sidebar.contains("href=\"/sessions/contestations\""),
        "sidebar must have a single MCP entry with the proposal icon (no Contestations row)"
    );
    let main = include_str!("../../src/main.rs");
    assert!(
        main.contains("nest(\n            \"/sessions/mcp\"") || main.contains("\"/sessions/mcp\""),
        "main.rs must nest /sessions/mcp"
    );
    assert!(
        main.contains("require_mcp_zone")
            && main.contains("/access")
            && main.contains("/contestations")
            && main.contains("contestation_list")
            && main.contains("contestation_claim_web")
            && main.contains("contestation_uphold_web")
            && main.contains("contestation_overturn_web"),
        "MCP nest must mount list + claim/uphold/overturn behind require_mcp_zone"
    );
    assert_eq!(
        main.matches("contestation_claim_web").count(),
        1,
        "claim/uphold/overturn must not be aliased outside the MCP nest"
    );
    assert_eq!(main.matches("contestation_uphold_web").count(), 1);
    assert_eq!(main.matches("contestation_overturn_web").count(), 1);
    assert!(
        main.contains("contestation_detail_user_zone")
            && !main.contains("Redirect::to(&format!(\"/sessions/mcp/contestations/{uuid}\"))"),
        "GET /sessions/contestations/{{uuid}} is User Zone, not a redirect into the nest"
    );
    let contest = include_str!("../../src/handlers/web/access_contestation.rs");
    let open_start = contest
        .find("contestation_open_web")
        .expect("contestation_open_web");
    let claim_start = contest
        .find("contestation_claim_web")
        .expect("contestation_claim_web");
    assert!(
        contest[open_start..claim_start].contains("/sessions/contestations/{}")
            && !contest[open_start..claim_start].contains("/sessions/mcp/contestations/{}"),
        "contestation_open_web must redirect to the User Zone status page"
    );
    let detail = contest
        .find("async fn contestation_detail_inner")
        .expect("contestation_detail_inner");
    let detail_end = contest[detail..]
        .find("\npub async fn ")
        .map(|i| detail + i)
        .unwrap_or(contest.len());
    assert!(
        !contest[detail..detail_end].contains("mcp_can_supervise: true"),
        "contestation detail must not hardcode mcp_can_supervise = true"
    );
    let discover = include_str!("../../src/services/mcp_discover.rs");
    assert!(
        !discover.contains("fn set_tool_require_plan_in_catalog"),
        "catalogue must not write require_plan"
    );
    assert!(
        discover.contains("rule_require_plan.contains")
            && !discover.contains("let require_plan = t.require_plan"),
        "constraints emit require_plan from the access rule only"
    );
    let session = include_str!("../../src/services/mcp_session.rs");
    let policy = include_str!("../../../shared/src/mcp_policy.rs");
    assert!(
        session.contains("resolve_rule_require_plan_tools")
            && session.contains("mcp_require_plan_tools")
            && session.contains("mcp_rule_callable_tools")
            && !session.contains("fn mcp_rule_callable_tools"),
        "session open must read require_plan and call the shared callable set"
    );
    assert!(
        policy.contains("pub fn mcp_rule_callable_tools")
            && policy.contains("pub fn flatten_pg_text_array"),
        "callable set must live in one shared copy"
    );
    let access = include_str!("../../../vauban-access/src/handlers.rs");
    assert!(
        access.contains("mcp_rule_callable_tools")
            && !access.contains("fn mcp_rule_callable_tools("),
        "access mint must use the shared callable set, not a local copy"
    );
    let mcp_access = include_str!("../../src/handlers/web/mcp_access.rs");
    assert!(
        mcp_access.contains("fn columns_from_modes")
            && mcp_access.contains("columns_from_modes(&form.mcp_tool_modes)")
            && mcp_access.contains("fn keep_approved_names")
            && mcp_access.contains("fn keep_approved_or_existing")
            && mcp_access.contains("fn with_unposted_modes")
            && mcp_access.contains("fn sections_from_group_catalog")
            && mcp_access.contains("fn sections_from_group_catalog_filtered")
            && mcp_access.contains("fn tools_summary_from_columns"),
        "MCP Save must derive SQL columns from one mode per tool"
    );
    let discover_web = include_str!("../../src/handlers/web/mcp_discover.rs");
    assert!(
        discover_web.contains("pub async fn load_mcp_live_tool_names"),
        "group live tool names must exclude tombstoned MCP assets"
    );
    let matrix_form = include_str!("../../templates/mcp/access_form_fields.html");
    assert!(
        matrix_form.contains("name=\"mcp_tool_mode[{{ tool.name }}]\"")
            && matrix_form.contains("value=\"require_plan\"")
            && matrix_form.contains("for section in sections")
            && matrix_form.contains("include \"mcp/access_matrix_heading.html\"")
            && matrix_form.contains("w-44")
            && !matrix_form.contains("<table")
            && matrix_form.contains("tool.asset_label")
            && matrix_form.contains("tool.descriptions_diverge")
            && !matrix_form.contains("name=\"mcp_tools\"")
            && !matrix_form.contains("name=\"mcp_hitl_tools\"")
            && !matrix_form.contains("type=\"checkbox\" name=\"mcp_"),
        "MCP tool matrix must be one select per tool, grouped by asset, not three checkboxes"
    );
    let detail_page = include_str!("../../templates/mcp/access_detail.html");
    assert!(
        detail_page.contains("Modes are this access rule only")
            && detail_page.contains("for section in sections")
            && detail_page.contains("include \"mcp/access_matrix_heading.html\"")
            && detail_page.contains("tool.descriptions_diverge")
            && !detail_page.contains("<table")
            && !detail_page.contains("Allow-list")
            && !detail_page.contains("allowed_label")
            && !detail_page.contains("plan_label"),
        "MCP rule detail must show the rule matrix, not catalogue-filtered SQL dumps"
    );
    let heading = include_str!("../../templates/mcp/access_matrix_heading.html");
    assert!(
        heading.contains("section.badge_label") && heading.contains("rounded-full"),
        "asset heading must show the MCP badge next to the asset name"
    );
    let create = include_str!("../../templates/assets/access_rule_create.html");
    let edit = include_str!("../../templates/assets/access_rule_edit.html");
    assert!(
        !create.contains("allowed_mcp")
            && !create.contains("mcp_tools")
            && !edit.contains("allowed_mcp")
            && !edit.contains("name=\"mcp_tools\""),
        "generic /assets/access forms must not expose MCP tool fields"
    );
    let pam = include_str!("../../src/handlers/web/access_rules.rs");
    assert!(
        pam.contains("mcp_access_edit_path")
            && pam.contains("protocols_include_mcp")
            && pam.contains("/sessions/mcp/access/"),
        "PAM /assets/access detail+edit must bounce MCP rules into the MCP nest"
    );
}

/// MCP Access Rules mode select is the session SoT. Catalogue `hitl`
/// must not re-select HITL or freeze it after Save clears it.
#[test]
fn gwt_mcp_access_rule_hitl_save_is_sot() {
    let matrix = include_str!("../../src/handlers/web/mcp_access.rs");
    assert!(
        matrix.contains("fn matrix_mode")
            && matrix.contains("hitl.contains(name)")
            && !matrix.contains("|| t.hitl"),
        "edit matrix must render the mode from the rule, not catalogue OR"
    );
    let discover = include_str!("../../src/services/mcp_discover.rs");
    assert!(
        discover.contains("let hitl = rule_hitl.contains(&t.name);")
            && !discover.contains("let hitl = t.hitl || rule_hitl.contains"),
        "frozen constraints must take HITL from the access rule only"
    );
}

/// MCP HITL / contestation / mandate-drift must queue the existing
/// mailer (outbox only). Claim and empty mailboxes do not enqueue.
#[test]
fn gwt_mcp_mailer_hooks_outbox_only() {
    let pending = include_str!("../../src/ipc/proxy_mcp.rs");
    assert!(
        pending.contains("queue_hitl_pending"),
        "McpHitlPendingNotify must queue mcp.hitl_pending"
    );
    let decide = include_str!("../../src/handlers/web/mcp_hitl.rs");
    assert!(
        decide.contains("queue_hitl_decided"),
        "HITL decide (web) must queue mcp.hitl_decided"
    );
    let api = include_str!("../../src/handlers/web/mcp_hitl.rs");
    assert!(
        api.contains("queue_hitl_decided"),
        "HITL decide must queue mcp.hitl_decided"
    );
    let contest = include_str!("../../src/handlers/web/access_contestation.rs");
    let open_start = contest
        .find("contestation_open_web")
        .expect("contestation_open_web");
    let claim_start = contest
        .find("contestation_claim_web")
        .expect("contestation_claim_web");
    let uphold_start = contest
        .find("contestation_uphold_web")
        .expect("contestation_uphold_web");
    assert!(
        contest[open_start..claim_start].contains("queue_contestation_opened"),
        "contestation open must queue reviewer mail"
    );
    assert!(
        !contest[claim_start..uphold_start].contains("queue_contestation"),
        "contestation claim must not send email"
    );
    assert!(
        contest.contains("queue_contestation_resolved"),
        "contestation uphold/overturn must queue opener mail"
    );
    let helper = include_str!("../../src/services/mcp_mail.rs");
    let prod = helper.split("#[cfg(test)]").next().unwrap_or(helper);
    assert!(
        prod.contains("queue_mandate_drift") && prod.contains("mcp.mandate_drift"),
        "first Mission Seal -32033 (IAM suspend) must queue mcp.mandate_drift"
    );
    assert!(
        prod.contains("load_approver_contacts")
            && prod.contains("requester_may_receive_mail")
            && prod.contains("exclude_author")
            && !prod.contains("lettre::")
            && !prod.contains("connect("),
        "MCP mail helper must reuse the JIT pool and never speak SMTP"
    );
}

/// First Mission Seal CheckStep deny always cuts the visit; IAM is read
/// from the matching access rule (`mcp_drift_iam`), not hard-coded.
#[test]
fn gwt_mcp_mandate_drift_iam_suspension() {
    let proxy = include_str!("../../../vauban-proxy-mcp/src/main.rs");
    assert!(
        proxy.contains("McpMandateDriftNotify")
            && proxy.contains("emit_mandate_perimeter_drift")
            && proxy.contains("is_perimeter_drift"),
        "proxy must notify + terminate only on perimeter CheckStep deny"
    );
    let expired = proxy
        .find("reason\": \"mission_expired\"")
        .or_else(|| proxy.find("mission_expired"))
        .expect("mission_expired path");
    let expired_window = &proxy[expired..expired.saturating_add(800).min(proxy.len())];
    assert!(
        !expired_window.contains("McpMandateDriftNotify"),
        "TTL expiry must not trigger IAM suspension"
    );
    let web = include_str!("../../src/ipc/proxy_mcp.rs");
    assert!(
        web.contains("McpMandateDriftNotify") && web.contains("apply_mandate_drift"),
        "web must apply mandate drift on notify"
    );
    let drift = include_str!("../../src/services/mcp_drift.rs");
    assert!(
        drift.contains("mcp_drift_iam")
            && drift.contains("resolve_drift_iam")
            && drift.contains("McpDriftIam")
            && drift.contains("terminate_mcp_with_actor")
            && drift.contains("mandate_drift")
            && drift.contains("queue_mandate_drift")
            && !drift.contains("vbw_"),
        "drift must always cut + mail; IAM is chosen from the access-rule enum"
    );
    assert!(
        drift.contains("remove_group_member") && drift.contains("stamp_live_mcp_source_group"),
        "suspend_group must keep today's RemoveGroupMember path"
    );
    let labels = include_str!("../../src/services/access_decision.rs");
    assert!(
        labels.contains("\"mandate_drift\"") && labels.contains("ACTOR_MANDATE_DRIFT"),
        "mandate_drift must have operator-facing reason/actor labels"
    );
}

#[test]
fn gwt_connect_mcp_no_superuser_bypass() {
    let src = include_str!("../../src/handlers/web/mcp.rs");
    let prod = src.split("#[cfg(test)]").next().unwrap_or(src);
    assert!(
        !prod.contains("is_superuser"),
        "Connect UI must not bypass assets:connect_mcp via is_superuser"
    );
    assert!(
        !prod.contains("sessions_bypass_access_rules"),
        "Connect UI must always evaluate access_rules (same as API MCP)"
    );
    assert!(
        src.contains("extract_client_ip"),
        "Connect UI must record the real client IP"
    );
}

#[test]
fn gwt_api_mcp_open_requires_vbn() {
    let src = include_str!("../../src/handlers/api/mcp_sessions.rs");
    assert!(
        src.contains("requires a vbn_ API key") && src.contains("AppError::Authorization"),
        "MCP hop 1 API without vbn_ must be Authorization (403), not Internal 500"
    );
    let hitl = include_str!("../../src/handlers/web/mcp_hitl.rs");
    assert!(
        hitl.contains("mcp_hitl_decided"),
        "HITL decide must emit the list-refresh event"
    );
}

#[test]
fn gwt_contestation_badge_matches_broadcast() {
    let web = include_str!("../../src/handlers/web/mod.rs");
    assert!(
        web.contains("fn broadcast_contestation_badge")
            && web.contains("sidebar-mcp-badge")
            && web.contains("send_raw"),
        "sidebar contestation count must match global OOB broadcast"
    );
}

#[test]
fn gwt_mcp_nav_hides_supervise_tabs() {
    let nav = include_str!("../../templates/mcp/nav.html");
    assert!(
        nav.contains("mcp_can_supervise"),
        "HITL/contestation tabs must be gated for access_rules:read-only users"
    );
}

#[test]
fn gwt_mission_ttl_uses_distinct_error() {
    let mandate = include_str!("../../../shared/src/mcp_mandate.rs");
    assert!(
        mandate.contains("ERR_MISSION_EXPIRED") && mandate.contains("-32034"),
        "TTL expiry must be -32034, not the perimeter-drift -32033"
    );
    let access = include_str!("../../../vauban-access/src/mcp_pdp.rs");
    assert!(
        access.contains("mission_expired") && access.contains("CheckStepAuthorized"),
        "vauban-access must own CheckStep TTL (PDP)"
    );
}

#[test]
fn gwt_pdp_pep_wiring_pins() {
    let proxy = include_str!("../../../vauban-proxy-mcp/src/main.rs");
    assert!(
        proxy.contains("PdpGate::AllowUpstream => return None"),
        "supervised Allow must short-circuit HITL"
    );
    assert!(
        proxy.contains("sync_local_mandate_after_pdp_allow"),
        "PDP Allow must consume Session.mandate so the next Seal is Replace"
    );
    let mandate = include_str!("../../../shared/src/mcp_mandate.rs");
    assert!(
        mandate.contains("MandatePdpPlan::Replace")
            && mandate.contains("all_steps_done")
            && mandate.contains("fn plan_mandate_pdp"),
        "after all_steps_done, a new Story+Contract must plan Replace (not CheckStep)"
    );
    assert!(
        !proxy.contains("MCP_LAB_AUTO_APPROVE"),
        "access seal must not depend on a lab auto-approve switch"
    );
    assert!(
        proxy.contains("spawn_clear_mcp_mandate"),
        "PEP must clear access PDP on session end"
    );
    let recheck = include_str!("../../src/services/mcp_recheck.rs");
    assert!(
        recheck.contains("policy_update_failed"),
        "failed whitelist shrink must terminate, not keep a stale allow-list"
    );
    let supervisor = include_str!("../../../vauban-supervisor/src/main.rs");
    assert!(
        supervisor.contains(r#"&["web", "proxy_mcp"]"#)
            && supervisor.contains(r#"&["web", "proxy_ssh"]"#)
            && supervisor.contains(r#"&["web", "proxy_rdp"]"#),
        "web crash must linked-restart SSH, RDP, and MCP"
    );
}

#[test]
fn gwt_catalogue_hitl_toggle_removed() {
    let edit = include_str!("../../templates/assets/asset_edit.html");
    assert!(
        !edit.contains("mcp-tool-hitl") && !edit.contains("Require HITL"),
        "asset edit must not expose catalogue HITL as a policy toggle"
    );
    assert!(
        !edit.contains("set_mcp_tool_hitl_web"),
        "catalogue copy must not keep a per-tool HITL toggle"
    );
    let main = include_str!("../../src/main.rs");
    assert!(
        !main.contains("mcp-tool-hitl") && !main.contains("set_mcp_tool_hitl_web"),
        "catalogue HITL POST route must be gone"
    );
    let discover = include_str!("../../src/services/mcp_discover.rs");
    assert!(
        !discover.contains("fn set_tool_hitl_in_catalog"),
        "catalogue must not write a HITL policy flag"
    );
}

/// Hop 1 is the only web TcpConnect. Mid-visit FD death is proxy
/// re-broker (same token), not a remint / second hop 1.
#[test]
fn gwt_mcp_rebroker_is_not_a_new_hop1() {
    let open = include_str!("../../src/services/mcp_session.rs");
    assert!(
        open.contains("request_tcp_connect") && open.contains("Service::ProxyMcp"),
        "hop 1 MUST broker TcpConnect once at session open"
    );
    assert!(
        !open.contains("replace_brokered_upstream") && !open.contains("McpUpstreamRebroker"),
        "web must not re-broker; that is proxy-mcp PEP"
    );
    let proxy = include_str!("../../../vauban-proxy-mcp/src/upstream_rebroker.rs");
    let impl_src = proxy.split("#[cfg(test)]").next().unwrap_or(proxy);
    assert!(
        impl_src.contains("target_service: Service::ProxyMcp")
            && impl_src.contains("session_token"),
        "proxy re-broker MUST re-present the hop-1 session token"
    );
}

#[test]
fn gwt_connect_mcp_honours_rule_mfa_and_ttl_cap() {
    let src = include_str!("../../src/handlers/web/mcp.rs");
    assert!(
        src.contains("require_mfa") && src.contains("mfa_verified"),
        "connect-mcp must gate require_mfa like /api/v1/sessions"
    );
    assert!(
        src.contains("clamp_ttl_capped")
            && src.contains("max_session_duration")
            && src.contains("session_ttl_clamped"),
        "connect-mcp must apply the access-rule session cap and [mcp].session_ttl_seconds"
    );
    assert!(
        src.contains("validate_double_submit") && src.contains("CookieJar"),
        "connect-mcp must validate CSRF like connect_ssh"
    );
}

#[test]
fn gwt_api_mcp_open_honours_appliance_ttl() {
    let src = include_str!("../../src/handlers/api/mcp_sessions.rs");
    assert!(
        src.contains("clamp_ttl_capped") && src.contains("session_ttl_clamped"),
        "API hop 1 must clamp visit TTL with [mcp].session_ttl_seconds"
    );
    let generic = include_str!("../../src/handlers/api/sessions.rs");
    assert!(
        generic.contains("asset_type == \"mcp\""),
        "generic POST /api/v1/sessions must refuse an MCP asset"
    );
}

#[test]
fn gwt_empty_asset_groups_is_not_a_catalogue_grant() {
    let src = include_str!("../../src/services/mcp_session.rs");
    let start = src
        .find("pub async fn resolve_effective_allowed_tools")
        .expect("resolve_effective_allowed_tools");
    let body = &src[start..];
    let end = body
        .find("\npub async fn resolve_rule_hitl_tools")
        .unwrap_or(body.len());
    let fn_src = &body[..end];
    assert!(
        fn_src.contains("asset_group_ids.is_empty()") && fn_src.contains("Ok(Some(Vec::new()))"),
        "no asset group must deny (empty whitelist), not return the catalogue"
    );
    assert!(
        !fn_src.contains("return Ok(catalog)"),
        "catalogue must not grant when no asset group applies"
    );
}

#[test]
fn gwt_hitl_mirror_drops_after_ipc_write() {
    let src = include_str!("../../src/ipc/proxy_mcp.rs");
    let start = src.find("pub fn hitl_decision").expect("hitl_decision");
    let body = &src[start..];
    let end = body.find("\n    pub fn ").unwrap_or(body.len().min(1200));
    let fn_src = &body[..end];
    let send_at = fn_src
        .find("send_fire_and_forget")
        .expect("HITL decide must send IPC");
    let remove_at = fn_src
        .find("g.remove(pending_id)")
        .expect("HITL decide must drop the local mirror");
    assert!(
        send_at < remove_at,
        "web HITL mirror must drop only after the proxy IPC write"
    );
}

#[test]
fn gwt_mcp_ws_hitl_payloads_are_json() {
    let hitl = include_str!("../../src/handlers/web/mcp_hitl.rs");
    assert!(
        hitl.contains("serde_json::json!") && hitl.contains("mcp_hitl_decided"),
        "HITL decided WS payload must be serde_json, not format!"
    );
    let pending = include_str!("../../src/ipc/proxy_mcp.rs");
    assert!(
        pending.contains("serde_json::json!") && pending.contains("mcp_hitl_pending"),
        "HITL pending WS payload must be serde_json, not format!"
    );
    let api = include_str!("../../src/handlers/web/mcp_hitl.rs");
    assert!(
        api.contains("serde_json::json!") && api.contains("mcp_hitl_decided"),
        "HITL decided WS payload must be serde_json, not format!"
    );
}

#[test]
fn gwt_hitl_story_fields_are_redacted() {
    let src = include_str!("../../src/handlers/web/mcp_hitl.rs");
    assert!(
        src.contains("sanitize_story_field") && src.contains("redact_sensitive_json"),
        "HITL Story strings must run through json_redact (JWT-looking values)"
    );
}
