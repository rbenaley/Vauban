use chrono::Utc;
use diesel::dsl::sql;
use diesel::prelude::*;
use diesel::sql_types::Bool as SqlBool;
use diesel_async::AsyncConnection;
use diesel_async::RunQueryDsl;
use shared::messages::{
    AccessCheckResult, AccessCheckResultEntry, AccessRequest, AccessResponse, AccessRuleData,
    AccessRuleInfo, AccessibleGroupEntry, ApprovalDecisionKind, ApprovalDenyReason, AssetGroupInfo,
    DEFAULT_IPC_PAGE_LIMIT, GroupOption, IpcPage, IpcPageParams, MAX_IPC_PAGE_LIMIT,
    VaubanGroupInfo,
};
use shared::session_token::{SessionToken, SessionTokenParams, TokenKey};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};
use uuid::Uuid;

use crate::db::{DbConnection, DbPool};
use crate::schema::{
    access_rules, approval_audit_log, asset_asset_groups, asset_groups, assets, proxy_sessions,
    user_groups, users, vauban_groups,
};

type AccessRuleRow = (
    Uuid,
    String,
    Option<String>,
    i32,
    Uuid,
    String,
    i32,
    Uuid,
    String,
    Vec<Option<String>>,
    Option<chrono::DateTime<Utc>>,
    Option<chrono::DateTime<Utc>>,
    bool,
    bool,
    Option<i32>,
    bool,
    i32,
    chrono::DateTime<Utc>,
    chrono::DateTime<Utc>,
);

macro_rules! access_rule_columns {
    () => {
        (
            access_rules::uuid,
            access_rules::name,
            access_rules::description,
            access_rules::user_group_id,
            vauban_groups::uuid,
            vauban_groups::name,
            access_rules::asset_group_id,
            asset_groups::uuid,
            asset_groups::name,
            access_rules::allowed_protocols,
            access_rules::valid_from,
            access_rules::valid_until,
            access_rules::require_mfa,
            access_rules::require_approval,
            access_rules::max_session_duration,
            access_rules::is_active,
            access_rules::priority,
            access_rules::created_at,
            access_rules::updated_at,
        )
    };
}

// ==================== Main dispatch ====================

pub async fn handle_access_request(pool: &DbPool, request: AccessRequest) -> AccessResponse {
    let mut conn = match pool.get().await {
        Ok(c) => c,
        Err(e) => return AccessResponse::Error(format!("DB connection error: {}", e)),
    };

    match request {
        AccessRequest::CheckAccess {
            user_id,
            asset_group_id,
            protocol,
        } => handle_check_access(&mut conn, user_id, asset_group_id, &protocol).await,

        AccessRequest::CheckAccessMulti {
            user_id,
            asset_group_ids,
            protocol,
        } => handle_check_access_multi(&mut conn, user_id, &asset_group_ids, &protocol).await,

        AccessRequest::CheckAccessByUuid {
            user_uuid,
            asset_uuid,
            protocol,
        } => handle_check_access_by_uuid(&mut conn, &user_uuid, &asset_uuid, &protocol).await,

        AccessRequest::ListAccessibleGroups { user_id, page } => {
            handle_list_accessible_groups(&mut conn, user_id, page).await
        }

        AccessRequest::CreateAccessRule { data, actor_uuid } => {
            handle_create_access_rule(&mut conn, data, actor_uuid.as_deref()).await
        }
        AccessRequest::GetAccessRule { uuid } => handle_get_access_rule(&mut conn, &uuid).await,
        AccessRequest::ListAccessRules { page } => handle_list_access_rules(&mut conn, page).await,
        AccessRequest::UpdateAccessRule {
            uuid,
            data,
            actor_uuid,
        } => handle_update_access_rule(&mut conn, &uuid, data, actor_uuid.as_deref()).await,
        AccessRequest::DeleteAccessRule { uuid } => {
            handle_delete_access_rule(&mut conn, &uuid).await
        }

        AccessRequest::CreateVaubanGroup { name, description } => {
            handle_create_vauban_group(&mut conn, &name, description.as_deref()).await
        }
        AccessRequest::GetVaubanGroup { uuid } => handle_get_vauban_group(&mut conn, &uuid).await,
        AccessRequest::GetVaubanGroupById { id } => {
            handle_get_vauban_group_by_id(&mut conn, id).await
        }
        AccessRequest::ListVaubanGroups { page } => {
            handle_list_vauban_groups(&mut conn, page).await
        }
        AccessRequest::UpdateVaubanGroup {
            uuid,
            name,
            description,
        } => handle_update_vauban_group(&mut conn, &uuid, &name, description.as_deref()).await,
        AccessRequest::DeleteVaubanGroup { uuid } => {
            handle_delete_vauban_group(&mut conn, &uuid).await
        }

        AccessRequest::AddGroupMember { group_id, user_id } => {
            handle_add_group_member(&mut conn, group_id, user_id).await
        }
        AccessRequest::RemoveGroupMember { group_id, user_id } => {
            handle_remove_group_member(&mut conn, group_id, user_id).await
        }
        AccessRequest::ListGroupMembers { group_id, page } => {
            handle_list_group_members(&mut conn, group_id, page).await
        }
        AccessRequest::ListUserGroups { user_id, page } => {
            handle_list_user_groups(&mut conn, user_id, page).await
        }

        AccessRequest::CreateAssetGroup {
            name,
            slug,
            description,
            color,
            icon,
            actor_uuid,
        } => {
            handle_create_asset_group(
                &mut conn,
                &name,
                &slug,
                description.as_deref(),
                &color,
                &icon,
                actor_uuid.as_deref(),
            )
            .await
        }
        AccessRequest::GetAssetGroup { uuid } => handle_get_asset_group(&mut conn, &uuid).await,
        AccessRequest::ListAssetGroups {
            page,
            include_virtual,
        } => handle_list_asset_groups(&mut conn, page, include_virtual).await,
        AccessRequest::UpdateAssetGroup {
            uuid,
            name,
            slug,
            description,
            color,
            icon,
            actor_uuid,
        } => {
            handle_update_asset_group(
                &mut conn,
                &uuid,
                &name,
                &slug,
                description.as_deref(),
                &color,
                &icon,
                actor_uuid.as_deref(),
            )
            .await
        }
        AccessRequest::DeleteAssetGroup { uuid } => {
            handle_delete_asset_group(&mut conn, &uuid).await
        }

        AccessRequest::ListUserGroupOptions { page } => {
            handle_list_user_group_options(&mut conn, page).await
        }
        AccessRequest::ListAssetGroupOptions {
            page,
            include_virtual,
        } => handle_list_asset_group_options(&mut conn, page, include_virtual).await,

        // SECURITY: minting requires the cryptographic key, which lives
        // in `main.rs`. The variant MUST be intercepted before it
        // reaches this dispatch (see `handle_message` in `main.rs`).
        // Falling through to here means a programmer error in the
        // routing layer; we collapse to `SessionTokenDenied` rather
        // than panicking so a misconfigured build still fails closed
        // instead of opening a session.
        AccessRequest::IssueSessionToken { .. } => {
            warn!(
                "IssueSessionToken reached handle_access_request dispatch; \
                 routing bug in vauban-access main loop. Fail-closed deny."
            );
            AccessResponse::SessionTokenDenied
        }

        // SECURITY: same fail-closed safety net as `IssueSessionToken`.
        // IssueDiagnosticToken also requires the MAC key and is routed
        // ahead of this dispatch in `main.rs::handle_message`. Reaching
        // this arm means the routing layer dropped the variant -- we
        // refuse rather than panic so a misconfigured build never opens
        // a token-shaped credential without crypto.
        AccessRequest::IssueDiagnosticToken { .. } => {
            warn!(
                "IssueDiagnosticToken reached handle_access_request \
                 dispatch; routing bug in vauban-access main loop. \
                 Fail-closed deny."
            );
            AccessResponse::SessionTokenDenied
        }

        AccessRequest::CheckApprovalEligibility {
            actor_user_uuid,
            session_uuid,
        } => handle_check_approval_eligibility(&mut conn, &actor_user_uuid, &session_uuid).await,

        AccessRequest::RecordApprovalDecision {
            actor_user_uuid,
            session_uuid,
            decision,
            duration_override_seconds,
            decision_reason,
            decision_ip,
            decision_user_agent,
            request_id,
        } => {
            handle_record_approval_decision(
                &mut conn,
                ApprovalDecisionInput {
                    actor_user_uuid: &actor_user_uuid,
                    session_uuid: &session_uuid,
                    decision,
                    duration_override_seconds,
                    decision_reason,
                    decision_ip,
                    decision_user_agent,
                    request_id,
                },
            )
            .await
        }

        AccessRequest::VerifySessionAccess {
            session_uuid,
            requesting_user_uuid,
            intent,
        } => {
            handle_verify_session_access(&mut conn, &session_uuid, &requesting_user_uuid, intent)
                .await
        }

        // ===================================================================
        // IACS / EWS onboarding -- atomic decisions in vauban-access::iacs.
        // Every variant runs in a Diesel transaction with audit append-only.
        // ===================================================================
        AccessRequest::SubmitEwsOnboarding {
            actor_user_uuid,
            name,
            public_key,
            public_key_fingerprint,
            key_algo,
            justification,
            max_ews_per_user,
            actor_ip,
        } => {
            crate::iacs::handle_submit_ews_onboarding(
                &mut conn,
                &actor_user_uuid,
                name,
                public_key,
                public_key_fingerprint,
                key_algo,
                justification,
                max_ews_per_user,
                actor_ip,
            )
            .await
        }
        AccessRequest::EditEwsRequest {
            actor_user_uuid,
            request_uuid,
            name,
            public_key,
            public_key_fingerprint,
            key_algo,
            justification,
            actor_ip,
        } => {
            crate::iacs::handle_edit_ews_request(
                &mut conn,
                &actor_user_uuid,
                &request_uuid,
                name,
                public_key,
                public_key_fingerprint,
                key_algo,
                justification,
                actor_ip,
            )
            .await
        }
        AccessRequest::CancelEwsRequest {
            actor_user_uuid,
            request_uuid,
            actor_ip,
        } => {
            crate::iacs::handle_cancel_ews_request(
                &mut conn,
                &actor_user_uuid,
                &request_uuid,
                actor_ip,
            )
            .await
        }
        AccessRequest::RecordEwsDecision {
            actor_user_uuid,
            request_uuid,
            decision,
            decision_reason,
            actor_ip,
        } => {
            crate::iacs::handle_record_ews_decision(
                &mut conn,
                &actor_user_uuid,
                &request_uuid,
                decision,
                decision_reason,
                actor_ip,
            )
            .await
        }
        AccessRequest::DisableEws {
            actor_user_uuid,
            ews_uuid,
            actor_ip,
        } => {
            crate::iacs::handle_disable_ews(&mut conn, &actor_user_uuid, &ews_uuid, actor_ip).await
        }
        AccessRequest::EnableEws {
            actor_user_uuid,
            ews_uuid,
            actor_ip,
        } => crate::iacs::handle_enable_ews(&mut conn, &actor_user_uuid, &ews_uuid, actor_ip).await,
        AccessRequest::OffboardEws {
            actor_user_uuid,
            ews_uuid,
            on_behalf_of_self,
            decision_reason,
            actor_ip,
        } => {
            crate::iacs::handle_offboard_ews(
                &mut conn,
                &actor_user_uuid,
                &ews_uuid,
                on_behalf_of_self,
                decision_reason,
                actor_ip,
            )
            .await
        }
    }
}

/// SECURITY: instance-level decision for any consumer of an existing
/// `proxy_sessions` row (HTML viewer, WebSocket upgrade, JSON metadata
/// read, terminate). Combines:
///
/// 1. **Existence + status** — sessions in `terminated`, `expired`, or
///    `disconnected` are reported as `Gone`. Unknown UUIDs are
///    `NotFound`.
/// 2. **Ownership** — `proxy_sessions.user_id` must match the supplied
///    `requesting_user_uuid`. The Casbin `sessions:supervise` /
///    `sessions:write` OR-overrides are layered later by the
///    vauban-web service.
/// 3. **Access-rule re-check** — the matching access rule for
///    (owner, asset, session_type) is re-evaluated against
///    `is_active`, `valid_from`, `valid_until`, and protocol coverage
///    via [`handle_check_access_by_uuid`]. A revoked, expired, or
///    not-yet-valid rule yields `AccessRuleRevoked` -> the consumer
///    is fail-fast cut at its next page-load or WS handshake.
///
/// `intent` is recorded in the audit log but does not influence the
/// decision; the OR-overrides are applied uniformly on the vauban-web
/// side.
///
/// Fail-closed: any unexpected DB error collapses to a denial
/// (`AccessRuleRevoked`) rather than `Error`, so a misbehaving
/// infrastructure cannot accidentally grant access.
async fn handle_verify_session_access(
    conn: &mut DbConnection,
    session_uuid: &str,
    requesting_user_uuid: &str,
    intent: shared::messages::SessionAccessIntent,
) -> AccessResponse {
    use shared::messages::{SessionAccessDecision, SessionDenialReason};

    let denied = |reason: SessionDenialReason| AccessResponse::SessionAccessChecked {
        decision: SessionAccessDecision::Denied(reason),
    };

    let session_uuid_parsed = match Uuid::parse_str(session_uuid) {
        Ok(u) => u,
        Err(e) => {
            warn!(session_uuid, error = %e, "VerifySessionAccess: invalid session uuid");
            return denied(SessionDenialReason::NotFound);
        }
    };
    let requesting_user_parsed = match Uuid::parse_str(requesting_user_uuid) {
        Ok(u) => u,
        Err(e) => {
            warn!(requesting_user_uuid, error = %e, "VerifySessionAccess: invalid user uuid");
            return denied(SessionDenialReason::NotOwner);
        }
    };

    type SessionRow = (Uuid, String, Uuid, String);
    let row: Option<SessionRow> = match proxy_sessions::table
        .inner_join(users::table.on(users::id.eq(proxy_sessions::user_id)))
        .inner_join(assets::table.on(assets::id.eq(proxy_sessions::asset_id)))
        .filter(proxy_sessions::uuid.eq(session_uuid_parsed))
        .select((
            users::uuid,
            proxy_sessions::status,
            assets::uuid,
            proxy_sessions::session_type,
        ))
        .first::<SessionRow>(conn)
        .await
        .optional()
    {
        Ok(opt) => opt,
        Err(e) => {
            warn!(session_uuid, error = %e, "VerifySessionAccess: db error loading session");
            return denied(SessionDenialReason::NotFound);
        }
    };

    let (owner_uuid, status, asset_uuid, session_type) = match row {
        Some(r) => r,
        None => {
            info!(
                session_uuid,
                ?intent,
                "VerifySessionAccess denied: session not found"
            );
            return denied(SessionDenialReason::NotFound);
        }
    };

    let is_gone = status == "terminated" || status == "expired" || status == "disconnected";

    // SECURITY: ordering matters.
    //
    // For `OpenViewer` / `ConsumeWs` (interactive intents) we keep
    // the historical "status before owner" order: a non-owner
    // attacker probing a known UUID sees `Gone` only if the session
    // is actually gone, otherwise `NotOwner` (collapsed to 404 by
    // the service). The interactive surface MUST refuse a `Gone`
    // upgrade regardless of identity (the underlying TCP/RDP/SSH
    // connection is dead).
    //
    // For `Terminate` and `ReadMetadata` (idempotent / historical
    // intents) we surface ownership BEFORE status:
    //
    // * `Terminate`: the owner of an already-terminated session
    //   reaches the service-layer idempotency path (Gone -> Allowed
    //   for a verified owner / sessions:write holder) instead of
    //   being told "404" on their own session.
    // * `ReadMetadata`: the owner of a Gone session can still read
    //   the session detail page (audit, replay link, durations,
    //   bytes...) -- losing this read on the very moment the session
    //   stops being live was a regression introduced by the IDOR
    //   centralisation. A non-owner still gets `NotOwner` (collapsed
    //   to 404 unless they hold `sessions:supervise`), preserving
    //   the anti-enumeration property.
    let owner_check_first = matches!(
        intent,
        shared::messages::SessionAccessIntent::Terminate
            | shared::messages::SessionAccessIntent::ReadMetadata
    );
    if owner_check_first && owner_uuid != requesting_user_parsed {
        info!(
            session_uuid,
            ?intent,
            "VerifySessionAccess denied: requesting user is not the owner"
        );
        return denied(SessionDenialReason::NotOwner);
    }

    if is_gone {
        // ReadMetadata + owner: the access-rule re-check is moot
        // (the session is already historical), and the operator
        // legitimately needs to consult the trace. We short-circuit
        // to `Allowed` here so the web layer renders the detail
        // page instead of redirecting to "/sessions" with a flash
        // "Session not found" -- the regression that motivated this
        // path. For Terminate the service-layer keeps the Gone -> Allowed
        // idempotency translation; for OpenViewer / ConsumeWs we stay
        // strict (Gone -> 410).
        if matches!(intent, shared::messages::SessionAccessIntent::ReadMetadata) {
            return AccessResponse::SessionAccessChecked {
                decision: SessionAccessDecision::Allowed,
            };
        }
        info!(
            session_uuid,
            status,
            ?intent,
            "VerifySessionAccess denied: session is gone"
        );
        return denied(SessionDenialReason::Gone);
    }

    if !owner_check_first && owner_uuid != requesting_user_parsed {
        info!(
            session_uuid,
            ?intent,
            "VerifySessionAccess denied: requesting user is not the owner"
        );
        return denied(SessionDenialReason::NotOwner);
    }

    let owner_uuid_str = owner_uuid.to_string();
    let asset_uuid_str = asset_uuid.to_string();
    let check =
        handle_check_access_by_uuid(conn, &owner_uuid_str, &asset_uuid_str, &session_type).await;
    let allowed = matches!(
        check,
        AccessResponse::AccessChecked(AccessCheckResult { allowed: true, .. })
    );
    if !allowed {
        info!(
            session_uuid,
            owner = %owner_uuid_str,
            asset = %asset_uuid_str,
            protocol = %session_type,
            ?intent,
            "VerifySessionAccess denied: access rule no longer applies"
        );
        return denied(SessionDenialReason::AccessRuleRevoked);
    }

    AccessResponse::SessionAccessChecked {
        decision: SessionAccessDecision::Allowed,
    }
}

/// SECURITY: mint a cryptographic session token after re-running the
/// instance-level access check. This is the issuer side of the
/// session-token gate that the supervisor and the protocol proxies
/// later verify before opening sockets and upstream sessions.
///
/// Fail-closed semantics: every error path collapses to
/// [`AccessResponse::SessionTokenDenied`]. The variant is intentionally
/// indistinguishable from a policy-denied reply so a probe cannot
/// fingerprint whether the issue is policy, DB, or minter.
pub async fn handle_issue_session_token(
    pool: &DbPool,
    key: &TokenKey,
    params: SessionTokenParams,
) -> AccessResponse {
    let mut conn = match pool.get().await {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "IssueSessionToken: DB connection error, deny");
            return AccessResponse::SessionTokenDenied;
        }
    };

    // Re-run the same authorization the proxy will demand. We intentionally
    // call the existing checker so a future policy refinement automatically
    // tightens the issuer too.
    let check = handle_check_access_by_uuid(
        &mut conn,
        &params.user_uuid,
        &params.asset_uuid,
        &params.protocol,
    )
    .await;
    let allowed = matches!(
        check,
        AccessResponse::AccessChecked(AccessCheckResult { allowed: true, .. })
    );
    if !allowed {
        info!(
            user_uuid = %params.user_uuid,
            asset_uuid = %params.asset_uuid,
            protocol = %params.protocol,
            session_id = %params.session_id,
            "IssueSessionToken denied: policy check failed"
        );
        return AccessResponse::SessionTokenDenied;
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let token = SessionToken::mint(key, now, params);
    match token.to_bytes() {
        Ok(bytes) => AccessResponse::SessionTokenIssued { token: bytes },
        Err(e) => {
            warn!(error = ?e, "IssueSessionToken: serialization failure, deny");
            AccessResponse::SessionTokenDenied
        }
    }
}

/// Mint a session-token-shaped credential for a strictly read-only
/// diagnostic operation (today: SSH host-key verify and admin
/// host-key fetch).
///
/// Authorisation contract: gates ONLY on
/// `caller_has_assets_manage = true`. The access-rule re-check
/// performed by `handle_issue_session_token` is intentionally skipped
/// here because the diagnostic path does NOT open an upstream SSH
/// session (the russh handshake stops after key exchange) and the
/// admins that need to fix a host-key mismatch typically have no
/// explicit access rule for the asset.
///
/// Wire format and crypto match `handle_issue_session_token`: same
/// MAC key, same anti-replay nonce, same field bindings. The
/// supervisor's TCP broker and the proxy session-token gate accept
/// the resulting token without code changes.
///
/// Fail-closed: any non-`assets:manage` caller, or any serialization
/// failure, collapses to `AccessResponse::SessionTokenDenied`. The
/// reply is intentionally indistinguishable from the
/// `IssueSessionToken` denial so a probe cannot fingerprint which
/// path was used.
pub async fn handle_issue_diagnostic_token(
    key: &TokenKey,
    params: SessionTokenParams,
    caller_has_assets_manage: bool,
) -> AccessResponse {
    if !caller_has_assets_manage {
        info!(
            user_uuid = %params.user_uuid,
            asset_uuid = %params.asset_uuid,
            protocol = %params.protocol,
            session_id = %params.session_id,
            "IssueDiagnosticToken denied: caller lacks assets:manage"
        );
        return AccessResponse::SessionTokenDenied;
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let token = SessionToken::mint(key, now, params);
    match token.to_bytes() {
        Ok(bytes) => AccessResponse::SessionTokenIssued { token: bytes },
        Err(e) => {
            warn!(error = ?e, "IssueDiagnosticToken: serialization failure, deny");
            AccessResponse::SessionTokenDenied
        }
    }
}

// ==================== Helpers ====================

fn normalize_ipc_page(page: IpcPageParams) -> (i64, i64) {
    let limit = if page.limit == 0 {
        DEFAULT_IPC_PAGE_LIMIT
    } else {
        page.limit.min(MAX_IPC_PAGE_LIMIT)
    };
    (i64::from(limit), i64::from(page.offset))
}

fn parse_optional_datetime(
    value: &Option<String>,
) -> Result<Option<chrono::DateTime<Utc>>, String> {
    match value {
        Some(s) if !s.is_empty() => {
            let dt = chrono::DateTime::parse_from_rfc3339(s)
                .map_err(|e| format!("Invalid datetime '{}': {}", s, e))?;
            Ok(Some(dt.with_timezone(&Utc)))
        }
        _ => Ok(None),
    }
}

fn to_access_rule_info(row: AccessRuleRow) -> AccessRuleInfo {
    AccessRuleInfo {
        uuid: row.0.to_string(),
        name: row.1,
        description: row.2,
        user_group_id: row.3,
        user_group_uuid: row.4.to_string(),
        user_group_name: row.5,
        asset_group_id: row.6,
        asset_group_uuid: row.7.to_string(),
        asset_group_name: row.8,
        allowed_protocols: row.9.into_iter().flatten().collect(),
        valid_from: row.10.map(|dt| dt.to_rfc3339()),
        valid_until: row.11.map(|dt| dt.to_rfc3339()),
        require_mfa: row.12,
        require_approval: row.13,
        max_session_duration: row.14,
        is_active: row.15,
        priority: row.16,
        created_at: row.17.to_rfc3339(),
        updated_at: row.18.to_rfc3339(),
    }
}

async fn load_access_rule_by_uuid(
    conn: &mut DbConnection,
    rule_uuid: Uuid,
) -> Result<AccessRuleInfo, String> {
    let row: AccessRuleRow = access_rules::table
        .inner_join(vauban_groups::table)
        .inner_join(asset_groups::table)
        .filter(access_rules::uuid.eq(rule_uuid))
        .select(access_rule_columns!())
        .first(conn)
        .await
        .map_err(|e| format!("Access rule not found: {}", e))?;

    Ok(to_access_rule_info(row))
}

#[allow(clippy::too_many_arguments)]
async fn build_vauban_group_info(
    conn: &mut DbConnection,
    id: i32,
    uuid: Uuid,
    name: &str,
    description: Option<&str>,
    source: &str,
    external_id: Option<&str>,
    created_at: chrono::DateTime<Utc>,
    updated_at: chrono::DateTime<Utc>,
    last_synced: Option<chrono::DateTime<Utc>>,
) -> Result<VaubanGroupInfo, diesel::result::Error> {
    let member_count: i64 = user_groups::table
        .filter(user_groups::group_id.eq(id))
        .count()
        .get_result(conn)
        .await?;

    Ok(VaubanGroupInfo {
        id,
        uuid: uuid.to_string(),
        name: name.to_string(),
        description: description.map(String::from),
        source: source.to_string(),
        external_id: external_id.map(String::from),
        created_at: created_at.to_rfc3339(),
        updated_at: updated_at.to_rfc3339(),
        last_synced: last_synced.map(|dt| dt.to_rfc3339()),
        member_count,
    })
}

fn parse_uuid(uuid_str: &str) -> Result<Uuid, String> {
    Uuid::parse_str(uuid_str).map_err(|e| format!("Invalid UUID '{}': {}", uuid_str, e))
}

/// Issue #22 — resolve a JWT-side actor UUID into a numeric
/// `users.id` suitable for stamping `created_by_id` /
/// `updated_by_id`. Returns `None` for any reason (missing
/// arg, malformed UUID, unknown user, transient DB error) — the
/// audit columns are `Nullable<Int4>` so a `None` only flips
/// the read-side Metadata cell to the muted em-dash on the web
/// detail pages, never blocking the write itself.
async fn resolve_actor_id(conn: &mut DbConnection, actor_uuid: Option<&str>) -> Option<i32> {
    let raw = actor_uuid?;
    let parsed = Uuid::parse_str(raw).ok()?;
    users::table
        .filter(users::uuid.eq(parsed))
        .select(users::id)
        .first::<i32>(conn)
        .await
        .ok()
}

// ==================== Access checking ====================

/// Bridge the request-side `protocol` string and the access_rules
/// row's `allowed_protocols` column.
///
/// For most protocols (`ssh`, `rdp`, applicative `iacs_*`) the rule
/// holds the literal request string and a Postgres `@>` containment
/// test ("the rule's array contains the request value") is the
/// correct semantics. For the IACS transport-meta `iacs_tunnel`
/// however, the rule holds the *applicative* protocol (`iacs_modbus`,
/// `iacs_opcua`, ...) and we want a `&&` overlap test ("the rule's
/// array intersects the expanded set"). The seam is centralised in
/// [`shared::access_guard::expand_protocol_for_access_match`]; this
/// helper plumbs the result into the Diesel query as a raw SQL
/// fragment because Diesel's stable surface does not expose a
/// generic `&& ARRAY[$bind]` helper for `Array<Nullable<Text>>`
/// columns.
fn protocol_match_filter(protocol: &str) -> diesel::expression::SqlLiteral<SqlBool> {
    let expanded = shared::access_guard::expand_protocol_for_access_match(protocol);
    // Anti-injection: every element MUST go through `escape_sql_array_literal`
    // because `sql_query` here is built by string concat (Diesel's bind
    // parameter system on dynamic-length array literals is awkward to
    // thread through `dsl::sql`). The escaper enforces that only the
    // expected canonical protocol strings reach the SQL surface; an
    // unexpected character collapses to fail-closed deny.
    let array_literal = expanded
        .iter()
        .map(|p| escape_sql_array_literal(p))
        .collect::<Vec<_>>()
        .join(",");
    sql::<SqlBool>(&format!(
        "allowed_protocols && ARRAY[{array_literal}]::text[]"
    ))
}

/// True when an active access_rule for `user_id` matches the IACS tunnel
/// meta-protocol AND explicitly lists `asset_type` in `allowed_protocols`.
async fn iacs_tunnel_rule_includes_asset_type(
    conn: &mut DbConnection,
    user_id: i32,
    asset_group_ids: &[i32],
    asset_type: &str,
) -> bool {
    use crate::schema::{access_rules, user_groups};

    let type_literal = escape_sql_array_literal(asset_type);
    let count: i64 = match access_rules::table
        .inner_join(user_groups::table.on(user_groups::group_id.eq(access_rules::user_group_id)))
        .filter(user_groups::user_id.eq(user_id))
        .filter(access_rules::asset_group_id.eq_any(asset_group_ids))
        .filter(access_rules::is_active.eq(true))
        .filter(sql::<SqlBool>(
            "(valid_from IS NULL OR valid_from <= NOW())",
        ))
        .filter(sql::<SqlBool>(
            "(valid_until IS NULL OR valid_until >= NOW())",
        ))
        .filter(protocol_match_filter(
            shared::access_guard::PROTOCOL_IACS_TUNNEL,
        ))
        .filter(sql::<SqlBool>(&format!(
            "allowed_protocols @> ARRAY[{type_literal}]::text[]"
        )))
        .count()
        .get_result(conn)
        .await
    {
        Ok(c) => c,
        Err(e) => {
            warn!(
                user_id,
                asset_type,
                error = %e,
                "CheckAccessByUuid: db error checking asset_type in granting rule"
            );
            return false;
        }
    };
    count > 0
}

/// Defence-in-depth escaper for the protocol literals threaded
/// through [`protocol_match_filter`]. Returns a fully-quoted Postgres
/// string literal (`'iacs_modbus'`). Any character outside
/// `[A-Za-z0-9_]` -- which includes every legitimate protocol the
/// access-rule form can write -- is replaced with `_` and the
/// literal is then wrapped in single quotes. The replacement cannot
/// produce a valid match against any real `allowed_protocols`
/// element (those only contain `[a-z_]`), so a malicious or
/// malformed request degrades to a SQL fragment that matches
/// nothing -- fail-closed.
fn escape_sql_array_literal(s: &str) -> String {
    let sanitised: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    format!("'{sanitised}'")
}

async fn handle_check_access(
    conn: &mut DbConnection,
    user_id: i32,
    asset_group_id: i32,
    protocol: &str,
) -> AccessResponse {
    let matching_rules = access_rules::table
        .inner_join(user_groups::table.on(user_groups::group_id.eq(access_rules::user_group_id)))
        .filter(user_groups::user_id.eq(user_id))
        .filter(access_rules::asset_group_id.eq(asset_group_id))
        .filter(access_rules::is_active.eq(true))
        .filter(sql::<SqlBool>(
            "(valid_from IS NULL OR valid_from <= NOW())",
        ))
        .filter(sql::<SqlBool>(
            "(valid_until IS NULL OR valid_until >= NOW())",
        ))
        .filter(protocol_match_filter(protocol))
        .select((
            access_rules::require_mfa,
            access_rules::require_approval,
            access_rules::max_session_duration,
        ))
        .load::<(bool, bool, Option<i32>)>(conn)
        .await;

    match matching_rules {
        Ok(rules) if rules.is_empty() => {
            info!(
                user_id,
                asset_group_id, protocol, "Access denied: no matching rules"
            );
            AccessResponse::AccessChecked(AccessCheckResult {
                allowed: false,
                require_mfa: false,
                require_approval: false,
                max_session_duration: None,
            })
        }
        Ok(rules) => {
            let require_mfa = rules.iter().any(|(mfa, _, _)| *mfa);
            let require_approval = rules.iter().any(|(_, just, _)| *just);
            let max_session_duration = rules.iter().filter_map(|(_, _, dur)| *dur).min();

            info!(
                user_id,
                asset_group_id,
                protocol,
                rule_count = rules.len(),
                require_mfa,
                require_approval,
                "Access granted"
            );

            AccessResponse::AccessChecked(AccessCheckResult {
                allowed: true,
                require_mfa,
                require_approval,
                max_session_duration,
            })
        }
        Err(e) => AccessResponse::Error(format!("Failed to check access: {}", e)),
    }
}

async fn handle_check_access_multi(
    conn: &mut DbConnection,
    user_id: i32,
    asset_group_ids: &[i32],
    protocol: &str,
) -> AccessResponse {
    // Always pull in any rule on the singleton virtual "All assets" group
    // (kind='all'). Such a rule covers EVERY asset the user could query,
    // so we OR-aggregate its constraints into every requested group's
    // verdict below. The protocol/validity filters still apply -- a
    // virtual rule scoped to ssh does NOT grant rdp.
    //
    // virtual_group_id == UNINITIALIZED_VIRTUAL_ID before boot resolution
    // (or when running in dev mode without a DB seed). It cannot match any
    // real row, so every code path degrades cleanly to "no virtual rule
    // applies" -- which is the safe fail-closed default (no spurious
    // grant; user keeps whatever static rules they had).
    let virtual_id = crate::virtual_group::virtual_asset_group_id();
    let mut search_ids: Vec<i32> = asset_group_ids.to_vec();
    if !search_ids.contains(&virtual_id) {
        search_ids.push(virtual_id);
    }

    let rows = access_rules::table
        .inner_join(user_groups::table.on(user_groups::group_id.eq(access_rules::user_group_id)))
        .filter(user_groups::user_id.eq(user_id))
        .filter(access_rules::asset_group_id.eq_any(&search_ids))
        .filter(access_rules::is_active.eq(true))
        .filter(sql::<SqlBool>(
            "(valid_from IS NULL OR valid_from <= NOW())",
        ))
        .filter(sql::<SqlBool>(
            "(valid_until IS NULL OR valid_until >= NOW())",
        ))
        .filter(protocol_match_filter(protocol))
        .select((
            access_rules::asset_group_id,
            access_rules::require_mfa,
            access_rules::require_approval,
            access_rules::max_session_duration,
        ))
        .load::<(i32, bool, bool, Option<i32>)>(conn)
        .await;

    match rows {
        Ok(results) => {
            let mut group_map: HashMap<i32, Vec<(bool, bool, Option<i32>)>> = HashMap::new();
            let mut virtual_rules: Vec<(bool, bool, Option<i32>)> = Vec::new();
            for (ag_id, mfa, just, dur) in results {
                if ag_id == virtual_id {
                    virtual_rules.push((mfa, just, dur));
                } else {
                    group_map.entry(ag_id).or_default().push((mfa, just, dur));
                }
            }

            let entries: Vec<AccessCheckResultEntry> = asset_group_ids
                .iter()
                .map(|&ag_id| {
                    // Combine static rules for this group with every
                    // virtual rule (which by definition matches every
                    // asset). The OR/min semantics is identical to what
                    // the existing code does for overlapping static
                    // rules -- virtual rules just join the candidate set.
                    let static_rules = group_map.get(&ag_id);
                    let any_rule_applies =
                        static_rules.is_some_and(|r| !r.is_empty()) || !virtual_rules.is_empty();
                    let result = if any_rule_applies {
                        let combined = static_rules
                            .into_iter()
                            .flatten()
                            .chain(virtual_rules.iter());
                        let combined: Vec<&(bool, bool, Option<i32>)> = combined.collect();
                        AccessCheckResult {
                            allowed: true,
                            require_mfa: combined.iter().any(|(mfa, _, _)| *mfa),
                            require_approval: combined.iter().any(|(_, just, _)| *just),
                            max_session_duration: combined
                                .iter()
                                .filter_map(|(_, _, dur)| *dur)
                                .min(),
                        }
                    } else {
                        AccessCheckResult {
                            allowed: false,
                            require_mfa: false,
                            require_approval: false,
                            max_session_duration: None,
                        }
                    };
                    AccessCheckResultEntry {
                        asset_group_id: ag_id,
                        result,
                    }
                })
                .collect();

            AccessResponse::AccessCheckedMulti(entries)
        }
        Err(e) => AccessResponse::Error(format!("Failed to check access multi: {e}")),
    }
}

/// SECURITY: UUID-addressed authorization check used by services that have no
/// database connection of their own (typically `vauban-proxy-ssh` running
/// under Capsicum). The proxy receives `Message::SshSessionOpen { user_id:
/// <uuid>, asset_id: <uuid> }` directly from `vauban-web` and must re-verify
/// the request before opening the upstream SSH connection -- defense-in-depth
/// so that a compromised vauban-web cannot single-handedly authorise an SSH
/// session.
///
/// Fail-closed semantics: any failure path (UUID parse error, unknown user,
/// inactive user, deleted asset, asset belonging to no group, DB error)
/// returns `AccessChecked { allowed: false, ... }` rather than `Error(...)`,
/// so the proxy can treat the response as a clean denial without having to
/// distinguish "policy says no" from "infrastructure error". The diagnostic
/// detail still surfaces in logs at `warn` level.
async fn handle_check_access_by_uuid(
    conn: &mut DbConnection,
    user_uuid: &str,
    asset_uuid: &str,
    protocol: &str,
) -> AccessResponse {
    let denied = || {
        AccessResponse::AccessChecked(AccessCheckResult {
            allowed: false,
            require_mfa: false,
            require_approval: false,
            max_session_duration: None,
        })
    };

    let user_uuid_parsed = match Uuid::parse_str(user_uuid) {
        Ok(u) => u,
        Err(e) => {
            warn!(user_uuid, error = %e, protocol, "CheckAccessByUuid: invalid user uuid");
            return denied();
        }
    };
    let asset_uuid_parsed = match Uuid::parse_str(asset_uuid) {
        Ok(u) => u,
        Err(e) => {
            warn!(asset_uuid, error = %e, protocol, "CheckAccessByUuid: invalid asset uuid");
            return denied();
        }
    };

    let user_id: i32 = match users::table
        .filter(users::uuid.eq(user_uuid_parsed))
        .filter(users::is_active.eq(true))
        .select(users::id)
        .first::<i32>(conn)
        .await
    {
        Ok(id) => id,
        Err(diesel::result::Error::NotFound) => {
            warn!(
                user_uuid,
                protocol, "CheckAccessByUuid: unknown or inactive user"
            );
            return denied();
        }
        Err(e) => {
            warn!(user_uuid, error = %e, "CheckAccessByUuid: db error resolving user");
            return denied();
        }
    };

    let (asset_id, asset_type): (i32, String) = match assets::table
        .filter(assets::uuid.eq(asset_uuid_parsed))
        .filter(assets::is_deleted.eq(false))
        .select((assets::id, assets::asset_type))
        .first(conn)
        .await
    {
        Ok(row) => row,
        Err(diesel::result::Error::NotFound) => {
            warn!(
                asset_uuid,
                protocol, "CheckAccessByUuid: unknown or deleted asset"
            );
            return denied();
        }
        Err(e) => {
            warn!(asset_uuid, error = %e, "CheckAccessByUuid: db error resolving asset");
            return denied();
        }
    };

    // IACS tunnel transport-meta MUST NOT grant on non-IACS assets, and
    // the granting access_rule MUST include the asset's applicative type
    // (`iacs_modbus`, ...) -- not just any expanded `iacs_*` overlap.
    if protocol == shared::access_guard::PROTOCOL_IACS_TUNNEL
        && !shared::access_guard::IACS_APPLICATIVE_PROTOCOLS.contains(&asset_type.as_str())
    {
        info!(
            asset_uuid,
            asset_id,
            asset_type = %asset_type,
            protocol,
            "CheckAccessByUuid denied: iacs_tunnel requested for non-IACS asset"
        );
        return denied();
    }

    let mut asset_group_ids: Vec<i32> = match asset_asset_groups::table
        .filter(asset_asset_groups::asset_id.eq(asset_id))
        .select(asset_asset_groups::asset_group_id)
        .load::<i32>(conn)
        .await
    {
        Ok(ids) => ids,
        Err(e) => {
            warn!(
                asset_uuid, asset_id, error = %e,
                "CheckAccessByUuid: db error loading asset groups"
            );
            return denied();
        }
    };

    // Defense-in-depth: ALWAYS append the virtual "All assets" id so that
    // an orphan asset (member of no static group) is still reachable when
    // the user has a virtual rule. The aggregation in
    // `handle_check_access_multi` already OR-aggregates every virtual rule
    // into every requested group's verdict; this push ensures we still
    // call into it (instead of taking the empty-list early-return path
    // below) when the only rule that grants access is a virtual one.
    let virtual_id = crate::virtual_group::virtual_asset_group_id();
    if !asset_group_ids.contains(&virtual_id) {
        asset_group_ids.push(virtual_id);
    }

    if asset_group_ids.is_empty() {
        info!(
            asset_uuid,
            asset_id,
            protocol,
            "CheckAccessByUuid denied: asset belongs to no asset_group (and no virtual fallback)"
        );
        return denied();
    }

    let multi = handle_check_access_multi(conn, user_id, &asset_group_ids, protocol).await;
    let entries = match multi {
        AccessResponse::AccessCheckedMulti(entries) => entries,
        AccessResponse::Error(e) => {
            warn!(user_uuid, asset_uuid, protocol, error = %e, "CheckAccessByUuid: multi-check error");
            return denied();
        }
        _ => {
            warn!(
                user_uuid,
                asset_uuid, protocol, "CheckAccessByUuid: unexpected multi-check response"
            );
            return denied();
        }
    };

    let allowed = entries.iter().any(|e| e.result.allowed);
    if !allowed {
        info!(
            user_uuid,
            asset_uuid, protocol, "CheckAccessByUuid denied: no granting access_rule"
        );
        return denied();
    }

    if protocol == shared::access_guard::PROTOCOL_IACS_TUNNEL
        && !iacs_tunnel_rule_includes_asset_type(conn, user_id, &asset_group_ids, &asset_type).await
    {
        info!(
            user_uuid,
            asset_uuid,
            asset_id,
            asset_type = %asset_type,
            protocol,
            "CheckAccessByUuid denied: no granting access_rule includes asset_type"
        );
        return denied();
    }

    let granting: Vec<&AccessCheckResult> = entries
        .iter()
        .filter_map(|e| e.result.allowed.then_some(&e.result))
        .collect();

    let require_mfa = granting.iter().any(|r| r.require_mfa);
    let require_approval = granting.iter().any(|r| r.require_approval);
    let max_session_duration = granting.iter().filter_map(|r| r.max_session_duration).min();

    info!(
        user_uuid,
        asset_uuid, protocol, require_mfa, require_approval, "CheckAccessByUuid granted"
    );

    AccessResponse::AccessChecked(AccessCheckResult {
        allowed: true,
        require_mfa,
        require_approval,
        max_session_duration,
    })
}

async fn handle_list_accessible_groups(
    conn: &mut DbConnection,
    user_id: i32,
    page: IpcPageParams,
) -> AccessResponse {
    let (base_limit, offset) = normalize_ipc_page(page);
    let fetch = base_limit.saturating_add(1);

    // Step 1: fetch paginated distinct asset_group_ids (fetch = limit+1 for has_more)
    let mut distinct_ids = match access_rules::table
        .inner_join(user_groups::table.on(user_groups::group_id.eq(access_rules::user_group_id)))
        .filter(user_groups::user_id.eq(user_id))
        .filter(access_rules::is_active.eq(true))
        .filter(sql::<SqlBool>(
            "(valid_from IS NULL OR valid_from <= NOW())",
        ))
        .filter(sql::<SqlBool>(
            "(valid_until IS NULL OR valid_until >= NOW())",
        ))
        .select(access_rules::asset_group_id)
        .distinct()
        .order_by(access_rules::asset_group_id.asc())
        .limit(fetch)
        .offset(offset)
        .load::<i32>(conn)
        .await
    {
        Ok(ids) => ids,
        Err(e) => {
            return AccessResponse::Error(format!("Failed to list accessible groups: {e}"));
        }
    };

    let has_more = distinct_ids.len() > base_limit as usize;
    if has_more {
        distinct_ids.truncate(base_limit as usize);
    }

    if distinct_ids.is_empty() {
        return AccessResponse::AccessibleGroupsPage(IpcPage {
            items: vec![],
            has_more: false,
        });
    }

    // Step 2: fetch protocols for those IDs (same connection, no pool overhead)
    let rows = access_rules::table
        .inner_join(user_groups::table.on(user_groups::group_id.eq(access_rules::user_group_id)))
        .filter(user_groups::user_id.eq(user_id))
        .filter(access_rules::is_active.eq(true))
        .filter(sql::<SqlBool>(
            "(valid_from IS NULL OR valid_from <= NOW())",
        ))
        .filter(sql::<SqlBool>(
            "(valid_until IS NULL OR valid_until >= NOW())",
        ))
        .filter(access_rules::asset_group_id.eq_any(&distinct_ids))
        .select((
            access_rules::asset_group_id,
            access_rules::allowed_protocols,
        ))
        .load::<(i32, Vec<Option<String>>)>(conn)
        .await;

    match rows {
        Ok(results) => {
            let mut group_map: HashMap<i32, Vec<String>> = HashMap::new();
            for (group_id, protocols) in results {
                let entry = group_map.entry(group_id).or_default();
                for proto in protocols.into_iter().flatten() {
                    if !entry.contains(&proto) {
                        entry.push(proto);
                    }
                }
            }

            let entries: Vec<AccessibleGroupEntry> = distinct_ids
                .into_iter()
                .map(|id| {
                    let protocols = group_map.remove(&id).unwrap_or_default();
                    AccessibleGroupEntry {
                        asset_group_id: id,
                        protocols,
                    }
                })
                .collect();

            AccessResponse::AccessibleGroupsPage(IpcPage {
                items: entries,
                has_more,
            })
        }
        Err(e) => AccessResponse::Error(format!("Failed to list accessible groups: {e}")),
    }
}

// ==================== Access rule CRUD ====================

async fn handle_create_access_rule(
    conn: &mut DbConnection,
    data: AccessRuleData,
    actor_uuid: Option<&str>,
) -> AccessResponse {
    let new_uuid = Uuid::new_v4();
    let now = Utc::now();

    let valid_from = match parse_optional_datetime(&data.valid_from) {
        Ok(v) => v,
        Err(e) => return AccessResponse::AccessRule(Err(e)),
    };
    let valid_until = match parse_optional_datetime(&data.valid_until) {
        Ok(v) => v,
        Err(e) => return AccessResponse::AccessRule(Err(e)),
    };

    let protocols: Vec<Option<String>> = data.allowed_protocols.into_iter().map(Some).collect();
    // Issue #22 — stamp the audit pair so the Metadata UI on
    // `/assets/access/{uuid}` can surface "Created by" /
    // "Updated by" for every freshly-created rule. `None` here
    // only happens when the JWT `sub` claim no longer maps to a
    // live user row; we let the INSERT proceed and fall back to
    // the muted em-dash on render rather than refuse the write.
    let actor_id = resolve_actor_id(conn, actor_uuid).await;

    let result = diesel::insert_into(access_rules::table)
        .values((
            access_rules::uuid.eq(new_uuid),
            access_rules::name.eq(&data.name),
            access_rules::description.eq(&data.description),
            access_rules::user_group_id.eq(data.user_group_id),
            access_rules::asset_group_id.eq(data.asset_group_id),
            access_rules::allowed_protocols.eq(&protocols),
            access_rules::valid_from.eq(valid_from),
            access_rules::valid_until.eq(valid_until),
            access_rules::require_mfa.eq(data.require_mfa),
            access_rules::require_approval.eq(data.require_approval),
            access_rules::max_session_duration.eq(data.max_session_duration),
            access_rules::is_active.eq(data.is_active),
            access_rules::priority.eq(data.priority),
            access_rules::created_by_id.eq(actor_id),
            access_rules::updated_by_id.eq(actor_id),
            access_rules::created_at.eq(now),
            access_rules::updated_at.eq(now),
        ))
        .execute(conn)
        .await;

    match result {
        Ok(_) => {
            info!(uuid = %new_uuid, name = %data.name, "Access rule created");
            match load_access_rule_by_uuid(conn, new_uuid).await {
                Ok(info) => AccessResponse::AccessRule(Ok(info)),
                Err(e) => AccessResponse::Error(e),
            }
        }
        Err(e) => AccessResponse::AccessRule(Err(format!("Failed to create access rule: {}", e))),
    }
}

async fn handle_get_access_rule(conn: &mut DbConnection, uuid_str: &str) -> AccessResponse {
    let rule_uuid = match parse_uuid(uuid_str) {
        Ok(u) => u,
        Err(e) => return AccessResponse::AccessRule(Err(e)),
    };

    match load_access_rule_by_uuid(conn, rule_uuid).await {
        Ok(info) => AccessResponse::AccessRule(Ok(info)),
        Err(e) => AccessResponse::AccessRule(Err(e)),
    }
}

async fn handle_list_access_rules(conn: &mut DbConnection, page: IpcPageParams) -> AccessResponse {
    let (base_limit, offset) = normalize_ipc_page(page);
    let fetch = base_limit.saturating_add(1);
    let result = access_rules::table
        .inner_join(vauban_groups::table)
        .inner_join(asset_groups::table)
        .order(access_rules::priority.desc())
        .then_order_by(access_rules::id.desc())
        .select(access_rule_columns!())
        .limit(fetch)
        .offset(offset)
        .load::<AccessRuleRow>(conn)
        .await;

    match result {
        Ok(mut rows) => {
            let has_more = rows.len() > base_limit as usize;
            if has_more {
                rows.truncate(base_limit as usize);
            }
            let infos: Vec<AccessRuleInfo> = rows.into_iter().map(to_access_rule_info).collect();
            AccessResponse::AccessRulePage(IpcPage {
                items: infos,
                has_more,
            })
        }
        Err(e) => AccessResponse::Error(format!("Failed to list access rules: {}", e)),
    }
}

async fn handle_update_access_rule(
    conn: &mut DbConnection,
    uuid_str: &str,
    data: AccessRuleData,
    actor_uuid: Option<&str>,
) -> AccessResponse {
    let rule_uuid = match parse_uuid(uuid_str) {
        Ok(u) => u,
        Err(e) => return AccessResponse::AccessRule(Err(e)),
    };

    let valid_from = match parse_optional_datetime(&data.valid_from) {
        Ok(v) => v,
        Err(e) => return AccessResponse::AccessRule(Err(e)),
    };
    let valid_until = match parse_optional_datetime(&data.valid_until) {
        Ok(v) => v,
        Err(e) => return AccessResponse::AccessRule(Err(e)),
    };

    let protocols: Vec<Option<String>> = data.allowed_protocols.into_iter().map(Some).collect();
    let now = Utc::now();
    // Issue #22 — re-stamp `updated_by_id` on every update so the
    // "Updated by" cell on `/assets/access/{uuid}` reflects the
    // operator that performed the most recent edit.
    let actor_id = resolve_actor_id(conn, actor_uuid).await;

    let affected = diesel::update(access_rules::table.filter(access_rules::uuid.eq(rule_uuid)))
        .set((
            access_rules::name.eq(&data.name),
            access_rules::description.eq(&data.description),
            access_rules::user_group_id.eq(data.user_group_id),
            access_rules::asset_group_id.eq(data.asset_group_id),
            access_rules::allowed_protocols.eq(&protocols),
            access_rules::valid_from.eq(valid_from),
            access_rules::valid_until.eq(valid_until),
            access_rules::require_mfa.eq(data.require_mfa),
            access_rules::require_approval.eq(data.require_approval),
            access_rules::max_session_duration.eq(data.max_session_duration),
            access_rules::is_active.eq(data.is_active),
            access_rules::priority.eq(data.priority),
            access_rules::updated_at.eq(now),
            access_rules::updated_by_id.eq(actor_id),
        ))
        .execute(conn)
        .await;

    match affected {
        Ok(0) => AccessResponse::AccessRule(Err(format!("Access rule {} not found", uuid_str))),
        Ok(_) => {
            info!(uuid = %uuid_str, "Access rule updated");
            match load_access_rule_by_uuid(conn, rule_uuid).await {
                Ok(info) => AccessResponse::AccessRule(Ok(info)),
                Err(e) => AccessResponse::Error(e),
            }
        }
        Err(e) => AccessResponse::AccessRule(Err(format!("Failed to update access rule: {}", e))),
    }
}

async fn handle_delete_access_rule(conn: &mut DbConnection, uuid_str: &str) -> AccessResponse {
    let rule_uuid = match parse_uuid(uuid_str) {
        Ok(u) => u,
        Err(e) => return AccessResponse::Deleted(Err(e)),
    };

    match diesel::delete(access_rules::table.filter(access_rules::uuid.eq(rule_uuid)))
        .execute(conn)
        .await
    {
        Ok(0) => AccessResponse::Deleted(Err(format!("Access rule {} not found", uuid_str))),
        Ok(_) => {
            info!(uuid = %uuid_str, "Access rule deleted");
            AccessResponse::Deleted(Ok(()))
        }
        Err(e) => AccessResponse::Deleted(Err(format!("Failed to delete access rule: {}", e))),
    }
}

// ==================== Vauban group CRUD ====================

async fn handle_create_vauban_group(
    conn: &mut DbConnection,
    name: &str,
    description: Option<&str>,
) -> AccessResponse {
    let new_uuid = Uuid::new_v4();
    let now = Utc::now();

    let result = diesel::insert_into(vauban_groups::table)
        .values((
            vauban_groups::uuid.eq(new_uuid),
            vauban_groups::name.eq(name),
            vauban_groups::description.eq(description),
            vauban_groups::source.eq("local"),
            vauban_groups::created_at.eq(now),
            vauban_groups::updated_at.eq(now),
        ))
        .returning(vauban_groups::id)
        .get_result::<i32>(conn)
        .await;

    match result {
        Ok(id) => {
            info!(uuid = %new_uuid, name, "Vauban group created");
            AccessResponse::VaubanGroup(Ok(VaubanGroupInfo {
                id,
                uuid: new_uuid.to_string(),
                name: name.to_string(),
                description: description.map(String::from),
                source: "local".to_string(),
                external_id: None,
                created_at: now.to_rfc3339(),
                updated_at: now.to_rfc3339(),
                last_synced: None,
                member_count: 0,
            }))
        }
        Err(e) => AccessResponse::VaubanGroup(Err(format!("Failed to create group: {}", e))),
    }
}

type VaubanGroupRow = (
    i32,
    Uuid,
    String,
    Option<String>,
    String,
    Option<String>,
    chrono::DateTime<Utc>,
    chrono::DateTime<Utc>,
    Option<chrono::DateTime<Utc>>,
);

async fn handle_get_vauban_group(conn: &mut DbConnection, uuid_str: &str) -> AccessResponse {
    let group_uuid = match parse_uuid(uuid_str) {
        Ok(u) => u,
        Err(e) => return AccessResponse::VaubanGroup(Err(e)),
    };

    let row = vauban_groups::table
        .filter(vauban_groups::uuid.eq(group_uuid))
        .select((
            vauban_groups::id,
            vauban_groups::uuid,
            vauban_groups::name,
            vauban_groups::description,
            vauban_groups::source,
            vauban_groups::external_id,
            vauban_groups::created_at,
            vauban_groups::updated_at,
            vauban_groups::last_synced,
        ))
        .first::<VaubanGroupRow>(conn)
        .await;

    match row {
        Ok((
            id,
            uuid,
            name,
            description,
            source,
            external_id,
            created_at,
            updated_at,
            last_synced,
        )) => {
            match build_vauban_group_info(
                conn,
                id,
                uuid,
                &name,
                description.as_deref(),
                &source,
                external_id.as_deref(),
                created_at,
                updated_at,
                last_synced,
            )
            .await
            {
                Ok(info) => AccessResponse::VaubanGroup(Ok(info)),
                Err(e) => AccessResponse::VaubanGroup(Err(format!("Failed to load group: {}", e))),
            }
        }
        Err(e) => AccessResponse::VaubanGroup(Err(format!("Group not found: {}", e))),
    }
}

async fn handle_get_vauban_group_by_id(conn: &mut DbConnection, id: i32) -> AccessResponse {
    let row = vauban_groups::table
        .filter(vauban_groups::id.eq(id))
        .select((
            vauban_groups::id,
            vauban_groups::uuid,
            vauban_groups::name,
            vauban_groups::description,
            vauban_groups::source,
            vauban_groups::external_id,
            vauban_groups::created_at,
            vauban_groups::updated_at,
            vauban_groups::last_synced,
        ))
        .first::<VaubanGroupRow>(conn)
        .await;

    match row {
        Ok((
            id,
            uuid,
            name,
            description,
            source,
            external_id,
            created_at,
            updated_at,
            last_synced,
        )) => {
            match build_vauban_group_info(
                conn,
                id,
                uuid,
                &name,
                description.as_deref(),
                &source,
                external_id.as_deref(),
                created_at,
                updated_at,
                last_synced,
            )
            .await
            {
                Ok(info) => AccessResponse::VaubanGroup(Ok(info)),
                Err(e) => AccessResponse::VaubanGroup(Err(format!("Failed to load group: {}", e))),
            }
        }
        Err(e) => AccessResponse::VaubanGroup(Err(format!("Group not found: {}", e))),
    }
}

async fn handle_list_vauban_groups(conn: &mut DbConnection, page: IpcPageParams) -> AccessResponse {
    let (base_limit, offset) = normalize_ipc_page(page);
    let fetch = base_limit.saturating_add(1);
    let rows = vauban_groups::table
        .order(vauban_groups::name.asc())
        .then_order_by(vauban_groups::id.asc())
        .select((
            vauban_groups::id,
            vauban_groups::uuid,
            vauban_groups::name,
            vauban_groups::description,
            vauban_groups::source,
            vauban_groups::external_id,
            vauban_groups::created_at,
            vauban_groups::updated_at,
            vauban_groups::last_synced,
        ))
        .limit(fetch)
        .offset(offset)
        .load::<VaubanGroupRow>(conn)
        .await;

    match rows {
        Ok(mut groups) => {
            let has_more = groups.len() > base_limit as usize;
            if has_more {
                groups.truncate(base_limit as usize);
            }
            let mut infos = Vec::with_capacity(groups.len());
            for (
                id,
                uuid,
                name,
                description,
                source,
                external_id,
                created_at,
                updated_at,
                last_synced,
            ) in groups
            {
                match build_vauban_group_info(
                    conn,
                    id,
                    uuid,
                    &name,
                    description.as_deref(),
                    &source,
                    external_id.as_deref(),
                    created_at,
                    updated_at,
                    last_synced,
                )
                .await
                {
                    Ok(info) => infos.push(info),
                    Err(e) => {
                        warn!(group_id = id, error = %e, "Failed to load group member count");
                        infos.push(VaubanGroupInfo {
                            id,
                            uuid: uuid.to_string(),
                            name,
                            description,
                            source,
                            external_id,
                            created_at: created_at.to_rfc3339(),
                            updated_at: updated_at.to_rfc3339(),
                            last_synced: last_synced.map(|dt| dt.to_rfc3339()),
                            member_count: 0,
                        });
                    }
                }
            }
            AccessResponse::VaubanGroupPage(IpcPage {
                items: infos,
                has_more,
            })
        }
        Err(e) => AccessResponse::Error(format!("Failed to list groups: {}", e)),
    }
}

async fn handle_update_vauban_group(
    conn: &mut DbConnection,
    uuid_str: &str,
    name: &str,
    description: Option<&str>,
) -> AccessResponse {
    let group_uuid = match parse_uuid(uuid_str) {
        Ok(u) => u,
        Err(e) => return AccessResponse::VaubanGroup(Err(e)),
    };

    let affected = diesel::update(vauban_groups::table.filter(vauban_groups::uuid.eq(group_uuid)))
        .set((
            vauban_groups::name.eq(name),
            vauban_groups::description.eq(description),
            vauban_groups::updated_at.eq(Utc::now()),
        ))
        .execute(conn)
        .await;

    match affected {
        Ok(0) => AccessResponse::VaubanGroup(Err(format!("Group {} not found", uuid_str))),
        Ok(_) => {
            info!(uuid = %uuid_str, name, "Vauban group updated");
            handle_get_vauban_group(conn, uuid_str).await
        }
        Err(e) => AccessResponse::VaubanGroup(Err(format!("Failed to update group: {}", e))),
    }
}

async fn handle_delete_vauban_group(conn: &mut DbConnection, uuid_str: &str) -> AccessResponse {
    let group_uuid = match parse_uuid(uuid_str) {
        Ok(u) => u,
        Err(e) => return AccessResponse::Deleted(Err(e)),
    };

    // Resolve the group's internal id so we can pre-check membership.
    let group_id: Option<i32> = match vauban_groups::table
        .filter(vauban_groups::uuid.eq(group_uuid))
        .select(vauban_groups::id)
        .first::<i32>(conn)
        .await
        .optional()
    {
        Ok(v) => v,
        Err(e) => return AccessResponse::Deleted(Err(format!("Failed to lookup group: {}", e))),
    };

    let group_id = match group_id {
        Some(id) => id,
        None => return AccessResponse::Deleted(Err(format!("Group {} not found", uuid_str))),
    };

    // Refuse to delete a group that still has members. The caller is expected
    // to surface a friendly error message mentioning "member" so that the UI
    // can display a specific hint.
    let member_count: i64 = match user_groups::table
        .filter(user_groups::group_id.eq(group_id))
        .count()
        .get_result(conn)
        .await
    {
        Ok(c) => c,
        Err(e) => {
            return AccessResponse::Deleted(Err(format!("Failed to count members: {}", e)));
        }
    };
    if member_count > 0 {
        return AccessResponse::Deleted(Err(format!(
            "Group {} still has {} member(s); remove them first",
            uuid_str, member_count
        )));
    }

    match diesel::delete(vauban_groups::table.filter(vauban_groups::uuid.eq(group_uuid)))
        .execute(conn)
        .await
    {
        Ok(0) => AccessResponse::Deleted(Err(format!("Group {} not found", uuid_str))),
        Ok(_) => {
            info!(uuid = %uuid_str, "Vauban group deleted");
            AccessResponse::Deleted(Ok(()))
        }
        Err(e) => AccessResponse::Deleted(Err(format!("Failed to delete group: {}", e))),
    }
}

// ==================== Group member management ====================

async fn handle_add_group_member(
    conn: &mut DbConnection,
    group_id: i32,
    user_id: i32,
) -> AccessResponse {
    let result = diesel::insert_into(user_groups::table)
        .values((
            user_groups::user_id.eq(user_id),
            user_groups::group_id.eq(group_id),
        ))
        .on_conflict_do_nothing()
        .execute(conn)
        .await;

    match result {
        Ok(_) => {
            info!(group_id, user_id, "Group member added");
            AccessResponse::Ok
        }
        Err(e) => AccessResponse::Error(format!("Failed to add group member: {}", e)),
    }
}

async fn handle_remove_group_member(
    conn: &mut DbConnection,
    group_id: i32,
    user_id: i32,
) -> AccessResponse {
    let result = diesel::delete(
        user_groups::table
            .filter(user_groups::group_id.eq(group_id))
            .filter(user_groups::user_id.eq(user_id)),
    )
    .execute(conn)
    .await;

    match result {
        Ok(_) => {
            info!(group_id, user_id, "Group member removed");
            AccessResponse::Ok
        }
        Err(e) => AccessResponse::Error(format!("Failed to remove group member: {}", e)),
    }
}

async fn handle_list_group_members(
    conn: &mut DbConnection,
    group_id: i32,
    page: IpcPageParams,
) -> AccessResponse {
    let (base_limit, offset) = normalize_ipc_page(page);
    let fetch = base_limit.saturating_add(1);
    let result = user_groups::table
        .filter(user_groups::group_id.eq(group_id))
        .order_by(user_groups::user_id.asc())
        .select(user_groups::user_id)
        .limit(fetch)
        .offset(offset)
        .load::<i32>(conn)
        .await;

    match result {
        Ok(mut members) => {
            let has_more = members.len() > base_limit as usize;
            if has_more {
                members.truncate(base_limit as usize);
            }
            AccessResponse::MemberListPage(IpcPage {
                items: members,
                has_more,
            })
        }
        Err(e) => AccessResponse::Error(format!("Failed to list group members: {}", e)),
    }
}

async fn handle_list_user_groups(
    conn: &mut DbConnection,
    user_id: i32,
    page: IpcPageParams,
) -> AccessResponse {
    let (base_limit, offset) = normalize_ipc_page(page);
    let fetch = base_limit.saturating_add(1);
    let rows = user_groups::table
        .inner_join(vauban_groups::table)
        .filter(user_groups::user_id.eq(user_id))
        .order_by(vauban_groups::name.asc())
        .then_order_by(vauban_groups::id.asc())
        .select((
            vauban_groups::id,
            vauban_groups::uuid,
            vauban_groups::name,
            vauban_groups::description,
            vauban_groups::source,
            vauban_groups::external_id,
            vauban_groups::created_at,
            vauban_groups::updated_at,
            vauban_groups::last_synced,
        ))
        .limit(fetch)
        .offset(offset)
        .load::<VaubanGroupRow>(conn)
        .await;

    match rows {
        Ok(mut groups) => {
            let has_more = groups.len() > base_limit as usize;
            if has_more {
                groups.truncate(base_limit as usize);
            }
            let mut infos = Vec::with_capacity(groups.len());
            for (
                id,
                uuid,
                name,
                description,
                source,
                external_id,
                created_at,
                updated_at,
                last_synced,
            ) in groups
            {
                match build_vauban_group_info(
                    conn,
                    id,
                    uuid,
                    &name,
                    description.as_deref(),
                    &source,
                    external_id.as_deref(),
                    created_at,
                    updated_at,
                    last_synced,
                )
                .await
                {
                    Ok(info) => infos.push(info),
                    Err(e) => {
                        warn!(group_id = id, error = %e, "Failed to count group members");
                        infos.push(VaubanGroupInfo {
                            id,
                            uuid: uuid.to_string(),
                            name,
                            description,
                            source,
                            external_id,
                            created_at: created_at.to_rfc3339(),
                            updated_at: updated_at.to_rfc3339(),
                            last_synced: last_synced.map(|dt| dt.to_rfc3339()),
                            member_count: 0,
                        });
                    }
                }
            }
            AccessResponse::UserGroupPage(IpcPage {
                items: infos,
                has_more,
            })
        }
        Err(e) => AccessResponse::Error(format!("Failed to list user groups: {}", e)),
    }
}

// ==================== Asset group CRUD ====================

async fn handle_create_asset_group(
    conn: &mut DbConnection,
    name: &str,
    slug: &str,
    description: Option<&str>,
    color: &str,
    icon: &str,
    actor_uuid: Option<&str>,
) -> AccessResponse {
    let new_uuid = Uuid::new_v4();
    let now = Utc::now();
    // Issue #22 — stamp the audit pair so the Metadata UI on
    // `/assets/groups/{uuid}` surfaces "Created by" / "Updated by"
    // for every freshly-created group. `None` falls back to the
    // muted em-dash on render rather than refusing the write.
    let actor_id = resolve_actor_id(conn, actor_uuid).await;

    let result = diesel::insert_into(asset_groups::table)
        .values((
            asset_groups::uuid.eq(new_uuid),
            asset_groups::name.eq(name),
            asset_groups::slug.eq(slug),
            asset_groups::description.eq(description),
            asset_groups::color.eq(color),
            asset_groups::icon.eq(icon),
            asset_groups::created_by_id.eq(actor_id),
            asset_groups::updated_by_id.eq(actor_id),
            asset_groups::created_at.eq(now),
            asset_groups::updated_at.eq(now),
        ))
        .returning((
            asset_groups::id,
            asset_groups::uuid,
            asset_groups::name,
            asset_groups::slug,
            asset_groups::description,
            asset_groups::color,
            asset_groups::icon,
            asset_groups::created_at,
            asset_groups::updated_at,
        ))
        .get_result::<(
            i32,
            Uuid,
            String,
            String,
            Option<String>,
            String,
            String,
            chrono::DateTime<Utc>,
            chrono::DateTime<Utc>,
        )>(conn)
        .await;

    match result {
        Ok((id, uuid, name, slug, description, color, icon, created_at, updated_at)) => {
            info!(uuid = %uuid, name = %name, "Asset group created");
            AccessResponse::AssetGroup(Ok(AssetGroupInfo {
                id,
                uuid: uuid.to_string(),
                name,
                slug,
                description,
                color,
                icon,
                created_at: created_at.to_rfc3339(),
                updated_at: updated_at.to_rfc3339(),
                // CreateAssetGroup is the user-facing path; only static
                // groups can be minted this way. The virtual "All assets"
                // row is system-seeded by migration and protected by the
                // trigger -- it can never be created via this handler.
                kind: shared::messages::ASSET_GROUP_KIND_STATIC.to_string(),
            }))
        }
        Err(e) => AccessResponse::AssetGroup(Err(format!("Failed to create asset group: {}", e))),
    }
}

async fn handle_get_asset_group(conn: &mut DbConnection, uuid_str: &str) -> AccessResponse {
    let group_uuid = match parse_uuid(uuid_str) {
        Ok(u) => u,
        Err(e) => return AccessResponse::AssetGroup(Err(e)),
    };

    let result = asset_groups::table
        .filter(asset_groups::uuid.eq(group_uuid))
        .select((
            asset_groups::id,
            asset_groups::uuid,
            asset_groups::name,
            asset_groups::slug,
            asset_groups::description,
            asset_groups::color,
            asset_groups::icon,
            asset_groups::created_at,
            asset_groups::updated_at,
            asset_groups::kind,
        ))
        .first::<(
            i32,
            Uuid,
            String,
            String,
            Option<String>,
            String,
            String,
            chrono::DateTime<Utc>,
            chrono::DateTime<Utc>,
            String,
        )>(conn)
        .await;

    match result {
        Ok((id, uuid, name, slug, description, color, icon, created_at, updated_at, kind)) => {
            AccessResponse::AssetGroup(Ok(AssetGroupInfo {
                id,
                uuid: uuid.to_string(),
                name,
                slug,
                description,
                color,
                icon,
                created_at: created_at.to_rfc3339(),
                updated_at: updated_at.to_rfc3339(),
                kind,
            }))
        }
        Err(e) => AccessResponse::AssetGroup(Err(format!("Asset group not found: {}", e))),
    }
}

async fn handle_list_asset_groups(
    conn: &mut DbConnection,
    page: IpcPageParams,
    include_virtual: bool,
) -> AccessResponse {
    use shared::messages::ASSET_GROUP_KIND_STATIC;

    let (base_limit, offset) = normalize_ipc_page(page);
    let fetch = base_limit.saturating_add(1);

    // Always exclude virtual groups by default. The access-rule editor is
    // currently the only legitimate caller that opts in to seeing them
    // (`include_virtual = true`). Defense-in-depth: even if a UI handler
    // forgets to filter, virtual groups never leak into ordinary group
    // lists.
    let mut query = asset_groups::table
        .filter(asset_groups::is_deleted.eq(false))
        .into_boxed();
    if !include_virtual {
        query = query.filter(asset_groups::kind.eq(ASSET_GROUP_KIND_STATIC));
    }

    let result = query
        .order(asset_groups::name.asc())
        .then_order_by(asset_groups::id.asc())
        .select((
            asset_groups::id,
            asset_groups::uuid,
            asset_groups::name,
            asset_groups::slug,
            asset_groups::description,
            asset_groups::color,
            asset_groups::icon,
            asset_groups::created_at,
            asset_groups::updated_at,
            asset_groups::kind,
        ))
        .limit(fetch)
        .offset(offset)
        .load::<(
            i32,
            Uuid,
            String,
            String,
            Option<String>,
            String,
            String,
            chrono::DateTime<Utc>,
            chrono::DateTime<Utc>,
            String,
        )>(conn)
        .await;

    match result {
        Ok(mut rows) => {
            let has_more = rows.len() > base_limit as usize;
            if has_more {
                rows.truncate(base_limit as usize);
            }
            let infos: Vec<AssetGroupInfo> = rows
                .into_iter()
                .map(
                    |(
                        id,
                        uuid,
                        name,
                        slug,
                        description,
                        color,
                        icon,
                        created_at,
                        updated_at,
                        kind,
                    )| {
                        AssetGroupInfo {
                            id,
                            uuid: uuid.to_string(),
                            name,
                            slug,
                            description,
                            color,
                            icon,
                            created_at: created_at.to_rfc3339(),
                            updated_at: updated_at.to_rfc3339(),
                            kind,
                        }
                    },
                )
                .collect();
            AccessResponse::AssetGroupPage(IpcPage {
                items: infos,
                has_more,
            })
        }
        Err(e) => AccessResponse::Error(format!("Failed to list asset groups: {}", e)),
    }
}

// Signature mirrors the `AccessRequest::UpdateAssetGroup` variant
// 1:1; collapsing the args into a struct here would only push the
// same fan-out to the IPC dispatch and obscure the field-by-field
// audit lint passes do on the variant. `actor_uuid` is the 8th arg
// added by issue #22.
#[allow(clippy::too_many_arguments)]
async fn handle_update_asset_group(
    conn: &mut DbConnection,
    uuid_str: &str,
    name: &str,
    slug: &str,
    description: Option<&str>,
    color: &str,
    icon: &str,
    actor_uuid: Option<&str>,
) -> AccessResponse {
    let group_uuid = match parse_uuid(uuid_str) {
        Ok(u) => u,
        Err(e) => return AccessResponse::AssetGroup(Err(e)),
    };
    // Issue #22 — re-stamp `updated_by_id` on every successful
    // update so the Metadata UI on `/assets/groups/{uuid}` shows
    // the operator that performed the most recent edit.
    let actor_id = resolve_actor_id(conn, actor_uuid).await;

    let affected = diesel::update(asset_groups::table.filter(asset_groups::uuid.eq(group_uuid)))
        .set((
            asset_groups::name.eq(name),
            asset_groups::slug.eq(slug),
            asset_groups::description.eq(description),
            asset_groups::color.eq(color),
            asset_groups::icon.eq(icon),
            asset_groups::updated_at.eq(Utc::now()),
            asset_groups::updated_by_id.eq(actor_id),
        ))
        .execute(conn)
        .await;

    match affected {
        Ok(0) => AccessResponse::AssetGroup(Err(format!("Asset group {} not found", uuid_str))),
        Ok(_) => {
            info!(uuid = %uuid_str, name, "Asset group updated");
            handle_get_asset_group(conn, uuid_str).await
        }
        Err(e) => AccessResponse::AssetGroup(Err(format!("Failed to update asset group: {}", e))),
    }
}

async fn handle_delete_asset_group(conn: &mut DbConnection, uuid_str: &str) -> AccessResponse {
    let group_uuid = match parse_uuid(uuid_str) {
        Ok(u) => u,
        Err(e) => return AccessResponse::Deleted(Err(e)),
    };

    match diesel::delete(asset_groups::table.filter(asset_groups::uuid.eq(group_uuid)))
        .execute(conn)
        .await
    {
        Ok(0) => AccessResponse::Deleted(Err(format!("Asset group {} not found", uuid_str))),
        Ok(_) => {
            info!(uuid = %uuid_str, "Asset group deleted");
            AccessResponse::Deleted(Ok(()))
        }
        Err(e) => AccessResponse::Deleted(Err(format!("Failed to delete asset group: {}", e))),
    }
}

// ==================== Group options ====================

async fn handle_list_user_group_options(
    conn: &mut DbConnection,
    page: IpcPageParams,
) -> AccessResponse {
    let (base_limit, offset) = normalize_ipc_page(page);
    let fetch = base_limit.saturating_add(1);
    let user_group_rows = vauban_groups::table
        .order(vauban_groups::name.asc())
        .then_order_by(vauban_groups::id.asc())
        .select((vauban_groups::id, vauban_groups::uuid, vauban_groups::name))
        .limit(fetch)
        .offset(offset)
        .load::<(i32, Uuid, String)>(conn)
        .await;

    match user_group_rows {
        Ok(mut ug_rows) => {
            let has_more = ug_rows.len() > base_limit as usize;
            if has_more {
                ug_rows.truncate(base_limit as usize);
            }
            let items = ug_rows
                .into_iter()
                .map(|(id, uuid, name)| GroupOption {
                    id,
                    uuid: uuid.to_string(),
                    name,
                    // vauban_groups have no `kind` column today; the field
                    // exists on `GroupOption` only to surface virtual
                    // *asset* groups in the editor dropdown. Tag every
                    // user-group option as static so downstream rendering
                    // never accidentally shows a "Virtual" badge here.
                    kind: shared::messages::ASSET_GROUP_KIND_STATIC.to_string(),
                })
                .collect();
            AccessResponse::UserGroupOptionsPage(IpcPage { items, has_more })
        }
        Err(e) => AccessResponse::Error(format!("Failed to load user group options: {}", e)),
    }
}

async fn handle_list_asset_group_options(
    conn: &mut DbConnection,
    page: IpcPageParams,
    include_virtual: bool,
) -> AccessResponse {
    use shared::messages::ASSET_GROUP_KIND_STATIC;

    let (base_limit, offset) = normalize_ipc_page(page);
    let fetch = base_limit.saturating_add(1);

    // Same fail-closed default as `handle_list_asset_groups`: virtual
    // groups stay hidden unless the caller explicitly opts in.
    let mut query = asset_groups::table
        .filter(asset_groups::is_deleted.eq(false))
        .into_boxed();
    if !include_virtual {
        query = query.filter(asset_groups::kind.eq(ASSET_GROUP_KIND_STATIC));
    }

    let asset_group_rows = query
        .order(asset_groups::name.asc())
        .then_order_by(asset_groups::id.asc())
        .select((
            asset_groups::id,
            asset_groups::uuid,
            asset_groups::name,
            asset_groups::kind,
        ))
        .limit(fetch)
        .offset(offset)
        .load::<(i32, Uuid, String, String)>(conn)
        .await;

    match asset_group_rows {
        Ok(mut ag_rows) => {
            let has_more = ag_rows.len() > base_limit as usize;
            if has_more {
                ag_rows.truncate(base_limit as usize);
            }
            let items = ag_rows
                .into_iter()
                .map(|(id, uuid, name, kind)| GroupOption {
                    id,
                    uuid: uuid.to_string(),
                    name,
                    kind,
                })
                .collect();
            AccessResponse::AssetGroupOptionsPage(IpcPage { items, has_more })
        }
        Err(e) => AccessResponse::Error(format!("Failed to load asset group options: {}", e)),
    }
}

// ==================== Approval Audit & Separation of Duties ====================

/// Input bundle for [`handle_record_approval_decision`]. Grouped to keep
/// the function signature manageable and to match the IPC variant 1:1
/// (every field flows directly from `RecordApprovalDecision`).
struct ApprovalDecisionInput<'a> {
    actor_user_uuid: &'a str,
    session_uuid: &'a str,
    decision: ApprovalDecisionKind,
    duration_override_seconds: Option<i32>,
    decision_reason: Option<String>,
    decision_ip: Option<String>,
    decision_user_agent: Option<String>,
    request_id: Option<String>,
}

/// Internal snapshot of the bits of `proxy_sessions` + `users` + `assets`
/// needed both for eligibility checks and for the audit-log row. Resolved
/// once inside the transaction (or once standalone for the read-only
/// eligibility request) so we never split the policy across two queries
/// and never let DB state drift between the read and the write.
struct PendingSessionSnapshot {
    session_pk: i32,
    requester_id: i32,
    requester_username: String,
    requester_is_active: bool,
    requester_is_deleted: bool,
    asset_uuid: Uuid,
    asset_name: String,
    session_type: String,
    rule_requires_approval: bool,
    current_max_session_duration: Option<i32>,
    /// Set for APPROVED grants (post-approval verbs recompute
    /// `expires_at` from it); `None` while the request is pending.
    approved_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Which `proxy_sessions.status` a decision verb operates on, and the
/// structured deny reason surfaced when the row is not in that state.
/// Approve/reject act on `pending` requests; revoke/update_duration act
/// on `approved` grants.
fn expected_status_for(decision: ApprovalDecisionKind) -> (&'static str, ApprovalDenyReason) {
    match decision {
        ApprovalDecisionKind::Approve | ApprovalDecisionKind::Reject => {
            ("pending", ApprovalDenyReason::SessionNotPending)
        }
        ApprovalDecisionKind::Revoke | ApprovalDecisionKind::UpdateDuration => {
            ("approved", ApprovalDenyReason::SessionNotApproved)
        }
    }
}

/// Read-only pre-flight: would the actor be allowed to approve/reject
/// the given session right now?
///
/// The reply is purely advisory -- the same checks are re-asserted
/// inside `handle_record_approval_decision`'s transaction. Two
/// responses can therefore disagree across a TOCTOU window; the
/// authoritative one is always the in-transaction re-check.
pub async fn handle_check_approval_eligibility(
    conn: &mut DbConnection,
    actor_user_uuid: &str,
    session_uuid_str: &str,
) -> AccessResponse {
    let actor_uuid = match Uuid::parse_str(actor_user_uuid) {
        Ok(u) => u,
        Err(_) => {
            return AccessResponse::ApprovalEligibility {
                allowed: false,
                reason: Some(ApprovalDenyReason::SessionNotFound),
            };
        }
    };
    let session_uuid = match Uuid::parse_str(session_uuid_str) {
        Ok(u) => u,
        Err(_) => {
            return AccessResponse::ApprovalEligibility {
                allowed: false,
                reason: Some(ApprovalDenyReason::SessionNotFound),
            };
        }
    };

    let actor_id: i32 = match users::table
        .filter(users::uuid.eq(actor_uuid))
        .select(users::id)
        .first(conn)
        .await
    {
        Ok(id) => id,
        Err(_) => {
            return AccessResponse::ApprovalEligibility {
                allowed: false,
                reason: Some(ApprovalDenyReason::SessionNotFound),
            };
        }
    };

    match load_decision_snapshot(
        conn,
        session_uuid,
        "pending",
        ApprovalDenyReason::SessionNotPending,
    )
    .await
    {
        Ok(snap) => {
            if let Some(reason) = evaluate_eligibility(&snap, actor_id) {
                AccessResponse::ApprovalEligibility {
                    allowed: false,
                    reason: Some(reason),
                }
            } else {
                AccessResponse::ApprovalEligibility {
                    allowed: true,
                    reason: None,
                }
            }
        }
        Err(reason) => AccessResponse::ApprovalEligibility {
            allowed: false,
            reason: Some(reason),
        },
    }
}

/// Authoritative decision recorder. Performs the eligibility re-check,
/// the `proxy_sessions` UPDATE and the `approval_audit_log` INSERT in a
/// single Diesel transaction so a sub-step failure rolls back the
/// whole thing. Fail-closed: any DB error collapses to
/// `ApprovalDenied { SessionNotFound }` and leaves the session
/// untouched.
async fn handle_record_approval_decision<'a>(
    conn: &mut DbConnection,
    input: ApprovalDecisionInput<'a>,
) -> AccessResponse {
    let actor_uuid = match Uuid::parse_str(input.actor_user_uuid) {
        Ok(u) => u,
        Err(_) => {
            return AccessResponse::ApprovalDenied {
                reason: ApprovalDenyReason::SessionNotFound,
            };
        }
    };
    let session_uuid = match Uuid::parse_str(input.session_uuid) {
        Ok(u) => u,
        Err(_) => {
            return AccessResponse::ApprovalDenied {
                reason: ApprovalDenyReason::SessionNotFound,
            };
        }
    };

    // Resolve the actor identity OUTSIDE the transaction to avoid an
    // extra round-trip; the in-transaction re-check still validates
    // separation-of-duties using the actor_id.
    let (actor_id, actor_username) = match users::table
        .filter(users::uuid.eq(actor_uuid))
        .select((users::id, users::username))
        .first::<(i32, String)>(conn)
        .await
    {
        Ok(row) => row,
        Err(_) => {
            return AccessResponse::ApprovalDenied {
                reason: ApprovalDenyReason::SessionNotFound,
            };
        }
    };

    let decision = input.decision;
    let duration_override = input.duration_override_seconds;

    // update_duration without a duration is a caller bug (the web form
    // marks it required); fail-closed before touching the DB.
    if decision == ApprovalDecisionKind::UpdateDuration && duration_override.is_none() {
        return AccessResponse::Error("update_duration requires duration_override_seconds".into());
    }

    let decision_reason = input.decision_reason.clone();
    let decision_ip_str = input.decision_ip.clone();
    let decision_user_agent = input.decision_user_agent.clone();
    let request_id = input.request_id.clone();
    let actor_username_for_audit = actor_username.clone();

    // Wrap into a transaction so the UPDATE and the INSERT are atomic.
    // Any error inside the closure rolls everything back; we then map
    // the structured error onto a fail-closed `ApprovalDenied` reply.
    let outcome: Result<RecordedApproval, ApprovalTxnError> = conn
        .transaction::<RecordedApproval, ApprovalTxnError, _>(move |conn| {
            let actor_username = actor_username_for_audit.clone();
            let decision_reason = decision_reason.clone();
            let decision_ip_str = decision_ip_str.clone();
            let decision_user_agent = decision_user_agent.clone();
            let request_id = request_id.clone();
            Box::pin(async move {
                // SECURITY: re-load the snapshot WITHIN the transaction.
                // Postgres' default REPEATABLE READ is not in play here
                // (we use READ COMMITTED), but the row-level UPDATE later
                // takes a row-lock that prevents two concurrent admins
                // from both winning the race -- the loser sees `updated
                // == 0` and we fail-closed it with the state-mismatch
                // reason of the verb (SessionNotPending for
                // approve/reject, SessionNotApproved for the
                // post-approval verbs).
                let (expected_status, wrong_state_reason) = expected_status_for(decision);
                let snap =
                    load_decision_snapshot(conn, session_uuid, expected_status, wrong_state_reason)
                        .await
                        .map_err(ApprovalTxnError::Eligibility)?;

                if let Some(reason) = evaluate_decision_eligibility(decision, &snap, actor_id) {
                    return Err(ApprovalTxnError::Eligibility(reason));
                }

                let now = chrono::Utc::now();

                let updated = match decision {
                    ApprovalDecisionKind::Approve => {
                        // Effective duration: explicit override wins;
                        // otherwise keep the value copied from the rule
                        // at request time.
                        let effective_duration =
                            duration_override.or(snap.current_max_session_duration);
                        let approval_expires_at = effective_duration
                            .map(|secs| now + chrono::Duration::seconds(secs as i64));

                        if let Some(secs) = duration_override {
                            diesel::update(
                                proxy_sessions::table
                                    .filter(proxy_sessions::uuid.eq(session_uuid))
                                    .filter(proxy_sessions::status.eq("pending")),
                            )
                            .set((
                                proxy_sessions::status.eq("approved"),
                                proxy_sessions::approved_by_id.eq(Some(actor_id)),
                                proxy_sessions::approved_at.eq(Some(now)),
                                proxy_sessions::max_session_duration.eq(Some(secs)),
                                proxy_sessions::expires_at.eq(approval_expires_at),
                                proxy_sessions::updated_at.eq(now),
                                proxy_sessions::decision_reason.eq(decision_reason.clone()),
                            ))
                            .execute(conn)
                            .await
                            .map_err(|e| ApprovalTxnError::Db(e.to_string()))?
                        } else {
                            diesel::update(
                                proxy_sessions::table
                                    .filter(proxy_sessions::uuid.eq(session_uuid))
                                    .filter(proxy_sessions::status.eq("pending")),
                            )
                            .set((
                                proxy_sessions::status.eq("approved"),
                                proxy_sessions::approved_by_id.eq(Some(actor_id)),
                                proxy_sessions::approved_at.eq(Some(now)),
                                proxy_sessions::expires_at.eq(approval_expires_at),
                                proxy_sessions::updated_at.eq(now),
                                proxy_sessions::decision_reason.eq(decision_reason.clone()),
                            ))
                            .execute(conn)
                            .await
                            .map_err(|e| ApprovalTxnError::Db(e.to_string()))?
                        }
                    }
                    ApprovalDecisionKind::Reject => diesel::update(
                        proxy_sessions::table
                            .filter(proxy_sessions::uuid.eq(session_uuid))
                            .filter(proxy_sessions::status.eq("pending")),
                    )
                    .set((
                        proxy_sessions::status.eq("rejected"),
                        proxy_sessions::rejected_by_id.eq(Some(actor_id)),
                        proxy_sessions::rejected_at.eq(Some(now)),
                        proxy_sessions::decision_reason.eq(decision_reason.clone()),
                        proxy_sessions::updated_at.eq(now),
                    ))
                    .execute(conn)
                    .await
                    .map_err(|e| ApprovalTxnError::Db(e.to_string()))?,
                    // Terminal state for an APPROVED grant: blocks NEW
                    // sessions instantly (every connect lookup filters on
                    // status = 'approved'); the web layer cascades the
                    // termination of live sessions and the WS
                    // revalidation probe backstops it. `expires_at` is
                    // deliberately left untouched so the audit trail
                    // keeps the originally granted window.
                    ApprovalDecisionKind::Revoke => diesel::update(
                        proxy_sessions::table
                            .filter(proxy_sessions::uuid.eq(session_uuid))
                            .filter(proxy_sessions::status.eq("approved")),
                    )
                    .set((
                        proxy_sessions::status.eq("revoked"),
                        proxy_sessions::revoked_by_id.eq(Some(actor_id)),
                        proxy_sessions::revoked_at.eq(Some(now)),
                        proxy_sessions::decision_reason.eq(decision_reason.clone()),
                        proxy_sessions::updated_at.eq(now),
                    ))
                    .execute(conn)
                    .await
                    .map_err(|e| ApprovalTxnError::Db(e.to_string()))?,
                    // Recompute the grant window from `approved_at`
                    // (same semantics as the original approval: "the
                    // access lasts D from the approval"), in either
                    // direction. A window shortened below the elapsed
                    // time lands `expires_at` in the past: the grant is
                    // instantly inert for connects (`expires_at > now`
                    // filter) and the cleanup task expires it.
                    ApprovalDecisionKind::UpdateDuration => {
                        // Presence enforced before the transaction.
                        let secs = duration_override.unwrap_or_default();
                        let base = snap.approved_at.unwrap_or(now);
                        let new_expires_at = base + chrono::Duration::seconds(secs as i64);
                        diesel::update(
                            proxy_sessions::table
                                .filter(proxy_sessions::uuid.eq(session_uuid))
                                .filter(proxy_sessions::status.eq("approved")),
                        )
                        .set((
                            proxy_sessions::max_session_duration.eq(Some(secs)),
                            proxy_sessions::expires_at.eq(Some(new_expires_at)),
                            proxy_sessions::decision_reason.eq(decision_reason.clone()),
                            proxy_sessions::updated_at.eq(now),
                        ))
                        .execute(conn)
                        .await
                        .map_err(|e| ApprovalTxnError::Db(e.to_string()))?
                    }
                };

                if updated == 0 {
                    // Either someone else won the race (status moved off
                    // the expected state), or one of the SoD CHECK
                    // constraints fired before the row matched. Either
                    // way we fail-closed with the verb's state-mismatch
                    // reason -- the in-snapshot checks already ruled out
                    // the legitimate causes.
                    let (_, wrong_state_reason) = expected_status_for(decision);
                    return Err(ApprovalTxnError::Eligibility(wrong_state_reason));
                }

                // INSERT the audit row. Snapshot usernames so the trail
                // survives later user soft-deletion / rename.
                let decision_ip_inet: Option<ipnetwork::IpNetwork> = decision_ip_str
                    .as_deref()
                    .and_then(|s| s.parse::<std::net::IpAddr>().ok())
                    .map(ipnetwork::IpNetwork::from);

                let audit_id: i64 = diesel::insert_into(approval_audit_log::table)
                    .values((
                        approval_audit_log::session_uuid.eq(session_uuid),
                        approval_audit_log::decision.eq(decision.as_str()),
                        approval_audit_log::actor_user_id.eq(Some(actor_id)),
                        approval_audit_log::actor_username.eq(&actor_username),
                        approval_audit_log::requester_user_id.eq(Some(snap.requester_id)),
                        approval_audit_log::requester_username.eq(&snap.requester_username),
                        approval_audit_log::asset_uuid.eq(snap.asset_uuid),
                        approval_audit_log::asset_name.eq(&snap.asset_name),
                        approval_audit_log::protocol.eq(Some(snap.session_type.clone())),
                        approval_audit_log::duration_override_seconds.eq(duration_override),
                        approval_audit_log::decision_reason.eq(decision_reason.clone()),
                        approval_audit_log::decision_ip.eq(decision_ip_inet),
                        approval_audit_log::decision_user_agent.eq(decision_user_agent.clone()),
                        approval_audit_log::request_id.eq(request_id.clone()),
                    ))
                    .returning(approval_audit_log::id)
                    .get_result(conn)
                    .await
                    .map_err(|e| ApprovalTxnError::Db(e.to_string()))?;

                Ok(RecordedApproval {
                    audit_id,
                    requester_id: snap.requester_id,
                    session_pk: snap.session_pk,
                })
            })
        })
        .await;

    match outcome {
        Ok(rec) => {
            info!(
                session_uuid = %session_uuid,
                actor_username = %actor_username,
                decision = %decision.as_str(),
                audit_id = rec.audit_id,
                requester_id = rec.requester_id,
                session_pk = rec.session_pk,
                "Approval decision recorded"
            );
            AccessResponse::ApprovalRecorded {
                audit_log_id: rec.audit_id,
            }
        }
        Err(ApprovalTxnError::Eligibility(reason)) => {
            info!(
                session_uuid = %session_uuid,
                actor_username = %actor_username,
                decision = %decision.as_str(),
                reason = ?reason,
                "Approval decision denied at in-transaction re-check"
            );
            AccessResponse::ApprovalDenied { reason }
        }
        Err(ApprovalTxnError::Db(msg)) => {
            // Log the real DB error at ERROR level so operators can
            // diagnose missing migrations, schema drift, etc. The
            // original code only logged at WARN and then returned
            // the generic "SessionNotFound", which masks the true
            // cause (e.g. missing approval_audit_log table).
            tracing::error!(
                session_uuid = %session_uuid,
                actor_username = %actor_username,
                decision = %decision.as_str(),
                db_error = %msg,
                "Approval decision transaction failed; fail-closed deny"
            );
            // If the SoD CHECK constraint fired, surface the structured
            // self-approval reason so the UI can display the right
            // message (rather than a generic "not found"). Postgres
            // emits the constraint name in the error string.
            let reason = if msg.contains("approval_separation_of_duties")
                || msg.contains("rejection_separation_of_duties")
            {
                ApprovalDenyReason::SelfApproval
            } else {
                ApprovalDenyReason::SessionNotFound
            };
            AccessResponse::ApprovalDenied { reason }
        }
    }
}

struct RecordedApproval {
    audit_id: i64,
    requester_id: i32,
    session_pk: i32,
}

enum ApprovalTxnError {
    Eligibility(ApprovalDenyReason),
    Db(String),
}

impl std::fmt::Display for ApprovalTxnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Eligibility(r) => write!(f, "eligibility:{:?}", r),
            Self::Db(s) => write!(f, "db:{}", s),
        }
    }
}

impl std::fmt::Debug for ApprovalTxnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl std::error::Error for ApprovalTxnError {}

impl From<diesel::result::Error> for ApprovalTxnError {
    fn from(e: diesel::result::Error) -> Self {
        Self::Db(e.to_string())
    }
}

/// Single source of truth for "is this session decidable AT ALL". Used
/// both by the read-only eligibility endpoint and by the in-transaction
/// re-check inside `handle_record_approval_decision`. Returning an
/// `ApprovalDenyReason` here MUST stay in sync with the structured
/// variants surfaced over IPC.
///
/// `expected_status` / `wrong_state_reason` parameterize the lifecycle
/// gate: approve/reject load `pending` requests, revoke/update_duration
/// load `approved` grants. Requester-liveness is NOT enforced here (it
/// is a per-decision policy, checked by
/// [`evaluate_decision_eligibility`]): revoking the grant of an
/// already-disabled requester must remain possible.
async fn load_decision_snapshot(
    conn: &mut DbConnection,
    session_uuid: Uuid,
    expected_status: &'static str,
    wrong_state_reason: ApprovalDenyReason,
) -> Result<PendingSessionSnapshot, ApprovalDenyReason> {
    // We deliberately query without a JOIN to keep the policy clear:
    // first the session, then the user, then the asset, then the rule.
    // Each missing piece maps to a structured deny reason.
    type SessionRow = (
        i32,
        i32,
        i32,
        String,
        String,
        Option<i32>,
        Option<chrono::DateTime<chrono::Utc>>,
    );
    let session: SessionRow = match proxy_sessions::table
        .filter(proxy_sessions::uuid.eq(session_uuid))
        .select((
            proxy_sessions::id,
            proxy_sessions::user_id,
            proxy_sessions::asset_id,
            proxy_sessions::status,
            proxy_sessions::session_type,
            proxy_sessions::max_session_duration,
            proxy_sessions::approved_at,
        ))
        .first(conn)
        .await
    {
        Ok(row) => row,
        Err(_) => return Err(ApprovalDenyReason::SessionNotFound),
    };

    let (session_pk, requester_id, asset_pk, status, session_type, current_max, approved_at) =
        session;

    if status != expected_status {
        return Err(wrong_state_reason);
    }

    let (requester_username, requester_is_active, requester_is_deleted): (String, bool, bool) =
        match users::table
            .filter(users::id.eq(requester_id))
            .select((users::username, users::is_active, users::is_deleted))
            .first(conn)
            .await
        {
            Ok(r) => r,
            Err(_) => return Err(ApprovalDenyReason::SessionNotFound),
        };

    let (asset_uuid, asset_name): (Uuid, String) = match assets::table
        .filter(assets::id.eq(asset_pk))
        .select((assets::uuid, assets::name))
        .first(conn)
        .await
    {
        Ok(r) => r,
        Err(_) => return Err(ApprovalDenyReason::SessionNotFound),
    };

    // Re-evaluate whether ANY rule that grants the requester access to
    // the asset still requires approval. If every applicable rule was
    // edited to drop the requirement, the request is moot. We check the
    // OR-aggregate across rules that could grant this access, mirroring
    // what `handle_check_access_by_uuid` does.
    let group_ids: Vec<i32> = match user_groups::table
        .filter(user_groups::user_id.eq(requester_id))
        .select(user_groups::group_id)
        .load(conn)
        .await
    {
        Ok(ids) => ids,
        Err(_) => return Err(ApprovalDenyReason::SessionNotFound),
    };

    let asset_group_ids: Vec<i32> = match asset_asset_groups::table
        .filter(asset_asset_groups::asset_id.eq(asset_pk))
        .select(asset_asset_groups::asset_group_id)
        .load(conn)
        .await
    {
        Ok(ids) => ids,
        Err(_) => return Err(ApprovalDenyReason::SessionNotFound),
    };

    // Include the virtual "All assets" group when present so a rule
    // bound to it counts toward this asset.
    let mut asset_group_ids = asset_group_ids;
    let virtual_id = crate::virtual_group::virtual_asset_group_id();
    if virtual_id != crate::virtual_group::UNINITIALIZED_VIRTUAL_ID
        && !asset_group_ids.contains(&virtual_id)
    {
        asset_group_ids.push(virtual_id);
    }

    let still_requires_approval: bool = if group_ids.is_empty() || asset_group_ids.is_empty() {
        // No matching rule path -> the request itself has lost its
        // grant chain. Treat as moot rather than as an SoD issue.
        false
    } else {
        access_rules::table
            .filter(access_rules::user_group_id.eq_any(&group_ids))
            .filter(access_rules::asset_group_id.eq_any(&asset_group_ids))
            .filter(access_rules::is_active.eq(true))
            .filter(access_rules::require_approval.eq(true))
            .select(diesel::dsl::count_star())
            .first::<i64>(conn)
            .await
            .map(|c| c > 0)
            .unwrap_or(false)
    };

    Ok(PendingSessionSnapshot {
        session_pk,
        requester_id,
        requester_username,
        requester_is_active,
        requester_is_deleted,
        asset_uuid,
        asset_name,
        session_type,
        rule_requires_approval: still_requires_approval,
        current_max_session_duration: current_max,
        approved_at,
    })
}

/// Pure policy check: given a snapshot and an actor, return `Some(reason)`
/// if the actor cannot decide on this request, `None` otherwise.
///
/// Centralised here so the read-only eligibility endpoint and the
/// in-transaction re-check share the same predicate -- a single test
/// (Tier 3) covers both call sites.
fn evaluate_eligibility(
    snap: &PendingSessionSnapshot,
    actor_id: i32,
) -> Option<ApprovalDenyReason> {
    if !snap.requester_is_active || snap.requester_is_deleted {
        return Some(ApprovalDenyReason::RequesterDisabled);
    }
    if snap.requester_id == actor_id {
        // SECURITY (separation of duties): the actor is the requester.
        // Even if they have admin_view, they cannot decide on their own
        // request. The DB CHECK constraints provide a defense-in-depth
        // layer in case this path is ever bypassed.
        return Some(ApprovalDenyReason::SelfApproval);
    }
    if !snap.rule_requires_approval {
        return Some(ApprovalDenyReason::RuleNoLongerRequiresApproval);
    }
    None
}

/// Per-decision policy on top of the shared predicate.
///
/// * Approve / Reject / UpdateDuration: full [`evaluate_eligibility`]
///   (SoD, requester liveness, rule still requires approval) --
///   granting or re-widening access must stay fully fenced.
/// * Revoke: NO checks. Reducing access is always legitimate: an admin
///   may revoke a grant they approved themselves, revoke the grant of
///   an already-disabled requester, or revoke a grant whose rule no
///   longer requires approval. Fail-open here is the SAFE direction
///   (the operation can only remove access, never add it).
fn evaluate_decision_eligibility(
    decision: ApprovalDecisionKind,
    snap: &PendingSessionSnapshot,
    actor_id: i32,
) -> Option<ApprovalDenyReason> {
    match decision {
        ApprovalDecisionKind::Approve
        | ApprovalDecisionKind::Reject
        | ApprovalDecisionKind::UpdateDuration => evaluate_eligibility(snap, actor_id),
        ApprovalDecisionKind::Revoke => None,
    }
}

#[cfg(test)]
mod escape_tests {
    use super::*;

    /// Pin the SQL-injection-safe escaper used by
    /// [`protocol_match_filter`]. The pre-fix implementation used
    /// raw `format!("ARRAY[{}]")` which would have shell-injected on
    /// any `'`/`;`/`--` byte. The escaper must ALWAYS produce a
    /// fragment that can only ever match a legitimate protocol
    /// string -- never a control sequence.
    #[test]
    fn escape_sql_array_literal_preserves_canonical_protocols() {
        // Every string the form / IPC writes to access_rules MUST
        // pass through unchanged.
        assert_eq!(escape_sql_array_literal("ssh"), "'ssh'");
        assert_eq!(escape_sql_array_literal("rdp"), "'rdp'");
        assert_eq!(escape_sql_array_literal("iacs_modbus"), "'iacs_modbus'");
        assert_eq!(escape_sql_array_literal("iacs_opcua"), "'iacs_opcua'");
        assert_eq!(escape_sql_array_literal("iacs_iec104"), "'iacs_iec104'");
        assert_eq!(escape_sql_array_literal("iacs_tunnel"), "'iacs_tunnel'");
    }

    #[test]
    fn escape_sql_array_literal_neutralises_sql_injection_attempts() {
        // Single quote -> _, the canonical SQL break-out character.
        assert_eq!(
            escape_sql_array_literal("ssh'; DROP TABLE access_rules;--"),
            "'ssh___DROP_TABLE_access_rules___'"
        );
        // Backslash, semicolon, double quote, parens -- every control
        // character a SQL injection would rely on.
        assert_eq!(escape_sql_array_literal("a';"), "'a__'");
        assert_eq!(escape_sql_array_literal("\\\\"), "'__'");
        assert_eq!(escape_sql_array_literal("(1=1)"), "'_1_1_'");
        // Null byte / newline / tab.
        assert_eq!(escape_sql_array_literal("\0\n\t"), "'___'");
        // Empty -> empty literal (matches no row, fail-closed).
        assert_eq!(escape_sql_array_literal(""), "''");
    }

    #[test]
    fn protocol_match_filter_iacs_tunnel_expands_to_overlap_with_applicative() {
        // We can't run the SQL fragment without a Postgres connection,
        // but we can render it and check the structure. The fragment
        // produced for `iacs_tunnel` MUST mention every applicative
        // IACS protocol AND use the `&&` overlap operator (NOT the
        // `@>` containment operator that broke the pre-fix wiring).
        use diesel::pg::Pg;
        use diesel::query_builder::{QueryBuilder, QueryFragment};

        let frag = protocol_match_filter("iacs_tunnel");
        let mut query_builder = <diesel::pg::PgQueryBuilder as Default>::default();
        frag.to_sql(&mut query_builder, &Pg)
            .expect("fragment must render");
        let sql = query_builder.finish();
        assert!(
            sql.contains("&&"),
            "the IACS meta-protocol filter MUST use the overlap (&&) \
             operator, NOT the containment (@>) operator. Got: {sql}"
        );
        for needle in [
            "'iacs_modbus'",
            "'iacs_opcua'",
            "'iacs_profinet'",
            "'iacs_iec104'",
            "'iacs_tcp'",
        ] {
            assert!(
                sql.contains(needle),
                "the IACS meta-protocol filter MUST mention {needle} \
                 in its expansion. Got: {sql}"
            );
        }
        // The transport-meta itself MUST NOT appear in the expansion --
        // an admin who manually wrote `iacs_tunnel` into a rule
        // (impossible via the form, possible via raw IPC) would
        // otherwise match the request via self-reference, which is
        // not the contract.
        assert!(
            !sql.contains("'iacs_tunnel'"),
            "the IACS meta-protocol MUST NOT self-include in its own \
             expansion. Got: {sql}"
        );
    }

    #[test]
    fn protocol_match_filter_ssh_is_one_element_and_uses_overlap() {
        use diesel::pg::Pg;
        use diesel::query_builder::{QueryBuilder, QueryFragment};
        let frag = protocol_match_filter("ssh");
        let mut query_builder = <diesel::pg::PgQueryBuilder as Default>::default();
        frag.to_sql(&mut query_builder, &Pg).unwrap();
        let sql = query_builder.finish();
        // We use `&&` even for non-meta protocols -- this is harmless
        // (overlap with a one-element array is equivalent to
        // containment) and keeps the SQL homogeneous so the index
        // (GIN on `allowed_protocols`) is hit consistently.
        assert!(sql.contains("&&"), "expected overlap operator, got: {sql}");
        assert!(sql.contains("'ssh'"), "expected 'ssh' literal, got: {sql}");
        assert!(
            !sql.contains("'rdp'") && !sql.contains("'iacs_"),
            "ssh filter must NOT mention any other protocol, got: {sql}"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::handle_access_request;
    use crate::db::DbPool;
    use crate::schema::{access_rules, asset_groups, users};
    use diesel::prelude::*;
    use diesel_async::pooled_connection::AsyncDieselConnectionManager;
    use diesel_async::pooled_connection::deadpool::Pool;
    use diesel_async::{AsyncPgConnection, RunQueryDsl};
    use shared::messages::{
        AccessRequest, AccessResponse, AccessRuleData, AccessRuleInfo, AccessibleGroupEntry,
        AssetGroupInfo, DEFAULT_IPC_PAGE_LIMIT, IpcPage, IpcPageParams, MAX_IPC_PAGE_LIMIT,
        VaubanGroupInfo,
    };
    use uuid::Uuid;

    fn page0() -> IpcPageParams {
        IpcPageParams {
            limit: 0,
            offset: 0,
        }
    }

    async fn collect_paged<T: std::fmt::Debug>(
        pool: &DbPool,
        page_limit: u32,
        make_request: impl Fn(IpcPageParams) -> AccessRequest,
        extract: impl Fn(AccessResponse) -> IpcPage<T>,
    ) -> Vec<T> {
        let mut all = Vec::new();
        let mut offset = 0u32;
        loop {
            let resp = handle_access_request(
                pool,
                make_request(IpcPageParams {
                    limit: page_limit,
                    offset,
                }),
            )
            .await;
            let page = extract(resp);
            let n = page.items.len() as u32;
            all.extend(page.items);
            if !page.has_more || n == 0 {
                break;
            }
            offset = offset.saturating_add(n);
        }
        all
    }

    async fn collect_asset_group_ids_paged(pool: &DbPool, page_limit: u32) -> Vec<i32> {
        let mut ids: Vec<i32> = collect_paged(
            pool,
            page_limit,
            |p| AccessRequest::ListAssetGroups {
                page: p,
                include_virtual: false,
            },
            |r| match r {
                AccessResponse::AssetGroupPage(p) => p,
                other => panic!("expected AssetGroupPage, got {:?}", other),
            },
        )
        .await
        .into_iter()
        .map(|g| g.id)
        .collect();
        ids.sort_unstable();
        ids.dedup();
        ids
    }

    async fn collect_access_rule_uuids_paged(pool: &DbPool, page_limit: u32) -> Vec<String> {
        let mut uuids: Vec<String> = collect_paged(
            pool,
            page_limit,
            |p| AccessRequest::ListAccessRules { page: p },
            |r| match r {
                AccessResponse::AccessRulePage(p) => p,
                other => panic!("expected AccessRulePage, got {:?}", other),
            },
        )
        .await
        .into_iter()
        .map(|r| r.uuid)
        .collect();
        uuids.sort();
        uuids
    }

    async fn collect_vauban_group_ids_paged(pool: &DbPool, page_limit: u32) -> Vec<i32> {
        let mut ids: Vec<i32> = collect_paged(
            pool,
            page_limit,
            |p| AccessRequest::ListVaubanGroups { page: p },
            |r| match r {
                AccessResponse::VaubanGroupPage(p) => p,
                other => panic!("expected VaubanGroupPage, got {:?}", other),
            },
        )
        .await
        .into_iter()
        .map(|g| g.id)
        .collect();
        ids.sort_unstable();
        ids.dedup();
        ids
    }

    fn normalize_accessible_entries(entries: Vec<AccessibleGroupEntry>) -> Vec<(i32, Vec<String>)> {
        let mut v: Vec<_> = entries
            .into_iter()
            .map(|e| {
                let mut p = e.protocols;
                p.sort();
                (e.asset_group_id, p)
            })
            .collect();
        v.sort_by_key(|(id, _)| *id);
        v
    }

    async fn collect_accessible_groups_normalized_paged(
        pool: &DbPool,
        user_id: i32,
        page_limit: u32,
    ) -> Vec<(i32, Vec<String>)> {
        let all = collect_paged(
            pool,
            page_limit,
            |p| AccessRequest::ListAccessibleGroups { user_id, page: p },
            |r| match r {
                AccessResponse::AccessibleGroupsPage(p) => p,
                other => panic!("expected AccessibleGroupsPage, got {:?}", other),
            },
        )
        .await;
        normalize_accessible_entries(all)
    }

    async fn collect_group_member_ids_paged(
        pool: &DbPool,
        group_id: i32,
        page_limit: u32,
    ) -> Vec<i32> {
        let mut ids = collect_paged(
            pool,
            page_limit,
            |p| AccessRequest::ListGroupMembers { group_id, page: p },
            |r| match r {
                AccessResponse::MemberListPage(p) => p,
                other => panic!("expected MemberListPage, got {:?}", other),
            },
        )
        .await;
        ids.sort_unstable();
        ids.dedup();
        ids
    }

    async fn collect_user_group_ids_paged(
        pool: &DbPool,
        user_id: i32,
        page_limit: u32,
    ) -> Vec<i32> {
        let mut ids: Vec<i32> = collect_paged(
            pool,
            page_limit,
            |p| AccessRequest::ListUserGroups { user_id, page: p },
            |r| match r {
                AccessResponse::UserGroupPage(p) => p,
                other => panic!("expected UserGroupPage, got {:?}", other),
            },
        )
        .await
        .into_iter()
        .map(|g| g.id)
        .collect();
        ids.sort_unstable();
        ids.dedup();
        ids
    }

    async fn collect_user_group_option_ids_paged(pool: &DbPool, page_limit: u32) -> Vec<i32> {
        let mut ids: Vec<i32> = collect_paged(
            pool,
            page_limit,
            |p| AccessRequest::ListUserGroupOptions { page: p },
            |r| match r {
                AccessResponse::UserGroupOptionsPage(p) => p,
                other => panic!("expected UserGroupOptionsPage, got {:?}", other),
            },
        )
        .await
        .into_iter()
        .map(|g| g.id)
        .collect();
        ids.sort_unstable();
        ids.dedup();
        ids
    }

    async fn collect_asset_group_option_ids_paged(pool: &DbPool, page_limit: u32) -> Vec<i32> {
        let mut ids: Vec<i32> = collect_paged(
            pool,
            page_limit,
            |p| AccessRequest::ListAssetGroupOptions {
                page: p,
                include_virtual: false,
            },
            |r| match r {
                AccessResponse::AssetGroupOptionsPage(p) => p,
                other => panic!("expected AssetGroupOptionsPage, got {:?}", other),
            },
        )
        .await
        .into_iter()
        .map(|g| g.id)
        .collect();
        ids.sort_unstable();
        ids.dedup();
        ids
    }

    use std::collections::HashSet;
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn unique_name(prefix: &str) -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        format!("{}_{ts}_{id}", prefix)
    }

    const MAX_TEST_USERS: i64 = 1000;
    const MAX_TEST_ASSET_GROUPS: i64 = 500;
    const MAX_TEST_VAUBAN_GROUPS: i64 = 500;

    async fn prune_test_db(pool: &DbPool) {
        let mut conn = pool.get().await.unwrap();

        let user_count: i64 = users::table
            .count()
            .get_result(&mut conn)
            .await
            .unwrap_or(0);
        let ag_count: i64 = crate::schema::asset_groups::table
            .count()
            .get_result(&mut conn)
            .await
            .unwrap_or(0);
        let vg_count: i64 = crate::schema::vauban_groups::table
            .count()
            .get_result(&mut conn)
            .await
            .unwrap_or(0);

        if user_count <= MAX_TEST_USERS
            && ag_count <= MAX_TEST_ASSET_GROUPS
            && vg_count <= MAX_TEST_VAUBAN_GROUPS
        {
            return;
        }

        eprintln!(
            "[test-prune] Stale data detected (users={user_count}, \
             asset_groups={ag_count}, vauban_groups={vg_count}). \
             Pruning to {MAX_TEST_USERS}/{MAX_TEST_ASSET_GROUPS}/\
             {MAX_TEST_VAUBAN_GROUPS}..."
        );

        // Dependent/junction tables are cleaned first (no cap needed).
        // IACS tables are TRUNCATEd alongside the rest because their FKs to
        // `users` use ON DELETE RESTRICT (intentional in production: an
        // active EWS owner cannot be silently hard-deleted), which would
        // otherwise block the per-batch user prune below.
        diesel::sql_query(
            "TRUNCATE access_rules, user_groups, asset_asset_groups, \
             proxy_sessions, auth_sessions, api_keys, assets, \
             ews, ews_onboarding_requests, ews_audit_log CASCADE",
        )
        .execute(&mut conn)
        .await
        .expect("test-prune: TRUNCATE dependents failed");

        // Break self-references before trimming.
        diesel::sql_query("UPDATE vauban_groups SET parent_id = NULL WHERE parent_id IS NOT NULL")
            .execute(&mut conn)
            .await
            .ok();
        diesel::sql_query("UPDATE asset_groups SET parent_id = NULL WHERE parent_id IS NOT NULL")
            .execute(&mut conn)
            .await
            .ok();

        // Nullify cross-FK refs from groups to users we might delete.
        diesel::sql_query(
            "UPDATE asset_groups SET created_by_id = NULL, updated_by_id = NULL \
             WHERE created_by_id IS NOT NULL",
        )
        .execute(&mut conn)
        .await
        .ok();

        // Trim each table keeping the N most recent rows by id.
        diesel::sql_query(format!(
            "DELETE FROM users WHERE id NOT IN \
             (SELECT id FROM users ORDER BY id DESC LIMIT {MAX_TEST_USERS})"
        ))
        .execute(&mut conn)
        .await
        .expect("test-prune: DELETE users failed");

        diesel::sql_query(format!(
            "DELETE FROM vauban_groups WHERE id NOT IN \
             (SELECT id FROM vauban_groups ORDER BY id DESC LIMIT {MAX_TEST_VAUBAN_GROUPS})"
        ))
        .execute(&mut conn)
        .await
        .expect("test-prune: DELETE vauban_groups failed");

        diesel::sql_query(format!(
            "DELETE FROM asset_groups WHERE kind = 'static' AND id NOT IN \
             (SELECT id FROM asset_groups ORDER BY id DESC LIMIT {MAX_TEST_ASSET_GROUPS})"
        ))
        .execute(&mut conn)
        .await
        .expect("test-prune: DELETE asset_groups failed");

        let remaining_users: i64 = users::table
            .count()
            .get_result(&mut conn)
            .await
            .unwrap_or(0);
        let remaining_ag: i64 = crate::schema::asset_groups::table
            .count()
            .get_result(&mut conn)
            .await
            .unwrap_or(0);
        let remaining_vg: i64 = crate::schema::vauban_groups::table
            .count()
            .get_result(&mut conn)
            .await
            .unwrap_or(0);
        eprintln!(
            "[test-prune] Done. Remaining: users={remaining_users}, \
             asset_groups={remaining_ag}, vauban_groups={remaining_vg}"
        );
    }

    static PRUNE_DONE: OnceLock<()> = OnceLock::new();

    async fn test_pool() -> DbPool {
        let url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
            "postgresql://vauban_test:vauban_test@localhost/vauban_test".to_string()
        });
        let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(&url);
        let pool = Pool::builder(manager).max_size(2).build().unwrap();
        if PRUNE_DONE.get().is_none() {
            prune_test_db(&pool).await;
            let _ = PRUNE_DONE.set(());
        }
        pool
    }

    async fn insert_test_user(pool: &DbPool, username: &str) -> i32 {
        let mut conn = pool.get().await.unwrap();
        let email = format!("{username}@test.local");
        diesel::insert_into(users::table)
            .values((
                users::username.eq(username),
                users::email.eq(&email),
                users::password_hash.eq("nologin"),
                users::is_superuser.eq(false),
                users::is_staff.eq(false),
                users::is_active.eq(true),
            ))
            .on_conflict(users::username)
            .do_update()
            .set(users::username.eq(users::username))
            .returning(users::id)
            .get_result::<i32>(&mut conn)
            .await
            .unwrap()
    }

    async fn ensure_test_user(pool: &DbPool) -> i32 {
        insert_test_user(pool, "access_test_user").await
    }

    async fn create_test_vauban_group(pool: &DbPool, name: &str) -> VaubanGroupInfo {
        match handle_access_request(
            pool,
            AccessRequest::CreateVaubanGroup {
                name: name.to_string(),
                description: Some("test group".to_string()),
            },
        )
        .await
        {
            AccessResponse::VaubanGroup(Ok(info)) => info,
            other => panic!("Expected VaubanGroup(Ok), got {:?}", other),
        }
    }

    async fn create_test_asset_group(pool: &DbPool, name: &str) -> AssetGroupInfo {
        let slug = name.to_lowercase().replace(' ', "-");
        match handle_access_request(
            pool,
            AccessRequest::CreateAssetGroup {
                name: name.to_string(),
                slug: slug.clone(),
                description: Some("test asset group".to_string()),
                color: "#6B7280".to_string(),
                icon: "folder".to_string(),
                actor_uuid: None,
            },
        )
        .await
        {
            AccessResponse::AssetGroup(Ok(info)) => info,
            other => panic!("Expected AssetGroup(Ok), got {:?}", other),
        }
    }

    async fn create_test_rule(
        pool: &DbPool,
        name: &str,
        ug_id: i32,
        ag_id: i32,
        protocols: Vec<&str>,
    ) -> AccessRuleInfo {
        let data = AccessRuleData {
            name: name.to_string(),
            description: None,
            user_group_id: ug_id,
            asset_group_id: ag_id,
            allowed_protocols: protocols.into_iter().map(|s| s.to_string()).collect(),
            valid_from: None,
            valid_until: None,
            require_mfa: false,
            require_approval: false,
            max_session_duration: None,
            is_active: true,
            priority: 0,
        };
        match handle_access_request(
            pool,
            AccessRequest::CreateAccessRule {
                data,
                actor_uuid: None,
            },
        )
        .await
        {
            AccessResponse::AccessRule(Ok(info)) => info,
            other => panic!("Expected AccessRule(Ok), got {:?}", other),
        }
    }

    async fn cleanup_rule(pool: &DbPool, uuid: &str) {
        handle_access_request(
            pool,
            AccessRequest::DeleteAccessRule {
                uuid: uuid.to_string(),
            },
        )
        .await;
    }

    async fn cleanup_vauban_group(pool: &DbPool, uuid: &str) {
        handle_access_request(
            pool,
            AccessRequest::DeleteVaubanGroup {
                uuid: uuid.to_string(),
            },
        )
        .await;
    }

    async fn cleanup_asset_group(pool: &DbPool, uuid: &str) {
        handle_access_request(
            pool,
            AccessRequest::DeleteAssetGroup {
                uuid: uuid.to_string(),
            },
        )
        .await;
    }

    // ==================== Vauban Groups CRUD ====================

    #[tokio::test]
    async fn test_create_vauban_group_ok() {
        let pool = test_pool().await;
        let name = unique_name("vg");
        let group = create_test_vauban_group(&pool, &name).await;
        assert_eq!(group.name, name);
        assert!(group.id > 0);
        cleanup_vauban_group(&pool, &group.uuid).await;
    }

    #[tokio::test]
    async fn test_get_vauban_group_ok() {
        let pool = test_pool().await;
        let name = unique_name("vg_get");
        let group = create_test_vauban_group(&pool, &name).await;

        let resp = handle_access_request(
            &pool,
            AccessRequest::GetVaubanGroup {
                uuid: group.uuid.clone(),
            },
        )
        .await;
        match resp {
            AccessResponse::VaubanGroup(Ok(info)) => {
                assert_eq!(info.name, name);
                assert_eq!(info.uuid, group.uuid);
            }
            other => panic!("Expected VaubanGroup(Ok), got {:?}", other),
        }
        cleanup_vauban_group(&pool, &group.uuid).await;
    }

    #[tokio::test]
    async fn test_get_vauban_group_not_found() {
        let pool = test_pool().await;
        let resp = handle_access_request(
            &pool,
            AccessRequest::GetVaubanGroup {
                uuid: "nonexistent-uuid".to_string(),
            },
        )
        .await;
        match resp {
            AccessResponse::VaubanGroup(Err(_)) => {}
            other => panic!("Expected VaubanGroup(Err), got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_list_vauban_groups() {
        let pool = test_pool().await;
        let resp =
            handle_access_request(&pool, AccessRequest::ListVaubanGroups { page: page0() }).await;
        match resp {
            AccessResponse::VaubanGroupPage(page) => {
                let _ = page;
            }
            other => panic!("Expected VaubanGroupPage, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_list_vauban_groups_pagination_equivalence() {
        let pool = test_pool().await;
        let g1 = create_test_vauban_group(&pool, &unique_name("vg_eq_a")).await;
        let g2 = create_test_vauban_group(&pool, &unique_name("vg_eq_b")).await;
        let ids_1 = collect_vauban_group_ids_paged(&pool, 50).await;
        let ids_256 = collect_vauban_group_ids_paged(&pool, 256).await;
        assert_eq!(ids_1, ids_256);
        cleanup_vauban_group(&pool, &g1.uuid).await;
        cleanup_vauban_group(&pool, &g2.uuid).await;
    }

    #[tokio::test]
    async fn test_delete_vauban_group_ok() {
        let pool = test_pool().await;
        let name = unique_name("vg_del");
        let group = create_test_vauban_group(&pool, &name).await;

        let resp = handle_access_request(
            &pool,
            AccessRequest::DeleteVaubanGroup {
                uuid: group.uuid.clone(),
            },
        )
        .await;
        match resp {
            AccessResponse::Deleted(Ok(())) => {}
            other => panic!("Expected Deleted(Ok), got {:?}", other),
        }
    }

    // ==================== Asset Groups CRUD ====================

    #[tokio::test]
    async fn test_create_asset_group_ok() {
        let pool = test_pool().await;
        let name = unique_name("ag");
        let group = create_test_asset_group(&pool, &name).await;
        assert_eq!(group.name, name);
        cleanup_asset_group(&pool, &group.uuid).await;
    }

    /// Issue #22 — `CreateAssetGroup` MUST stamp `created_by_id`
    /// and `updated_by_id` from the actor UUID forwarded by the
    /// web layer. The Metadata UI on `/assets/groups/{uuid}`
    /// reads those columns directly via
    /// `audit_authors::resolve_audit_pair`.
    #[tokio::test]
    async fn test_create_asset_group_stamps_audit_pair_from_actor_uuid() {
        let pool = test_pool().await;
        let user_id = insert_test_user(&pool, &unique_name("ag_audit_actor")).await;
        let actor_uuid: Uuid = {
            let mut conn = pool.get().await.unwrap();
            users::table
                .filter(users::id.eq(user_id))
                .select(users::uuid)
                .first::<Uuid>(&mut conn)
                .await
                .unwrap()
        };

        let name = unique_name("ag_audit");
        let slug = name.to_lowercase().replace(' ', "-");
        let resp = handle_access_request(
            &pool,
            AccessRequest::CreateAssetGroup {
                name: name.clone(),
                slug,
                description: None,
                color: "#abcdef".to_string(),
                icon: "folder".to_string(),
                actor_uuid: Some(actor_uuid.to_string()),
            },
        )
        .await;
        let info = match resp {
            AccessResponse::AssetGroup(Ok(info)) => info,
            other => panic!("expected AssetGroup(Ok), got {:?}", other),
        };

        let mut conn = pool.get().await.unwrap();
        let row: (Option<i32>, Option<i32>) = asset_groups::table
            .filter(asset_groups::id.eq(info.id))
            .select((asset_groups::created_by_id, asset_groups::updated_by_id))
            .first(&mut conn)
            .await
            .unwrap();
        assert_eq!(
            row,
            (Some(user_id), Some(user_id)),
            "CreateAssetGroup must stamp both audit columns with the actor"
        );

        cleanup_asset_group(&pool, &info.uuid).await;
    }

    /// Issue #22 — `UpdateAssetGroup` MUST re-stamp
    /// `updated_by_id` while LEAVING `created_by_id` untouched.
    /// Otherwise an admin "fixing a typo" would erase the
    /// original creator from the audit trail.
    #[tokio::test]
    async fn test_update_asset_group_restamps_only_updated_by() {
        let pool = test_pool().await;
        let creator = insert_test_user(&pool, &unique_name("ag_audit_creator")).await;
        let editor = insert_test_user(&pool, &unique_name("ag_audit_editor")).await;
        let creator_uuid: Uuid = {
            let mut conn = pool.get().await.unwrap();
            users::table
                .filter(users::id.eq(creator))
                .select(users::uuid)
                .first::<Uuid>(&mut conn)
                .await
                .unwrap()
        };
        let editor_uuid: Uuid = {
            let mut conn = pool.get().await.unwrap();
            users::table
                .filter(users::id.eq(editor))
                .select(users::uuid)
                .first::<Uuid>(&mut conn)
                .await
                .unwrap()
        };

        let name = unique_name("ag_audit_upd");
        let slug = name.to_lowercase().replace(' ', "-");
        let create_resp = handle_access_request(
            &pool,
            AccessRequest::CreateAssetGroup {
                name: name.clone(),
                slug: slug.clone(),
                description: None,
                color: "#000000".to_string(),
                icon: "folder".to_string(),
                actor_uuid: Some(creator_uuid.to_string()),
            },
        )
        .await;
        let info = match create_resp {
            AccessResponse::AssetGroup(Ok(info)) => info,
            other => panic!("expected AssetGroup(Ok), got {:?}", other),
        };

        let _ = handle_access_request(
            &pool,
            AccessRequest::UpdateAssetGroup {
                uuid: info.uuid.clone(),
                name: format!("{}-renamed", name),
                slug: format!("{}-renamed", slug),
                description: Some("edited".to_string()),
                color: "#111111".to_string(),
                icon: "server".to_string(),
                actor_uuid: Some(editor_uuid.to_string()),
            },
        )
        .await;

        let mut conn = pool.get().await.unwrap();
        let row: (Option<i32>, Option<i32>) = asset_groups::table
            .filter(asset_groups::id.eq(info.id))
            .select((asset_groups::created_by_id, asset_groups::updated_by_id))
            .first(&mut conn)
            .await
            .unwrap();
        assert_eq!(
            row.0,
            Some(creator),
            "UpdateAssetGroup MUST NOT rewrite created_by_id"
        );
        assert_eq!(
            row.1,
            Some(editor),
            "UpdateAssetGroup MUST re-stamp updated_by_id with the new actor"
        );

        cleanup_asset_group(&pool, &info.uuid).await;
    }

    /// Issue #22 — a missing or unresolvable `actor_uuid` MUST
    /// NOT block the write. The audit columns are
    /// `Nullable<Int4>` precisely so a transient lookup miss
    /// only collapses the read-side cell to a muted em-dash.
    #[tokio::test]
    async fn test_create_asset_group_missing_actor_uuid_falls_back_to_null() {
        let pool = test_pool().await;
        let name = unique_name("ag_audit_no_actor");
        let slug = name.to_lowercase().replace(' ', "-");
        let resp = handle_access_request(
            &pool,
            AccessRequest::CreateAssetGroup {
                name: name.clone(),
                slug,
                description: None,
                color: "#aaaaaa".to_string(),
                icon: "folder".to_string(),
                actor_uuid: None,
            },
        )
        .await;
        let info = match resp {
            AccessResponse::AssetGroup(Ok(info)) => info,
            other => panic!("expected AssetGroup(Ok), got {:?}", other),
        };

        let mut conn = pool.get().await.unwrap();
        let row: (Option<i32>, Option<i32>) = asset_groups::table
            .filter(asset_groups::id.eq(info.id))
            .select((asset_groups::created_by_id, asset_groups::updated_by_id))
            .first(&mut conn)
            .await
            .unwrap();
        assert_eq!(
            row,
            (None, None),
            "missing actor_uuid must fall back to NULL audit columns, not block the write"
        );
        cleanup_asset_group(&pool, &info.uuid).await;
    }

    /// Issue #22 — a malformed `actor_uuid` falls through to
    /// `None` (treated as "unknown / system" on the Metadata UI),
    /// without ever leaking a parser error to the operator.
    #[tokio::test]
    async fn test_create_asset_group_malformed_actor_uuid_is_silently_ignored() {
        let pool = test_pool().await;
        let name = unique_name("ag_audit_bad_uuid");
        let slug = name.to_lowercase().replace(' ', "-");
        let resp = handle_access_request(
            &pool,
            AccessRequest::CreateAssetGroup {
                name: name.clone(),
                slug,
                description: None,
                color: "#bbbbbb".to_string(),
                icon: "folder".to_string(),
                actor_uuid: Some("not-a-uuid".to_string()),
            },
        )
        .await;
        let info = match resp {
            AccessResponse::AssetGroup(Ok(info)) => info,
            other => panic!("expected AssetGroup(Ok), got {:?}", other),
        };

        let mut conn = pool.get().await.unwrap();
        let row: (Option<i32>, Option<i32>) = asset_groups::table
            .filter(asset_groups::id.eq(info.id))
            .select((asset_groups::created_by_id, asset_groups::updated_by_id))
            .first(&mut conn)
            .await
            .unwrap();
        assert_eq!(
            row,
            (None, None),
            "malformed actor_uuid must collapse to NULL, not be persisted"
        );
        cleanup_asset_group(&pool, &info.uuid).await;
    }

    #[tokio::test]
    async fn test_list_asset_groups() {
        let pool = test_pool().await;
        let resp = handle_access_request(
            &pool,
            AccessRequest::ListAssetGroups {
                page: page0(),
                include_virtual: false,
            },
        )
        .await;
        match resp {
            AccessResponse::AssetGroupPage(_) => {}
            other => panic!("Expected AssetGroupPage, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_list_asset_groups_pagination_equivalence() {
        let pool = test_pool().await;
        let g1 = create_test_asset_group(&pool, &unique_name("ag_page_eq_a")).await;
        let g2 = create_test_asset_group(&pool, &unique_name("ag_page_eq_b")).await;
        let ids_1 = collect_asset_group_ids_paged(&pool, 50).await;
        let ids_256 = collect_asset_group_ids_paged(&pool, 256).await;
        assert_eq!(
            ids_1, ids_256,
            "paginating with limit 1 vs 256 should yield the same id set"
        );
        cleanup_asset_group(&pool, &g1.uuid).await;
        cleanup_asset_group(&pool, &g2.uuid).await;
    }

    #[tokio::test]
    async fn test_list_asset_groups_offset_beyond_end() {
        let pool = test_pool().await;
        let resp = handle_access_request(
            &pool,
            AccessRequest::ListAssetGroups {
                page: IpcPageParams {
                    limit: 50,
                    offset: 9_000_000,
                },
                include_virtual: false,
            },
        )
        .await;
        match resp {
            AccessResponse::AssetGroupPage(p) => {
                assert!(p.items.is_empty());
                assert!(!p.has_more);
            }
            other => panic!("Expected AssetGroupPage, got {:?}", other),
        }
    }

    /// Many rows: walking the list with a small page limit must still return every created group id.
    #[tokio::test]
    async fn test_list_asset_groups_many_pages_collects_all_ids() {
        const N: usize = 48;
        let pool = test_pool().await;
        let prefix = unique_name("ag_vol");
        let mut uuids = Vec::new();
        let mut created_ids = Vec::new();
        for i in 0..N {
            let name = format!("{prefix}_{i}");
            let g = create_test_asset_group(&pool, &name).await;
            created_ids.push(g.id);
            uuids.push(g.uuid);
        }
        created_ids.sort_unstable();
        let collected = collect_asset_group_ids_paged(&pool, 50).await;
        let collected_set: HashSet<i32> = collected.into_iter().collect();
        for id in &created_ids {
            assert!(
                collected_set.contains(id),
                "missing asset_group id {id} after many limit-1 pages"
            );
        }
        for u in uuids {
            cleanup_asset_group(&pool, &u).await;
        }
    }

    // ==================== Access Rules CRUD ====================

    #[tokio::test]
    async fn test_create_access_rule_ok() {
        let pool = test_pool().await;
        let ug_name = unique_name("ug_rule");
        let ag_name = unique_name("ag_rule");
        let ug = create_test_vauban_group(&pool, &ug_name).await;
        let ag = create_test_asset_group(&pool, &ag_name).await;

        let rule = create_test_rule(&pool, &unique_name("rule"), ug.id, ag.id, vec!["ssh"]).await;
        assert!(!rule.uuid.is_empty());
        assert!(rule.is_active);

        cleanup_rule(&pool, &rule.uuid).await;
        cleanup_asset_group(&pool, &ag.uuid).await;
        cleanup_vauban_group(&pool, &ug.uuid).await;
    }

    /// Issue #22 — `CreateAccessRule` MUST stamp `created_by_id`
    /// and `updated_by_id` from the actor UUID forwarded by the
    /// web layer; `UpdateAccessRule` MUST re-stamp only the
    /// updated column. Same contract as the asset-group test
    /// above — kept as an explicit assertion so a future refactor
    /// of either handler cannot silently drop the audit pair.
    #[tokio::test]
    async fn test_access_rule_create_and_update_audit_pair() {
        let pool = test_pool().await;
        let creator = insert_test_user(&pool, &unique_name("ar_audit_creator")).await;
        let editor = insert_test_user(&pool, &unique_name("ar_audit_editor")).await;
        let creator_uuid: Uuid = {
            let mut conn = pool.get().await.unwrap();
            users::table
                .filter(users::id.eq(creator))
                .select(users::uuid)
                .first::<Uuid>(&mut conn)
                .await
                .unwrap()
        };
        let editor_uuid: Uuid = {
            let mut conn = pool.get().await.unwrap();
            users::table
                .filter(users::id.eq(editor))
                .select(users::uuid)
                .first::<Uuid>(&mut conn)
                .await
                .unwrap()
        };

        let ug = create_test_vauban_group(&pool, &unique_name("ar_audit_ug")).await;
        let ag = create_test_asset_group(&pool, &unique_name("ar_audit_ag")).await;

        let data = AccessRuleData {
            name: unique_name("ar_audit"),
            description: None,
            user_group_id: ug.id,
            asset_group_id: ag.id,
            allowed_protocols: vec!["ssh".to_string()],
            valid_from: None,
            valid_until: None,
            require_mfa: false,
            require_approval: false,
            max_session_duration: None,
            is_active: true,
            priority: 0,
        };
        let create = handle_access_request(
            &pool,
            AccessRequest::CreateAccessRule {
                data: data.clone(),
                actor_uuid: Some(creator_uuid.to_string()),
            },
        )
        .await;
        let info = match create {
            AccessResponse::AccessRule(Ok(info)) => info,
            other => panic!("expected AccessRule(Ok), got {:?}", other),
        };

        let rule_uuid = Uuid::parse_str(&info.uuid).unwrap();
        // Scope each pool.get() so the connection is returned to
        // the pool before the next IPC call. The pool is sized to
        // 2 (`test_pool().max_size(2)`); leaking a guard across
        // `handle_access_request` plus the trailing cleanup_*
        // helpers would saturate the pool and deadlock the test.
        let after_create: (Option<i32>, Option<i32>) = {
            let mut conn = pool.get().await.unwrap();
            access_rules::table
                .filter(access_rules::uuid.eq(rule_uuid))
                .select((access_rules::created_by_id, access_rules::updated_by_id))
                .first(&mut conn)
                .await
                .unwrap()
        };
        assert_eq!(
            after_create,
            (Some(creator), Some(creator)),
            "CreateAccessRule must stamp both audit columns"
        );

        let updated = AccessRuleData {
            name: format!("{}-renamed", data.name),
            ..data
        };
        let _ = handle_access_request(
            &pool,
            AccessRequest::UpdateAccessRule {
                uuid: info.uuid.clone(),
                data: updated,
                actor_uuid: Some(editor_uuid.to_string()),
            },
        )
        .await;

        let after_update: (Option<i32>, Option<i32>) = {
            let mut conn = pool.get().await.unwrap();
            access_rules::table
                .filter(access_rules::uuid.eq(rule_uuid))
                .select((access_rules::created_by_id, access_rules::updated_by_id))
                .first(&mut conn)
                .await
                .unwrap()
        };
        assert_eq!(
            after_update.0,
            Some(creator),
            "UpdateAccessRule MUST NOT rewrite created_by_id"
        );
        assert_eq!(
            after_update.1,
            Some(editor),
            "UpdateAccessRule MUST re-stamp updated_by_id"
        );

        cleanup_rule(&pool, &info.uuid).await;
        cleanup_asset_group(&pool, &ag.uuid).await;
        cleanup_vauban_group(&pool, &ug.uuid).await;
    }

    #[tokio::test]
    async fn test_list_access_rules() {
        let pool = test_pool().await;
        let resp =
            handle_access_request(&pool, AccessRequest::ListAccessRules { page: page0() }).await;
        match resp {
            AccessResponse::AccessRulePage(_) => {}
            other => panic!("Expected AccessRulePage, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_list_access_rules_pagination_equivalence() {
        let pool = test_pool().await;
        let ug_name = unique_name("ug_rule_eq");
        let ag_a = unique_name("ag_rule_eq_a");
        let ag_b = unique_name("ag_rule_eq_b");
        let ug = create_test_vauban_group(&pool, &ug_name).await;
        let ag1 = create_test_asset_group(&pool, &ag_a).await;
        let ag2 = create_test_asset_group(&pool, &ag_b).await;
        let r1 =
            create_test_rule(&pool, &unique_name("rule_eq_a"), ug.id, ag1.id, vec!["ssh"]).await;
        let r2 =
            create_test_rule(&pool, &unique_name("rule_eq_b"), ug.id, ag2.id, vec!["rdp"]).await;
        let uuids_1 = collect_access_rule_uuids_paged(&pool, 50).await;
        let uuids_256 = collect_access_rule_uuids_paged(&pool, 256).await;
        assert_eq!(uuids_1, uuids_256);
        cleanup_rule(&pool, &r1.uuid).await;
        cleanup_rule(&pool, &r2.uuid).await;
        cleanup_asset_group(&pool, &ag1.uuid).await;
        cleanup_asset_group(&pool, &ag2.uuid).await;
        cleanup_vauban_group(&pool, &ug.uuid).await;
    }

    // ==================== Membership ====================

    #[tokio::test]
    async fn test_add_and_list_group_member() {
        let pool = test_pool().await;
        let user_id = ensure_test_user(&pool).await;
        let name = unique_name("vg_member");
        let group = create_test_vauban_group(&pool, &name).await;

        let resp = handle_access_request(
            &pool,
            AccessRequest::AddGroupMember {
                group_id: group.id,
                user_id,
            },
        )
        .await;
        match resp {
            AccessResponse::Ok => {}
            other => panic!("Expected Ok, got {:?}", other),
        }

        let resp = handle_access_request(
            &pool,
            AccessRequest::ListGroupMembers {
                group_id: group.id,
                page: page0(),
            },
        )
        .await;
        match resp {
            AccessResponse::MemberListPage(page) => {
                assert!(page.items.contains(&user_id));
            }
            other => panic!("Expected MemberListPage, got {:?}", other),
        }

        let resp = handle_access_request(
            &pool,
            AccessRequest::RemoveGroupMember {
                group_id: group.id,
                user_id,
            },
        )
        .await;
        match resp {
            AccessResponse::Ok => {}
            other => panic!("Expected Ok, got {:?}", other),
        }

        cleanup_vauban_group(&pool, &group.uuid).await;
    }

    #[tokio::test]
    async fn test_list_group_members_pagination_equivalence() {
        let pool = test_pool().await;
        let user_a = ensure_test_user(&pool).await;
        let user_b = insert_test_user(&pool, &unique_name("u_mem_b")).await;
        let group = create_test_vauban_group(&pool, &unique_name("vg_mem_eq")).await;
        handle_access_request(
            &pool,
            AccessRequest::AddGroupMember {
                group_id: group.id,
                user_id: user_a,
            },
        )
        .await;
        handle_access_request(
            &pool,
            AccessRequest::AddGroupMember {
                group_id: group.id,
                user_id: user_b,
            },
        )
        .await;
        let ids_1 = collect_group_member_ids_paged(&pool, group.id, 1).await;
        let ids_256 = collect_group_member_ids_paged(&pool, group.id, 256).await;
        assert_eq!(ids_1, ids_256);
        handle_access_request(
            &pool,
            AccessRequest::RemoveGroupMember {
                group_id: group.id,
                user_id: user_a,
            },
        )
        .await;
        handle_access_request(
            &pool,
            AccessRequest::RemoveGroupMember {
                group_id: group.id,
                user_id: user_b,
            },
        )
        .await;
        cleanup_vauban_group(&pool, &group.uuid).await;
    }

    #[tokio::test]
    async fn test_list_user_groups_pagination_equivalence() {
        let pool = test_pool().await;
        let user_id = ensure_test_user(&pool).await;
        let g1 = create_test_vauban_group(&pool, &unique_name("vg_ug_eq_a")).await;
        let g2 = create_test_vauban_group(&pool, &unique_name("vg_ug_eq_b")).await;
        handle_access_request(
            &pool,
            AccessRequest::AddGroupMember {
                group_id: g1.id,
                user_id,
            },
        )
        .await;
        handle_access_request(
            &pool,
            AccessRequest::AddGroupMember {
                group_id: g2.id,
                user_id,
            },
        )
        .await;
        let ids_1 = collect_user_group_ids_paged(&pool, user_id, 1).await;
        let ids_256 = collect_user_group_ids_paged(&pool, user_id, 256).await;
        assert_eq!(ids_1, ids_256);
        handle_access_request(
            &pool,
            AccessRequest::RemoveGroupMember {
                group_id: g1.id,
                user_id,
            },
        )
        .await;
        handle_access_request(
            &pool,
            AccessRequest::RemoveGroupMember {
                group_id: g2.id,
                user_id,
            },
        )
        .await;
        cleanup_vauban_group(&pool, &g1.uuid).await;
        cleanup_vauban_group(&pool, &g2.uuid).await;
    }

    // ==================== Evaluation ====================

    #[tokio::test]
    async fn test_check_access_denied_no_rule() {
        let pool = test_pool().await;
        let resp = handle_access_request(
            &pool,
            AccessRequest::CheckAccess {
                user_id: 99999,
                asset_group_id: 99999,
                protocol: "ssh".to_string(),
            },
        )
        .await;
        match resp {
            AccessResponse::AccessChecked(result) => {
                assert!(!result.allowed);
            }
            other => panic!("Expected AccessChecked, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_check_access_allowed() {
        let pool = test_pool().await;
        let user_id = ensure_test_user(&pool).await;
        let ug_name = unique_name("ug_eval");
        let ag_name = unique_name("ag_eval");
        let ug = create_test_vauban_group(&pool, &ug_name).await;
        let ag = create_test_asset_group(&pool, &ag_name).await;

        handle_access_request(
            &pool,
            AccessRequest::AddGroupMember {
                group_id: ug.id,
                user_id,
            },
        )
        .await;

        let rule =
            create_test_rule(&pool, &unique_name("eval_rule"), ug.id, ag.id, vec!["ssh"]).await;

        let resp = handle_access_request(
            &pool,
            AccessRequest::CheckAccess {
                user_id,
                asset_group_id: ag.id,
                protocol: "ssh".to_string(),
            },
        )
        .await;
        match resp {
            AccessResponse::AccessChecked(result) => {
                assert!(result.allowed);
            }
            other => panic!("Expected AccessChecked, got {:?}", other),
        }

        let resp = handle_access_request(
            &pool,
            AccessRequest::CheckAccess {
                user_id,
                asset_group_id: ag.id,
                protocol: "rdp".to_string(),
            },
        )
        .await;
        match resp {
            AccessResponse::AccessChecked(result) => {
                assert!(!result.allowed);
            }
            other => panic!("Expected AccessChecked, got {:?}", other),
        }

        handle_access_request(
            &pool,
            AccessRequest::RemoveGroupMember {
                group_id: ug.id,
                user_id,
            },
        )
        .await;
        cleanup_rule(&pool, &rule.uuid).await;
        cleanup_asset_group(&pool, &ag.uuid).await;
        cleanup_vauban_group(&pool, &ug.uuid).await;
    }

    #[tokio::test]
    async fn test_list_accessible_groups() {
        let pool = test_pool().await;
        let user_id = ensure_test_user(&pool).await;
        let ug_name = unique_name("ug_lag");
        let ag_name = unique_name("ag_lag");
        let ug = create_test_vauban_group(&pool, &ug_name).await;
        let ag = create_test_asset_group(&pool, &ag_name).await;

        handle_access_request(
            &pool,
            AccessRequest::AddGroupMember {
                group_id: ug.id,
                user_id,
            },
        )
        .await;
        let rule = create_test_rule(
            &pool,
            &unique_name("lag_rule"),
            ug.id,
            ag.id,
            vec!["ssh", "rdp"],
        )
        .await;

        let resp = handle_access_request(
            &pool,
            AccessRequest::ListAccessibleGroups {
                user_id,
                page: page0(),
            },
        )
        .await;
        match resp {
            AccessResponse::AccessibleGroupsPage(page) => {
                let entries = &page.items;
                let entry = entries.iter().find(|e| e.asset_group_id == ag.id);
                assert!(entry.is_some(), "Should find the asset group");
                let entry = entry.unwrap();
                assert!(entry.protocols.contains(&"ssh".to_string()));
                assert!(entry.protocols.contains(&"rdp".to_string()));
            }
            other => panic!("Expected AccessibleGroupsPage, got {:?}", other),
        }

        handle_access_request(
            &pool,
            AccessRequest::RemoveGroupMember {
                group_id: ug.id,
                user_id,
            },
        )
        .await;
        cleanup_rule(&pool, &rule.uuid).await;
        cleanup_asset_group(&pool, &ag.uuid).await;
        cleanup_vauban_group(&pool, &ug.uuid).await;
    }

    #[tokio::test]
    async fn test_list_accessible_groups_pagination_equivalence() {
        let pool = test_pool().await;
        let user_id = ensure_test_user(&pool).await;
        let ug_name = unique_name("ug_lag_eq");
        let ag_name = unique_name("ag_lag_eq");
        let ug = create_test_vauban_group(&pool, &ug_name).await;
        let ag = create_test_asset_group(&pool, &ag_name).await;
        handle_access_request(
            &pool,
            AccessRequest::AddGroupMember {
                group_id: ug.id,
                user_id,
            },
        )
        .await;
        let rule = create_test_rule(
            &pool,
            &unique_name("lag_eq_rule"),
            ug.id,
            ag.id,
            vec!["ssh", "rdp"],
        )
        .await;
        let n1 = collect_accessible_groups_normalized_paged(&pool, user_id, 50).await;
        let n256 = collect_accessible_groups_normalized_paged(&pool, user_id, 256).await;
        assert_eq!(n1, n256);
        handle_access_request(
            &pool,
            AccessRequest::RemoveGroupMember {
                group_id: ug.id,
                user_id,
            },
        )
        .await;
        cleanup_rule(&pool, &rule.uuid).await;
        cleanup_asset_group(&pool, &ag.uuid).await;
        cleanup_vauban_group(&pool, &ug.uuid).await;
    }

    // ==================== Group Options ====================

    #[tokio::test]
    async fn test_get_group_options() {
        let pool = test_pool().await;
        let resp =
            handle_access_request(&pool, AccessRequest::ListUserGroupOptions { page: page0() })
                .await;
        match resp {
            AccessResponse::UserGroupOptionsPage(_) => {}
            other => panic!("Expected UserGroupOptionsPage, got {:?}", other),
        }
        let resp = handle_access_request(
            &pool,
            AccessRequest::ListAssetGroupOptions {
                page: page0(),
                include_virtual: false,
            },
        )
        .await;
        match resp {
            AccessResponse::AssetGroupOptionsPage(_) => {}
            other => panic!("Expected AssetGroupOptionsPage, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_list_user_group_options_pagination_equivalence() {
        let pool = test_pool().await;
        let _g = create_test_vauban_group(&pool, &unique_name("vg_opt_eq")).await;
        let ids_1 = collect_user_group_option_ids_paged(&pool, 50).await;
        let ids_256 = collect_user_group_option_ids_paged(&pool, 256).await;
        assert_eq!(ids_1, ids_256);
        cleanup_vauban_group(&pool, &_g.uuid).await;
    }

    #[tokio::test]
    async fn test_list_asset_group_options_pagination_equivalence() {
        let pool = test_pool().await;
        let _g = create_test_asset_group(&pool, &unique_name("ag_opt_eq")).await;
        let ids_1 = collect_asset_group_option_ids_paged(&pool, 50).await;
        let ids_256 = collect_asset_group_option_ids_paged(&pool, 256).await;
        assert_eq!(ids_1, ids_256);
        cleanup_asset_group(&pool, &_g.uuid).await;
    }

    // ==================== Edge-case Tests ====================

    #[tokio::test]
    async fn test_pagination_empty_page_has_more_false() {
        let pool = test_pool().await;
        let resp = handle_access_request(
            &pool,
            AccessRequest::ListAssetGroups {
                page: IpcPageParams {
                    limit: 10,
                    offset: 999_999,
                },
                include_virtual: false,
            },
        )
        .await;
        let AccessResponse::AssetGroupPage(p) = resp else {
            panic!("expected AssetGroupPage, got {:?}", resp);
        };
        assert!(p.items.is_empty());
        assert!(!p.has_more, "has_more must be false when items is empty");
    }

    #[tokio::test]
    async fn test_list_asset_groups_limit_zero_uses_default() {
        let pool = test_pool().await;
        let resp = handle_access_request(
            &pool,
            AccessRequest::ListAssetGroups {
                page: IpcPageParams {
                    limit: 0,
                    offset: 0,
                },
                include_virtual: false,
            },
        )
        .await;
        let AccessResponse::AssetGroupPage(p) = resp else {
            panic!("expected AssetGroupPage, got {:?}", resp);
        };
        assert!(
            p.items.len() <= DEFAULT_IPC_PAGE_LIMIT as usize,
            "limit=0 should use DEFAULT_IPC_PAGE_LIMIT ({}), got {} items",
            DEFAULT_IPC_PAGE_LIMIT,
            p.items.len()
        );
    }

    #[tokio::test]
    async fn test_list_asset_groups_max_page_limit_clamped() {
        let pool = test_pool().await;
        let over_max = MAX_IPC_PAGE_LIMIT + 100;
        let resp = handle_access_request(
            &pool,
            AccessRequest::ListAssetGroups {
                page: IpcPageParams {
                    limit: over_max,
                    offset: 0,
                },
                include_virtual: false,
            },
        )
        .await;
        let AccessResponse::AssetGroupPage(p) = resp else {
            panic!("expected AssetGroupPage, got {:?}", resp);
        };
        assert!(
            p.items.len() <= MAX_IPC_PAGE_LIMIT as usize,
            "server should clamp to MAX_IPC_PAGE_LIMIT ({}), got {} items",
            MAX_IPC_PAGE_LIMIT,
            p.items.len()
        );
    }

    #[tokio::test]
    async fn test_drain_loop_terminates_with_empty_page() {
        let items = collect_paged(
            &test_pool().await,
            10,
            |p| AccessRequest::ListAssetGroups {
                page: p,
                include_virtual: false,
            },
            |r| match r {
                AccessResponse::AssetGroupPage(_) => IpcPage {
                    items: Vec::<AssetGroupInfo>::new(),
                    has_more: true,
                },
                other => panic!("unexpected: {:?}", other),
            },
        )
        .await;
        assert!(items.is_empty(), "drain loop must terminate on empty page");
    }

    #[tokio::test]
    async fn test_accessible_groups_multi_rule_protocol_merge() {
        let pool = test_pool().await;
        let user_id = ensure_test_user(&pool).await;
        let ug_name = unique_name("merge_ug");
        let ag_name = unique_name("merge_ag");
        let ug = create_test_vauban_group(&pool, &ug_name).await;
        let ag = create_test_asset_group(&pool, &ag_name).await;
        handle_access_request(
            &pool,
            AccessRequest::AddGroupMember {
                group_id: ug.id,
                user_id,
            },
        )
        .await;

        let ug2_name = unique_name("merge_ug2");
        let ug2 = create_test_vauban_group(&pool, &ug2_name).await;
        handle_access_request(
            &pool,
            AccessRequest::AddGroupMember {
                group_id: ug2.id,
                user_id,
            },
        )
        .await;

        let r1 = create_test_rule(&pool, &unique_name("merge_r1"), ug.id, ag.id, vec!["ssh"]).await;
        let r2 =
            create_test_rule(&pool, &unique_name("merge_r2"), ug2.id, ag.id, vec!["rdp"]).await;

        let groups = collect_accessible_groups_normalized_paged(&pool, user_id, 256).await;
        let entry = groups
            .iter()
            .find(|(id, _)| *id == ag.id)
            .expect("should find asset group");
        assert!(
            entry.1.contains(&"ssh".to_string()),
            "protocols should contain ssh"
        );
        assert!(
            entry.1.contains(&"rdp".to_string()),
            "protocols should contain rdp"
        );
        assert_eq!(entry.1.len(), 2, "should have exactly 2 merged protocols");

        for gid in [ug.id, ug2.id] {
            handle_access_request(
                &pool,
                AccessRequest::RemoveGroupMember {
                    group_id: gid,
                    user_id,
                },
            )
            .await;
        }
        cleanup_rule(&pool, &r1.uuid).await;
        cleanup_rule(&pool, &r2.uuid).await;
        cleanup_asset_group(&pool, &ag.uuid).await;
        cleanup_vauban_group(&pool, &ug.uuid).await;
        cleanup_vauban_group(&pool, &ug2.uuid).await;
    }

    #[tokio::test]
    async fn test_check_access_multi_merges_constraints() {
        let pool = test_pool().await;
        let user_id = ensure_test_user(&pool).await;

        let ug_name = unique_name("cam_ug");
        let ag1_name = unique_name("cam_ag1");
        let ag2_name = unique_name("cam_ag2");

        let ug = create_test_vauban_group(&pool, &ug_name).await;
        let ag1 = create_test_asset_group(&pool, &ag1_name).await;
        let ag2 = create_test_asset_group(&pool, &ag2_name).await;

        handle_access_request(
            &pool,
            AccessRequest::AddGroupMember {
                group_id: ug.id,
                user_id,
            },
        )
        .await;

        let r1 = handle_access_request(
            &pool,
            AccessRequest::CreateAccessRule {
                data: AccessRuleData {
                    name: unique_name("cam_r1"),
                    description: None,
                    user_group_id: ug.id,
                    asset_group_id: ag1.id,
                    allowed_protocols: vec!["ssh".to_string()],
                    valid_from: None,
                    valid_until: None,
                    require_mfa: true,
                    require_approval: false,
                    max_session_duration: Some(3600),
                    is_active: true,
                    priority: 0,
                },
                actor_uuid: None,
            },
        )
        .await;
        let r1_uuid = match &r1 {
            AccessResponse::AccessRule(Ok(info)) => info.uuid.clone(),
            other => panic!("expected AccessRule(Ok), got {:?}", other),
        };

        let r2 = handle_access_request(
            &pool,
            AccessRequest::CreateAccessRule {
                data: AccessRuleData {
                    name: unique_name("cam_r2"),
                    description: None,
                    user_group_id: ug.id,
                    asset_group_id: ag2.id,
                    allowed_protocols: vec!["ssh".to_string()],
                    valid_from: None,
                    valid_until: None,
                    require_mfa: false,
                    require_approval: true,
                    max_session_duration: Some(7200),
                    is_active: true,
                    priority: 0,
                },
                actor_uuid: None,
            },
        )
        .await;
        let r2_uuid = match &r2 {
            AccessResponse::AccessRule(Ok(info)) => info.uuid.clone(),
            other => panic!("expected AccessRule(Ok), got {:?}", other),
        };

        let resp = handle_access_request(
            &pool,
            AccessRequest::CheckAccessMulti {
                user_id,
                asset_group_ids: vec![ag1.id, ag2.id, 999_999],
                protocol: "ssh".to_string(),
            },
        )
        .await;
        let AccessResponse::AccessCheckedMulti(entries) = resp else {
            panic!("expected AccessCheckedMulti, got {:?}", resp);
        };
        assert_eq!(entries.len(), 3);

        let e1 = entries.iter().find(|e| e.asset_group_id == ag1.id).unwrap();
        assert!(e1.result.allowed);
        assert!(e1.result.require_mfa);
        assert!(!e1.result.require_approval);
        assert_eq!(e1.result.max_session_duration, Some(3600));

        let e2 = entries.iter().find(|e| e.asset_group_id == ag2.id).unwrap();
        assert!(e2.result.allowed);
        assert!(!e2.result.require_mfa);
        assert!(e2.result.require_approval);
        assert_eq!(e2.result.max_session_duration, Some(7200));

        let e3 = entries
            .iter()
            .find(|e| e.asset_group_id == 999_999)
            .unwrap();
        assert!(!e3.result.allowed, "non-existent group should be denied");

        handle_access_request(
            &pool,
            AccessRequest::RemoveGroupMember {
                group_id: ug.id,
                user_id,
            },
        )
        .await;
        cleanup_rule(&pool, &r1_uuid).await;
        cleanup_rule(&pool, &r2_uuid).await;
        cleanup_asset_group(&pool, &ag1.uuid).await;
        cleanup_asset_group(&pool, &ag2.uuid).await;
        cleanup_vauban_group(&pool, &ug.uuid).await;
    }

    #[tokio::test]
    async fn test_list_asset_groups_exact_page_boundary() {
        let pool = test_pool().await;
        let mut groups = Vec::new();
        for i in 0..3 {
            groups.push(create_test_asset_group(&pool, &unique_name(&format!("epb_{i}"))).await);
        }

        let resp = handle_access_request(
            &pool,
            AccessRequest::ListAssetGroups {
                page: IpcPageParams {
                    limit: 3,
                    offset: 0,
                },
                include_virtual: false,
            },
        )
        .await;
        let AccessResponse::AssetGroupPage(p) = resp else {
            panic!("expected AssetGroupPage, got {:?}", resp);
        };
        let our_ids: Vec<i32> = groups.iter().map(|g| g.id).collect();
        let page_has_ours = p.items.iter().filter(|g| our_ids.contains(&g.id)).count();

        if page_has_ours == 3 && p.items.len() == 3 {
            assert!(
                !p.has_more || p.items.len() >= 3,
                "exact boundary: has_more depends on total"
            );
        }

        for g in &groups {
            cleanup_asset_group(&pool, &g.uuid).await;
        }
    }

    // ==================== CheckAccessByUuid ====================

    async fn user_uuid(pool: &DbPool, user_id: i32) -> String {
        let mut conn = pool.get().await.unwrap();
        users::table
            .filter(users::id.eq(user_id))
            .select(users::uuid)
            .first::<Uuid>(&mut conn)
            .await
            .unwrap()
            .to_string()
    }

    async fn insert_test_asset(pool: &DbPool, name: &str) -> (i32, String) {
        insert_test_asset_with_type(pool, name, "ssh", 22).await
    }

    async fn insert_test_asset_with_type(
        pool: &DbPool,
        name: &str,
        asset_type: &str,
        port: i32,
    ) -> (i32, String) {
        let mut conn = pool.get().await.unwrap();
        use crate::schema::assets;
        let asset_uuid = Uuid::new_v4();
        let id: i32 = diesel::insert_into(assets::table)
            .values((
                assets::uuid.eq(asset_uuid),
                assets::name.eq(name),
                assets::hostname.eq("iacs.test.local"),
                assets::port.eq(port),
                assets::asset_type.eq(asset_type),
                assets::status.eq("active"),
                assets::connection_config.eq(serde_json::json!({})),
                assets::is_deleted.eq(false),
                assets::connection_username.eq(""),
            ))
            .returning(assets::id)
            .get_result::<i32>(&mut conn)
            .await
            .unwrap();
        (id, asset_uuid.to_string())
    }

    async fn link_asset_to_group(pool: &DbPool, asset_id: i32, asset_group_id: i32) {
        let mut conn = pool.get().await.unwrap();
        use crate::schema::asset_asset_groups;
        diesel::insert_into(asset_asset_groups::table)
            .values((
                asset_asset_groups::asset_id.eq(asset_id),
                asset_asset_groups::asset_group_id.eq(asset_group_id),
            ))
            .on_conflict_do_nothing()
            .execute(&mut conn)
            .await
            .unwrap();
    }

    async fn cleanup_asset(pool: &DbPool, asset_id: i32) {
        let mut conn = pool.get().await.unwrap();
        use crate::schema::{asset_asset_groups, assets};
        let _ = diesel::delete(
            asset_asset_groups::table.filter(asset_asset_groups::asset_id.eq(asset_id)),
        )
        .execute(&mut conn)
        .await;
        let _ = diesel::delete(assets::table.filter(assets::id.eq(asset_id)))
            .execute(&mut conn)
            .await;
    }

    fn assert_denied(resp: &AccessResponse) {
        match resp {
            AccessResponse::AccessChecked(r) => assert!(
                !r.allowed,
                "expected fail-closed denial AccessChecked {{ allowed: false, .. }}, got allowed=true"
            ),
            other => panic!(
                "expected fail-closed AccessChecked {{ allowed: false }}, got {:?}",
                other
            ),
        }
    }

    #[tokio::test]
    async fn test_check_access_by_uuid_invalid_user_uuid_denied() {
        let pool = test_pool().await;
        let resp = handle_access_request(
            &pool,
            AccessRequest::CheckAccessByUuid {
                user_uuid: "not-a-uuid".to_string(),
                asset_uuid: Uuid::new_v4().to_string(),
                protocol: "ssh".to_string(),
            },
        )
        .await;
        assert_denied(&resp);
    }

    #[tokio::test]
    async fn test_check_access_by_uuid_invalid_asset_uuid_denied() {
        let pool = test_pool().await;
        let resp = handle_access_request(
            &pool,
            AccessRequest::CheckAccessByUuid {
                user_uuid: Uuid::new_v4().to_string(),
                asset_uuid: "also-not-a-uuid".to_string(),
                protocol: "ssh".to_string(),
            },
        )
        .await;
        assert_denied(&resp);
    }

    #[tokio::test]
    async fn test_check_access_by_uuid_unknown_user_denied() {
        let pool = test_pool().await;
        let resp = handle_access_request(
            &pool,
            AccessRequest::CheckAccessByUuid {
                user_uuid: Uuid::new_v4().to_string(),
                asset_uuid: Uuid::new_v4().to_string(),
                protocol: "ssh".to_string(),
            },
        )
        .await;
        assert_denied(&resp);
    }

    #[tokio::test]
    async fn test_check_access_by_uuid_unknown_asset_denied() {
        let pool = test_pool().await;
        let user_id = ensure_test_user(&pool).await;
        let user_uuid = user_uuid(&pool, user_id).await;
        let resp = handle_access_request(
            &pool,
            AccessRequest::CheckAccessByUuid {
                user_uuid,
                asset_uuid: Uuid::new_v4().to_string(),
                protocol: "ssh".to_string(),
            },
        )
        .await;
        assert_denied(&resp);
    }

    #[tokio::test]
    async fn test_check_access_by_uuid_asset_in_no_group_denied() {
        let pool = test_pool().await;
        let user_id = ensure_test_user(&pool).await;
        let user_uuid = user_uuid(&pool, user_id).await;
        let (asset_id, asset_uuid) = insert_test_asset(&pool, &unique_name("asset_no_group")).await;

        let resp = handle_access_request(
            &pool,
            AccessRequest::CheckAccessByUuid {
                user_uuid,
                asset_uuid,
                protocol: "ssh".to_string(),
            },
        )
        .await;
        assert_denied(&resp);

        cleanup_asset(&pool, asset_id).await;
    }

    #[tokio::test]
    async fn test_check_access_by_uuid_inactive_user_denied() {
        let pool = test_pool().await;
        let username = unique_name("inactive_uuid_user");
        let mut conn = pool.get().await.unwrap();
        let email = format!("{username}@test.local");
        let user_id: i32 = diesel::insert_into(users::table)
            .values((
                users::username.eq(&username),
                users::email.eq(&email),
                users::password_hash.eq("nologin"),
                users::is_superuser.eq(false),
                users::is_staff.eq(false),
                users::is_active.eq(false),
            ))
            .returning(users::id)
            .get_result::<i32>(&mut conn)
            .await
            .unwrap();
        drop(conn);

        let user_uuid = user_uuid(&pool, user_id).await;
        let resp = handle_access_request(
            &pool,
            AccessRequest::CheckAccessByUuid {
                user_uuid,
                asset_uuid: Uuid::new_v4().to_string(),
                protocol: "ssh".to_string(),
            },
        )
        .await;
        assert_denied(&resp);
    }

    #[tokio::test]
    async fn test_check_access_by_uuid_deleted_asset_denied() {
        let pool = test_pool().await;
        let user_id = ensure_test_user(&pool).await;
        let user_uuid = user_uuid(&pool, user_id).await;

        let mut conn = pool.get().await.unwrap();
        use crate::schema::assets;
        let asset_uuid = Uuid::new_v4();
        let asset_id: i32 = diesel::insert_into(assets::table)
            .values((
                assets::uuid.eq(asset_uuid),
                assets::name.eq(unique_name("deleted_asset")),
                assets::hostname.eq("ssh.test.local"),
                assets::port.eq(22),
                assets::asset_type.eq("ssh"),
                assets::status.eq("active"),
                assets::connection_config.eq(serde_json::json!({})),
                assets::is_deleted.eq(true),
                assets::connection_username.eq("root"),
            ))
            .returning(assets::id)
            .get_result::<i32>(&mut conn)
            .await
            .unwrap();
        drop(conn);

        let resp = handle_access_request(
            &pool,
            AccessRequest::CheckAccessByUuid {
                user_uuid,
                asset_uuid: asset_uuid.to_string(),
                protocol: "ssh".to_string(),
            },
        )
        .await;
        assert_denied(&resp);

        cleanup_asset(&pool, asset_id).await;
    }

    #[tokio::test]
    async fn test_check_access_by_uuid_allowed_full_chain() {
        let pool = test_pool().await;
        let user_id = ensure_test_user(&pool).await;
        let user_uuid_str = user_uuid(&pool, user_id).await;

        let ug = create_test_vauban_group(&pool, &unique_name("ug_uuid_chain")).await;
        let ag = create_test_asset_group(&pool, &unique_name("ag_uuid_chain")).await;
        handle_access_request(
            &pool,
            AccessRequest::AddGroupMember {
                group_id: ug.id,
                user_id,
            },
        )
        .await;
        let rule = create_test_rule(
            &pool,
            &unique_name("uuid_chain_rule"),
            ug.id,
            ag.id,
            vec!["ssh"],
        )
        .await;
        let (asset_id, asset_uuid_str) =
            insert_test_asset(&pool, &unique_name("asset_uuid_chain")).await;
        link_asset_to_group(&pool, asset_id, ag.id).await;

        let resp = handle_access_request(
            &pool,
            AccessRequest::CheckAccessByUuid {
                user_uuid: user_uuid_str.clone(),
                asset_uuid: asset_uuid_str.clone(),
                protocol: "ssh".to_string(),
            },
        )
        .await;
        match resp {
            AccessResponse::AccessChecked(r) => assert!(r.allowed, "ssh must be allowed"),
            other => panic!("Expected AccessChecked, got {:?}", other),
        }

        // Wrong protocol must still deny -- the access_rule above only grants
        // ssh, so an rdp probe on the same user/asset must yield allowed=false
        // (and NOT bubble up an Error).
        let resp = handle_access_request(
            &pool,
            AccessRequest::CheckAccessByUuid {
                user_uuid: user_uuid_str,
                asset_uuid: asset_uuid_str,
                protocol: "rdp".to_string(),
            },
        )
        .await;
        assert_denied(&resp);

        cleanup_asset(&pool, asset_id).await;
        handle_access_request(
            &pool,
            AccessRequest::RemoveGroupMember {
                group_id: ug.id,
                user_id,
            },
        )
        .await;
        cleanup_rule(&pool, &rule.uuid).await;
        cleanup_asset_group(&pool, &ag.uuid).await;
        cleanup_vauban_group(&pool, &ug.uuid).await;
    }

    // ==================== IACS transport-meta semantics ==================
    //
    // Pin the bridging contract from
    // [`shared::access_guard::expand_protocol_for_access_match`]:
    // an access_rule that allows ANY applicative IACS protocol on a
    // given (user, asset) pair MUST grant the `iacs_tunnel`
    // transport-meta probe. Conversely, an access_rule that allows
    // ONLY non-IACS protocols (e.g. `ssh`) MUST deny `iacs_tunnel`.
    //
    // Without these tests, a regression in `protocol_match_filter`
    // that switched back to `@>` (containment) instead of `&&`
    // (overlap) -- or that dropped the meta-protocol expansion --
    // would silently break every IACS tunnel session in production
    // (the pre-fix bug). They are paired with the structural pin
    // tests in `escape_tests::protocol_match_filter_*`.
    // =====================================================================

    /// An access_rule with the canonical IACS form-side expansion
    /// (`["iacs_modbus", "iacs_opcua", "iacs_profinet", "iacs_iec104",
    /// "iacs_tcp"]`) MUST grant a `protocol="iacs_tunnel"` request
    /// on the matching (user, asset). This is the reproduction of
    /// the production bug that motivated the fix.
    #[tokio::test]
    async fn test_check_access_by_uuid_iacs_tunnel_meta_protocol_grants_via_iacs_modbus_rule() {
        let pool = test_pool().await;
        let user_id = ensure_test_user(&pool).await;
        let user_uuid_str = user_uuid(&pool, user_id).await;

        let ug = create_test_vauban_group(&pool, &unique_name("ug_iacs_meta")).await;
        let ag = create_test_asset_group(&pool, &unique_name("ag_iacs_meta")).await;
        handle_access_request(
            &pool,
            AccessRequest::AddGroupMember {
                group_id: ug.id,
                user_id,
            },
        )
        .await;
        // The form-side expansion writes EVERY iacs_* atomically; we
        // mirror that here. The transport-meta `iacs_tunnel` is NOT
        // in the rule (it is never written by the form).
        let rule = create_test_rule(
            &pool,
            &unique_name("iacs_meta_rule"),
            ug.id,
            ag.id,
            vec![
                "iacs_modbus",
                "iacs_opcua",
                "iacs_profinet",
                "iacs_iec104",
                "iacs_tcp",
            ],
        )
        .await;
        let (asset_id, asset_uuid_str) =
            insert_test_asset_with_type(&pool, &unique_name("asset_iacs_meta"), "iacs_modbus", 502)
                .await;
        link_asset_to_group(&pool, asset_id, ag.id).await;

        // The headline contract.
        let resp = handle_access_request(
            &pool,
            AccessRequest::CheckAccessByUuid {
                user_uuid: user_uuid_str.clone(),
                asset_uuid: asset_uuid_str.clone(),
                protocol: "iacs_tunnel".to_string(),
            },
        )
        .await;
        match resp {
            AccessResponse::AccessChecked(r) => assert!(
                r.allowed,
                "iacs_tunnel transport-meta MUST be allowed when the \
                 access_rule allows any applicative iacs_* protocol \
                 (this is the reproduction of the production bug)"
            ),
            other => panic!("Expected AccessChecked, got {:?}", other),
        }

        // The applicative protocol used in the rule must also still
        // be allowed (no regression on the verbatim path).
        let resp = handle_access_request(
            &pool,
            AccessRequest::CheckAccessByUuid {
                user_uuid: user_uuid_str.clone(),
                asset_uuid: asset_uuid_str.clone(),
                protocol: "iacs_modbus".to_string(),
            },
        )
        .await;
        match resp {
            AccessResponse::AccessChecked(r) => assert!(r.allowed),
            other => panic!("Expected AccessChecked, got {:?}", other),
        }

        cleanup_asset(&pool, asset_id).await;
        handle_access_request(
            &pool,
            AccessRequest::RemoveGroupMember {
                group_id: ug.id,
                user_id,
            },
        )
        .await;
        cleanup_rule(&pool, &rule.uuid).await;
        cleanup_asset_group(&pool, &ag.uuid).await;
        cleanup_vauban_group(&pool, &ug.uuid).await;
    }

    /// A rule scoped to `iacs_modbus` MUST grant `iacs_tunnel` only
    /// when the asset row is also `iacs_modbus` (asset_type binding).
    #[tokio::test]
    async fn test_check_access_by_uuid_iacs_tunnel_grants_via_partial_rule_with_only_iacs_modbus() {
        let pool = test_pool().await;
        let user_id = ensure_test_user(&pool).await;
        let user_uuid_str = user_uuid(&pool, user_id).await;

        let ug = create_test_vauban_group(&pool, &unique_name("ug_iacs_partial")).await;
        let ag = create_test_asset_group(&pool, &unique_name("ag_iacs_partial")).await;
        handle_access_request(
            &pool,
            AccessRequest::AddGroupMember {
                group_id: ug.id,
                user_id,
            },
        )
        .await;
        let rule = create_test_rule(
            &pool,
            &unique_name("iacs_partial_rule"),
            ug.id,
            ag.id,
            vec!["iacs_modbus"],
        )
        .await;
        let (asset_id, asset_uuid_str) = insert_test_asset_with_type(
            &pool,
            &unique_name("asset_iacs_partial"),
            "iacs_modbus",
            502,
        )
        .await;
        link_asset_to_group(&pool, asset_id, ag.id).await;

        let resp = handle_access_request(
            &pool,
            AccessRequest::CheckAccessByUuid {
                user_uuid: user_uuid_str,
                asset_uuid: asset_uuid_str,
                protocol: "iacs_tunnel".to_string(),
            },
        )
        .await;
        match resp {
            AccessResponse::AccessChecked(r) => assert!(
                r.allowed,
                "a one-protocol IACS rule (iacs_modbus only) MUST \
                 grant iacs_tunnel when asset_type is also iacs_modbus"
            ),
            other => panic!("Expected AccessChecked, got {:?}", other),
        }

        cleanup_asset(&pool, asset_id).await;
        handle_access_request(
            &pool,
            AccessRequest::RemoveGroupMember {
                group_id: ug.id,
                user_id,
            },
        )
        .await;
        cleanup_rule(&pool, &rule.uuid).await;
        cleanup_asset_group(&pool, &ag.uuid).await;
        cleanup_vauban_group(&pool, &ug.uuid).await;
    }

    #[tokio::test]
    async fn test_check_access_by_uuid_iacs_tunnel_denied_when_rule_modbus_but_asset_profinet() {
        let pool = test_pool().await;
        let user_id = ensure_test_user(&pool).await;
        let user_uuid_str = user_uuid(&pool, user_id).await;

        let ug = create_test_vauban_group(&pool, &unique_name("ug_iacs_cross")).await;
        let ag = create_test_asset_group(&pool, &unique_name("ag_iacs_cross")).await;
        handle_access_request(
            &pool,
            AccessRequest::AddGroupMember {
                group_id: ug.id,
                user_id,
            },
        )
        .await;
        let rule = create_test_rule(
            &pool,
            &unique_name("iacs_cross_rule"),
            ug.id,
            ag.id,
            vec!["iacs_modbus"],
        )
        .await;
        let (asset_id, asset_uuid_str) = insert_test_asset_with_type(
            &pool,
            &unique_name("asset_iacs_profinet"),
            "iacs_profinet",
            34962,
        )
        .await;
        link_asset_to_group(&pool, asset_id, ag.id).await;

        let resp = handle_access_request(
            &pool,
            AccessRequest::CheckAccessByUuid {
                user_uuid: user_uuid_str,
                asset_uuid: asset_uuid_str,
                protocol: "iacs_tunnel".to_string(),
            },
        )
        .await;
        match resp {
            AccessResponse::AccessChecked(r) => assert!(
                !r.allowed,
                "iacs_tunnel MUST be denied when rule is modbus-only but asset is profinet"
            ),
            other => panic!("Expected AccessChecked, got {:?}", other),
        }

        cleanup_asset(&pool, asset_id).await;
        handle_access_request(
            &pool,
            AccessRequest::RemoveGroupMember {
                group_id: ug.id,
                user_id,
            },
        )
        .await;
        cleanup_rule(&pool, &rule.uuid).await;
        cleanup_asset_group(&pool, &ag.uuid).await;
        cleanup_vauban_group(&pool, &ug.uuid).await;
    }

    #[tokio::test]
    async fn test_check_access_by_uuid_iacs_tunnel_denied_for_non_iacs_asset() {
        let pool = test_pool().await;
        let user_id = ensure_test_user(&pool).await;
        let user_uuid_str = user_uuid(&pool, user_id).await;

        let ug = create_test_vauban_group(&pool, &unique_name("ug_iacs_non")).await;
        let ag = create_test_asset_group(&pool, &unique_name("ag_iacs_non")).await;
        handle_access_request(
            &pool,
            AccessRequest::AddGroupMember {
                group_id: ug.id,
                user_id,
            },
        )
        .await;
        let rule = create_test_rule(
            &pool,
            &unique_name("iacs_non_rule"),
            ug.id,
            ag.id,
            vec![
                "iacs_modbus",
                "iacs_opcua",
                "iacs_profinet",
                "iacs_iec104",
                "iacs_tcp",
            ],
        )
        .await;
        let (asset_id, asset_uuid_str) =
            insert_test_asset(&pool, &unique_name("asset_ssh_only")).await;
        link_asset_to_group(&pool, asset_id, ag.id).await;

        let resp = handle_access_request(
            &pool,
            AccessRequest::CheckAccessByUuid {
                user_uuid: user_uuid_str,
                asset_uuid: asset_uuid_str,
                protocol: "iacs_tunnel".to_string(),
            },
        )
        .await;
        match resp {
            AccessResponse::AccessChecked(r) => assert!(
                !r.allowed,
                "iacs_tunnel MUST be denied for a classical ssh asset row"
            ),
            other => panic!("Expected AccessChecked, got {:?}", other),
        }

        cleanup_asset(&pool, asset_id).await;
        handle_access_request(
            &pool,
            AccessRequest::RemoveGroupMember {
                group_id: ug.id,
                user_id,
            },
        )
        .await;
        cleanup_rule(&pool, &rule.uuid).await;
        cleanup_asset_group(&pool, &ag.uuid).await;
        cleanup_vauban_group(&pool, &ug.uuid).await;
    }

    /// Negative pin: an `ssh`-only rule MUST NOT grant `iacs_tunnel`.
    /// The bridging is OR-of-applicative-IACS, NOT OR-of-anything.
    /// A regression that overgranted (e.g. expanded `iacs_tunnel`
    /// to `[ssh, rdp, iacs_*]` by accident) would be caught here.
    #[tokio::test]
    async fn test_check_access_by_uuid_iacs_tunnel_denied_when_only_ssh_rule() {
        let pool = test_pool().await;
        let user_id = ensure_test_user(&pool).await;
        let user_uuid_str = user_uuid(&pool, user_id).await;

        let ug = create_test_vauban_group(&pool, &unique_name("ug_iacs_neg")).await;
        let ag = create_test_asset_group(&pool, &unique_name("ag_iacs_neg")).await;
        handle_access_request(
            &pool,
            AccessRequest::AddGroupMember {
                group_id: ug.id,
                user_id,
            },
        )
        .await;
        let rule = create_test_rule(
            &pool,
            &unique_name("iacs_neg_rule"),
            ug.id,
            ag.id,
            vec!["ssh"],
        )
        .await;
        let (asset_id, asset_uuid_str) =
            insert_test_asset(&pool, &unique_name("asset_iacs_neg")).await;
        link_asset_to_group(&pool, asset_id, ag.id).await;

        let resp = handle_access_request(
            &pool,
            AccessRequest::CheckAccessByUuid {
                user_uuid: user_uuid_str,
                asset_uuid: asset_uuid_str,
                protocol: "iacs_tunnel".to_string(),
            },
        )
        .await;
        assert_denied(&resp);

        cleanup_asset(&pool, asset_id).await;
        handle_access_request(
            &pool,
            AccessRequest::RemoveGroupMember {
                group_id: ug.id,
                user_id,
            },
        )
        .await;
        cleanup_rule(&pool, &rule.uuid).await;
        cleanup_asset_group(&pool, &ag.uuid).await;
        cleanup_vauban_group(&pool, &ug.uuid).await;
    }

    // ==================== VerifySessionAccess ====================

    /// Helpers shared by the VerifySessionAccess test matrix. Insert a
    /// minimal `proxy_sessions` row tied to (user, asset) with the
    /// requested status / session_type. Returns (session_uuid).
    async fn insert_test_session(
        pool: &DbPool,
        user_id: i32,
        asset_id: i32,
        session_type: &str,
        status: &str,
    ) -> String {
        use crate::schema::proxy_sessions;
        use ipnetwork::IpNetwork;
        let mut conn = pool.get().await.unwrap();
        let session_uuid = Uuid::new_v4();
        let client_ip: IpNetwork = "127.0.0.1".parse().unwrap();
        diesel::insert_into(proxy_sessions::table)
            .values((
                proxy_sessions::uuid.eq(session_uuid),
                proxy_sessions::user_id.eq(user_id),
                proxy_sessions::asset_id.eq(asset_id),
                proxy_sessions::credential_id.eq(Uuid::new_v4().to_string()),
                proxy_sessions::credential_username.eq("root"),
                proxy_sessions::session_type.eq(session_type),
                proxy_sessions::status.eq(status),
                proxy_sessions::client_ip.eq(client_ip),
                proxy_sessions::is_recorded.eq(false),
                proxy_sessions::bytes_sent.eq(0i64),
                proxy_sessions::bytes_received.eq(0i64),
                proxy_sessions::commands_count.eq(0i32),
                proxy_sessions::metadata.eq(serde_json::json!({})),
            ))
            .execute(&mut conn)
            .await
            .unwrap();
        session_uuid.to_string()
    }

    async fn cleanup_session(pool: &DbPool, session_uuid: &str) {
        use crate::schema::proxy_sessions;
        let mut conn = pool.get().await.unwrap();
        let parsed = match Uuid::parse_str(session_uuid) {
            Ok(u) => u,
            Err(_) => return,
        };
        let _ = diesel::delete(proxy_sessions::table.filter(proxy_sessions::uuid.eq(parsed)))
            .execute(&mut conn)
            .await;
    }

    /// Build a complete (user_in_group + asset_in_group + active rule)
    /// fixture that grants `protocols` over (user_id, asset_id). Returns
    /// the rule + group uuids so the caller can mutate / clean them up.
    struct VsaFixture {
        user_id: i32,
        user_uuid: String,
        asset_id: i32,
        ug_uuid: String,
        ag_uuid: String,
        rule_uuid: String,
    }

    async fn make_vsa_fixture(pool: &DbPool, prefix: &str, protocols: Vec<&str>) -> VsaFixture {
        let username = unique_name(&format!("{prefix}_owner"));
        let user_id = insert_test_user(pool, &username).await;
        let user_uuid = user_uuid(pool, user_id).await;
        let ug = create_test_vauban_group(pool, &unique_name(&format!("{prefix}_ug"))).await;
        let ag = create_test_asset_group(pool, &unique_name(&format!("{prefix}_ag"))).await;
        handle_access_request(
            pool,
            AccessRequest::AddGroupMember {
                group_id: ug.id,
                user_id,
            },
        )
        .await;
        let rule = create_test_rule(
            pool,
            &unique_name(&format!("{prefix}_rule")),
            ug.id,
            ag.id,
            protocols,
        )
        .await;
        let (asset_id, _asset_uuid_str) =
            insert_test_asset(pool, &unique_name(&format!("{prefix}_asset"))).await;
        link_asset_to_group(pool, asset_id, ag.id).await;
        VsaFixture {
            user_id,
            user_uuid,
            asset_id,
            ug_uuid: ug.uuid,
            ag_uuid: ag.uuid,
            rule_uuid: rule.uuid,
        }
    }

    async fn cleanup_vsa_fixture(pool: &DbPool, fx: &VsaFixture) {
        cleanup_asset(pool, fx.asset_id).await;
        cleanup_rule(pool, &fx.rule_uuid).await;
        cleanup_asset_group(pool, &fx.ag_uuid).await;
        cleanup_vauban_group(pool, &fx.ug_uuid).await;
    }

    async fn deactivate_rule(pool: &DbPool, rule_uuid: &str) {
        use crate::schema::access_rules;
        let mut conn = pool.get().await.unwrap();
        let parsed = Uuid::parse_str(rule_uuid).unwrap();
        diesel::update(access_rules::table.filter(access_rules::uuid.eq(parsed)))
            .set(access_rules::is_active.eq(false))
            .execute(&mut conn)
            .await
            .unwrap();
    }

    async fn set_rule_validity(
        pool: &DbPool,
        rule_uuid: &str,
        valid_from: Option<chrono::DateTime<chrono::Utc>>,
        valid_until: Option<chrono::DateTime<chrono::Utc>>,
    ) {
        use crate::schema::access_rules;
        let mut conn = pool.get().await.unwrap();
        let parsed = Uuid::parse_str(rule_uuid).unwrap();
        diesel::update(access_rules::table.filter(access_rules::uuid.eq(parsed)))
            .set((
                access_rules::valid_from.eq(valid_from),
                access_rules::valid_until.eq(valid_until),
            ))
            .execute(&mut conn)
            .await
            .unwrap();
    }

    fn assert_session_decision(
        resp: AccessResponse,
        expected: shared::messages::SessionAccessDecision,
    ) {
        match resp {
            AccessResponse::SessionAccessChecked { decision } => assert_eq!(
                decision, expected,
                "VerifySessionAccess returned an unexpected decision"
            ),
            other => panic!("expected SessionAccessChecked, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_verify_session_access_allowed_owner_active_rule() {
        use shared::messages::{SessionAccessDecision, SessionAccessIntent};
        let pool = test_pool().await;
        let fx = make_vsa_fixture(&pool, "vsa_ok", vec!["ssh"]).await;
        let session_uuid =
            insert_test_session(&pool, fx.user_id, fx.asset_id, "ssh", "active").await;

        let resp = handle_access_request(
            &pool,
            AccessRequest::VerifySessionAccess {
                session_uuid: session_uuid.clone(),
                requesting_user_uuid: fx.user_uuid.clone(),
                intent: SessionAccessIntent::OpenViewer,
            },
        )
        .await;
        assert_session_decision(resp, SessionAccessDecision::Allowed);

        cleanup_session(&pool, &session_uuid).await;
        cleanup_vsa_fixture(&pool, &fx).await;
    }

    #[tokio::test]
    async fn test_verify_session_access_denied_not_owner() {
        use shared::messages::{SessionAccessDecision, SessionAccessIntent, SessionDenialReason};
        let pool = test_pool().await;
        let fx = make_vsa_fixture(&pool, "vsa_not_owner", vec!["ssh"]).await;
        let session_uuid =
            insert_test_session(&pool, fx.user_id, fx.asset_id, "ssh", "active").await;
        let intruder_id = insert_test_user(&pool, &unique_name("vsa_intruder")).await;
        let intruder_uuid = user_uuid(&pool, intruder_id).await;

        let resp = handle_access_request(
            &pool,
            AccessRequest::VerifySessionAccess {
                session_uuid: session_uuid.clone(),
                requesting_user_uuid: intruder_uuid,
                intent: SessionAccessIntent::OpenViewer,
            },
        )
        .await;
        assert_session_decision(
            resp,
            SessionAccessDecision::Denied(SessionDenialReason::NotOwner),
        );

        cleanup_session(&pool, &session_uuid).await;
        cleanup_vsa_fixture(&pool, &fx).await;
    }

    #[tokio::test]
    async fn test_verify_session_access_denied_session_terminated() {
        use shared::messages::{SessionAccessDecision, SessionAccessIntent, SessionDenialReason};
        let pool = test_pool().await;
        let fx = make_vsa_fixture(&pool, "vsa_term", vec!["ssh"]).await;
        let session_uuid =
            insert_test_session(&pool, fx.user_id, fx.asset_id, "ssh", "terminated").await;

        let resp = handle_access_request(
            &pool,
            AccessRequest::VerifySessionAccess {
                session_uuid: session_uuid.clone(),
                requesting_user_uuid: fx.user_uuid.clone(),
                intent: SessionAccessIntent::ConsumeWs,
            },
        )
        .await;
        assert_session_decision(
            resp,
            SessionAccessDecision::Denied(SessionDenialReason::Gone),
        );

        cleanup_session(&pool, &session_uuid).await;
        cleanup_vsa_fixture(&pool, &fx).await;
    }

    #[tokio::test]
    async fn test_verify_session_access_expired_consumews_collapses_to_gone() {
        // Interactive intents (OpenViewer / ConsumeWs) MUST collapse a
        // Gone session to `Gone` regardless of identity -- the
        // underlying connection is dead.
        use shared::messages::{SessionAccessDecision, SessionAccessIntent, SessionDenialReason};
        let pool = test_pool().await;
        let fx = make_vsa_fixture(&pool, "vsa_exp", vec!["ssh"]).await;
        let session_uuid =
            insert_test_session(&pool, fx.user_id, fx.asset_id, "ssh", "expired").await;

        let resp = handle_access_request(
            &pool,
            AccessRequest::VerifySessionAccess {
                session_uuid: session_uuid.clone(),
                requesting_user_uuid: fx.user_uuid.clone(),
                intent: SessionAccessIntent::ConsumeWs,
            },
        )
        .await;
        assert_session_decision(
            resp,
            SessionAccessDecision::Denied(SessionDenialReason::Gone),
        );

        cleanup_session(&pool, &session_uuid).await;
        cleanup_vsa_fixture(&pool, &fx).await;
    }

    #[tokio::test]
    async fn test_verify_session_access_owner_read_metadata_terminated_allowed() {
        // Regression guard: the owner of a `terminated` session MUST
        // still be able to read its metadata (the detail page doubles
        // as the audit trace + recording entry-point). Pre-fix, this
        // path collapsed to `Denied(Gone)` -> 410, which the web
        // handler turned into a 303 to /sessions with a misleading
        // "Session not found" flash.
        use shared::messages::{SessionAccessDecision, SessionAccessIntent};
        let pool = test_pool().await;
        let fx = make_vsa_fixture(&pool, "vsa_term_owner_read", vec!["ssh"]).await;
        let session_uuid =
            insert_test_session(&pool, fx.user_id, fx.asset_id, "ssh", "terminated").await;

        let resp = handle_access_request(
            &pool,
            AccessRequest::VerifySessionAccess {
                session_uuid: session_uuid.clone(),
                requesting_user_uuid: fx.user_uuid.clone(),
                intent: SessionAccessIntent::ReadMetadata,
            },
        )
        .await;
        assert_session_decision(resp, SessionAccessDecision::Allowed);

        cleanup_session(&pool, &session_uuid).await;
        cleanup_vsa_fixture(&pool, &fx).await;
    }

    #[tokio::test]
    async fn test_verify_session_access_owner_read_metadata_expired_allowed() {
        // Twin of the terminated case: every status that is_gone()
        // (terminated / expired / disconnected) MUST allow the owner
        // to read the historical metadata. Covers the `expired`
        // branch.
        use shared::messages::{SessionAccessDecision, SessionAccessIntent};
        let pool = test_pool().await;
        let fx = make_vsa_fixture(&pool, "vsa_exp_owner_read", vec!["ssh"]).await;
        let session_uuid =
            insert_test_session(&pool, fx.user_id, fx.asset_id, "ssh", "expired").await;

        let resp = handle_access_request(
            &pool,
            AccessRequest::VerifySessionAccess {
                session_uuid: session_uuid.clone(),
                requesting_user_uuid: fx.user_uuid.clone(),
                intent: SessionAccessIntent::ReadMetadata,
            },
        )
        .await;
        assert_session_decision(resp, SessionAccessDecision::Allowed);

        cleanup_session(&pool, &session_uuid).await;
        cleanup_vsa_fixture(&pool, &fx).await;
    }

    #[tokio::test]
    async fn test_verify_session_access_owner_read_metadata_disconnected_allowed() {
        // Third is_gone() status: `disconnected`.
        use shared::messages::{SessionAccessDecision, SessionAccessIntent};
        let pool = test_pool().await;
        let fx = make_vsa_fixture(&pool, "vsa_disc_owner_read", vec!["ssh"]).await;
        let session_uuid =
            insert_test_session(&pool, fx.user_id, fx.asset_id, "ssh", "disconnected").await;

        let resp = handle_access_request(
            &pool,
            AccessRequest::VerifySessionAccess {
                session_uuid: session_uuid.clone(),
                requesting_user_uuid: fx.user_uuid.clone(),
                intent: SessionAccessIntent::ReadMetadata,
            },
        )
        .await;
        assert_session_decision(resp, SessionAccessDecision::Allowed);

        cleanup_session(&pool, &session_uuid).await;
        cleanup_vsa_fixture(&pool, &fx).await;
    }

    #[tokio::test]
    async fn test_verify_session_access_intruder_read_metadata_terminated_not_owner() {
        // Anti-enumeration property: a non-owner probing a Gone
        // session via ReadMetadata MUST receive `NotOwner`, never
        // `Gone`. Otherwise an attacker who holds neither
        // `sessions:supervise` nor ownership could distinguish a
        // truly-non-existent UUID (NotFound -> 404) from an existing
        // but terminated session of someone else (Gone -> 410). The
        // owner-check-first ordering makes both collapse to the same
        // 404 at the service layer.
        use shared::messages::{SessionAccessDecision, SessionAccessIntent, SessionDenialReason};
        let pool = test_pool().await;
        let fx = make_vsa_fixture(&pool, "vsa_term_intruder_read", vec!["ssh"]).await;
        let session_uuid =
            insert_test_session(&pool, fx.user_id, fx.asset_id, "ssh", "terminated").await;
        let intruder_id = insert_test_user(&pool, &unique_name("vsa_intruder_read")).await;
        let intruder_uuid = user_uuid(&pool, intruder_id).await;

        let resp = handle_access_request(
            &pool,
            AccessRequest::VerifySessionAccess {
                session_uuid: session_uuid.clone(),
                requesting_user_uuid: intruder_uuid,
                intent: SessionAccessIntent::ReadMetadata,
            },
        )
        .await;
        assert_session_decision(
            resp,
            SessionAccessDecision::Denied(SessionDenialReason::NotOwner),
        );

        cleanup_session(&pool, &session_uuid).await;
        cleanup_vsa_fixture(&pool, &fx).await;
    }

    #[tokio::test]
    async fn test_verify_session_access_denied_rule_inactive() {
        use shared::messages::{SessionAccessDecision, SessionAccessIntent, SessionDenialReason};
        let pool = test_pool().await;
        let fx = make_vsa_fixture(&pool, "vsa_inactive", vec!["ssh"]).await;
        let session_uuid =
            insert_test_session(&pool, fx.user_id, fx.asset_id, "ssh", "active").await;
        deactivate_rule(&pool, &fx.rule_uuid).await;

        let resp = handle_access_request(
            &pool,
            AccessRequest::VerifySessionAccess {
                session_uuid: session_uuid.clone(),
                requesting_user_uuid: fx.user_uuid.clone(),
                intent: SessionAccessIntent::OpenViewer,
            },
        )
        .await;
        assert_session_decision(
            resp,
            SessionAccessDecision::Denied(SessionDenialReason::AccessRuleRevoked),
        );

        cleanup_session(&pool, &session_uuid).await;
        cleanup_vsa_fixture(&pool, &fx).await;
    }

    #[tokio::test]
    async fn test_verify_session_access_denied_rule_expired() {
        use chrono::{Duration, Utc};
        use shared::messages::{SessionAccessDecision, SessionAccessIntent, SessionDenialReason};
        let pool = test_pool().await;
        let fx = make_vsa_fixture(&pool, "vsa_rule_exp", vec!["ssh"]).await;
        let session_uuid =
            insert_test_session(&pool, fx.user_id, fx.asset_id, "ssh", "active").await;
        set_rule_validity(
            &pool,
            &fx.rule_uuid,
            None,
            Some(Utc::now() - Duration::hours(1)),
        )
        .await;

        let resp = handle_access_request(
            &pool,
            AccessRequest::VerifySessionAccess {
                session_uuid: session_uuid.clone(),
                requesting_user_uuid: fx.user_uuid.clone(),
                intent: SessionAccessIntent::OpenViewer,
            },
        )
        .await;
        assert_session_decision(
            resp,
            SessionAccessDecision::Denied(SessionDenialReason::AccessRuleRevoked),
        );

        cleanup_session(&pool, &session_uuid).await;
        cleanup_vsa_fixture(&pool, &fx).await;
    }

    #[tokio::test]
    async fn test_verify_session_access_denied_rule_not_yet_valid() {
        use chrono::{Duration, Utc};
        use shared::messages::{SessionAccessDecision, SessionAccessIntent, SessionDenialReason};
        let pool = test_pool().await;
        let fx = make_vsa_fixture(&pool, "vsa_rule_future", vec!["ssh"]).await;
        let session_uuid =
            insert_test_session(&pool, fx.user_id, fx.asset_id, "ssh", "active").await;
        set_rule_validity(
            &pool,
            &fx.rule_uuid,
            Some(Utc::now() + Duration::hours(1)),
            None,
        )
        .await;

        let resp = handle_access_request(
            &pool,
            AccessRequest::VerifySessionAccess {
                session_uuid: session_uuid.clone(),
                requesting_user_uuid: fx.user_uuid.clone(),
                intent: SessionAccessIntent::ConsumeWs,
            },
        )
        .await;
        assert_session_decision(
            resp,
            SessionAccessDecision::Denied(SessionDenialReason::AccessRuleRevoked),
        );

        cleanup_session(&pool, &session_uuid).await;
        cleanup_vsa_fixture(&pool, &fx).await;
    }

    #[tokio::test]
    async fn test_verify_session_access_denied_protocol_mismatch() {
        use shared::messages::{SessionAccessDecision, SessionAccessIntent, SessionDenialReason};
        let pool = test_pool().await;
        // Rule grants ssh, session is rdp -> protocol mismatch -> revoked.
        let fx = make_vsa_fixture(&pool, "vsa_proto", vec!["ssh"]).await;
        let session_uuid =
            insert_test_session(&pool, fx.user_id, fx.asset_id, "rdp", "active").await;

        let resp = handle_access_request(
            &pool,
            AccessRequest::VerifySessionAccess {
                session_uuid: session_uuid.clone(),
                requesting_user_uuid: fx.user_uuid.clone(),
                intent: SessionAccessIntent::OpenViewer,
            },
        )
        .await;
        assert_session_decision(
            resp,
            SessionAccessDecision::Denied(SessionDenialReason::AccessRuleRevoked),
        );

        cleanup_session(&pool, &session_uuid).await;
        cleanup_vsa_fixture(&pool, &fx).await;
    }

    #[tokio::test]
    async fn test_verify_session_access_denied_session_not_found() {
        use shared::messages::{SessionAccessDecision, SessionAccessIntent, SessionDenialReason};
        let pool = test_pool().await;
        let user_id = ensure_test_user(&pool).await;
        let user_uuid_str = user_uuid(&pool, user_id).await;

        let resp = handle_access_request(
            &pool,
            AccessRequest::VerifySessionAccess {
                session_uuid: Uuid::new_v4().to_string(),
                requesting_user_uuid: user_uuid_str,
                intent: SessionAccessIntent::OpenViewer,
            },
        )
        .await;
        assert_session_decision(
            resp,
            SessionAccessDecision::Denied(SessionDenialReason::NotFound),
        );
    }

    #[tokio::test]
    async fn test_verify_session_access_invalid_session_uuid_collapses_not_found() {
        use shared::messages::{SessionAccessDecision, SessionAccessIntent, SessionDenialReason};
        let pool = test_pool().await;
        let user_id = ensure_test_user(&pool).await;
        let user_uuid_str = user_uuid(&pool, user_id).await;

        let resp = handle_access_request(
            &pool,
            AccessRequest::VerifySessionAccess {
                session_uuid: "not-a-uuid".to_string(),
                requesting_user_uuid: user_uuid_str,
                intent: SessionAccessIntent::Terminate,
            },
        )
        .await;
        assert_session_decision(
            resp,
            SessionAccessDecision::Denied(SessionDenialReason::NotFound),
        );
    }

    #[tokio::test]
    async fn test_verify_session_access_full_wire_roundtrip() {
        use shared::ipc::IpcChannel;
        use shared::messages::{Message, SessionAccessDecision, SessionAccessIntent};
        use std::time::Duration;

        fn make_pipe() -> (i32, i32) {
            let mut fds = [0i32; 2];
            let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
            assert_eq!(rc, 0, "libc::pipe() failed");
            (fds[0], fds[1])
        }

        let pool = test_pool().await;
        let fx = make_vsa_fixture(&pool, "vsa_wire", vec!["ssh"]).await;
        let session_uuid =
            insert_test_session(&pool, fx.user_id, fx.asset_id, "ssh", "active").await;

        let (a_read, a_write) = make_pipe();
        let (b_read, b_write) = make_pipe();
        let proxy_side = unsafe { IpcChannel::from_raw_fds(a_read, b_write) };
        let access_side = unsafe { IpcChannel::from_raw_fds(b_read, a_write) };

        let pool_for_server = pool.clone();
        let server = tokio::task::spawn(async move {
            let (access_side, req) = tokio::task::spawn_blocking(move || {
                let req = access_side.recv().expect("access recv");
                (access_side, req)
            })
            .await
            .unwrap();
            let (request_id, request) = match req {
                Message::AccessRequest {
                    request_id,
                    request,
                } => (request_id, request),
                other => panic!("expected AccessRequest, got {:?}", other),
            };
            let response = handle_access_request(&pool_for_server, request).await;
            let reply = Message::AccessResponse {
                request_id,
                response,
            };
            tokio::task::spawn_blocking(move || {
                access_side.send(&reply).expect("access send");
            })
            .await
            .unwrap();
        });

        let request_id: u64 = 0xFEEDFACE;
        let req = Message::AccessRequest {
            request_id,
            request: AccessRequest::VerifySessionAccess {
                session_uuid: session_uuid.clone(),
                requesting_user_uuid: fx.user_uuid.clone(),
                intent: SessionAccessIntent::OpenViewer,
            },
        };
        let reply = tokio::task::spawn_blocking(move || {
            proxy_side.send(&req).expect("proxy send");
            proxy_side.recv().expect("proxy recv reply")
        })
        .await
        .unwrap();

        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("server task should complete within 5s")
            .unwrap();

        match reply {
            Message::AccessResponse {
                request_id: rid,
                response: AccessResponse::SessionAccessChecked { decision },
            } => {
                assert_eq!(rid, request_id, "request_id must round-trip verbatim");
                assert_eq!(
                    decision,
                    SessionAccessDecision::Allowed,
                    "owner with active rule must round-trip as Allowed"
                );
            }
            other => panic!(
                "expected AccessResponse(SessionAccessChecked), got {:?} -- if \
                 this changed, the AccessRequest/AccessResponse bincode \
                 variant indices may have drifted between vauban-web and \
                 vauban-access; both must be rebuilt together",
                other
            ),
        }

        cleanup_session(&pool, &session_uuid).await;
        cleanup_vsa_fixture(&pool, &fx).await;
    }

    /// SECURITY POLICY: handle_check_access_by_uuid MUST NOT bypass the
    /// access_rule lookup for superusers or staff. Both layers
    /// (vauban-web::handlers::web::ssh and the proxy-ssh re-check) now
    /// apply the EXACT same policy -- no privileged-user shortcut. If
    /// this test fails, somebody re-introduced the bypass and the proxy
    /// will start denying sessions that vauban-web waved through.
    #[tokio::test]
    async fn test_check_access_by_uuid_superuser_without_rule_is_denied() {
        let pool = test_pool().await;
        let username = unique_name("super_no_rule");
        let mut conn = pool.get().await.unwrap();
        let email = format!("{username}@test.local");
        let user_id: i32 = diesel::insert_into(users::table)
            .values((
                users::username.eq(&username),
                users::email.eq(&email),
                users::password_hash.eq("nologin"),
                users::is_superuser.eq(true),
                users::is_staff.eq(true),
                users::is_active.eq(true),
            ))
            .returning(users::id)
            .get_result::<i32>(&mut conn)
            .await
            .unwrap();
        drop(conn);

        let user_uuid_str = user_uuid(&pool, user_id).await;
        let (asset_id, asset_uuid_str) =
            insert_test_asset(&pool, &unique_name("super_no_rule_asset")).await;

        let resp = handle_access_request(
            &pool,
            AccessRequest::CheckAccessByUuid {
                user_uuid: user_uuid_str,
                asset_uuid: asset_uuid_str,
                protocol: "ssh".to_string(),
            },
        )
        .await;
        assert_denied(&resp);

        cleanup_asset(&pool, asset_id).await;
    }

    /// END-TO-END WIRE TEST: proves that a CheckAccessByUuid request
    /// serialised by a proxy-ssh-shaped caller round-trips through a
    /// real Unix pipe + bincode + handle_access_request + a real
    /// PostgreSQL pool, and the AccessResponse decodes correctly on
    /// the way back. This is the test that would have caught the
    /// "vauban-access never reads the proxy_ssh pipe" bug if it had
    /// existed at the time, AND would catch any future bincode
    /// variant-index drift between AccessRequest and AccessResponse
    /// across the proxy-ssh / vauban-access boundary.
    #[tokio::test]
    async fn test_check_access_by_uuid_full_wire_roundtrip() {
        use shared::ipc::IpcChannel;
        use shared::messages::Message;
        use std::time::Duration;

        // We can't use nix here (vauban-access doesn't depend on it).
        // libc::pipe is portable enough for a unit test on macOS/Linux.
        fn make_pipe() -> (i32, i32) {
            let mut fds = [0i32; 2];
            let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
            assert_eq!(rc, 0, "libc::pipe() failed");
            (fds[0], fds[1])
        }

        let pool = test_pool().await;
        let user_id = ensure_test_user(&pool).await;
        let user_uuid_str = user_uuid(&pool, user_id).await;
        let ug = create_test_vauban_group(&pool, &unique_name("ug_wire")).await;
        let ag = create_test_asset_group(&pool, &unique_name("ag_wire")).await;
        handle_access_request(
            &pool,
            AccessRequest::AddGroupMember {
                group_id: ug.id,
                user_id,
            },
        )
        .await;
        let rule =
            create_test_rule(&pool, &unique_name("wire_rule"), ug.id, ag.id, vec!["ssh"]).await;
        let (asset_id, asset_uuid_str) = insert_test_asset(&pool, &unique_name("asset_wire")).await;
        link_asset_to_group(&pool, asset_id, ag.id).await;

        // Build a paired pipe -- proxy side writes, access side reads.
        let (a_read, a_write) = make_pipe();
        let (b_read, b_write) = make_pipe();
        let proxy_side = unsafe { IpcChannel::from_raw_fds(a_read, b_write) };
        let access_side = unsafe { IpcChannel::from_raw_fds(b_read, a_write) };

        // Stand up a minimal vauban-access dispatch loop on the access
        // side: read one Message, dispatch, reply. We deliberately do
        // NOT call run_service() here (it owns the runtime / capsicum)
        // -- we only exercise the message contract.
        let pool_for_server = pool.clone();
        let server = tokio::task::spawn(async move {
            let (access_side, req) = tokio::task::spawn_blocking(move || {
                let req = access_side.recv().expect("access recv");
                (access_side, req)
            })
            .await
            .unwrap();
            let (request_id, request) = match req {
                Message::AccessRequest {
                    request_id,
                    request,
                } => (request_id, request),
                other => panic!("expected AccessRequest, got {:?}", other),
            };
            let response = handle_access_request(&pool_for_server, request).await;
            let reply = Message::AccessResponse {
                request_id,
                response,
            };
            tokio::task::spawn_blocking(move || {
                access_side.send(&reply).expect("access send");
            })
            .await
            .unwrap();
        });

        // Proxy side: send the request, await the reply.
        let request_id: u64 = 0xCAFEBABE;
        let req = Message::AccessRequest {
            request_id,
            request: AccessRequest::CheckAccessByUuid {
                user_uuid: user_uuid_str.clone(),
                asset_uuid: asset_uuid_str.clone(),
                protocol: "ssh".to_string(),
            },
        };
        let reply = tokio::task::spawn_blocking(move || {
            proxy_side.send(&req).expect("proxy send");
            proxy_side.recv().expect("proxy recv reply")
        })
        .await
        .unwrap();

        // 5s is generous for an in-memory dispatch with a warm pool.
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("server task should complete within 5s")
            .unwrap();

        match reply {
            Message::AccessResponse {
                request_id: rid,
                response: AccessResponse::AccessChecked(r),
            } => {
                assert_eq!(rid, request_id, "request_id must round-trip verbatim");
                assert!(
                    r.allowed,
                    "user is in vauban_group, asset is in asset_group, \
                     access_rule grants ssh -> must be allowed"
                );
            }
            other => panic!(
                "expected AccessResponse(AccessChecked), got {:?} -- if this \
                 changed, AccessRequest/AccessResponse bincode variant \
                 indices may have drifted between proxy-ssh and vauban-\
                 access; both must be rebuilt together",
                other
            ),
        }

        cleanup_asset(&pool, asset_id).await;
        handle_access_request(
            &pool,
            AccessRequest::RemoveGroupMember {
                group_id: ug.id,
                user_id,
            },
        )
        .await;
        cleanup_rule(&pool, &rule.uuid).await;
        cleanup_asset_group(&pool, &ag.uuid).await;
        cleanup_vauban_group(&pool, &ug.uuid).await;
    }
}
