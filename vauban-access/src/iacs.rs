//! IACS / EWS onboarding -- atomic decision recorder.
//!
//! Mirrors the JIT `RecordApprovalDecision` pattern (see
//! `handlers::handle_record_approval_decision`):
//!
//!   - Every write operation runs in a single Diesel transaction.
//!   - The `ews_audit_log` row is INSERTed inside the same transaction
//!     as the state mutation; the `block_ews_audit_log_mutation`
//!     PostgreSQL trigger pins the append-only contract at the lowest
//!     layer.
//!   - In-transaction re-checks defend against TOCTOU drift between
//!     the optimistic check at form-submit time (in vauban-web's
//!     `services::iacs::check_fingerprint_uniqueness_advisory`) and
//!     the authoritative decision here.
//!   - Fail-closed: any DB error collapses to a structured
//!     `EwsDenyReason` reply and leaves the EWS / request row in its
//!     previous state. Operators get the real cause at ERROR level so
//!     missing migrations / schema drift do not silently masquerade
//!     as "not found".
//!
//! Wire compatibility: every variant added to `AccessRequest` /
//! `AccessResponse` in `shared::messages` MUST be appended to the
//! match in `handle_iacs_request` so the dispatch never collapses to
//! a generic `Error` (which would leak the existence of the variant
//! and break the structural pin tests).

use chrono::Utc;
use diesel::prelude::*;
use diesel_async::AsyncConnection;
use diesel_async::RunQueryDsl;
use shared::messages::{AccessResponse, EwsDecisionKind, EwsDenyReason};
use tracing::{error, info};
use uuid::Uuid;

use crate::db::DbConnection;
use crate::schema::{ews, ews_audit_log, ews_onboarding_requests, users};

// ===================================================================
// Internal structs / errors
// ===================================================================

/// Resolved actor identity, fetched once outside the transaction so we
/// avoid an extra round-trip and the in-transaction re-checks operate
/// on a stable PK.
struct ActorIdentity {
    id: i32,
    username: String,
}

/// Snapshot of the bits of a target user (the requester / EWS owner)
/// we need both for ownership re-check and for audit snapshots.
struct TargetUserSnapshot {
    id: i32,
    username: String,
    is_active: bool,
    is_deleted: bool,
}

/// Local error type used inside the `transaction` closures. Every
/// variant maps to either a structured `EwsDenyReason` (business deny)
/// or a fail-closed `RequestNotFound` / `EwsNotFound` for raw DB
/// errors.
enum IacsTxnError {
    Deny(EwsDenyReason),
    Db(String),
}

impl From<diesel::result::Error> for IacsTxnError {
    fn from(e: diesel::result::Error) -> Self {
        Self::Db(e.to_string())
    }
}

// ===================================================================
// Hooks
// ===================================================================

/// Best-effort termination of every long-running SSH tunnel currently
/// open from the EWS towards Vauban. Stub for this preliminary
/// iteration: the IACS asset feature that drives such tunnels is not
/// shipped yet, so this is a no-op. Wired in `disable_ews` /
/// `offboard_ews` so the contract is stable before the consumer
/// arrives.
///
/// IMPORTANT: this is NOT about the user's web session. Killing the
/// owner's HTTPS session would surprise legitimate operators that
/// happen to be working in the platform UI when an admin disables
/// one of their many EWS. The hook only targets the SSH clients
/// that the EWS itself opens (long-running tunnels for IACS asset
/// access).
fn terminate_ssh_tunnels_for_ews(ews_uuid: Uuid) {
    info!(
        %ews_uuid,
        "terminate_ssh_tunnels_for_ews: no-op stub (IACS asset tunnels \
         not introduced yet); will fan out termination once the asset \
         feature lands"
    );
}

// ===================================================================
// Common helpers
// ===================================================================

#[allow(clippy::result_large_err)]
fn parse_uuid_or_request_not_found(s: &str) -> Result<Uuid, AccessResponse> {
    Uuid::parse_str(s).map_err(|_| AccessResponse::EwsDecisionDenied {
        reason: EwsDenyReason::RequestNotFound,
    })
}

#[allow(clippy::result_large_err)]
fn parse_uuid_or_ews_not_found(s: &str) -> Result<Uuid, AccessResponse> {
    Uuid::parse_str(s).map_err(|_| AccessResponse::EwsDecisionDenied {
        reason: EwsDenyReason::EwsNotFound,
    })
}

async fn load_actor(
    conn: &mut DbConnection,
    actor_user_uuid: &str,
    not_found_reason: EwsDenyReason,
) -> Result<ActorIdentity, AccessResponse> {
    let actor_uuid =
        Uuid::parse_str(actor_user_uuid).map_err(|_| AccessResponse::EwsDecisionDenied {
            reason: not_found_reason,
        })?;
    match users::table
        .filter(users::uuid.eq(actor_uuid))
        .select((users::id, users::username))
        .first::<(i32, String)>(conn)
        .await
    {
        Ok((id, username)) => Ok(ActorIdentity { id, username }),
        Err(_) => Err(AccessResponse::EwsDecisionDenied {
            reason: not_found_reason,
        }),
    }
}

async fn load_target_user(
    conn: &mut DbConnection,
    user_id: i32,
) -> Result<TargetUserSnapshot, IacsTxnError> {
    match users::table
        .filter(users::id.eq(user_id))
        .select((
            users::id,
            users::username,
            users::is_active,
            users::is_deleted,
        ))
        .first::<(i32, String, bool, bool)>(conn)
        .await
    {
        Ok((id, username, is_active, is_deleted)) => Ok(TargetUserSnapshot {
            id,
            username,
            is_active,
            is_deleted,
        }),
        Err(diesel::result::Error::NotFound) => Err(IacsTxnError::Deny(EwsDenyReason::NotOwner)),
        Err(e) => Err(IacsTxnError::Db(e.to_string())),
    }
}

fn parse_actor_ip(s: Option<&str>) -> Option<ipnetwork::IpNetwork> {
    s.and_then(|s| s.parse::<std::net::IpAddr>().ok())
        .map(ipnetwork::IpNetwork::from)
}

fn map_db_error_to_deny(msg: &str, fallback: EwsDenyReason) -> EwsDenyReason {
    let lower = msg.to_lowercase();
    if lower.contains("ews_active_fingerprint_uniq") {
        EwsDenyReason::KeyAlreadyUsed
    } else if lower.contains("ews_request_decision_consistency")
        || lower.contains("ews_disabled_consistency")
        || lower.contains("ews_offboarded_consistency")
    {
        EwsDenyReason::RequestNotPending
    } else {
        fallback
    }
}

// ===================================================================
// Handlers
// ===================================================================

/// Submit a new EWS onboarding request.
#[allow(clippy::too_many_arguments)]
pub async fn handle_submit_ews_onboarding(
    conn: &mut DbConnection,
    actor_user_uuid: &str,
    name: String,
    public_key: String,
    public_key_fingerprint: String,
    key_algo: String,
    justification: String,
    max_ews_per_user: u32,
    actor_ip: Option<String>,
) -> AccessResponse {
    let actor = match load_actor(conn, actor_user_uuid, EwsDenyReason::RequestNotFound).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };

    let actor_ip_inet = parse_actor_ip(actor_ip.as_deref());
    let actor_username = actor.username.clone();

    let outcome: Result<(Uuid, i64), IacsTxnError> = conn
        .transaction::<(Uuid, i64), IacsTxnError, _>(move |conn| {
            let actor_username = actor_username.clone();
            let name = name.clone();
            let public_key = public_key.clone();
            let public_key_fingerprint = public_key_fingerprint.clone();
            let key_algo = key_algo.clone();
            let justification = justification.clone();
            Box::pin(async move {
                // Re-check actor still exists / is active inside the
                // transaction. A user soft-deleted between the actor
                // load and the transaction would create an orphan
                // pending request -- defend against it.
                let target = load_target_user(conn, actor.id).await?;
                if target.is_deleted || !target.is_active {
                    return Err(IacsTxnError::Deny(EwsDenyReason::TargetUserDisabled));
                }

                // Quota: count active + pending rows owned by the user.
                if max_ews_per_user > 0 {
                    let active_count: i64 = ews::table
                        .filter(ews::user_id.eq(actor.id))
                        .filter(ews::offboarded_at.is_null())
                        .count()
                        .get_result(conn)
                        .await?;
                    let pending_count: i64 = ews_onboarding_requests::table
                        .filter(ews_onboarding_requests::user_id.eq(actor.id))
                        .filter(ews_onboarding_requests::status.eq("pending"))
                        .count()
                        .get_result(conn)
                        .await?;
                    if (active_count + pending_count) as u32 >= max_ews_per_user {
                        return Err(IacsTxnError::Deny(EwsDenyReason::MaxEwsPerUserReached));
                    }
                }

                // Authoritative fingerprint uniqueness check. Three
                // overlapping locks:
                //   1. existing active OR disabled `ews` row -- the
                //      partial unique index will also catch this on
                //      approval, but we surface the deny earlier with
                //      a cleaner message.
                //   2. another user's pending request with the same
                //      fingerprint -- not enforced at the DB layer
                //      (intentional: two pendings could legitimately
                //      collide if a third party tries to claim the
                //      same key, and the loser at decision time would
                //      simply rejoin the queue). Surfaced as
                //      KeyAlreadyUsed for UX clarity.
                let existing_active: i64 = ews::table
                    .filter(ews::public_key_fingerprint.eq(&public_key_fingerprint))
                    .filter(ews::offboarded_at.is_null())
                    .count()
                    .get_result(conn)
                    .await?;
                if existing_active > 0 {
                    return Err(IacsTxnError::Deny(EwsDenyReason::KeyAlreadyUsed));
                }
                let existing_pending: i64 = ews_onboarding_requests::table
                    .filter(
                        ews_onboarding_requests::public_key_fingerprint.eq(&public_key_fingerprint),
                    )
                    .filter(ews_onboarding_requests::status.eq("pending"))
                    .count()
                    .get_result(conn)
                    .await?;
                if existing_pending > 0 {
                    return Err(IacsTxnError::Deny(EwsDenyReason::KeyAlreadyUsed));
                }

                let request_uuid: Uuid = diesel::insert_into(ews_onboarding_requests::table)
                    .values((
                        ews_onboarding_requests::user_id.eq(actor.id),
                        ews_onboarding_requests::name.eq(&name),
                        ews_onboarding_requests::public_key.eq(&public_key),
                        ews_onboarding_requests::public_key_fingerprint.eq(&public_key_fingerprint),
                        ews_onboarding_requests::key_algo.eq(&key_algo),
                        ews_onboarding_requests::justification.eq(&justification),
                    ))
                    .returning(ews_onboarding_requests::uuid)
                    .get_result(conn)
                    .await?;

                let audit_id: i64 = diesel::insert_into(ews_audit_log::table)
                    .values((
                        ews_audit_log::request_uuid.eq(Some(request_uuid)),
                        ews_audit_log::event.eq("submitted"),
                        ews_audit_log::actor_user_id.eq(Some(actor.id)),
                        ews_audit_log::actor_username.eq(&actor_username),
                        ews_audit_log::target_user_id.eq(Some(target.id)),
                        ews_audit_log::target_username.eq(&target.username),
                        ews_audit_log::ews_name.eq(&name),
                        ews_audit_log::public_key_fingerprint.eq(&public_key_fingerprint),
                        ews_audit_log::actor_ip.eq(actor_ip_inet),
                    ))
                    .returning(ews_audit_log::id)
                    .get_result(conn)
                    .await?;

                Ok((request_uuid, audit_id))
            })
        })
        .await;

    match outcome {
        Ok((request_uuid, audit_log_id)) => {
            info!(
                actor = %actor.username,
                %request_uuid,
                audit_log_id,
                "EWS onboarding request submitted"
            );
            AccessResponse::EwsRequestSubmitted {
                request_uuid: request_uuid.to_string(),
                audit_log_id,
            }
        }
        Err(IacsTxnError::Deny(reason)) => {
            info!(actor = %actor.username, ?reason, "EWS submit denied");
            AccessResponse::EwsDecisionDenied { reason }
        }
        Err(IacsTxnError::Db(msg)) => {
            error!(actor = %actor.username, db_error = %msg, "EWS submit DB error");
            AccessResponse::EwsDecisionDenied {
                reason: map_db_error_to_deny(&msg, EwsDenyReason::RequestNotFound),
            }
        }
    }
}

/// Edit a pending request the actor owns.
#[allow(clippy::too_many_arguments)]
pub async fn handle_edit_ews_request(
    conn: &mut DbConnection,
    actor_user_uuid: &str,
    request_uuid: &str,
    name: String,
    public_key: String,
    public_key_fingerprint: String,
    key_algo: String,
    justification: String,
    actor_ip: Option<String>,
) -> AccessResponse {
    let request_uuid_parsed = match parse_uuid_or_request_not_found(request_uuid) {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    let actor = match load_actor(conn, actor_user_uuid, EwsDenyReason::RequestNotFound).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    let actor_ip_inet = parse_actor_ip(actor_ip.as_deref());
    let actor_username = actor.username.clone();

    let outcome: Result<i64, IacsTxnError> = conn
        .transaction::<i64, IacsTxnError, _>(move |conn| {
            let actor_username = actor_username.clone();
            let name = name.clone();
            let public_key = public_key.clone();
            let public_key_fingerprint = public_key_fingerprint.clone();
            let key_algo = key_algo.clone();
            let justification = justification.clone();
            Box::pin(async move {
                // Locate + ownership re-check + status re-check, all in
                // one query. NotFound -> RequestNotFound (collapse to
                // 404 in the handler -- anti-enumeration). Wrong owner
                // -> NotOwner (also 404).
                let row: Option<(i32, String)> = ews_onboarding_requests::table
                    .filter(ews_onboarding_requests::uuid.eq(request_uuid_parsed))
                    .select((
                        ews_onboarding_requests::user_id,
                        ews_onboarding_requests::status,
                    ))
                    .first::<(i32, String)>(conn)
                    .await
                    .optional()?;
                let (user_id, status) = match row {
                    Some(r) => r,
                    None => return Err(IacsTxnError::Deny(EwsDenyReason::RequestNotFound)),
                };
                if user_id != actor.id {
                    return Err(IacsTxnError::Deny(EwsDenyReason::NotOwner));
                }
                if status != "pending" {
                    return Err(IacsTxnError::Deny(EwsDenyReason::RequestNotPending));
                }

                // Fingerprint may have changed -- re-run the uniqueness
                // re-check exactly like submit, but exclude the current
                // pending row from the pending counterpart.
                let existing_active: i64 = ews::table
                    .filter(ews::public_key_fingerprint.eq(&public_key_fingerprint))
                    .filter(ews::offboarded_at.is_null())
                    .count()
                    .get_result(conn)
                    .await?;
                if existing_active > 0 {
                    return Err(IacsTxnError::Deny(EwsDenyReason::KeyAlreadyUsed));
                }
                let existing_pending: i64 = ews_onboarding_requests::table
                    .filter(
                        ews_onboarding_requests::public_key_fingerprint.eq(&public_key_fingerprint),
                    )
                    .filter(ews_onboarding_requests::status.eq("pending"))
                    .filter(ews_onboarding_requests::uuid.ne(request_uuid_parsed))
                    .count()
                    .get_result(conn)
                    .await?;
                if existing_pending > 0 {
                    return Err(IacsTxnError::Deny(EwsDenyReason::KeyAlreadyUsed));
                }

                let now = Utc::now();
                let updated = diesel::update(
                    ews_onboarding_requests::table
                        .filter(ews_onboarding_requests::uuid.eq(request_uuid_parsed))
                        .filter(ews_onboarding_requests::status.eq("pending"))
                        .filter(ews_onboarding_requests::user_id.eq(actor.id)),
                )
                .set((
                    ews_onboarding_requests::name.eq(&name),
                    ews_onboarding_requests::public_key.eq(&public_key),
                    ews_onboarding_requests::public_key_fingerprint.eq(&public_key_fingerprint),
                    ews_onboarding_requests::key_algo.eq(&key_algo),
                    ews_onboarding_requests::justification.eq(&justification),
                    ews_onboarding_requests::updated_at.eq(now),
                ))
                .execute(conn)
                .await?;
                if updated == 0 {
                    return Err(IacsTxnError::Deny(EwsDenyReason::RequestNotPending));
                }

                let audit_id: i64 = diesel::insert_into(ews_audit_log::table)
                    .values((
                        ews_audit_log::request_uuid.eq(Some(request_uuid_parsed)),
                        ews_audit_log::event.eq("edited"),
                        ews_audit_log::actor_user_id.eq(Some(actor.id)),
                        ews_audit_log::actor_username.eq(&actor_username),
                        ews_audit_log::target_user_id.eq(Some(actor.id)),
                        ews_audit_log::target_username.eq(&actor_username),
                        ews_audit_log::ews_name.eq(&name),
                        ews_audit_log::public_key_fingerprint.eq(&public_key_fingerprint),
                        ews_audit_log::actor_ip.eq(actor_ip_inet),
                    ))
                    .returning(ews_audit_log::id)
                    .get_result(conn)
                    .await?;
                Ok(audit_id)
            })
        })
        .await;

    match outcome {
        Ok(audit_log_id) => {
            info!(actor = %actor.username, %request_uuid_parsed, audit_log_id, "EWS request edited");
            AccessResponse::EwsRequestEdited { audit_log_id }
        }
        Err(IacsTxnError::Deny(reason)) => AccessResponse::EwsDecisionDenied { reason },
        Err(IacsTxnError::Db(msg)) => {
            error!(actor = %actor.username, db_error = %msg, "EWS edit DB error");
            AccessResponse::EwsDecisionDenied {
                reason: map_db_error_to_deny(&msg, EwsDenyReason::RequestNotFound),
            }
        }
    }
}

/// Cancel a pending request the actor owns.
pub async fn handle_cancel_ews_request(
    conn: &mut DbConnection,
    actor_user_uuid: &str,
    request_uuid: &str,
    actor_ip: Option<String>,
) -> AccessResponse {
    let request_uuid_parsed = match parse_uuid_or_request_not_found(request_uuid) {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    let actor = match load_actor(conn, actor_user_uuid, EwsDenyReason::RequestNotFound).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    let actor_ip_inet = parse_actor_ip(actor_ip.as_deref());
    let actor_username = actor.username.clone();

    let outcome: Result<i64, IacsTxnError> = conn
        .transaction::<i64, IacsTxnError, _>(move |conn| {
            let actor_username = actor_username.clone();
            Box::pin(async move {
                let row: Option<(i32, String, String, String)> = ews_onboarding_requests::table
                    .filter(ews_onboarding_requests::uuid.eq(request_uuid_parsed))
                    .select((
                        ews_onboarding_requests::user_id,
                        ews_onboarding_requests::status,
                        ews_onboarding_requests::name,
                        ews_onboarding_requests::public_key_fingerprint,
                    ))
                    .first::<(i32, String, String, String)>(conn)
                    .await
                    .optional()?;
                let (user_id, status, name, fingerprint) = match row {
                    Some(r) => r,
                    None => return Err(IacsTxnError::Deny(EwsDenyReason::RequestNotFound)),
                };
                if user_id != actor.id {
                    return Err(IacsTxnError::Deny(EwsDenyReason::NotOwner));
                }
                if status != "pending" {
                    return Err(IacsTxnError::Deny(EwsDenyReason::RequestNotPending));
                }
                let now = Utc::now();
                let updated = diesel::update(
                    ews_onboarding_requests::table
                        .filter(ews_onboarding_requests::uuid.eq(request_uuid_parsed))
                        .filter(ews_onboarding_requests::status.eq("pending"))
                        .filter(ews_onboarding_requests::user_id.eq(actor.id)),
                )
                .set((
                    ews_onboarding_requests::status.eq("cancelled"),
                    ews_onboarding_requests::decided_by_id.eq(Some(actor.id)),
                    ews_onboarding_requests::decided_at.eq(Some(now)),
                    ews_onboarding_requests::updated_at.eq(now),
                ))
                .execute(conn)
                .await?;
                if updated == 0 {
                    return Err(IacsTxnError::Deny(EwsDenyReason::RequestNotPending));
                }
                let audit_id: i64 = diesel::insert_into(ews_audit_log::table)
                    .values((
                        ews_audit_log::request_uuid.eq(Some(request_uuid_parsed)),
                        ews_audit_log::event.eq("cancelled"),
                        ews_audit_log::actor_user_id.eq(Some(actor.id)),
                        ews_audit_log::actor_username.eq(&actor_username),
                        ews_audit_log::target_user_id.eq(Some(actor.id)),
                        ews_audit_log::target_username.eq(&actor_username),
                        ews_audit_log::ews_name.eq(&name),
                        ews_audit_log::public_key_fingerprint.eq(&fingerprint),
                        ews_audit_log::actor_ip.eq(actor_ip_inet),
                    ))
                    .returning(ews_audit_log::id)
                    .get_result(conn)
                    .await?;
                Ok(audit_id)
            })
        })
        .await;

    match outcome {
        Ok(audit_log_id) => {
            info!(actor = %actor.username, %request_uuid_parsed, audit_log_id, "EWS request cancelled");
            AccessResponse::EwsRequestCancelled { audit_log_id }
        }
        Err(IacsTxnError::Deny(reason)) => AccessResponse::EwsDecisionDenied { reason },
        Err(IacsTxnError::Db(msg)) => {
            error!(actor = %actor.username, db_error = %msg, "EWS cancel DB error");
            AccessResponse::EwsDecisionDenied {
                reason: EwsDenyReason::RequestNotFound,
            }
        }
    }
}

/// Approve or reject a pending request. On approve, also creates the
/// `ews` row in the same transaction.
pub async fn handle_record_ews_decision(
    conn: &mut DbConnection,
    actor_user_uuid: &str,
    request_uuid: &str,
    decision: EwsDecisionKind,
    decision_reason: Option<String>,
    actor_ip: Option<String>,
) -> AccessResponse {
    let request_uuid_parsed = match parse_uuid_or_request_not_found(request_uuid) {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    if matches!(decision, EwsDecisionKind::Reject)
        && decision_reason.as_ref().is_none_or(|s| s.trim().is_empty())
    {
        // Mandatory rejection reason; the handler should validate
        // upstream too but the decision recorder is the hard floor.
        return AccessResponse::EwsDecisionDenied {
            reason: EwsDenyReason::RequestNotPending,
        };
    }
    let actor = match load_actor(conn, actor_user_uuid, EwsDenyReason::RequestNotFound).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    let actor_ip_inet = parse_actor_ip(actor_ip.as_deref());
    let actor_username = actor.username.clone();
    let decision_reason_clone = decision_reason.clone();

    let outcome: Result<(i64, Option<Uuid>), IacsTxnError> = conn
        .transaction::<(i64, Option<Uuid>), IacsTxnError, _>(move |conn| {
            let actor_username = actor_username.clone();
            let decision_reason = decision_reason_clone.clone();
            Box::pin(async move {
                #[derive(Queryable)]
                struct PendingRow {
                    user_id: i32,
                    name: String,
                    public_key: String,
                    public_key_fingerprint: String,
                    key_algo: String,
                    status: String,
                }
                let row: Option<PendingRow> = ews_onboarding_requests::table
                    .filter(ews_onboarding_requests::uuid.eq(request_uuid_parsed))
                    .select((
                        ews_onboarding_requests::user_id,
                        ews_onboarding_requests::name,
                        ews_onboarding_requests::public_key,
                        ews_onboarding_requests::public_key_fingerprint,
                        ews_onboarding_requests::key_algo,
                        ews_onboarding_requests::status,
                    ))
                    .first::<PendingRow>(conn)
                    .await
                    .optional()?;
                let req = match row {
                    Some(r) => r,
                    None => return Err(IacsTxnError::Deny(EwsDenyReason::RequestNotFound)),
                };
                if req.status != "pending" {
                    return Err(IacsTxnError::Deny(EwsDenyReason::RequestNotPending));
                }
                let target = load_target_user(conn, req.user_id).await?;
                if target.is_deleted || !target.is_active {
                    return Err(IacsTxnError::Deny(EwsDenyReason::TargetUserDisabled));
                }

                let now = Utc::now();
                let (status_label, audit_event) = match decision {
                    EwsDecisionKind::Approve => ("approved", "approved"),
                    EwsDecisionKind::Reject => ("rejected", "rejected"),
                };
                let updated = diesel::update(
                    ews_onboarding_requests::table
                        .filter(ews_onboarding_requests::uuid.eq(request_uuid_parsed))
                        .filter(ews_onboarding_requests::status.eq("pending")),
                )
                .set((
                    ews_onboarding_requests::status.eq(status_label),
                    ews_onboarding_requests::decided_by_id.eq(Some(actor.id)),
                    ews_onboarding_requests::decided_at.eq(Some(now)),
                    ews_onboarding_requests::decision_reason.eq(decision_reason.clone()),
                    ews_onboarding_requests::updated_at.eq(now),
                ))
                .execute(conn)
                .await?;
                if updated == 0 {
                    return Err(IacsTxnError::Deny(EwsDenyReason::RequestNotPending));
                }

                // On approve: insert the active `ews` row. The partial
                // unique index `ews_active_fingerprint_uniq` is the hard
                // floor; if it fires we surface KeyAlreadyUsed.
                let ews_uuid_opt = if matches!(decision, EwsDecisionKind::Approve) {
                    let inserted: Result<Uuid, diesel::result::Error> =
                        diesel::insert_into(ews::table)
                            .values((
                                ews::request_uuid.eq(request_uuid_parsed),
                                ews::user_id.eq(req.user_id),
                                ews::name.eq(&req.name),
                                ews::public_key.eq(&req.public_key),
                                ews::public_key_fingerprint.eq(&req.public_key_fingerprint),
                                ews::key_algo.eq(&req.key_algo),
                            ))
                            .returning(ews::uuid)
                            .get_result(conn)
                            .await;
                    match inserted {
                        Ok(u) => Some(u),
                        Err(e) => {
                            let msg = e.to_string();
                            if msg.to_lowercase().contains("ews_active_fingerprint_uniq") {
                                return Err(IacsTxnError::Deny(EwsDenyReason::KeyAlreadyUsed));
                            }
                            return Err(IacsTxnError::Db(msg));
                        }
                    }
                } else {
                    None
                };

                let audit_id: i64 = diesel::insert_into(ews_audit_log::table)
                    .values((
                        ews_audit_log::ews_uuid.eq(ews_uuid_opt),
                        ews_audit_log::request_uuid.eq(Some(request_uuid_parsed)),
                        ews_audit_log::event.eq(audit_event),
                        ews_audit_log::actor_user_id.eq(Some(actor.id)),
                        ews_audit_log::actor_username.eq(&actor_username),
                        ews_audit_log::target_user_id.eq(Some(target.id)),
                        ews_audit_log::target_username.eq(&target.username),
                        ews_audit_log::ews_name.eq(&req.name),
                        ews_audit_log::public_key_fingerprint.eq(&req.public_key_fingerprint),
                        ews_audit_log::decision_reason.eq(decision_reason.clone()),
                        ews_audit_log::actor_ip.eq(actor_ip_inet),
                    ))
                    .returning(ews_audit_log::id)
                    .get_result(conn)
                    .await?;
                Ok((audit_id, ews_uuid_opt))
            })
        })
        .await;

    match outcome {
        Ok((audit_log_id, ews_uuid_opt)) => {
            info!(
                actor = %actor.username,
                %request_uuid_parsed,
                decision = ?decision,
                audit_log_id,
                ?ews_uuid_opt,
                "EWS decision recorded"
            );
            AccessResponse::EwsDecisionRecorded {
                audit_log_id,
                ews_uuid: ews_uuid_opt.map(|u| u.to_string()),
            }
        }
        Err(IacsTxnError::Deny(reason)) => AccessResponse::EwsDecisionDenied { reason },
        Err(IacsTxnError::Db(msg)) => {
            error!(actor = %actor.username, db_error = %msg, "EWS decision DB error");
            AccessResponse::EwsDecisionDenied {
                reason: map_db_error_to_deny(&msg, EwsDenyReason::RequestNotFound),
            }
        }
    }
}

/// Disable an active EWS (reversible). Disabling does NOT release
/// the fingerprint.
pub async fn handle_disable_ews(
    conn: &mut DbConnection,
    actor_user_uuid: &str,
    ews_uuid: &str,
    actor_ip: Option<String>,
) -> AccessResponse {
    transition_ews_state(
        conn,
        actor_user_uuid,
        ews_uuid,
        EwsTransition::Disable,
        false,
        None,
        actor_ip,
    )
    .await
}

/// Re-enable a disabled EWS.
pub async fn handle_enable_ews(
    conn: &mut DbConnection,
    actor_user_uuid: &str,
    ews_uuid: &str,
    actor_ip: Option<String>,
) -> AccessResponse {
    transition_ews_state(
        conn,
        actor_user_uuid,
        ews_uuid,
        EwsTransition::Enable,
        false,
        None,
        actor_ip,
    )
    .await
}

/// Offboard an EWS (irreversible soft-delete). Releases the
/// fingerprint. Calls the (stub) `terminate_ssh_tunnels_for_ews`
/// hook from inside the same transaction so the audit log line
/// covers it.
pub async fn handle_offboard_ews(
    conn: &mut DbConnection,
    actor_user_uuid: &str,
    ews_uuid: &str,
    on_behalf_of_self: bool,
    decision_reason: Option<String>,
    actor_ip: Option<String>,
) -> AccessResponse {
    transition_ews_state(
        conn,
        actor_user_uuid,
        ews_uuid,
        EwsTransition::Offboard,
        on_behalf_of_self,
        decision_reason,
        actor_ip,
    )
    .await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EwsTransition {
    Disable,
    Enable,
    Offboard,
}

impl EwsTransition {
    fn audit_event(self) -> &'static str {
        match self {
            Self::Disable => "disabled",
            Self::Enable => "enabled",
            Self::Offboard => "offboarded",
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn transition_ews_state(
    conn: &mut DbConnection,
    actor_user_uuid: &str,
    ews_uuid: &str,
    transition: EwsTransition,
    on_behalf_of_self: bool,
    decision_reason: Option<String>,
    actor_ip: Option<String>,
) -> AccessResponse {
    let ews_uuid_parsed = match parse_uuid_or_ews_not_found(ews_uuid) {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    let actor = match load_actor(conn, actor_user_uuid, EwsDenyReason::EwsNotFound).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    let actor_ip_inet = parse_actor_ip(actor_ip.as_deref());
    let actor_username = actor.username.clone();
    let decision_reason_clone = decision_reason.clone();

    let outcome: Result<i64, IacsTxnError> = conn
        .transaction::<i64, IacsTxnError, _>(move |conn| {
            let actor_username = actor_username.clone();
            let decision_reason = decision_reason_clone.clone();
            Box::pin(async move {
                #[derive(Queryable)]
                struct EwsRow {
                    user_id: i32,
                    name: String,
                    public_key_fingerprint: String,
                    disabled_at: Option<chrono::DateTime<Utc>>,
                    offboarded_at: Option<chrono::DateTime<Utc>>,
                }
                let row: Option<EwsRow> = ews::table
                    .filter(ews::uuid.eq(ews_uuid_parsed))
                    .select((
                        ews::user_id,
                        ews::name,
                        ews::public_key_fingerprint,
                        ews::disabled_at,
                        ews::offboarded_at,
                    ))
                    .first::<EwsRow>(conn)
                    .await
                    .optional()?;
                let ews_row = match row {
                    Some(r) => r,
                    None => return Err(IacsTxnError::Deny(EwsDenyReason::EwsNotFound)),
                };
                if on_behalf_of_self && ews_row.user_id != actor.id {
                    return Err(IacsTxnError::Deny(EwsDenyReason::NotOwner));
                }
                if ews_row.offboarded_at.is_some() {
                    return Err(IacsTxnError::Deny(EwsDenyReason::EwsAlreadyOffboarded));
                }
                let target = load_target_user(conn, ews_row.user_id).await?;

                let now = Utc::now();
                let updated = match transition {
                    EwsTransition::Disable => {
                        if ews_row.disabled_at.is_some() {
                            // Already disabled -- treat as no-op deny so
                            // the UI hint is accurate. Map to
                            // RequestNotPending (collapses to "already
                            // processed").
                            return Err(IacsTxnError::Deny(EwsDenyReason::RequestNotPending));
                        }
                        diesel::update(
                            ews::table
                                .filter(ews::uuid.eq(ews_uuid_parsed))
                                .filter(ews::disabled_at.is_null())
                                .filter(ews::offboarded_at.is_null()),
                        )
                        .set((
                            ews::disabled_by_id.eq(Some(actor.id)),
                            ews::disabled_at.eq(Some(now)),
                            ews::updated_at.eq(now),
                        ))
                        .execute(conn)
                        .await?
                    }
                    EwsTransition::Enable => {
                        if ews_row.disabled_at.is_none() {
                            return Err(IacsTxnError::Deny(EwsDenyReason::RequestNotPending));
                        }
                        diesel::update(
                            ews::table
                                .filter(ews::uuid.eq(ews_uuid_parsed))
                                .filter(ews::disabled_at.is_not_null())
                                .filter(ews::offboarded_at.is_null()),
                        )
                        .set((
                            ews::disabled_by_id.eq::<Option<i32>>(None),
                            ews::disabled_at.eq::<Option<chrono::DateTime<Utc>>>(None),
                            ews::updated_at.eq(now),
                        ))
                        .execute(conn)
                        .await?
                    }
                    EwsTransition::Offboard => {
                        diesel::update(
                            ews::table
                                .filter(ews::uuid.eq(ews_uuid_parsed))
                                .filter(ews::offboarded_at.is_null()),
                        )
                        .set((
                            ews::offboarded_by_id.eq(Some(actor.id)),
                            ews::offboarded_at.eq(Some(now)),
                            ews::updated_at.eq(now),
                        ))
                        .execute(conn)
                        .await?
                    }
                };
                if updated == 0 {
                    return Err(IacsTxnError::Deny(EwsDenyReason::RequestNotPending));
                }

                let audit_id: i64 = diesel::insert_into(ews_audit_log::table)
                    .values((
                        ews_audit_log::ews_uuid.eq(Some(ews_uuid_parsed)),
                        ews_audit_log::event.eq(transition.audit_event()),
                        ews_audit_log::actor_user_id.eq(Some(actor.id)),
                        ews_audit_log::actor_username.eq(&actor_username),
                        ews_audit_log::target_user_id.eq(Some(target.id)),
                        ews_audit_log::target_username.eq(&target.username),
                        ews_audit_log::ews_name.eq(&ews_row.name),
                        ews_audit_log::public_key_fingerprint.eq(&ews_row.public_key_fingerprint),
                        ews_audit_log::decision_reason.eq(decision_reason.clone()),
                        ews_audit_log::actor_ip.eq(actor_ip_inet),
                    ))
                    .returning(ews_audit_log::id)
                    .get_result(conn)
                    .await?;

                // Side-effects after the audit row but still inside the
                // transaction so a panic / error rolls back EVERYTHING
                // (state mutation + audit row + tunnel termination).
                if matches!(transition, EwsTransition::Disable | EwsTransition::Offboard) {
                    terminate_ssh_tunnels_for_ews(ews_uuid_parsed);
                }

                Ok(audit_id)
            })
        })
        .await;

    match outcome {
        Ok(audit_log_id) => {
            info!(
                actor = %actor.username,
                %ews_uuid_parsed,
                ?transition,
                audit_log_id,
                "EWS state transition recorded"
            );
            AccessResponse::EwsStateChanged { audit_log_id }
        }
        Err(IacsTxnError::Deny(reason)) => AccessResponse::EwsDecisionDenied { reason },
        Err(IacsTxnError::Db(msg)) => {
            error!(
                actor = %actor.username,
                db_error = %msg,
                ?transition,
                "EWS state transition DB error"
            );
            AccessResponse::EwsDecisionDenied {
                reason: map_db_error_to_deny(&msg, EwsDenyReason::EwsNotFound),
            }
        }
    }
}
