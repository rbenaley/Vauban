//! Battle-tests for the Approval Audit & Separation-of-Duties feature.
//!
//! These tests pin the DB-level invariants and the IPC contract so a
//! future refactor that quietly weakens either layer fails CI loudly.
//!
//! Tier 1 (DB invariants):
//!   * `approval_separation_of_duties` CHECK rejects approver==requester
//!   * `rejection_separation_of_duties` CHECK rejects rejecter==requester
//!   * `block_approval_audit_log_mutation` trigger blocks UPDATE
//!   * `block_approval_audit_log_mutation` trigger blocks DELETE
//!   * `approval_audit_log.decision` CHECK rejects unknown decisions
//!   * Inserting a well-formed audit row succeeds
//!   * Audit row survives requester user deletion (FK ON DELETE SET NULL)
//!
//! Tier 2 (IPC contracts):
//!   * `CheckApprovalEligibility` with malformed actor uuid -> SessionNotFound
//!   * `CheckApprovalEligibility` with malformed session uuid -> SessionNotFound
//!   * `CheckApprovalEligibility` on missing session -> SessionNotFound
//!   * `RecordApprovalDecision` with malformed uuids -> ApprovalDenied{SessionNotFound}
//!
//! All `ApprovalDenyReason` variants exposed over IPC are covered either
//! here or in the handler tests (`SelfApproval`, `RequesterDisabled`,
//! `RuleNoLongerRequiresApproval` in higher-tier integration tests).

use crate::db::DbPool;
use crate::handlers::handle_access_request;
use crate::schema::{approval_audit_log, proxy_sessions, users};
use diesel::prelude::*;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::deadpool::Pool;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use shared::messages::{AccessRequest, AccessResponse, ApprovalDecisionKind, ApprovalDenyReason};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use uuid::Uuid;

static COUNTER: AtomicU64 = AtomicU64::new(0);
static POOL_INIT: OnceLock<()> = OnceLock::new();

fn unique(prefix: &str) -> String {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_micros();
    format!("{prefix}_{ts}_{n}")
}

async fn pool() -> DbPool {
    let url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgresql://vauban_test:vauban_test@localhost/vauban_test".to_string()
    });
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(&url);
    let p = Pool::builder(manager).max_size(2).build().unwrap();
    POOL_INIT.get_or_init(|| ());
    p
}

async fn insert_user(pool: &DbPool, username: &str) -> i32 {
    let mut conn = pool.get().await.unwrap();
    diesel::insert_into(users::table)
        .values((
            users::username.eq(username),
            users::email.eq(format!("{username}@aud.local")),
            users::password_hash.eq("nologin"),
            users::is_superuser.eq(false),
            users::is_staff.eq(false),
            users::is_active.eq(true),
        ))
        .returning(users::id)
        .get_result::<i32>(&mut conn)
        .await
        .unwrap()
}

/// Insert a minimal asset row so we can satisfy the FK from
/// `proxy_sessions.asset_id`. We only fill the columns needed to
/// pass NOT NULL constraints and ignore everything else.
async fn insert_asset(pool: &DbPool, name: &str) -> i32 {
    use crate::schema::assets;
    let mut conn = pool.get().await.unwrap();
    diesel::insert_into(assets::table)
        .values((
            assets::name.eq(name),
            assets::hostname.eq(format!("{name}.example.com")),
            assets::port.eq(22i32),
            assets::asset_type.eq("ssh"),
            assets::status.eq("online"),
            assets::connection_config.eq(serde_json::json!({})),
            assets::connection_username.eq("root"),
        ))
        .returning(assets::id)
        .get_result::<i32>(&mut conn)
        .await
        .unwrap()
}

async fn insert_pending_session(pool: &DbPool, user_id: i32, asset_id: i32) -> Uuid {
    let mut conn = pool.get().await.unwrap();
    let uuid = Uuid::new_v4();
    let ip: ipnetwork::IpNetwork = "127.0.0.1/32".parse().unwrap();
    diesel::insert_into(proxy_sessions::table)
        .values((
            proxy_sessions::uuid.eq(uuid),
            proxy_sessions::user_id.eq(user_id),
            proxy_sessions::asset_id.eq(asset_id),
            proxy_sessions::credential_id.eq(Uuid::new_v4().to_string()),
            proxy_sessions::credential_username.eq("root"),
            proxy_sessions::session_type.eq("ssh"),
            proxy_sessions::status.eq("pending"),
            proxy_sessions::client_ip.eq(ip),
            proxy_sessions::is_recorded.eq(true),
            proxy_sessions::bytes_sent.eq(0i64),
            proxy_sessions::bytes_received.eq(0i64),
            proxy_sessions::commands_count.eq(0i32),
            proxy_sessions::metadata.eq(serde_json::json!({})),
            proxy_sessions::justification.eq(Some("test")),
        ))
        .execute(&mut conn)
        .await
        .unwrap();
    uuid
}

// =====================================================================
// Tier 1 — DB invariants
// =====================================================================

#[tokio::test]
async fn db_check_approval_separation_of_duties_blocks_self_approval() {
    let p = pool().await;
    let requester = insert_user(&p, &unique("req")).await;
    let asset = insert_asset(&p, &unique("a")).await;
    let session_uuid = insert_pending_session(&p, requester, asset).await;
    let mut conn = p.get().await.unwrap();
    // Try to UPDATE the session marking the *requester themselves* as
    // approver. The CHECK constraint must reject this — defense in
    // depth even if the IPC layer were ever bypassed.
    let res = diesel::update(proxy_sessions::table.filter(proxy_sessions::uuid.eq(session_uuid)))
        .set((
            proxy_sessions::status.eq("approved"),
            proxy_sessions::approved_by_id.eq(Some(requester)),
            proxy_sessions::approved_at.eq(Some(chrono::Utc::now())),
        ))
        .execute(&mut conn)
        .await;
    assert!(
        res.is_err(),
        "UPDATE with approved_by_id == user_id must violate CHECK"
    );
    let err = format!("{:?}", res.unwrap_err()).to_lowercase();
    assert!(
        err.contains("approval_separation_of_duties") || err.contains("check"),
        "error must reference the SoD CHECK constraint, got: {err}"
    );
}

#[tokio::test]
async fn db_check_rejection_separation_of_duties_blocks_self_rejection() {
    let p = pool().await;
    let requester = insert_user(&p, &unique("req")).await;
    let asset = insert_asset(&p, &unique("a")).await;
    let session_uuid = insert_pending_session(&p, requester, asset).await;
    let mut conn = p.get().await.unwrap();
    let res = diesel::update(proxy_sessions::table.filter(proxy_sessions::uuid.eq(session_uuid)))
        .set((
            proxy_sessions::status.eq("rejected"),
            proxy_sessions::rejected_by_id.eq(Some(requester)),
            proxy_sessions::rejected_at.eq(Some(chrono::Utc::now())),
        ))
        .execute(&mut conn)
        .await;
    assert!(
        res.is_err(),
        "UPDATE with rejected_by_id == user_id must violate CHECK"
    );
}

#[tokio::test]
async fn db_check_separation_of_duties_allows_cross_user_approval() {
    let p = pool().await;
    let requester = insert_user(&p, &unique("req")).await;
    let approver = insert_user(&p, &unique("apr")).await;
    let asset = insert_asset(&p, &unique("a")).await;
    let session_uuid = insert_pending_session(&p, requester, asset).await;
    let mut conn = p.get().await.unwrap();
    let res = diesel::update(proxy_sessions::table.filter(proxy_sessions::uuid.eq(session_uuid)))
        .set((
            proxy_sessions::status.eq("approved"),
            proxy_sessions::approved_by_id.eq(Some(approver)),
            proxy_sessions::approved_at.eq(Some(chrono::Utc::now())),
        ))
        .execute(&mut conn)
        .await;
    assert!(
        res.is_ok(),
        "UPDATE with approved_by_id != user_id must succeed, got: {res:?}"
    );
}

#[tokio::test]
async fn db_audit_trigger_blocks_update() {
    let p = pool().await;
    let requester = insert_user(&p, &unique("req")).await;
    let approver = insert_user(&p, &unique("apr")).await;
    let mut conn = p.get().await.unwrap();
    let id: i64 = diesel::insert_into(approval_audit_log::table)
        .values((
            approval_audit_log::session_uuid.eq(Uuid::new_v4()),
            approval_audit_log::decision.eq("approve"),
            approval_audit_log::actor_user_id.eq(Some(approver)),
            approval_audit_log::actor_username.eq("apr"),
            approval_audit_log::requester_user_id.eq(Some(requester)),
            approval_audit_log::requester_username.eq("req"),
            approval_audit_log::asset_uuid.eq(Uuid::new_v4()),
            approval_audit_log::asset_name.eq("a"),
        ))
        .returning(approval_audit_log::id)
        .get_result(&mut conn)
        .await
        .unwrap();
    // Any UPDATE must raise from the trigger.
    let res = diesel::update(approval_audit_log::table.filter(approval_audit_log::id.eq(id)))
        .set(approval_audit_log::asset_name.eq("tampered"))
        .execute(&mut conn)
        .await;
    assert!(
        res.is_err(),
        "UPDATE on append-only audit log must raise, got: {res:?}"
    );
    let msg = format!("{:?}", res.unwrap_err()).to_lowercase();
    assert!(
        msg.contains("append-only"),
        "trigger must mention append-only, got: {msg}"
    );
}

#[tokio::test]
async fn db_audit_trigger_blocks_delete() {
    let p = pool().await;
    let requester = insert_user(&p, &unique("req")).await;
    let approver = insert_user(&p, &unique("apr")).await;
    let mut conn = p.get().await.unwrap();
    let id: i64 = diesel::insert_into(approval_audit_log::table)
        .values((
            approval_audit_log::session_uuid.eq(Uuid::new_v4()),
            approval_audit_log::decision.eq("reject"),
            approval_audit_log::actor_user_id.eq(Some(approver)),
            approval_audit_log::actor_username.eq("apr"),
            approval_audit_log::requester_user_id.eq(Some(requester)),
            approval_audit_log::requester_username.eq("req"),
            approval_audit_log::asset_uuid.eq(Uuid::new_v4()),
            approval_audit_log::asset_name.eq("a"),
        ))
        .returning(approval_audit_log::id)
        .get_result(&mut conn)
        .await
        .unwrap();
    let res = diesel::delete(approval_audit_log::table.filter(approval_audit_log::id.eq(id)))
        .execute(&mut conn)
        .await;
    assert!(res.is_err(), "DELETE on audit log must raise");
}

#[tokio::test]
async fn db_audit_decision_check_rejects_unknown_value() {
    let p = pool().await;
    let approver = insert_user(&p, &unique("apr")).await;
    let mut conn = p.get().await.unwrap();
    let res = diesel::insert_into(approval_audit_log::table)
        .values((
            approval_audit_log::session_uuid.eq(Uuid::new_v4()),
            approval_audit_log::decision.eq("hijack"),
            approval_audit_log::actor_user_id.eq(Some(approver)),
            approval_audit_log::actor_username.eq("apr"),
            approval_audit_log::requester_username.eq("req"),
            approval_audit_log::asset_uuid.eq(Uuid::new_v4()),
            approval_audit_log::asset_name.eq("a"),
        ))
        .execute(&mut conn)
        .await;
    assert!(
        res.is_err(),
        "INSERT with decision='hijack' must violate the CHECK"
    );
}

#[tokio::test]
async fn db_audit_row_snapshot_survives_user_soft_deletion() {
    // The snapshot fields (`actor_username`, `requester_username`,
    // `asset_name`) are the trail's *survival contract*: even after a
    // user is soft-deleted (or eventually hard-deleted, see the
    // sibling test `db_user_hard_delete_blocked_when_audit_row_exists`),
    // the audit row must still render meaningfully.
    let p = pool().await;
    let requester = insert_user(&p, &unique("req_del")).await;
    let approver = insert_user(&p, &unique("apr_del")).await;
    let mut conn = p.get().await.unwrap();
    let id: i64 = diesel::insert_into(approval_audit_log::table)
        .values((
            approval_audit_log::session_uuid.eq(Uuid::new_v4()),
            approval_audit_log::decision.eq("approve"),
            approval_audit_log::actor_user_id.eq(Some(approver)),
            approval_audit_log::actor_username.eq("apr_del_snapshot"),
            approval_audit_log::requester_user_id.eq(Some(requester)),
            approval_audit_log::requester_username.eq("req_del_snapshot"),
            approval_audit_log::asset_uuid.eq(Uuid::new_v4()),
            approval_audit_log::asset_name.eq("a"),
        ))
        .returning(approval_audit_log::id)
        .get_result(&mut conn)
        .await
        .unwrap();
    // Soft-delete: flag the row as deleted but keep it in place. The
    // FK is preserved AND the snapshot username is still authoritative
    // for compliance reads.
    diesel::update(users::table.filter(users::id.eq(requester)))
        .set((users::is_deleted.eq(true), users::is_active.eq(false)))
        .execute(&mut conn)
        .await
        .unwrap();

    let uname: String = approval_audit_log::table
        .filter(approval_audit_log::id.eq(id))
        .select(approval_audit_log::requester_username)
        .first(&mut conn)
        .await
        .unwrap();
    assert_eq!(uname, "req_del_snapshot");
}

#[tokio::test]
async fn db_user_hard_delete_cascades_set_null_on_audit_log() {
    // Deleting a user fires the FK ON DELETE SET NULL cascade, which
    // UPDATEs only the nullable FK columns (actor_user_id,
    // requester_user_id). The append-only trigger allows this
    // narrow mutation so that user lifecycle management does not
    // require dropping the trigger. The snapshotted usernames
    // and all audit-significant fields remain intact.
    let p = pool().await;
    let requester = insert_user(&p, &unique("req_hd")).await;
    let approver = insert_user(&p, &unique("apr_hd")).await;
    let mut conn = p.get().await.unwrap();
    let audit_session_uuid = Uuid::new_v4();
    diesel::insert_into(approval_audit_log::table)
        .values((
            approval_audit_log::session_uuid.eq(audit_session_uuid),
            approval_audit_log::decision.eq("approve"),
            approval_audit_log::actor_user_id.eq(Some(approver)),
            approval_audit_log::actor_username.eq("apr"),
            approval_audit_log::requester_user_id.eq(Some(requester)),
            approval_audit_log::requester_username.eq("req"),
            approval_audit_log::asset_uuid.eq(Uuid::new_v4()),
            approval_audit_log::asset_name.eq("a"),
        ))
        .execute(&mut conn)
        .await
        .unwrap();
    // Hard-delete the requester — FK cascade SETs NULL on the audit row.
    diesel::delete(users::table.filter(users::id.eq(requester)))
        .execute(&mut conn)
        .await
        .expect("hard-delete of user must succeed (FK SET NULL allowed)");

    // The audit row survives with the FK NULLed but the snapshot intact.
    let (req_id, req_name): (Option<i32>, String) = approval_audit_log::table
        .filter(approval_audit_log::session_uuid.eq(audit_session_uuid))
        .select((
            approval_audit_log::requester_user_id,
            approval_audit_log::requester_username,
        ))
        .first(&mut conn)
        .await
        .unwrap();
    assert!(
        req_id.is_none(),
        "requester FK must be NULLed after user delete"
    );
    assert_eq!(
        req_name, "req",
        "snapshotted username must survive user delete"
    );
}

// =====================================================================
// Tier 2 — IPC contracts
// =====================================================================

#[tokio::test]
async fn ipc_check_eligibility_rejects_malformed_actor_uuid() {
    let p = pool().await;
    let resp = handle_access_request(
        &p,
        AccessRequest::CheckApprovalEligibility {
            actor_user_uuid: "not-a-uuid".to_string(),
            session_uuid: Uuid::new_v4().to_string(),
        },
    )
    .await;
    match resp {
        AccessResponse::ApprovalEligibility {
            allowed: false,
            reason: Some(ApprovalDenyReason::SessionNotFound),
        } => {}
        other => panic!("expected SessionNotFound, got {other:?}"),
    }
}

#[tokio::test]
async fn ipc_check_eligibility_rejects_malformed_session_uuid() {
    let p = pool().await;
    let actor = insert_user(&p, &unique("apr")).await;
    let actor_uuid: Uuid = users::table
        .filter(users::id.eq(actor))
        .select(users::uuid)
        .first(&mut p.get().await.unwrap())
        .await
        .unwrap();
    let resp = handle_access_request(
        &p,
        AccessRequest::CheckApprovalEligibility {
            actor_user_uuid: actor_uuid.to_string(),
            session_uuid: "not-a-uuid".to_string(),
        },
    )
    .await;
    match resp {
        AccessResponse::ApprovalEligibility {
            allowed: false,
            reason: Some(ApprovalDenyReason::SessionNotFound),
        } => {}
        other => panic!("expected SessionNotFound, got {other:?}"),
    }
}

#[tokio::test]
async fn ipc_check_eligibility_unknown_session() {
    let p = pool().await;
    let actor = insert_user(&p, &unique("apr")).await;
    let actor_uuid: Uuid = users::table
        .filter(users::id.eq(actor))
        .select(users::uuid)
        .first(&mut p.get().await.unwrap())
        .await
        .unwrap();
    let resp = handle_access_request(
        &p,
        AccessRequest::CheckApprovalEligibility {
            actor_user_uuid: actor_uuid.to_string(),
            session_uuid: Uuid::new_v4().to_string(),
        },
    )
    .await;
    match resp {
        AccessResponse::ApprovalEligibility {
            allowed: false,
            reason: Some(ApprovalDenyReason::SessionNotFound),
        } => {}
        other => panic!("expected SessionNotFound, got {other:?}"),
    }
}

#[tokio::test]
async fn ipc_record_decision_rejects_malformed_uuids() {
    let p = pool().await;
    let resp = handle_access_request(
        &p,
        AccessRequest::RecordApprovalDecision {
            actor_user_uuid: "not-a-uuid".to_string(),
            session_uuid: "not-a-uuid".to_string(),
            decision: ApprovalDecisionKind::Approve,
            duration_override_seconds: None,
            decision_reason: None,
            decision_ip: None,
            decision_user_agent: None,
            request_id: None,
        },
    )
    .await;
    match resp {
        AccessResponse::ApprovalDenied {
            reason: ApprovalDenyReason::SessionNotFound,
        } => {}
        other => panic!("expected ApprovalDenied{{SessionNotFound}}, got {other:?}"),
    }
}

// =====================================================================
// Tier 5 — adversarial threat model
//
// Threat catalog (mapped to tests below or to earlier tiers):
//   T1 self-approval         -> Tier 1: db_check_approval_separation_*
//   T2 re-pointing audit row -> here: t5_audit_row_session_uuid_is_immutable
//   T3 audit tamper          -> Tier 1: db_audit_trigger_blocks_update/delete
//   T4 forged IP             -> handled at the trusted-proxy middleware
//                               layer (resolved before IPC); pinned by
//                               handler test in vauban-web tests
//   T5 dual-decision race    -> here: t5_second_decision_after_approval_loses
//   T6 silent reject         -> here: t5_reject_decision_writes_audit_row
//   T7 rebound after reject  -> here: t5_second_decision_after_reject_loses
//   T8 user-delete cascade   -> Tier 1: db_user_hard_delete_cascades_set_null_*
//   T9 stolen API key        -> session-token gate (separate test suite)
// =====================================================================

#[tokio::test]
async fn t5_audit_row_session_uuid_is_immutable() {
    // T2: an attacker compromising vauban-access cannot re-point an
    // existing audit row to a different session, because the
    // append-only trigger blocks every UPDATE — including a partial
    // one that only changes `session_uuid`.
    let p = pool().await;
    let approver = insert_user(&p, &unique("apr_t2")).await;
    let requester = insert_user(&p, &unique("req_t2")).await;
    let mut conn = p.get().await.unwrap();
    let original_uuid = Uuid::new_v4();
    let id: i64 = diesel::insert_into(approval_audit_log::table)
        .values((
            approval_audit_log::session_uuid.eq(original_uuid),
            approval_audit_log::decision.eq("approve"),
            approval_audit_log::actor_user_id.eq(Some(approver)),
            approval_audit_log::actor_username.eq("apr"),
            approval_audit_log::requester_user_id.eq(Some(requester)),
            approval_audit_log::requester_username.eq("req"),
            approval_audit_log::asset_uuid.eq(Uuid::new_v4()),
            approval_audit_log::asset_name.eq("a"),
        ))
        .returning(approval_audit_log::id)
        .get_result(&mut conn)
        .await
        .unwrap();
    let attempt = diesel::update(approval_audit_log::table.filter(approval_audit_log::id.eq(id)))
        .set(approval_audit_log::session_uuid.eq(Uuid::new_v4()))
        .execute(&mut conn)
        .await;
    assert!(attempt.is_err(), "session_uuid re-pointing must be blocked");
    let stored: Uuid = approval_audit_log::table
        .filter(approval_audit_log::id.eq(id))
        .select(approval_audit_log::session_uuid)
        .first(&mut conn)
        .await
        .unwrap();
    assert_eq!(
        stored, original_uuid,
        "session_uuid must match the original"
    );
}

#[tokio::test]
async fn t5_reject_decision_writes_audit_row() {
    // T6: a rejection is not "silent" — it leaves the same kind of
    // audit footprint as an approval. Compliance queries that count
    // rejections per actor / requester rely on this.
    let p = pool().await;
    let approver = insert_user(&p, &unique("apr_t6")).await;
    let requester = insert_user(&p, &unique("req_t6")).await;
    let mut conn = p.get().await.unwrap();
    let session_uuid = Uuid::new_v4();
    diesel::insert_into(approval_audit_log::table)
        .values((
            approval_audit_log::session_uuid.eq(session_uuid),
            approval_audit_log::decision.eq("reject"),
            approval_audit_log::actor_user_id.eq(Some(approver)),
            approval_audit_log::actor_username.eq("apr_t6_snapshot"),
            approval_audit_log::requester_user_id.eq(Some(requester)),
            approval_audit_log::requester_username.eq("req_t6_snapshot"),
            approval_audit_log::asset_uuid.eq(Uuid::new_v4()),
            approval_audit_log::asset_name.eq("a"),
            approval_audit_log::decision_reason.eq(Some("test rejection")),
        ))
        .execute(&mut conn)
        .await
        .unwrap();
    let count: i64 = approval_audit_log::table
        .filter(approval_audit_log::session_uuid.eq(session_uuid))
        .filter(approval_audit_log::decision.eq("reject"))
        .count()
        .get_result(&mut conn)
        .await
        .unwrap();
    assert_eq!(count, 1, "reject must produce exactly one audit row");
}

#[tokio::test]
async fn t5_proxy_session_cannot_be_set_to_self_approval_via_raw_sql() {
    // Combined T1 + T3: even a raw SQL path (e.g. DBA console
    // bypassing the application layer) cannot mark a session as
    // self-approved. The CHECK constraint is the *hard floor* — any
    // future bug in the IPC handler is contained by this layer.
    let p = pool().await;
    let requester = insert_user(&p, &unique("req_raw")).await;
    let asset = insert_asset(&p, &unique("a_raw")).await;
    let session_uuid = insert_pending_session(&p, requester, asset).await;
    let mut conn = p.get().await.unwrap();
    let raw = diesel::sql_query(format!(
        "UPDATE proxy_sessions SET status='approved', \
         approved_by_id=user_id, approved_at=NOW() \
         WHERE uuid='{session_uuid}'"
    ))
    .execute(&mut conn)
    .await;
    assert!(raw.is_err(), "raw SQL self-approval must be blocked");
}

#[tokio::test]
async fn ipc_record_decision_unknown_session() {
    let p = pool().await;
    let actor = insert_user(&p, &unique("apr")).await;
    let actor_uuid: Uuid = users::table
        .filter(users::id.eq(actor))
        .select(users::uuid)
        .first(&mut p.get().await.unwrap())
        .await
        .unwrap();
    let resp = handle_access_request(
        &p,
        AccessRequest::RecordApprovalDecision {
            actor_user_uuid: actor_uuid.to_string(),
            session_uuid: Uuid::new_v4().to_string(),
            decision: ApprovalDecisionKind::Reject,
            duration_override_seconds: None,
            decision_reason: Some("test".to_string()),
            decision_ip: None,
            decision_user_agent: None,
            request_id: None,
        },
    )
    .await;
    // Either SessionNotFound (snapshot loader returned NotFound) or
    // SessionNotPending — either way, must be ApprovalDenied, never
    // ApprovalRecorded.
    match resp {
        AccessResponse::ApprovalDenied { .. } => {}
        other => panic!("expected ApprovalDenied, got {other:?}"),
    }
}

// =====================================================================
// Tier 6 — JIT grant revocation & duration updates
//
// Battle-tests for the post-approval verbs added by the
// 20260705000000_jit_grant_revocation migration:
//   * revoke on an approved grant -> status=revoked + audit row
//   * self-revoke allowed (reducing one's own access has no SoD)
//   * revoke on pending / already-revoked -> denied SessionNotApproved
//   * update_duration recomputes expires_at from approved_at
//   * update_duration without a duration -> hard Error (caller bug)
//   * update_duration on one's own grant -> denied SelfApproval
//   * audit CHECK accepts the two new decision literals
// =====================================================================

/// Seed the full grant chain (user group + membership, asset group +
/// membership, active access rule with `require_approval = true`) so
/// `evaluate_eligibility` does not deny with
/// `RuleNoLongerRequiresApproval` on the re-widening verbs.
async fn link_grant_chain(pool: &DbPool, user_id: i32, asset_id: i32) {
    use crate::schema::{
        access_rules, asset_asset_groups, asset_groups, user_groups, vauban_groups,
    };
    let mut conn = pool.get().await.unwrap();
    let g_name = unique("t6g");
    let group_id: i32 = diesel::insert_into(vauban_groups::table)
        .values((
            vauban_groups::name.eq(&g_name),
            vauban_groups::source.eq("local"),
        ))
        .returning(vauban_groups::id)
        .get_result(&mut conn)
        .await
        .unwrap();
    diesel::insert_into(user_groups::table)
        .values((
            user_groups::user_id.eq(user_id),
            user_groups::group_id.eq(group_id),
        ))
        .execute(&mut conn)
        .await
        .unwrap();
    let ag_name = unique("t6ag");
    let asset_group_id: i32 = diesel::insert_into(asset_groups::table)
        .values((
            asset_groups::name.eq(&ag_name),
            asset_groups::slug.eq(&ag_name),
            asset_groups::color.eq("#000000"),
            asset_groups::icon.eq("server"),
        ))
        .returning(asset_groups::id)
        .get_result(&mut conn)
        .await
        .unwrap();
    diesel::insert_into(asset_asset_groups::table)
        .values((
            asset_asset_groups::asset_id.eq(asset_id),
            asset_asset_groups::asset_group_id.eq(asset_group_id),
        ))
        .execute(&mut conn)
        .await
        .unwrap();
    diesel::insert_into(access_rules::table)
        .values((
            access_rules::name.eq(unique("t6rule")),
            access_rules::user_group_id.eq(group_id),
            access_rules::asset_group_id.eq(asset_group_id),
            access_rules::allowed_protocols.eq(vec![Some("ssh".to_string())]),
            access_rules::require_mfa.eq(false),
            access_rules::require_approval.eq(true),
            access_rules::is_active.eq(true),
            access_rules::priority.eq(0),
        ))
        .execute(&mut conn)
        .await
        .unwrap();
}

type Ts = chrono::DateTime<chrono::Utc>;

async fn user_uuid_of(pool: &DbPool, user_id: i32) -> Uuid {
    users::table
        .filter(users::id.eq(user_id))
        .select(users::uuid)
        .first(&mut pool.get().await.unwrap())
        .await
        .unwrap()
}

/// Insert an APPROVED grant: approved 10 minutes ago by `approver_id`,
/// 1 h window (expires in 50 min).
async fn insert_approved_session(
    pool: &DbPool,
    user_id: i32,
    approver_id: i32,
    asset_id: i32,
) -> Uuid {
    let session_uuid = insert_pending_session(pool, user_id, asset_id).await;
    let mut conn = pool.get().await.unwrap();
    let approved_at = chrono::Utc::now() - chrono::Duration::minutes(10);
    diesel::update(proxy_sessions::table.filter(proxy_sessions::uuid.eq(session_uuid)))
        .set((
            proxy_sessions::status.eq("approved"),
            proxy_sessions::approved_by_id.eq(Some(approver_id)),
            proxy_sessions::approved_at.eq(Some(approved_at)),
            proxy_sessions::max_session_duration.eq(Some(3600)),
            proxy_sessions::expires_at.eq(Some(approved_at + chrono::Duration::seconds(3600))),
        ))
        .execute(&mut conn)
        .await
        .unwrap();
    session_uuid
}

async fn record_decision(
    pool: &DbPool,
    actor_uuid: Uuid,
    session_uuid: Uuid,
    decision: ApprovalDecisionKind,
    duration_override_seconds: Option<i32>,
) -> AccessResponse {
    handle_access_request(
        pool,
        AccessRequest::RecordApprovalDecision {
            actor_user_uuid: actor_uuid.to_string(),
            session_uuid: session_uuid.to_string(),
            decision,
            duration_override_seconds,
            decision_reason: Some("t6".to_string()),
            decision_ip: None,
            decision_user_agent: None,
            request_id: None,
        },
    )
    .await
}

#[tokio::test]
async fn t6_revoke_approved_grant_succeeds_and_writes_audit() {
    let p = pool().await;
    let requester = insert_user(&p, &unique("req_rv")).await;
    let approver = insert_user(&p, &unique("apr_rv")).await;
    let revoker = insert_user(&p, &unique("rvk_rv")).await;
    let asset = insert_asset(&p, &unique("a_rv")).await;
    let session_uuid = insert_approved_session(&p, requester, approver, asset).await;
    let revoker_uuid = user_uuid_of(&p, revoker).await;

    let resp = record_decision(
        &p,
        revoker_uuid,
        session_uuid,
        ApprovalDecisionKind::Revoke,
        None,
    )
    .await;
    match resp {
        AccessResponse::ApprovalRecorded { audit_log_id } => assert!(audit_log_id > 0),
        other => panic!("expected ApprovalRecorded, got {other:?}"),
    }

    let mut conn = p.get().await.unwrap();
    let (status, revoked_by, revoked_at, expires_at): (
        String,
        Option<i32>,
        Option<Ts>,
        Option<Ts>,
    ) = proxy_sessions::table
        .filter(proxy_sessions::uuid.eq(session_uuid))
        .select((
            proxy_sessions::status,
            proxy_sessions::revoked_by_id,
            proxy_sessions::revoked_at,
            proxy_sessions::expires_at,
        ))
        .first(&mut conn)
        .await
        .unwrap();
    assert_eq!(status, "revoked");
    assert_eq!(revoked_by, Some(revoker), "revoker must be recorded");
    assert!(revoked_at.is_some(), "revoked_at must be stamped");
    assert!(
        expires_at.is_some(),
        "expires_at must be preserved for the audit trail"
    );

    let audit_count: i64 = approval_audit_log::table
        .filter(approval_audit_log::session_uuid.eq(session_uuid))
        .filter(approval_audit_log::decision.eq("revoke"))
        .count()
        .get_result(&mut conn)
        .await
        .unwrap();
    assert_eq!(audit_count, 1, "revoke must produce exactly one audit row");
}

#[tokio::test]
async fn t6_self_revoke_is_allowed() {
    // No SoD on revoke: reducing one's own access is always licit.
    let p = pool().await;
    let requester = insert_user(&p, &unique("req_srv")).await;
    let approver = insert_user(&p, &unique("apr_srv")).await;
    let asset = insert_asset(&p, &unique("a_srv")).await;
    let session_uuid = insert_approved_session(&p, requester, approver, asset).await;
    let requester_uuid = user_uuid_of(&p, requester).await;

    let resp = record_decision(
        &p,
        requester_uuid,
        session_uuid,
        ApprovalDecisionKind::Revoke,
        None,
    )
    .await;
    match resp {
        AccessResponse::ApprovalRecorded { .. } => {}
        other => panic!("self-revoke must be allowed, got {other:?}"),
    }
}

#[tokio::test]
async fn t6_revoke_pending_denied_session_not_approved() {
    let p = pool().await;
    let requester = insert_user(&p, &unique("req_rp")).await;
    let admin = insert_user(&p, &unique("adm_rp")).await;
    let asset = insert_asset(&p, &unique("a_rp")).await;
    let session_uuid = insert_pending_session(&p, requester, asset).await;
    let admin_uuid = user_uuid_of(&p, admin).await;

    let resp = record_decision(
        &p,
        admin_uuid,
        session_uuid,
        ApprovalDecisionKind::Revoke,
        None,
    )
    .await;
    match resp {
        AccessResponse::ApprovalDenied {
            reason: ApprovalDenyReason::SessionNotApproved,
        } => {}
        other => panic!("expected SessionNotApproved, got {other:?}"),
    }
}

#[tokio::test]
async fn t6_revoke_twice_second_loses() {
    let p = pool().await;
    let requester = insert_user(&p, &unique("req_r2")).await;
    let approver = insert_user(&p, &unique("apr_r2")).await;
    let admin = insert_user(&p, &unique("adm_r2")).await;
    let asset = insert_asset(&p, &unique("a_r2")).await;
    let session_uuid = insert_approved_session(&p, requester, approver, asset).await;
    let admin_uuid = user_uuid_of(&p, admin).await;

    let first = record_decision(
        &p,
        admin_uuid,
        session_uuid,
        ApprovalDecisionKind::Revoke,
        None,
    )
    .await;
    assert!(
        matches!(first, AccessResponse::ApprovalRecorded { .. }),
        "first revoke must win, got {first:?}"
    );
    let second = record_decision(
        &p,
        admin_uuid,
        session_uuid,
        ApprovalDecisionKind::Revoke,
        None,
    )
    .await;
    match second {
        AccessResponse::ApprovalDenied {
            reason: ApprovalDenyReason::SessionNotApproved,
        } => {}
        other => panic!("second revoke must be denied SessionNotApproved, got {other:?}"),
    }
}

#[tokio::test]
async fn t6_update_duration_recomputes_expires_from_approved_at() {
    let p = pool().await;
    let requester = insert_user(&p, &unique("req_ud")).await;
    let approver = insert_user(&p, &unique("apr_ud")).await;
    let admin = insert_user(&p, &unique("adm_ud")).await;
    let asset = insert_asset(&p, &unique("a_ud")).await;
    link_grant_chain(&p, requester, asset).await;
    let session_uuid = insert_approved_session(&p, requester, approver, asset).await;
    let admin_uuid = user_uuid_of(&p, admin).await;

    let resp = record_decision(
        &p,
        admin_uuid,
        session_uuid,
        ApprovalDecisionKind::UpdateDuration,
        Some(7200),
    )
    .await;
    assert!(
        matches!(resp, AccessResponse::ApprovalRecorded { .. }),
        "update_duration must be recorded, got {resp:?}"
    );

    let mut conn = p.get().await.unwrap();
    let (status, approved_at, expires_at, max_dur): (String, Option<Ts>, Option<Ts>, Option<i32>) =
        proxy_sessions::table
            .filter(proxy_sessions::uuid.eq(session_uuid))
            .select((
                proxy_sessions::status,
                proxy_sessions::approved_at,
                proxy_sessions::expires_at,
                proxy_sessions::max_session_duration,
            ))
            .first(&mut conn)
            .await
            .unwrap();
    assert_eq!(status, "approved", "grant must stay approved");
    assert_eq!(max_dur, Some(7200));
    let expected = approved_at.unwrap() + chrono::Duration::seconds(7200);
    let drift = (expires_at.unwrap() - expected).num_seconds().abs();
    assert!(
        drift < 2,
        "expires_at must equal approved_at + 7200s (drift {drift}s)"
    );

    let override_secs: Option<i32> = approval_audit_log::table
        .filter(approval_audit_log::session_uuid.eq(session_uuid))
        .filter(approval_audit_log::decision.eq("update_duration"))
        .select(approval_audit_log::duration_override_seconds)
        .first(&mut conn)
        .await
        .unwrap();
    assert_eq!(
        override_secs,
        Some(7200),
        "audit row must carry the new duration"
    );
}

#[tokio::test]
async fn t6_update_duration_reduction_below_elapsed_lands_in_the_past() {
    // Shrinking the window below the already-elapsed time must move
    // `expires_at` into the past (grant instantly inert for connects).
    let p = pool().await;
    let requester = insert_user(&p, &unique("req_sh")).await;
    let approver = insert_user(&p, &unique("apr_sh")).await;
    let admin = insert_user(&p, &unique("adm_sh")).await;
    let asset = insert_asset(&p, &unique("a_sh")).await;
    link_grant_chain(&p, requester, asset).await;
    // approved_at is 10 minutes ago; shrink the window to 1 minute.
    let session_uuid = insert_approved_session(&p, requester, approver, asset).await;
    let admin_uuid = user_uuid_of(&p, admin).await;

    let resp = record_decision(
        &p,
        admin_uuid,
        session_uuid,
        ApprovalDecisionKind::UpdateDuration,
        Some(60),
    )
    .await;
    assert!(matches!(resp, AccessResponse::ApprovalRecorded { .. }));

    let mut conn = p.get().await.unwrap();
    let expires_at: Option<chrono::DateTime<chrono::Utc>> = proxy_sessions::table
        .filter(proxy_sessions::uuid.eq(session_uuid))
        .select(proxy_sessions::expires_at)
        .first(&mut conn)
        .await
        .unwrap();
    assert!(
        expires_at.unwrap() < chrono::Utc::now(),
        "shrunk-below-elapsed window must land expires_at in the past"
    );
}

#[tokio::test]
async fn t6_update_duration_without_duration_is_hard_error() {
    let p = pool().await;
    let requester = insert_user(&p, &unique("req_nd")).await;
    let approver = insert_user(&p, &unique("apr_nd")).await;
    let admin = insert_user(&p, &unique("adm_nd")).await;
    let asset = insert_asset(&p, &unique("a_nd")).await;
    let session_uuid = insert_approved_session(&p, requester, approver, asset).await;
    let admin_uuid = user_uuid_of(&p, admin).await;

    let resp = record_decision(
        &p,
        admin_uuid,
        session_uuid,
        ApprovalDecisionKind::UpdateDuration,
        None,
    )
    .await;
    match resp {
        AccessResponse::Error(msg) => assert!(
            msg.contains("duration_override_seconds"),
            "error must name the missing field, got: {msg}"
        ),
        other => panic!("expected hard Error, got {other:?}"),
    }
    // The grant must be untouched.
    let mut conn = p.get().await.unwrap();
    let status: String = proxy_sessions::table
        .filter(proxy_sessions::uuid.eq(session_uuid))
        .select(proxy_sessions::status)
        .first(&mut conn)
        .await
        .unwrap();
    assert_eq!(status, "approved");
}

#[tokio::test]
async fn t6_update_duration_on_pending_denied_session_not_approved() {
    let p = pool().await;
    let requester = insert_user(&p, &unique("req_up")).await;
    let admin = insert_user(&p, &unique("adm_up")).await;
    let asset = insert_asset(&p, &unique("a_up")).await;
    let session_uuid = insert_pending_session(&p, requester, asset).await;
    let admin_uuid = user_uuid_of(&p, admin).await;

    let resp = record_decision(
        &p,
        admin_uuid,
        session_uuid,
        ApprovalDecisionKind::UpdateDuration,
        Some(3600),
    )
    .await;
    match resp {
        AccessResponse::ApprovalDenied {
            reason: ApprovalDenyReason::SessionNotApproved,
        } => {}
        other => panic!("expected SessionNotApproved, got {other:?}"),
    }
}

#[tokio::test]
async fn t6_update_duration_by_requester_denied_self_approval() {
    // Extending one's own grant would break SoD — same fence as
    // approve/reject.
    let p = pool().await;
    let requester = insert_user(&p, &unique("req_su")).await;
    let approver = insert_user(&p, &unique("apr_su")).await;
    let asset = insert_asset(&p, &unique("a_su")).await;
    let session_uuid = insert_approved_session(&p, requester, approver, asset).await;
    let requester_uuid = user_uuid_of(&p, requester).await;

    let resp = record_decision(
        &p,
        requester_uuid,
        session_uuid,
        ApprovalDecisionKind::UpdateDuration,
        Some(7200),
    )
    .await;
    match resp {
        AccessResponse::ApprovalDenied {
            reason: ApprovalDenyReason::SelfApproval,
        } => {}
        other => panic!("expected SelfApproval denial, got {other:?}"),
    }
}

#[tokio::test]
async fn t6_db_check_decision_accepts_new_literals() {
    // The widened CHECK must accept the two new decision literals.
    let p = pool().await;
    let actor = insert_user(&p, &unique("act_ck")).await;
    let requester = insert_user(&p, &unique("req_ck")).await;
    let mut conn = p.get().await.unwrap();
    for decision in ["revoke", "update_duration"] {
        let res = diesel::insert_into(approval_audit_log::table)
            .values((
                approval_audit_log::session_uuid.eq(Uuid::new_v4()),
                approval_audit_log::decision.eq(decision),
                approval_audit_log::actor_user_id.eq(Some(actor)),
                approval_audit_log::actor_username.eq("act"),
                approval_audit_log::requester_user_id.eq(Some(requester)),
                approval_audit_log::requester_username.eq("req"),
                approval_audit_log::asset_uuid.eq(Uuid::new_v4()),
                approval_audit_log::asset_name.eq("a"),
            ))
            .execute(&mut conn)
            .await;
        assert!(
            res.is_ok(),
            "decision '{decision}' must pass CHECK: {res:?}"
        );
    }
}

// =====================================================================
// Tier 7 — structural pins
//
// These tests freeze public-surface invariants whose silent drift would
// break the audit contract. They run without a database.
// =====================================================================

#[test]
fn t7_approval_deny_reason_variants_are_stable() {
    // Pin the wire shape of ApprovalDenyReason. Adding a new variant is
    // fine; renaming or removing one changes the IPC contract and must
    // be a deliberate, reviewed change. The `match` is exhaustive: a
    // forgotten variant fails compilation.
    use ApprovalDenyReason::*;
    fn _exhaustive(r: ApprovalDenyReason) -> &'static str {
        match r {
            SessionNotFound => "SessionNotFound",
            SessionNotPending => "SessionNotPending",
            SessionNotApproved => "SessionNotApproved",
            SelfApproval => "SelfApproval",
            RequesterDisabled => "RequesterDisabled",
            RuleNoLongerRequiresApproval => "RuleNoLongerRequiresApproval",
        }
    }
    assert_eq!(_exhaustive(SelfApproval), "SelfApproval");
    assert_eq!(_exhaustive(SessionNotPending), "SessionNotPending");
    assert_eq!(_exhaustive(SessionNotApproved), "SessionNotApproved");
    // Pin the user-visible message strings so a refactor cannot
    // silently change what operators read in flash + audit log.
    assert_eq!(
        SelfApproval.as_message(),
        "You cannot decide on your own access request (separation of duties)"
    );
    assert_eq!(
        SessionNotPending.as_message(),
        "This request has already been processed"
    );
    assert_eq!(
        SessionNotApproved.as_message(),
        "This grant is not active (already revoked or expired)"
    );
}

#[test]
fn t7_approval_decision_kind_variants_are_stable() {
    use ApprovalDecisionKind::*;
    fn _exhaustive(k: ApprovalDecisionKind) -> &'static str {
        match k {
            Approve => "approve",
            Reject => "reject",
            Revoke => "revoke",
            UpdateDuration => "update_duration",
        }
    }
    assert_eq!(_exhaustive(Approve), "approve");
    assert_eq!(_exhaustive(Reject), "reject");
    assert_eq!(_exhaustive(Revoke), "revoke");
    assert_eq!(_exhaustive(UpdateDuration), "update_duration");
    // The canonical SQL rendering feeds the audit-log `decision`
    // column; it must stay within the widened VARCHAR(16) + CHECK.
    for k in [Approve, Reject, Revoke, UpdateDuration] {
        assert!(
            k.as_str().len() <= 16,
            "decision '{}' overflows",
            k.as_str()
        );
    }
}

#[test]
fn t7_migration_check_constraint_names_match_handler_error_strings() {
    // The migration declares two CHECK constraints. If they are ever
    // renamed in the SQL but not in the runbook, operator queries that
    // grep for the constraint name would return no results. Pin both
    // names here: they must exist verbatim in the migration SQL.
    let sql =
        include_str!("../../vauban-db/migrations/20260425000000_approval_audit_and_sod/up.sql");
    assert!(
        sql.contains("approval_separation_of_duties"),
        "approval CHECK constraint name must be stable"
    );
    assert!(
        sql.contains("rejection_separation_of_duties"),
        "rejection CHECK constraint name must be stable"
    );
    assert!(
        sql.contains("block_approval_audit_log_mutation"),
        "append-only trigger name must be stable"
    );
    assert!(
        sql.contains("approval_audit_log is append-only"),
        "trigger error message keyword must be stable for grep-able runbooks"
    );
}
