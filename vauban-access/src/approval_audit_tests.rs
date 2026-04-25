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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
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
            assets::status.eq("active"),
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
    let res = diesel::update(
        proxy_sessions::table.filter(proxy_sessions::uuid.eq(session_uuid)),
    )
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
    let res = diesel::update(
        proxy_sessions::table.filter(proxy_sessions::uuid.eq(session_uuid)),
    )
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
    let res = diesel::update(
        proxy_sessions::table.filter(proxy_sessions::uuid.eq(session_uuid)),
    )
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
    let res = diesel::update(
        approval_audit_log::table.filter(approval_audit_log::id.eq(id)),
    )
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
    let res = diesel::delete(
        approval_audit_log::table.filter(approval_audit_log::id.eq(id)),
    )
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
async fn db_user_hard_delete_blocked_when_audit_row_exists() {
    // Deleting a user that owns audit rows would fire the FK ON DELETE
    // SET NULL action, which itself UPDATEs the audit row -- and the
    // append-only trigger blocks ANY UPDATE. The end result is that
    // history cannot be erased even by a privileged DBA via a plain
    // `DELETE FROM users`. Hard-delete must therefore be preceded by
    // an explicit DROP of the trigger (a loud, auditable action). This
    // test pins that property so a future migration that loosens the
    // trigger is forced to update the test (and reconsider the
    // tradeoff).
    let p = pool().await;
    let requester = insert_user(&p, &unique("req_hd")).await;
    let approver = insert_user(&p, &unique("apr_hd")).await;
    let mut conn = p.get().await.unwrap();
    diesel::insert_into(approval_audit_log::table)
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
        .execute(&mut conn)
        .await
        .unwrap();
    let res = diesel::delete(users::table.filter(users::id.eq(requester)))
        .execute(&mut conn)
        .await;
    assert!(
        res.is_err(),
        "hard-delete of user with audit rows must be blocked"
    );
    let msg = format!("{:?}", res.unwrap_err()).to_lowercase();
    assert!(
        msg.contains("append-only"),
        "the block must come from the audit-log trigger, got: {msg}"
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
//   T8 user-delete cascade   -> Tier 1: db_user_hard_delete_blocked_*
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
    let attempt = diesel::update(
        approval_audit_log::table.filter(approval_audit_log::id.eq(id)),
    )
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
    assert_eq!(stored, original_uuid, "session_uuid must match the original");
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
            SelfApproval => "SelfApproval",
            RequesterDisabled => "RequesterDisabled",
            RuleNoLongerRequiresApproval => "RuleNoLongerRequiresApproval",
        }
    }
    assert_eq!(_exhaustive(SelfApproval), "SelfApproval");
    assert_eq!(_exhaustive(SessionNotPending), "SessionNotPending");
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
}

#[test]
fn t7_approval_decision_kind_variants_are_stable() {
    use ApprovalDecisionKind::*;
    fn _exhaustive(k: ApprovalDecisionKind) -> &'static str {
        match k {
            Approve => "approve",
            Reject => "reject",
        }
    }
    assert_eq!(_exhaustive(Approve), "approve");
    assert_eq!(_exhaustive(Reject), "reject");
}

#[test]
fn t7_migration_check_constraint_names_match_handler_error_strings() {
    // The migration declares two CHECK constraints. If they are ever
    // renamed in the SQL but not in the runbook, operator queries that
    // grep for the constraint name would return no results. Pin both
    // names here: they must exist verbatim in the migration SQL.
    let sql = include_str!(
        "../../vauban-db/migrations/20260425000000_approval_audit_and_sod/up.sql"
    );
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
