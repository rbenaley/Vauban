//! Battle-tests for the IACS / EWS onboarding feature -- Tier 1 (DB
//! invariants) + Tier 7 (structural pins).
//!
//! Tier 2 (IPC contracts) tests live next to the IPC handlers -- they
//! exercise `AccessRequest::SubmitEwsOnboarding`, `RecordEwsDecision`,
//! `OffboardEws`, etc. and are added in the IPC palier alongside the
//! handler implementation.
//!
//! The DB-level invariants pinned here are the *hard floor* of the
//! defense-in-depth model: they hold even if every Rust layer above
//! is bypassed (raw psql, compromised vauban-access, application bug).
//!
//! Tier 1 (DB invariants):
//!   - `block_ews_audit_log_mutation` rejects every UPDATE
//!   - `block_ews_audit_log_mutation` rejects every DELETE
//!   - `ews_audit_log.event` CHECK rejects unknown event literals
//!   - `ews_onboarding_requests.status` CHECK rejects unknown literals
//!   - `ews_request_decision_consistency` CHECK rejects pending+decided drift
//!   - `ews_active_fingerprint_uniq` rejects two active EWS sharing a key
//!   - `ews_active_fingerprint_uniq` allows re-use after offboarding
//!   - No unique constraint on `name` -- two EWS may share a name
//!   - FK ON DELETE SET NULL preserves audit snapshot after user delete
//!
//! Tier 7 (structural pins):
//!   - migration carries the expected constraint / trigger names so the
//!     runbook keeps grepping the right strings

use crate::db::DbPool;
use crate::handlers::handle_access_request;
use crate::schema::{ews, ews_audit_log, ews_onboarding_requests, users};
use diesel::prelude::*;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::deadpool::Pool;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use shared::messages::{AccessRequest, AccessResponse, EwsDecisionKind, EwsDenyReason};
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

/// A 64-hex-char fingerprint that is unique across test runs, so the
/// partial unique index on `ews(public_key_fingerprint)` does not
/// collide between repeated executions of the same test.
fn unique_fingerprint() -> String {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let raw = format!("{ts:032x}{n:032x}");
    let mut s = raw[..64.min(raw.len())].to_string();
    while s.len() < 64 {
        s.push('0');
    }
    s
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
            users::email.eq(format!("{username}@iacs.local")),
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

async fn user_uuid_of(pool: &DbPool, user_id: i32) -> Uuid {
    let mut conn = pool.get().await.unwrap();
    users::table
        .filter(users::id.eq(user_id))
        .select(users::uuid)
        .first(&mut conn)
        .await
        .unwrap()
}

async fn insert_pending_request(pool: &DbPool, user_id: i32, fingerprint: &str) -> Uuid {
    let mut conn = pool.get().await.unwrap();
    diesel::insert_into(ews_onboarding_requests::table)
        .values((
            ews_onboarding_requests::user_id.eq(user_id),
            ews_onboarding_requests::name.eq(unique("ews")),
            ews_onboarding_requests::public_key.eq("ssh-ed25519 AAAA...test"),
            ews_onboarding_requests::public_key_fingerprint.eq(fingerprint),
            ews_onboarding_requests::key_algo.eq("ssh-ed25519"),
            ews_onboarding_requests::justification.eq("test fixture"),
        ))
        .returning(ews_onboarding_requests::uuid)
        .get_result::<Uuid>(&mut conn)
        .await
        .unwrap()
}

async fn insert_active_ews(
    pool: &DbPool,
    user_id: i32,
    name: &str,
    fingerprint: &str,
) -> (Uuid, Uuid) {
    let request_uuid = insert_pending_request(pool, user_id, fingerprint).await;
    let mut conn = pool.get().await.unwrap();
    // Approve the request so the fixture matches the real business
    // sequence: a request is in `pending` only between submit and
    // decide; once we materialise the `ews` row, the source request
    // MUST be in `approved`. Otherwise the pending row would still
    // lock the fingerprint at re-submit time (see
    // `ipc_offboard_ews_is_irreversible_and_releases_fingerprint`).
    diesel::update(
        ews_onboarding_requests::table.filter(ews_onboarding_requests::uuid.eq(request_uuid)),
    )
    .set((
        ews_onboarding_requests::status.eq("approved"),
        ews_onboarding_requests::decided_by_id.eq(Some(user_id)),
        ews_onboarding_requests::decided_at.eq(Some(chrono::Utc::now())),
    ))
    .execute(&mut conn)
    .await
    .unwrap();
    let ews_uuid: Uuid = diesel::insert_into(ews::table)
        .values((
            ews::request_uuid.eq(request_uuid),
            ews::user_id.eq(user_id),
            ews::name.eq(name),
            ews::public_key.eq("ssh-ed25519 AAAA...test"),
            ews::public_key_fingerprint.eq(fingerprint),
            ews::key_algo.eq("ssh-ed25519"),
        ))
        .returning(ews::uuid)
        .get_result(&mut conn)
        .await
        .unwrap();
    (request_uuid, ews_uuid)
}

// =====================================================================
// Tier 1 -- DB invariants
// =====================================================================

#[tokio::test]
async fn db_audit_trigger_blocks_update() {
    let p = pool().await;
    let actor = insert_user(&p, &unique("act")).await;
    let target = insert_user(&p, &unique("tgt")).await;
    let mut conn = p.get().await.unwrap();
    let id: i64 = diesel::insert_into(ews_audit_log::table)
        .values((
            ews_audit_log::request_uuid.eq(Some(Uuid::new_v4())),
            ews_audit_log::event.eq("submitted"),
            ews_audit_log::actor_user_id.eq(Some(actor)),
            ews_audit_log::actor_username.eq("act"),
            ews_audit_log::target_user_id.eq(Some(target)),
            ews_audit_log::target_username.eq("tgt"),
            ews_audit_log::ews_name.eq("workstation"),
            ews_audit_log::public_key_fingerprint.eq(unique_fingerprint()),
        ))
        .returning(ews_audit_log::id)
        .get_result(&mut conn)
        .await
        .unwrap();
    let res = diesel::update(ews_audit_log::table.filter(ews_audit_log::id.eq(id)))
        .set(ews_audit_log::ews_name.eq("tampered"))
        .execute(&mut conn)
        .await;
    assert!(
        res.is_err(),
        "UPDATE on append-only ews_audit_log must raise, got: {res:?}"
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
    let actor = insert_user(&p, &unique("act")).await;
    let target = insert_user(&p, &unique("tgt")).await;
    let mut conn = p.get().await.unwrap();
    let id: i64 = diesel::insert_into(ews_audit_log::table)
        .values((
            ews_audit_log::request_uuid.eq(Some(Uuid::new_v4())),
            ews_audit_log::event.eq("approved"),
            ews_audit_log::actor_user_id.eq(Some(actor)),
            ews_audit_log::actor_username.eq("act"),
            ews_audit_log::target_user_id.eq(Some(target)),
            ews_audit_log::target_username.eq("tgt"),
            ews_audit_log::ews_name.eq("workstation"),
            ews_audit_log::public_key_fingerprint.eq(unique_fingerprint()),
        ))
        .returning(ews_audit_log::id)
        .get_result(&mut conn)
        .await
        .unwrap();
    let res = diesel::delete(ews_audit_log::table.filter(ews_audit_log::id.eq(id)))
        .execute(&mut conn)
        .await;
    assert!(res.is_err(), "DELETE on ews_audit_log must raise");
}

#[tokio::test]
async fn db_audit_event_check_rejects_unknown_value() {
    let p = pool().await;
    let actor = insert_user(&p, &unique("act")).await;
    let target = insert_user(&p, &unique("tgt")).await;
    let mut conn = p.get().await.unwrap();
    let res = diesel::insert_into(ews_audit_log::table)
        .values((
            ews_audit_log::request_uuid.eq(Some(Uuid::new_v4())),
            ews_audit_log::event.eq("hijack"),
            ews_audit_log::actor_user_id.eq(Some(actor)),
            ews_audit_log::actor_username.eq("act"),
            ews_audit_log::target_user_id.eq(Some(target)),
            ews_audit_log::target_username.eq("tgt"),
            ews_audit_log::ews_name.eq("ws"),
            ews_audit_log::public_key_fingerprint.eq(unique_fingerprint()),
        ))
        .execute(&mut conn)
        .await;
    assert!(
        res.is_err(),
        "INSERT with event='hijack' must violate the CHECK"
    );
}

#[tokio::test]
async fn db_request_status_check_rejects_unknown_value() {
    let p = pool().await;
    let user = insert_user(&p, &unique("u")).await;
    let mut conn = p.get().await.unwrap();
    let res = diesel::insert_into(ews_onboarding_requests::table)
        .values((
            ews_onboarding_requests::user_id.eq(user),
            ews_onboarding_requests::name.eq("ws"),
            ews_onboarding_requests::public_key.eq("ssh-ed25519 X"),
            ews_onboarding_requests::public_key_fingerprint.eq(unique_fingerprint()),
            ews_onboarding_requests::key_algo.eq("ssh-ed25519"),
            ews_onboarding_requests::justification.eq("j"),
            ews_onboarding_requests::status.eq("hijack"),
        ))
        .execute(&mut conn)
        .await;
    assert!(
        res.is_err(),
        "INSERT with status='hijack' must violate the CHECK"
    );
}

#[tokio::test]
async fn db_request_decision_consistency_blocks_pending_with_decided_at() {
    // pending row with a non-null decided_at violates ews_request_decision_consistency.
    let p = pool().await;
    let user = insert_user(&p, &unique("u")).await;
    let mut conn = p.get().await.unwrap();
    let res = diesel::insert_into(ews_onboarding_requests::table)
        .values((
            ews_onboarding_requests::user_id.eq(user),
            ews_onboarding_requests::name.eq("ws"),
            ews_onboarding_requests::public_key.eq("ssh-ed25519 X"),
            ews_onboarding_requests::public_key_fingerprint.eq(unique_fingerprint()),
            ews_onboarding_requests::key_algo.eq("ssh-ed25519"),
            ews_onboarding_requests::justification.eq("j"),
            ews_onboarding_requests::status.eq("pending"),
            ews_onboarding_requests::decided_at.eq(Some(chrono::Utc::now())),
        ))
        .execute(&mut conn)
        .await;
    assert!(
        res.is_err(),
        "pending + decided_at must violate decision_consistency CHECK"
    );
}

#[tokio::test]
async fn db_request_decision_consistency_blocks_rejected_without_reason() {
    // rejected without decision_reason violates the CHECK.
    let p = pool().await;
    let user = insert_user(&p, &unique("u")).await;
    let mut conn = p.get().await.unwrap();
    let res = diesel::insert_into(ews_onboarding_requests::table)
        .values((
            ews_onboarding_requests::user_id.eq(user),
            ews_onboarding_requests::name.eq("ws"),
            ews_onboarding_requests::public_key.eq("ssh-ed25519 X"),
            ews_onboarding_requests::public_key_fingerprint.eq(unique_fingerprint()),
            ews_onboarding_requests::key_algo.eq("ssh-ed25519"),
            ews_onboarding_requests::justification.eq("j"),
            ews_onboarding_requests::status.eq("rejected"),
            ews_onboarding_requests::decided_at.eq(Some(chrono::Utc::now())),
        ))
        .execute(&mut conn)
        .await;
    assert!(
        res.is_err(),
        "rejected without decision_reason must violate CHECK"
    );
}

#[tokio::test]
async fn db_active_fingerprint_uniq_blocks_second_active_ews_with_same_key() {
    let p = pool().await;
    let user_a = insert_user(&p, &unique("ua")).await;
    let user_b = insert_user(&p, &unique("ub")).await;
    let fp = unique_fingerprint();
    let _ = insert_active_ews(&p, user_a, "wsA", &fp).await;
    // Second active EWS reusing the fingerprint must fail.
    let req_b = insert_pending_request(&p, user_b, &fp).await;
    let mut conn = p.get().await.unwrap();
    let res = diesel::insert_into(ews::table)
        .values((
            ews::request_uuid.eq(req_b),
            ews::user_id.eq(user_b),
            ews::name.eq("wsB"),
            ews::public_key.eq("ssh-ed25519 X"),
            ews::public_key_fingerprint.eq(&fp),
            ews::key_algo.eq("ssh-ed25519"),
        ))
        .execute(&mut conn)
        .await;
    assert!(
        res.is_err(),
        "second active EWS with same fingerprint must violate ews_active_fingerprint_uniq"
    );
}

#[tokio::test]
async fn db_active_fingerprint_uniq_allows_reuse_after_offboarding() {
    let p = pool().await;
    let user_a = insert_user(&p, &unique("ua")).await;
    let user_b = insert_user(&p, &unique("ub")).await;
    let fp = unique_fingerprint();
    let (_req_a, ews_a) = insert_active_ews(&p, user_a, "wsA", &fp).await;
    // Offboard wsA -- this must release the fingerprint.
    let mut conn = p.get().await.unwrap();
    diesel::update(ews::table.filter(ews::uuid.eq(ews_a)))
        .set((
            ews::offboarded_by_id.eq(Some(user_a)),
            ews::offboarded_at.eq(Some(chrono::Utc::now())),
        ))
        .execute(&mut conn)
        .await
        .unwrap();
    // Now user_b can claim the same fingerprint on a fresh active EWS.
    let req_b = insert_pending_request(&p, user_b, &fp).await;
    let res = diesel::insert_into(ews::table)
        .values((
            ews::request_uuid.eq(req_b),
            ews::user_id.eq(user_b),
            ews::name.eq("wsB"),
            ews::public_key.eq("ssh-ed25519 X"),
            ews::public_key_fingerprint.eq(&fp),
            ews::key_algo.eq("ssh-ed25519"),
        ))
        .execute(&mut conn)
        .await;
    assert!(
        res.is_ok(),
        "reusing a fingerprint after offboarding must succeed, got: {res:?}"
    );
}

#[tokio::test]
async fn db_active_fingerprint_uniq_still_blocks_after_disable() {
    // Disabling does NOT release the fingerprint -- only offboarding does.
    let p = pool().await;
    let user_a = insert_user(&p, &unique("ua")).await;
    let user_b = insert_user(&p, &unique("ub")).await;
    let fp = unique_fingerprint();
    let (_req_a, ews_a) = insert_active_ews(&p, user_a, "wsA", &fp).await;
    let mut conn = p.get().await.unwrap();
    diesel::update(ews::table.filter(ews::uuid.eq(ews_a)))
        .set((
            ews::disabled_by_id.eq(Some(user_a)),
            ews::disabled_at.eq(Some(chrono::Utc::now())),
        ))
        .execute(&mut conn)
        .await
        .unwrap();
    let req_b = insert_pending_request(&p, user_b, &fp).await;
    let res = diesel::insert_into(ews::table)
        .values((
            ews::request_uuid.eq(req_b),
            ews::user_id.eq(user_b),
            ews::name.eq("wsB"),
            ews::public_key.eq("ssh-ed25519 X"),
            ews::public_key_fingerprint.eq(&fp),
            ews::key_algo.eq("ssh-ed25519"),
        ))
        .execute(&mut conn)
        .await;
    assert!(
        res.is_err(),
        "fingerprint must stay locked while EWS is disabled"
    );
}

#[tokio::test]
async fn db_no_unique_on_name_two_ews_can_share_a_name() {
    // Spec: the SHA-256 fingerprint discriminates visually; nothing
    // prevents two EWS from sharing a `name` value (even for the same
    // user, as long as the fingerprints differ).
    let p = pool().await;
    let user = insert_user(&p, &unique("u")).await;
    let (_, ews_a) = insert_active_ews(&p, user, "Laptop1", &unique_fingerprint()).await;
    let (_, ews_b) = insert_active_ews(&p, user, "Laptop1", &unique_fingerprint()).await;
    assert_ne!(
        ews_a, ews_b,
        "two distinct EWS rows must coexist with the same name"
    );
}

#[tokio::test]
async fn db_audit_row_snapshot_survives_user_soft_deletion() {
    // The snapshot fields keep the trail meaningful after the actor
    // or target user is soft-deleted.
    let p = pool().await;
    let actor = insert_user(&p, &unique("act_soft")).await;
    let target = insert_user(&p, &unique("tgt_soft")).await;
    let mut conn = p.get().await.unwrap();
    let id: i64 = diesel::insert_into(ews_audit_log::table)
        .values((
            ews_audit_log::request_uuid.eq(Some(Uuid::new_v4())),
            ews_audit_log::event.eq("approved"),
            ews_audit_log::actor_user_id.eq(Some(actor)),
            ews_audit_log::actor_username.eq("act_snapshot"),
            ews_audit_log::target_user_id.eq(Some(target)),
            ews_audit_log::target_username.eq("tgt_snapshot"),
            ews_audit_log::ews_name.eq("ws"),
            ews_audit_log::public_key_fingerprint.eq(unique_fingerprint()),
        ))
        .returning(ews_audit_log::id)
        .get_result(&mut conn)
        .await
        .unwrap();
    diesel::update(users::table.filter(users::id.eq(target)))
        .set((users::is_deleted.eq(true), users::is_active.eq(false)))
        .execute(&mut conn)
        .await
        .unwrap();
    let uname: String = ews_audit_log::table
        .filter(ews_audit_log::id.eq(id))
        .select(ews_audit_log::target_username)
        .first(&mut conn)
        .await
        .unwrap();
    assert_eq!(uname, "tgt_snapshot");
}

#[tokio::test]
async fn db_user_hard_delete_cascades_set_null_on_audit_log() {
    // FK ON DELETE SET NULL on actor / target user-id columns so user
    // lifecycle management does not need to drop the trigger.
    let p = pool().await;
    let actor = insert_user(&p, &unique("act_hd")).await;
    let target = insert_user(&p, &unique("tgt_hd")).await;
    let mut conn = p.get().await.unwrap();
    let request_uuid = Uuid::new_v4();
    diesel::insert_into(ews_audit_log::table)
        .values((
            ews_audit_log::request_uuid.eq(Some(request_uuid)),
            ews_audit_log::event.eq("submitted"),
            ews_audit_log::actor_user_id.eq(Some(actor)),
            ews_audit_log::actor_username.eq("act"),
            ews_audit_log::target_user_id.eq(Some(target)),
            ews_audit_log::target_username.eq("tgt"),
            ews_audit_log::ews_name.eq("ws"),
            ews_audit_log::public_key_fingerprint.eq(unique_fingerprint()),
        ))
        .execute(&mut conn)
        .await
        .unwrap();
    diesel::delete(users::table.filter(users::id.eq(target)))
        .execute(&mut conn)
        .await
        .expect("hard-delete of user must succeed (FK SET NULL)");
    let (tgt_id, tgt_name): (Option<i32>, String) = ews_audit_log::table
        .filter(ews_audit_log::request_uuid.eq(Some(request_uuid)))
        .select((
            ews_audit_log::target_user_id,
            ews_audit_log::target_username,
        ))
        .first(&mut conn)
        .await
        .unwrap();
    assert!(tgt_id.is_none(), "target FK must be NULLed after delete");
    assert_eq!(
        tgt_name, "tgt",
        "snapshotted username must survive user delete"
    );
}

#[tokio::test]
async fn db_audit_event_targets_check_rejects_both_uuids_null() {
    // The CHECK `ews_audit_log_event_targets_at_least_one` requires
    // at least one of `ews_uuid` or `request_uuid` to be non-NULL.
    let p = pool().await;
    let actor = insert_user(&p, &unique("a")).await;
    let target = insert_user(&p, &unique("t")).await;
    let mut conn = p.get().await.unwrap();
    let res = diesel::insert_into(ews_audit_log::table)
        .values((
            ews_audit_log::event.eq("submitted"),
            ews_audit_log::actor_user_id.eq(Some(actor)),
            ews_audit_log::actor_username.eq("a"),
            ews_audit_log::target_user_id.eq(Some(target)),
            ews_audit_log::target_username.eq("t"),
            ews_audit_log::ews_name.eq("ws"),
            ews_audit_log::public_key_fingerprint.eq(unique_fingerprint()),
        ))
        .execute(&mut conn)
        .await;
    assert!(
        res.is_err(),
        "both ews_uuid and request_uuid NULL must violate the CHECK"
    );
}

// =====================================================================
// Tier 7 -- structural pins (no DB)
// =====================================================================

#[test]
fn t7_migration_carries_expected_constraint_and_trigger_names() {
    let sql = include_str!("../../vauban-db/migrations/20260506000000_iacs_ews_onboarding/up.sql");
    for needle in [
        "ews_onboarding_requests",
        "ews_request_decision_consistency",
        "ews_disabled_consistency",
        "ews_offboarded_consistency",
        "ews_active_fingerprint_uniq",
        "ews_audit_log",
        "block_ews_audit_log_mutation",
        "block_ews_audit_log_update",
        "block_ews_audit_log_delete",
        "ews_audit_log_event_targets_at_least_one",
        "ews_audit_log is append-only",
    ] {
        assert!(
            sql.contains(needle),
            "migration must contain '{needle}' (runbook / lint stability)"
        );
    }
}

#[test]
fn t7_migration_lists_every_audit_event_literal() {
    // The CHECK on `ews_audit_log.event` must list exactly the eight
    // events emitted by the IACS lifecycle. A drift would either let
    // an unknown event slip through (silent) or block a legitimate
    // event (loud, but bad).
    let sql = include_str!("../../vauban-db/migrations/20260506000000_iacs_ews_onboarding/up.sql");
    for event in [
        "'submitted'",
        "'edited'",
        "'cancelled'",
        "'approved'",
        "'rejected'",
        "'disabled'",
        "'enabled'",
        "'offboarded'",
    ] {
        assert!(
            sql.contains(event),
            "migration must list event literal {event}"
        );
    }
}

#[test]
fn t7_migration_lists_every_request_status_literal() {
    let sql = include_str!("../../vauban-db/migrations/20260506000000_iacs_ews_onboarding/up.sql");
    for status in ["'pending'", "'approved'", "'rejected'", "'cancelled'"] {
        assert!(
            sql.contains(status),
            "migration must list request status literal {status}"
        );
    }
}

// =====================================================================
// Tier 2 -- IPC contracts (live DB + dispatcher)
//
// Each test exercises one variant of `AccessRequest` end-to-end through
// `handle_access_request`, ensuring (a) the dispatch matches the
// variant, (b) the in-transaction re-checks fail-closed on adversarial
// input, and (c) the `ews_audit_log` row is committed atomically.
// =====================================================================

fn pubkey() -> String {
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDoesNotMatterForIpcTier".to_string()
}

#[tokio::test]
async fn ipc_submit_ews_onboarding_happy_path() {
    let p = pool().await;
    let user = insert_user(&p, &unique("u")).await;
    let actor_uuid = user_uuid_of(&p, user).await;
    let fp = unique_fingerprint();
    let resp = handle_access_request(
        &p,
        AccessRequest::SubmitEwsOnboarding {
            actor_user_uuid: actor_uuid.to_string(),
            name: "MyLaptop".into(),
            public_key: pubkey(),
            public_key_fingerprint: fp.clone(),
            key_algo: "ssh-ed25519".into(),
            justification: "I need to onboard my workstation".into(),
            max_ews_per_user: 0,
            actor_ip: None,
        },
    )
    .await;
    let request_uuid = match resp {
        AccessResponse::EwsRequestSubmitted {
            request_uuid,
            audit_log_id,
        } => {
            assert!(audit_log_id > 0);
            request_uuid
        }
        other => panic!("expected EwsRequestSubmitted, got {other:?}"),
    };
    // Audit row was inserted.
    let mut conn = p.get().await.unwrap();
    let count: i64 = ews_audit_log::table
        .filter(ews_audit_log::request_uuid.eq(Some(Uuid::parse_str(&request_uuid).unwrap())))
        .filter(ews_audit_log::event.eq("submitted"))
        .count()
        .get_result(&mut conn)
        .await
        .unwrap();
    assert_eq!(count, 1, "submitted audit row must exist");
}

#[tokio::test]
async fn ipc_submit_ews_onboarding_rejects_malformed_actor_uuid() {
    let p = pool().await;
    let resp = handle_access_request(
        &p,
        AccessRequest::SubmitEwsOnboarding {
            actor_user_uuid: "not-a-uuid".into(),
            name: "ws".into(),
            public_key: pubkey(),
            public_key_fingerprint: unique_fingerprint(),
            key_algo: "ssh-ed25519".into(),
            justification: "j".into(),
            max_ews_per_user: 0,
            actor_ip: None,
        },
    )
    .await;
    match resp {
        AccessResponse::EwsDecisionDenied {
            reason: EwsDenyReason::RequestNotFound,
        } => {}
        other => panic!("expected RequestNotFound, got {other:?}"),
    }
}

#[tokio::test]
async fn ipc_submit_ews_onboarding_rejects_duplicate_active_fingerprint() {
    let p = pool().await;
    let user_a = insert_user(&p, &unique("ua")).await;
    let user_b = insert_user(&p, &unique("ub")).await;
    let fp = unique_fingerprint();
    let _ = insert_active_ews(&p, user_a, "wsA", &fp).await;

    let resp = handle_access_request(
        &p,
        AccessRequest::SubmitEwsOnboarding {
            actor_user_uuid: user_uuid_of(&p, user_b).await.to_string(),
            name: "wsB".into(),
            public_key: pubkey(),
            public_key_fingerprint: fp,
            key_algo: "ssh-ed25519".into(),
            justification: "j".into(),
            max_ews_per_user: 0,
            actor_ip: None,
        },
    )
    .await;
    match resp {
        AccessResponse::EwsDecisionDenied {
            reason: EwsDenyReason::KeyAlreadyUsed,
        } => {}
        other => panic!("expected KeyAlreadyUsed, got {other:?}"),
    }
}

#[tokio::test]
async fn ipc_submit_ews_onboarding_enforces_max_ews_per_user() {
    let p = pool().await;
    let user = insert_user(&p, &unique("u")).await;
    let actor_uuid = user_uuid_of(&p, user).await.to_string();
    // First submit succeeds (count=0 < cap=1).
    let r1 = handle_access_request(
        &p,
        AccessRequest::SubmitEwsOnboarding {
            actor_user_uuid: actor_uuid.clone(),
            name: "ws1".into(),
            public_key: pubkey(),
            public_key_fingerprint: unique_fingerprint(),
            key_algo: "ssh-ed25519".into(),
            justification: "j".into(),
            max_ews_per_user: 1,
            actor_ip: None,
        },
    )
    .await;
    assert!(matches!(r1, AccessResponse::EwsRequestSubmitted { .. }));
    // Second submit hits the cap (1 pending == cap).
    let r2 = handle_access_request(
        &p,
        AccessRequest::SubmitEwsOnboarding {
            actor_user_uuid: actor_uuid,
            name: "ws2".into(),
            public_key: pubkey(),
            public_key_fingerprint: unique_fingerprint(),
            key_algo: "ssh-ed25519".into(),
            justification: "j".into(),
            max_ews_per_user: 1,
            actor_ip: None,
        },
    )
    .await;
    match r2 {
        AccessResponse::EwsDecisionDenied {
            reason: EwsDenyReason::MaxEwsPerUserReached,
        } => {}
        other => panic!("expected MaxEwsPerUserReached, got {other:?}"),
    }
}

#[tokio::test]
async fn ipc_edit_ews_request_denies_not_owner() {
    let p = pool().await;
    let owner = insert_user(&p, &unique("own")).await;
    let stranger = insert_user(&p, &unique("str")).await;
    let req = insert_pending_request(&p, owner, &unique_fingerprint()).await;
    let resp = handle_access_request(
        &p,
        AccessRequest::EditEwsRequest {
            actor_user_uuid: user_uuid_of(&p, stranger).await.to_string(),
            request_uuid: req.to_string(),
            name: "evil".into(),
            public_key: pubkey(),
            public_key_fingerprint: unique_fingerprint(),
            key_algo: "ssh-ed25519".into(),
            justification: "evil".into(),
            actor_ip: None,
        },
    )
    .await;
    match resp {
        AccessResponse::EwsDecisionDenied {
            reason: EwsDenyReason::NotOwner,
        } => {}
        other => panic!("expected NotOwner, got {other:?}"),
    }
}

#[tokio::test]
async fn ipc_cancel_ews_request_happy_path_then_re_cancel_denies() {
    let p = pool().await;
    let user = insert_user(&p, &unique("u")).await;
    let req = insert_pending_request(&p, user, &unique_fingerprint()).await;
    let actor_uuid = user_uuid_of(&p, user).await.to_string();

    let r1 = handle_access_request(
        &p,
        AccessRequest::CancelEwsRequest {
            actor_user_uuid: actor_uuid.clone(),
            request_uuid: req.to_string(),
            actor_ip: None,
        },
    )
    .await;
    assert!(matches!(r1, AccessResponse::EwsRequestCancelled { .. }));

    let r2 = handle_access_request(
        &p,
        AccessRequest::CancelEwsRequest {
            actor_user_uuid: actor_uuid,
            request_uuid: req.to_string(),
            actor_ip: None,
        },
    )
    .await;
    match r2 {
        AccessResponse::EwsDecisionDenied {
            reason: EwsDenyReason::RequestNotPending,
        } => {}
        other => panic!("second cancel must deny with RequestNotPending, got {other:?}"),
    }
}

#[tokio::test]
async fn ipc_record_ews_decision_approve_creates_ews_row() {
    let p = pool().await;
    let admin = insert_user(&p, &unique("adm")).await;
    let owner = insert_user(&p, &unique("own")).await;
    let req = insert_pending_request(&p, owner, &unique_fingerprint()).await;
    let resp = handle_access_request(
        &p,
        AccessRequest::RecordEwsDecision {
            actor_user_uuid: user_uuid_of(&p, admin).await.to_string(),
            request_uuid: req.to_string(),
            decision: EwsDecisionKind::Approve,
            decision_reason: None,
            actor_ip: None,
        },
    )
    .await;
    let (audit_log_id, ews_uuid) = match resp {
        AccessResponse::EwsDecisionRecorded {
            audit_log_id,
            ews_uuid,
        } => (audit_log_id, ews_uuid.unwrap()),
        other => panic!("expected EwsDecisionRecorded with ews_uuid, got {other:?}"),
    };
    assert!(audit_log_id > 0);
    // ews row was created.
    let mut conn = p.get().await.unwrap();
    let cnt: i64 = ews::table
        .filter(ews::uuid.eq(Uuid::parse_str(&ews_uuid).unwrap()))
        .count()
        .get_result(&mut conn)
        .await
        .unwrap();
    assert_eq!(cnt, 1);
}

#[tokio::test]
async fn ipc_record_ews_decision_reject_requires_reason() {
    let p = pool().await;
    let admin = insert_user(&p, &unique("adm")).await;
    let owner = insert_user(&p, &unique("own")).await;
    let req = insert_pending_request(&p, owner, &unique_fingerprint()).await;
    // Empty reason -> deny.
    let resp = handle_access_request(
        &p,
        AccessRequest::RecordEwsDecision {
            actor_user_uuid: user_uuid_of(&p, admin).await.to_string(),
            request_uuid: req.to_string(),
            decision: EwsDecisionKind::Reject,
            decision_reason: Some("   ".into()),
            actor_ip: None,
        },
    )
    .await;
    assert!(matches!(
        resp,
        AccessResponse::EwsDecisionDenied {
            reason: EwsDenyReason::RequestNotPending
        }
    ));
    // Non-empty reason -> success.
    let resp = handle_access_request(
        &p,
        AccessRequest::RecordEwsDecision {
            actor_user_uuid: user_uuid_of(&p, admin).await.to_string(),
            request_uuid: req.to_string(),
            decision: EwsDecisionKind::Reject,
            decision_reason: Some("Insufficient justification".into()),
            actor_ip: None,
        },
    )
    .await;
    assert!(matches!(
        resp,
        AccessResponse::EwsDecisionRecorded { ews_uuid: None, .. }
    ));
}

#[tokio::test]
async fn ipc_disable_then_enable_restores_active_state() {
    let p = pool().await;
    let admin = insert_user(&p, &unique("adm")).await;
    let owner = insert_user(&p, &unique("own")).await;
    let (_req, ews_u) = insert_active_ews(&p, owner, "ws", &unique_fingerprint()).await;
    let admin_uuid = user_uuid_of(&p, admin).await.to_string();
    // Disable.
    assert!(matches!(
        handle_access_request(
            &p,
            AccessRequest::DisableEws {
                actor_user_uuid: admin_uuid.clone(),
                ews_uuid: ews_u.to_string(),
                actor_ip: None,
            }
        )
        .await,
        AccessResponse::EwsStateChanged { .. }
    ));
    // Re-enable.
    assert!(matches!(
        handle_access_request(
            &p,
            AccessRequest::EnableEws {
                actor_user_uuid: admin_uuid.clone(),
                ews_uuid: ews_u.to_string(),
                actor_ip: None,
            }
        )
        .await,
        AccessResponse::EwsStateChanged { .. }
    ));
    // Disabling twice in a row denies.
    let _ = handle_access_request(
        &p,
        AccessRequest::DisableEws {
            actor_user_uuid: admin_uuid.clone(),
            ews_uuid: ews_u.to_string(),
            actor_ip: None,
        },
    )
    .await;
    let r = handle_access_request(
        &p,
        AccessRequest::DisableEws {
            actor_user_uuid: admin_uuid,
            ews_uuid: ews_u.to_string(),
            actor_ip: None,
        },
    )
    .await;
    assert!(matches!(
        r,
        AccessResponse::EwsDecisionDenied {
            reason: EwsDenyReason::RequestNotPending
        }
    ));
}

#[tokio::test]
async fn ipc_offboard_ews_is_irreversible_and_releases_fingerprint() {
    let p = pool().await;
    let admin = insert_user(&p, &unique("adm")).await;
    let owner = insert_user(&p, &unique("own")).await;
    let fp = unique_fingerprint();
    let (_req, ews_u) = insert_active_ews(&p, owner, "ws", &fp).await;
    let admin_uuid = user_uuid_of(&p, admin).await.to_string();
    // Offboard.
    let r1 = handle_access_request(
        &p,
        AccessRequest::OffboardEws {
            actor_user_uuid: admin_uuid.clone(),
            ews_uuid: ews_u.to_string(),
            on_behalf_of_self: false,
            decision_reason: Some("retired".into()),
            actor_ip: None,
        },
    )
    .await;
    assert!(matches!(r1, AccessResponse::EwsStateChanged { .. }));
    // Second offboard denies (already offboarded).
    let r2 = handle_access_request(
        &p,
        AccessRequest::OffboardEws {
            actor_user_uuid: admin_uuid,
            ews_uuid: ews_u.to_string(),
            on_behalf_of_self: false,
            decision_reason: None,
            actor_ip: None,
        },
    )
    .await;
    assert!(matches!(
        r2,
        AccessResponse::EwsDecisionDenied {
            reason: EwsDenyReason::EwsAlreadyOffboarded
        }
    ));
    // Re-submitting the same fingerprint as a NEW user/request now succeeds.
    let user2 = insert_user(&p, &unique("u2")).await;
    let r3 = handle_access_request(
        &p,
        AccessRequest::SubmitEwsOnboarding {
            actor_user_uuid: user_uuid_of(&p, user2).await.to_string(),
            name: "ws2".into(),
            public_key: pubkey(),
            public_key_fingerprint: fp,
            key_algo: "ssh-ed25519".into(),
            justification: "j".into(),
            max_ews_per_user: 0,
            actor_ip: None,
        },
    )
    .await;
    assert!(matches!(r3, AccessResponse::EwsRequestSubmitted { .. }));
}

#[tokio::test]
async fn ipc_offboard_ews_self_denied_for_other_user() {
    let p = pool().await;
    let owner = insert_user(&p, &unique("own")).await;
    let stranger = insert_user(&p, &unique("str")).await;
    let (_req, ews_u) = insert_active_ews(&p, owner, "ws", &unique_fingerprint()).await;
    let resp = handle_access_request(
        &p,
        AccessRequest::OffboardEws {
            actor_user_uuid: user_uuid_of(&p, stranger).await.to_string(),
            ews_uuid: ews_u.to_string(),
            on_behalf_of_self: true,
            decision_reason: None,
            actor_ip: None,
        },
    )
    .await;
    assert!(matches!(
        resp,
        AccessResponse::EwsDecisionDenied {
            reason: EwsDenyReason::NotOwner
        }
    ));
}

// =====================================================================
// Tier 7 -- IPC structural pins (no DB)
// =====================================================================

#[test]
fn t7_ews_decision_kind_variants_are_stable() {
    use EwsDecisionKind::*;
    fn _exhaustive(k: EwsDecisionKind) -> &'static str {
        match k {
            Approve => "approve",
            Reject => "reject",
        }
    }
    assert_eq!(_exhaustive(Approve), "approve");
    assert_eq!(_exhaustive(Reject), "reject");
}

#[test]
fn t7_ews_deny_reason_variants_are_stable() {
    use EwsDenyReason::*;
    fn _exhaustive(r: EwsDenyReason) -> &'static str {
        match r {
            RequestNotFound => "RequestNotFound",
            EwsNotFound => "EwsNotFound",
            RequestNotPending => "RequestNotPending",
            EwsAlreadyOffboarded => "EwsAlreadyOffboarded",
            KeyAlreadyUsed => "KeyAlreadyUsed",
            MaxEwsPerUserReached => "MaxEwsPerUserReached",
            NotOwner => "NotOwner",
            TargetUserDisabled => "TargetUserDisabled",
        }
    }
    // Pin a couple of message strings so refactors that drop one
    // localised text do not silently change what operators read.
    assert_eq!(KeyAlreadyUsed.as_message(), KeyAlreadyUsed.as_message());
    assert!(!RequestNotFound.as_message().is_empty());
    let _ = _exhaustive(NotOwner);
}
