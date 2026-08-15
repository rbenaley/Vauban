//! Property-based invariants for group-membership visibility (ghost
//! members bug, July 2026).
//!
//! Soft-deleting a user used to leave its `user_groups` rows in place,
//! so the raw member count of a vauban group diverged from the member
//! list rendered by the detail page ("2 members" in the list, empty
//! detail) and groups whose members were all deleted became
//! undeletable. The fix routes every read through the
//! `visible_member_count` seam in vauban-access (JOIN users filtered
//! `NOT is_deleted`).
//!
//! This proptest drives BOUNDED RANDOM SEQUENCES of operations
//! (add_member / remove_member / soft-delete / undelete) against the
//! real database through the real vauban-access handler, mirrors them
//! in a trivial in-memory model, and asserts after EVERY step:
//!
//! 1. IPC `member_count` == number of ids returned by
//!    `ListGroupMembers` == visible members predicted by the model.
//! 2. `ListGroupMembers` never returns the id of a soft-deleted user.
//! 3. At the end of the sequence, the delete guard accepts the group
//!    IFF the model says it has zero visible members.
//!
//! The soft-delete op here is a RAW `UPDATE users SET is_deleted =
//! true` that intentionally does NOT purge `user_groups` (the pre-fix
//! orphan shape): the read seam must hold on its own, independently of
//! the write-path purge and of the cleanup migration.

use std::collections::BTreeSet;

use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::deadpool::Pool;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use proptest::prelude::*;
use secrecy::ExposeSecret;
use serial_test::serial;
use shared::messages::{AccessRequest, AccessResponse, IpcPageParams};
use vauban_access::handlers::handle_access_request;
use vauban_web::config::{Config, Environment};

use crate::fixtures::unique_name;

const MAX_USERS: usize = 6;

/// One step of the generated scenario; the user index is resolved
/// against the pool of `MAX_USERS` throwaway users created per case.
#[derive(Debug, Clone, Copy)]
enum Op {
    AddMember(usize),
    RemoveMember(usize),
    SoftDelete(usize),
    Undelete(usize),
}

fn op_strategy() -> impl Strategy<Value = Op> {
    (0..MAX_USERS, 0..4u8).prop_map(|(u, kind)| match kind {
        0 => Op::AddMember(u),
        1 => Op::RemoveMember(u),
        2 => Op::SoftDelete(u),
        _ => Op::Undelete(u),
    })
}

/// In-memory model: membership rows and deletion flags evolve
/// independently (exactly like the two DB tables).
#[derive(Default)]
struct Model {
    members: BTreeSet<usize>,
    deleted: BTreeSet<usize>,
}

impl Model {
    fn apply(&mut self, op: Op) {
        match op {
            Op::AddMember(u) => {
                self.members.insert(u);
            }
            Op::RemoveMember(u) => {
                self.members.remove(&u);
            }
            Op::SoftDelete(u) => {
                self.deleted.insert(u);
            }
            Op::Undelete(u) => {
                self.deleted.remove(&u);
            }
        }
    }

    fn visible(&self) -> BTreeSet<usize> {
        self.members
            .iter()
            .copied()
            .filter(|u| !self.deleted.contains(u))
            .collect()
    }
}

type TestPool = Pool<AsyncPgConnection>;

fn build_pool() -> TestPool {
    let config_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .join("config");
    let config = Config::load_with_environment(config_dir, Environment::Testing)
        .expect("load testing config");
    let manager =
        AsyncDieselConnectionManager::<AsyncPgConnection>::new(config.database.url.expose_secret());
    Pool::builder(manager)
        .max_size(2)
        .build()
        .expect("build test pool")
}

async fn create_user(pool: &TestPool, prefix: &str) -> i32 {
    use vauban_web::schema::users;

    let mut conn = pool.get().await.expect("conn");
    let name = unique_name(prefix);
    diesel::insert_into(users::table)
        .values((
            users::uuid.eq(uuid::Uuid::new_v4()),
            users::username.eq(&name),
            users::email.eq(format!("{name}@test.local")),
            users::password_hash.eq("not_used"),
            users::is_active.eq(true),
        ))
        .returning(users::id)
        .get_result::<i32>(&mut conn)
        .await
        .expect("insert throwaway user")
}

async fn set_deleted(pool: &TestPool, user_id: i32, deleted: bool) {
    use vauban_web::schema::users;

    let mut conn = pool.get().await.expect("conn");
    diesel::update(users::table.filter(users::id.eq(user_id)))
        .set((
            users::is_deleted.eq(deleted),
            users::is_active.eq(!deleted),
            users::deleted_at.eq(deleted.then(chrono::Utc::now)),
        ))
        .execute(&mut conn)
        .await
        .expect("toggle is_deleted");
}

async fn observed_state(pool: &TestPool, group_uuid: &str, group_id: i32) -> (i64, Vec<i32>) {
    let count = match handle_access_request(
        pool,
        AccessRequest::GetVaubanGroup {
            uuid: group_uuid.to_string(),
        },
    )
    .await
    {
        AccessResponse::VaubanGroup(Ok(info)) => info.member_count,
        other => panic!("GetVaubanGroup failed: {other:?}"),
    };
    let members = match handle_access_request(
        pool,
        AccessRequest::ListGroupMembers {
            group_id,
            page: IpcPageParams {
                limit: 0,
                offset: 0,
            },
        },
    )
    .await
    {
        AccessResponse::MemberListPage(page) => {
            assert!(!page.has_more, "test scenarios fit in one IPC page");
            page.items
        }
        other => panic!("ListGroupMembers failed: {other:?}"),
    };
    (count, members)
}

async fn cleanup(pool: &TestPool, group_uuid: &str, user_ids: &[i32]) {
    use vauban_web::schema::{user_groups, users};

    // Physical deletes: the throwaway users are ours, and the FK
    // cascade removes any remaining membership row before the group
    // delete guard runs.
    let mut conn = pool.get().await.expect("conn");
    diesel::delete(user_groups::table.filter(user_groups::user_id.eq_any(user_ids)))
        .execute(&mut conn)
        .await
        .expect("purge memberships");
    diesel::delete(users::table.filter(users::id.eq_any(user_ids)))
        .execute(&mut conn)
        .await
        .expect("delete throwaway users");
    drop(conn);
    let resp = handle_access_request(
        pool,
        AccessRequest::DeleteVaubanGroup {
            uuid: group_uuid.to_string(),
        },
    )
    .await;
    assert!(
        matches!(resp, AccessResponse::Deleted(Ok(()))),
        "cleanup group delete failed: {resp:?}"
    );
}

async fn run_scenario(ops: Vec<Op>) {
    let pool = build_pool();

    let group = match handle_access_request(
        &pool,
        AccessRequest::CreateVaubanGroup {
            name: unique_name("prop_ghost_vg"),
            description: None,
        },
    )
    .await
    {
        AccessResponse::VaubanGroup(Ok(info)) => info,
        other => panic!("CreateVaubanGroup failed: {other:?}"),
    };

    let mut user_ids = Vec::with_capacity(MAX_USERS);
    for _ in 0..MAX_USERS {
        user_ids.push(create_user(&pool, "prop_ghost_user").await);
    }

    let mut model = Model::default();
    for op in &ops {
        match *op {
            Op::AddMember(u) => {
                let resp = handle_access_request(
                    &pool,
                    AccessRequest::AddGroupMember {
                        group_id: group.id,
                        user_id: user_ids[u],
                    },
                )
                .await;
                assert!(
                    matches!(resp, AccessResponse::Ok),
                    "AddGroupMember failed: {resp:?}"
                );
            }
            Op::RemoveMember(u) => {
                let resp = handle_access_request(
                    &pool,
                    AccessRequest::RemoveGroupMember {
                        group_id: group.id,
                        user_id: user_ids[u],
                    },
                )
                .await;
                assert!(
                    matches!(resp, AccessResponse::Ok),
                    "RemoveGroupMember failed: {resp:?}"
                );
            }
            Op::SoftDelete(u) => set_deleted(&pool, user_ids[u], true).await,
            Op::Undelete(u) => set_deleted(&pool, user_ids[u], false).await,
        }
        model.apply(*op);

        let expected: BTreeSet<i32> = model.visible().iter().map(|&u| user_ids[u]).collect();
        let (count, members) = observed_state(&pool, &group.uuid, group.id).await;
        let observed: BTreeSet<i32> = members.iter().copied().collect();

        // Invariant 1: count and list agree with each other AND with
        // the model (no ghost members, no missing members).
        assert_eq!(
            count as usize,
            observed.len(),
            "member_count must equal the number of listed members after {op:?}"
        );
        assert_eq!(
            observed, expected,
            "listed members must be exactly the model's visible members after {op:?}"
        );

        // Invariant 2: no soft-deleted id ever leaks out of the IPC.
        for (u, id) in user_ids.iter().enumerate() {
            if model.deleted.contains(&u) {
                assert!(
                    !observed.contains(id),
                    "soft-deleted user {id} leaked out of ListGroupMembers after {op:?}"
                );
            }
        }
    }

    // Invariant 3: the delete guard accepts IFF the model says the
    // group has zero visible members (the "undeletable group" pin).
    let visible_now = model.visible().len();
    let resp = handle_access_request(
        &pool,
        AccessRequest::DeleteVaubanGroup {
            uuid: group.uuid.clone(),
        },
    )
    .await;
    match resp {
        AccessResponse::Deleted(Ok(())) => {
            assert_eq!(
                visible_now, 0,
                "delete must only succeed when the model sees zero visible members"
            );
            // Group already gone: only the users remain to clean up.
            use vauban_web::schema::{user_groups, users};
            let mut conn = pool.get().await.expect("conn");
            diesel::delete(user_groups::table.filter(user_groups::user_id.eq_any(&user_ids)))
                .execute(&mut conn)
                .await
                .expect("purge memberships");
            diesel::delete(users::table.filter(users::id.eq_any(&user_ids)))
                .execute(&mut conn)
                .await
                .expect("delete throwaway users");
        }
        AccessResponse::Deleted(Err(msg)) => {
            assert!(
                visible_now > 0,
                "delete refused ({msg}) although the model sees zero visible members \
                 -- the undeletable-group bug is back"
            );
            assert!(
                msg.contains("member"),
                "refusal must mention members so the UI shows the specific hint: {msg}"
            );
            cleanup(&pool, &group.uuid, &user_ids).await;
        }
        other => panic!("DeleteVaubanGroup unexpected response: {other:?}"),
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    /// Random bounded op sequences: the IPC-visible membership state
    /// always matches the in-memory model, and the delete guard
    /// decision matches the model's visible-member count.
    #[test]
    #[serial]
    fn membership_visibility_matches_model(
        ops in proptest::collection::vec(op_strategy(), 1..=10)
    ) {
        runtime().block_on(run_scenario(ops));
    }
}
