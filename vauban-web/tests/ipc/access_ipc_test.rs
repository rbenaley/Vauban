/// IPC integration tests for vauban-access via in-process pipe pair.
///
/// These tests verify that the AccessIpcClient correctly communicates
/// with the vauban-access handler through a real pipe pair, covering
/// CRUD operations for access rules, vauban groups, asset groups,
/// membership, and access evaluation.
use diesel::{ExpressionMethods, OptionalExtension, QueryDsl};
use diesel_async::RunQueryDsl;
use serial_test::serial;

use crate::common::TestApp;
use crate::fixtures::unique_name;

async fn ensure_test_user_exists() -> i32 {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    use vauban_web::schema::users;

    let existing: Option<i32> = users::table
        .filter(users::username.eq("ipc_test_user"))
        .select(users::id)
        .first::<i32>(&mut conn)
        .await
        .optional()
        .expect("query user");

    if let Some(id) = existing {
        return id;
    }

    use vauban_web::models::user::{AuthSource, NewUser};
    let user: vauban_web::models::user::User = diesel::insert_into(users::table)
        .values(NewUser {
            uuid: uuid::Uuid::new_v4(),
            username: "ipc_test_user".to_string(),
            email: "ipc_test@test.local".to_string(),
            password_hash: "not_used".to_string(),
            first_name: Some("IPC".to_string()),
            last_name: Some("Test".to_string()),
            phone: None,
            is_active: true,
            is_staff: false,
            is_superuser: false,
            is_service_account: false,
            mfa_enabled: false,
            mfa_enforced: false,
            mfa_secret: None,
            preferences: serde_json::json!({}),
            auth_source: AuthSource::Local,
            external_id: None,
        })
        .get_result(&mut conn)
        .await
        .expect("create ipc_test_user");
    user.id
}

// ==================== Vauban Groups CRUD via IPC ====================

#[tokio::test]
#[serial]
async fn test_ipc_create_and_get_vauban_group() {
    let app = TestApp::spawn().await;
    let client = app.access_ipc_client().await;

    let name = unique_name("ipc_vg");
    let group = client
        .create_vauban_group(&name, Some("IPC test group".to_string()))
        .await
        .expect("create vauban group");

    assert_eq!(group.name, name);
    assert!(group.id > 0);
    assert_eq!(group.member_count, 0);

    let fetched = client
        .get_vauban_group(&group.uuid)
        .await
        .expect("get vauban group");
    assert_eq!(fetched.name, name);
    assert_eq!(fetched.id, group.id);

    client
        .delete_vauban_group(&group.uuid)
        .await
        .expect("cleanup");
}

#[tokio::test]
#[serial]
async fn test_ipc_list_vauban_groups() {
    let app = TestApp::spawn().await;
    let client = app.access_ipc_client().await;

    let name = unique_name("ipc_vg_list");
    let group = client
        .create_vauban_group(&name, None)
        .await
        .expect("create group");

    let list = client.list_vauban_groups().await.expect("list groups");
    assert!(list.iter().any(|g| g.uuid == group.uuid));

    client
        .delete_vauban_group(&group.uuid)
        .await
        .expect("cleanup");
}

#[tokio::test]
#[serial]
async fn test_ipc_update_vauban_group() {
    let app = TestApp::spawn().await;
    let client = app.access_ipc_client().await;

    let name = unique_name("ipc_vg_upd");
    let group = client
        .create_vauban_group(&name, None)
        .await
        .expect("create");

    let new_name = unique_name("ipc_vg_upd2");
    let updated = client
        .update_vauban_group(&group.uuid, &new_name, Some("updated desc".to_string()))
        .await
        .expect("update");
    assert_eq!(updated.name, new_name);

    client
        .delete_vauban_group(&group.uuid)
        .await
        .expect("cleanup");
}

// ==================== Asset Groups CRUD via IPC ====================

#[tokio::test]
#[serial]
async fn test_ipc_create_and_get_asset_group() {
    let app = TestApp::spawn().await;
    let client = app.access_ipc_client().await;

    let name = unique_name("ipc_ag");
    let slug = name.to_lowercase().replace('_', "-");
    let group = client
        .create_asset_group(
            &name,
            &slug,
            Some("IPC test".to_string()),
            "#FF0000",
            "server",
            None,
        )
        .await
        .expect("create asset group");

    assert_eq!(group.name, name);
    assert_eq!(group.slug, slug);
    // Upper-case hex is accepted but persisted in its canonical
    // lower-case form (asset_groups_color_chk).
    assert_eq!(group.color, "#ff0000");
    assert_eq!(group.icon, "server");

    let fetched = client
        .get_asset_group(&group.uuid)
        .await
        .expect("get asset group");
    assert_eq!(fetched.name, name);

    client
        .delete_asset_group(&group.uuid)
        .await
        .expect("cleanup");
}

#[tokio::test]
#[serial]
async fn test_ipc_list_asset_groups() {
    let app = TestApp::spawn().await;
    let client = app.access_ipc_client().await;

    let name = unique_name("ipc_ag_list");
    let slug = name.to_lowercase().replace('_', "-");
    let group = client
        .create_asset_group(&name, &slug, None, "#000000", "folder", None)
        .await
        .expect("create");

    let list = client.list_asset_groups().await.expect("list");
    assert!(list.iter().any(|g| g.uuid == group.uuid));

    client
        .delete_asset_group(&group.uuid)
        .await
        .expect("cleanup");
}

// ==================== Access Rules CRUD via IPC ====================

#[tokio::test]
#[serial]
async fn test_ipc_create_and_get_access_rule() {
    let app = TestApp::spawn().await;
    let client = app.access_ipc_client().await;

    let ug_name = unique_name("ipc_ug_rule");
    let ag_name = unique_name("ipc_ag_rule");
    let ag_slug = ag_name.to_lowercase().replace('_', "-");

    let ug = client
        .create_vauban_group(&ug_name, None)
        .await
        .expect("create ug");
    let ag = client
        .create_asset_group(&ag_name, &ag_slug, None, "#123456", "folder", None)
        .await
        .expect("create ag");

    let data = shared::messages::AccessRuleData {
        name: unique_name("ipc_rule"),
        description: Some("IPC test rule".to_string()),
        user_group_id: ug.id,
        asset_group_id: ag.id,
        allowed_protocols: vec!["ssh".to_string()],
        valid_from: None,
        valid_until: None,
        require_mfa: false,
        require_approval: false,
        max_session_duration: None,
        is_active: true,
        priority: 10,
    };

    let rule = client
        .create_access_rule(data, None)
        .await
        .expect("create access rule");
    assert!(rule.is_active);
    assert_eq!(rule.priority, 10);
    assert_eq!(rule.user_group_id, ug.id);
    assert_eq!(rule.asset_group_id, ag.id);

    let fetched = client
        .get_access_rule(&rule.uuid)
        .await
        .expect("get access rule");
    assert_eq!(fetched.uuid, rule.uuid);

    let list = client.list_access_rules().await.expect("list access rules");
    assert!(list.iter().any(|r| r.uuid == rule.uuid));

    client
        .delete_access_rule(&rule.uuid)
        .await
        .expect("cleanup rule");
    client
        .delete_asset_group(&ag.uuid)
        .await
        .expect("cleanup ag");
    client
        .delete_vauban_group(&ug.uuid)
        .await
        .expect("cleanup ug");
}

// ==================== Membership via IPC ====================

#[tokio::test]
#[serial]
async fn test_ipc_group_membership() {
    let user_id = ensure_test_user_exists().await;
    let app = TestApp::spawn().await;
    let client = app.access_ipc_client().await;

    let name = unique_name("ipc_vg_mem");
    let group = client
        .create_vauban_group(&name, None)
        .await
        .expect("create group");

    client
        .add_group_member(group.id, user_id)
        .await
        .expect("add member");

    let members = client
        .list_group_members(group.id)
        .await
        .expect("list members");
    assert!(members.contains(&user_id));

    let refreshed = client
        .get_vauban_group(&group.uuid)
        .await
        .expect("get group");
    assert_eq!(refreshed.member_count, 1);

    client
        .remove_group_member(group.id, user_id)
        .await
        .expect("remove member");

    let members_after = client
        .list_group_members(group.id)
        .await
        .expect("list after remove");
    assert!(!members_after.contains(&user_id));

    client
        .delete_vauban_group(&group.uuid)
        .await
        .expect("cleanup");
}

// ==================== Access Evaluation via IPC ====================

#[tokio::test]
#[serial]
async fn test_ipc_check_access_denied_no_rule() {
    let app = TestApp::spawn().await;
    let client = app.access_ipc_client().await;

    let result = client
        .check_access(99999, 99999, "ssh")
        .await
        .expect("check access");
    assert!(!result.allowed);
}

#[tokio::test]
#[serial]
async fn test_ipc_check_access_allowed_and_protocol_filter() {
    let user_id = ensure_test_user_exists().await;
    let app = TestApp::spawn().await;
    let client = app.access_ipc_client().await;

    let ug_name = unique_name("ipc_ug_eval");
    let ag_name = unique_name("ipc_ag_eval");
    let ag_slug = ag_name.to_lowercase().replace('_', "-");

    let ug = client
        .create_vauban_group(&ug_name, None)
        .await
        .expect("create ug");
    let ag = client
        .create_asset_group(&ag_name, &ag_slug, None, "#000000", "server", None)
        .await
        .expect("create ag");

    client
        .add_group_member(ug.id, user_id)
        .await
        .expect("add member");

    let data = shared::messages::AccessRuleData {
        name: unique_name("ipc_eval_rule"),
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
    let rule = client
        .create_access_rule(data, None)
        .await
        .expect("create rule");

    let ssh_result = client
        .check_access(user_id, ag.id, "ssh")
        .await
        .expect("check ssh");
    assert!(ssh_result.allowed, "SSH should be allowed");

    let rdp_result = client
        .check_access(user_id, ag.id, "rdp")
        .await
        .expect("check rdp");
    assert!(!rdp_result.allowed, "RDP should be denied (SSH-only rule)");

    client.remove_group_member(ug.id, user_id).await.ok();
    client.delete_access_rule(&rule.uuid).await.ok();
    client.delete_asset_group(&ag.uuid).await.ok();
    client.delete_vauban_group(&ug.uuid).await.ok();
}

#[tokio::test]
#[serial]
async fn test_ipc_list_accessible_groups() {
    let user_id = ensure_test_user_exists().await;
    let app = TestApp::spawn().await;
    let client = app.access_ipc_client().await;

    let ug_name = unique_name("ipc_ug_lag");
    let ag_name = unique_name("ipc_ag_lag");
    let ag_slug = ag_name.to_lowercase().replace('_', "-");

    let ug = client
        .create_vauban_group(&ug_name, None)
        .await
        .expect("create ug");
    let ag = client
        .create_asset_group(&ag_name, &ag_slug, None, "#000000", "folder", None)
        .await
        .expect("create ag");

    client
        .add_group_member(ug.id, user_id)
        .await
        .expect("add member");

    let data = shared::messages::AccessRuleData {
        name: unique_name("ipc_lag_rule"),
        description: None,
        user_group_id: ug.id,
        asset_group_id: ag.id,
        allowed_protocols: vec!["ssh".to_string(), "rdp".to_string()],
        valid_from: None,
        valid_until: None,
        require_mfa: false,
        require_approval: false,
        max_session_duration: None,
        is_active: true,
        priority: 0,
    };
    let rule = client
        .create_access_rule(data, None)
        .await
        .expect("create rule");

    let groups = client
        .list_accessible_groups(user_id)
        .await
        .expect("list accessible");
    let entry = groups.iter().find(|e| e.asset_group_id == ag.id);
    assert!(entry.is_some(), "Should find the accessible group");
    let entry = entry.unwrap();
    assert!(entry.protocols.contains(&"ssh".to_string()));
    assert!(entry.protocols.contains(&"rdp".to_string()));

    client.remove_group_member(ug.id, user_id).await.ok();
    client.delete_access_rule(&rule.uuid).await.ok();
    client.delete_asset_group(&ag.uuid).await.ok();
    client.delete_vauban_group(&ug.uuid).await.ok();
}

// ==================== Group Options via IPC ====================

#[tokio::test]
#[serial]
async fn test_ipc_get_group_options() {
    let app = TestApp::spawn().await;
    let client = app.access_ipc_client().await;

    let ug_name = unique_name("ipc_ug_opts");
    let ag_name = unique_name("ipc_ag_opts");
    let ag_slug = ag_name.to_lowercase().replace('_', "-");

    let ug = client
        .create_vauban_group(&ug_name, None)
        .await
        .expect("create ug");
    let ag = client
        .create_asset_group(&ag_name, &ag_slug, None, "#000000", "folder", None)
        .await
        .expect("create ag");

    let (user_groups, asset_groups) = client.get_group_options().await.expect("get options");
    assert!(user_groups.iter().any(|g| g.id == ug.id));
    assert!(asset_groups.iter().any(|g| g.id == ag.id));

    client.delete_asset_group(&ag.uuid).await.ok();
    client.delete_vauban_group(&ug.uuid).await.ok();
}

// ==================== Ghost members (soft-deleted users) ====================
//
// July 2026 incident: soft-deleting a user left its user_groups rows in
// place, so the raw member count diverged from the (filtered) member
// list and groups whose members were all deleted became undeletable.
// These tests pin the fixed read seam (visible_member_count) end-to-end
// through the IPC.

/// Create a fresh throwaway user (unique username) and return its id.
async fn create_fresh_user(app: &TestApp, prefix: &str) -> i32 {
    use vauban_web::models::user::{AuthSource, NewUser};
    use vauban_web::schema::users;

    let mut conn = app.get_conn().await;
    let name = unique_name(prefix);
    let user: vauban_web::models::user::User = diesel::insert_into(users::table)
        .values(NewUser {
            uuid: uuid::Uuid::new_v4(),
            username: name.clone(),
            email: format!("{}@test.local", name),
            password_hash: "not_used".to_string(),
            first_name: None,
            last_name: None,
            phone: None,
            is_active: true,
            is_staff: false,
            is_superuser: false,
            is_service_account: false,
            mfa_enabled: false,
            mfa_enforced: false,
            mfa_secret: None,
            preferences: serde_json::json!({}),
            auth_source: AuthSource::Local,
            external_id: None,
        })
        .get_result(&mut conn)
        .await
        .expect("create fresh user");
    user.id
}

/// Soft-delete a user directly in the DB WITHOUT purging user_groups,
/// simulating the pre-fix orphan rows found in production.
async fn soft_delete_user_raw(app: &TestApp, user_id: i32) {
    use vauban_web::schema::users;

    let mut conn = app.get_conn().await;
    diesel::update(users::table.filter(users::id.eq(user_id)))
        .set((
            users::is_deleted.eq(true),
            users::deleted_at.eq(chrono::Utc::now()),
        ))
        .execute(&mut conn)
        .await
        .expect("soft-delete user");
}

#[tokio::test]
#[serial]
async fn test_ipc_soft_deleted_member_is_invisible_and_group_deletable() {
    let app = TestApp::spawn().await;
    let client = app.access_ipc_client().await;

    let group = client
        .create_vauban_group(&unique_name("ipc_vg_ghost"), None)
        .await
        .expect("create group");
    let user_id = create_fresh_user(app, "ipc_ghost_user").await;

    client
        .add_group_member(group.id, user_id)
        .await
        .expect("add member");
    assert_eq!(
        client
            .get_vauban_group(&group.uuid)
            .await
            .expect("get group")
            .member_count,
        1
    );

    // Orphan the membership: soft-delete the user without purging
    // user_groups (pre-fix behaviour / pre-migration database state).
    soft_delete_user_raw(app, user_id).await;

    let refreshed = client
        .get_vauban_group(&group.uuid)
        .await
        .expect("get group after soft-delete");
    assert_eq!(
        refreshed.member_count, 0,
        "member_count must ignore soft-deleted users"
    );

    let members = client
        .list_group_members(group.id)
        .await
        .expect("list members");
    assert!(
        !members.contains(&user_id),
        "list_group_members must not return soft-deleted user ids"
    );

    // The bug made such groups undeletable: the delete guard counted
    // the raw rows. It must now succeed.
    client
        .delete_vauban_group(&group.uuid)
        .await
        .expect("group whose only member was soft-deleted must be deletable");
}

#[tokio::test]
#[serial]
async fn test_ipc_manually_inserted_orphan_row_is_ignored() {
    let app = TestApp::spawn().await;
    let client = app.access_ipc_client().await;

    let group = client
        .create_vauban_group(&unique_name("ipc_vg_orphan"), None)
        .await
        .expect("create group");

    // User soft-deleted FIRST, membership row inserted afterwards by
    // hand: proves the read layer alone, independently of the
    // write-path purge and of the cleanup migration.
    let user_id = create_fresh_user(app, "ipc_orphan_user").await;
    soft_delete_user_raw(app, user_id).await;
    {
        use vauban_web::schema::user_groups;
        let mut conn = app.get_conn().await;
        diesel::insert_into(user_groups::table)
            .values((
                user_groups::user_id.eq(user_id),
                user_groups::group_id.eq(group.id),
            ))
            .execute(&mut conn)
            .await
            .expect("insert orphan membership row");
    }

    assert_eq!(
        client
            .get_vauban_group(&group.uuid)
            .await
            .expect("get group")
            .member_count,
        0,
        "an orphan membership row must not be counted"
    );
    assert!(
        !client
            .list_group_members(group.id)
            .await
            .expect("list members")
            .contains(&user_id)
    );
    client
        .delete_vauban_group(&group.uuid)
        .await
        .expect("delete group with only an orphan row");
}

#[tokio::test]
#[serial]
async fn test_ipc_mixed_active_and_deleted_members_counts_active_only() {
    let app = TestApp::spawn().await;
    let client = app.access_ipc_client().await;

    let group = client
        .create_vauban_group(&unique_name("ipc_vg_mixed"), None)
        .await
        .expect("create group");
    let active_id = create_fresh_user(app, "ipc_mixed_active").await;
    let deleted_id = create_fresh_user(app, "ipc_mixed_deleted").await;

    client
        .add_group_member(group.id, active_id)
        .await
        .expect("add active");
    client
        .add_group_member(group.id, deleted_id)
        .await
        .expect("add soon-deleted");
    soft_delete_user_raw(app, deleted_id).await;

    // Production "Administrators" case: 1 active + 1 deleted => 1.
    assert_eq!(
        client
            .get_vauban_group(&group.uuid)
            .await
            .expect("get group")
            .member_count,
        1
    );
    let members = client
        .list_group_members(group.id)
        .await
        .expect("list members");
    assert!(members.contains(&active_id));
    assert!(!members.contains(&deleted_id));

    client
        .remove_group_member(group.id, active_id)
        .await
        .expect("remove active");
    client
        .delete_vauban_group(&group.uuid)
        .await
        .expect("cleanup group");
}
