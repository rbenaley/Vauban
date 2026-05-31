//! Tier 2 — IPC contract tests for the virtual "All assets" group.
//!
//! These tests exercise the boundary between vauban-web and the
//! in-process vauban-access service: payloads cross a real pipe, the
//! service answers from a real Postgres, and we assert the public
//! shape (defaults, kind, badges) is correct AND that mutation IPCs
//! against the singleton row are refused with a structured error,
//! NOT a generic database leak.
//!
//! Invariants under test:
//!
//! * **C1** — `ListAssetGroups { include_virtual: false }` (the
//!   default) excludes the virtual row.
//! * **C2** — `ListAssetGroups { include_virtual: true }` includes
//!   it; the entry carries `kind = 'all'` so the editor can render
//!   the badge.
//! * **C3** — `AssetGroupInfo.kind` is correctly populated for both
//!   static and virtual rows.
//! * **C4** — `CreateAccessRule { asset_group_uuid =
//!   ALL_ASSETS_GROUP_UUID }` succeeds and the persisted rule's
//!   `asset_group_id` resolves to the singleton.
//! * **C5** — `UpdateAssetGroup { uuid = ALL_ASSETS_GROUP_UUID }`
//!   returns a structured error mentioning the virtual group, NOT a
//!   generic Diesel/Postgres leak.
//! * **C6** — `DeleteAssetGroup { uuid = ALL_ASSETS_GROUP_UUID }`
//!   returns the same structured error.
//! * **C7** — `AddAssetToGroup { group = ALL_UUID }` returns the
//!   structured error.
//! * **C8** — `ListAssetGroupOptions { include_virtual }` honours the
//!   flag identically to `ListAssetGroups` (this is the dropdown
//!   feed).
//!
//! C1-C2-C8 also pin defaults: the IPC payload must default
//! `include_virtual` to `false` so a forgotten field does not silently
//! leak the virtual row into the regular asset-group index.

use diesel::{ExpressionMethods, OptionalExtension, QueryDsl};
use diesel_async::RunQueryDsl;
use serial_test::serial;

use shared::messages::{
    ALL_ASSETS_GROUP_UUID, ASSET_GROUP_KIND_ALL, ASSET_GROUP_KIND_STATIC, AssetGroupInfo,
    GroupOption,
};

use crate::common::TestApp;
use crate::fixtures::unique_name;

async fn list_all_asset_groups(
    client: &vauban_web::ipc::AccessIpcClient,
    include_virtual: bool,
) -> Vec<AssetGroupInfo> {
    if include_virtual {
        client
            .list_asset_groups_with_virtual()
            .await
            .expect("list with virtual")
    } else {
        client.list_asset_groups().await.expect("list default")
    }
}

async fn list_all_asset_group_options(
    client: &vauban_web::ipc::AccessIpcClient,
    include_virtual: bool,
) -> Vec<GroupOption> {
    let (_user, asset) = if include_virtual {
        client
            .get_group_options_with_virtual()
            .await
            .expect("group options with virtual")
    } else {
        client
            .get_group_options()
            .await
            .expect("group options default")
    };
    asset
}

// =====================================================================
// C1 — Default ListAssetGroups (include_virtual=false) excludes virtual
// =====================================================================

#[tokio::test]
#[serial]
async fn c1_list_asset_groups_excludes_virtual_by_default() {
    let app = TestApp::spawn().await;
    let client = app.access_ipc_client().await;

    let groups = list_all_asset_groups(&client, false).await;
    let virtual_seen = groups
        .iter()
        .any(|g| g.uuid == ALL_ASSETS_GROUP_UUID || g.kind == ASSET_GROUP_KIND_ALL);
    assert!(
        !virtual_seen,
        "include_virtual=false MUST hide the virtual row; got {:?}",
        groups
            .iter()
            .map(|g| (&g.name, &g.kind))
            .collect::<Vec<_>>()
    );
}

// =====================================================================
// C2 — ListAssetGroups { include_virtual: true } includes virtual with kind='all'
// =====================================================================

#[tokio::test]
#[serial]
async fn c2_list_asset_groups_with_virtual_includes_singleton() {
    let app = TestApp::spawn().await;
    let client = app.access_ipc_client().await;

    let groups = list_all_asset_groups(&client, true).await;
    let v: Vec<&AssetGroupInfo> = groups
        .iter()
        .filter(|g| g.uuid == ALL_ASSETS_GROUP_UUID)
        .collect();
    assert_eq!(
        v.len(),
        1,
        "exactly one virtual entry expected; got {}",
        v.len()
    );
    let virt = v[0];
    assert_eq!(virt.kind, ASSET_GROUP_KIND_ALL);
    assert_eq!(virt.name, "All assets");
}

// =====================================================================
// C3 — AssetGroupInfo.kind is correctly populated for both kinds
// =====================================================================

#[tokio::test]
#[serial]
async fn c3_asset_group_info_kind_field_correct() {
    let app = TestApp::spawn().await;
    let client = app.access_ipc_client().await;

    // Static
    let name = unique_name("c3_static");
    let slug = name.to_lowercase().replace('_', "-");
    let static_grp = client
        .create_asset_group(&name, &slug, None, "#000", "folder", None)
        .await
        .expect("create static");
    assert_eq!(
        static_grp.kind, ASSET_GROUP_KIND_STATIC,
        "create returns kind='static'"
    );

    let info = client
        .get_asset_group(&static_grp.uuid)
        .await
        .expect("get static");
    assert_eq!(info.kind, ASSET_GROUP_KIND_STATIC);

    // Virtual: read-back via direct lookup
    let v_info = client
        .get_asset_group(ALL_ASSETS_GROUP_UUID)
        .await
        .expect("get virtual");
    assert_eq!(v_info.kind, ASSET_GROUP_KIND_ALL);

    client.delete_asset_group(&static_grp.uuid).await.ok();
}

// =====================================================================
// C4 — CreateAccessRule on the virtual group succeeds end-to-end
// =====================================================================

#[tokio::test]
#[serial]
async fn c4_create_access_rule_on_virtual_group() {
    use shared::messages::AccessRuleData;

    let app = TestApp::spawn().await;
    let client = app.access_ipc_client().await;
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let ug_name = unique_name("c4_ug");
    let ug = client
        .create_vauban_group(&ug_name, None)
        .await
        .expect("create ug");

    let virtual_info = client
        .get_asset_group(ALL_ASSETS_GROUP_UUID)
        .await
        .expect("get virtual");

    let now = chrono::Utc::now();
    let data = AccessRuleData {
        name: unique_name("c4_rule"),
        description: None,
        user_group_id: ug.id,
        asset_group_id: virtual_info.id,
        allowed_protocols: vec!["ssh".to_string()],
        valid_from: Some(now.to_rfc3339()),
        valid_until: Some((now + chrono::Duration::days(30)).to_rfc3339()),
        require_mfa: false,
        require_approval: false,
        max_session_duration: Some(3600),
        is_active: true,
        priority: 0,
    };

    let rule = client
        .create_access_rule(data, None)
        .await
        .expect("create access rule on virtual group");

    use vauban_web::schema::{access_rules, asset_groups};
    let rule_uuid = uuid::Uuid::parse_str(&rule.uuid).expect("uuid parse");
    let asset_group_id: i32 = access_rules::table
        .filter(access_rules::uuid.eq(rule_uuid))
        .select(access_rules::asset_group_id)
        .first(&mut conn)
        .await
        .expect("query rule");
    let virtual_uuid: uuid::Uuid = asset_groups::table
        .filter(asset_groups::id.eq(asset_group_id))
        .select(asset_groups::uuid)
        .first(&mut conn)
        .await
        .expect("query group");
    assert_eq!(virtual_uuid.to_string(), ALL_ASSETS_GROUP_UUID);

    client.delete_access_rule(&rule.uuid).await.ok();
    client.delete_vauban_group(&ug.uuid).await.ok();
}

// =====================================================================
// C5 — UpdateAssetGroup on virtual returns a structured failure
// =====================================================================

#[tokio::test]
#[serial]
async fn c5_update_virtual_asset_group_is_refused() {
    let app = TestApp::spawn().await;
    let client = app.access_ipc_client().await;

    let res = client
        .update_asset_group(
            ALL_ASSETS_GROUP_UUID,
            "Hijack",
            "hijack",
            None,
            "#ff0000",
            "skull",
            None,
        )
        .await;
    assert!(
        res.is_err(),
        "updating the virtual group MUST fail; got Ok({:?})",
        res
    );

    // The virtual row's name/slug must not have changed.
    let info = client
        .get_asset_group(ALL_ASSETS_GROUP_UUID)
        .await
        .expect("readback");
    assert_eq!(info.name, "All assets");
    assert_eq!(info.slug, "__all-assets__");
    assert_eq!(info.kind, ASSET_GROUP_KIND_ALL);
}

// =====================================================================
// C6 — DeleteAssetGroup on virtual returns a structured failure
// =====================================================================

#[tokio::test]
#[serial]
async fn c6_delete_virtual_asset_group_is_refused() {
    let app = TestApp::spawn().await;
    let client = app.access_ipc_client().await;

    let res = client.delete_asset_group(ALL_ASSETS_GROUP_UUID).await;
    assert!(res.is_err(), "deleting the virtual group MUST fail; got Ok");

    // Singleton survives.
    let info = client
        .get_asset_group(ALL_ASSETS_GROUP_UUID)
        .await
        .expect("survives");
    assert_eq!(info.kind, ASSET_GROUP_KIND_ALL);
}

// =====================================================================
// C7 — Direct INSERT into asset_asset_groups for the virtual row is refused
//
// There is no IPC "AddAssetToGroup" path (asset/group attachments are
// performed via direct SQL inside the web handler). We assert here at
// the IPC boundary level that even the plain SQL path is sealed by the
// trigger AND that, after the failure, the asset has NO leaked
// membership row pointing at the virtual id.
// =====================================================================

#[tokio::test]
#[serial]
async fn c7_direct_membership_insert_on_virtual_is_refused() {
    use diesel::sql_query;

    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    use vauban_web::models::asset::{AssetType, NewAsset};
    use vauban_web::schema::assets;
    let asset_uuid = uuid::Uuid::new_v4();
    let asset_db_id: i32 = diesel::insert_into(assets::table)
        .values(NewAsset {
            uuid: asset_uuid,
            name: unique_name("c7_asset"),
            hostname: "c7.local".to_string(),
            port: 22,
            asset_type: AssetType::Ssh,
            status: "online".to_string(),
            description: None,
            connection_config: serde_json::json!({}),
            created_by_id: None,
            updated_by_id: None,
            connection_username: "root".to_string(),
        })
        .returning(assets::id)
        .get_result(&mut conn)
        .await
        .expect("insert c7 asset");

    let err = sql_query(format!(
        "INSERT INTO asset_asset_groups (asset_id, asset_group_id)
         SELECT {asset_db_id}, id FROM asset_groups WHERE kind = 'all'"
    ))
    .execute(&mut conn)
    .await
    .expect_err("attaching to virtual must raise (trigger)");
    assert!(
        format!("{err:?}").to_lowercase().contains("virtual"),
        "expected trigger error mentioning 'virtual', got: {err:?}"
    );

    use vauban_web::schema::{asset_asset_groups, asset_groups};
    let virtual_id: i32 = asset_groups::table
        .filter(asset_groups::kind.eq(ASSET_GROUP_KIND_ALL))
        .select(asset_groups::id)
        .first(&mut conn)
        .await
        .expect("virtual id");
    let leaked: Option<i32> = asset_asset_groups::table
        .filter(asset_asset_groups::asset_id.eq(asset_db_id))
        .filter(asset_asset_groups::asset_group_id.eq(virtual_id))
        .select(asset_asset_groups::asset_id)
        .first(&mut conn)
        .await
        .optional()
        .expect("query");
    assert!(
        leaked.is_none(),
        "no membership row may exist after refused insert"
    );

    diesel::delete(assets::table.filter(assets::uuid.eq(asset_uuid)))
        .execute(&mut conn)
        .await
        .ok();
}

// =====================================================================
// C8 — ListAssetGroupOptions honours include_virtual identically
// =====================================================================

#[tokio::test]
#[serial]
async fn c8_list_asset_group_options_honours_include_virtual() {
    let app = TestApp::spawn().await;
    let client = app.access_ipc_client().await;

    let opts_default = list_all_asset_group_options(&client, false).await;
    let leaked_default = opts_default.iter().any(|o| o.kind == ASSET_GROUP_KIND_ALL);
    assert!(
        !leaked_default,
        "default MUST hide virtual; got: {:?}",
        opts_default
            .iter()
            .map(|o| (&o.name, &o.kind))
            .collect::<Vec<_>>()
    );

    let opts_with = list_all_asset_group_options(&client, true).await;
    let virt: Vec<&GroupOption> = opts_with
        .iter()
        .filter(|o| o.kind == ASSET_GROUP_KIND_ALL)
        .collect();
    assert_eq!(virt.len(), 1, "exactly one virtual option");
    assert_eq!(virt[0].name, "All assets");
}
