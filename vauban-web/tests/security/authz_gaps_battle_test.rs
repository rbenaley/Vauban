//! Contention tests for the three authorization fences closed by
//! `docs/remediation/authz_shadowing_and_api_gaps.md`.
//!
//! Each `battle_*` test releases a burst of concurrent requests behind a
//! `Barrier` and asserts that the fence holds for every one of them and
//! that the protected row is byte-for-byte unchanged afterward.

use std::sync::Arc;

use axum::http::header;
use serde_json::json;
use serial_test::serial;
use tokio::sync::Barrier;
use tokio::task::JoinSet;

use super::authz_gaps_e2e_test::{
    created_uuid, grant_with_approval, post_session, session_liveness, stored_request, user_row,
    ws_get,
};
use crate::common::{TestApp, unwrap_ok};
use crate::fixtures::{
    create_admin_user, create_simple_rdp_asset, create_simple_ssh_asset, create_staff_only_user,
    create_test_session_with_access, create_test_user, get_asset_uuid, unique_name,
};

const BURST: usize = 16;

/// A burst of supervisors hammers both interactive routes of two live
/// sessions. Every probe is refused and neither session row moves.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn battle_supervisor_flood_on_data_plane_is_rejected() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let owner = create_test_user(&mut conn, &app.auth_service, &unique_name("azb_own1")).await;
    let staff =
        create_staff_only_user(&mut conn, &app.auth_service, &unique_name("azb_staff1")).await;
    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("azb_adm1")).await;
    let ssh_asset =
        create_simple_ssh_asset(&mut conn, &unique_name("azb-asset1s"), owner.user.id).await;
    let rdp_asset =
        create_simple_rdp_asset(&mut conn, &unique_name("azb-asset1r"), owner.user.id).await;
    let (_i, ssh_session, _r) =
        create_test_session_with_access(&mut conn, owner.user.id, ssh_asset, "ssh", "active").await;
    let (_i, rdp_session, _r) =
        create_test_session_with_access(&mut conn, owner.user.id, rdp_asset, "rdp", "active").await;
    let ssh_before = session_liveness(&mut conn, ssh_session).await;
    let rdp_before = session_liveness(&mut conn, rdp_session).await;
    drop(conn);

    let barrier = Arc::new(Barrier::new(BURST));
    let mut set = JoinSet::new();
    for i in 0..BURST {
        let barrier = Arc::clone(&barrier);
        let token = if i % 2 == 0 {
            staff.token.clone()
        } else {
            admin.token.clone()
        };
        let path = if i % 4 < 2 {
            format!("/ws/terminal/{ssh_session}")
        } else {
            format!("/ws/rdp/{rdp_session}")
        };
        set.spawn(async move {
            barrier.wait().await;
            (path.clone(), ws_get(app, &path, &token).await)
        });
    }
    while let Some(joined) = set.join_next().await {
        let (path, status) = unwrap_ok!(joined);
        assert_eq!(status, 404, "non-owner probe on {path} must be refused");
    }

    let mut conn = app.get_conn().await;
    assert_eq!(session_liveness(&mut conn, ssh_session).await, ssh_before);
    assert_eq!(session_liveness(&mut conn, rdp_session).await, rdp_before);
}

/// A burst of staff calls tries to deactivate and re-address the same
/// superuser. Every call is refused and the row is unchanged.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn battle_staff_flood_on_superuser_account_is_rejected() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let staff =
        create_staff_only_user(&mut conn, &app.auth_service, &unique_name("azb_staff2")).await;
    let target = create_admin_user(&mut conn, &app.auth_service, &unique_name("azb_sup2")).await;
    let before = user_row(&mut conn, target.user.id).await;
    drop(conn);

    let barrier = Arc::new(Barrier::new(BURST));
    let mut set = JoinSet::new();
    for i in 0..BURST {
        let barrier = Arc::clone(&barrier);
        let api_key = staff.api_key.clone();
        let target_uuid = target.user.uuid;
        let body = if i % 2 == 0 {
            json!({ "is_active": false })
        } else {
            json!({ "email": format!("hijack{i}@attacker.test") })
        };
        set.spawn(async move {
            barrier.wait().await;
            app.server
                .put(&format!("/api/v1/accounts/{target_uuid}"))
                .add_header(header::AUTHORIZATION, app.api_key_header(&api_key))
                .json(&body)
                .await
                .status_code()
                .as_u16()
        });
    }
    while let Some(joined) = set.join_next().await {
        assert_eq!(unwrap_ok!(joined), 403, "every staff call must be refused");
    }

    let mut conn = app.get_conn().await;
    assert_eq!(user_row(&mut conn, target.user.id).await, before);
}

/// A burst of API requests on the same asset: every stored row carries
/// the rule's duration cap and the credential placeholder, none slips
/// through unbounded under contention.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn battle_concurrent_api_requests_are_all_bounded() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user = create_test_user(&mut conn, &app.auth_service, &unique_name("azb_req3")).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("azb-asset3"), user.user.id).await;
    let asset_uuid = get_asset_uuid(&mut conn, asset_id).await;
    grant_with_approval(&mut conn, user.user.id, asset_id, Some(1200)).await;
    drop(conn);

    let barrier = Arc::new(Barrier::new(BURST));
    let mut set = JoinSet::new();
    for i in 0..BURST {
        let barrier = Arc::clone(&barrier);
        let api_key = user.api_key.clone();
        set.spawn(async move {
            barrier.wait().await;
            let response = post_session(
                app,
                &api_key,
                json!({
                    "asset_id": asset_uuid,
                    "session_type": "ssh",
                    "credential_id": format!("smuggled-{i}"),
                    "justification": format!("Concurrent maintenance request number {i}")
                }),
            )
            .await;
            assert_eq!(
                response.status_code().as_u16(),
                200,
                "request {i} must be recorded: {}",
                response.text()
            );
            created_uuid(&response)
        });
    }
    let mut created = Vec::with_capacity(BURST);
    while let Some(joined) = set.join_next().await {
        created.push(unwrap_ok!(joined));
    }
    assert_eq!(created.len(), BURST);

    let mut conn = app.get_conn().await;
    for session_uuid in created {
        let stored = stored_request(&mut conn, session_uuid).await;
        assert_eq!(stored.status, "pending");
        assert_eq!(stored.credential_id, "pending");
        assert_eq!(stored.credential_username, "pending");
        assert_eq!(stored.max_session_duration, Some(1200));
    }
}
