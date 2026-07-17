//! Issue #27 — anti-enumeration pin for the `/assets/manage/*`
//! admin sub-tree.
//!
//! `require_assets_manage` lives at the routing layer (a
//! `route_layer` on the `Router::nest`) precisely so denials
//! happen BEFORE any handler is reached and BEFORE any DB lookup
//! is performed. A `role:user` poking
//! `/assets/manage/{random-uuid}` MUST receive a stable 403 for
//! every UUID — whether the asset exists or not, whether the
//! caller has an access rule on it or not. Otherwise the URL
//! becomes an oracle for asset existence (a 403 vs 404 differential
//! would let an attacker enumerate assets they cannot otherwise
//! see).
//!
//! We seed real assets in the database, then probe both real and
//! random UUIDs as a regular user. Every status code MUST be 403
//! and every body MUST be byte-identical so even a content-length
//! oracle cannot leak.

use axum::http::header::{self, COOKIE};
use serial_test::serial;
use uuid::Uuid;

use crate::common::{TestApp, assertions::assert_status};
use crate::fixtures::{create_test_ssh_asset, create_test_user, unique_name};

/// Probe `/assets/manage/{uuid}` (and `/edit`, `/delete`) with a
/// regular user. Status MUST be 403 for both an existing asset
/// and a synthetic UUID; the bodies MUST match byte-for-byte so
/// the only signal an attacker gets is "you are not authorised".
#[tokio::test]
#[serial]
async fn web_admin_routes_do_not_leak_asset_existence() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Seed a real asset so the existence-vs-not-found differential
    // would actually have something to differentiate.
    let real = create_test_ssh_asset(&mut conn, &unique_name("anti_enum_seed")).await;
    let random = Uuid::new_v4();

    let user_name = unique_name("anti_enum_user");
    let user = create_test_user(&mut conn, &app.auth_service, &user_name).await;

    let probes = [
        format!("/assets/manage/{}", real.asset.uuid),
        format!("/assets/manage/{}", random),
        format!("/assets/manage/{}/edit", real.asset.uuid),
        format!("/assets/manage/{}/edit", random),
    ];

    let mut bodies: Vec<(String, String)> = Vec::with_capacity(probes.len());
    for url in probes {
        let resp = app
            .server
            .get(&url)
            .add_header(COOKIE, format!("access_token={}", user.token))
            .await;
        assert_status(&resp, 403);
        bodies.push((url, resp.text()));
    }

    let baseline = &bodies[0].1;
    for (url, body) in &bodies[1..] {
        assert_eq!(
            body, baseline,
            "{}: anti-enumeration leak — body differs from the baseline 403 response. \
             A `role:user` could distinguish 'asset exists' from 'asset does not \
             exist' by the body length / content. The route_layer middleware MUST \
             return the same response shape for every denied call.",
            url
        );
    }
}

/// Same anti-enumeration contract for the API admin sub-tree.
/// Every JSON response MUST carry the same payload (no UUID echo,
/// no asset name, no resource-existence flag).
#[tokio::test]
#[serial]
async fn api_admin_routes_do_not_leak_asset_existence() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let real = create_test_ssh_asset(&mut conn, &unique_name("anti_enum_api_seed")).await;
    let random = Uuid::new_v4();

    let user_name = unique_name("anti_enum_api_user");
    let user = create_test_user(&mut conn, &app.auth_service, &user_name).await;

    let probes = [
        format!("/api/v1/assets/manage/{}", real.asset.uuid),
        format!("/api/v1/assets/manage/{}", random),
        format!("/api/v1/assets/manage/{}/ssh-host-key", real.asset.uuid),
        format!("/api/v1/assets/manage/{}/ssh-host-key", random),
    ];

    let mut bodies: Vec<(String, String)> = Vec::with_capacity(probes.len());
    for url in probes {
        let resp = app
            .server
            .get(&url)
            .add_header(header::AUTHORIZATION, app.api_key_header(&user.api_key))
            .await;
        assert_status(&resp, 403);
        bodies.push((url, resp.text()));
    }

    let baseline = &bodies[0].1;
    for (url, body) in &bodies[1..] {
        assert_eq!(
            body, baseline,
            "{}: anti-enumeration leak in API JSON response — should match the \
             baseline 403 body byte-for-byte (no UUID echo, no resource hint).",
            url
        );
    }
}

/// BAC hardening: same anti-enumeration contract for the asset
/// groups sub-tree (`/assets/manage/groups/{uuid}`). Before the
/// move, `GET /assets/groups/{uuid}` was reachable by ANY
/// authenticated user and rendered every asset of the group (the
/// production information-disclosure this hardening fixes). Now a
/// `role:user` MUST receive one stable 403 whether the group
/// exists or not.
#[tokio::test]
#[serial]
async fn web_asset_group_routes_do_not_leak_group_existence() {
    use crate::fixtures::create_test_asset_group;

    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let real = create_test_asset_group(&mut conn, &unique_name("anti-enum-grp")).await;
    let random = Uuid::new_v4();

    let user_name = unique_name("anti_enum_grp_user");
    let user = create_test_user(&mut conn, &app.auth_service, &user_name).await;

    let probes = [
        "/assets/manage/groups".to_string(),
        format!("/assets/manage/groups/{}", real),
        format!("/assets/manage/groups/{}", random),
        format!("/assets/manage/groups/{}/edit", real),
        format!("/assets/manage/groups/{}/edit", random),
        format!("/assets/manage/groups/{}/add-asset", real),
        format!("/assets/manage/groups/{}/add-asset", random),
    ];

    let mut bodies: Vec<(String, String)> = Vec::with_capacity(probes.len());
    for url in probes {
        let resp = app
            .server
            .get(&url)
            .add_header(COOKIE, format!("access_token={}", user.token))
            .await;
        assert_status(&resp, 403);
        bodies.push((url, resp.text()));
    }

    let baseline = &bodies[0].1;
    for (url, body) in &bodies[1..] {
        assert_eq!(
            body, baseline,
            "{}: anti-enumeration leak — a `role:user` could distinguish \
             'group exists' from 'group does not exist' by the response \
             body. The route_layer middleware MUST return one stable \
             403 shape for the whole sub-tree.",
            url
        );
    }
}

/// `POST /assets/manage/{uuid}/delete` MUST also return 403 for
/// `role:user` regardless of whether the asset exists. This is a
/// destructive verb so the leak would be especially harmful: a
/// 404 differential here would let an attacker confirm that an
/// asset exists right before someone else (a legitimate admin)
/// deletes it.
#[tokio::test]
#[serial]
async fn web_delete_action_does_not_leak_existence() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let real = create_test_ssh_asset(&mut conn, &unique_name("anti_enum_del_seed")).await;
    let random = Uuid::new_v4();

    let user_name = unique_name("anti_enum_del_user");
    let user = create_test_user(&mut conn, &app.auth_service, &user_name).await;

    for uuid in [real.asset.uuid.to_string(), random.to_string()] {
        let resp = app
            .server
            .post(&format!("/assets/manage/{}/delete", uuid))
            .add_header(COOKIE, format!("access_token={}", user.token))
            .await;
        assert_status(&resp, 403);
    }
}
