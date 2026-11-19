//! E2E -- "Require approval" on an access rule applies to IACS tunnels.
//!
//! Until 0.9.60 `POST /assets/{uuid}/connect-iacs` did not read the
//! `require_approval` flag `vauban-access` returns: a tunnel opened
//! without any approval. These tests drive the production handler, with
//! the in-process `vauban-access`, against rules that require one.

use crate::common::{TestApp, unwrap_ok};
use crate::fixtures::{
    add_user_to_vauban_group, create_simple_admin_user, create_simple_user,
    create_test_access_rule_with_constraints, create_test_asset_group,
    create_test_asset_in_group_with_type, create_test_vauban_group, unique_name,
};
use axum::http::header::COOKIE;
use chrono::{Duration, Utc};
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use vauban_web::models::asset::AssetType;
use vauban_web::models::session::{NewProxySession, SessionType};
use vauban_web::schema::proxy_sessions;

const JUSTIFICATION: &str = "Planned maintenance of the PLC, ticket 4812";

struct Scene {
    username: String,
    user_id: i32,
    user_uuid: Uuid,
    asset_id: i32,
    asset_uuid: Uuid,
    ews_uuid: Uuid,
}

async fn seed_active_ews(conn: &mut AsyncPgConnection, user_id: i32, label: &str) -> Uuid {
    let key_seed = Sha256::digest(format!("{}-{}", label, Uuid::new_v4()).as_bytes());
    let fp_hex = hex::encode(key_seed);
    let request_uuid = Uuid::new_v4();
    let ews_uuid = Uuid::new_v4();
    let now = Utc::now();

    diesel::sql_query(
        "INSERT INTO ews_onboarding_requests \
         (uuid, user_id, name, public_key, public_key_fingerprint, key_algo, \
          status, justification, decided_by_id, decided_at, created_at, updated_at) \
         VALUES ($1, $2, $3, 'ssh-ed25519 placeholder', $4, 'ed25519', \
                 'approved', 'seed-justification', $2, $5, $5, $5)",
    )
    .bind::<diesel::sql_types::Uuid, _>(request_uuid)
    .bind::<diesel::sql_types::Integer, _>(user_id)
    .bind::<diesel::sql_types::Text, _>(format!("ews_{}", &request_uuid.to_string()[..8]))
    .bind::<diesel::sql_types::Text, _>(&fp_hex)
    .bind::<diesel::sql_types::Timestamptz, _>(now)
    .execute(conn)
    .await
    .expect("insert seed ews_onboarding_requests");

    diesel::sql_query(
        "INSERT INTO ews \
         (uuid, request_uuid, user_id, name, public_key, public_key_fingerprint, \
          key_algo, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, 'ssh-ed25519 placeholder', $5, 'ed25519', $6, $6)",
    )
    .bind::<diesel::sql_types::Uuid, _>(ews_uuid)
    .bind::<diesel::sql_types::Uuid, _>(request_uuid)
    .bind::<diesel::sql_types::Integer, _>(user_id)
    .bind::<diesel::sql_types::Text, _>(format!("ews_{}", &ews_uuid.to_string()[..8]))
    .bind::<diesel::sql_types::Text, _>(&fp_hex)
    .bind::<diesel::sql_types::Timestamptz, _>(now)
    .execute(conn)
    .await
    .expect("insert seed ews");

    ews_uuid
}

/// A user with an active EWS and a Modbus asset reachable through a rule
/// with the given constraints.
async fn scene(
    conn: &mut AsyncPgConnection,
    label: &str,
    require_mfa: bool,
    require_approval: bool,
    rule_duration: Option<i32>,
) -> Scene {
    use vauban_web::schema::{assets, users};

    let admin_id = create_simple_admin_user(conn, &unique_name(&format!("{label}_adm"))).await;
    let username = unique_name(&format!("{label}_usr"));
    let user_id = create_simple_user(conn, &username).await;
    let user_uuid: Uuid = unwrap_ok!(
        users::table
            .filter(users::id.eq(user_id))
            .select(users::uuid)
            .first(conn)
            .await
    );

    let suffix = unique_name(label);
    let asset_group_uuid = create_test_asset_group(conn, &format!("{suffix}-ag")).await;
    let user_group_uuid = create_test_vauban_group(conn, &format!("{suffix}-ug")).await;
    add_user_to_vauban_group(conn, user_id, &user_group_uuid).await;
    let asset_id = create_test_asset_in_group_with_type(
        conn,
        &format!("{suffix}-modbus"),
        admin_id,
        &asset_group_uuid,
        AssetType::IacsModbus,
    )
    .await;
    let asset_uuid: Uuid = unwrap_ok!(
        assets::table
            .filter(assets::id.eq(asset_id))
            .select(assets::uuid)
            .first(conn)
            .await
    );
    let _ = create_test_access_rule_with_constraints(
        conn,
        &user_group_uuid,
        &asset_group_uuid,
        &["iacs_modbus"],
        require_mfa,
        require_approval,
        rule_duration,
    )
    .await;
    let ews_uuid = seed_active_ews(conn, user_id, label).await;

    Scene {
        username,
        user_id,
        user_uuid,
        asset_id,
        asset_uuid,
        ews_uuid,
    }
}

/// An access request in `status`, as the approval flow leaves it.
async fn seed_request(
    conn: &mut AsyncPgConnection,
    scene: &Scene,
    status: &str,
    expires_at: Option<chrono::DateTime<Utc>>,
    max_session_duration: Option<i32>,
) -> Uuid {
    let uuid = Uuid::new_v4();
    let request = NewProxySession {
        uuid,
        user_id: scene.user_id,
        asset_id: scene.asset_id,
        credential_id: "pending".to_string(),
        credential_username: "pending".to_string(),
        session_type: SessionType::IacsTunnel,
        status: status.to_string(),
        client_ip: unwrap_ok!("127.0.0.1".parse()),
        client_user_agent: None,
        proxy_instance: None,
        justification: Some(JUSTIFICATION.to_string()),
        is_recorded: false,
        metadata: serde_json::json!({}),
        max_session_duration,
        industrial_protocol: Some("modbus".to_string()),
        ews_uuid: Some(scene.ews_uuid),
        tunnel_target_addr: None,
        expires_at,
        connected_at: None,
    };
    unwrap_ok!(
        diesel::insert_into(proxy_sessions::table)
            .values(&request)
            .execute(conn)
            .await
    );
    uuid
}

/// Tunnel rows of this user on this asset: what an open leaves behind.
async fn tunnels(
    conn: &mut AsyncPgConnection,
    scene: &Scene,
) -> Vec<(
    String,
    Option<String>,
    Option<i32>,
    Option<chrono::DateTime<Utc>>,
)> {
    unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::user_id.eq(scene.user_id))
            .filter(proxy_sessions::asset_id.eq(scene.asset_id))
            .filter(proxy_sessions::status.eq("waiting_client"))
            .select((
                proxy_sessions::status,
                proxy_sessions::justification,
                proxy_sessions::max_session_duration,
                proxy_sessions::expires_at,
            ))
            .load(conn)
            .await
    )
}

async fn connect(app: &TestApp, scene: &Scene, htmx: bool) -> axum_test::TestResponse {
    let token = app
        .generate_test_token(&scene.user_uuid.to_string(), &scene.username, false, false)
        .await;
    let csrf = app.generate_csrf_token();
    let mut request = app
        .server
        .post(&format!("/assets/{}/connect-iacs", scene.asset_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf),
        );
    if htmx {
        request = request.add_header("HX-Request", "true");
    }
    request.form(&[("csrf_token", csrf.as_str())]).await
}

fn opened(response: &axum_test::TestResponse) -> bool {
    matches!(response.status_code().as_u16(), 302 | 303)
        || response.headers().contains_key("hx-redirect")
}

/// The defect: a rule that requires an approval, no request at all.
#[tokio::test]
async fn attack_iacs_tunnel_without_approval_is_rejected() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let scene = scene(&mut conn, "iacs_appr_none", false, true, None).await;

    let response = connect(app, &scene, false).await;

    assert_eq!(response.status_code().as_u16(), 403);
    assert!(!opened(&response));
    assert!(
        tunnels(&mut conn, &scene).await.is_empty(),
        "a refused open must leave no tunnel row"
    );
}

/// The same refusal for the browser: the request modal is opened, with
/// the asset and its MFA requirement, and nothing is created.
#[tokio::test]
async fn iacs_tunnel_without_approval_opens_the_request_modal() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let scene = scene(&mut conn, "iacs_appr_modal", true, true, None).await;

    let response = connect(app, &scene, true).await;

    assert!(!opened(&response));
    let trigger = response
        .headers()
        .get("hx-trigger")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let trigger: serde_json::Value = serde_json::from_str(&trigger).unwrap_or_default();
    let modal = &trigger["show-access-request-modal"];
    assert_eq!(modal["asset_uuid"], scene.asset_uuid.to_string());
    assert_eq!(modal["asset_type"], "iacs_modbus");
    assert_eq!(modal["require_mfa"], true);
    assert!(tunnels(&mut conn, &scene).await.is_empty());
}

/// Requests that are not a live approval do not open a tunnel.
#[tokio::test]
async fn attack_iacs_tunnel_with_a_request_that_is_not_a_live_approval_is_rejected() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let future = Some(Utc::now() + Duration::hours(1));
    let past = Some(Utc::now() - Duration::minutes(1));

    for (label, status, expires_at) in [
        ("iacs_appr_pending", "pending", future),
        ("iacs_appr_expired", "approved", past),
        ("iacs_appr_denied", "rejected", future),
        ("iacs_appr_lapsed", "expired", future),
    ] {
        let scene = scene(&mut conn, label, false, true, None).await;
        seed_request(&mut conn, &scene, status, expires_at, Some(600)).await;

        let response = connect(app, &scene, false).await;

        assert_eq!(response.status_code().as_u16(), 403, "{label}");
        assert!(tunnels(&mut conn, &scene).await.is_empty(), "{label}");
    }
}

/// An approval is the requester's own, for the asset it names.
#[tokio::test]
async fn attack_iacs_tunnel_with_someone_elses_approval_is_rejected() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let future = Some(Utc::now() + Duration::hours(1));
    let holder = scene(&mut conn, "iacs_appr_holder", false, true, None).await;
    let other = scene(&mut conn, "iacs_appr_other", false, true, None).await;
    // The holder is approved for its own asset only.
    seed_request(&mut conn, &holder, "approved", future, Some(600)).await;

    let response = connect(app, &other, false).await;

    assert_eq!(response.status_code().as_u16(), 403);
    assert!(tunnels(&mut conn, &other).await.is_empty());
}

/// With a live approval the tunnel opens, and the session carries what
/// was approved: the justification and the granted duration.
#[tokio::test]
async fn iacs_tunnel_opens_under_a_live_approval_and_carries_it() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    // The rule allows one hour; the approver granted ten minutes.
    let scene = scene(&mut conn, "iacs_appr_ok", false, true, Some(3600)).await;
    seed_request(
        &mut conn,
        &scene,
        "approved",
        Some(Utc::now() + Duration::hours(1)),
        Some(600),
    )
    .await;
    let before = Utc::now();

    let response = connect(app, &scene, false).await;

    assert!(opened(&response), "status {}", response.status_code());
    let rows = tunnels(&mut conn, &scene).await;
    assert_eq!(rows.len(), 1);
    let (_, justification, duration, expires_at) = &rows[0];
    assert_eq!(justification.as_deref(), Some(JUSTIFICATION));
    assert_eq!(*duration, Some(600));
    let expires_at = expires_at.expect("an approved tunnel has an expiry");
    assert!(expires_at >= before + Duration::seconds(590));
    assert!(expires_at <= Utc::now() + Duration::seconds(610));
}

/// A rule that requires both: the second factor was checked when the
/// request was filed, so the open under the approval asks for no code.
#[tokio::test]
async fn iacs_tunnel_under_an_approval_asks_for_no_code_again() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let scene = scene(&mut conn, "iacs_appr_mfa", true, true, None).await;
    seed_request(
        &mut conn,
        &scene,
        "approved",
        Some(Utc::now() + Duration::hours(1)),
        Some(600),
    )
    .await;

    let response = connect(app, &scene, false).await;

    assert!(opened(&response), "status {}", response.status_code());
    assert_eq!(tunnels(&mut conn, &scene).await.len(), 1);
}

/// Control: a rule without the flag still opens with no request, and an
/// approval lying around does not shorten or annotate that session.
#[tokio::test]
async fn iacs_tunnel_without_the_flag_opens_and_ignores_a_stray_approval() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let scene = scene(&mut conn, "iacs_appr_off", false, false, None).await;
    seed_request(
        &mut conn,
        &scene,
        "approved",
        Some(Utc::now() + Duration::hours(1)),
        Some(600),
    )
    .await;

    let response = connect(app, &scene, false).await;

    assert!(opened(&response), "status {}", response.status_code());
    let rows = tunnels(&mut conn, &scene).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].1, None, "no approval was needed: none is recorded");
    assert_eq!(rows[0].2, None);
}

/// Status, industrial protocol, workstation and duration of a request.
type RequestRow = (String, Option<String>, Option<Uuid>, Option<i32>);

/// Filing the request itself: the browser posts the one session type
/// IACS has, and the row satisfies what the database requires of an
/// `iacs_tunnel` row (protocol and workstation). Before 0.9.60 nothing
/// offered this request, and its INSERT would have been refused.
#[tokio::test]
async fn an_access_request_can_be_filed_for_an_iacs_asset() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let scene = scene(&mut conn, "iacs_appr_file", false, true, Some(1800)).await;
    let token = app
        .generate_test_token(&scene.user_uuid.to_string(), &scene.username, false, false)
        .await;
    let csrf = app.generate_csrf_token();

    let response = app
        .server
        .post("/sessions/request")
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf),
        )
        .add_header("HX-Request", "true")
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("asset_uuid", scene.asset_uuid.to_string().as_str()),
            ("session_type", "iacs_tunnel"),
            ("justification", JUSTIFICATION),
        ])
        .await;

    let trigger = response
        .headers()
        .get("hx-trigger")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(trigger.contains("Access request submitted"), "{trigger}");

    let rows: Vec<RequestRow> = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::user_id.eq(scene.user_id))
            .filter(proxy_sessions::asset_id.eq(scene.asset_id))
            .select((
                proxy_sessions::status,
                proxy_sessions::industrial_protocol,
                proxy_sessions::ews_uuid,
                proxy_sessions::max_session_duration,
            ))
            .load(&mut conn)
            .await
    );
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, "pending");
    assert_eq!(rows[0].1.as_deref(), Some("modbus"));
    assert_eq!(rows[0].2, Some(scene.ews_uuid));
    assert_eq!(rows[0].3, Some(1800));

    // A pending request opens nothing.
    let response = connect(app, &scene, false).await;
    assert_eq!(response.status_code().as_u16(), 403);
    assert!(tunnels(&mut conn, &scene).await.is_empty());
}
