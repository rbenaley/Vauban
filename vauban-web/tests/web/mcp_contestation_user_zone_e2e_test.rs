//! User Zone contestation: subject follows status; reviewers stay in the MCP nest.
use axum::http::header::{AUTHORIZATION, COOKIE, LOCATION};
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::RunQueryDsl;
use serial_test::serial;
use uuid::Uuid;
use vauban_web::models::asset::{Asset, AssetType, NewAsset};
use vauban_web::schema::{assets, proxy_sessions};

use crate::common::{TestApp, test_db};
use crate::fixtures::{
    create_admin_user, create_test_session_with_access, create_test_user, unique_name,
};

fn auth_csrf_cookie(token: &str, csrf: &str) -> String {
    format!("access_token={}; __vauban_csrf={}", token, csrf)
}

async fn seed_terminated_mcp(
    conn: &mut diesel_async::AsyncPgConnection,
    user_id: i32,
    created_by: i32,
) -> (Uuid, String) {
    let asset: Asset = diesel::insert_into(assets::table)
        .values(&NewAsset {
            uuid: Uuid::new_v4(),
            name: unique_name("mcp-uz-asset"),
            hostname: format!("{}.mcp.test", unique_name("uz")),
            port: 19001,
            asset_type: AssetType::Mcp,
            status: "online".into(),
            description: Some("user-zone contestation fixture".into()),
            connection_config: serde_json::json!({}),
            created_by_id: Some(created_by),
            updated_by_id: Some(created_by),
            connection_username: String::new(),
        })
        .get_result(conn)
        .await
        .unwrap();

    let (_session_id, session_uuid, _rule) =
        create_test_session_with_access(conn, user_id, asset.id, "mcp", "terminated").await;
    let decision_id = format!("D-UZ-{}", &session_uuid.to_string()[..8]);
    diesel::update(proxy_sessions::table.filter(proxy_sessions::uuid.eq(session_uuid)))
        .set((
            proxy_sessions::justification.eq("Visit plant historian for quarterly close"),
            proxy_sessions::decision_id.eq(decision_id.clone()),
            proxy_sessions::termination_reason.eq("mandate_drift"),
        ))
        .execute(conn)
        .await
        .unwrap();
    (session_uuid, decision_id)
}

#[tokio::test]
#[serial]
async fn subject_follows_contestation_in_user_zone_reviewer_stays_in_nest() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let subject = create_test_user(&mut conn, &app.auth_service, &unique_name("uz_subject")).await;
    let reviewer =
        create_admin_user(&mut conn, &app.auth_service, &unique_name("uz_reviewer")).await;
    let intruder =
        create_test_user(&mut conn, &app.auth_service, &unique_name("uz_intruder")).await;

    let (session_uuid, decision_id) =
        seed_terminated_mcp(&mut conn, subject.user.id, reviewer.user.id).await;

    let subject_csrf = app.generate_csrf_token();
    let subject_cookie = auth_csrf_cookie(&subject.token, &subject_csrf);
    let reviewer_csrf = app.generate_csrf_token();
    let reviewer_cookie = auth_csrf_cookie(&reviewer.token, &reviewer_csrf);
    let intruder_csrf = app.generate_csrf_token();
    let intruder_cookie = auth_csrf_cookie(&intruder.token, &intruder_csrf);

    let my_requests = app
        .server
        .get("/sessions/my-requests")
        .add_header(AUTHORIZATION, app.auth_header(&subject.token))
        .add_header(COOKIE, subject_cookie.as_str())
        .await;
    assert_eq!(
        my_requests.status_code().as_u16(),
        200,
        "My Requests must render for role:user"
    );
    let my_html = my_requests.text();
    assert!(
        my_html.contains(&decision_id)
            && my_html.contains("Terminated")
            && my_html.contains("Contest"),
        "My Requests must show the terminated MCP row + Contest"
    );
    assert!(
        my_html.contains(&format!("/sessions/{session_uuid}")),
        "View/Contest must link to the session page"
    );

    let detail = app
        .server
        .get(&format!("/sessions/{session_uuid}"))
        .add_header(AUTHORIZATION, app.auth_header(&subject.token))
        .add_header(COOKIE, subject_cookie.as_str())
        .await;
    assert_eq!(
        detail.status_code().as_u16(),
        200,
        "owner must load terminated MCP session, got {} body={}",
        detail.status_code(),
        detail.text().chars().take(200).collect::<String>()
    );

    let opened = app
        .server
        .post(&format!("/sessions/{session_uuid}/contest"))
        .add_header(AUTHORIZATION, app.auth_header(&subject.token))
        .add_header(COOKIE, subject_cookie.as_str())
        .form(&[
            ("csrf_token", subject_csrf.as_str()),
            (
                "open_reason",
                "The drift was a false positive on a documented tool",
            ),
        ])
        .await;
    let open_status = opened.status_code().as_u16();
    assert!(
        open_status == 302 || open_status == 303,
        "POST contest must redirect, got {open_status}"
    );
    let loc = opened
        .headers()
        .get(LOCATION)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        loc.starts_with("/sessions/contestations/"),
        "open must land on User Zone, got {loc}"
    );
    assert!(
        !loc.contains("/sessions/mcp/contestations/"),
        "open must not bounce into the MCP nest"
    );

    let user_zone = app
        .server
        .get(&loc)
        .add_header(AUTHORIZATION, app.auth_header(&subject.token))
        .add_header(COOKIE, subject_cookie.as_str())
        .await;
    assert_eq!(user_zone.status_code().as_u16(), 200);
    let uz_html = user_zone.text();
    assert!(
        uz_html.contains("Open") || uz_html.contains("open"),
        "subject must see Open status"
    );
    assert!(
        !uz_html.contains("/sessions/mcp/contestations/")
            && !uz_html.contains("action=\"/sessions/mcp/contestations/"),
        "User Zone must not expose claim/uphold/overturn"
    );
    assert!(
        !uz_html.contains("href=\"/sessions/mcp\"") && !uz_html.contains(">HITL<"),
        "User Zone must not leak MCP HITL nav"
    );

    for path in [
        "/sessions/mcp/contestations".to_string(),
        loc.replacen(
            "/sessions/contestations/",
            "/sessions/mcp/contestations/",
            1,
        ),
    ] {
        let denied = app
            .server
            .get(&path)
            .add_header(AUTHORIZATION, app.auth_header(&subject.token))
            .add_header(COOKIE, subject_cookie.as_str())
            .await;
        assert_eq!(
            denied.status_code().as_u16(),
            403,
            "subject must not enter the MCP nest ({path})"
        );
    }

    let nest_list = app
        .server
        .get("/sessions/mcp/contestations")
        .add_header(AUTHORIZATION, app.auth_header(&reviewer.token))
        .add_header(COOKIE, reviewer_cookie.as_str())
        .await;
    assert_eq!(nest_list.status_code().as_u16(), 200);

    let nest_detail_path = loc.replacen(
        "/sessions/contestations/",
        "/sessions/mcp/contestations/",
        1,
    );
    let nest_detail = app
        .server
        .get(&nest_detail_path)
        .add_header(AUTHORIZATION, app.auth_header(&reviewer.token))
        .add_header(COOKIE, reviewer_cookie.as_str())
        .await;
    assert_eq!(nest_detail.status_code().as_u16(), 200);
    let nest_html = nest_detail.text();
    assert!(
        nest_html.contains("/claim") && nest_html.contains("HITL"),
        "reviewer nest page must offer claim and MCP nav"
    );

    let claimed = app
        .server
        .post(&format!("{nest_detail_path}/claim"))
        .add_header(AUTHORIZATION, app.auth_header(&reviewer.token))
        .add_header(COOKIE, reviewer_cookie.as_str())
        .form(&[("csrf_token", reviewer_csrf.as_str())])
        .await;
    let claim_status = claimed.status_code().as_u16();
    assert!(
        claim_status == 302 || claim_status == 303,
        "claim must redirect, got {claim_status} body={}",
        claimed.text().chars().take(200).collect::<String>()
    );

    let after_claim = app
        .server
        .get(&nest_detail_path)
        .add_header(AUTHORIZATION, app.auth_header(&reviewer.token))
        .add_header(COOKIE, reviewer_cookie.as_str())
        .await;
    let after_html = after_claim.text();
    assert!(
        after_html.contains("/uphold") || after_html.contains("Uphold"),
        "reviewer must be able to uphold after claim"
    );

    let stranger = app
        .server
        .get(&loc)
        .add_header(AUTHORIZATION, app.auth_header(&intruder.token))
        .add_header(COOKIE, intruder_cookie.as_str())
        .await;
    let missing = app
        .server
        .get(&format!("/sessions/contestations/{}", Uuid::new_v4()))
        .add_header(AUTHORIZATION, app.auth_header(&intruder.token))
        .add_header(COOKIE, intruder_cookie.as_str())
        .await;
    let stranger_status = stranger.status_code().as_u16();
    let missing_status = missing.status_code().as_u16();
    assert!(
        (stranger_status == 302 || stranger_status == 303) && stranger_status == missing_status,
        "intruder vs unknown uuid must share one redirect, got {stranger_status} vs {missing_status}"
    );
    let stranger_loc = stranger
        .headers()
        .get(LOCATION)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    let missing_loc = missing
        .headers()
        .get(LOCATION)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    assert_eq!(
        stranger_loc, missing_loc,
        "User Zone must not be an existence oracle"
    );
    assert!(
        stranger_loc.contains("/sessions/my-requests"),
        "intruder redirect must land on My Requests, got {stranger_loc}"
    );

    test_db::cleanup(&mut conn).await;
}
