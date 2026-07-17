//! End-to-end regression coverage for never-connected JIT grants.

use askama::Template;
use axum::http::header::COOKIE;
use chrono::{DateTime, Duration, Utc};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;

use crate::common::{TestApp, assertions::assert_status, unwrap_ok};
use crate::fixtures::{
    add_user_to_vauban_group, create_simple_admin_user, create_simple_user,
    create_test_access_rule_with_constraints, create_test_asset_group, create_test_asset_in_group,
    create_test_vauban_group, get_asset_uuid, unique_name,
};

type PersistedGrant = (
    String,
    i32,
    DateTime<Utc>,
    String,
    String,
    Option<DateTime<Utc>>,
    Option<DateTime<Utc>>,
);

#[tokio::test]
async fn expired_ssh_and_rdp_requests_keep_requester_and_created_time_without_sentinel() {
    use vauban_web::schema::proxy_sessions::dsl as ps;

    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin_name = unique_name("expired_ui_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid: uuid::Uuid = unwrap_ok!(
        vauban_web::schema::users::table
            .filter(vauban_web::schema::users::id.eq(admin_id))
            .select(vauban_web::schema::users::uuid)
            .first(&mut conn)
            .await
    );
    let admin_token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    for protocol in ["ssh", "rdp"] {
        let user_name = unique_name(&format!("expired_ui_{protocol}_user"));
        let user_id = create_simple_user(&mut conn, &user_name).await;
        let user_uuid: uuid::Uuid = unwrap_ok!(
            vauban_web::schema::users::table
                .filter(vauban_web::schema::users::id.eq(user_id))
                .select(vauban_web::schema::users::uuid)
                .first(&mut conn)
                .await
        );
        let user_token = app
            .generate_test_token(&user_uuid.to_string(), &user_name, false, false)
            .await;

        let ug = create_test_vauban_group(
            &mut conn,
            &unique_name(&format!("expired_ui_{protocol}_ug")),
        )
        .await;
        add_user_to_vauban_group(&mut conn, user_id, &ug).await;
        let ag = create_test_asset_group(
            &mut conn,
            &unique_name(&format!("expired_ui_{protocol}_ag")),
        )
        .await;
        let asset_name = unique_name(&format!("expired_ui_{protocol}_asset"));
        let asset_id = create_test_asset_in_group(&mut conn, &asset_name, admin_id, &ag).await;
        let asset_uuid = get_asset_uuid(&mut conn, asset_id).await;
        create_test_access_rule_with_constraints(
            &mut conn,
            &ug,
            &ag,
            &[protocol],
            false,
            true,
            Some(600),
        )
        .await;

        let csrf = app.generate_csrf_token();
        let response = app
            .server
            .post("/sessions/request")
            .add_header(
                COOKIE,
                format!("access_token={user_token}; __vauban_csrf={csrf}"),
            )
            .form(&[
                ("csrf_token", csrf.as_str()),
                ("asset_uuid", &asset_uuid.to_string()),
                ("session_type", protocol),
                ("justification", "BUG-03 never-connected request"),
            ])
            .await;
        assert!(
            matches!(response.status_code().as_u16(), 200 | 303),
            "POST /sessions/request failed for {protocol}"
        );

        let (session_id, session_uuid): (i32, uuid::Uuid) = unwrap_ok!(
            ps::proxy_sessions
                .filter(ps::user_id.eq(user_id))
                .filter(ps::asset_id.eq(asset_id))
                .filter(ps::status.eq("pending"))
                .select((ps::id, ps::uuid))
                .first(&mut conn)
                .await
        );

        let now = Utc::now();
        let original_created = now - Duration::hours(25);
        unwrap_ok!(
            diesel::update(ps::proxy_sessions.filter(ps::id.eq(session_id)))
                .set(ps::created_at.eq(original_created))
                .execute(&mut conn)
                .await
        );

        let expired = unwrap_ok!(
            vauban_web::services::session_lifecycle::expire_stale_pending_requests_at(
                &app.db_pool,
                now,
                24,
            )
            .await
        );
        assert!(expired >= 1, "the stale {protocol} grant must expire");

        let persisted: PersistedGrant = unwrap_ok!(
            ps::proxy_sessions
                .filter(ps::id.eq(session_id))
                .select((
                    ps::status,
                    ps::user_id,
                    ps::created_at,
                    ps::credential_id,
                    ps::credential_username,
                    ps::connected_at,
                    ps::disconnected_at,
                ))
                .first(&mut conn)
                .await
        );
        assert_eq!(persisted.0, "expired");
        assert_eq!(persisted.1, user_id);
        assert_eq!(persisted.2, original_created);
        assert_eq!(persisted.3, "pending");
        assert_eq!(persisted.4, "pending");
        assert!(persisted.5.is_none());
        assert!(persisted.6.is_none());

        let list = app
            .server
            .get(&format!("/sessions?asset={asset_name}"))
            .add_header(COOKIE, format!("access_token={admin_token}"))
            .await;
        assert_status(&list, 200);
        let list_html = list.text();
        assert!(list_html.contains(&asset_name));
        assert!(list_html.contains(&format!("Requested by {user_name}")));
        assert!(list_html.contains("Requested "));

        let detail = app
            .server
            .get(&format!("/sessions/{session_id}"))
            .add_header(COOKIE, format!("access_token={admin_token}"))
            .await;
        assert_status(&detail, 200);
        let detail_html = detail.text();
        assert!(detail_html.contains(&user_name));
        assert!(detail_html.contains("Not selected (request never connected)"));
        assert!(detail_html.contains("Not connected"));
        assert!(detail_html.contains("Not recorded"));
        assert!(detail_html.contains(&format!("/sessions/approvals/{session_uuid}")));

        let approval = app
            .server
            .get(&format!("/sessions/approvals/{session_uuid}"))
            .add_header(COOKIE, format!("access_token={admin_token}"))
            .await;
        assert_status(&approval, 200);
        assert!(
            approval
                .text()
                .contains("Not selected (request never connected)")
        );

        let owner_detail = app
            .server
            .get(&format!("/sessions/{session_id}"))
            .add_header(COOKIE, format!("access_token={user_token}"))
            .await;
        assert_status(&owner_detail, 200);
        assert!(
            !owner_detail
                .text()
                .contains(&format!("/sessions/approvals/{session_uuid}"))
        );
    }
}

#[test]
fn session_templates_never_interpolate_raw_pending_credentials() {
    let detail = include_str!("../../templates/sessions/session_detail.html");
    let approval = include_str!("../../templates/sessions/approval_detail.html");
    assert!(!detail.contains("{{ session.credential_username }}"));
    assert!(!approval.contains("{{ approval.credential_username }}"));
    assert!(detail.contains("session.credential_display()"));
    assert!(approval.contains("approval.credential_display()"));
}

#[test]
fn all_session_history_producers_use_the_shared_mapper() {
    for source in [
        include_str!("../../src/handlers/web/sessions.rs"),
        include_str!("../../src/handlers/websocket.rs"),
        include_str!("../../src/tasks/dashboard.rs"),
    ] {
        assert!(
            source.contains("SessionHistoryRow::from")
                || source.contains("session_history::SessionHistoryRow::from"),
            "HTTP, WS and task producers must use SessionHistoryRow"
        );
    }
}

#[test]
fn realtime_payload_roundtrip_preserves_requester_and_requested_timestamp() {
    use vauban_web::models::session::SessionType;
    use vauban_web::services::session_history::SessionHistoryRow;
    use vauban_web::templates::sessions::{SessionListContentWidget, SessionListPayload};

    let created_at = DateTime::<Utc>::UNIX_EPOCH + Duration::hours(42);
    let item = SessionHistoryRow {
        id: 42,
        uuid: uuid::Uuid::new_v4(),
        asset_name: "Realtime Asset".to_string(),
        asset_hostname: "realtime.example.test".to_string(),
        session_type: SessionType::Ssh,
        status: "expired".to_string(),
        credential_id: "pending".to_string(),
        credential_username: "pending".to_string(),
        tunnel_target_addr: None,
        connected_at: None,
        disconnected_at: None,
        is_recorded: true,
        recording_path: None,
        requester_username: "alice".to_string(),
        created_at,
    }
    .into_list_item(created_at + Duration::hours(25));

    let payload = SessionListPayload {
        sessions: vec![item],
        show_view_link: true,
    };
    let json = unwrap_ok!(serde_json::to_string(&payload));
    let decoded: SessionListPayload = unwrap_ok!(serde_json::from_str(&json));
    let html = unwrap_ok!(
        SessionListContentWidget {
            sessions: decoded.sessions,
            show_view_link: decoded.show_view_link,
            tz: chrono_tz::Tz::UTC,
        }
        .render()
    );

    assert!(html.contains("Requested by alice"));
    assert!(html.contains("Requested 1970-01-02 18:00 UTC"));
    assert!(!html.contains(">pending<"));
}

#[test]
fn presentation_witnesses_preserve_connected_credentials_and_iacs_targets() {
    use vauban_web::models::session::SessionType;
    use vauban_web::services::session_history::SessionHistoryRow;

    let created = DateTime::<Utc>::UNIX_EPOCH + Duration::hours(1);
    let connected = created + Duration::minutes(5);
    let witnesses = [
        (
            SessionHistoryRow {
                id: 1,
                uuid: uuid::Uuid::new_v4(),
                asset_name: "SSH".to_string(),
                asset_hostname: "ssh.test".to_string(),
                session_type: SessionType::Ssh,
                status: "active".to_string(),
                credential_id: "vault-42".to_string(),
                credential_username: "root".to_string(),
                tunnel_target_addr: None,
                connected_at: Some(connected),
                disconnected_at: None,
                is_recorded: true,
                recording_path: None,
                requester_username: "alice".to_string(),
                created_at: created,
            },
            "root",
            "Connected",
        ),
        (
            SessionHistoryRow {
                id: 2,
                uuid: uuid::Uuid::new_v4(),
                asset_name: "Rejected grant".to_string(),
                asset_hostname: "rdp.test".to_string(),
                session_type: SessionType::Rdp,
                status: "rejected".to_string(),
                credential_id: "pending".to_string(),
                credential_username: "pending".to_string(),
                tunnel_target_addr: None,
                connected_at: None,
                disconnected_at: None,
                is_recorded: true,
                recording_path: None,
                requester_username: "bob".to_string(),
                created_at: created,
            },
            "bob",
            "Requested",
        ),
        (
            SessionHistoryRow {
                id: 3,
                uuid: uuid::Uuid::new_v4(),
                asset_name: "IACS".to_string(),
                asset_hostname: "plc.test".to_string(),
                session_type: SessionType::IacsTunnel,
                status: "tunnel_active".to_string(),
                credential_id: "iacs".to_string(),
                credential_username: String::new(),
                tunnel_target_addr: Some("10.0.0.5:502".to_string()),
                connected_at: Some(connected),
                disconnected_at: None,
                is_recorded: false,
                recording_path: None,
                requester_username: "carol".to_string(),
                created_at: created,
            },
            "10.0.0.5:502",
            "Connected",
        ),
    ];

    for (row, expected_identity, expected_event) in witnesses {
        let item = row.into_list_item(connected + Duration::minutes(1));
        assert_eq!(item.display_identity(), expected_identity);
        assert_eq!(item.event_label, expected_event);
        assert_ne!(item.display_identity(), "pending");
    }
}

#[tokio::test]
async fn deterministic_expiry_services_only_transition_eligible_grants() {
    use vauban_web::schema::proxy_sessions::dsl as ps;

    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let owner_name = unique_name("expiry_matrix_owner");
    let owner_id = create_simple_user(&mut conn, &owner_name).await;
    let asset_id = crate::fixtures::create_simple_ssh_asset(
        &mut conn,
        &unique_name("expiry_matrix_asset"),
        owner_id,
    )
    .await;
    let ip: ipnetwork::IpNetwork = unwrap_ok!("127.0.0.1".parse());
    let now = Utc::now();

    let fresh_pending = uuid::Uuid::new_v4();
    let stale_approved = uuid::Uuid::new_v4();
    let connected_active = uuid::Uuid::new_v4();

    for (uuid, status, credential_id, credential_username, created_at, connected_at, expires_at) in [
        (
            fresh_pending,
            "pending",
            "pending",
            "pending",
            now - Duration::hours(1),
            None,
            None,
        ),
        (
            stale_approved,
            "approved",
            "pending",
            "pending",
            now - Duration::hours(2),
            None,
            Some(now - Duration::hours(1)),
        ),
        (
            connected_active,
            "active",
            "local",
            "root",
            now - Duration::hours(2),
            Some(now - Duration::hours(1)),
            Some(now - Duration::minutes(1)),
        ),
    ] {
        unwrap_ok!(
            diesel::insert_into(ps::proxy_sessions)
                .values((
                    ps::uuid.eq(uuid),
                    ps::user_id.eq(owner_id),
                    ps::asset_id.eq(asset_id),
                    ps::credential_id.eq(credential_id),
                    ps::credential_username.eq(credential_username),
                    ps::session_type.eq("ssh"),
                    ps::status.eq(status),
                    ps::client_ip.eq(ip),
                    ps::created_at.eq(created_at),
                    ps::connected_at.eq(connected_at),
                    ps::expires_at.eq(expires_at),
                    ps::metadata.eq(serde_json::json!({})),
                ))
                .execute(&mut conn)
                .await
        );
    }

    unwrap_ok!(
        vauban_web::services::session_lifecycle::expire_stale_pending_requests_at(
            &app.db_pool,
            now,
            24,
        )
        .await
    );
    unwrap_ok!(
        vauban_web::services::session_lifecycle::expire_stale_approved_sessions_at(
            &app.db_pool,
            now,
        )
        .await
    );

    let rows: Vec<(uuid::Uuid, String, String, Option<chrono::DateTime<Utc>>)> = unwrap_ok!(
        ps::proxy_sessions
            .filter(ps::uuid.eq_any([fresh_pending, stale_approved, connected_active]))
            .select((
                ps::uuid,
                ps::status,
                ps::credential_username,
                ps::connected_at
            ))
            .load(&mut conn)
            .await
    );

    let status_of = |needle| {
        rows.iter()
            .find(|row| row.0 == needle)
            .map(|row| (row.1.as_str(), row.2.as_str(), row.3))
    };
    assert_eq!(status_of(fresh_pending), Some(("pending", "pending", None)));
    assert_eq!(
        status_of(stale_approved),
        Some(("expired", "pending", None))
    );
    assert!(matches!(
        status_of(connected_active),
        Some(("active", "root", Some(_)))
    ));
}
