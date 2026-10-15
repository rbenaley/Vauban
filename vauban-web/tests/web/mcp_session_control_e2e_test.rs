//! MCP session control end to end: web suspends and resumes through a fake
//! proxy on a real IPC pair, and proxy state notifies land in the DB.
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::RunQueryDsl;
use serial_test::serial;
use shared::ipc::IpcChannel;
use shared::messages::Message;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;
use vauban_web::ipc::ProxyMcpClient;
use vauban_web::models::asset::{Asset, AssetType, NewAsset};
use vauban_web::models::session::ProxySession;
use vauban_web::schema::{assets, proxy_sessions};
use vauban_web::services::mcp_control;

use crate::common::TestApp;
use crate::fixtures::{create_admin_user, create_test_session_with_access, unique_name};

struct Proxy {
    state: vauban_web::AppState,
    peer: IpcChannel,
}

impl Proxy {
    fn new(app: &TestApp) -> Self {
        let (web_side, peer) = IpcChannel::pair().unwrap();
        let client = ProxyMcpClient::new(web_side.read_fd(), web_side.write_fd()).unwrap();
        std::mem::forget(web_side);
        let pump = Arc::clone(&client);
        tokio::spawn(async move { pump.process_incoming().await });
        let mut state = app.app_state.clone();
        state.proxy_mcp = Some(Arc::clone(&client));
        client.set_runtime(state.clone());
        Self { state, peer }
    }

    async fn received(&self) -> Vec<Message> {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut out = Vec::new();
        while let Ok(m) = self.peer.try_recv() {
            out.push(m);
        }
        out
    }
}

async fn seed_mcp_session(app: &TestApp, status: &str) -> (Uuid, String) {
    let mut conn = app.get_conn().await;
    let owner = create_admin_user(&mut conn, &app.auth_service, &unique_name("mcp_ctl")).await;
    let asset: Asset = diesel::insert_into(assets::table)
        .values(&NewAsset {
            uuid: Uuid::new_v4(),
            name: unique_name("mcp-ctl-asset"),
            hostname: format!("{}.mcp.test", unique_name("ctl")),
            port: 19002,
            asset_type: AssetType::Mcp,
            status: "online".into(),
            description: None,
            connection_config: serde_json::json!({}),
            created_by_id: Some(owner.user.id),
            updated_by_id: Some(owner.user.id),
            connection_username: String::new(),
        })
        .get_result(&mut conn)
        .await
        .unwrap();
    let (_, session_uuid, _) =
        create_test_session_with_access(&mut conn, owner.user.id, asset.id, "mcp", status).await;
    (session_uuid, owner.user.uuid.to_string())
}

async fn load(app: &TestApp, session_uuid: Uuid) -> ProxySession {
    let mut conn = app.get_conn().await;
    proxy_sessions::table
        .filter(proxy_sessions::uuid.eq(session_uuid))
        .first(&mut conn)
        .await
        .unwrap()
}

async fn status_after_notify(app: &TestApp, session_uuid: Uuid, expect: &str) -> String {
    for _ in 0..50 {
        let s = load(app, session_uuid).await.status;
        if s == expect {
            return s;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    load(app, session_uuid).await.status
}

#[tokio::test]
#[serial]
async fn mcp_suspend_then_resume_reaches_the_proxy_and_the_db() {
    let app = TestApp::spawn().await;
    let p = Proxy::new(app);
    let (sid, actor) = seed_mcp_session(app, "active").await;

    let session = load(app, sid).await;
    let suspended = mcp_control::suspend_mcp_session(&p.state, &session, "ops", &actor)
        .await
        .unwrap();
    assert_eq!(suspended.status, "suspended");
    let again = mcp_control::suspend_mcp_session(&p.state, &suspended, "ops", &actor)
        .await
        .unwrap();
    assert_eq!(again.status, "suspended", "suspending twice is a no-op");

    let resumed = mcp_control::resume_mcp_session(&p.state, &suspended, &actor)
        .await
        .unwrap();
    assert_eq!(resumed.status, "active");

    let sent = p.received().await;
    assert_eq!(sent.len(), 2, "one suspend and one resume: {sent:?}");
    assert!(matches!(
        &sent[0],
        Message::McpSessionSuspend { session_id, reason, actor_user_id, .. }
            if *session_id == sid.to_string() && reason == "ops" && *actor_user_id == actor
    ));
    assert!(matches!(
        &sent[1],
        Message::McpSessionResume { session_id, actor_user_id, .. }
            if *session_id == sid.to_string() && *actor_user_id == actor
    ));
}

#[tokio::test]
#[serial]
async fn mcp_ended_session_cannot_be_suspended_or_resumed() {
    let app = TestApp::spawn().await;
    let p = Proxy::new(app);
    let (sid, actor) = seed_mcp_session(app, "terminated").await;
    let session = load(app, sid).await;

    assert!(
        mcp_control::suspend_mcp_session(&p.state, &session, "ops", &actor)
            .await
            .is_err()
    );
    assert!(
        mcp_control::resume_mcp_session(&p.state, &session, &actor)
            .await
            .is_err()
    );
    assert!(
        p.received().await.is_empty(),
        "nothing is sent to the proxy"
    );
    assert_eq!(load(app, sid).await.status, "terminated");
}

#[tokio::test]
#[serial]
async fn mcp_proxy_state_notify_updates_a_live_session() {
    let app = TestApp::spawn().await;
    let p = Proxy::new(app);
    let (sid, _) = seed_mcp_session(app, "active").await;

    p.peer
        .send(&Message::McpSessionStateNotify {
            session_id: sid.to_string(),
            status: "suspended".into(),
            reason: "envelope".into(),
        })
        .unwrap();
    assert_eq!(
        status_after_notify(app, sid, "suspended").await,
        "suspended"
    );

    p.peer
        .send(&Message::McpSessionStateNotify {
            session_id: sid.to_string(),
            status: "active".into(),
            reason: "resume".into(),
        })
        .unwrap();
    assert_eq!(status_after_notify(app, sid, "active").await, "active");
}

#[tokio::test]
#[serial]
async fn mcp_late_state_notify_never_revives_an_ended_session() {
    let app = TestApp::spawn().await;
    let p = Proxy::new(app);
    for ended in ["terminated", "expired", "failed"] {
        let (sid, _) = seed_mcp_session(app, ended).await;
        for status in ["active", "suspended"] {
            p.peer
                .send(&Message::McpSessionStateNotify {
                    session_id: sid.to_string(),
                    status: status.into(),
                    reason: "late".into(),
                })
                .unwrap();
            tokio::time::sleep(Duration::from_millis(150)).await;
            assert_eq!(
                load(app, sid).await.status,
                ended,
                "a late `{status}` notify revived a {ended} session"
            );
        }
    }
}

#[tokio::test]
#[serial]
async fn mcp_revocation_cuts_live_and_suspended_sessions_on_the_proxy() {
    let app = TestApp::spawn().await;
    let p = Proxy::new(app);
    let (active, _) = seed_mcp_session(app, "active").await;
    let owner = load(app, active).await.user_id;
    let (suspended, _) = seed_mcp_session(app, "suspended").await;
    {
        let mut conn = app.get_conn().await;
        diesel::update(proxy_sessions::table.filter(proxy_sessions::uuid.eq(suspended)))
            .set(proxy_sessions::user_id.eq(owner))
            .execute(&mut conn)
            .await
            .unwrap();
    }
    let owner_uuid = {
        use vauban_web::schema::users;
        let mut conn = app.get_conn().await;
        users::table
            .filter(users::id.eq(owner))
            .select(users::uuid)
            .first::<Uuid>(&mut conn)
            .await
            .unwrap()
    };

    vauban_web::handlers::web::deactivate_user(
        &p.state,
        owner,
        &owner_uuid.to_string(),
        "account_deleted",
    )
    .await;

    let mut cut: Vec<String> = p
        .received()
        .await
        .into_iter()
        .filter_map(|m| match m {
            Message::McpSessionTerminate { session_id, .. } => Some(session_id),
            _ => None,
        })
        .collect();
    cut.sort();
    let mut expected = vec![active.to_string(), suspended.to_string()];
    expected.sort();
    assert_eq!(
        cut, expected,
        "every open MCP session of a revoked user is cut"
    );
    for sid in [active, suspended] {
        assert_eq!(load(app, sid).await.status, "terminated");
    }
}
