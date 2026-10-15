//! MCP HITL decisions are web-only: a logged-in human with
//! `sessions:supervise`, a valid CSRF token, and not the requester.
//! A fake proxy on an IPC pair announces the pending and records what
//! web forwards (`McpHitlDecision`).
use crate::common::{TestApp, assertions::*, build_test_router};
use crate::fixtures::{TestUser, create_admin_user, create_test_user, unique_name};
use axum::http::header::{AUTHORIZATION, COOKIE, SET_COOKIE};
use axum_test::TestServer;
use serial_test::serial;
use shared::ipc::IpcChannel;
use shared::messages::Message;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;
use vauban_web::ipc::ProxyMcpClient;

struct Harness {
    server: TestServer,
    router: axum::Router,
    client: Arc<ProxyMcpClient>,
    peer: IpcChannel,
    session_id: String,
}

impl Harness {
    async fn new(app: &TestApp) -> Self {
        Self::build(app, false).await
    }

    /// Mailer on and the client bound to the state, as in production.
    async fn with_mailer(app: &TestApp) -> Self {
        Self::build(app, true).await
    }

    async fn build(app: &TestApp, mailer: bool) -> Self {
        let (web_side, peer) = IpcChannel::pair().unwrap();
        let client = ProxyMcpClient::new(web_side.read_fd(), web_side.write_fd()).unwrap();
        std::mem::forget(web_side);
        let pump = Arc::clone(&client);
        tokio::spawn(async move { pump.process_incoming().await });
        let mut state = app.app_state.clone();
        state.proxy_mcp = Some(Arc::clone(&client));
        if mailer {
            state.mailer = vauban_web::services::mailer::Mailer::new(
                Arc::new(tokio::sync::Notify::new()),
                true,
                5,
            );
            client.set_runtime(state.clone());
        }
        let router = build_test_router(state);
        Self {
            server: TestServer::new(router.clone()).unwrap(),
            router,
            client,
            peer,
            session_id: Uuid::new_v4().to_string(),
        }
    }

    /// The proxy announces a pending opened by `requester`.
    async fn pending(&self, requester: &TestUser) -> String {
        let pending_id = Uuid::new_v4().to_string();
        self.peer
            .send(&Message::McpHitlPendingNotify {
                session_id: self.session_id.clone(),
                pending_id: pending_id.clone(),
                tool: "delete_task".into(),
                args_blake3: "00".into(),
                expires_at: (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
                requester_user_id: requester.user.uuid.to_string(),
                requester_api_key_id: String::new(),
                plan_contract_json: String::new(),
                plan_story_json: String::new(),
                mandate_id: String::new(),
                sealed_digest: String::new(),
            })
            .unwrap();
        for _ in 0..50 {
            if self.client.get_hitl_pending(&pending_id).is_some() {
                return pending_id;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("pending never reached web");
    }

    fn url(&self, pending_id: &str, decision: &str) -> String {
        format!("/sessions/mcp/{}/{pending_id}/{decision}", self.session_id)
    }

    async fn decide(
        &self,
        pending_id: &str,
        decision: &str,
        token: &str,
        csrf_cookie: &str,
        csrf_form: &str,
    ) -> axum_test::TestResponse {
        self.server
            .post(&self.url(pending_id, decision))
            .add_header(
                COOKIE,
                format!("access_token={token}; __vauban_csrf={csrf_cookie}"),
            )
            .form(&[("csrf_token", csrf_form)])
            .await
    }

    /// Decisions the proxy received, waiting a little for the IPC write.
    async fn forwarded(&self) -> Vec<(String, String, String)> {
        tokio::time::sleep(Duration::from_millis(150)).await;
        let mut out = Vec::new();
        while let Ok(m) = self.peer.try_recv() {
            if let Message::McpHitlDecision {
                pending_id,
                decision,
                actor_user_id,
                ..
            } = m
            {
                out.push((pending_id, decision, actor_user_id));
            }
        }
        out
    }
}

fn extract_flash_cookie(response: &axum_test::TestResponse) -> Option<String> {
    response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|c| c.to_str().ok())
        .find(|c| c.contains("__vauban_flash"))
        .and_then(|c| c.split(';').next())
        .map(|s| s.to_string())
}

async fn users(app: &TestApp) -> (TestUser, TestUser) {
    let mut conn = app.get_conn().await;
    let approver =
        create_admin_user(&mut conn, &app.auth_service, &unique_name("test_hitl_ok")).await;
    let requester =
        create_admin_user(&mut conn, &app.auth_service, &unique_name("test_hitl_req")).await;
    (approver, requester)
}

#[tokio::test]
#[serial]
async fn mcp_hitl_decide_staff_approve_and_deny_reach_the_proxy() {
    let app = TestApp::spawn().await;
    let h = Harness::new(app).await;
    let (approver, requester) = users(app).await;
    let csrf = app.generate_csrf_token();

    let pid = h.pending(&requester).await;
    let resp = h
        .decide(&pid, "approve", &approver.token, &csrf, &csrf)
        .await;
    assert_status(&resp, 303);
    let flash = extract_flash_cookie(&resp).expect("approval must set a flash");
    let page = h
        .server
        .get("/sessions/mcp")
        .add_header(COOKIE, format!("access_token={}; {flash}", approver.token))
        .await;
    assert!(
        page.text().contains("HITL approve recorded"),
        "the approver sees the outcome"
    );
    let uuid = approver.user.uuid.to_string();
    assert_eq!(
        h.forwarded().await,
        vec![(pid.clone(), "approve".into(), uuid.clone())]
    );
    assert!(
        h.client.get_hitl_pending(&pid).is_none(),
        "decided pending leaves the queue"
    );

    let pid = h.pending(&requester).await;
    h.decide(&pid, "deny", &approver.token, &csrf, &csrf).await;
    assert_eq!(h.forwarded().await, vec![(pid, "deny".into(), uuid)]);
}

/// The proxy is gone when staff decide: the decision fails visibly and the
/// pending goes back to the queue, so another try is possible.
#[tokio::test]
#[serial]
async fn mcp_hitl_decide_with_the_proxy_gone_keeps_the_pending() {
    let app = TestApp::spawn().await;
    let h = Harness::new(app).await;
    let (approver, requester) = users(app).await;
    let csrf = app.generate_csrf_token();
    let pid = h.pending(&requester).await;
    let url = h.url(&pid, "approve");
    let Harness {
        server,
        client,
        peer,
        ..
    } = h;
    drop(peer);

    let resp = server
        .post(&url)
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={csrf}", approver.token),
        )
        .form(&[("csrf_token", csrf.as_str())])
        .await;
    assert_status(&resp, 303);
    let flash = extract_flash_cookie(&resp).expect("the failure must set a flash");
    let page = server
        .get("/sessions/mcp")
        .add_header(COOKIE, format!("access_token={}; {flash}", approver.token))
        .await;
    assert!(
        page.text().contains("HITL decision failed"),
        "the approver sees the failure"
    );
    assert!(
        client.get_hitl_pending(&pid).is_some(),
        "an undelivered decision must not drop the pending"
    );
}

#[tokio::test]
#[serial]
async fn mcp_hitl_decide_requester_cannot_decide_own_pending() {
    let app = TestApp::spawn().await;
    let h = Harness::new(app).await;
    let (_, requester) = users(app).await;
    let csrf = app.generate_csrf_token();

    let pid = h.pending(&requester).await;
    let resp = h
        .decide(&pid, "approve", &requester.token, &csrf, &csrf)
        .await;
    assert_status(&resp, 303);
    assert!(h.forwarded().await.is_empty());
    assert!(h.client.get_hitl_pending(&pid).is_some());

    let flash = extract_flash_cookie(&resp).expect("refusal must set a flash");
    let page = h
        .server
        .get("/sessions/mcp")
        .add_header(COOKIE, format!("access_token={}; {flash}", requester.token))
        .await;
    assert!(
        page.text().contains("Separation of duties"),
        "the refusal reason must be shown"
    );
}

#[tokio::test]
#[serial]
async fn mcp_hitl_decide_refuses_bad_csrf_missing_permission_and_api_key() {
    let app = TestApp::spawn().await;
    let h = Harness::new(app).await;
    let (approver, requester) = users(app).await;
    let mut conn = app.get_conn().await;
    let plain = create_test_user(
        &mut conn,
        &app.auth_service,
        &unique_name("test_hitl_plain"),
    )
    .await;
    let csrf = app.generate_csrf_token();
    let pid = h.pending(&requester).await;

    h.decide(&pid, "approve", &approver.token, &csrf, "forged")
        .await;
    h.decide(&pid, "approve", &approver.token, "", "").await;
    let no_perm = h.decide(&pid, "approve", &plain.token, &csrf, &csrf).await;
    assert_ne!(no_perm.status_code().as_u16(), 200);
    let by_key = h
        .server
        .post(&h.url(&pid, "approve"))
        .add_header(AUTHORIZATION, format!("Bearer {}", approver.api_key))
        .form(&[("csrf_token", csrf.as_str())])
        .await;
    assert!(
        !by_key.status_code().is_success(),
        "an API key is not a logged-in human"
    );

    assert!(h.forwarded().await.is_empty());
    assert!(h.client.get_hitl_pending(&pid).is_some());
}

/// One raw POST on the router, so concurrent decisions can run on
/// different worker threads (the `TestServer` drives one task).
async fn raw_decide(
    router: axum::Router,
    url: String,
    token: String,
    csrf: String,
) -> Option<String> {
    use tower::ServiceExt;
    let req = axum::http::Request::post(url)
        .header(
            COOKIE,
            format!("access_token={token}; __vauban_csrf={csrf}"),
        )
        .header(
            axum::http::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(axum::body::Body::from(format!("csrf_token={csrf}")))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    resp.headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|c| c.to_str().ok())
        .find(|c| c.contains("__vauban_flash"))
        .and_then(|c| c.split(';').next())
        .map(str::to_string)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn battle_two_staff_decide_the_same_pending_under_contention() {
    let app = TestApp::spawn().await;
    let h = Harness::new(app).await;
    let (first, requester) = users(app).await;
    let mut conn = app.get_conn().await;
    let second =
        create_admin_user(&mut conn, &app.auth_service, &unique_name("test_hitl_ok2")).await;
    let csrf = app.generate_csrf_token();

    for _ in 0..20 {
        let pid = h.pending(&requester).await;
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let tasks: Vec<_> = [("approve", &first), ("deny", &second)]
            .into_iter()
            .map(|(decision, who)| {
                let (router, barrier) = (h.router.clone(), Arc::clone(&barrier));
                let (url, token, csrf) = (h.url(&pid, decision), who.token.clone(), csrf.clone());
                tokio::spawn(async move {
                    barrier.wait().await;
                    raw_decide(router, url, token, csrf).await
                })
            })
            .collect();
        let mut recorded = 0;
        for t in tasks {
            let flash = t
                .await
                .unwrap()
                .expect("every decision attempt sets a flash");
            let page = h
                .server
                .get("/sessions/mcp")
                .add_header(COOKIE, format!("access_token={}; {flash}", first.token))
                .await;
            if page.text().contains("recorded") {
                recorded += 1;
            }
        }
        let forwarded = h.forwarded().await;
        assert_eq!(
            forwarded.len(),
            1,
            "exactly one decision reaches the proxy: {forwarded:?}"
        );
        assert_eq!(
            recorded, 1,
            "exactly one staff member is told the decision was recorded"
        );
        assert!(h.client.get_hitl_pending(&pid).is_none());
    }
}

#[tokio::test]
#[serial]
async fn attack_cross_session_hitl_decision_is_rejected() {
    let app = TestApp::spawn().await;
    let h = Harness::new(app).await;
    let (approver, requester) = users(app).await;
    let csrf = app.generate_csrf_token();
    let pid = h.pending(&requester).await;

    let other_session = format!("/sessions/mcp/{}/{pid}/approve", Uuid::new_v4());
    h.server
        .post(&other_session)
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={csrf}", approver.token),
        )
        .form(&[("csrf_token", csrf.as_str())])
        .await;
    h.decide(
        &Uuid::new_v4().to_string(),
        "approve",
        &approver.token,
        &csrf,
        &csrf,
    )
    .await;

    assert!(h.forwarded().await.is_empty(), "nothing reaches the proxy");
    assert!(
        h.client.get_hitl_pending(&pid).is_some(),
        "the real pending stays decidable"
    );
}

async fn mails(app: &TestApp, kind: &str, to: &str) -> i64 {
    use diesel::{ExpressionMethods, QueryDsl};
    use diesel_async::RunQueryDsl;
    use vauban_web::schema::email_outbox;
    let mut conn = app.get_conn().await;
    email_outbox::table
        .filter(email_outbox::event_kind.eq(kind))
        .filter(email_outbox::recipient.eq(to))
        .count()
        .get_result(&mut conn)
        .await
        .unwrap()
}

async fn mails_eventually(app: &TestApp, kind: &str, to: &str) -> i64 {
    for _ in 0..50 {
        let n = mails(app, kind, to).await;
        if n > 0 {
            return n;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    0
}

#[tokio::test]
#[serial]
async fn mcp_hitl_mails_go_to_approvers_then_to_the_requester_once() {
    let app = TestApp::spawn().await;
    let h = Harness::with_mailer(app).await;
    let (approver, requester) = users(app).await;
    let csrf = app.generate_csrf_token();

    let pid = h.pending(&requester).await;
    assert_eq!(
        mails_eventually(app, "mcp.hitl_pending", &approver.user.email).await,
        1
    );
    assert_eq!(
        mails(app, "mcp.hitl_pending", &requester.user.email).await,
        0,
        "the requester is not asked to review their own call"
    );

    h.decide(&pid, "approve", &approver.token, &csrf, &csrf)
        .await;
    h.decide(&pid, "deny", &approver.token, &csrf, &csrf).await;
    assert_eq!(
        mails_eventually(app, "mcp.hitl_decided", &requester.user.email).await,
        1
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        mails(app, "mcp.hitl_decided", &requester.user.email).await,
        1,
        "one decision, one mail"
    );
    assert_eq!(
        mails(app, "mcp.hitl_decided", &approver.user.email).await,
        0
    );
}
