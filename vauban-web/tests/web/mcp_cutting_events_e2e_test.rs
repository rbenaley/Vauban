//! Cutting events end to end: an administrator takes access away in the
//! web UI and the proxies are told at once over a real IPC pair.
//!
//! Each fake proxy is an `IpcChannel` peer that records what web sends.
//! The test drives the real handlers through the router, then reads both
//! what reached the proxy and what landed in the database.
use crate::common::{TestApp, build_test_router};
use crate::fixtures::{TestUser, create_admin_user, create_test_session_with_uuid, unique_name};
use axum::http::header::COOKIE;
use axum_test::TestServer;
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::RunQueryDsl;
use serial_test::serial;
use shared::ipc::IpcChannel;
use shared::messages::Message;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;
use vauban_web::ipc::ProxyMcpClient;
use vauban_web::ipc::proxy_iacs::ProxyIacsClient;
use vauban_web::ipc::proxy_rdp::ProxyRdpClient;
use vauban_web::ipc::proxy_ssh::ProxySshClient;
use vauban_web::models::asset::{Asset, AssetType, NewAsset};
use vauban_web::models::session::ProxySession;
use vauban_web::schema::{assets, proxy_sessions};
use vauban_web::services::policy_recheck::{FailureTracker, recheck_tick};
use vauban_web::services::session_termination::{
    REASON_ASSET_DELETED, REASON_ASSET_RECONFIGURED, end_visits_on_reconfigured_asset,
    resend_lost_terminates,
};

const PIN: &str = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

/// Web wired to fake MCP, SSH and IACS proxies.
struct Bench {
    state: vauban_web::AppState,
    server: TestServer,
    mcp: IpcChannel,
    ssh: IpcChannel,
    rdp: IpcChannel,
    iacs: IpcChannel,
    admin: TestUser,
}

fn pair() -> (IpcChannel, IpcChannel) {
    IpcChannel::pair().unwrap()
}

impl Bench {
    async fn new(app: &TestApp) -> Self {
        Self::build(app, true).await
    }

    /// Same state, but proxy-mcp is unreachable: the first terminate is lost.
    async fn without_mcp_proxy(app: &TestApp) -> Self {
        Self::build(app, false).await
    }

    async fn build(app: &TestApp, with_mcp: bool) -> Self {
        let mut state = app.app_state.clone();

        let (web_mcp, mcp) = pair();
        let client = ProxyMcpClient::new(web_mcp.read_fd(), web_mcp.write_fd()).unwrap();
        std::mem::forget(web_mcp);
        let pump = Arc::clone(&client);
        tokio::spawn(async move { pump.process_incoming().await });
        state.proxy_mcp = with_mcp.then(|| Arc::clone(&client));
        client.set_runtime(state.clone());

        let (web_ssh, ssh) = pair();
        state.ssh_proxy = Some(ProxySshClient::new(web_ssh.read_fd(), web_ssh.write_fd()).unwrap());
        std::mem::forget(web_ssh);

        let (web_rdp, rdp) = pair();
        state.rdp_proxy = Some(ProxyRdpClient::new(web_rdp.read_fd(), web_rdp.write_fd()).unwrap());
        std::mem::forget(web_rdp);

        let (web_iacs, iacs) = pair();
        state.proxy_iacs =
            Some(ProxyIacsClient::new(web_iacs.read_fd(), web_iacs.write_fd()).unwrap());
        std::mem::forget(web_iacs);

        let mut conn = app.get_conn().await;
        let admin =
            create_admin_user(&mut conn, &app.auth_service, &unique_name("cut_admin")).await;
        let server = TestServer::new(build_test_router(state.clone())).unwrap();
        Self {
            state,
            server,
            mcp,
            ssh,
            rdp,
            iacs,
            admin,
        }
    }

    fn cookie(&self, csrf: &str) -> String {
        format!("access_token={}; __vauban_csrf={csrf}", self.admin.token)
    }

    async fn delete_asset(&self, app: &TestApp, asset: &Asset) -> u16 {
        let csrf = app.generate_csrf_token();
        self.server
            .post(&format!("/assets/manage/{}/delete", asset.uuid))
            .add_header(COOKIE, self.cookie(&csrf))
            .form(&[("csrf_token", csrf.as_str())])
            .await
            .status_code()
            .as_u16()
    }

    async fn edit_mcp_asset(&self, app: &TestApp, asset: &Asset, name: &str, pin: &str) {
        let csrf = app.generate_csrf_token();
        let port = asset.port.to_string();
        let r = self
            .server
            .post(&format!("/assets/manage/{}/edit", asset.uuid))
            .add_header(COOKIE, self.cookie(&csrf))
            .form(&[
                ("csrf_token", csrf.as_str()),
                ("name", name),
                ("hostname", asset.hostname.as_str()),
                ("port", port.as_str()),
                ("status", "online"),
                ("mcp_tls_spki", pin),
            ])
            .await;
        assert!(
            matches!(r.status_code().as_u16(), 302 | 303),
            "edit refused: {}",
            r.status_code()
        );
    }
}

/// Everything a fake proxy received, after a short wait for the IPC write.
async fn received(peer: &IpcChannel) -> Vec<Message> {
    tokio::time::sleep(Duration::from_millis(150)).await;
    let mut out = Vec::new();
    while let Ok(m) = peer.try_recv() {
        out.push(m);
    }
    out
}

fn mcp_terminates(msgs: &[Message]) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = msgs
        .iter()
        .filter_map(|m| match m {
            Message::McpSessionTerminate {
                session_id, reason, ..
            } => Some((session_id.clone(), reason.clone())),
            _ => None,
        })
        .collect();
    out.sort();
    out
}

async fn asset_of(app: &TestApp, owner: i32, asset_type: AssetType, port: i32) -> Asset {
    let mut conn = app.get_conn().await;
    let config = if asset_type == AssetType::Mcp {
        serde_json::json!({"mcp_upstream_tls_spki": PIN})
    } else {
        serde_json::json!({})
    };
    diesel::insert_into(assets::table)
        .values(&NewAsset {
            uuid: Uuid::new_v4(),
            name: unique_name("cut-asset"),
            hostname: format!("{}.cut.test", unique_name("h")),
            port,
            asset_type,
            status: "online".into(),
            description: None,
            connection_config: config,
            created_by_id: Some(owner),
            updated_by_id: Some(owner),
            connection_username: String::new(),
        })
        .get_result(&mut conn)
        .await
        .unwrap()
}

async fn session(app: &TestApp, user: i32, asset: &Asset, kind: &str, status: &str) -> Uuid {
    let mut conn = app.get_conn().await;
    create_test_session_with_uuid(&mut conn, user, asset.id, kind, status)
        .await
        .1
}

async fn load(app: &TestApp, uuid: Uuid) -> ProxySession {
    let mut conn = app.get_conn().await;
    proxy_sessions::table
        .filter(proxy_sessions::uuid.eq(uuid))
        .first(&mut conn)
        .await
        .unwrap()
}

#[tokio::test]
#[serial]
async fn gwt_deleting_an_asset_ends_its_live_and_suspended_mcp_visits() {
    let app = TestApp::spawn().await;
    let b = Bench::new(app).await;
    let owner = b.admin.user.id;
    let asset = asset_of(app, owner, AssetType::Mcp, 19002).await;
    let other = asset_of(app, owner, AssetType::Mcp, 19003).await;
    let live = session(app, owner, &asset, "mcp", "active").await;
    let paused = session(app, owner, &asset, "mcp", "suspended").await;
    let ended = session(app, owner, &asset, "mcp", "terminated").await;
    let pending = session(app, owner, &asset, "mcp", "pending").await;
    let elsewhere = session(app, owner, &other, "mcp", "active").await;

    assert!(matches!(b.delete_asset(app, &asset).await, 200 | 302 | 303));

    let mut expected = vec![
        (live.to_string(), REASON_ASSET_DELETED.to_string()),
        (paused.to_string(), REASON_ASSET_DELETED.to_string()),
    ];
    expected.sort();
    assert_eq!(
        mcp_terminates(&received(&b.mcp).await),
        expected,
        "proxy-mcp is told to end exactly the open visits of the deleted asset"
    );
    for sid in [live, paused] {
        let row = load(app, sid).await;
        assert_eq!(row.status, "terminated");
        assert_eq!(
            row.termination_reason.as_deref(),
            Some(REASON_ASSET_DELETED)
        );
        assert!(
            row.decision_id.is_some(),
            "the cut is a contestable decision"
        );
        assert!(row.disconnected_at.is_some());
    }
    assert_eq!(
        load(app, ended).await.termination_reason,
        None,
        "an ended visit is left alone"
    );
    assert_eq!(load(app, pending).await.status, "orphaned");
    assert_eq!(
        load(app, elsewhere).await.status,
        "active",
        "another asset is untouched"
    );
}

#[tokio::test]
#[serial]
async fn gwt_deleting_an_asset_closes_its_ssh_sessions_and_iacs_tunnels() {
    let app = TestApp::spawn().await;
    let b = Bench::new(app).await;
    let owner = b.admin.user.id;
    let ssh_asset = asset_of(app, owner, AssetType::Ssh, 22).await;
    let ssh_live = session(app, owner, &ssh_asset, "ssh", "active").await;
    let ssh_dialing = session(app, owner, &ssh_asset, "ssh", "connecting").await;

    assert!(matches!(
        b.delete_asset(app, &ssh_asset).await,
        200 | 302 | 303
    ));
    let mut closed: Vec<String> = received(&b.ssh)
        .await
        .into_iter()
        .filter_map(|m| match m {
            Message::SshSessionClose { session_id } => Some(session_id),
            _ => None,
        })
        .collect();
    closed.sort();
    let mut expected = vec![ssh_live.to_string(), ssh_dialing.to_string()];
    expected.sort();
    assert_eq!(closed, expected, "proxy-ssh closes every open session");
    for sid in [ssh_live, ssh_dialing] {
        assert_eq!(load(app, sid).await.status, "terminated");
    }

    let iacs_asset = {
        let mut conn = app.get_conn().await;
        let id =
            crate::fixtures::create_simple_iacs_asset(&mut conn, &unique_name("cut-iacs"), owner)
                .await;
        assets::table
            .filter(assets::id.eq(id))
            .first::<Asset>(&mut conn)
            .await
            .unwrap()
    };
    let tunnel = {
        let mut conn = app.get_conn().await;
        crate::fixtures::create_iacs_test_session_with_uuid(
            &mut conn,
            owner,
            iacs_asset.id,
            "tunnel_active",
        )
        .await
        .1
    };
    if app.app_state.config.industrial.enabled {
        assert!(matches!(
            b.delete_asset(app, &iacs_asset).await,
            200 | 302 | 303
        ));
        let terminated = received(&b.iacs).await.into_iter().any(|m| {
            matches!(m, Message::IacsTunnelTerminate { session_id, reason, .. }
                if session_id == tunnel.to_string() && reason == REASON_ASSET_DELETED)
        });
        assert!(terminated, "proxy-iacs is told to drop the tunnel");
        assert_eq!(load(app, tunnel).await.status, "terminated");
    }
}

#[tokio::test]
#[serial]
async fn gwt_deleting_an_asset_twice_sends_nothing_more() {
    let app = TestApp::spawn().await;
    let b = Bench::new(app).await;
    let owner = b.admin.user.id;
    let asset = asset_of(app, owner, AssetType::Mcp, 19002).await;
    let live = session(app, owner, &asset, "mcp", "active").await;

    b.delete_asset(app, &asset).await;
    assert_eq!(mcp_terminates(&received(&b.mcp).await).len(), 1);
    b.delete_asset(app, &asset).await;
    assert!(
        mcp_terminates(&received(&b.mcp).await).is_empty(),
        "a second delete finds no open visit"
    );
    assert_eq!(load(app, live).await.status, "terminated");
}

#[tokio::test]
#[serial]
async fn gwt_lost_terminate_is_resent_by_the_recheck() {
    let app = TestApp::spawn().await;
    let lost = Bench::without_mcp_proxy(app).await;
    let owner = lost.admin.user.id;
    let asset = asset_of(app, owner, AssetType::Mcp, 19002).await;
    let live = session(app, owner, &asset, "mcp", "active").await;
    let stale = session(app, owner, &asset, "mcp", "active").await;

    lost.delete_asset(app, &asset).await;
    assert_eq!(load(app, live).await.status, "terminated");
    {
        let mut conn = app.get_conn().await;
        diesel::update(proxy_sessions::table.filter(proxy_sessions::uuid.eq(stale)))
            .set(
                proxy_sessions::disconnected_at
                    .eq(chrono::Utc::now() - chrono::Duration::hours(24)),
            )
            .execute(&mut conn)
            .await
            .unwrap();
    }

    let ssh_asset = asset_of(app, owner, AssetType::Ssh, 22).await;
    let rdp_asset = asset_of(app, owner, AssetType::Rdp, 3389).await;
    let ssh = session(app, owner, &ssh_asset, "ssh", "active").await;
    let rdp = session(app, owner, &rdp_asset, "rdp", "active").await;
    lost.delete_asset(app, &ssh_asset).await;
    lost.delete_asset(app, &rdp_asset).await;

    let b = Bench::new(app).await;
    let (_, _, resent) = recheck_tick(&b.state, &mut FailureTracker::default()).await;
    assert!(resent >= 3, "the recheck resends every lost close");
    let cut = mcp_terminates(&received(&b.mcp).await);
    assert!(
        cut.contains(&(live.to_string(), REASON_ASSET_DELETED.to_string())),
        "the lost terminate reaches proxy-mcp on the next pass: {cut:?}"
    );
    assert!(
        !cut.iter().any(|(sid, _)| *sid == stale.to_string()),
        "a visit that could no longer be alive is not resent"
    );
    let ssh_closed = received(&b.ssh).await.into_iter().any(
        |m| matches!(m, Message::SshSessionClose { session_id } if session_id == ssh.to_string()),
    );
    let rdp_closed = received(&b.rdp).await.into_iter().any(
        |m| matches!(m, Message::RdpSessionClose { session_id } if session_id == rdp.to_string()),
    );
    assert!(
        ssh_closed && rdp_closed,
        "SSH and RDP closes are resent too"
    );
}

#[tokio::test]
#[serial]
async fn gwt_lost_access_recheck_terminate_is_resent() {
    use vauban_web::schema::users;
    let app = TestApp::spawn().await;
    let lost = Bench::without_mcp_proxy(app).await;
    let asset = asset_of(app, lost.admin.user.id, AssetType::Mcp, 19002).await;
    let agent = {
        let mut conn = app.get_conn().await;
        crate::fixtures::create_test_user(&mut conn, &app.auth_service, &unique_name("cut_agent"))
            .await
            .user
            .id
    };
    let visit = session(app, agent, &asset, "mcp", "active").await;
    {
        let mut conn = app.get_conn().await;
        diesel::update(users::table.filter(users::id.eq(agent)))
            .set(users::is_active.eq(false))
            .execute(&mut conn)
            .await
            .unwrap();
    }

    vauban_web::services::mcp_recheck::run_once(&lost.state).await;
    assert_eq!(load(app, visit).await.status, "terminated");

    let b = Bench::new(app).await;
    recheck_tick(&b.state, &mut FailureTracker::default()).await;
    let cut = mcp_terminates(&received(&b.mcp).await);
    assert!(
        cut.contains(&(visit.to_string(), "user_inactive".to_string())),
        "a terminate lost by the access recheck reaches proxy-mcp on the next pass: {cut:?}"
    );
}

#[tokio::test]
#[serial]
async fn gwt_an_unreachable_database_is_logged_not_fatal() {
    use diesel_async::AsyncPgConnection;
    use diesel_async::pooled_connection::AsyncDieselConnectionManager;
    use diesel_async::pooled_connection::deadpool::Pool;
    let app = TestApp::spawn().await;
    let mut state = app.app_state.clone();
    state.db_pool = Pool::builder(AsyncDieselConnectionManager::<AsyncPgConnection>::new(
        "postgresql://nobody:none@127.0.0.1:1/none",
    ))
    .max_size(1)
    .build()
    .unwrap();
    assert_eq!(resend_lost_terminates(&state).await, 0);
    end_visits_on_reconfigured_asset(&state, 1).await;
}

/// Each grant change, web and API, recomputes the live visit at once:
/// the fake proxy-mcp receives an update or a terminate for it.
#[tokio::test]
#[serial]
async fn gwt_every_grant_change_reaches_live_visits_without_waiting() {
    use crate::fixtures::{create_real_api_key, get_vauban_group_id};
    use vauban_web::models::api_key::ApiKeyScope;
    use vauban_web::schema::{asset_groups, users};
    let app = TestApp::spawn().await;
    let b = Bench::new(app).await;
    let owner = b.admin.user.id;
    let api_key = {
        let mut conn = app.get_conn().await;
        create_real_api_key(&mut conn, owner, &[ApiKeyScope::Admin], None)
            .await
            .1
    };
    let reached = async |visit: Uuid| {
        received(&b.mcp).await.iter().any(|m| match m {
            Message::McpSessionUpdate { session_id, .. }
            | Message::McpSessionTerminate { session_id, .. } => *session_id == visit.to_string(),
            _ => false,
        })
    };
    let ids = async |g: &Granted| {
        let mut conn = app.get_conn().await;
        let ug: Uuid = users::table
            .filter(users::id.eq(g.agent))
            .select(users::uuid)
            .first(&mut conn)
            .await
            .unwrap();
        let ag_id: i32 = asset_groups::table
            .filter(asset_groups::uuid.eq(g.asset_group))
            .select(asset_groups::id)
            .first(&mut conn)
            .await
            .unwrap();
        (ug, ag_id)
    };
    let api = |req: axum_test::TestRequest| {
        req.add_header(
            axum::http::header::AUTHORIZATION,
            app.api_key_header(&api_key),
        )
    };

    // Web: a new rule for the same groups, then editing the agent's rule.
    let g = granted_visit(app, owner).await;
    let _ = received(&b.mcp).await;
    let (users_group, ag_id) = {
        let mut conn = app.get_conn().await;
        let users_group = crate::fixtures::create_test_vauban_group(&mut conn, "cut_other").await;
        (
            get_vauban_group_id(&mut conn, &users_group).await,
            ids(&g).await.1,
        )
    };
    let csrf = app.generate_csrf_token();
    b.server
        .post("/assets/access")
        .add_header(COOKIE, b.cookie(&csrf))
        .form(&serde_json::json!({
            "csrf_token": csrf, "name": unique_name("cut-new-rule"),
            "user_group_id": users_group, "asset_group_id": ag_id,
            "allowed_ssh": "true", "is_active": "true",
        }))
        .await;
    assert!(
        reached(g.visit).await,
        "creating a rule recomputes live visits"
    );

    let g = granted_visit(app, owner).await;
    let _ = received(&b.mcp).await;
    let (rule_ug, rule_ag): (i32, i32) = {
        use vauban_web::schema::access_rules;
        let mut conn = app.get_conn().await;
        access_rules::table
            .filter(access_rules::uuid.eq(g.rule))
            .select((access_rules::user_group_id, access_rules::asset_group_id))
            .first(&mut conn)
            .await
            .unwrap()
    };
    let csrf = app.generate_csrf_token();
    b.server
        .post(&format!("/assets/access/{}/edit", g.rule))
        .add_header(COOKIE, b.cookie(&csrf))
        .form(&serde_json::json!({
            "csrf_token": csrf, "name": unique_name("cut-edited"),
            "user_group_id": rule_ug, "asset_group_id": rule_ag,
            "allowed_ssh": "true", "is_active": "true",
        }))
        .await;
    assert!(
        reached(g.visit).await,
        "editing the rule recomputes live visits"
    );

    // Web: adding an asset to the group, deleting the group, adding a member.
    let g = granted_visit(app, owner).await;
    let _ = received(&b.mcp).await;
    let extra = asset_of(app, owner, AssetType::Ssh, 22).await;
    let csrf = app.generate_csrf_token();
    let body = format!("csrf_token={csrf}&asset_uuids={}", extra.uuid);
    b.server
        .post(&format!(
            "/assets/manage/groups/{}/add-asset",
            g.asset_group
        ))
        .add_header(COOKIE, b.cookie(&csrf))
        .content_type("application/x-www-form-urlencoded")
        .bytes(body.into())
        .await;
    assert!(
        reached(g.visit).await,
        "adding an asset to the group recomputes live visits"
    );

    let g = granted_visit(app, owner).await;
    let _ = received(&b.mcp).await;
    let csrf = app.generate_csrf_token();
    b.server
        .post(&format!("/assets/manage/groups/{}/delete", g.asset_group))
        .add_header(COOKIE, b.cookie(&csrf))
        .form(&[("csrf_token", csrf.as_str())])
        .await;
    assert!(
        reached(g.visit).await,
        "deleting the asset group recomputes live visits"
    );

    let g = granted_visit(app, owner).await;
    let _ = received(&b.mcp).await;
    let (team, newcomer) = {
        let mut conn = app.get_conn().await;
        let team = crate::fixtures::create_test_vauban_group(&mut conn, "cut_team").await;
        let newcomer = crate::fixtures::create_test_user(
            &mut conn,
            &app.auth_service,
            &unique_name("cut_new"),
        )
        .await
        .user
        .uuid;
        (team, newcomer)
    };
    let csrf = app.generate_csrf_token();
    b.server
        .post(&format!("/accounts/groups/{team}/members"))
        .add_header(COOKIE, b.cookie(&csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("user_uuid", newcomer.to_string().as_str()),
        ])
        .await;
    assert!(
        reached(g.visit).await,
        "adding a group member recomputes live visits"
    );

    // API: create, update, delete a rule.
    let g = granted_visit(app, owner).await;
    let _ = received(&b.mcp).await;
    let other_users = {
        let mut conn = app.get_conn().await;
        crate::fixtures::create_test_vauban_group(&mut conn, "cut_api").await
    };
    let r = api(b.server.post("/api/v1/access-rules"))
        .json(&serde_json::json!({
            "name": unique_name("cut-api-rule"),
            "user_group_uuid": other_users.to_string(),
            "asset_group_uuid": g.asset_group.to_string(),
            "allowed_protocols": ["ssh"],
        }))
        .await;
    assert_eq!(r.status_code().as_u16(), 200, "{}", r.text());
    assert!(
        reached(g.visit).await,
        "creating a rule over the API recomputes live visits"
    );

    let g = granted_visit(app, owner).await;
    let _ = received(&b.mcp).await;
    let r = api(b.server.put(&format!("/api/v1/access-rules/{}", g.rule)))
        .json(&serde_json::json!({ "allowed_protocols": ["ssh"] }))
        .await;
    assert_eq!(r.status_code().as_u16(), 200, "{}", r.text());
    assert!(
        reached(g.visit).await,
        "editing a rule over the API recomputes live visits"
    );

    let g = granted_visit(app, owner).await;
    let _ = received(&b.mcp).await;
    let r = api(b.server.delete(&format!("/api/v1/access-rules/{}", g.rule))).await;
    assert_eq!(r.status_code().as_u16(), 200, "{}", r.text());
    assert!(
        reached(g.visit).await,
        "deleting a rule over the API recomputes live visits"
    );
}

#[tokio::test]
#[serial]
async fn gwt_moving_an_mcp_upstream_over_the_api_ends_its_visits() {
    use crate::fixtures::create_real_api_key;
    use vauban_web::models::api_key::ApiKeyScope;
    let app = TestApp::spawn().await;
    let b = Bench::new(app).await;
    let owner = b.admin.user.id;
    let api_key = {
        let mut conn = app.get_conn().await;
        create_real_api_key(&mut conn, owner, &[ApiKeyScope::Admin], None)
            .await
            .1
    };
    let asset = asset_of(app, owner, AssetType::Mcp, 19002).await;
    let live = session(app, owner, &asset, "mcp", "active").await;
    let put = async |body: serde_json::Value| {
        b.server
            .put(&format!("/api/v1/assets/manage/{}", asset.uuid))
            .add_header(
                axum::http::header::AUTHORIZATION,
                app.api_key_header(&api_key),
            )
            .json(&body)
            .await
            .status_code()
            .as_u16()
    };

    assert_eq!(
        put(serde_json::json!({ "name": unique_name("cut-renamed") })).await,
        200
    );
    assert!(
        mcp_terminates(&received(&b.mcp).await).is_empty(),
        "a rename ends nothing"
    );

    assert_eq!(put(serde_json::json!({ "port": 19004 })).await, 200);
    assert_eq!(
        mcp_terminates(&received(&b.mcp).await),
        vec![(live.to_string(), REASON_ASSET_RECONFIGURED.to_string())],
        "a new port ends the visits still talking to the old one"
    );
}

#[tokio::test]
#[serial]
async fn gwt_changing_the_pin_ends_visits_but_renaming_does_not() {
    let app = TestApp::spawn().await;
    let b = Bench::new(app).await;
    let owner = b.admin.user.id;
    let asset = asset_of(app, owner, AssetType::Mcp, 19002).await;
    let live = session(app, owner, &asset, "mcp", "active").await;

    b.edit_mcp_asset(app, &asset, &unique_name("renamed"), PIN)
        .await;
    assert!(
        mcp_terminates(&received(&b.mcp).await).is_empty(),
        "renaming keeps the upstream: visits keep running"
    );
    assert_eq!(load(app, live).await.status, "active");

    let rotated = format!("SHA256:{}A=", "B".repeat(42));
    b.edit_mcp_asset(app, &asset, &unique_name("renamed"), &rotated)
        .await;
    assert_eq!(
        mcp_terminates(&received(&b.mcp).await),
        vec![(live.to_string(), REASON_ASSET_RECONFIGURED.to_string())],
        "a new pin ends the visits still holding the old one"
    );
    let row = load(app, live).await;
    assert_eq!(row.status, "terminated");
    assert_eq!(
        row.termination_reason.as_deref(),
        Some(REASON_ASSET_RECONFIGURED)
    );
}

#[tokio::test]
#[serial]
async fn attack_tools_call_after_asset_deleted_never_reaches_the_proxy_as_live() {
    // The attacker keeps calling with the old `vbw_` after the admin
    // deleted the asset. Web's half of the guarantee: the proxy has been
    // told to drop the visit, and hop 1 refuses to open a new one.
    let app = TestApp::spawn().await;
    let b = Bench::new(app).await;
    let owner = b.admin.user.id;
    let asset = asset_of(app, owner, AssetType::Mcp, 19002).await;
    let live = session(app, owner, &asset, "mcp", "active").await;
    b.delete_asset(app, &asset).await;
    assert_eq!(
        mcp_terminates(&received(&b.mcp).await),
        vec![(live.to_string(), REASON_ASSET_DELETED.to_string())]
    );
    let mut conn = app.get_conn().await;
    let gone: bool = assets::table
        .filter(assets::id.eq(asset.id))
        .select(assets::is_deleted)
        .first(&mut conn)
        .await
        .unwrap();
    assert!(
        gone,
        "hop 1 filters on is_deleted, so no new visit can open"
    );
}

/// An agent in a user group reaches an MCP asset in an asset group through
/// one access rule, and holds a live visit on it.
struct Granted {
    agent: i32,
    asset_uuid: Uuid,
    asset_group: Uuid,
    rule: Uuid,
    visit: Uuid,
}

async fn granted_visit(app: &TestApp, owner: i32) -> Granted {
    use crate::fixtures::{
        add_user_to_vauban_group, create_test_access_rule, create_test_asset_group,
        create_test_asset_in_group_with_type, create_test_user, create_test_vauban_group,
    };
    let mut conn = app.get_conn().await;
    let agent = create_test_user(&mut conn, &app.auth_service, &unique_name("cut_agent"))
        .await
        .user
        .id;
    let users = create_test_vauban_group(&mut conn, "cut_users").await;
    add_user_to_vauban_group(&mut conn, agent, &users).await;
    let asset_group = create_test_asset_group(&mut conn, &unique_name("cut-ag")).await;
    let asset_id = create_test_asset_in_group_with_type(
        &mut conn,
        &unique_name("cut-mcp"),
        owner,
        &asset_group,
        AssetType::Mcp,
    )
    .await;
    let rule = create_test_access_rule(&mut conn, &users, &asset_group, &["mcp"]).await;
    let asset_uuid = assets::table
        .filter(assets::id.eq(asset_id))
        .select(assets::uuid)
        .first(&mut conn)
        .await
        .unwrap();
    let visit = create_test_session_with_uuid(&mut conn, agent, asset_id, "mcp", "active")
        .await
        .1;
    Granted {
        agent,
        asset_uuid,
        asset_group,
        rule,
        visit,
    }
}

fn cut_visits(msgs: &[Message]) -> Vec<String> {
    mcp_terminates(msgs)
        .into_iter()
        .map(|(sid, _)| sid)
        .collect()
}

#[tokio::test]
#[serial]
async fn attack_access_rule_delete_cuts_without_waiting() {
    // The admin deletes the only rule; the agent must not keep calling
    // tools until the 30 s check comes round.
    let app = TestApp::spawn().await;
    let b = Bench::new(app).await;
    let g = granted_visit(app, b.admin.user.id).await;
    let _ = received(&b.mcp).await;

    let csrf = app.generate_csrf_token();
    let r = b
        .server
        .post(&format!("/assets/access/{}/delete", g.rule))
        .add_header(COOKIE, b.cookie(&csrf))
        .form(&[("csrf_token", csrf.as_str())])
        .await;
    assert!(
        matches!(r.status_code().as_u16(), 200 | 302 | 303),
        "{}",
        r.status_code()
    );

    assert!(
        cut_visits(&received(&b.mcp).await).contains(&g.visit.to_string()),
        "deleting the rule ends the visit at once (agent {})",
        g.agent
    );
    assert_eq!(load(app, g.visit).await.status, "terminated");
}

#[tokio::test]
#[serial]
async fn attack_asset_removed_from_group_cuts_without_waiting() {
    let app = TestApp::spawn().await;
    let b = Bench::new(app).await;
    let g = granted_visit(app, b.admin.user.id).await;
    let _ = received(&b.mcp).await;

    let csrf = app.generate_csrf_token();
    let asset_uuid = g.asset_uuid.to_string();
    let r = b
        .server
        .post(&format!(
            "/assets/manage/groups/{}/remove-asset",
            g.asset_group
        ))
        .add_header(COOKIE, b.cookie(&csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("asset_uuid", asset_uuid.as_str()),
        ])
        .await;
    assert!(
        matches!(r.status_code().as_u16(), 200 | 302 | 303),
        "{}",
        r.status_code()
    );

    assert!(
        cut_visits(&received(&b.mcp).await).contains(&g.visit.to_string()),
        "taking the asset out of its group ends the visit at once"
    );
    assert_eq!(load(app, g.visit).await.status, "terminated");
}

#[tokio::test]
#[serial]
async fn attack_hitl_pending_on_deleted_asset_cannot_be_approved() {
    // A pending HITL call on the visit dies with it: web drops the visit's
    // pendings when it sends the terminate, so the approve button finds
    // nothing to forward (and proxy-mcp clears its own copy too).
    let app = TestApp::spawn().await;
    let b = Bench::new(app).await;
    let owner = b.admin.user.id;
    let asset = asset_of(app, owner, AssetType::Mcp, 19002).await;
    let live = session(app, owner, &asset, "mcp", "active").await;
    let client = b.state.proxy_mcp.clone().unwrap();
    let pending_id = Uuid::new_v4().to_string();
    b.mcp
        .send(&Message::McpHitlPendingNotify {
            session_id: live.to_string(),
            pending_id: pending_id.clone(),
            tool: "delete_task".into(),
            args_blake3: "00".into(),
            expires_at: (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
            requester_user_id: Uuid::new_v4().to_string(),
            requester_api_key_id: String::new(),
            plan_contract_json: String::new(),
            plan_story_json: String::new(),
            mandate_id: String::new(),
            sealed_digest: String::new(),
        })
        .unwrap();
    for _ in 0..50 {
        if client.get_hitl_pending(&pending_id).is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    b.delete_asset(app, &asset).await;
    let _ = received(&b.mcp).await;

    let csrf = app.generate_csrf_token();
    b.server
        .post(&format!("/sessions/mcp/{live}/{pending_id}/approve"))
        .add_header(COOKIE, b.cookie(&csrf))
        .form(&[("csrf_token", csrf.as_str())])
        .await;
    let forwarded = received(&b.mcp).await.into_iter().any(|m| {
        matches!(m, Message::McpHitlDecision { pending_id: p, decision, .. }
            if p == pending_id && decision == "approve")
    });
    assert!(
        !forwarded,
        "an approval for a visit cut by the asset deletion must not reach the proxy"
    );
}
