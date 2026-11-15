//! Property: changing one access rule ends exactly the open MCP visits it covers.
//!
//! Random users, assets, protocols and visits. One rule's user group and
//! asset group are chosen, or the rule targets every asset. Afterwards:
//!
//! 1. proxy-mcp was told to end exactly the open MCP visits in that cohort,
//!    each once, with the reason that carries the sentence;
//! 2. those rows are `terminated` and store the sentence;
//! 3. an SSH, RDP or tunnel visit in the same groups keeps its status, and
//!    so does a visit outside the cohort;
//! 4. changing the rule again sends nothing.
//!
//! Cases are drawn with a seeded `TestRunner` inside one Tokio test: the
//! shared `TestApp` pool must stay on a single runtime.
use crate::common::TestApp;
use crate::fixtures::{create_test_session_with_uuid, create_test_user, unique_name};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use proptest::prelude::*;
use proptest::strategy::ValueTree;
use proptest::test_runner::{Config, TestRunner};
use serial_test::serial;
use shared::ipc::IpcChannel;
use shared::messages::Message;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;
use vauban_web::ipc::ProxyMcpClient;
use vauban_web::models::asset::{AssetType, NewAsset};
use vauban_web::models::session::SessionStatus;
use vauban_web::schema::{asset_asset_groups, assets, proxy_sessions, user_groups};
use vauban_web::services::rule_revoke::{RuleCohort, revoke_sessions_for_rule_change};

const STATUSES: [&str; 8] = [
    "connecting",
    "active",
    "suspended",
    "pending",
    "terminated",
    "disconnected",
    "failed",
    "orphaned",
];

const PROTOCOLS: [&str; 4] = ["mcp", "ssh", "rdp", "iacs_tunnel"];

const RULE_NAME: &str = "Prop rule";

#[derive(Debug, Clone)]
struct Case {
    /// `(user in the rule's group, asset in the rule's group, status, protocol)`.
    visits: Vec<(bool, bool, usize, usize)>,
    all_assets: bool,
}

fn case_strategy() -> impl Strategy<Value = Case> {
    (
        proptest::collection::vec(
            (
                any::<bool>(),
                any::<bool>(),
                0..STATUSES.len(),
                0..PROTOCOLS.len(),
            ),
            1..=6,
        ),
        any::<bool>(),
    )
        .prop_map(|(visits, all_assets)| Case { visits, all_assets })
}

async fn drain(peer: &IpcChannel) -> Vec<(String, String)> {
    tokio::time::sleep(Duration::from_millis(80)).await;
    let mut out = Vec::new();
    while let Ok(m) = peer.try_recv() {
        if let Message::McpSessionTerminate {
            session_id, reason, ..
        } = m
        {
            out.push((session_id, reason));
        }
    }
    out.sort();
    out
}

async fn run_case(app: &TestApp, state: &vauban_web::AppState, mcp: &IpcChannel, case: &Case) {
    let mut conn = app.get_conn().await;
    let user_group = crate::fixtures::create_test_vauban_group(&mut conn, "revprop").await;
    let user_group_id = crate::fixtures::get_vauban_group_id(&mut conn, &user_group).await;
    let asset_group =
        crate::fixtures::create_test_asset_group(&mut conn, &unique_name("revprop")).await;
    let asset_group_id: i32 = vauban_web::schema::asset_groups::table
        .filter(vauban_web::schema::asset_groups::uuid.eq(asset_group))
        .select(vauban_web::schema::asset_groups::id)
        .first(&mut conn)
        .await
        .unwrap();

    let mut rows: Vec<(Uuid, bool, &str)> = Vec::new();
    for (user_in, asset_in, status_idx, protocol_idx) in &case.visits {
        let user = create_test_user(&mut conn, &app.auth_service, &unique_name("revprop"))
            .await
            .user;
        if *user_in {
            diesel::insert_into(user_groups::table)
                .values((
                    user_groups::user_id.eq(user.id),
                    user_groups::group_id.eq(user_group_id),
                ))
                .execute(&mut conn)
                .await
                .unwrap();
        }
        let asset_id: i32 = diesel::insert_into(assets::table)
            .values(&NewAsset {
                uuid: Uuid::new_v4(),
                name: unique_name("revprop-asset"),
                hostname: format!("{}.revprop.test", unique_name("h")),
                port: 19002,
                asset_type: AssetType::Mcp,
                status: "online".into(),
                description: None,
                connection_config: serde_json::json!({"mcp_upstream_tls_spki": "SHA256:x="}),
                created_by_id: Some(user.id),
                updated_by_id: Some(user.id),
                connection_username: String::new(),
            })
            .returning(assets::id)
            .get_result(&mut conn)
            .await
            .unwrap();
        if *asset_in {
            diesel::insert_into(asset_asset_groups::table)
                .values((
                    asset_asset_groups::asset_id.eq(asset_id),
                    asset_asset_groups::asset_group_id.eq(asset_group_id),
                ))
                .execute(&mut conn)
                .await
                .unwrap();
        }
        let status = STATUSES[*status_idx];
        let protocol = PROTOCOLS[*protocol_idx];
        let uuid = if protocol == "iacs_tunnel" {
            crate::fixtures::create_iacs_test_session_with_uuid(
                &mut conn, user.id, asset_id, status,
            )
            .await
            .1
        } else {
            create_test_session_with_uuid(&mut conn, user.id, asset_id, protocol, status)
                .await
                .1
        };
        let covered = protocol == "mcp" && *user_in && (case.all_assets || *asset_in);
        rows.push((uuid, covered, status));
    }
    drop(conn);
    let _ = drain(mcp).await;

    let asset_group_for_rule = if case.all_assets {
        vauban_web::services::virtual_group::virtual_asset_group_id()
    } else {
        asset_group_id
    };
    let ended = revoke_sessions_for_rule_change(
        state,
        RULE_NAME,
        &[RuleCohort {
            user_group_id,
            asset_group_id: asset_group_for_rule,
        }],
    )
    .await
    .unwrap();

    let wire = shared::access_rule_revoke::wire_reason(RULE_NAME);
    let sentence = shared::access_rule_revoke::sentence(RULE_NAME);
    let expected: BTreeSet<(String, String)> = rows
        .iter()
        .filter(|(_, covered, status)| *covered && SessionStatus::OPEN_AS_STR.contains(status))
        .map(|(uuid, _, _)| (uuid.to_string(), wire.clone()))
        .collect();
    let sent = drain(mcp).await;
    assert_eq!(
        sent.len(),
        expected.len(),
        "each open visit is told once: {case:?}"
    );
    assert_eq!(
        sent.into_iter().collect::<BTreeSet<_>>(),
        expected,
        "{case:?}"
    );
    assert_eq!(ended, expected.len(), "{case:?}");

    let mut conn = app.get_conn().await;
    for (uuid, covered, before) in &rows {
        let (status, why): (String, Option<String>) = proxy_sessions::table
            .filter(proxy_sessions::uuid.eq(uuid))
            .select((proxy_sessions::status, proxy_sessions::termination_reason))
            .first(&mut conn)
            .await
            .unwrap();
        if *covered && SessionStatus::OPEN_AS_STR.contains(before) {
            assert_eq!(status, "terminated", "{case:?}");
            assert_eq!(why.as_deref(), Some(sentence.as_str()), "{case:?}");
        } else {
            assert_eq!(status, *before, "untouched row changed: {case:?}");
        }
    }
    drop(conn);

    let again = revoke_sessions_for_rule_change(
        state,
        RULE_NAME,
        &[RuleCohort {
            user_group_id,
            asset_group_id: asset_group_for_rule,
        }],
    )
    .await
    .unwrap();
    assert_eq!(again, 0, "{case:?}");
    assert!(
        drain(mcp).await.is_empty(),
        "a second change sends nothing: {case:?}"
    );
}

#[tokio::test]
#[serial]
async fn an_empty_change_ends_nothing() {
    let app = TestApp::spawn().await;
    let mut state = app.app_state.clone();
    let (web_side, mcp) = IpcChannel::pair().unwrap();
    let client = ProxyMcpClient::new(web_side.read_fd(), web_side.write_fd()).unwrap();
    std::mem::forget(web_side);
    let pump = Arc::clone(&client);
    tokio::spawn(async move { pump.process_incoming().await });
    state.proxy_mcp = Some(Arc::clone(&client));
    client.set_runtime(state.clone());

    let ended = revoke_sessions_for_rule_change(&state, "unused", &[])
        .await
        .unwrap();
    assert_eq!(ended, 0);
    assert!(drain(&mcp).await.is_empty(), "no cohort, so no terminate");
}

#[tokio::test]
#[serial]
// `run_case` takes `&TestApp`. A function argument does not autoref, so
// `&app` is the type the signature requires. Clippy 1.99 still asks for `app`.
#[allow(clippy::needless_borrow)]
async fn changing_a_rule_ends_exactly_its_open_tickets() {
    let app = TestApp::spawn().await;
    let mut state = app.app_state.clone();
    let (web_side, mcp) = IpcChannel::pair().unwrap();
    let client = ProxyMcpClient::new(web_side.read_fd(), web_side.write_fd()).unwrap();
    std::mem::forget(web_side);
    let pump = Arc::clone(&client);
    tokio::spawn(async move { pump.process_incoming().await });
    state.proxy_mcp = Some(Arc::clone(&client));
    client.set_runtime(state.clone());

    let mut runner = TestRunner::new_with_rng(
        Config::with_cases(16),
        proptest::test_runner::TestRng::deterministic_rng(
            proptest::test_runner::RngAlgorithm::ChaCha,
        ),
    );
    let strategy = case_strategy();
    for _ in 0..16 {
        let case = strategy.new_tree(&mut runner).unwrap().current();
        run_case(&app, &state, &mcp, &case).await;
    }
}
