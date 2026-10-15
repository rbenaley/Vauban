//! Property: cutting an asset ends exactly its open visits.
//!
//! Random fleets of MCP assets, each with visits in random statuses (open
//! or not). One asset is deleted or has its upstream moved. Afterwards:
//!
//! 1. proxy-mcp was told to end exactly the open visits of that asset,
//!    each once and with the right reason;
//! 2. those rows are `terminated` with that reason; every other row keeps
//!    its status;
//! 3. cutting the same asset again sends nothing.
//!
//! Cases are drawn with a seeded `TestRunner` inside one Tokio test: the
//! shared `TestApp` pool must stay on a single runtime.
use crate::common::TestApp;
use crate::fixtures::{create_test_session_with_uuid, create_test_user, unique_name};
use diesel::{ExpressionMethods, QueryDsl};
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
use vauban_web::schema::{assets, proxy_sessions};
use vauban_web::services::session_termination::{
    REASON_ASSET_DELETED, REASON_ASSET_RECONFIGURED, terminate_open_sessions_on_asset,
};

const STATUSES: [&str; 10] = [
    "connecting",
    "active",
    "waiting_client",
    "suspended",
    "pending",
    "approved",
    "terminated",
    "disconnected",
    "failed",
    "orphaned",
];

#[derive(Debug, Clone)]
struct Case {
    /// Per asset, the status index of each of its visits.
    fleet: Vec<Vec<usize>>,
    target: usize,
    deleted: bool,
}

fn case_strategy() -> impl Strategy<Value = Case> {
    proptest::collection::vec(proptest::collection::vec(0..STATUSES.len(), 0..=5), 2..=4)
        .prop_flat_map(|fleet| {
            let n = fleet.len();
            (Just(fleet), 0..n, any::<bool>())
        })
        .prop_map(|(fleet, target, deleted)| Case {
            fleet,
            target,
            deleted,
        })
}

async fn drain(peer: &IpcChannel) -> Vec<(String, String)> {
    tokio::time::sleep(Duration::from_millis(100)).await;
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
    let owner = create_test_user(&mut conn, &app.auth_service, &unique_name("cutprop"))
        .await
        .user;
    let mut assets_ids = Vec::new();
    let mut visits: Vec<Vec<(Uuid, &str)>> = Vec::new();
    for statuses in &case.fleet {
        let asset_id: i32 = diesel::insert_into(assets::table)
            .values(&NewAsset {
                uuid: Uuid::new_v4(),
                name: unique_name("cutprop-asset"),
                hostname: format!("{}.cutprop.test", unique_name("h")),
                port: 19002,
                asset_type: AssetType::Mcp,
                status: "online".into(),
                description: None,
                connection_config: serde_json::json!({"mcp_upstream_tls_spki": "SHA256:x="}),
                created_by_id: Some(owner.id),
                updated_by_id: Some(owner.id),
                connection_username: String::new(),
            })
            .returning(assets::id)
            .get_result(&mut conn)
            .await
            .unwrap();
        let mut rows = Vec::new();
        for &s in statuses {
            let (_, uuid) =
                create_test_session_with_uuid(&mut conn, owner.id, asset_id, "mcp", STATUSES[s])
                    .await;
            rows.push((uuid, STATUSES[s]));
        }
        assets_ids.push(asset_id);
        visits.push(rows);
    }
    drop(conn);
    let _ = drain(mcp).await;

    let reason = if case.deleted {
        REASON_ASSET_DELETED
    } else {
        REASON_ASSET_RECONFIGURED
    };
    let target = assets_ids[case.target];
    let ended = terminate_open_sessions_on_asset(state, target, reason)
        .await
        .unwrap();

    let expected: BTreeSet<(String, String)> = visits[case.target]
        .iter()
        .filter(|(_, s)| SessionStatus::OPEN_AS_STR.contains(s))
        .map(|(u, _)| (u.to_string(), reason.to_string()))
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
    for (i, rows) in visits.iter().enumerate() {
        for (uuid, before) in rows {
            let (status, why): (String, Option<String>) = proxy_sessions::table
                .filter(proxy_sessions::uuid.eq(uuid))
                .select((proxy_sessions::status, proxy_sessions::termination_reason))
                .first(&mut conn)
                .await
                .unwrap();
            if i == case.target && SessionStatus::OPEN_AS_STR.contains(before) {
                assert_eq!(status, "terminated", "{case:?}");
                assert_eq!(why.as_deref(), Some(reason), "{case:?}");
            } else {
                assert_eq!(status, *before, "untouched row changed: {case:?}");
            }
        }
    }
    drop(conn);

    let again = terminate_open_sessions_on_asset(state, target, reason)
        .await
        .unwrap();
    assert_eq!(again, 0, "{case:?}");
    assert!(
        drain(mcp).await.is_empty(),
        "a second cut sends nothing: {case:?}"
    );
}

#[tokio::test]
#[serial]
async fn cutting_an_asset_ends_exactly_its_open_visits() {
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
        run_case(app, &state, &mcp, &case).await;
    }
}
