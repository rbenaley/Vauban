//! Wire layer of the proxy: what agents and the recording reader see.
//! JSON-RPC codes, the `arguments.vauban` schema advertised on Require plan
//! tools, and the session JSONL / meta field names are consumed outside
//! this crate (agents, lab clients, `vauban-web-evidence`, auditors).
//! Changing any value pinned here is a protocol break, not a refactor.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use crate::mcp_fix_e2e_tests::E2e;
use crate::test_upstream::Mode;
use std::collections::BTreeSet;

#[test]
fn json_rpc_error_codes_are_frozen() {
    assert_eq!(rpc_codes::TOOL_NOT_ALLOWED, -32001);
    assert_eq!(rpc_codes::TOOL_PENDING_OR_DRIFT, -32002);
    assert_eq!(rpc_codes::SESSION_UNKNOWN, -32003);
    assert_eq!(rpc_codes::SESSION_TERMINATED, -32004);
    assert_eq!(rpc_codes::UPSTREAM_OR_RECORDING, -32010);
    assert_eq!(rpc_codes::RATE_LIMITED, -32029);
    assert_eq!(rpc_codes::APPROVAL_REQUIRED, -32030);
    assert_eq!(rpc_codes::SESSION_SUSPENDED, -32031);
    assert_eq!(rpc_codes::HITL_DENIED, -32032);
    assert_eq!(mandate::ERR_MANDATE_STEP_DENIED, -32033);
    assert_eq!(mandate::ERR_MISSION_EXPIRED, -32034);
    assert_eq!(rpc_codes::INVALID_REQUEST, -32600);
    assert_eq!(rpc_codes::METHOD_NOT_FOUND, -32601);
    assert_eq!(rpc_codes::INVALID_PARAMS, -32602);
}

/// Web's cut reasons travel verbatim into the recording's `session_end`,
/// which auditors read to tell a deleted asset from a moved upstream.
#[tokio::test]
async fn asset_cut_reasons_reach_the_recording_verbatim() {
    for reason in ["asset_deleted", "asset_reconfigured"] {
        let e = E2e::start(Mode::default()).await;
        handle_mcp_session_terminate(
            &e.state,
            Message::McpSessionTerminate {
                request_id: 1,
                session_id: e.sid.clone(),
                reason: reason.into(),
            },
        );
        let mut end = None;
        for _ in 0..100 {
            end = e.jsonl().into_iter().find(|v| v["event"] == "session_end");
            if end.is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let end = end.unwrap_or_else(|| panic!("{reason}: no session_end"));
        assert_eq!(end["reason"], reason);
    }
}

fn keys(v: &Value) -> BTreeSet<String> {
    v.as_object()
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default()
}

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| s.to_string()).collect()
}

/// The agent DTO: Story (four prose fields) + Contract (mission approval,
/// literal steps). Agents build their first Require plan call from it.
#[test]
fn vauban_plan_schema_shape_is_frozen() {
    let s = agent_view::vauban_plan_schema();
    assert_eq!(agent_view::VAUBAN_ARGS_KEY, "vauban");
    assert_eq!(s["required"], json!(["story", "contract"]));
    assert_eq!(s["additionalProperties"], false);
    let story = &s["properties"]["story"];
    assert_eq!(
        story["required"],
        json!(["summary", "context", "objective", "risks"])
    );
    for (field, max) in [
        ("summary", 200),
        ("context", 500),
        ("objective", 500),
        ("risks", 500),
    ] {
        assert_eq!(story["properties"][field]["minLength"], 10, "{field}");
        assert_eq!(story["properties"][field]["maxLength"], max, "{field}");
    }
    let contract = &s["properties"]["contract"];
    assert_eq!(contract["required"], json!(["approval", "steps"]));
    assert_eq!(
        contract["properties"]["approval"]["enum"],
        json!(["mission"])
    );
    assert_eq!(contract["properties"]["steps"]["maxItems"], 64);
    let step = &contract["properties"]["steps"]["items"];
    assert_eq!(
        step["required"],
        json!(["step_id", "operation", "intent", "mode", "arguments"])
    );
    assert_eq!(step["properties"]["mode"]["enum"], json!(["literal"]));
}

/// Hop 2 `tools/list` is the only machine catalogue: a Require plan tool
/// carries `arguments.vauban` in its input schema, an Allow tool does not.
#[tokio::test]
async fn require_plan_tool_advertises_arguments_vauban() {
    let e = E2e::start_with(Mode::default(), |s| {
        s.tool_constraints.insert(
            "delete_task".into(),
            tool_constraints::ToolConstraint {
                input_schema: json!({"type": "object"}),
                hitl: true,
                require_plan: true,
                ..Default::default()
            },
        );
    })
    .await;
    let (_, list) = e.rpc("tools/list", json!({})).await;
    let tools = list["result"]["tools"].as_array().unwrap();
    let by_name = |n: &str| tools.iter().find(|t| t["name"] == n).unwrap().clone();
    let plan = by_name("delete_task");
    assert_eq!(
        keys(&plan["inputSchema"]["properties"]["vauban"]["properties"]),
        set(&["story", "contract"]),
        "{plan}"
    );
    assert!(
        plan["description"]
            .as_str()
            .unwrap()
            .contains("arguments.vauban.story")
    );
    let allow = by_name("echo");
    assert!(
        allow["inputSchema"]["properties"].get("vauban").is_none(),
        "{allow}"
    );
}

/// Field names of every JSONL event of a relayed visit, and of the sealed
/// `meta.json`. `vauban-web-evidence` and auditors parse these by name.
#[tokio::test]
async fn session_jsonl_and_meta_fields_are_frozen() {
    let e = E2e::start(Mode::default()).await;
    e.rpc("initialize", json!({"protocolVersion": "2025-03-26"}))
        .await;
    e.rpc("tools/list", json!({})).await;
    e.call("echo", json!({"msg": "wire"})).await;
    e.call("not_allowed", json!({})).await;
    let stats = e
        .state
        .audit
        .recording()
        .finalize(&e.sid, "wire_test", false)
        .await
        .unwrap();

    let events = e.jsonl();
    let shape = |event: &str, phase: Option<&str>| -> BTreeSet<String> {
        let ev = events
            .iter()
            .find(|v| v["event"] == event && phase.is_none_or(|p| v["phase"] == p))
            .unwrap_or_else(|| panic!("no {event} {phase:?} in {events:?}"));
        keys(ev)
    };
    let base = ["ts", "session_id", "event"];
    let with = |extra: &[&str]| set(&[&base[..], extra].concat());
    assert_eq!(shape("session_open", None), with(&[]));
    assert_eq!(shape("initialize", None), with(&["decision"]));
    assert_eq!(shape("tools/list", None), with(&["decision"]));
    assert_eq!(
        shape("tools/call", Some("intent")),
        with(&["phase", "tool_name", "decision", "args"])
    );
    assert_eq!(
        shape("tools/call", Some("result")),
        with(&["phase", "tool_name", "outcome", "reason_code", "response"])
    );
    let deny = events
        .iter()
        .find(|v| v["event"] == "tools/call" && v["decision"] == "deny")
        .unwrap();
    assert_eq!(
        keys(deny),
        with(&["tool_name", "decision", "reason_code", "args", "response"])
    );
    assert_eq!(shape("session_end", None), with(&["reason", "partial"]));

    let meta: Value =
        serde_json::from_str(&std::fs::read_to_string(e.dir.join(&stats.relative_meta)).unwrap())
            .unwrap();
    assert_eq!(meta["format"], "mcp-jsonl-v1");
    assert_eq!(meta["playback"], "asciicast-v2");
    assert_eq!(meta["payload_encoding"], "json-events-v1");
    assert_eq!(
        keys(&meta),
        set(&[
            "format",
            "playback",
            "payload_encoding",
            "blake3_hex",
            "cast_blake3_hex",
            "cast_path",
            "equivalence_verified",
            "total_bytes",
            "total_events",
            "duration_ms",
            "partial",
        ])
    );
    assert_eq!(meta["equivalence_verified"], true);
}
