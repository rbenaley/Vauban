//! WIRE COMPATIBILITY pins for the MCP feature (ADR 004, flat append-only
//! enums over bincode). A variant index or a field order change here
//! silently breaks a mixed-version appliance (web, proxy-mcp, access,
//! supervisor) and every persisted WORM record: append, never reorder.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use serde::Serialize;
use serde::de::DeserializeOwned;
use shared::messages::{AccessRequest, AccessResponse, AuditEventType, Message, ServiceStats};

fn encode<T: Serialize>(v: &T) -> Vec<u8> {
    bincode::serde::encode_to_vec(v, bincode::config::standard()).unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Encoded bytes start with the frozen variant index (single-byte varint
/// below 251) and survive a decode / re-encode round trip.
fn assert_frozen<T: Serialize + DeserializeOwned>(name: &str, v: &T, index: u8) -> Vec<u8> {
    let bytes = encode(v);
    assert_eq!(bytes[0], index, "{name}: variant index moved");
    let (back, used): (T, usize) =
        bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
    assert_eq!(used, bytes.len(), "{name}: trailing bytes");
    assert_eq!(encode(&back), bytes, "{name}: round trip changed the bytes");
    bytes
}

fn pin(b: u8) -> [u8; 32] {
    [b; 32]
}

fn mcp_messages() -> Vec<(&'static str, Message, u8, &'static str)> {
    vec![
        (
            "McpSessionOpen",
            Message::McpSessionOpen {
                request_id: 1,
                ipc_version: 1,
                session_id: "s".into(),
                asset_id: "a".into(),
                user_id: "u".into(),
                api_key_id: "k".into(),
                expires_at: "e".into(),
                vbw_hash: pin(7),
                allowed_tools: Some(vec!["t".into()]),
                tool_constraints_json: "{}".into(),
                envelope_max_calls: 2,
                envelope_window_seconds: 3,
                envelope_on_exceed: "x".into(),
                upstream_host: "h".into(),
                upstream_port: 443,
                upstream_tls_spki_pin: Some("p".into()),
                forward_identity_headers: true,
                credential_blob: vec![9],
                justification: "j".into(),
                max_body_bytes: 4,
                session_token: vec![8],
                transport: "d".into(),
                require_seal: true,
                recording_open_unix: 5,
            },
            40,
            "280101017301610175016b0165070707070707070707070707070707070707070707070707070707070707070701010174027b7d020301780168fbbb01010170010109016a04010801640105",
        ),
        (
            "McpSessionOpened",
            Message::McpSessionOpened {
                request_id: 1,
                session_id: "s".into(),
                success: false,
                error: Some("e".into()),
            },
            41,
            "2901017300010165",
        ),
        (
            "McpSessionUpdate",
            Message::McpSessionUpdate {
                request_id: 1,
                session_id: "s".into(),
                allowed_tools: None,
                tool_constraints_json: "{}".into(),
                envelope_max_calls: 2,
                envelope_window_seconds: 3,
                envelope_on_exceed: "x".into(),
                expires_at: Some("e".into()),
            },
            42,
            "2a01017300027b7d02030178010165",
        ),
        (
            "McpSessionTerminate",
            Message::McpSessionTerminate {
                request_id: 1,
                session_id: "s".into(),
                reason: "r".into(),
            },
            43,
            "2b0101730172",
        ),
        (
            "McpSessionSuspend",
            Message::McpSessionSuspend {
                request_id: 1,
                session_id: "s".into(),
                reason: "r".into(),
                actor_user_id: "u".into(),
            },
            44,
            "2c01017301720175",
        ),
        (
            "McpSessionResume",
            Message::McpSessionResume {
                request_id: 1,
                session_id: "s".into(),
                actor_user_id: "u".into(),
            },
            45,
            "2d0101730175",
        ),
        (
            "McpHitlDecision",
            Message::McpHitlDecision {
                request_id: 1,
                session_id: "s".into(),
                pending_id: "p".into(),
                decision: "approve".into(),
                actor_user_id: "u".into(),
            },
            46,
            "2e010173017007617070726f76650175",
        ),
        (
            "McpHitlPendingNotify",
            Message::McpHitlPendingNotify {
                session_id: "s".into(),
                pending_id: "p".into(),
                tool: "t".into(),
                args_blake3: "b".into(),
                expires_at: "e".into(),
                requester_user_id: "u".into(),
                requester_api_key_id: "k".into(),
                plan_contract_json: "c".into(),
                plan_story_json: "y".into(),
                mandate_id: "m".into(),
                sealed_digest: "d".into(),
            },
            47,
            "2f017301700174016201650175016b01630179016d0164",
        ),
        (
            "McpSessionStateNotify",
            Message::McpSessionStateNotify {
                session_id: "s".into(),
                status: "suspended".into(),
                reason: "r".into(),
            },
            48,
            "3001730973757370656e6465640172",
        ),
        (
            "McpDiscover",
            Message::McpDiscover {
                request_id: 1,
                session_id: "s".into(),
                asset_id: "a".into(),
                user_id: "u".into(),
                upstream_host: "h".into(),
                upstream_port: 443,
                credential_blob: vec![9],
                session_token: vec![8],
                upstream_tls_spki_pin: None,
            },
            104,
            "68010173016101750168fbbb010109010800",
        ),
        (
            "McpDiscovered",
            Message::McpDiscovered {
                request_id: 1,
                session_id: "s".into(),
                success: true,
                tools_json: Some("[]".into()),
                error: None,
            },
            105,
            "690101730101025b5d00",
        ),
        (
            "McpMandateDriftNotify",
            Message::McpMandateDriftNotify {
                session_id: "s".into(),
                tool: "t".into(),
                reason: "r".into(),
                mandate_id: "m".into(),
                sealed_digest: "d".into(),
                requester_user_id: "u".into(),
            },
            110,
            "6e017301740172016d01640175",
        ),
        (
            "McpRelayRequest",
            Message::McpRelayRequest {
                relay_id: 1,
                client_ip: "i".into(),
                authorization: "b".to_string().into(),
                content_type: "c".into(),
                accept: "a".into(),
                mcp_session_id: Some("s".into()),
                mcp_protocol_version: None,
                body_len: 2,
            },
            111,
            "6f0101690162016301610101730002",
        ),
        (
            "McpRelayBody",
            Message::McpRelayBody {
                relay_id: 1,
                seq: 2,
                last: true,
                data: vec![3],
            },
            112,
            "700102010103",
        ),
        (
            "McpRelayResponse",
            Message::McpRelayResponse {
                relay_id: 1,
                status: 200,
                content_type: "c".into(),
                mcp_session_id: None,
                body_len: 2,
            },
            113,
            "7101c801630002",
        ),
        (
            "McpRelayAbort",
            Message::McpRelayAbort {
                relay_id: 1,
                reason: "r".into(),
            },
            114,
            "72010172",
        ),
        (
            "McpTunnelOpen",
            Message::McpTunnelOpen {
                tunnel_id: 1,
                client_ip: "i".into(),
            },
            115,
            "73010169",
        ),
        (
            "McpTunnelData",
            Message::McpTunnelData {
                tunnel_id: 1,
                data: vec![3],
            },
            116,
            "74010103",
        ),
        (
            "McpTunnelClose",
            Message::McpTunnelClose {
                tunnel_id: 1,
                reason: "r".into(),
            },
            117,
            "75010172",
        ),
        (
            "McpTunnelIdentityProvision",
            Message::McpTunnelIdentityProvision {
                cert_der: vec![3],
                key_pem: "k".to_string().into(),
            },
            118,
            "760103016b",
        ),
        (
            "McpTunnelIdentityFingerprint",
            Message::McpTunnelIdentityFingerprint {
                spki_sha256: "f".into(),
            },
            119,
            "770166",
        ),
        ("McpProxyReady", Message::McpProxyReady, 120, "78"),
        (
            "McpToolDefinitionDrift",
            Message::McpToolDefinitionDrift {
                session_id: "s".into(),
                asset_id: "a".into(),
                tool: "t".into(),
                approved_fp: "f".into(),
                live_fp: "g".into(),
                live_definition_json: "{}".into(),
            },
            121,
            "7901730161017401660167027b7d",
        ),
    ]
}

#[test]
fn mcp_message_indices_and_bytes_are_frozen() {
    let moved: Vec<String> = mcp_messages()
        .into_iter()
        .filter_map(|(name, msg, index, golden)| {
            let got = hex(&assert_frozen(name, &msg, index));
            (got != golden).then(|| format!("{name}: {got}"))
        })
        .collect();
    assert!(
        moved.is_empty(),
        "field layout moved:\n{}",
        moved.join("\n")
    );
}

#[test]
fn mcp_access_request_indices_are_frozen() {
    let cases: Vec<(&str, AccessRequest, u8)> = vec![
        (
            "ComputeMcpEffectiveTools",
            AccessRequest::ComputeMcpEffectiveTools {
                user_uuid: "u".into(),
                asset_uuid: "a".into(),
            },
            51,
        ),
        (
            "SealMcpMandate",
            AccessRequest::SealMcpMandate {
                session_id: "s".into(),
                mandate_id: "m".into(),
                asset_id: "a".into(),
                contract_json: "{}".into(),
                now_unix: 1.5,
            },
            52,
        ),
        (
            "CheckStepAuthorized",
            AccessRequest::CheckStepAuthorized {
                session_id: "s".into(),
                tool: "t".into(),
                arguments_json: "{}".into(),
                now_unix: 1.5,
            },
            53,
        ),
        (
            "CommitMcpMandateStep",
            AccessRequest::CommitMcpMandateStep {
                session_id: "s".into(),
                result_json: "{}".into(),
            },
            54,
        ),
        (
            "RollbackMcpMandateStep",
            AccessRequest::RollbackMcpMandateStep {
                session_id: "s".into(),
            },
            55,
        ),
        (
            "ClearMcpMandate",
            AccessRequest::ClearMcpMandate {
                session_id: "s".into(),
            },
            56,
        ),
    ];
    for (name, req, index) in cases {
        assert_frozen(name, &req, index);
    }
}

#[test]
fn mcp_access_response_indices_are_frozen() {
    let cases: Vec<(&str, AccessResponse, u8)> = vec![
        (
            "McpEffectiveTools",
            AccessResponse::McpEffectiveTools {
                tools: vec!["t".into()],
            },
            35,
        ),
        (
            "McpMandateSealed",
            AccessResponse::McpMandateSealed {
                sealed_digest: "d".into(),
                expires_at: 1.5,
            },
            36,
        ),
        (
            "McpMandateSealDenied",
            AccessResponse::McpMandateSealDenied { reason: "r".into() },
            37,
        ),
        (
            "McpCheckStepAllowed",
            AccessResponse::McpCheckStepAllowed {
                step_id: "1".into(),
                call_digest: "c".into(),
            },
            38,
        ),
        (
            "McpCheckStepReplay",
            AccessResponse::McpCheckStepReplay {
                step_id: "1".into(),
                cached_json: "{}".into(),
            },
            39,
        ),
        (
            "McpCheckStepDenied",
            AccessResponse::McpCheckStepDenied { reason: "r".into() },
            40,
        ),
        ("McpMandateAck", AccessResponse::McpMandateAck, 41),
    ];
    for (name, resp, index) in cases {
        assert_frozen(name, &resp, index);
    }
}

#[test]
fn mcp_rule_tools_prune_wire_is_frozen() {
    let cases: Vec<(&str, Vec<u8>, &str)> = vec![
        (
            "PruneMcpRuleTools scoped",
            assert_frozen(
                "PruneMcpRuleTools",
                &AccessRequest::PruneMcpRuleTools {
                    asset_group_ids: Some(vec![1, 2]),
                },
                57,
            ),
            "3901020204",
        ),
        (
            "PruneMcpRuleTools all",
            assert_frozen(
                "PruneMcpRuleTools",
                &AccessRequest::PruneMcpRuleTools {
                    asset_group_ids: None,
                },
                57,
            ),
            "3900",
        ),
        (
            "McpRuleToolsPruned",
            assert_frozen(
                "McpRuleToolsPruned",
                &AccessResponse::McpRuleToolsPruned { rules_changed: 3 },
                42,
            ),
            "2a03",
        ),
    ];
    for (name, bytes, golden) in cases {
        assert_eq!(hex(&bytes), golden, "{name}: field layout moved");
    }
}

#[test]
fn mcp_audit_event_type_indices_are_frozen() {
    use AuditEventType::*;
    let cases = [
        (McpSessionOpened, 58),
        (McpToolCallAllowed, 59),
        (McpToolCallDenied, 60),
        (McpToolCallThrottled, 61),
        (McpPrivilegeEscalationAttempt, 62),
        (McpRecordingFinalized, 63),
        (McpEnvelopeThreshold, 64),
        (McpSessionSuspended, 65),
        (McpSessionResumed, 66),
        (McpHitlPending, 67),
        (McpHitlDecided, 68),
        (McpHitlExpired, 69),
        (McpClientinfoDrift, 70),
        (McpAccessDecision, 71),
        (McpContestationOpened, 72),
        (McpContestationResolved, 73),
        (McpToolCallUpstreamFailed, 79),
        (McpToolDefinitionDrift, 80),
    ];
    for (ev, index) in cases {
        assert_eq!(encode(&ev), vec![index], "{ev:?}: WORM index moved");
    }
}

/// `audit_events_dropped` is the last field: the supervisor decodes the
/// heartbeat `Pong` of every leaf with this layout.
#[test]
fn service_stats_layout_is_frozen() {
    let stats = ServiceStats {
        uptime_secs: 1,
        requests_processed: 2,
        requests_failed: 3,
        active_connections: 4,
        pending_requests: 5,
        recording_ack_timeouts: 6,
        recording_ack_dropped: 7,
        recording_try_send_full: 8,
        recording_ack_wait_ms_max: 9,
        audit_events_dropped: 10,
    };
    assert_eq!(hex(&encode(&stats)), "0102030405060708090a");
}

#[test]
fn service_proxy_mcp_token_discriminant_is_frozen() {
    assert_eq!(
        shared::messages::Service::ProxyMcp.as_token_discriminant(),
        10
    );
}
