//! Mission Seal PDP store — live [`MandateState`] owned by vauban-access.
//!
//! Same role as `CheckAccessByUuid` for SSH/RDP: the proxy asks, access
//! decides. State is process-local (survives proxy restart, not access
//! restart). Persistence is a later hop.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use shared::mcp_mandate::{self, CheckStepOutcome, MandateState, is_expired};
use shared::messages::{AccessRequest, AccessResponse};

static STORE: OnceLock<Mutex<HashMap<String, MandateState>>> = OnceLock::new();

fn store() -> &'static Mutex<HashMap<String, MandateState>> {
    STORE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn lock_store() -> std::sync::MutexGuard<'static, HashMap<String, MandateState>> {
    match store().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

pub fn is_mandate_request(request: &AccessRequest) -> bool {
    matches!(
        request,
        AccessRequest::SealMcpMandate { .. }
            | AccessRequest::CheckStepAuthorized { .. }
            | AccessRequest::CommitMcpMandateStep { .. }
            | AccessRequest::RollbackMcpMandateStep { .. }
            | AccessRequest::ClearMcpMandate { .. }
    )
}

pub fn handle(request: AccessRequest) -> AccessResponse {
    match request {
        AccessRequest::SealMcpMandate {
            session_id,
            mandate_id,
            asset_id,
            contract_json,
            now_unix,
        } => seal(
            &session_id,
            &mandate_id,
            &asset_id,
            &contract_json,
            now_unix,
        ),
        AccessRequest::CheckStepAuthorized {
            session_id,
            tool,
            arguments_json,
            now_unix,
        } => check_step(&session_id, &tool, &arguments_json, now_unix),
        AccessRequest::CommitMcpMandateStep {
            session_id,
            result_json,
        } => commit(&session_id, &result_json),
        AccessRequest::RollbackMcpMandateStep { session_id } => rollback(&session_id),
        AccessRequest::ClearMcpMandate { session_id } => {
            lock_store().remove(&session_id);
            AccessResponse::McpMandateAck
        }
        _ => AccessResponse::Error("not a mandate request".into()),
    }
}

fn seal(
    session_id: &str,
    mandate_id: &str,
    asset_id: &str,
    contract_json: &str,
    now: f64,
) -> AccessResponse {
    let raw: serde_json::Value = match serde_json::from_str(contract_json) {
        Ok(v) => v,
        Err(e) => {
            return AccessResponse::McpMandateSealDenied {
                reason: format!("invalid_contract: {e}"),
            };
        }
    };
    let contract = match mcp_mandate::parse_contract(&raw) {
        Ok(c) => c,
        Err(e) => return AccessResponse::McpMandateSealDenied { reason: e },
    };
    match mcp_mandate::seal_mandate(mandate_id, session_id, asset_id, &contract, now) {
        Ok(m) => {
            let digest = m.sealed_digest.clone();
            let expires_at = m.expires_at;
            lock_store().insert(session_id.to_string(), m);
            AccessResponse::McpMandateSealed {
                sealed_digest: digest,
                expires_at,
            }
        }
        Err(e) => AccessResponse::McpMandateSealDenied { reason: e },
    }
}

fn check_step(session_id: &str, tool: &str, arguments_json: &str, now: f64) -> AccessResponse {
    let args: serde_json::Value = match serde_json::from_str(arguments_json) {
        Ok(v) => v,
        Err(_) => serde_json::Value::Null,
    };
    let mut g = lock_store();
    let Some(m) = g.get_mut(session_id) else {
        return AccessResponse::McpCheckStepDenied {
            reason: "no_mandate".into(),
        };
    };
    if is_expired(m, now) {
        g.remove(session_id);
        return AccessResponse::McpCheckStepDenied {
            reason: "mission_expired".into(),
        };
    }
    match mcp_mandate::check_step(m, tool, Some(&args)) {
        CheckStepOutcome::Allow {
            step_id,
            call_digest,
        } => AccessResponse::McpCheckStepAllowed {
            step_id,
            call_digest,
        },
        CheckStepOutcome::Replay { step_id, cached } => AccessResponse::McpCheckStepReplay {
            step_id,
            cached_json: cached.to_string(),
        },
        CheckStepOutcome::Deny { reason } => AccessResponse::McpCheckStepDenied {
            reason: reason.to_string(),
        },
    }
}

fn commit(session_id: &str, result_json: &str) -> AccessResponse {
    let body: serde_json::Value =
        serde_json::from_str(result_json).unwrap_or(serde_json::Value::Null);
    let mut g = lock_store();
    if let Some(m) = g.get_mut(session_id)
        && let Some((step_id, call_digest)) = m.inflight.clone()
    {
        mcp_mandate::commit_step_result(m, &step_id, &call_digest, body);
    }
    AccessResponse::McpMandateAck
}

fn rollback(session_id: &str) -> AccessResponse {
    if let Some(m) = lock_store().get_mut(session_id) {
        mcp_mandate::rollback_inflight(m);
    }
    AccessResponse::McpMandateAck
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    pub(super) fn contract_json() -> String {
        json!({
            "approval": "mission",
            "edges": [],
            "steps": [{
                "step_id": "1",
                "intent": "Echo the sealed lab message now",
                "operation": "echo",
                "mode": "literal",
                "arguments": { "message": "access-pdp" }
            }]
        })
        .to_string()
    }

    pub(super) fn sid() -> String {
        format!("sess-{}", uuid::Uuid::new_v4())
    }

    #[test]
    fn access_pdp_seal_check_drift_and_replay() {
        let session_id = sid();
        let sealed = handle(AccessRequest::SealMcpMandate {
            session_id: session_id.clone(),
            mandate_id: "m1".into(),
            asset_id: "asset-1".into(),
            contract_json: contract_json(),
            now_unix: 1_000.0,
        });
        let AccessResponse::McpMandateSealed { sealed_digest, .. } = sealed else {
            panic!("expected seal, got {sealed:?}");
        };
        assert!(!sealed_digest.is_empty());

        let drift = handle(AccessRequest::CheckStepAuthorized {
            session_id: session_id.clone(),
            tool: "echo".into(),
            arguments_json: json!({"message": "wrong"}).to_string(),
            now_unix: 1_001.0,
        });
        match drift {
            AccessResponse::McpCheckStepDenied { reason } => {
                assert_eq!(reason, "args_mismatch_or_precedence");
                assert!(mcp_mandate::is_perimeter_drift(&reason));
            }
            other => panic!("expected drift deny, got {other:?}"),
        }

        let allow = handle(AccessRequest::CheckStepAuthorized {
            session_id: session_id.clone(),
            tool: "echo".into(),
            arguments_json: json!({"message": "access-pdp"}).to_string(),
            now_unix: 1_002.0,
        });
        let AccessResponse::McpCheckStepAllowed { step_id, .. } = allow else {
            panic!("expected allow, got {allow:?}");
        };
        assert_eq!(step_id, "1");

        let inflight = handle(AccessRequest::CheckStepAuthorized {
            session_id: session_id.clone(),
            tool: "echo".into(),
            arguments_json: json!({"message": "access-pdp"}).to_string(),
            now_unix: 1_003.0,
        });
        match inflight {
            AccessResponse::McpCheckStepDenied { reason } => {
                assert_eq!(reason, "step_inflight");
                assert!(!mcp_mandate::is_perimeter_drift(&reason));
            }
            other => panic!("expected inflight, got {other:?}"),
        }

        let _ = handle(AccessRequest::CommitMcpMandateStep {
            session_id: session_id.clone(),
            result_json: json!({"jsonrpc":"2.0","result":{"ok":true}}).to_string(),
        });
        let replay = handle(AccessRequest::CheckStepAuthorized {
            session_id: session_id.clone(),
            tool: "echo".into(),
            arguments_json: json!({"message": "access-pdp"}).to_string(),
            now_unix: 1_004.0,
        });
        assert!(matches!(replay, AccessResponse::McpCheckStepReplay { .. }));

        let expired = handle(AccessRequest::CheckStepAuthorized {
            session_id: session_id.clone(),
            tool: "echo".into(),
            arguments_json: json!({"message": "access-pdp"}).to_string(),
            now_unix: 1_000.0 + mcp_mandate::MISSION_TTL_DEFAULT_SECS + 1.0,
        });
        match expired {
            AccessResponse::McpCheckStepDenied { reason } => {
                assert_eq!(reason, "mission_expired");
                assert!(!mcp_mandate::is_perimeter_drift(&reason));
            }
            other => panic!("expected expiry, got {other:?}"),
        }
    }

    #[test]
    fn access_pdp_digest_binds_asset() {
        let a = handle(AccessRequest::SealMcpMandate {
            session_id: sid(),
            mandate_id: "m1".into(),
            asset_id: "asset-aaa".into(),
            contract_json: contract_json(),
            now_unix: 1_000.0,
        });
        let b = handle(AccessRequest::SealMcpMandate {
            session_id: sid(),
            mandate_id: "m1".into(),
            asset_id: "asset-bbb".into(),
            contract_json: contract_json(),
            now_unix: 1_000.0,
        });
        let AccessResponse::McpMandateSealed {
            sealed_digest: da, ..
        } = a
        else {
            panic!("{a:?}");
        };
        let AccessResponse::McpMandateSealed {
            sealed_digest: db, ..
        } = b
        else {
            panic!("{b:?}");
        };
        assert_ne!(da, db);
    }

    #[test]
    fn access_pdp_clear_removes_mandate() {
        let session_id = sid();
        let sealed = handle(AccessRequest::SealMcpMandate {
            session_id: session_id.clone(),
            mandate_id: "m1".into(),
            asset_id: "asset-1".into(),
            contract_json: contract_json(),
            now_unix: 1_000.0,
        });
        assert!(matches!(sealed, AccessResponse::McpMandateSealed { .. }));
        assert!(matches!(
            handle(AccessRequest::ClearMcpMandate {
                session_id: session_id.clone(),
            }),
            AccessResponse::McpMandateAck
        ));
        match handle(AccessRequest::CheckStepAuthorized {
            session_id,
            tool: "echo".into(),
            arguments_json: json!({"message": "access-pdp"}).to_string(),
            now_unix: 1_001.0,
        }) {
            AccessResponse::McpCheckStepDenied { reason } => {
                assert_eq!(reason, "no_mandate");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn access_pdp_covers_deny_and_ack_edges() {
        assert!(is_mandate_request(&AccessRequest::SealMcpMandate {
            session_id: "s".into(),
            mandate_id: "m".into(),
            asset_id: "a".into(),
            contract_json: "{}".into(),
            now_unix: 1.0,
        }));
        assert!(is_mandate_request(&AccessRequest::CheckStepAuthorized {
            session_id: "s".into(),
            tool: "echo".into(),
            arguments_json: "{}".into(),
            now_unix: 1.0,
        }));
        assert!(is_mandate_request(&AccessRequest::CommitMcpMandateStep {
            session_id: "s".into(),
            result_json: "{}".into(),
        }));
        assert!(is_mandate_request(&AccessRequest::RollbackMcpMandateStep {
            session_id: "s".into(),
        }));
        assert!(is_mandate_request(&AccessRequest::ClearMcpMandate {
            session_id: "s".into(),
        }));
        let other = AccessRequest::CheckAccess {
            user_id: 1,
            asset_group_id: 1,
            protocol: "mcp".into(),
        };
        assert!(!is_mandate_request(&other));
        assert!(matches!(handle(other), AccessResponse::Error(_)));
        assert!(matches!(
            handle(AccessRequest::SealMcpMandate {
                session_id: sid(),
                mandate_id: "m".into(),
                asset_id: "a".into(),
                contract_json: "not-json".into(),
                now_unix: 1.0,
            }),
            AccessResponse::McpMandateSealDenied { .. }
        ));
        assert!(matches!(
            handle(AccessRequest::SealMcpMandate {
                session_id: sid(),
                mandate_id: "m".into(),
                asset_id: "a".into(),
                contract_json: json!({"approval":"mission","steps":[]}).to_string(),
                now_unix: 1.0,
            }),
            AccessResponse::McpMandateSealDenied { .. }
        ));
        assert!(matches!(
            handle(AccessRequest::SealMcpMandate {
                session_id: sid(),
                mandate_id: "".into(),
                asset_id: "a".into(),
                contract_json: contract_json(),
                now_unix: 1.0,
            }),
            AccessResponse::McpMandateSealDenied { .. }
        ));
        let session_id = sid();
        assert!(matches!(
            handle(AccessRequest::SealMcpMandate {
                session_id: session_id.clone(),
                mandate_id: "m".into(),
                asset_id: "a".into(),
                contract_json: contract_json(),
                now_unix: 1.0,
            }),
            AccessResponse::McpMandateSealed { .. }
        ));
        let _ = handle(AccessRequest::CheckStepAuthorized {
            session_id: session_id.clone(),
            tool: "echo".into(),
            arguments_json: "not-json".into(),
            now_unix: 1.1,
        });
        let _ = handle(AccessRequest::RollbackMcpMandateStep {
            session_id: session_id.clone(),
        });
        assert!(matches!(
            handle(AccessRequest::CommitMcpMandateStep {
                session_id: session_id.clone(),
                result_json: "not-json".into(),
            }),
            AccessResponse::McpMandateAck
        ));
        let _ = handle(AccessRequest::CheckStepAuthorized {
            session_id: session_id.clone(),
            tool: "echo".into(),
            arguments_json: json!({"message": "access-pdp"}).to_string(),
            now_unix: 1.2,
        });
        assert!(matches!(
            handle(AccessRequest::RollbackMcpMandateStep {
                session_id: session_id.clone(),
            }),
            AccessResponse::McpMandateAck
        ));
        assert!(matches!(
            handle(AccessRequest::CommitMcpMandateStep {
                session_id: "nobody".into(),
                result_json: "{}".into(),
            }),
            AccessResponse::McpMandateAck
        ));
    }

    fn secret_contract_json() -> String {
        json!({
            "approval": "mission",
            "edges": [],
            "steps": [{
                "step_id": "1",
                "intent": "Read the sealed lab secret file now",
                "operation": "read_demo_file",
                "mode": "literal",
                "arguments": { "name": "secret.txt" }
            }]
        })
        .to_string()
    }

    /// After the last step is committed, leftover CheckStep on other
    /// args is `step_not_in_contract`. Clear + a new Seal is how the
    /// PEP Replace path starts a second mission (hello then secret).
    #[test]
    fn access_pdp_done_then_clear_and_reseal() {
        let session_id = sid();
        assert!(matches!(
            handle(AccessRequest::SealMcpMandate {
                session_id: session_id.clone(),
                mandate_id: "m-hello".into(),
                asset_id: "asset-1".into(),
                contract_json: json!({
                    "approval": "mission",
                    "edges": [],
                    "steps": [{
                        "step_id": "1",
                        "intent": "Read the sealed lab hello file now",
                        "operation": "read_demo_file",
                        "mode": "literal",
                        "arguments": { "name": "hello.txt" }
                    }]
                })
                .to_string(),
                now_unix: 1_000.0,
            }),
            AccessResponse::McpMandateSealed { .. }
        ));
        let allow = handle(AccessRequest::CheckStepAuthorized {
            session_id: session_id.clone(),
            tool: "read_demo_file".into(),
            arguments_json: json!({"name": "hello.txt"}).to_string(),
            now_unix: 1_001.0,
        });
        assert!(
            matches!(allow, AccessResponse::McpCheckStepAllowed { .. }),
            "{allow:?}"
        );
        let _ = handle(AccessRequest::CommitMcpMandateStep {
            session_id: session_id.clone(),
            result_json: json!({"ok": true}).to_string(),
        });

        match handle(AccessRequest::CheckStepAuthorized {
            session_id: session_id.clone(),
            tool: "read_demo_file".into(),
            arguments_json: json!({"name": "secret.txt"}).to_string(),
            now_unix: 1_002.0,
        }) {
            AccessResponse::McpCheckStepDenied { reason } => {
                assert_eq!(reason, "step_not_in_contract");
                assert!(mcp_mandate::is_perimeter_drift(&reason));
            }
            other => panic!("expected step_not_in_contract after done, got {other:?}"),
        }

        assert!(matches!(
            handle(AccessRequest::ClearMcpMandate {
                session_id: session_id.clone(),
            }),
            AccessResponse::McpMandateAck
        ));
        assert!(matches!(
            handle(AccessRequest::SealMcpMandate {
                session_id: session_id.clone(),
                mandate_id: "m-secret".into(),
                asset_id: "asset-1".into(),
                contract_json: secret_contract_json(),
                now_unix: 1_003.0,
            }),
            AccessResponse::McpMandateSealed { .. }
        ));
        match handle(AccessRequest::CheckStepAuthorized {
            session_id,
            tool: "read_demo_file".into(),
            arguments_json: json!({"name": "secret.txt"}).to_string(),
            now_unix: 1_004.0,
        }) {
            AccessResponse::McpCheckStepAllowed { step_id, .. } => {
                assert_eq!(step_id, "1");
            }
            other => panic!("expected Allow after reseal, got {other:?}"),
        }
    }

    #[test]
    fn attack_checkstep_drift_is_rejected() {
        let session_id = sid();
        let sealed = handle(AccessRequest::SealMcpMandate {
            session_id: session_id.clone(),
            mandate_id: "m-attack".into(),
            asset_id: "asset-1".into(),
            contract_json: contract_json(),
            now_unix: 2_000.0,
        });
        assert!(matches!(sealed, AccessResponse::McpMandateSealed { .. }));
        match handle(AccessRequest::CheckStepAuthorized {
            session_id,
            tool: "echo".into(),
            arguments_json: json!({"message": "forged"}).to_string(),
            now_unix: 2_001.0,
        }) {
            AccessResponse::McpCheckStepDenied { reason } => {
                assert_eq!(reason, "args_mismatch_or_precedence");
            }
            other => panic!("drift must be denied, got {other:?}"),
        }
    }

    #[test]
    fn battle_two_checksteps_one_allow() {
        let session_id = sid();
        assert!(matches!(
            handle(AccessRequest::SealMcpMandate {
                session_id: session_id.clone(),
                mandate_id: "m-battle".into(),
                asset_id: "asset-1".into(),
                contract_json: contract_json(),
                now_unix: 3_000.0,
            }),
            AccessResponse::McpMandateSealed { .. }
        ));
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let mut handles = Vec::new();
        for _ in 0..2 {
            let session_id = session_id.clone();
            let barrier = std::sync::Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                handle(AccessRequest::CheckStepAuthorized {
                    session_id,
                    tool: "echo".into(),
                    arguments_json: json!({"message": "access-pdp"}).to_string(),
                    now_unix: 3_001.0,
                })
            }));
        }
        let mut allows = 0;
        for handle_thread in handles {
            match handle_thread.join().expect("thread") {
                AccessResponse::McpCheckStepAllowed { .. } => allows += 1,
                AccessResponse::McpCheckStepDenied { reason } => {
                    assert_eq!(reason, "step_inflight");
                }
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(allows, 1);
    }
}

#[cfg(test)]
proptest::proptest! {
    #[test]
    fn proptest_unknown_tools_are_denied(tool in "[a-z][a-z0-9]{0,12}") {
        proptest::prelude::prop_assume!(tool != "echo");
        let session_id = tests::sid();
        let sealed = handle(AccessRequest::SealMcpMandate {
            session_id: session_id.clone(),
            mandate_id: "m-prop".into(),
            asset_id: "asset-1".into(),
            contract_json: tests::contract_json(),
            now_unix: 4_000.0,
        });
        let sealed_ok = matches!(sealed, AccessResponse::McpMandateSealed { .. });
        proptest::prop_assert!(sealed_ok);
        let denied = handle(AccessRequest::CheckStepAuthorized {
            session_id,
            tool,
            arguments_json: serde_json::json!({"message": "access-pdp"}).to_string(),
            now_unix: 4_001.0,
        });
        let denied_ok = matches!(denied, AccessResponse::McpCheckStepDenied { .. });
        proptest::prop_assert!(denied_ok);
    }
}
