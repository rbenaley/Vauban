//! Mission Seal PDP store — live [`MandateState`] owned by vauban-access.
//!
//! Write-through RAM + `mcp_mandates` PostgreSQL. Proxy is PEP; IPC verbs
//! (`CheckStepAuthorized` / `SealMcpMandate` / Commit / Rollback / Clear)
//! are unchanged. Access restart reloads the sealed Contract from DB.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, OnceLock};

use chrono::{DateTime, Utc};
use diesel::OptionalExtension;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use shared::mcp_mandate::{self, CheckStepOutcome, MandateState, is_expired};
use shared::messages::{AccessRequest, AccessResponse};

use crate::db::DbPool;
use crate::schema::mcp_mandates;

static STORE: OnceLock<Mutex<HashMap<String, MandateState>>> = OnceLock::new();

fn store() -> &'static Mutex<HashMap<String, MandateState>> {
    STORE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn lock_store() -> MutexGuard<'static, HashMap<String, MandateState>> {
    store().lock().unwrap_or_else(|e| e.into_inner())
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

/// RAM-only dispatch (unit tests without a pool).
fn ram_handle(request: AccessRequest) -> AccessResponse {
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

fn session_id_of(request: &AccessRequest) -> Option<&str> {
    match request {
        AccessRequest::SealMcpMandate { session_id, .. }
        | AccessRequest::CheckStepAuthorized { session_id, .. }
        | AccessRequest::CommitMcpMandateStep { session_id, .. }
        | AccessRequest::RollbackMcpMandateStep { session_id }
        | AccessRequest::ClearMcpMandate { session_id } => Some(session_id.as_str()),
        _ => None,
    }
}

/// Production PDP: RAM + PostgreSQL write-through. `pool = None` is RAM-only.
pub async fn handle(pool: Option<&DbPool>, request: AccessRequest) -> AccessResponse {
    let sid = session_id_of(&request).map(str::to_string);
    if let (Some(pool), Some(session_id), AccessRequest::CheckStepAuthorized { .. }) =
        (pool, &sid, &request)
        && !lock_store().contains_key(session_id.as_str())
        && let Err(e) = load_into_ram(pool, session_id).await
    {
        tracing::warn!(session_id = %session_id, error = %e, "mcp mandate load failed");
    }

    let is_seal = matches!(request, AccessRequest::SealMcpMandate { .. });
    let resp = ram_handle(request);

    if let (Some(pool), Some(session_id)) = (pool, sid) {
        let skip_persist = matches!(
            &resp,
            AccessResponse::McpCheckStepDenied { reason } if reason == "no_mandate"
        ) && !lock_store().contains_key(&session_id);
        if skip_persist {
            return resp;
        }
        if let Err(e) = sync_db(pool, &session_id).await {
            tracing::error!(session_id = %session_id, error = %e, "mcp mandate persist failed");
            if is_seal {
                lock_store().remove(&session_id);
                return AccessResponse::McpMandateSealDenied {
                    reason: format!("persist_failed: {e}"),
                };
            }
            return AccessResponse::Error(format!("mandate persist failed: {e}"));
        }
    }
    resp
}

fn mandate_expires_at(m: &MandateState) -> DateTime<Utc> {
    DateTime::from_timestamp(m.expires_at as i64, 0).unwrap_or_else(Utc::now)
}

async fn sync_db(pool: &DbPool, session_id: &str) -> Result<(), String> {
    let snapshot = lock_store().get(session_id).cloned();
    let mut conn = pool.get().await.map_err(|e| format!("db pool: {e}"))?;
    match snapshot {
        Some(m) => {
            let state = serde_json::to_value(&m).map_err(|e| format!("mandate serde: {e}"))?;
            let now = Utc::now();
            let expires = mandate_expires_at(&m);
            diesel::insert_into(mcp_mandates::table)
                .values((
                    mcp_mandates::session_id.eq(session_id),
                    mcp_mandates::mandate_id.eq(&m.mandate_id),
                    mcp_mandates::state.eq(&state),
                    mcp_mandates::expires_at.eq(expires),
                    mcp_mandates::updated_at.eq(now),
                ))
                .on_conflict(mcp_mandates::session_id)
                .do_update()
                .set((
                    mcp_mandates::mandate_id.eq(&m.mandate_id),
                    mcp_mandates::state.eq(&state),
                    mcp_mandates::expires_at.eq(expires),
                    mcp_mandates::updated_at.eq(now),
                ))
                .execute(&mut conn)
                .await
                .map_err(|e| format!("upsert mcp_mandates: {e}"))?;
        }
        None => {
            diesel::delete(mcp_mandates::table.filter(mcp_mandates::session_id.eq(session_id)))
                .execute(&mut conn)
                .await
                .map_err(|e| format!("delete mcp_mandates: {e}"))?;
        }
    }
    Ok(())
}

async fn load_into_ram(pool: &DbPool, session_id: &str) -> Result<(), String> {
    let mut conn = pool.get().await.map_err(|e| format!("db pool: {e}"))?;
    let state: Option<serde_json::Value> = mcp_mandates::table
        .filter(mcp_mandates::session_id.eq(session_id))
        .select(mcp_mandates::state)
        .first::<serde_json::Value>(&mut conn)
        .await
        .optional()
        .map_err(|e| format!("select mcp_mandates: {e}"))?;
    let Some(state) = state else {
        return Ok(());
    };
    let m: MandateState =
        serde_json::from_value(state).map_err(|e| format!("mandate decode: {e}"))?;
    lock_store().insert(session_id.to_string(), m);
    Ok(())
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
    fn gwt_mandate_postgres_write_through() {
        let src = include_str!("mcp_pdp.rs");
        assert!(
            src.contains("mcp_mandates")
                && src.contains("load_into_ram")
                && src.contains("persist_failed")
                && src.contains("into_inner()"),
            "PDP must persist MandateState in PostgreSQL; mutex poison must not panic"
        );
    }

    #[test]
    fn access_pdp_seal_check_drift_and_replay() {
        let session_id = sid();
        let sealed = ram_handle(AccessRequest::SealMcpMandate {
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

        let drift = ram_handle(AccessRequest::CheckStepAuthorized {
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

        let allow = ram_handle(AccessRequest::CheckStepAuthorized {
            session_id: session_id.clone(),
            tool: "echo".into(),
            arguments_json: json!({"message": "access-pdp"}).to_string(),
            now_unix: 1_002.0,
        });
        let AccessResponse::McpCheckStepAllowed { step_id, .. } = allow else {
            panic!("expected allow, got {allow:?}");
        };
        assert_eq!(step_id, "1");

        let inflight = ram_handle(AccessRequest::CheckStepAuthorized {
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

        let _ = ram_handle(AccessRequest::CommitMcpMandateStep {
            session_id: session_id.clone(),
            result_json: json!({"jsonrpc":"2.0","result":{"ok":true}}).to_string(),
        });
        let replay = ram_handle(AccessRequest::CheckStepAuthorized {
            session_id: session_id.clone(),
            tool: "echo".into(),
            arguments_json: json!({"message": "access-pdp"}).to_string(),
            now_unix: 1_004.0,
        });
        assert!(matches!(replay, AccessResponse::McpCheckStepReplay { .. }));

        let expired = ram_handle(AccessRequest::CheckStepAuthorized {
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
        let a = ram_handle(AccessRequest::SealMcpMandate {
            session_id: sid(),
            mandate_id: "m1".into(),
            asset_id: "asset-aaa".into(),
            contract_json: contract_json(),
            now_unix: 1_000.0,
        });
        let b = ram_handle(AccessRequest::SealMcpMandate {
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
        let sealed = ram_handle(AccessRequest::SealMcpMandate {
            session_id: session_id.clone(),
            mandate_id: "m1".into(),
            asset_id: "asset-1".into(),
            contract_json: contract_json(),
            now_unix: 1_000.0,
        });
        assert!(matches!(sealed, AccessResponse::McpMandateSealed { .. }));
        assert!(matches!(
            ram_handle(AccessRequest::ClearMcpMandate {
                session_id: session_id.clone(),
            }),
            AccessResponse::McpMandateAck
        ));
        match ram_handle(AccessRequest::CheckStepAuthorized {
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
        assert!(matches!(ram_handle(other), AccessResponse::Error(_)));
        assert!(matches!(
            ram_handle(AccessRequest::SealMcpMandate {
                session_id: sid(),
                mandate_id: "m".into(),
                asset_id: "a".into(),
                contract_json: "not-json".into(),
                now_unix: 1.0,
            }),
            AccessResponse::McpMandateSealDenied { .. }
        ));
        assert!(matches!(
            ram_handle(AccessRequest::SealMcpMandate {
                session_id: sid(),
                mandate_id: "m".into(),
                asset_id: "a".into(),
                contract_json: json!({"approval":"mission","steps":[]}).to_string(),
                now_unix: 1.0,
            }),
            AccessResponse::McpMandateSealDenied { .. }
        ));
        assert!(matches!(
            ram_handle(AccessRequest::SealMcpMandate {
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
            ram_handle(AccessRequest::SealMcpMandate {
                session_id: session_id.clone(),
                mandate_id: "m".into(),
                asset_id: "a".into(),
                contract_json: contract_json(),
                now_unix: 1.0,
            }),
            AccessResponse::McpMandateSealed { .. }
        ));
        let _ = ram_handle(AccessRequest::CheckStepAuthorized {
            session_id: session_id.clone(),
            tool: "echo".into(),
            arguments_json: "not-json".into(),
            now_unix: 1.1,
        });
        let _ = ram_handle(AccessRequest::RollbackMcpMandateStep {
            session_id: session_id.clone(),
        });
        assert!(matches!(
            ram_handle(AccessRequest::CommitMcpMandateStep {
                session_id: session_id.clone(),
                result_json: "not-json".into(),
            }),
            AccessResponse::McpMandateAck
        ));
        let _ = ram_handle(AccessRequest::CheckStepAuthorized {
            session_id: session_id.clone(),
            tool: "echo".into(),
            arguments_json: json!({"message": "access-pdp"}).to_string(),
            now_unix: 1.2,
        });
        assert!(matches!(
            ram_handle(AccessRequest::RollbackMcpMandateStep {
                session_id: session_id.clone(),
            }),
            AccessResponse::McpMandateAck
        ));
        assert!(matches!(
            ram_handle(AccessRequest::CommitMcpMandateStep {
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
            ram_handle(AccessRequest::SealMcpMandate {
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
        let allow = ram_handle(AccessRequest::CheckStepAuthorized {
            session_id: session_id.clone(),
            tool: "read_demo_file".into(),
            arguments_json: json!({"name": "hello.txt"}).to_string(),
            now_unix: 1_001.0,
        });
        assert!(
            matches!(allow, AccessResponse::McpCheckStepAllowed { .. }),
            "{allow:?}"
        );
        let _ = ram_handle(AccessRequest::CommitMcpMandateStep {
            session_id: session_id.clone(),
            result_json: json!({"ok": true}).to_string(),
        });

        match ram_handle(AccessRequest::CheckStepAuthorized {
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
            ram_handle(AccessRequest::ClearMcpMandate {
                session_id: session_id.clone(),
            }),
            AccessResponse::McpMandateAck
        ));
        assert!(matches!(
            ram_handle(AccessRequest::SealMcpMandate {
                session_id: session_id.clone(),
                mandate_id: "m-secret".into(),
                asset_id: "asset-1".into(),
                contract_json: secret_contract_json(),
                now_unix: 1_003.0,
            }),
            AccessResponse::McpMandateSealed { .. }
        ));
        match ram_handle(AccessRequest::CheckStepAuthorized {
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
    fn lock_store_recovers_from_poison() {
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _g = lock_store();
            panic!("intentional pdp poison");
        }));
        assert!(caught.is_err());
        let _g = lock_store();
    }

    fn test_db_url() -> String {
        std::env::var("VAUBAN_TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://vauban_test:vauban_test@localhost/vauban_test".into())
    }

    async fn test_pool() -> DbPool {
        crate::db::create_pool_sandboxed(&test_db_url(), 2)
            .expect("Persist tests need PostgreSQL (config/testing.toml vauban_test)")
    }

    async fn delete_mandate_row(pool: &DbPool, sid: &str) {
        let mut conn = pool.get().await.unwrap();
        diesel::delete(mcp_mandates::table.filter(mcp_mandates::session_id.eq(sid)))
            .execute(&mut conn)
            .await
            .ok();
    }

    async fn mandate_row_exists(pool: &DbPool, sid: &str) -> bool {
        let mut conn = pool.get().await.unwrap();
        mcp_mandates::table
            .filter(mcp_mandates::session_id.eq(sid))
            .select(mcp_mandates::session_id)
            .first::<String>(&mut conn)
            .await
            .optional()
            .unwrap()
            .is_some()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn persist_seal_survives_ram_evict() {
        let pool = test_pool().await;
        let sid = sid();
        delete_mandate_row(&pool, &sid).await;
        let sealed = handle(
            Some(&pool),
            AccessRequest::SealMcpMandate {
                session_id: sid.clone(),
                mandate_id: "m-persist".into(),
                asset_id: "asset-1".into(),
                contract_json: contract_json(),
                now_unix: 1_000.0,
            },
        )
        .await;
        assert!(
            matches!(sealed, AccessResponse::McpMandateSealed { .. }),
            "{sealed:?}"
        );
        assert!(mandate_row_exists(&pool, &sid).await);
        lock_store().remove(&sid);
        assert!(!lock_store().contains_key(&sid));
        let check = handle(
            Some(&pool),
            AccessRequest::CheckStepAuthorized {
                session_id: sid.clone(),
                tool: "echo".into(),
                arguments_json: json!({"message": "access-pdp"}).to_string(),
                now_unix: 1_001.0,
            },
        )
        .await;
        match check {
            AccessResponse::McpCheckStepAllowed { step_id, .. } => assert_eq!(step_id, "1"),
            other => panic!("CheckStep after access restart must Allow, got {other:?}"),
        }
        lock_store().remove(&sid);
        delete_mandate_row(&pool, &sid).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn checkstep_no_mandate_does_not_delete_undecodable_row() {
        let pool = test_pool().await;
        let sid = sid();
        delete_mandate_row(&pool, &sid).await;
        {
            let mut conn = pool.get().await.unwrap();
            diesel::insert_into(mcp_mandates::table)
                .values((
                    mcp_mandates::session_id.eq(&sid),
                    mcp_mandates::mandate_id.eq("m-bad"),
                    mcp_mandates::state.eq(serde_json::json!("not-an-object")),
                    mcp_mandates::expires_at.eq(Utc::now() + chrono::Duration::hours(1)),
                    mcp_mandates::updated_at.eq(Utc::now()),
                ))
                .execute(&mut conn)
                .await
                .unwrap();
        }
        lock_store().remove(&sid);
        let check = handle(
            Some(&pool),
            AccessRequest::CheckStepAuthorized {
                session_id: sid.clone(),
                tool: "echo".into(),
                arguments_json: json!({"message": "access-pdp"}).to_string(),
                now_unix: 1_001.0,
            },
        )
        .await;
        match check {
            AccessResponse::McpCheckStepDenied { reason } => assert_eq!(reason, "no_mandate"),
            other => panic!("{other:?}"),
        }
        assert!(
            mandate_row_exists(&pool, &sid).await,
            "load decode fail must not DELETE the row"
        );
        delete_mandate_row(&pool, &sid).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn clear_deletes_persisted_mandate() {
        let pool = test_pool().await;
        let sid = sid();
        delete_mandate_row(&pool, &sid).await;
        let _ = handle(
            Some(&pool),
            AccessRequest::SealMcpMandate {
                session_id: sid.clone(),
                mandate_id: "m-clear".into(),
                asset_id: "asset-1".into(),
                contract_json: contract_json(),
                now_unix: 1_000.0,
            },
        )
        .await;
        assert!(mandate_row_exists(&pool, &sid).await);
        let ack = handle(
            Some(&pool),
            AccessRequest::ClearMcpMandate {
                session_id: sid.clone(),
            },
        )
        .await;
        assert!(matches!(ack, AccessResponse::McpMandateAck));
        assert!(!mandate_row_exists(&pool, &sid).await);
        lock_store().remove(&sid);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn expired_checkstep_deletes_persisted_mandate() {
        let pool = test_pool().await;
        let sid = sid();
        delete_mandate_row(&pool, &sid).await;
        let _ = handle(
            Some(&pool),
            AccessRequest::SealMcpMandate {
                session_id: sid.clone(),
                mandate_id: "m-exp".into(),
                asset_id: "asset-1".into(),
                contract_json: contract_json(),
                now_unix: 1_000.0,
            },
        )
        .await;
        lock_store().remove(&sid);
        let check = handle(
            Some(&pool),
            AccessRequest::CheckStepAuthorized {
                session_id: sid.clone(),
                tool: "echo".into(),
                arguments_json: json!({"message": "access-pdp"}).to_string(),
                now_unix: 1_000.0 + 10_000.0,
            },
        )
        .await;
        match check {
            AccessResponse::McpCheckStepDenied { reason } => {
                assert_eq!(reason, "mission_expired");
            }
            other => panic!("{other:?}"),
        }
        assert!(
            !mandate_row_exists(&pool, &sid).await,
            "TTL expire must DELETE mcp_mandates"
        );
    }

    #[test]
    fn attack_checkstep_drift_is_rejected() {
        let session_id = sid();
        let sealed = ram_handle(AccessRequest::SealMcpMandate {
            session_id: session_id.clone(),
            mandate_id: "m-attack".into(),
            asset_id: "asset-1".into(),
            contract_json: contract_json(),
            now_unix: 2_000.0,
        });
        assert!(matches!(sealed, AccessResponse::McpMandateSealed { .. }));
        match ram_handle(AccessRequest::CheckStepAuthorized {
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
            ram_handle(AccessRequest::SealMcpMandate {
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
                ram_handle(AccessRequest::CheckStepAuthorized {
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
        let sealed = ram_handle(AccessRequest::SealMcpMandate {
            session_id: session_id.clone(),
            mandate_id: "m-prop".into(),
            asset_id: "asset-1".into(),
            contract_json: tests::contract_json(),
            now_unix: 4_000.0,
        });
        let sealed_ok = matches!(sealed, AccessResponse::McpMandateSealed { .. });
        proptest::prop_assert!(sealed_ok);
        let denied = ram_handle(AccessRequest::CheckStepAuthorized {
            session_id,
            tool,
            arguments_json: serde_json::json!({"message": "access-pdp"}).to_string(),
            now_unix: 4_001.0,
        });
        let denied_ok = matches!(denied, AccessResponse::McpCheckStepDenied { .. });
        proptest::prop_assert!(denied_ok);
    }
}
