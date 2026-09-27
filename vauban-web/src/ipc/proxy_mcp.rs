//! IPC client for communication with vauban-proxy-mcp.
//!
//! `vauban-proxy-mcp` is the MCP Streamable-HTTP L7 proxy (Lot 1a,
//! see `docs/specs/vauban-mcp/`). vauban-web is the **control plane**:
//! it computes the authorization envelope once (via vauban-access),
//! mints the SessionToken / `vbw_` bearer, and pushes a frozen copy of
//! the whitelist / constraints / envelope / **vault ciphertext** to the
//! proxy via `McpSessionOpen`. The proxy VaultDecrypts credentials once
//! at open. Every `tools/call` afterwards is decided by the proxy alone
//! (fail-closed, no RPC back to Access).
//!
//! The wire surface is intentionally small: a single open verb
//! (`McpSessionOpen` -> `McpSessionOpened`), an update verb
//! (`McpSessionUpdate`, fire-and-forget, used by the 30 s recheck),
//! and a terminate verb (`McpSessionTerminate`, fire-and-forget, used
//! by session-close / the revocation watchdog). See
//! `shared/src/messages.rs` for the full wire definitions.

use crate::error::AppResult;
use crate::ipc::correlated::{CorrelatedIpcCore, CorrelatedIpcErrorExt, deliver_or_warn};
use shared::messages::Message;
use std::collections::HashMap;
use std::io;
use std::os::unix::io::RawFd;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::Duration;
use tokio::sync::oneshot;
use tracing::{debug, warn};

const MCP_OPEN_TIMEOUT: Duration = Duration::from_secs(30);

/// Request to open an MCP session on `vauban-proxy-mcp`.
///
/// Every field here becomes the proxy's frozen, in-memory copy of the
/// authorization decision (contract §2, IPC `McpSessionOpen`). The
/// proxy never re-asks Access for a `tools/call` decision.
#[derive(Clone, Debug)]
pub struct McpSessionOpenRequest {
    pub session_id: String,
    pub asset_id: String,
    pub user_id: String,
    /// UUID of the `api_keys` row that opened the session, or empty when
    /// the open came from Connect UI (human JWT — no API token).
    /// Never a user UUID (M7 / docs/specs/vauban-mcp/05-contrats.md).
    pub api_key_id: String,
    /// RFC3339 timestamp.
    pub expires_at: String,
    /// BLAKE3 (or SHA-256; fixed by the proxy implementation) of the
    /// raw `vbw_` bearer. vauban-web never re-sends the bearer itself.
    pub vbw_hash: [u8; 32],
    /// `None` = every `approved` tool in the catalogue; `Some([])` =
    /// deny-all; `Some([...])` = exactly these tools.
    pub allowed_tools: Option<Vec<String>>,
    /// JSON object mapping tool name -> arg constraints. `"{}"` when
    /// no destructive tool is in scope.
    pub tool_constraints_json: String,
    pub envelope_max_calls: u32,
    pub envelope_window_seconds: u32,
    /// `"throttle"` | `"alert"` | `"suspend"` (09 Phase C; suspend
    /// requires Resume/Terminate recours shipped in the same jalon).
    pub envelope_on_exceed: String,
    pub upstream_host: String,
    pub upstream_port: u16,
    /// SPKI pin `SHA256:<b64>` (RDP fingerprint format). Present → HTTPS-on-FD
    /// + enforce; `None` → lab plaintext HTTP on the brokered FD.
    pub upstream_tls_spki_pin: Option<String>,
    pub forward_identity_headers: bool,
    /// Vault ciphertext bytes of the upstream credential (e.g. bearer
    /// token). Decrypted by the proxy exactly once, at open.
    pub credential_blob: Vec<u8>,
    pub justification: String,
    pub max_body_bytes: u64,
    /// Cryptographic session token (BLAKE3-keyed MAC) issued by
    /// vauban-access, verified by vauban-proxy-mcp BEFORE trusting
    /// the rest of this payload -- same invariant as SSH/RDP/IACS.
    pub session_token: Vec<u8>,
}

/// Response from opening an MCP session.
#[derive(Debug, Clone)]
pub struct McpSessionOpened {
    pub request_id: u64,
    pub session_id: String,
    pub success: bool,
    pub error: Option<String>,
}

/// Update pushed on the 30 s Access recheck (contract §3). The proxy
/// REPLACES its copy; it never widens a whitelist unilaterally sent
/// by a (potentially compromised) web -- new tool names absent from
/// the current copy are dropped server-side and audited as
/// `mcp_privilege_escalation_attempt` (rule T1).
#[derive(Clone, Debug)]
pub struct McpSessionUpdateRequest {
    pub session_id: String,
    pub allowed_tools: Option<Vec<String>>,
    pub tool_constraints_json: String,
    pub envelope_max_calls: u32,
    pub envelope_window_seconds: u32,
    pub envelope_on_exceed: String,
    /// Only ever tightens (`Some(t)` with `t <= current`); the proxy
    /// ignores any attempt to extend a session's lifetime here.
    pub expires_at: Option<String>,
}

/// Async client for communicating with vauban-proxy-mcp.
///
/// Transport/correlation is owned by [`CorrelatedIpcCore`] (30 s open
/// timeout, matching SSH/RDP/IACS -- INV-CORR-5).
/// In-memory HITL pending mirrored from proxy notifies (UI/API listing).
#[derive(Debug, Clone)]
pub struct McpHitlPendingEntry {
    pub session_id: String,
    pub pending_id: String,
    pub tool: String,
    pub args_blake3: String,
    pub expires_at: String,
    pub requester_user_id: String,
    pub requester_api_key_id: String,
    pub plan_contract_json: String,
    pub plan_story_json: String,
    pub mandate_id: String,
    pub sealed_digest: String,
}

#[derive(Debug, Clone)]
pub struct McpDiscoverRequest {
    pub session_id: String,
    pub asset_id: String,
    pub user_id: String,
    pub upstream_host: String,
    pub upstream_port: u16,
    pub credential_blob: Vec<u8>,
    pub session_token: Vec<u8>,
    /// `SHA256:<base64>` SPKI pin → HTTPS discover. `None` = lab HTTP.
    pub upstream_tls_spki_pin: Option<String>,
}

#[derive(Debug, Clone)]
pub struct McpDiscovered {
    pub request_id: u64,
    pub session_id: String,
    pub success: bool,
    pub tools_json: Option<String>,
    pub error: Option<String>,
}

/// Keep unparseable `expires_at` visible (do not hide a live pending).
fn hitl_unexpired(expires_at: &str) -> bool {
    match chrono::DateTime::parse_from_rfc3339(expires_at) {
        Ok(t) => t > chrono::Utc::now(),
        Err(_) => true,
    }
}

pub struct ProxyMcpClient {
    core: CorrelatedIpcCore,
    pending_open_requests: StdMutex<HashMap<u64, oneshot::Sender<McpSessionOpened>>>,
    pending_discover_requests: StdMutex<HashMap<u64, oneshot::Sender<McpDiscovered>>>,
    hitl_pendings: StdMutex<HashMap<String, McpHitlPendingEntry>>,
    /// Set after AppState is built — applies envelope auto-suspend DB updates.
    runtime: StdMutex<Option<crate::AppState>>,
}

impl ProxyMcpClient {
    /// Create a new MCP proxy client. File descriptors are passed by
    /// the supervisor.
    pub fn new(read_fd: RawFd, write_fd: RawFd) -> io::Result<Arc<Self>> {
        Ok(Arc::new(Self {
            core: CorrelatedIpcCore::from_fds(read_fd, write_fd)?,
            pending_open_requests: StdMutex::new(HashMap::new()),
            pending_discover_requests: StdMutex::new(HashMap::new()),
            hitl_pendings: StdMutex::new(HashMap::new()),
            runtime: StdMutex::new(None),
        }))
    }

    /// Push a frozen authorization envelope to proxy-mcp for a new
    /// session. Sends `McpSessionOpen`, waits for `McpSessionOpened`,
    /// times out after 30 s.
    /// Bind AppState so proxy→web state notifies can update `proxy_sessions`.
    pub fn set_runtime(&self, state: crate::AppState) {
        if let Ok(mut g) = self.runtime.lock() {
            *g = Some(state);
        }
    }

    pub async fn open_session(
        &self,
        request: McpSessionOpenRequest,
    ) -> AppResult<McpSessionOpened> {
        let request_id = self.core.alloc_id();
        let session_id = request.session_id.clone();

        debug!(
            request_id = request_id,
            session_id = %session_id,
            upstream_host = %request.upstream_host,
            upstream_port = request.upstream_port,
            "Opening MCP session"
        );

        let msg = Message::McpSessionOpen {
            request_id,
            ipc_version: 1,
            session_id,
            asset_id: request.asset_id,
            user_id: request.user_id,
            api_key_id: request.api_key_id,
            expires_at: request.expires_at,
            vbw_hash: request.vbw_hash,
            allowed_tools: request.allowed_tools,
            tool_constraints_json: request.tool_constraints_json,
            envelope_max_calls: request.envelope_max_calls,
            envelope_window_seconds: request.envelope_window_seconds,
            envelope_on_exceed: request.envelope_on_exceed,
            upstream_host: request.upstream_host,
            upstream_port: request.upstream_port,
            upstream_tls_spki_pin: request.upstream_tls_spki_pin,
            forward_identity_headers: request.forward_identity_headers,
            credential_blob: request.credential_blob,
            justification: request.justification,
            max_body_bytes: request.max_body_bytes,
            session_token: request.session_token,
        };

        self.core
            .request(
                &self.pending_open_requests,
                request_id,
                &msg,
                Some(MCP_OPEN_TIMEOUT),
            )
            .await
            .map_err(|e| e.into_app_ipc())
    }

    /// Admin TOFU discover (Phase 2.1): proxy runs initialize+tools/list
    /// on a brokered FD. No free reqwest from web.
    pub async fn discover_tools(&self, request: McpDiscoverRequest) -> AppResult<McpDiscovered> {
        let request_id = self.core.alloc_id();
        let session_id = request.session_id.clone();
        debug!(
            request_id = request_id,
            session_id = %session_id,
            host = %request.upstream_host,
            port = request.upstream_port,
            "MCP discover via proxy"
        );
        let msg = Message::McpDiscover {
            request_id,
            session_id,
            asset_id: request.asset_id,
            user_id: request.user_id,
            upstream_host: request.upstream_host,
            upstream_port: request.upstream_port,
            credential_blob: request.credential_blob,
            session_token: request.session_token,
            upstream_tls_spki_pin: request.upstream_tls_spki_pin,
        };
        self.core
            .request(
                &self.pending_discover_requests,
                request_id,
                &msg,
                Some(MCP_OPEN_TIMEOUT),
            )
            .await
            .map_err(|e| e.into_app_ipc())
    }

    /// Push a tightened envelope on the 30 s Access recheck.
    /// Fire-and-forget: the proxy applies rule T1 (never widen) and
    /// audits any dropped addition on its own.
    pub fn update_session(&self, request: McpSessionUpdateRequest) -> AppResult<()> {
        let request_id = self.core.alloc_id();
        let msg = Message::McpSessionUpdate {
            request_id,
            session_id: request.session_id,
            allowed_tools: request.allowed_tools,
            tool_constraints_json: request.tool_constraints_json,
            envelope_max_calls: request.envelope_max_calls,
            envelope_window_seconds: request.envelope_window_seconds,
            envelope_on_exceed: request.envelope_on_exceed,
            expires_at: request.expires_at,
        };
        self.core
            .send_fire_and_forget(&msg)
            .map_err(|e| e.into_app_ipc())
    }

    /// Force-terminate a live MCP session (session close, revocation
    /// watchdog, or Access-down x3). Fire-and-forget: the proxy stops
    /// accepting `tools/call` on this `vbw_` and finalizes recording.
    pub fn terminate_session(&self, session_id: &str, reason: &str) -> AppResult<()> {
        let request_id = self.core.alloc_id();
        let msg = Message::McpSessionTerminate {
            request_id,
            session_id: session_id.to_string(),
            reason: reason.to_string(),
        };
        self.core
            .send_fire_and_forget(&msg)
            .map_err(|e| e.into_app_ipc())
    }

    /// Phase C: suspend live MCP session (`tools/call` → `-32031`).
    pub fn suspend_session(
        &self,
        session_id: &str,
        reason: &str,
        actor_user_id: &str,
    ) -> AppResult<()> {
        let request_id = self.core.alloc_id();
        let msg = Message::McpSessionSuspend {
            request_id,
            session_id: session_id.to_string(),
            reason: reason.to_string(),
            actor_user_id: actor_user_id.to_string(),
        };
        self.core
            .send_fire_and_forget(&msg)
            .map_err(|e| e.into_app_ipc())
    }

    /// Phase C: resume from suspended (resets envelope counter).
    pub fn resume_session(&self, session_id: &str, actor_user_id: &str) -> AppResult<()> {
        let request_id = self.core.alloc_id();
        let msg = Message::McpSessionResume {
            request_id,
            session_id: session_id.to_string(),
            actor_user_id: actor_user_id.to_string(),
        };
        self.core
            .send_fire_and_forget(&msg)
            .map_err(|e| e.into_app_ipc())
    }

    /// Phase C: HITL approve|deny.
    pub fn hitl_decision(
        &self,
        session_id: &str,
        pending_id: &str,
        decision: &str,
        actor_user_id: &str,
    ) -> AppResult<()> {
        let request_id = self.core.alloc_id();
        let msg = Message::McpHitlDecision {
            request_id,
            session_id: session_id.to_string(),
            pending_id: pending_id.to_string(),
            decision: decision.to_string(),
            actor_user_id: actor_user_id.to_string(),
        };
        // Drop the local mirror only after the proxy accepted the IPC
        // write. Removing first hid a still-pending PEP item from the queue.
        self.core
            .send_fire_and_forget(&msg)
            .map_err(|e| e.into_app_ipc())?;
        if let Ok(mut g) = self.hitl_pendings.lock() {
            g.remove(pending_id);
        }
        Ok(())
    }

    pub fn list_hitl_pendings(&self) -> Vec<McpHitlPendingEntry> {
        match self.hitl_pendings.lock() {
            Ok(mut g) => {
                g.retain(|_, e| hitl_unexpired(&e.expires_at));
                g.values().cloned().collect()
            }
            Err(_) => Vec::new(),
        }
    }

    pub fn get_hitl_pending(&self, pending_id: &str) -> Option<McpHitlPendingEntry> {
        self.hitl_pendings.lock().ok().and_then(|g| {
            g.get(pending_id)
                .filter(|e| hitl_unexpired(&e.expires_at))
                .cloned()
        })
    }

    /// Drain incoming messages from the proxy. Run forever in a
    /// dedicated task. Closes the loop on a `ConnectionClosed` IPC
    /// error (proxy-mcp respawn).
    pub async fn process_incoming(&self) -> AppResult<()> {
        self.core
            .process_loop(|msg| async {
                self.handle_message(msg).await;
            })
            .await
            .map_err(|e| e.into_app_ipc())
    }

    async fn handle_message(&self, msg: Message) {
        match msg {
            Message::McpSessionOpened {
                request_id,
                session_id,
                success,
                error,
            } => {
                debug!(
                    request_id = request_id,
                    session_id = %session_id,
                    success = success,
                    "MCP session opened response"
                );
                let response = McpSessionOpened {
                    request_id,
                    session_id,
                    success,
                    error,
                };
                deliver_or_warn(
                    &self.pending_open_requests,
                    request_id,
                    response,
                    "proxy_mcp",
                );
            }
            Message::McpDiscovered {
                request_id,
                session_id,
                success,
                tools_json,
                error,
            } => {
                debug!(
                    request_id = request_id,
                    session_id = %session_id,
                    success = success,
                    "MCP discover response"
                );
                deliver_or_warn(
                    &self.pending_discover_requests,
                    request_id,
                    McpDiscovered {
                        request_id,
                        session_id,
                        success,
                        tools_json,
                        error,
                    },
                    "proxy_mcp",
                );
            }
            Message::McpHitlPendingNotify {
                session_id,
                pending_id,
                tool,
                args_blake3,
                expires_at,
                requester_user_id,
                requester_api_key_id,
                plan_contract_json,
                plan_story_json,
                mandate_id,
                sealed_digest,
            } => {
                debug!(
                    session_id = %session_id,
                    pending_id = %pending_id,
                    tool = %tool,
                    "MCP HITL pending notify"
                );
                let has_mission_seal =
                    !plan_story_json.trim().is_empty() || !plan_contract_json.trim().is_empty();
                let requester_for_mail = requester_user_id.clone();
                if let Ok(mut g) = self.hitl_pendings.lock() {
                    g.insert(
                        pending_id.clone(),
                        McpHitlPendingEntry {
                            session_id: session_id.clone(),
                            pending_id: pending_id.clone(),
                            tool: tool.clone(),
                            args_blake3,
                            expires_at,
                            requester_user_id,
                            requester_api_key_id,
                            plan_contract_json,
                            plan_story_json,
                            mandate_id,
                            sealed_digest,
                        },
                    );
                }
                let runtime = self.runtime.lock().ok().and_then(|g| g.clone());
                if let Some(state) = runtime {
                    let sid = session_id;
                    let pid = pending_id;
                    let tool_name = tool;
                    tokio::spawn(async move {
                        let _ = state
                            .broadcast
                            .send(
                                &crate::services::broadcast::WsChannel::Notifications,
                                crate::services::broadcast::WsMessage::new(
                                    "jit-notification",
                                    serde_json::json!({
                                        "type": "mcp_hitl_pending",
                                        "session_uuid": sid,
                                        "pending_id": pid,
                                        "tool": tool_name,
                                    })
                                    .to_string(),
                                ),
                            )
                            .await;
                        crate::handlers::web::broadcast_mcp_hitl_badge(&state).await;
                        if let Err(e) = crate::services::mcp_mail::queue_hitl_pending(
                            &state,
                            &sid,
                            &pid,
                            &tool_name,
                            &requester_for_mail,
                            has_mission_seal,
                        )
                        .await
                        {
                            warn!(
                                session_id = %sid,
                                pending_id = %pid,
                                error = %e,
                                "Failed to queue mcp.hitl_pending emails"
                            );
                        }
                    });
                }
            }
            Message::McpMandateDriftNotify {
                session_id,
                tool,
                reason,
                mandate_id,
                sealed_digest: _,
                requester_user_id,
            } => {
                debug!(
                    session_id = %session_id,
                    tool = %tool,
                    reason = %reason,
                    "MCP Mission Seal drift notify"
                );
                let runtime = self.runtime.lock().ok().and_then(|g| g.clone());
                if let Some(state) = runtime {
                    tokio::spawn(async move {
                        if let Err(e) = crate::services::mcp_drift::apply_mandate_drift(
                            &state,
                            &session_id,
                            &tool,
                            &reason,
                            &mandate_id,
                            &requester_user_id,
                        )
                        .await
                        {
                            warn!(
                                session_id = %session_id,
                                error = %e,
                                "failed to apply MCP mandate drift"
                            );
                        }
                    });
                } else {
                    warn!(
                        session_id = %session_id,
                        "MCP mandate drift dropped: runtime AppState not bound yet"
                    );
                }
            }
            Message::McpSessionStateNotify {
                session_id,
                status,
                reason,
            } => {
                debug!(
                    session_id = %session_id,
                    status = %status,
                    reason = %reason,
                    "MCP session state notify"
                );
                let runtime = self.runtime.lock().ok().and_then(|g| g.clone());
                if let Some(state) = runtime {
                    tokio::spawn(async move {
                        if let Err(e) = crate::services::mcp_control::apply_proxy_state_notify(
                            &state,
                            &session_id,
                            &status,
                            &reason,
                        )
                        .await
                        {
                            warn!(
                                session_id = %session_id,
                                status = %status,
                                error = %e,
                                "failed to apply MCP session state notify"
                            );
                        }
                    });
                } else {
                    warn!(
                        session_id = %session_id,
                        "MCP state notify dropped: runtime AppState not bound yet"
                    );
                }
            }
            other => {
                warn!(?other, "Ignoring unexpected message from proxy-mcp");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mcp_session_opened_clone() {
        let r = McpSessionOpened {
            request_id: 7,
            session_id: "s".to_string(),
            success: true,
            error: None,
        };
        let c = r.clone();
        assert_eq!(c.request_id, 7);
        assert!(c.success);
    }

    #[test]
    fn test_open_request_clone_roundtrip() {
        let r = McpSessionOpenRequest {
            session_id: "s".to_string(),
            asset_id: "a".to_string(),
            user_id: "u".to_string(),
            api_key_id: "k".to_string(),
            expires_at: "2026-01-01T00:00:00Z".to_string(),
            vbw_hash: [0u8; 32],
            allowed_tools: Some(vec!["echo".to_string()]),
            tool_constraints_json: "{}".to_string(),
            envelope_max_calls: 120,
            envelope_window_seconds: 60,
            envelope_on_exceed: "throttle".to_string(),
            upstream_host: "127.0.0.1".to_string(),
            upstream_port: 19001,
            upstream_tls_spki_pin: None,
            forward_identity_headers: false,
            credential_blob: vec![],
            justification: "demo".to_string(),
            max_body_bytes: 1_048_576,
            session_token: vec![1, 2, 3],
        };
        let c = r.clone();
        assert_eq!(c.session_id, r.session_id);
        assert_eq!(c.upstream_port, r.upstream_port);
        assert_eq!(c.allowed_tools, r.allowed_tools);
    }

    /// Phase C: Suspend IPC verb is present (recours with Resume).
    #[test]
    fn suspend_resume_ipc_verbs_present() {
        let src = include_str!("proxy_mcp.rs");
        assert!(src.contains("McpSessionSuspend"));
        assert!(src.contains("McpSessionResume"));
        assert!(src.contains("McpHitlDecision"));
    }

    #[test]
    fn hitl_unexpired_keeps_future_and_unparseable() {
        assert!(hitl_unexpired("2099-01-01T00:00:00Z"));
        assert!(hitl_unexpired("not-a-timestamp"));
        assert!(!hitl_unexpired("2020-01-01T00:00:00Z"));
    }

    #[test]
    fn pending_notify_broadcasts_sidebar_badge() {
        let src = include_str!("proxy_mcp.rs");
        let start = src
            .find("Message::McpHitlPendingNotify")
            .expect("McpHitlPendingNotify arm must exist");
        let body = &src[start..];
        let end = body
            .find("Message::McpSessionStateNotify")
            .unwrap_or(body.len());
        let arm = &body[..end];
        assert!(
            arm.contains("broadcast_mcp_hitl_badge"),
            "HITL pending notify must push the sidebar badge"
        );
        assert!(
            arm.contains("queue_hitl_pending"),
            "HITL pending notify must queue mcp.hitl_pending"
        );
    }
}
