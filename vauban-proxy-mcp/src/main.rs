// Relax strict clippy lints in test code where unwrap/expect/panic are idiomatic.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::print_stdout,
        clippy::print_stderr
    )
)]

//! Vauban MCP L7 proxy — Streamable HTTP gateway.
//!
//! Capsicum leaf. Upstream bytes travel only on a supervisor-brokered FD.
//! When spawned by vauban-supervisor, also services the control channel
//! (Ping/Pong/Drain/Shutdown) on a background task.

#[cfg(test)]
mod mcp_pyramid_tests;

mod agent_view;
mod async_ipc;
mod audit;
mod data_pipe;
mod fd_passing;
mod mandate;
mod mcp_recording;
mod phase_c;
mod tls_pin;
mod tool_constraints;
mod tunnel;
mod upstream_http;
mod upstream_rebroker;
mod vault;

use anyhow::Result;
use audit::{McpAudit, open_audit_channel, spawn_audit_writer};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Extension, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use data_pipe::McpIngress;
use fd_passing::{
    FdPassingState, PendingConnections, claim_pending_wait, owned_fd_to_tcp_stream,
    receive_fd_with_retry,
};
use mcp_recording::RecordingLeaseReq;
use phase_c::{
    ClientInfo, HITL_MAX_PENDING_PER_SESSION, HitlPending, HitlStatus, args_blake3,
    extract_pending_id, hitl_decision_blocked, hitl_pending_ttl_secs, purge_expired_hitl,
    validate_on_exceed,
};
use serde_json::{Value, json};
use shared::access_guard::{AccessGuard, AccessGuardMetrics, AccessGuardWiring, PROTOCOL_MCP};
use shared::ipc::IpcChannel;
use shared::messages::{ControlMessage, Message, ServiceStats};
use shared::sandbox as capsicum;
use shared::session_token::proxy_gate as session_token_gate;
use std::collections::{HashMap, VecDeque};
use std::os::unix::io::RawFd;
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex as AsyncMutex, broadcast, mpsc};
use tool_constraints::{
    ToolConstraint, merge_constraints_tighten, parse_constraints_json, validate_tool_args,
};
use tracing::{debug, error, info, warn};
use upstream_rebroker::{McpUpstreamRebroker, is_dead_upstream_io};
use vault::{VaultDecryptClient, materialise_upstream_bearer};

/// Lightweight AccessGuard metrics for the MCP proxy (Droits / M4).
struct McpAccessMetrics {
    granted: AtomicU64,
    denied: AtomicU64,
    timeout: AtomicU64,
    ipc_error: AtomicU64,
}

impl McpAccessMetrics {
    fn new() -> Self {
        Self {
            granted: AtomicU64::new(0),
            denied: AtomicU64::new(0),
            timeout: AtomicU64::new(0),
            ipc_error: AtomicU64::new(0),
        }
    }
}

impl AccessGuardMetrics for McpAccessMetrics {
    fn record_granted(&self) {
        self.granted.fetch_add(1, Ordering::Relaxed);
    }
    fn record_denied(&self) {
        self.denied.fetch_add(1, Ordering::Relaxed);
    }
    fn record_timeout(&self) {
        self.timeout.fetch_add(1, Ordering::Relaxed);
    }
    fn record_ipc_error(&self) {
        self.ipc_error.fetch_add(1, Ordering::Relaxed);
    }
}

const PROTOCOL_VERSIONS: &[&str] = &["2024-11-05", "2025-03-26"];
const SUPPORTED_METHODS: &[&str] = &[
    "initialize",
    "notifications/initialized",
    "tools/list",
    "tools/call",
];

#[derive(Debug)]
struct Session {
    session_id: String,
    vbw_hash: String,
    expires_at: f64,
    allowed_tools: Option<Vec<String>>,
    envelope_max: u32,
    envelope_window: u32,
    on_exceed: String,
    call_times: VecDeque<f64>,
    terminated: bool,
    /// Phase C: reversible pause (`tools/call` → `-32031`).
    suspended: bool,
    justification: String,
    /// Web user UUID when opened via supervisor IPC; empty for local register.
    user_id: Option<String>,
    api_key_id: Option<String>,
    /// Access-rule asset UUID (Mission Seal `sealed_digest` bind). Lab
    /// HTTP register may leave this empty.
    asset_id: Option<String>,
    /// Per-session upstream MCP URL (`http://host:port/mcp`). Falls
    /// back to the process-wide `UPSTREAM_URL` when empty.
    upstream_url: Option<String>,
    /// Upstream bearer materialised via VaultDecrypt at open (never
    /// plaintext from web IPC). Forwarded as `Authorization: Bearer`.
    /// `None` when the asset has no secret. Hop 1 materialises it via Vault.
    upstream_bearer: Option<String>,
    /// Brokered upstream (SCM_RIGHTS): plaintext HTTP or TLS+SPKI.
    upstream_stream: Option<Arc<AsyncMutex<upstream_http::UpstreamIo>>>,
    /// Hop-1 SessionToken bytes — re-presented on IACS-style re-broker.
    session_token: Vec<u8>,
    upstream_host: String,
    upstream_port: u16,
    /// SPKI pin (`SHA256:<b64>`) when TLS is enabled; None for lab HTTP.
    upstream_tls_spki_pin: Option<String>,
    /// Per-tool arg constraints for destructive tools (M10). Empty = no extra gate.
    tool_constraints: HashMap<String, ToolConstraint>,
    /// Pin from first successful `initialize` (09 §6).
    client_info: Option<ClientInfo>,
    /// ClientInfo pin is always on.
    clientinfo_pin: bool,
    /// In-flight HITL pendings keyed by pending_id.
    hitl_pendings: HashMap<String, HitlPending>,
    /// Active Mission Seal mandate (post-Approve). Display / lab fallback.
    /// Supervised CheckStep SoT is vauban-access.
    mandate: Option<mandate::MandateState>,
    /// `direct` or `tunnel`. Frozen at `McpSessionOpen`.
    transport: String,
    /// Production visits treat every unsealed `tools/call` as Require plan.
    require_seal: bool,
}

#[derive(Clone)]
struct GatewayState {
    inner: Arc<Mutex<GatewayInner>>,
    audit: McpAudit,
    /// Fire-and-forget notifies toward vauban-web (HITL pending, etc.).
    web_notify_tx: Option<mpsc::UnboundedSender<Message>>,
    /// When wired (supervisor), Mission Seal PDP is vauban-access.
    access_guard: Option<Arc<AccessGuard>>,
    /// Mid-visit TcpConnect (same token). Set after FD socket is ready.
    rebroker: Arc<OnceLock<Arc<McpUpstreamRebroker>>>,
}

#[derive(Default)]
struct GatewayInner {
    sessions: HashMap<String, Session>,
    by_hash: HashMap<String, String>,
    alert_dedup: HashMap<String, f64>,
}

impl GatewayState {
    fn new(audit: McpAudit, web_notify_tx: Option<mpsc::UnboundedSender<Message>>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(GatewayInner::default())),
            audit,
            web_notify_tx,
            access_guard: None,
            rebroker: Arc::new(OnceLock::new()),
        }
    }

    fn notify_web(&self, msg: Message) {
        if let Some(ref tx) = self.web_notify_tx
            && let Err(e) = tx.send(msg)
        {
            warn!(error = %e, "MCP web notify dropped");
        }
    }

    fn lock_inner(&self) -> std::sync::MutexGuard<'_, GatewayInner> {
        match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn vbw_hash(token: &str) -> String {
        let hash = blake3::hash(token.as_bytes());
        hash.to_hex().to_string()
    }

    fn resolve_session(&self, headers: &HeaderMap) -> Result<Session, (StatusCode, Json<Value>)> {
        let auth = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !auth.starts_with("Bearer ") {
            return Err(session_error(
                -32003,
                "session_expired_or_unknown",
                StatusCode::UNAUTHORIZED,
            ));
        }
        let token = auth.strip_prefix("Bearer ").unwrap_or("").trim();
        if !token.starts_with("vbw_") {
            return Err(session_error(
                -32003,
                "session_expired_or_unknown",
                StatusCode::UNAUTHORIZED,
            ));
        }
        let digest = Self::vbw_hash(token);
        let mut guard = self.lock_inner();
        let sid = guard.by_hash.get(&digest).cloned().ok_or_else(|| {
            session_error(
                -32003,
                "session_expired_or_unknown",
                StatusCode::UNAUTHORIZED,
            )
        })?;
        let sess = guard.sessions.get_mut(&sid).ok_or_else(|| {
            session_error(
                -32003,
                "session_expired_or_unknown",
                StatusCode::UNAUTHORIZED,
            )
        })?;

        if let Some(hdr_sid) = headers.get("Mcp-Session-Id").and_then(|v| v.to_str().ok())
            && hdr_sid != sess.session_id
        {
            sess.terminated = true;
            return Err(session_error(
                -32004,
                "session_terminated",
                StatusCode::UNAUTHORIZED,
            ));
        }
        if sess.terminated {
            return Err(session_error(
                -32004,
                "session_terminated",
                StatusCode::UNAUTHORIZED,
            ));
        }
        let now = unix_now();
        if now > sess.expires_at {
            sess.terminated = true;
            let sid = sess.session_id.clone();
            drop(guard);
            self.spawn_clear_mcp_mandate(&sid);
            return Err(session_error(
                -32003,
                "session_expired_or_unknown",
                StatusCode::UNAUTHORIZED,
            ));
        }

        Ok(Session {
            session_id: sess.session_id.clone(),
            vbw_hash: sess.vbw_hash.clone(),
            expires_at: sess.expires_at,
            allowed_tools: sess.allowed_tools.clone(),
            envelope_max: sess.envelope_max,
            envelope_window: sess.envelope_window,
            on_exceed: sess.on_exceed.clone(),
            call_times: sess.call_times.clone(),
            terminated: sess.terminated,
            suspended: sess.suspended,
            justification: sess.justification.clone(),
            user_id: sess.user_id.clone(),
            api_key_id: sess.api_key_id.clone(),
            asset_id: sess.asset_id.clone(),
            upstream_url: sess.upstream_url.clone(),
            upstream_bearer: sess.upstream_bearer.clone(),
            upstream_stream: sess.upstream_stream.clone(),
            session_token: sess.session_token.clone(),
            upstream_host: sess.upstream_host.clone(),
            upstream_port: sess.upstream_port,
            upstream_tls_spki_pin: sess.upstream_tls_spki_pin.clone(),
            tool_constraints: sess.tool_constraints.clone(),
            client_info: sess.client_info.clone(),
            clientinfo_pin: sess.clientinfo_pin,
            hitl_pendings: sess.hitl_pendings.clone(),
            mandate: sess.mandate.clone(),
            transport: sess.transport.clone(),
            require_seal: sess.require_seal,
        })
    }

    fn spawn_clear_mcp_mandate(&self, session_id: &str) {
        let Some(guard) = self.access_guard.clone() else {
            return;
        };
        let sid = session_id.to_string();
        tokio::spawn(async move {
            guard.clear_mcp_mandate(&sid).await;
        });
    }

    fn terminate_session(&self, session_id: &str, reason: &str) {
        let user_id = {
            let mut guard = self.lock_inner();
            if let Some(sess) = guard.sessions.get_mut(session_id) {
                sess.terminated = true;
                sess.user_id.clone()
            } else {
                return;
            }
        };
        self.spawn_clear_mcp_mandate(session_id);
        self.audit
            .finalize_recording(session_id, user_id.as_deref(), reason, false);
    }

    /// Perimeter CheckStep deny: kill the live ticket immediately, then
    /// notify web for IAM + contestable `D-` (async hook must not be the
    /// only cut).
    fn emit_mandate_perimeter_drift(
        &self,
        session_id: &str,
        tool: &str,
        reason: &str,
        mandate_id: &str,
        sealed_digest: &str,
        requester_user_id: &str,
    ) {
        self.terminate_session(session_id, "mandate_drift");
        self.notify_web(Message::McpMandateDriftNotify {
            session_id: session_id.to_string(),
            tool: tool.to_string(),
            reason: reason.to_string(),
            mandate_id: mandate_id.to_string(),
            sealed_digest: sealed_digest.to_string(),
            requester_user_id: requester_user_id.to_string(),
        });
    }

    fn mandate_asset_id(sess: &Session) -> String {
        sess.asset_id
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "mcp".into())
    }

    /// Enter `suspended` if not already terminated. Returns true when newly suspended.
    fn suspend_session(&self, session_id: &str, reason: &str, actor_user_id: Option<&str>) -> bool {
        let user_id = {
            let mut guard = self.lock_inner();
            let Some(sess) = guard.sessions.get_mut(session_id) else {
                return false;
            };
            if sess.terminated || sess.suspended {
                return false;
            }
            sess.suspended = true;
            sess.user_id.clone()
        };
        info!(session_id, reason, "MCP session suspended");
        self.audit
            .record_session_suspended(session_id, user_id.as_deref(), reason, actor_user_id);
        self.notify_web(Message::McpSessionStateNotify {
            session_id: session_id.to_string(),
            status: "suspended".to_string(),
            reason: reason.to_string(),
        });
        true
    }

    /// Leave `suspended`, reset envelope counter. Returns true when resumed.
    fn resume_session(&self, session_id: &str, actor_user_id: &str) -> bool {
        let user_id = {
            let mut guard = self.lock_inner();
            let Some(sess) = guard.sessions.get_mut(session_id) else {
                return false;
            };
            if sess.terminated || !sess.suspended {
                return false;
            }
            sess.suspended = false;
            sess.call_times.clear();
            sess.user_id.clone()
        };
        info!(session_id, actor_user_id, "MCP session resumed");
        self.audit
            .record_session_resumed(session_id, user_id.as_deref(), actor_user_id);
        self.notify_web(Message::McpSessionStateNotify {
            session_id: session_id.to_string(),
            status: "active".to_string(),
            reason: "resume".to_string(),
        });
        true
    }

    /// B-4 / règle d'or: `on_exceed=suspend` only when Resume recours is reachable
    /// (web IPC notify channel attached). Lab HTTP-only must stay throttle|alert.
    fn resume_recours_available(&self) -> bool {
        self.web_notify_tx.is_some()
    }

    fn insert_session(&self, sess: Session) {
        let mut guard = self.lock_inner();
        guard
            .by_hash
            .insert(sess.vbw_hash.clone(), sess.session_id.clone());
        guard.sessions.insert(sess.session_id.clone(), sess);
    }

    fn update_call_times(&self, session_id: &str, times: VecDeque<f64>) {
        if let Some(sess) = self.lock_inner().sessions.get_mut(session_id) {
            sess.call_times = times;
        }
    }

    fn record_alert(&self, session_id: &str, now: f64) {
        self.lock_inner()
            .alert_dedup
            .insert(session_id.to_string(), now);
    }

    fn last_alert(&self, session_id: &str) -> f64 {
        self.lock_inner()
            .alert_dedup
            .get(session_id)
            .copied()
            .unwrap_or(0.0)
    }
}

fn session_error(code: i32, message: &str, status: StatusCode) -> (StatusCode, Json<Value>) {
    (
        status,
        Json(json!({
            "jsonrpc": "2.0",
            "id": null,
            "error": { "code": code, "message": message }
        })),
    )
}

fn clientinfo_pin_from_env() -> bool {
    true
}

fn unix_now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

fn patch_jsonrpc_id(mut body: Value, id: &Value) -> Value {
    if let Some(obj) = body.as_object_mut() {
        obj.insert("id".to_string(), id.clone());
    }
    body
}

/// After a Mission Seal tools/call reaches upstream: memorize result or roll back.
async fn finalize_mandate_upstream(
    state: &GatewayState,
    session_id: &str,
    payload: &Value,
    transport_ok: bool,
) {
    if let Some(guard) = state.access_guard.as_ref() {
        if transport_ok {
            guard.commit_mcp_mandate_step(session_id, payload).await;
        } else {
            guard.rollback_mcp_mandate_step(session_id).await;
        }
    }
    let mut g = state.lock_inner();
    let Some(live) = g.sessions.get_mut(session_id) else {
        return;
    };
    let Some(ref mut m) = live.mandate else {
        return;
    };
    if !transport_ok {
        mandate::rollback_inflight(m);
        return;
    }
    if let Some((step_id, call_digest)) = m.inflight.clone() {
        mandate::commit_step_result(m, &step_id, &call_digest, payload.clone());
        // Keep the mandate object after complete so a new Story+Contract
        // can replace it. PEP CheckStep is inactive once all_steps_done.
    }
}

/// Mirror a local seal into vauban-access when AccessGuard is wired.
async fn pdp_mirror_seal(
    state: &GatewayState,
    session_id: &str,
    mandate_id: &str,
    asset_id: &str,
    contract_json: &str,
    now: f64,
) {
    let Some(guard) = state.access_guard.as_ref() else {
        return;
    };
    if let Err(e) = guard
        .seal_mcp_mandate(session_id, mandate_id, asset_id, contract_json, now)
        .await
    {
        warn!(
            session_id,
            error = %e,
            "access SealMcpMandate failed (PEP will fail-closed on CheckStep)"
        );
    }
}

fn rfc3339_from_secs(secs: f64) -> String {
    let total = secs as i64;
    let days = total.div_euclid(86_400);
    let rem = total.rem_euclid(86_400);
    let hours = rem / 3600;
    let minutes = (rem % 3600) / 60;
    let seconds = rem % 60;
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if mp < 10 { y } else { y + 1 };
    (year, m, d)
}

mod hex {
    pub fn encode(bytes: [u8; 32]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

fn jsonrpc_err(id: Value, code: i32, message: &str, data: Option<Value>) -> Value {
    let mut err = json!({ "code": code, "message": message });
    if let Some(d) = data {
        err["data"] = d;
    }
    json!({ "jsonrpc": "2.0", "id": id, "error": err })
}

fn tool_allowed(sess: &Session, name: &str) -> bool {
    // Fail-closed (M4 / Droits): missing whitelist never means allow-all.
    match &sess.allowed_tools {
        None => false,
        Some(tools) => tools.iter().any(|t| t == name),
    }
}

fn check_envelope(state: &GatewayState, sess: &mut Session) -> Option<Value> {
    let now = unix_now();
    while let Some(front) = sess.call_times.front().copied() {
        if now - front > sess.envelope_window as f64 {
            sess.call_times.pop_front();
        } else {
            break;
        }
    }
    sess.call_times.push_back(now);
    if sess.call_times.len() <= sess.envelope_max as usize {
        state.update_call_times(&sess.session_id, sess.call_times.clone());
        return None;
    }
    if sess.on_exceed == "alert" {
        let last = state.last_alert(&sess.session_id);
        if now - last >= 60.0 {
            state.record_alert(&sess.session_id, now);
            warn!(
                session_id = %sess.session_id,
                count = sess.call_times.len(),
                "MCP envelope threshold (alert mode)"
            );
            state.audit.record_envelope_threshold(
                &sess.session_id,
                sess.user_id.as_deref(),
                sess.call_times.len(),
                sess.envelope_max,
                sess.envelope_window,
            );
        }
        state.update_call_times(&sess.session_id, sess.call_times.clone());
        return None;
    }
    if sess.on_exceed == "suspend" {
        state.update_call_times(&sess.session_id, sess.call_times.clone());
        state.suspend_session(&sess.session_id, "envelope", None);
        sess.suspended = true;
        return Some(jsonrpc_err(Value::Null, -32031, "session_suspended", None));
    }
    Some(jsonrpc_err(Value::Null, -32029, "rate_limited", None))
}

fn filter_tools_list(sess: &Session, result: Value) -> Value {
    let require_vauban = match &sess.mandate {
        None => true,
        Some(m) => mandate::all_steps_done(m),
    };
    agent_view::filter_and_enrich_tools(
        result,
        sess.allowed_tools.as_deref(),
        &sess.tool_constraints,
        require_vauban,
    )
}

enum PdpGate {
    /// Deny / replay / expired — do not continue HITL or upstream.
    Stop(Response),
    /// Access CheckStep Allow — skip local CheckStep, go upstream.
    AllowUpstream,
    /// No mandate in access (or no guard work) — keep local / HITL path.
    ContinueLocal,
}

/// Mirror an access PDP Allow onto `Session.mandate` (consumed + inflight).
fn sync_local_mandate_after_pdp_allow(
    state: &GatewayState,
    session_id: &str,
    name: &str,
    args: Option<&Value>,
) {
    let mut g = state.lock_inner();
    let Some(live) = g.sessions.get_mut(session_id) else {
        return;
    };
    let Some(m) = live.mandate.as_mut() else {
        return;
    };
    let _ = mandate::check_step(m, name, args);
}

/// Supervised PDP: CheckStep lives in vauban-access (same class as
/// AccessGuard for SSH/RDP). Local `Session.mandate` is display/fallback.
#[allow(clippy::too_many_arguments)]
async fn pdp_check_via_access(
    state: &GatewayState,
    sess: &Session,
    req_id: &Value,
    name: &str,
    args: Option<&Value>,
    params: &Value,
    require_plan: bool,
    now: f64,
) -> PdpGate {
    let Some(guard) = state.access_guard.as_ref() else {
        return PdpGate::ContinueLocal;
    };
    let (plan, mandate_id, sealed_digest) = {
        let g = state.lock_inner();
        match g.sessions.get(&sess.session_id) {
            Some(live) => match live.mandate.as_ref() {
                Some(m) => {
                    let plan = mandate::plan_mandate_pdp(Some(m), require_plan, params);
                    (plan, m.mandate_id.clone(), m.sealed_digest.clone())
                }
                None => (
                    mandate::MandatePdpPlan::NoMandate,
                    String::new(),
                    String::new(),
                ),
            },
            _ => (
                mandate::MandatePdpPlan::NoMandate,
                String::new(),
                String::new(),
            ),
        }
    };
    if matches!(plan, mandate::MandatePdpPlan::Replace) {
        guard.clear_mcp_mandate(&sess.session_id).await;
        let mut g = state.lock_inner();
        if let Some(live) = g.sessions.get_mut(&sess.session_id) {
            live.mandate = None;
        }
        return PdpGate::ContinueLocal;
    }
    if !matches!(plan, mandate::MandatePdpPlan::CheckStep) {
        return PdpGate::ContinueLocal;
    }

    let args_v = args.cloned().unwrap_or(Value::Null);
    match guard
        .check_step_authorized(&sess.session_id, name, &args_v, now)
        .await
    {
        mandate::CheckStepOutcome::Allow { step_id, .. } => {
            info!(
                session_id = %sess.session_id,
                %step_id,
                tool = %name,
                "Mission Seal CheckStep allow (access PDP)"
            );
            // Access consumed the step; keep Session.mandate in lockstep
            // so all_steps_done is true after commit. Otherwise a later
            // Story+Contract is planned as CheckStep and -32033s.
            sync_local_mandate_after_pdp_allow(state, &sess.session_id, name, args);
            PdpGate::AllowUpstream
        }
        mandate::CheckStepOutcome::Replay { step_id, cached } => {
            info!(
                session_id = %sess.session_id,
                %step_id,
                tool = %name,
                "Mission Seal CheckStep replay (access PDP)"
            );
            let body = patch_jsonrpc_id(cached, req_id);
            let _ = state.audit.record_tool_call(
                &sess.session_id,
                sess.user_id.as_deref(),
                name,
                "mandate_replay",
                "ok",
                args,
                Some(&body),
            );
            PdpGate::Stop(Json(body).into_response())
        }
        mandate::CheckStepOutcome::Deny { reason } => {
            // Local session has a mandate (we only CheckStep when
            // `has_mandate`); access miss = PDP unavailable, not HITL.
            if reason == "no_mandate" {
                let deny = jsonrpc_err(
                    req_id.clone(),
                    -32010,
                    "upstream_or_recording_sync",
                    Some(json!({
                        "tool": name,
                        "reason": "pdp_unavailable",
                        "mandate_id": mandate_id,
                        "sealed_digest": sealed_digest,
                    })),
                );
                let _ = state.audit.record_tool_call(
                    &sess.session_id,
                    sess.user_id.as_deref(),
                    name,
                    "deny",
                    "pdp_unavailable",
                    args,
                    None,
                );
                return PdpGate::Stop(Json(deny).into_response());
            }
            if reason == "mission_expired" {
                let mut g = state.lock_inner();
                if let Some(live) = g.sessions.get_mut(&sess.session_id) {
                    live.mandate = None;
                }
                let deny = jsonrpc_err(
                    req_id.clone(),
                    mandate::ERR_MISSION_EXPIRED,
                    "mission_expired",
                    Some(json!({ "tool": name, "reason": "mission_expired" })),
                );
                let _ = state.audit.record_tool_call(
                    &sess.session_id,
                    sess.user_id.as_deref(),
                    name,
                    "deny",
                    "mission_expired",
                    args,
                    None,
                );
                return PdpGate::Stop(Json(deny).into_response());
            }
            let (code, message) = if reason == "step_inflight" || reason == "pdp_unavailable" {
                (-32010, "upstream_or_recording_sync")
            } else {
                (mandate::ERR_MANDATE_STEP_DENIED, "mandate_step_denied")
            };
            let deny = jsonrpc_err(
                req_id.clone(),
                code,
                message,
                Some(json!({
                    "tool": name,
                    "reason": reason,
                    "mandate_id": mandate_id,
                    "sealed_digest": sealed_digest,
                })),
            );
            let _ = state.audit.record_tool_call(
                &sess.session_id,
                sess.user_id.as_deref(),
                name,
                "deny",
                reason,
                args,
                None,
            );
            if mandate::is_perimeter_drift(reason) {
                state.emit_mandate_perimeter_drift(
                    &sess.session_id,
                    name,
                    reason,
                    &mandate_id,
                    &sealed_digest,
                    sess.user_id.as_deref().unwrap_or(""),
                );
            }
            PdpGate::Stop(Json(deny).into_response())
        }
    }
}

/// HITL / Mission Seal for `tools/call`. `None` = proceed to upstream.
///
/// Classic HITL: one-shot Approve then re-emit (pending_id or tool+digest match).
/// Mission Seal (`require_plan`): first call seals Contract → -32030; after
/// Approve, CheckStep enforces literal bindings (-32033 on drift).
#[allow(clippy::too_many_arguments, clippy::let_and_return)]
async fn handle_hitl_tools_call(
    state: &GatewayState,
    sess: &Session,
    req_id: &Value,
    name: &str,
    args: Option<&Value>,
    params: &Value,
    pending_id: Option<&str>,
    require_plan: bool,
) -> Option<Response> {
    let digest = args_blake3(args);
    let now = unix_now();

    if state.access_guard.is_some() {
        match pdp_check_via_access(state, sess, req_id, name, args, params, require_plan, now).await
        {
            PdpGate::Stop(resp) => return Some(resp),
            PdpGate::AllowUpstream => return None,
            PdpGate::ContinueLocal => {}
        }
    }

    // Active mandate: CheckStep before upstream (PEP).
    // Lock is released before terminate+notify (avoid deadlock).
    let mut mandate_early: Option<Response> = None;
    let mut mandate_allow = false;
    let mut mandate_drift: Option<(String, String, String, String, String, String)> = None;
    let mut clear_access_mandate = false;
    {
        let mut guard = state.lock_inner();
        if let Some(live) = guard.sessions.get_mut(&sess.session_id) {
            if live
                .mandate
                .as_ref()
                .is_some_and(|m| mandate::is_expired(m, now))
            {
                info!(
                    session_id = %sess.session_id,
                    "Mission Seal mandate expired; clearing"
                );
                live.mandate = None;
                clear_access_mandate = true;
                let deny = jsonrpc_err(
                    req_id.clone(),
                    mandate::ERR_MISSION_EXPIRED,
                    "mission_expired",
                    Some(json!({
                        "tool": name,
                        "reason": "mission_expired",
                    })),
                );
                let _ = state.audit.record_tool_call(
                    &sess.session_id,
                    sess.user_id.as_deref(),
                    name,
                    "deny",
                    "mission_expired",
                    args,
                    None,
                );
                mandate_early = Some(Json(deny).into_response());
            } else {
                match mandate::plan_mandate_pdp(live.mandate.as_ref(), require_plan, params) {
                    mandate::MandatePdpPlan::Replace => {
                        info!(
                            session_id = %sess.session_id,
                            "Mission Seal complete; accepting new seal"
                        );
                        live.mandate = None;
                    }
                    mandate::MandatePdpPlan::CheckStep
                    | mandate::MandatePdpPlan::Inactive
                    | mandate::MandatePdpPlan::NoMandate => {}
                }
                if let Some(ref mut mandate) = live.mandate
                    && mandate::pep_mandate_active(mandate)
                {
                    match mandate::check_step(mandate, name, args) {
                        mandate::CheckStepOutcome::Allow { step_id, .. } => {
                            info!(
                                session_id = %sess.session_id,
                                %step_id,
                                tool = %name,
                                "Mission Seal CheckStep allow"
                            );
                            mandate_allow = true;
                        }
                        mandate::CheckStepOutcome::Replay { step_id, cached } => {
                            info!(
                                session_id = %sess.session_id,
                                %step_id,
                                tool = %name,
                                "Mission Seal CheckStep replay (cached; no upstream)"
                            );
                            let body = patch_jsonrpc_id(cached, req_id);
                            let _ = state.audit.record_tool_call(
                                &sess.session_id,
                                sess.user_id.as_deref(),
                                name,
                                "mandate_replay",
                                "ok",
                                args,
                                Some(&body),
                            );
                            mandate_early = Some(Json(body).into_response());
                        }
                        mandate::CheckStepOutcome::Deny { reason } => {
                            let (code, message) = if reason == "step_inflight" {
                                (-32010, "upstream_or_recording_sync")
                            } else {
                                (mandate::ERR_MANDATE_STEP_DENIED, "mandate_step_denied")
                            };
                            let deny = jsonrpc_err(
                                req_id.clone(),
                                code,
                                message,
                                Some(json!({
                                    "tool": name,
                                    "reason": reason,
                                    "mandate_id": mandate.mandate_id,
                                    "sealed_digest": mandate.sealed_digest,
                                })),
                            );
                            let _ = state.audit.record_tool_call(
                                &sess.session_id,
                                sess.user_id.as_deref(),
                                name,
                                "deny",
                                reason,
                                args,
                                None,
                            );
                            if mandate::is_perimeter_drift(reason) {
                                mandate_drift = Some((
                                    sess.session_id.clone(),
                                    name.to_string(),
                                    reason.to_string(),
                                    mandate.mandate_id.clone(),
                                    mandate.sealed_digest.clone(),
                                    sess.user_id.clone().unwrap_or_default(),
                                ));
                            }
                            mandate_early = Some(Json(deny).into_response());
                        }
                    }
                }
            }
        }
    }
    if clear_access_mandate {
        state.spawn_clear_mcp_mandate(&sess.session_id);
    }
    if let Some((sid, tool, rsn, mid, digest, uid)) = mandate_drift {
        state.emit_mandate_perimeter_drift(&sid, &tool, &rsn, &mid, &digest, &uid);
    }
    if let Some(resp) = mandate_early {
        return Some(resp);
    }
    if mandate_allow {
        return None;
    }

    enum HitlCallOutcome {
        AllowUpstream,
        ReplayCached(Value),
        Created(HitlPending),
        StillPending(HitlPending),
        ArgsMismatch,
        DeniedExhausted,
        QuotaExceeded,
        BadContract(String),
        MissingContract,
        MissingStory,
        BadStory(String),
        MandateDeny(String),
    }

    let (outcome, created, expired) = {
        let mut guard = state.lock_inner();
        let Some(live) = guard.sessions.get_mut(&sess.session_id) else {
            return Some(
                Json(jsonrpc_err(
                    req_id.clone(),
                    -32003,
                    "session_expired_or_unknown",
                    None,
                ))
                .into_response(),
            );
        };
        let expired = purge_expired_hitl(&mut live.hitl_pendings, now);

        let resolved_pid = pending_id.map(str::to_string).or_else(|| {
            live.hitl_pendings
                .values()
                .find(|p| {
                    p.status == HitlStatus::Approved
                        && p.tool == name
                        && p.args_blake3 == digest
                        && p.expires_at >= now
                })
                .map(|p| p.pending_id.clone())
        });

        if let Some(pid) = resolved_pid {
            let outcome = match live.hitl_pendings.get(&pid).cloned() {
                None => HitlCallOutcome::DeniedExhausted,
                Some(p) if p.tool != name => HitlCallOutcome::DeniedExhausted,
                Some(p) if p.args_blake3 != digest => HitlCallOutcome::ArgsMismatch,
                Some(p) if p.status == HitlStatus::Denied || p.expires_at < now => {
                    live.hitl_pendings.remove(&pid);
                    HitlCallOutcome::DeniedExhausted
                }
                Some(p) if p.status == HitlStatus::Approved => {
                    live.hitl_pendings.remove(&pid);
                    if !p.plan_contract_json.is_empty() {
                        if let Some(ref mut mandate) = live.mandate {
                            match mandate::check_step(mandate, name, args) {
                                mandate::CheckStepOutcome::Allow { .. } => {
                                    HitlCallOutcome::AllowUpstream
                                }
                                mandate::CheckStepOutcome::Replay { cached, .. } => {
                                    HitlCallOutcome::ReplayCached(cached)
                                }
                                mandate::CheckStepOutcome::Deny { reason } => {
                                    HitlCallOutcome::MandateDeny(reason.to_string())
                                }
                            }
                        } else {
                            HitlCallOutcome::DeniedExhausted
                        }
                    } else {
                        HitlCallOutcome::AllowUpstream
                    }
                }
                Some(p) if p.status == HitlStatus::Pending => HitlCallOutcome::StillPending(p),
                Some(_) => HitlCallOutcome::DeniedExhausted,
            };
            (outcome, false, expired)
        } else if require_plan {
            let story = match mandate::extract_story(params) {
                None => (HitlCallOutcome::MissingStory, false, expired),
                Some(raw) => match mandate::parse_story(&raw) {
                    Err(e) => (HitlCallOutcome::BadStory(e), false, expired),
                    Ok(story) => match mandate::extract_contract(params) {
                        None => (HitlCallOutcome::MissingContract, false, expired),
                        Some(raw_c) => match mandate::parse_contract(&raw_c) {
                            Err(e) => (HitlCallOutcome::BadContract(e), false, expired),
                            Ok(contract) => {
                                let matches_call = contract.steps.iter().any(|s| {
                                    s.operation == name
                                        && mandate::digest_args_raw(Some(&s.arguments)) == digest
                                });
                                if !matches_call {
                                    (
                                        HitlCallOutcome::BadContract(
                                            "call_not_in_contract_or_args_mismatch".into(),
                                        ),
                                        false,
                                        expired,
                                    )
                                } else {
                                    let active = live
                                        .hitl_pendings
                                        .values()
                                        .filter(|p| {
                                            p.status == HitlStatus::Pending && p.expires_at >= now
                                        })
                                        .count();
                                    if active >= HITL_MAX_PENDING_PER_SESSION {
                                        (HitlCallOutcome::QuotaExceeded, false, expired)
                                    } else {
                                        let mandate_id = uuid::Uuid::new_v4().to_string();
                                        let asset_id = GatewayState::mandate_asset_id(sess);
                                        match mandate::seal_mandate(
                                            &mandate_id,
                                            &sess.session_id,
                                            &asset_id,
                                            &contract,
                                            now,
                                        ) {
                                            Err(e) => {
                                                (HitlCallOutcome::BadContract(e), false, expired)
                                            }
                                            Ok(sealed) => {
                                                let pending_id = uuid::Uuid::new_v4().to_string();
                                                let expires_at = now + hitl_pending_ttl_secs();
                                                let pending = HitlPending {
                                                    pending_id: pending_id.clone(),
                                                    tool: name.to_string(),
                                                    args_blake3: digest.clone(),
                                                    expires_at,
                                                    status: HitlStatus::Pending,
                                                    plan_contract_json: sealed
                                                        .contract_json
                                                        .clone(),
                                                    plan_story_json: mandate::story_to_json(&story),
                                                    mandate_id: sealed.mandate_id.clone(),
                                                    sealed_digest: sealed.sealed_digest.clone(),
                                                };
                                                live.hitl_pendings
                                                    .insert(pending_id.clone(), pending.clone());
                                                (HitlCallOutcome::Created(pending), true, expired)
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    },
                },
            };
            story
        } else {
            let active = live
                .hitl_pendings
                .values()
                .filter(|p| p.status == HitlStatus::Pending && p.expires_at >= now)
                .count();
            if active >= HITL_MAX_PENDING_PER_SESSION {
                (HitlCallOutcome::QuotaExceeded, false, expired)
            } else {
                let pending_id = uuid::Uuid::new_v4().to_string();
                let expires_at = now + hitl_pending_ttl_secs();
                let pending = HitlPending {
                    pending_id: pending_id.clone(),
                    tool: name.to_string(),
                    args_blake3: digest.clone(),
                    expires_at,
                    status: HitlStatus::Pending,
                    plan_contract_json: String::new(),
                    plan_story_json: String::new(),
                    mandate_id: String::new(),
                    sealed_digest: String::new(),
                };
                live.hitl_pendings
                    .insert(pending_id.clone(), pending.clone());
                (HitlCallOutcome::Created(pending), true, expired)
            }
        }
    };

    for p in &expired {
        state.audit.record_hitl_expired(
            &sess.session_id,
            sess.user_id.as_deref(),
            &p.pending_id,
            &p.tool,
        );
    }

    match outcome {
        HitlCallOutcome::AllowUpstream => None,
        HitlCallOutcome::ReplayCached(cached) => {
            let body = patch_jsonrpc_id(cached, req_id);
            let _ = state.audit.record_tool_call(
                &sess.session_id,
                sess.user_id.as_deref(),
                name,
                "mandate_replay",
                "ok",
                args,
                Some(&body),
            );
            Some(Json(body).into_response())
        }
        HitlCallOutcome::ArgsMismatch => {
            let deny = jsonrpc_err(
                req_id.clone(),
                -32602,
                "invalid_params",
                Some(json!({ "tool": name, "reason": "hitl_args_mismatch" })),
            );
            let _ = state.audit.record_tool_call(
                &sess.session_id,
                sess.user_id.as_deref(),
                name,
                "deny",
                "hitl_args_mismatch",
                args,
                None,
            );
            Some(Json(deny).into_response())
        }
        HitlCallOutcome::MandateDeny(reason) => {
            let (code, message) = if reason == "step_inflight" {
                (-32010, "upstream_or_recording_sync")
            } else {
                (mandate::ERR_MANDATE_STEP_DENIED, "mandate_step_denied")
            };
            let deny = jsonrpc_err(
                req_id.clone(),
                code,
                message,
                Some(json!({ "tool": name, "reason": reason })),
            );
            let _ = state.audit.record_tool_call(
                &sess.session_id,
                sess.user_id.as_deref(),
                name,
                "deny",
                &reason,
                args,
                None,
            );
            if mandate::is_perimeter_drift(&reason) {
                state.emit_mandate_perimeter_drift(
                    &sess.session_id,
                    name,
                    &reason,
                    "",
                    "",
                    sess.user_id.as_deref().unwrap_or_default(),
                );
            }
            Some(Json(deny).into_response())
        }
        HitlCallOutcome::MissingContract => {
            let deny = jsonrpc_err(
                req_id.clone(),
                -32602,
                "invalid_params",
                Some(json!({
                    "tool": name,
                    "reason": "require_plan_missing_contract",
                })),
            );
            Some(Json(deny).into_response())
        }
        HitlCallOutcome::MissingStory => {
            let deny = jsonrpc_err(
                req_id.clone(),
                -32602,
                "invalid_params",
                Some(json!({
                    "tool": name,
                    "reason": "require_plan_story_for_human",
                    "detail": "Story is required: a human supervisor will read it before Approve/Deny. Provide arguments.vauban.story (or _meta.vauban.story for curl) with summary, context, objective, risks.",
                })),
            );
            Some(Json(deny).into_response())
        }
        HitlCallOutcome::BadStory(reason) | HitlCallOutcome::BadContract(reason) => {
            let deny = jsonrpc_err(
                req_id.clone(),
                -32602,
                "invalid_params",
                Some(json!({ "tool": name, "reason": reason })),
            );
            Some(Json(deny).into_response())
        }
        HitlCallOutcome::DeniedExhausted | HitlCallOutcome::QuotaExceeded => {
            let deny = jsonrpc_err(req_id.clone(), -32032, "hitl_denied_or_exhausted", None);
            let _ = state.audit.record_tool_call(
                &sess.session_id,
                sess.user_id.as_deref(),
                name,
                "hitl_deny",
                "hitl_denied_or_exhausted",
                args,
                None,
            );
            Some(Json(deny).into_response())
        }
        HitlCallOutcome::StillPending(p) | HitlCallOutcome::Created(p) => {
            let mut data = json!({
                "pending_id": p.pending_id,
                "tool": p.tool,
                "args_blake3": p.args_blake3,
                "expires_at": rfc3339_from_secs(p.expires_at),
            });
            if !p.mandate_id.is_empty() {
                data["mandate_id"] = json!(p.mandate_id);
                data["sealed_digest"] = json!(p.sealed_digest);
            }
            if created {
                state.audit.record_hitl_pending(
                    &sess.session_id,
                    sess.user_id.as_deref(),
                    &p.pending_id,
                    &p.tool,
                    &p.args_blake3,
                    &rfc3339_from_secs(p.expires_at),
                );
                state.notify_web(Message::McpHitlPendingNotify {
                    session_id: sess.session_id.clone(),
                    pending_id: p.pending_id.clone(),
                    tool: p.tool.clone(),
                    args_blake3: p.args_blake3.clone(),
                    expires_at: rfc3339_from_secs(p.expires_at),
                    requester_user_id: sess.user_id.clone().unwrap_or_default(),
                    requester_api_key_id: sess.api_key_id.clone().unwrap_or_default(),
                    plan_contract_json: p.plan_contract_json.clone(),
                    plan_story_json: p.plan_story_json.clone(),
                    mandate_id: p.mandate_id.clone(),
                    sealed_digest: p.sealed_digest.clone(),
                });
            }
            let err = jsonrpc_err(req_id.clone(), -32030, "tool_approval_required", Some(data));
            let _ = state.audit.record_tool_call(
                &sess.session_id,
                sess.user_id.as_deref(),
                name,
                "hitl_pending",
                "tool_approval_required",
                args,
                None,
            );
            Some(Json(err).into_response())
        }
    }
}

async fn handle_mcp(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    ingress: Option<Extension<McpIngress>>,
    Json(body): Json<Value>,
) -> Response {
    let Some(Extension(ingress)) = ingress else {
        return Json(jsonrpc_err(Value::Null, -32010, "ingress_required", None)).into_response();
    };
    let mut sess = match state.resolve_session(&headers) {
        Ok(s) => s,
        Err(resp) => return resp.into_response(),
    };
    if sess.transport == "tunnel" && matches!(ingress, McpIngress::Direct { .. }) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(jsonrpc_err(
                body.get("id").cloned().unwrap_or(Value::Null),
                -32003,
                "tunnel_required",
                None,
            )),
        )
            .into_response();
    }

    let req_id = body.get("id").cloned().unwrap_or(Value::Null);
    let method = body
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let params = body.get("params").cloned().unwrap_or(json!({}));

    if !SUPPORTED_METHODS.contains(&method.as_str()) {
        return Json(jsonrpc_err(
            req_id,
            -32601,
            "method_not_found",
            Some(json!({ "method": method })),
        ))
        .into_response();
    }

    if method == "initialize" {
        let version = params
            .get("protocolVersion")
            .and_then(Value::as_str)
            .unwrap_or(PROTOCOL_VERSIONS.last().copied().unwrap_or("2025-03-26"));
        if !PROTOCOL_VERSIONS.contains(&version) {
            // 04 §8 / V-10: unsupported version → -32600 then close session.
            state.terminate_session(&sess.session_id, "unsupported_protocol_version");
            return (
                StatusCode::BAD_REQUEST,
                Json(jsonrpc_err(
                    req_id,
                    -32600,
                    "unsupported_protocol_version",
                    None,
                )),
            )
                .into_response();
        }
        if sess.clientinfo_pin {
            match ClientInfo::from_params(&params) {
                None => {
                    state.terminate_session(&sess.session_id, "missing_client_info");
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(jsonrpc_err(req_id, -32600, "missing_client_info", None)),
                    )
                        .into_response();
                }
                Some(info) => {
                    let mut guard = state.lock_inner();
                    if let Some(live) = guard.sessions.get_mut(&sess.session_id) {
                        match &live.client_info {
                            None => {
                                live.client_info = Some(info.clone());
                                sess.client_info = Some(info);
                            }
                            Some(pinned) if pinned == &info => {}
                            Some(pinned) => {
                                let pinned_l = pinned.label();
                                let got_l = info.label();
                                drop(guard);
                                state.audit.record_clientinfo_drift(
                                    &sess.session_id,
                                    sess.user_id.as_deref(),
                                    &pinned_l,
                                    &got_l,
                                );
                                state.terminate_session(&sess.session_id, "clientinfo_drift");
                                return (
                                    StatusCode::BAD_REQUEST,
                                    Json(jsonrpc_err(req_id, -32600, "clientinfo_drift", None)),
                                )
                                    .into_response();
                            }
                        }
                    }
                }
            }
        }
    }

    let mut hitl_oneshot = false;

    if method == "tools/call" {
        let name = params.get("name").and_then(Value::as_str).unwrap_or("");
        let args = params
            .get("arguments")
            .cloned()
            .map(|a| mandate::strip_vauban_args(&a));

        if sess.suspended {
            let deny = jsonrpc_err(req_id.clone(), -32031, "session_suspended", None);
            let _ = state.audit.record_tool_call(
                &sess.session_id,
                sess.user_id.as_deref(),
                name,
                "suspended",
                "session_suspended",
                args.as_ref(),
                None,
            );
            return Json(deny).into_response();
        }

        if let Some(mut err) = check_envelope(&state, &mut sess) {
            if let Some(obj) = err.as_object_mut() {
                obj.insert("id".into(), req_id.clone());
            }
            let decision = if err.pointer("/error/code").and_then(Value::as_i64) == Some(-32031) {
                "suspended"
            } else {
                "throttle"
            };
            let reason = if decision == "suspended" {
                "session_suspended"
            } else {
                "rate_limited"
            };
            warn!(session_id = %sess.session_id, tool = %name, decision, "tools/call envelope");
            let _ = state.audit.record_tool_call(
                &sess.session_id,
                sess.user_id.as_deref(),
                name,
                decision,
                reason,
                args.as_ref(),
                None,
            );
            return Json(err).into_response();
        }
        if !tool_allowed(&sess, name) {
            let tofu_status = sess
                .tool_constraints
                .get(name)
                .and_then(|c| c.status.as_deref());
            let (code, reason) = match tofu_status {
                Some("pending") | Some("tombstone") => (-32002, "tool_pending_or_drift"),
                _ => (-32001, "tool_not_allowed"),
            };
            warn!(
                session_id = %sess.session_id,
                tool = %name,
                reason,
                "tools/call denied"
            );
            let deny = jsonrpc_err(
                req_id.clone(),
                code,
                reason,
                Some(json!({
                    "tool": name,
                    "status": tofu_status,
                    "schema_fingerprint": sess
                        .tool_constraints
                        .get(name)
                        .and_then(|c| c.schema_fingerprint.as_ref()),
                })),
            );
            if let Err(e) = state.audit.record_tool_call(
                &sess.session_id,
                sess.user_id.as_deref(),
                name,
                "deny",
                reason,
                args.as_ref(),
                None,
            ) {
                error!(error = %e, "audit JSONL sync failed on deny");
            }
            return Json(deny).into_response();
        }
        if let Some(constraint) = sess.tool_constraints.get(name)
            && let Err(reason) = validate_tool_args(constraint, args.as_ref())
        {
            warn!(
                session_id = %sess.session_id,
                tool = %name,
                %reason,
                "tools/call args rejected (destructive constraints)"
            );
            let deny = jsonrpc_err(
                req_id.clone(),
                -32602,
                "invalid_params",
                Some(json!({ "tool": name, "reason": reason })),
            );
            if let Err(e) = state.audit.record_tool_call(
                &sess.session_id,
                sess.user_id.as_deref(),
                name,
                "deny",
                "invalid_params",
                args.as_ref(),
                None,
            ) {
                error!(error = %e, "audit JSONL sync failed on args deny");
            }
            return Json(deny).into_response();
        }

        // HITL / Mission Seal gate: no upstream until approved.
        let live_mandate = {
            let g = state.lock_inner();
            g.sessions
                .get(&sess.session_id)
                .and_then(|s| s.mandate.clone())
        };
        let seal_gate = sess.require_seal
            && !live_mandate
                .as_ref()
                .is_some_and(mandate::pep_mandate_active);
        let needs_hitl = sess
            .tool_constraints
            .get(name)
            .map(|c| c.hitl)
            .unwrap_or(false)
            || seal_gate;
        let require_plan = sess
            .tool_constraints
            .get(name)
            .map(|c| c.require_plan)
            .unwrap_or(false)
            || seal_gate;
        if mandate::pep_enter_hitl(needs_hitl, live_mandate.as_ref()) {
            let pending_id = extract_pending_id(&params);
            if let Some(resp) = handle_hitl_tools_call(
                &state,
                &sess,
                &req_id,
                name,
                args.as_ref(),
                &params,
                pending_id.as_deref(),
                mandate::pep_treat_as_require_plan(require_plan, live_mandate.as_ref()),
            )
            .await
            {
                return resp;
            }
            // Approved one-shot / CheckStep allow → fall through to upstream.
            hitl_oneshot = true;
        }
    }

    let mut upstream_body = body;
    if method == "tools/call" {
        mandate::strip_vauban_from_rpc_body(&mut upstream_body);
    }

    let (status, payload) = if sess.upstream_stream.is_some() {
        let host = sess
            .upstream_url
            .as_deref()
            .and_then(|u| {
                u.strip_prefix("https://")
                    .or_else(|| u.strip_prefix("http://"))
            })
            .and_then(|u| u.split('/').next())
            .unwrap_or("127.0.0.1");
        match post_json_on_brokered_fd(&state, &sess, host, &upstream_body).await {
            Ok(v) => v,
            Err(e) => {
                warn!(session_id = %sess.session_id, error = %e, "upstream on brokered FD failed");
                if method == "tools/call" {
                    finalize_mandate_upstream(&state, &sess.session_id, &Value::Null, false).await;
                }
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(jsonrpc_err(
                        req_id,
                        -32010,
                        "upstream_unavailable",
                        Some(json!({ "detail": e.to_string() })),
                    )),
                )
                    .into_response();
            }
        }
    } else {
        warn!(
            session_id = %sess.session_id,
            method = %method,
            "refusing upstream without brokered FD"
        );
        if method == "tools/call" {
            finalize_mandate_upstream(&state, &sess.session_id, &Value::Null, false).await;
        }
        return (
            StatusCode::BAD_GATEWAY,
            Json(jsonrpc_err(
                req_id,
                -32010,
                "upstream_fd_required",
                Some(json!({
                    "detail": "no brokered upstream FD"
                })),
            )),
        )
            .into_response();
    };

    let mut out = payload;
    if method == "tools/list" {
        if let Some(result) = out.get("result").cloned()
            && let Value::Object(ref mut map) = out
        {
            map.insert("result".to_string(), filter_tools_list(&sess, result));
        }
        let _ = state.audit.record_method(
            &sess.session_id,
            "tools/list",
            json!({ "decision": "allow" }),
        );
    }

    if method == "initialize" {
        if let Some(result) = out.get_mut("result") {
            agent_view::attach_visit_instructions(
                result,
                sess.allowed_tools.as_deref(),
                &sess.tool_constraints,
            );
        }
        let _ = state.audit.record_method(
            &sess.session_id,
            "initialize",
            json!({ "decision": "allow" }),
        );
    }

    if method == "tools/call" {
        let name = params.get("name").and_then(Value::as_str).unwrap_or("");
        let args = params
            .get("arguments")
            .cloned()
            .map(|a| mandate::strip_vauban_args(&a));
        let decision = if hitl_oneshot { "hitl_allow" } else { "allow" };
        if let Err(e) = state.audit.record_tool_call(
            &sess.session_id,
            sess.user_id.as_deref(),
            name,
            decision,
            "ok",
            args.as_ref(),
            Some(&out),
        ) {
            error!(error = %e, "audit JSONL sync failed after tools/call");
            finalize_mandate_upstream(&state, &sess.session_id, &out, false).await;
            return Json(jsonrpc_err(
                req_id,
                -32010,
                "recording_sync_failed",
                Some(json!({ "detail": e.to_string() })),
            ))
            .into_response();
        }
        finalize_mandate_upstream(&state, &sess.session_id, &out, true).await;
    }

    if method == "notifications/initialized" {
        let _ = state
            .audit
            .record_method(&sess.session_id, "notifications/initialized", json!({}));
        return StatusCode::NO_CONTENT.into_response();
    }

    let http_status = if status >= 500 {
        StatusCode::OK
    } else {
        StatusCode::from_u16(status).unwrap_or(StatusCode::OK)
    };
    (http_status, Json(out)).into_response()
}

fn appliance_session_ttl_secs() -> f64 {
    appliance_session_ttl_secs_from(std::env::var("SESSION_TTL_SECONDS").ok().as_deref())
}

fn appliance_session_ttl_secs_from(raw: Option<&str>) -> f64 {
    raw.and_then(|v| v.parse::<f64>().ok())
        .filter(|d| *d > 0.0)
        .map(|d| d.clamp(30.0, 28_800.0))
        .unwrap_or(3600.0)
}

fn clamp_visit_expires_at(raw: f64, now: f64, appliance_ttl: f64) -> f64 {
    let cap = appliance_ttl.clamp(30.0, 28_800.0);
    raw.min(now + cap)
}

fn parse_rfc3339_approx(s: &str) -> Option<f64> {
    // Minimal parser for `YYYY-MM-DDTHH:MM:SSZ` produced by our stack.
    let s = s.trim().trim_end_matches('Z');
    let (date, time) = s.split_once('T')?;
    let mut d = date.split('-');
    let y: i64 = d.next()?.parse().ok()?;
    let m: i64 = d.next()?.parse().ok()?;
    let day: i64 = d.next()?.parse().ok()?;
    let mut t = time.split(':');
    let hh: i64 = t.next()?.parse().ok()?;
    let mm: i64 = t.next()?.parse().ok()?;
    let ss: i64 = t.next()?.parse::<f64>().ok()? as i64;
    let days = days_from_civil(y, m, day)?;
    Some((days * 86_400 + hh * 3600 + mm * 60 + ss) as f64)
}

fn days_from_civil(y: i64, m: i64, d: i64) -> Option<i64> {
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

/// Lab HTTP on the brokered FD is allowed only for loopback hosts.
/// Production RFC1918 / public names require a TLS SPKI pin.
fn is_loopback_upstream_host(host: &str) -> bool {
    let h = host
        .trim()
        .trim_matches(|c| c == '[' || c == ']')
        .to_ascii_lowercase();
    matches!(h.as_str(), "127.0.0.1" | "::1" | "localhost")
}

fn build_router(state: GatewayState) -> Router {
    Router::new()
        .route("/mcp", post(handle_mcp))
        .layer(DefaultBodyLimit::max(
            upstream_http::MAX_UPSTREAM_BODY_BYTES,
        ))
        .with_state(state)
}

#[allow(clippy::too_many_arguments)]
fn apply_session_update(
    sess: &mut Session,
    allowed_tools: Option<Vec<String>>,
    tool_constraints_json: Option<&str>,
    envelope_max_calls: Option<u32>,
    envelope_window_seconds: Option<u32>,
    envelope_on_exceed: Option<String>,
    expires_at: Option<String>,
    resume_recours: bool,
) -> bool {
    let mut widened = false;
    if let Some(new_tools) = allowed_tools {
        widened = match &sess.allowed_tools {
            None => false,
            Some(current) => new_tools.iter().any(|t| !current.contains(t)),
        };
        if widened {
            warn!(
                session_id = %sess.session_id,
                "mcp_privilege_escalation_attempt: update tried to add a tool \
                 absent from the current whitelist -- addition ignored"
            );
            let allowed_and_current: Vec<String> = match &sess.allowed_tools {
                Some(current) => new_tools
                    .into_iter()
                    .filter(|t| current.contains(t))
                    .collect(),
                // Fail-closed: no current whitelist → refuse to install tools via update.
                None => Vec::new(),
            };
            sess.allowed_tools = Some(allowed_and_current);
        } else {
            sess.allowed_tools = Some(new_tools);
        }
    }
    if let Some(raw) = tool_constraints_json {
        let trimmed = raw.trim();
        if !trimmed.is_empty() && trimmed != "{}" {
            let incoming = parse_constraints_json(trimmed);
            if !incoming.is_empty() {
                merge_constraints_tighten(&mut sess.tool_constraints, incoming);
            }
        }
    }
    if let Some(v) = envelope_max_calls {
        sess.envelope_max = v;
    }
    if let Some(v) = envelope_window_seconds {
        sess.envelope_window = v;
    }
    if let Some(v) = envelope_on_exceed {
        let v = v.trim();
        if v.is_empty() {
            // Leave on_exceed unchanged (recheck / partial updates).
        } else if validate_on_exceed(v).is_ok() {
            if v == "suspend" && !resume_recours {
                warn!(
                    session_id = %sess.session_id,
                    "ignoring envelope_on_exceed=suspend without Resume recours (B-4)"
                );
            } else {
                sess.on_exceed = v.to_string();
            }
        } else {
            warn!(
                session_id = %sess.session_id,
                on_exceed = %v,
                "McpSessionUpdate: ignoring invalid envelope_on_exceed"
            );
        }
    }
    if let Some(new_expiry) = expires_at.and_then(|s| parse_rfc3339_approx(&s))
        && new_expiry < sess.expires_at
    {
        sess.expires_at = new_expiry;
    }
    widened
}

struct ControlLoopState {
    start_time: Instant,
    requests_processed: u64,
    shutdown: bool,
}

fn handle_control(ctrl: ControlMessage, st: &mut ControlLoopState) -> Option<Message> {
    match ctrl {
        ControlMessage::Ping { seq } => {
            st.requests_processed = st.requests_processed.saturating_add(1);
            Some(Message::Control(ControlMessage::Pong {
                seq,
                stats: ServiceStats {
                    uptime_secs: st.start_time.elapsed().as_secs(),
                    requests_processed: st.requests_processed,
                    ..ServiceStats::default()
                },
            }))
        }
        ControlMessage::Drain => Some(Message::Control(ControlMessage::DrainComplete {
            pending_requests: 0,
        })),
        ControlMessage::Shutdown => {
            st.shutdown = true;
            None
        }
        ControlMessage::Pong { .. } | ControlMessage::DrainComplete { .. } => None,
    }
}

/// POST on the hop-1 FD; on EPIPE / unexpected EOF, IACS-style re-broker once.
async fn post_json_on_brokered_fd(
    state: &GatewayState,
    sess: &Session,
    host: &str,
    body: &Value,
) -> anyhow::Result<(u16, Value)> {
    let stream = sess
        .upstream_stream
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("no brokered upstream stream"))?;
    let first = {
        let mut guard = stream.lock().await;
        upstream_http::post_json(
            &mut *guard,
            host,
            "/mcp",
            sess.upstream_bearer.as_deref(),
            body,
        )
        .await
    };
    match first {
        Ok(v) => Ok(v),
        Err(e) if is_dead_upstream_io(&e) => {
            info!(
                session_id = %sess.session_id,
                error = %e,
                "mcp rebroker: hop-1 FD dead — supervisor TcpConnect retry"
            );
            let io = replace_brokered_upstream(state, sess).await?;
            let mut guard = io.lock().await;
            upstream_http::post_json(
                &mut *guard,
                host,
                "/mcp",
                sess.upstream_bearer.as_deref(),
                body,
            )
            .await
        }
        Err(e) => Err(e),
    }
}

async fn replace_brokered_upstream(
    state: &GatewayState,
    sess: &Session,
) -> anyhow::Result<Arc<AsyncMutex<upstream_http::UpstreamIo>>> {
    let rb = state
        .rebroker
        .get()
        .ok_or_else(|| anyhow::anyhow!("rebroker not wired (no supervisor FD socket)"))?;
    let tcp = rb
        .open(
            &sess.session_id,
            &sess.upstream_host,
            sess.upstream_port,
            &sess.session_token,
        )
        .await
        .map_err(|e| anyhow::anyhow!("rebroker open: {e}"))?;
    let io = match sess
        .upstream_tls_spki_pin
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(pin) => {
            let tls = tls_pin::connect_pinned(tcp, sess.upstream_host.trim(), pin)
                .await
                .map_err(anyhow::Error::msg)?;
            upstream_http::UpstreamIo::Tls(Box::new(tls))
        }
        None => upstream_http::UpstreamIo::Plain(tcp),
    };
    let arc = Arc::new(AsyncMutex::new(io));
    {
        let mut g = state.lock_inner();
        if let Some(live) = g.sessions.get_mut(&sess.session_id) {
            live.upstream_stream = Some(arc.clone());
        }
    }
    Ok(arc)
}

/// Handle `McpSessionOpen` (contract §2, IPC `Web -> ProxyMcp`).
///
/// Fail-closed gates (04 §4 / M3–M5), in order:
/// 1. SessionToken MAC verify (`verify_proxy`, protocol `"mcp"`)
/// 2. non-empty `allowed_tools`
/// 3. AccessGuard live RBAC re-check
/// 4. claim supervisor-brokered upstream FD (required under IPC)
///
/// Capsicum prevents free `connect()` after seal; the brokered FD is
/// the only upstream path.
async fn handle_mcp_session_open(
    state: &GatewayState,
    access_guard: Option<Arc<shared::access_guard::AccessGuard>>,
    pending: Option<PendingConnections>,
    vault: Option<Arc<VaultDecryptClient>>,
    msg: Message,
) -> Option<Message> {
    let Message::McpSessionOpen {
        request_id,
        session_id,
        asset_id,
        user_id,
        api_key_id,
        expires_at,
        vbw_hash,
        allowed_tools,
        envelope_max_calls,
        envelope_window_seconds,
        envelope_on_exceed,
        upstream_host,
        upstream_port,
        upstream_tls_spki_pin,
        credential_blob,
        justification,
        max_body_bytes,
        session_token,
        tool_constraints_json,
        transport,
        require_seal,
        ..
    } = msg
    else {
        return None;
    };

    // 1) Cryptographic session-token gate BEFORE AccessGuard / FD claim.
    if !session_token_gate::verify_proxy(&session_token, &user_id, &asset_id, "mcp", &session_id) {
        warn!(
            session_id = %session_id,
            "McpSessionOpen refused: session token verify failed"
        );
        return Some(Message::McpSessionOpened {
            request_id,
            session_id,
            success: false,
            error: Some("Access denied".to_string()),
        });
    }

    // Fail-closed: never fall back to process-wide ALLOWED_TOOLS / None allow-all.
    let tools = match allowed_tools {
        Some(t) if !t.is_empty() => t,
        _ => {
            warn!(
                session_id = %session_id,
                "McpSessionOpen refused: empty or missing allowed_tools"
            );
            return Some(Message::McpSessionOpened {
                request_id,
                session_id,
                success: false,
                error: Some("No MCP tools granted (empty whitelist)".to_string()),
            });
        }
    };

    if user_id.is_empty() || asset_id.is_empty() {
        warn!(
            session_id = %session_id,
            "McpSessionOpen refused: missing user_id or asset_id"
        );
        return Some(Message::McpSessionOpened {
            request_id,
            session_id,
            success: false,
            error: Some("Access denied".to_string()),
        });
    }

    match access_guard {
        Some(guard) => {
            let decision = guard.authorize(&user_id, &asset_id).await;
            if !decision.is_granted() {
                debug!(
                    session_id = %session_id,
                    user_id = %user_id,
                    asset_id = %asset_id,
                    ?decision,
                    "RBAC re-check denied MCP session"
                );
                return Some(Message::McpSessionOpened {
                    request_id,
                    session_id,
                    success: false,
                    error: Some("Access denied".to_string()),
                });
            }
            debug!(
                session_id = %session_id,
                user_id = %user_id,
                asset_id = %asset_id,
                "RBAC re-check granted MCP session"
            );
        }
        None => {
            // Supervisor always wires Access → ProxyMcp. Missing guard under
            // IPC open = misconfig → fail closed.
            error!(
                session_id = %session_id,
                "McpSessionOpen refused: AccessGuard not wired"
            );
            return Some(Message::McpSessionOpened {
                request_id,
                session_id,
                success: false,
                error: Some("Access denied".to_string()),
            });
        }
    }

    // Claim brokered upstream TCP (web already issued TcpConnect).
    let Some(pending_map) = pending else {
        warn!(
            session_id = %session_id,
            "McpSessionOpen refused: FD passing not configured"
        );
        return Some(Message::McpSessionOpened {
            request_id,
            session_id,
            success: false,
            error: Some("Upstream connection unavailable".to_string()),
        });
    };
    let tcp = match claim_pending_wait(&pending_map, &session_id, Duration::from_secs(2)).await {
        Some(fd) => match owned_fd_to_tcp_stream(fd) {
            Ok(stream) => stream,
            Err(e) => {
                error!(
                    session_id = %session_id,
                    error = %e,
                    "McpSessionOpen refused: brokered FD not usable as TcpStream"
                );
                return Some(Message::McpSessionOpened {
                    request_id,
                    session_id,
                    success: false,
                    error: Some("Upstream connection unavailable".to_string()),
                });
            }
        },
        None => {
            error!(
                session_id = %session_id,
                "McpSessionOpen refused: no brokered upstream FD"
            );
            return Some(Message::McpSessionOpened {
                request_id,
                session_id,
                success: false,
                error: Some("Upstream connection unavailable".to_string()),
            });
        }
    };

    let expires_at_secs = clamp_visit_expires_at(
        parse_rfc3339_approx(&expires_at)
            .unwrap_or_else(|| unix_now() + appliance_session_ttl_secs()),
        unix_now(),
        appliance_session_ttl_secs(),
    );
    let host_l = upstream_host.trim().to_ascii_lowercase();
    if host_l.starts_with("https://") || host_l.starts_with("http://") {
        warn!(
            session_id = %session_id,
            host = %upstream_host,
            "McpSessionOpen: scheme in upstream_host refused (bare hostname only)"
        );
        return Some(Message::McpSessionOpened {
            request_id,
            session_id,
            success: false,
            error: Some("upstream_host must be a bare hostname (no URL scheme)".into()),
        });
    }

    // Hop-2 ingress / upstream reads are capped at 1 MiB. Never raise
    // the wire `max_body_bytes` above that (web sends MAX_BODY_BYTES).
    if max_body_bytes == 0 || max_body_bytes > upstream_http::MAX_UPSTREAM_BODY_BYTES as u64 {
        warn!(
            session_id = %session_id,
            max_body_bytes,
            "McpSessionOpen: max_body_bytes out of range; hop-2 stays at 1 MiB"
        );
    }

    // RDP-parity TLS: pin present → HTTPS-on-FD + SPKI enforce;
    // absent → lab HTTP only on loopback. Off-loopback without pin
    // is plaintext on the brokered FD — refuse.
    let pin = upstream_tls_spki_pin
        .as_ref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty());
    if pin.is_none() && !is_loopback_upstream_host(&upstream_host) {
        warn!(
            session_id = %session_id,
            host = %upstream_host,
            "McpSessionOpen refused: TLS pin required for non-loopback upstream"
        );
        return Some(Message::McpSessionOpened {
            request_id,
            session_id,
            success: false,
            error: Some("TLS pin required for non-loopback MCP upstream".into()),
        });
    }
    let (upstream_io, upstream_url) = match pin {
        Some(pin) => match tls_pin::connect_pinned(tcp, upstream_host.trim(), pin).await {
            Ok(tls) => (
                upstream_http::UpstreamIo::Tls(Box::new(tls)),
                format!("https://{}:{}/mcp", upstream_host.trim(), upstream_port),
            ),
            Err(e) => {
                warn!(
                    session_id = %session_id,
                    error = %e,
                    "McpSessionOpen refused: TLS/SPKI failed"
                );
                return Some(Message::McpSessionOpened {
                    request_id,
                    session_id,
                    success: false,
                    error: Some(e),
                });
            }
        },
        None => (
            upstream_http::UpstreamIo::Plain(tcp),
            format!("http://{}:{}/mcp", upstream_host.trim(), upstream_port),
        ),
    };
    let upstream_stream = Some(Arc::new(AsyncMutex::new(upstream_io)));
    let upstream_bearer = match materialise_upstream_bearer(vault.as_ref(), credential_blob).await {
        Ok(b) => b,
        Err(e) => {
            warn!(
                session_id = %session_id,
                error = %e,
                "McpSessionOpen refused: credential VaultDecrypt failed"
            );
            return Some(Message::McpSessionOpened {
                request_id,
                session_id,
                success: false,
                error: Some(format!("Credential decrypt failed: {e}")),
            });
        }
    };
    let api_key_id_opt = if api_key_id.is_empty() {
        None
    } else {
        Some(api_key_id)
    };
    let tool_constraints = parse_constraints_json(&tool_constraints_json);
    if let Err(e) = validate_on_exceed(&envelope_on_exceed) {
        return Some(Message::McpSessionOpened {
            request_id,
            session_id,
            success: false,
            error: Some(e),
        });
    }
    if envelope_on_exceed == "suspend" && !state.resume_recours_available() {
        return Some(Message::McpSessionOpened {
            request_id,
            session_id,
            success: false,
            error: Some(
                "envelope_on_exceed=suspend requires Resume recours (web IPC); use throttle|alert"
                    .into(),
            ),
        });
    }

    state.insert_session(Session {
        session_id: session_id.clone(),
        vbw_hash: hex::encode(vbw_hash),
        expires_at: expires_at_secs,
        allowed_tools: Some(tools),
        envelope_max: envelope_max_calls,
        envelope_window: envelope_window_seconds,
        on_exceed: envelope_on_exceed,
        call_times: VecDeque::new(),
        terminated: false,
        suspended: false,
        justification,
        user_id: Some(user_id.clone()),
        api_key_id: api_key_id_opt.clone(),
        asset_id: Some(asset_id.clone()),
        upstream_url: Some(upstream_url.clone()),
        upstream_bearer,
        upstream_stream,
        session_token,
        upstream_host: upstream_host.trim().to_string(),
        upstream_port,
        upstream_tls_spki_pin,
        tool_constraints,
        client_info: None,
        clientinfo_pin: clientinfo_pin_from_env(),
        hitl_pendings: HashMap::new(),
        mandate: None,
        transport: if transport == "tunnel" {
            "tunnel".to_string()
        } else {
            "direct".to_string()
        },
        require_seal,
    });

    state
        .audit
        .record_session_opened(
            &session_id,
            Some(user_id.as_str()),
            json!({
                "source": "ipc",
                "upstream": upstream_url,
                "api_key_id": api_key_id_opt,
            }),
        )
        .await;

    info!(
        session_id = %session_id,
        upstream = %upstream_url,
        "MCP session opened via supervisor IPC"
    );

    Some(Message::McpSessionOpened {
        request_id,
        session_id,
        success: true,
        error: None,
    })
}

/// Handle `McpSessionUpdate` (contract §3). Rule T1: only ever
/// TIGHTENS the copy already held -- an update that tries to add a
/// tool name absent from the current whitelist has that addition
/// dropped (the rest of the update still applies).
fn handle_mcp_session_update(state: &GatewayState, msg: Message) {
    let Message::McpSessionUpdate {
        session_id,
        allowed_tools,
        tool_constraints_json,
        envelope_max_calls,
        envelope_window_seconds,
        envelope_on_exceed,
        expires_at,
        ..
    } = msg
    else {
        return;
    };

    let (widened, user_id, attempted) = {
        let resume_ok = state.resume_recours_available();
        let mut guard = state.lock_inner();
        let Some(sess) = guard.sessions.get_mut(&session_id) else {
            debug!(session_id = %session_id, "McpSessionUpdate: unknown session, ignored");
            return;
        };
        let attempted = allowed_tools.clone();
        let widened = apply_session_update(
            sess,
            allowed_tools,
            Some(tool_constraints_json.as_str()),
            Some(envelope_max_calls),
            Some(envelope_window_seconds),
            Some(envelope_on_exceed),
            expires_at,
            resume_ok,
        );
        (widened, sess.user_id.clone(), attempted)
    };
    if widened {
        state.audit.record_privilege_escalation(
            &session_id,
            user_id.as_deref(),
            json!({ "source": "ipc_update", "attempted_tools": attempted }),
        );
    }
    info!(session_id = %session_id, "MCP session envelope updated via supervisor IPC");
}

/// Handle `McpSessionTerminate` (contract §3 + revocation watchdog).
fn handle_mcp_session_terminate(state: &GatewayState, msg: Message) {
    let Message::McpSessionTerminate {
        session_id, reason, ..
    } = msg
    else {
        return;
    };
    let user_id = {
        let mut guard = state.lock_inner();
        if let Some(sess) = guard.sessions.get_mut(&session_id) {
            sess.terminated = true;
            info!(session_id = %session_id, reason = %reason, "MCP session terminated via supervisor IPC");
            sess.user_id.clone()
        } else {
            return;
        }
    };
    state.spawn_clear_mcp_mandate(&session_id);
    state
        .audit
        .finalize_recording(&session_id, user_id.as_deref(), &reason, false);
}

fn handle_mcp_session_suspend(state: &GatewayState, msg: Message) {
    let Message::McpSessionSuspend {
        session_id,
        reason,
        actor_user_id,
        ..
    } = msg
    else {
        return;
    };
    let actor = if actor_user_id.is_empty() {
        None
    } else {
        Some(actor_user_id.as_str())
    };
    let _ = state.suspend_session(&session_id, &reason, actor);
}

fn handle_mcp_session_resume(state: &GatewayState, msg: Message) {
    let Message::McpSessionResume {
        session_id,
        actor_user_id,
        ..
    } = msg
    else {
        return;
    };
    let _ = state.resume_session(&session_id, &actor_user_id);
}

async fn handle_mcp_hitl_decision(state: &GatewayState, msg: Message) {
    let Message::McpHitlDecision {
        session_id,
        pending_id,
        decision,
        actor_user_id,
        ..
    } = msg
    else {
        return;
    };
    let user_id = {
        let mut guard = state.lock_inner();
        let Some(sess) = guard.sessions.get_mut(&session_id) else {
            return;
        };
        let seal_asset = GatewayState::mandate_asset_id(sess);
        let Some(pending) = sess.hitl_pendings.get_mut(&pending_id) else {
            warn!(session_id = %session_id, pending_id = %pending_id, "HITL decision for unknown pending");
            return;
        };
        if let Some(why) = hitl_decision_blocked(
            unix_now(),
            pending.expires_at,
            &pending.status,
            sess.user_id.as_deref(),
            sess.api_key_id.as_deref(),
            &actor_user_id,
        ) {
            warn!(
                session_id = %session_id,
                pending_id = %pending_id,
                reason = why,
                "HITL decision rejected (fail-closed)"
            );
            return;
        }
        match decision.as_str() {
            "approve" => {
                // Mission Seal: install mandate before marking Approved.
                // Fail closed: never leave Approved without an active mandate.
                if !pending.plan_contract_json.is_empty() {
                    match serde_json::from_str::<serde_json::Value>(&pending.plan_contract_json)
                        .map_err(|e| e.to_string())
                        .and_then(|v| mandate::parse_contract(&v))
                        .and_then(|c| {
                            mandate::seal_mandate(
                                &pending.mandate_id,
                                &session_id,
                                &seal_asset,
                                &c,
                                unix_now(),
                            )
                        }) {
                        Ok(m) => {
                            info!(
                                session_id = %session_id,
                                mandate_id = %m.mandate_id,
                                expires_at = m.expires_at,
                                "Mission Seal mandate activated"
                            );
                            sess.mandate = Some(m);
                            pending.status = HitlStatus::Approved;
                        }
                        Err(e) => {
                            warn!(
                                session_id = %session_id,
                                error = %e,
                                "Mission Seal activate failed; denying pending (fail-closed)"
                            );
                            pending.status = HitlStatus::Denied;
                        }
                    }
                } else {
                    pending.status = HitlStatus::Approved;
                }
            }
            "deny" => pending.status = HitlStatus::Denied,
            other => {
                warn!(decision = %other, "invalid HITL decision");
                return;
            }
        }
        sess.user_id.clone()
    };
    if decision == "approve" {
        let (mid, asset, contract) = {
            let g = state.lock_inner();
            g.sessions
                .get(&session_id)
                .and_then(|s| {
                    s.hitl_pendings.get(&pending_id).map(|p| {
                        (
                            p.mandate_id.clone(),
                            GatewayState::mandate_asset_id(s),
                            p.plan_contract_json.clone(),
                        )
                    })
                })
                .unwrap_or_default()
        };
        if !contract.is_empty() {
            pdp_mirror_seal(state, &session_id, &mid, &asset, &contract, unix_now()).await;
        }
    } else if decision == "deny" {
        state.spawn_clear_mcp_mandate(&session_id);
    }
    let (worm_mid, worm_digest) = {
        let g = state.lock_inner();
        g.sessions
            .get(&session_id)
            .and_then(|s| {
                s.hitl_pendings
                    .get(&pending_id)
                    .map(|p| (p.mandate_id.clone(), p.sealed_digest.clone()))
            })
            .unwrap_or_default()
    };
    state.audit.record_hitl_decided(
        &session_id,
        user_id.as_deref(),
        &pending_id,
        &decision,
        &actor_user_id,
        &worm_mid,
        &worm_digest,
    );
    info!(
        session_id = %session_id,
        pending_id = %pending_id,
        decision = %decision,
        "MCP HITL decision applied"
    );
}

/// Supervisor's own control channel (`VAUBAN_IPC_READ/WRITE`):
/// Ping/Drain/Shutdown + `TcpConnectResponse` + recording FD leases.
async fn supervisor_control_loop(
    channel: IpcChannel,
    shutdown_tx: broadcast::Sender<()>,
    fd_passing: Option<Arc<FdPassingState>>,
    mut lease_rx: tokio::sync::mpsc::Receiver<RecordingLeaseReq>,
    mut tcp_connect_rx: mpsc::UnboundedReceiver<Message>,
) {
    use std::collections::HashMap;
    use std::fs::File;

    let mut st = ControlLoopState {
        start_time: Instant::now(),
        requests_processed: 0,
        shutdown: false,
    };
    let mut pending_recording: HashMap<String, tokio::sync::oneshot::Sender<Result<File, String>>> =
        HashMap::new();
    let mut recording_request_id: u64 = 0;

    loop {
        while let Ok(msg) = tcp_connect_rx.try_recv() {
            if let Err(e) = channel.send(&msg) {
                warn!(error = %e, "failed to send TcpConnectRequest (mcp rebroker)");
            }
        }

        // Outbound recording lease requests from McpRecording.
        while let Ok(req) = lease_rx.try_recv() {
            if fd_passing.is_none() {
                let _ = req.reply.send(Err("FD passing not configured".into()));
                continue;
            }
            if pending_recording.contains_key(&req.session_id) {
                let _ = req
                    .reply
                    .send(Err("recording lease already pending".into()));
                continue;
            }
            recording_request_id = recording_request_id.wrapping_add(1);
            pending_recording.insert(req.session_id.clone(), req.reply);
            let msg = Message::RecordingFileRequest {
                request_id: recording_request_id,
                session_id: req.session_id,
                relative_path: req.relative_path,
                read_only: req.read_only,
            };
            if let Err(e) = channel.send(&msg) {
                warn!(error = %e, "failed to send RecordingFileRequest");
            }
        }

        match channel.try_recv() {
            Ok(Message::Control(ctrl)) => {
                if let Some(reply) = handle_control(ctrl, &mut st) {
                    let _ = channel.send(&reply);
                }
            }
            Ok(Message::TcpConnectResponse {
                session_id,
                success,
                error,
                ..
            }) => {
                if success {
                    if let Some(ref fp) = fd_passing {
                        match receive_fd_with_retry(fp.socket_fd, 10, 50).await {
                            Ok(fd) => {
                                debug!(
                                    session_id = %session_id,
                                    "Received MCP upstream TCP FD from supervisor"
                                );
                                fp.pending.lock().await.insert(session_id, fd);
                            }
                            Err(e) => {
                                error!(
                                    session_id = %session_id,
                                    error = %e,
                                    "Failed to receive MCP upstream FD from supervisor"
                                );
                            }
                        }
                    } else {
                        warn!(
                            session_id = %session_id,
                            "TcpConnectResponse received but FD passing not configured"
                        );
                    }
                } else {
                    warn!(
                        session_id = %session_id,
                        error = ?error,
                        "MCP upstream TCP connect failed"
                    );
                }
            }
            Ok(Message::RecordingFileResponse {
                session_id,
                success,
                error,
                ..
            }) => {
                let reply = pending_recording.remove(&session_id);
                if success {
                    let file_result = if let Some(ref fp) = fd_passing {
                        receive_fd_with_retry(fp.socket_fd, 10, 50)
                            .await
                            .map(File::from)
                            .map_err(|e| e.to_string())
                    } else {
                        Err("FD passing is not configured".to_string())
                    };
                    if let Some(reply) = reply {
                        let _ = reply.send(file_result);
                    } else {
                        warn!(
                            session_id = %session_id,
                            "RecordingFileResponse has no pending lease"
                        );
                    }
                } else if let Some(reply) = reply {
                    let _ =
                        reply.send(Err(error.unwrap_or_else(|| "recording open failed".into())));
                }
            }
            Ok(Message::McpTunnelIdentityProvision { cert_der, key_pem }) => {
                if let Err(e) = tunnel::install_identity(cert_der, key_pem.as_str()) {
                    error!(error = %e, "rejected MCP tunnel identity");
                } else {
                    info!("MCP tunnel identity installed");
                }
            }
            Ok(other) => {
                debug!(
                    ?other,
                    "ignored non-control IPC message in MCP proxy control loop"
                );
            }
            Err(shared::ipc::IpcError::Io(e)) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // No control traffic yet.
            }
            Err(shared::ipc::IpcError::ConnectionClosed) => {
                info!("Supervisor connection closed, exiting");
                break;
            }
            Err(e) => {
                warn!(error = %e, "IPC try_recv in MCP proxy control loop, exiting");
                break;
            }
        }
        if st.shutdown {
            info!("Shutdown flag set, exiting main loop to run destructors");
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let _ = shutdown_tx.send(());
}

/// Admin discover (Phase 2.1): claim brokered FD, VaultDecrypt, run
/// initialize + tools/list — no durable session, no AccessGuard connect
/// rule (diagnostic token already gated by assets:manage).
async fn handle_mcp_discover(
    pending: Option<PendingConnections>,
    vault: Option<Arc<VaultDecryptClient>>,
    msg: Message,
) -> Option<Message> {
    let Message::McpDiscover {
        request_id,
        session_id,
        asset_id,
        user_id,
        upstream_host,
        upstream_port,
        credential_blob,
        session_token,
        upstream_tls_spki_pin,
    } = msg
    else {
        return None;
    };

    let fail = |error: String| {
        Some(Message::McpDiscovered {
            request_id,
            session_id: session_id.clone(),
            success: false,
            tools_json: None,
            error: Some(error),
        })
    };

    if !session_token_gate::verify_proxy(&session_token, &user_id, &asset_id, "mcp", &session_id) {
        warn!(
            session_id = %session_id,
            "McpDiscover refused: session token verify failed"
        );
        return fail("Access denied".into());
    }

    let Some(pending_map) = pending else {
        return fail("FD passing not configured".into());
    };
    let tcp = match claim_pending_wait(&pending_map, &session_id, Duration::from_secs(2)).await {
        Some(fd) => match owned_fd_to_tcp_stream(fd) {
            Ok(s) => s,
            Err(e) => return fail(format!("FD to TcpStream: {e}")),
        },
        None => return fail("claim brokered FD timed out".into()),
    };

    let host_l = upstream_host.trim().to_ascii_lowercase();
    if host_l.starts_with("https://") || host_l.starts_with("http://") {
        return fail("upstream_host must be a bare hostname (no URL scheme)".into());
    }

    let pin = upstream_tls_spki_pin
        .as_ref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty());
    if pin.is_none() && !is_loopback_upstream_host(&upstream_host) {
        return fail("TLS pin required for non-loopback MCP upstream".into());
    }
    let mut stream = match pin {
        Some(pin) => match tls_pin::connect_pinned(tcp, upstream_host.trim(), pin).await {
            Ok(tls) => upstream_http::UpstreamIo::Tls(Box::new(tls)),
            Err(e) => return fail(e),
        },
        None => upstream_http::UpstreamIo::Plain(tcp),
    };

    let bearer = match materialise_upstream_bearer(vault.as_ref(), credential_blob).await {
        Ok(b) => b,
        Err(e) => return fail(format!("credential decrypt: {e}")),
    };

    let host_header = format!("{}:{}", upstream_host.trim(), upstream_port);

    let init_body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": { "name": "vauban-discover", "version": "0.9.33" }
        }
    });
    if let Err(e) = upstream_http::post_json(
        &mut stream,
        &host_header,
        "/mcp",
        bearer.as_deref(),
        &init_body,
    )
    .await
    {
        return fail(format!("initialize: {e}"));
    }

    // Best-effort notifications/initialized (ignore errors).
    let _ = upstream_http::post_json(
        &mut stream,
        &host_header,
        "/mcp",
        bearer.as_deref(),
        &json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        }),
    )
    .await;

    let list_body = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    });
    let (_status, listed) = match upstream_http::post_json(
        &mut stream,
        &host_header,
        "/mcp",
        bearer.as_deref(),
        &list_body,
    )
    .await
    {
        Ok(v) => v,
        Err(e) => return fail(format!("tools/list: {e}")),
    };

    if listed.get("error").is_some() {
        let msg = listed
            .pointer("/error/message")
            .and_then(Value::as_str)
            .unwrap_or("upstream_error");
        return fail(format!("MCP upstream error: {msg}"));
    }

    let tools_json = match serde_json::to_string(&listed) {
        Ok(s) => s,
        Err(e) => return fail(format!("serialize tools: {e}")),
    };

    info!(
        session_id = %session_id,
        host = %upstream_host,
        port = upstream_port,
        "McpDiscover completed"
    );
    Some(Message::McpDiscovered {
        request_id,
        session_id,
        success: true,
        tools_json: Some(tools_json),
        error: None,
    })
}

/// `Web -> ProxyMcp` pipe (`VAUBAN_WEB_IPC_READ/WRITE`, topology edge
/// set up by the supervisor): `McpSessionOpen` / `McpSessionUpdate` /
/// `McpSessionTerminate` (contract §2-3). Separate from the
/// supervisor's own control channel above -- same split every other
/// proxy (SSH/RDP/IACS) uses.
async fn web_ipc_loop(
    channel: IpcChannel,
    mut shutdown_rx: broadcast::Receiver<()>,
    state: GatewayState,
    access_guard: Option<Arc<AccessGuard>>,
    pending: Option<PendingConnections>,
    vault: Option<Arc<VaultDecryptClient>>,
    mut web_notify_rx: mpsc::UnboundedReceiver<Message>,
) {
    loop {
        if shutdown_rx.try_recv().is_ok() {
            break;
        }
        while let Ok(msg) = web_notify_rx.try_recv() {
            if let Err(e) = channel.send(&msg) {
                warn!(error = %e, "failed to forward MCP web notify");
            }
        }
        match channel.try_recv() {
            Ok(msg @ Message::McpSessionOpen { .. }) => {
                // AccessGuard.authorize / VaultDecrypt are async and must
                // not block this poll loop longer than necessary — both
                // run inside the await below.
                let state_c = state.clone();
                let guard_c = access_guard.clone();
                let pending_c = pending.clone();
                let vault_c = vault.clone();
                let reply =
                    handle_mcp_session_open(&state_c, guard_c, pending_c, vault_c, msg).await;
                if let Some(reply) = reply {
                    let _ = channel.send(&reply);
                }
            }
            Ok(msg @ Message::McpDiscover { .. }) => {
                let pending_c = pending.clone();
                let vault_c = vault.clone();
                let reply = handle_mcp_discover(pending_c, vault_c, msg).await;
                if let Some(reply) = reply {
                    let _ = channel.send(&reply);
                }
            }
            Ok(msg @ Message::McpSessionUpdate { .. }) => {
                handle_mcp_session_update(&state, msg);
            }
            Ok(msg @ Message::McpSessionTerminate { .. }) => {
                handle_mcp_session_terminate(&state, msg);
            }
            Ok(msg @ Message::McpSessionSuspend { .. }) => {
                handle_mcp_session_suspend(&state, msg);
            }
            Ok(msg @ Message::McpSessionResume { .. }) => {
                handle_mcp_session_resume(&state, msg);
            }
            Ok(msg @ Message::McpHitlDecision { .. }) => {
                handle_mcp_hitl_decision(&state, msg).await;
            }
            Ok(other) => {
                debug!(?other, "ignored unexpected message on MCP web IPC channel");
            }
            Err(shared::ipc::IpcError::Io(e)) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // No traffic yet.
            }
            Err(e) => {
                debug!(error = %e, "IPC try_recv on MCP web channel");
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Block until the supervisor has pushed the tunnel identity. Heartbeats
/// that arrive first are answered so the wait cannot stall the parent.
fn wait_for_mcp_identity(channel: &IpcChannel) -> Result<(), String> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        if std::time::Instant::now() > deadline {
            return Err("timed out waiting for McpTunnelIdentityProvision".into());
        }
        match channel.try_recv() {
            Ok(Message::McpTunnelIdentityProvision { cert_der, key_pem }) => {
                return tunnel::install_identity(cert_der, key_pem.as_str());
            }
            Ok(Message::Control(shared::messages::ControlMessage::Ping { seq })) => {
                let stats = shared::messages::ServiceStats {
                    uptime_secs: 0,
                    requests_processed: 0,
                    requests_failed: 0,
                    active_connections: 0,
                    pending_requests: 0,
                    recording_ack_timeouts: 0,
                    recording_ack_dropped: 0,
                    recording_try_send_full: 0,
                    recording_ack_wait_ms_max: 0,
                };
                let _ = channel.send(&Message::Control(shared::messages::ControlMessage::Pong {
                    seq,
                    stats,
                }));
            }
            Ok(_) => {}
            Err(shared::ipc::IpcError::Io(e)) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            Err(e) => return Err(e.to_string()),
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    info!("vauban-proxy-mcp starting");

    // Same as proxy-rdp: aws-lc-rs CryptoProvider for rustls SPKI pinning.
    if tokio_rustls::rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .is_err()
    {
        tracing::debug!("Default CryptoProvider already installed");
    }

    // Parse IPC / FD-passing FDs before TokenKey / AccessGuard consume env.
    let supervisor_fds: Option<(RawFd, RawFd)> = match (
        std::env::var("VAUBAN_IPC_READ"),
        std::env::var("VAUBAN_IPC_WRITE"),
    ) {
        (Ok(r), Ok(w)) => match (r.parse(), w.parse()) {
            (Ok(r), Ok(w)) => Some((r, w)),
            _ => None,
        },
        _ => None,
    };
    let web_fds: Option<(RawFd, RawFd)> = match (
        std::env::var("VAUBAN_WEB_IPC_READ"),
        std::env::var("VAUBAN_WEB_IPC_WRITE"),
    ) {
        (Ok(r), Ok(w)) => match (r.parse(), w.parse()) {
            (Ok(r), Ok(w)) => Some((r, w)),
            _ => None,
        },
        _ => None,
    };
    let fd_passing_socket: Option<RawFd> = std::env::var("VAUBAN_FD_PASSING_SOCKET")
        .ok()
        .and_then(|s| s.parse().ok());
    let data_fds: Option<(RawFd, RawFd)> = match (
        std::env::var("VAUBAN_WEB_DATA_IPC_READ"),
        std::env::var("VAUBAN_WEB_DATA_IPC_WRITE"),
    ) {
        (Ok(r), Ok(w)) => match (r.parse(), w.parse()) {
            (Ok(r), Ok(w)) => Some((r, w)),
            _ => None,
        },
        _ => None,
    };

    // ProxyMcp → Vault (decrypt-only). Same env names as proxy-ssh.
    let vault_fds: Option<(RawFd, RawFd)> = {
        let r: Option<RawFd> = std::env::var("VAUBAN_VAULT_IPC_READ")
            .ok()
            .and_then(|s| s.parse().ok());
        let w: Option<RawFd> = std::env::var("VAUBAN_VAULT_IPC_WRITE")
            .ok()
            .and_then(|s| s.parse().ok());
        match (r, w) {
            (Some(r), Some(w)) => Some((r, w)),
            _ => {
                if supervisor_fds.is_some() || web_fds.is_some() {
                    warn!(
                        "Vault IPC channel not configured (VAUBAN_VAULT_IPC_READ/WRITE); \
                         credential decryption will be unavailable"
                    );
                }
                None
            }
        }
    };

    let supervised = supervisor_fds.is_some() || web_fds.is_some();
    if supervised && data_fds.is_none() {
        error!("MCP data pipe required under supervisor (refusing to start)");
        return ExitCode::FAILURE;
    }

    // Session-token MAC key BEFORE Capsicum (env mutation impossible after).
    match session_token_gate::init_from_env() {
        Ok(()) => info!("session-token MAC key loaded (BLAKE3-keyed)"),
        Err(e) if supervised => {
            error!(
                error = %e,
                "VAUBAN_SESSION_TOKEN_KEY required under supervisor (refusing to start)"
            );
            return ExitCode::FAILURE;
        }
        Err(e) => {
            warn!(
                error = %e,
                "session-token key not loaded — IPC opens fail closed; HTTP lab register still works"
            );
        }
    }

    // AccessGuard: required under supervisor (ProxyMcp → Access topology).
    // Optional in standalone HTTP lab (`cargo run` without IPC FDs).
    let mut access_fds: Vec<RawFd> = Vec::new();
    let access_guard: Option<Arc<AccessGuard>> =
        match AccessGuard::from_env(PROTOCOL_MCP, Arc::new(McpAccessMetrics::new())) {
            Ok(AccessGuardWiring { guard, fds }) => {
                access_fds = fds;
                guard.spawn_dispatcher();
                info!("AccessGuard initialised (MCP RBAC re-check)");
                Some(guard)
            }
            Err(e) if supervised => {
                error!(
                    error = %e,
                    "AccessGuard required under supervisor (refusing to start)"
                );
                return ExitCode::FAILURE;
            }
            Err(e) => {
                warn!(
                    error = %e,
                    "AccessGuard not wired — IPC McpSessionOpen will fail closed; \
                     HTTP lab register still works for local-tools"
                );
                None
            }
        };

    // Clear FD env vars (same invariant as other proxies).
    unsafe {
        std::env::remove_var("VAUBAN_IPC_READ");
        std::env::remove_var("VAUBAN_IPC_WRITE");
        std::env::remove_var("VAUBAN_WEB_IPC_READ");
        std::env::remove_var("VAUBAN_WEB_IPC_WRITE");
        std::env::remove_var("VAUBAN_WEB_DATA_IPC_READ");
        std::env::remove_var("VAUBAN_WEB_DATA_IPC_WRITE");
        std::env::remove_var("VAUBAN_FD_PASSING_SOCKET");
        std::env::remove_var("VAUBAN_VAULT_IPC_READ");
        std::env::remove_var("VAUBAN_VAULT_IPC_WRITE");
    }

    let audit_fds: Option<(RawFd, RawFd)> = match (
        std::env::var("VAUBAN_AUDIT_IPC_READ"),
        std::env::var("VAUBAN_AUDIT_IPC_WRITE"),
    ) {
        (Ok(r), Ok(w)) => match (r.parse(), w.parse()) {
            (Ok(r), Ok(w)) => Some((r, w)),
            _ => None,
        },
        _ => None,
    };

    let (lease_tx, lease_rx) = tokio::sync::mpsc::channel::<RecordingLeaseReq>(32);
    if supervisor_fds.is_some() && fd_passing_socket.is_none() {
        error!("recording FD lease required under supervisor (refusing to start)");
        return ExitCode::FAILURE;
    }
    let lease_for_audit = if fd_passing_socket.is_some() && supervisor_fds.is_some() {
        Some(lease_tx)
    } else {
        drop(lease_tx);
        None
    };

    let mut audit = McpAudit::from_env(lease_for_audit);
    if let Some(ch) = open_audit_channel() {
        audit = audit.with_audit_tx(spawn_audit_writer(ch));
    }
    info!(
        recording_dir = %audit.recording_dir().display(),
        "MCP JSONL recording enabled (YYYY/MM/uuid/session.mcp.jsonl)"
    );

    let (web_notify_tx, web_notify_rx) = mpsc::unbounded_channel::<Message>();
    let mut state = GatewayState::new(audit, Some(web_notify_tx));
    state.access_guard = access_guard.clone();
    let router = build_router(state.clone());

    let fd_passing = fd_passing_socket.map(|fd| {
        info!(fd, "FD passing socket available");
        Arc::new(FdPassingState {
            socket_fd: fd,
            pending: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        })
    });
    if supervised && fd_passing.is_none() {
        error!("FD passing socket required under supervisor (recording lease + brokered upstream)");
        return ExitCode::FAILURE;
    }

    // Vault decrypt client BEFORE Capsicum (AsyncFd registration).
    let vault_client: Option<Arc<VaultDecryptClient>> = match vault_fds {
        Some((r, w)) => {
            let ch = unsafe { IpcChannel::from_raw_fds(r, w) };
            match VaultDecryptClient::new(ch) {
                Ok(client) => {
                    info!("Vault decrypt-only IPC client initialised");
                    Some(client)
                }
                Err(e) => {
                    error!(error = %e, "Failed to initialise Vault IPC client");
                    None
                }
            }
        }
        None => None,
    };

    // Capsicum / pledge seal (noop on macOS lab). Enrol IPC + Access +
    // Audit + Vault + FD-receiver + Streamable HTTP listener (PROXY_MCP_KINDS).
    let supervisor_channel = supervisor_fds.map(|(r, w)| unsafe { IpcChannel::from_raw_fds(r, w) });
    if supervised {
        match supervisor_channel.as_ref() {
            Some(channel) => {
                if let Err(e) = wait_for_mcp_identity(channel) {
                    error!(error = %e, "MCP tunnel identity required before the sandbox");
                    return ExitCode::FAILURE;
                }
            }
            None => {
                error!("supervisor channel required before the sandbox");
                return ExitCode::FAILURE;
            }
        }
    }

    let mut ipc_fds: Vec<RawFd> = Vec::new();
    if let Some(ref channel) = supervisor_channel {
        ipc_fds.extend([channel.read_fd(), channel.write_fd()]);
    }
    if let Some((r, w)) = web_fds {
        ipc_fds.extend([r, w]);
    }
    if let Some((r, w)) = data_fds {
        ipc_fds.extend([r, w]);
    }
    if let Some((r, w)) = audit_fds {
        ipc_fds.extend([r, w]);
    }
    if let Some((r, w)) = vault_fds {
        ipc_fds.extend([r, w]);
    }
    ipc_fds.extend(access_fds.iter().copied());
    let fd_receiver_fds: Option<Vec<RawFd>> = fd_passing_socket.map(|fd| vec![fd]);
    let sealed = match capsicum::setup_service_sandbox_with_listeners(
        &ipc_fds,
        None,
        fd_receiver_fds.as_deref(),
        None,
    ) {
        Ok(sealed) => sealed,
        Err(e) => {
            error!(error = %e, "failed to setup service sandbox");
            return ExitCode::FAILURE;
        }
    };
    capsicum::log_main_loop_start(&sealed, "MCP gateway sealed, no listener");
    let _sealed: capsicum::Entered = sealed;

    // Vault reader after seal (mirrors AccessGuard / proxy-ssh).
    if let Some(ref vc) = vault_client {
        tokio::spawn(Arc::clone(vc).process_incoming());
    }

    info!("MCP gateway ready (hop 2 arrives on the data pipe)");

    let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
    let mut shutdown_rx = shutdown_tx.subscribe();

    let (tcp_tx, tcp_rx) = mpsc::unbounded_channel::<Message>();
    if let Some(ref fp) = fd_passing {
        let _ = state.rebroker.set(Arc::new(McpUpstreamRebroker::new(
            tcp_tx,
            Arc::clone(&fp.pending),
        )));
    } else {
        drop(tcp_tx);
    }

    if let Some(channel) = supervisor_channel {
        let shutdown_tx_ctrl = shutdown_tx.clone();
        let fd_passing_ctrl = fd_passing.clone();
        tokio::spawn(async move {
            supervisor_control_loop(channel, shutdown_tx_ctrl, fd_passing_ctrl, lease_rx, tcp_rx)
                .await;
        });
        info!("Supervisor control channel attached");
    } else {
        drop(lease_rx);
        drop(tcp_rx);
    }

    // `Web -> ProxyMcp` topology edge (see vauban-supervisor's TOPOLOGY):
    // vauban-web gets `VAUBAN_PROXY_MCP_IPC_{READ,WRITE}`, this process
    // gets the peer end named from ITS perspective, `VAUBAN_WEB_IPC_*`
    // -- identical convention to vauban-proxy-ssh/-rdp/-iacs.
    if let Some((read_fd, write_fd)) = web_fds {
        let channel = unsafe { IpcChannel::from_raw_fds(read_fd, write_fd) };
        let shutdown_rx_web = shutdown_tx.subscribe();
        let state_for_ipc = state.clone();
        let guard_for_ipc = access_guard.clone();
        let vault_for_ipc = vault_client.clone();
        let pending_for_ipc = fd_passing.as_ref().map(|fp| Arc::clone(&fp.pending));
        tokio::spawn(async move {
            web_ipc_loop(
                channel,
                shutdown_rx_web,
                state_for_ipc,
                guard_for_ipc,
                pending_for_ipc,
                vault_for_ipc,
                web_notify_rx,
            )
            .await;
        });
        info!("Web IPC channel attached (McpSessionOpen/Update/Terminate/Suspend/Resume/HITL)");
    } else {
        drop(web_notify_rx);
        debug!(
            "VAUBAN_WEB_IPC_READ/WRITE not set -- running without supervisor (dev HTTP-only mode)"
        );
    }

    if let Some((read_fd, write_fd)) = data_fds {
        let channel = unsafe { IpcChannel::from_raw_fds(read_fd, write_fd) };
        let max_tunnels = std::env::var("VAUBAN_MCP_MAX_TUNNELS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(256usize);
        let relay_timeout = std::time::Duration::from_secs(
            std::env::var("VAUBAN_MCP_RELAY_TIMEOUT_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(90u64),
        );
        let shutdown_rx_data = shutdown_tx.subscribe();
        let code = data_pipe::data_ipc_loop(
            channel,
            router,
            data_pipe::RELAY_MAX_INFLIGHT,
            max_tunnels,
            relay_timeout,
            shutdown_rx_data,
        )
        .await;
        let _ = shutdown_tx.send(());
        return code;
    }

    let _ = shutdown_rx.recv().await;
    let _ = shutdown_tx.send(());
    ExitCode::SUCCESS
}

#[cfg(test)]
mod gwt_tests {
    //! Phase 5.1 automated acceptance pins (docs/specs/vauban-mcp/08 + 09).
    //! Named `gwt_*` so `just test-mcp-gwt` can filter them.

    use super::*;
    use axum::body::to_bytes;
    use phase_c::HitlStatus;
    use shared::access_guard::AccessDecision;
    use tool_constraints::ToolConstraint;

    #[test]
    fn appliance_session_ttl_from_env_and_defaults() {
        assert_eq!(appliance_session_ttl_secs_from(None), 3600.0);
        assert_eq!(appliance_session_ttl_secs_from(Some("7200")), 7200.0);
        assert_eq!(appliance_session_ttl_secs_from(Some("10")), 30.0);
        assert_eq!(appliance_session_ttl_secs_from(Some("999999")), 28_800.0);
        assert_eq!(appliance_session_ttl_secs_from(Some("nope")), 3600.0);
    }

    #[test]
    fn leaf_has_no_listener_and_requires_the_data_pipe() {
        let src = include_str!("main.rs");
        let prod = src.split("mod gwt_tests").next().unwrap_or(src);
        assert!(
            !prod.contains(concat!("TcpListener::", "bind")),
            "the leaf must not bind a socket; hop 2 arrives on the data pipe"
        );
        assert!(
            !prod.contains(concat!("VAUBAN_MCP_", "BIND_ADDR")),
            "the supervisor must not tell the leaf an address to bind"
        );
        assert!(
            prod.contains("VAUBAN_WEB_DATA_IPC_READ")
                && prod.contains("MCP data pipe required under supervisor"),
            "supervised boot is fail-closed without the data pipe"
        );
        assert!(
            prod.contains("capsicum::setup_service_sandbox_with_listeners")
                && prod.contains("let _sealed: capsicum::Entered"),
            "sandbox entry must be the capsicum helper and keep the Entered witness"
        );
    }

    #[test]
    fn data_loop_observes_supervisor_shutdown() {
        let src = include_str!("main.rs");
        let prod = src.split("mod gwt_tests").next().unwrap_or(src);
        let call = prod
            .find("data_pipe::data_ipc_loop(")
            .expect("data_ipc_loop call");
        let window = &prod[call..prod.len().min(call + 500)];
        assert!(
            window.contains("shutdown_rx_data"),
            "the data pipe loop must observe supervisor shutdown"
        );
        let ctrl = prod
            .find("if st.shutdown")
            .expect("control-loop shutdown flag");
        let ctrl_window = &prod[ctrl..prod.len().min(ctrl + 500)];
        assert!(
            ctrl_window.contains("Shutdown flag set, exiting main loop to run destructors"),
            "control loop must log shutdown and leave the poll before the next sleep"
        );
    }

    #[test]
    fn shutdown_control_sets_the_flag() {
        let mut st = ControlLoopState {
            start_time: Instant::now(),
            requests_processed: 0,
            shutdown: false,
        };
        assert!(handle_control(ControlMessage::Shutdown, &mut st).is_none());
        assert!(st.shutdown);
    }

    #[test]
    fn visit_expires_at_cannot_beat_appliance() {
        let now = 1_000_000.0;
        assert_eq!(
            clamp_visit_expires_at(now + 99_999.0, now, 3600.0),
            now + 3600.0
        );
        assert_eq!(
            clamp_visit_expires_at(now + 600.0, now, 3600.0),
            now + 600.0
        );
        assert_eq!(clamp_visit_expires_at(now - 10.0, now, 3600.0), now - 10.0);
        assert_eq!(
            clamp_visit_expires_at(now + 10_000.0, now, 7200.0),
            now + 7200.0
        );
    }

    #[test]
    fn gwt_mcp_session_open_reclamps_expires_at() {
        let src = include_str!("main.rs");
        let start = src
            .find("async fn handle_mcp_session_open(")
            .expect("handle_mcp_session_open");
        let body = &src[start..];
        assert!(
            body.contains("clamp_visit_expires_at") && body.contains("appliance_session_ttl_secs"),
            "IPC McpSessionOpen must cap expires_at at [mcp].session_ttl_seconds"
        );
    }

    fn test_audit() -> McpAudit {
        McpAudit::from_env(None)
    }

    fn test_state() -> GatewayState {
        GatewayState::new(test_audit(), None)
    }

    fn base_session(id: &str) -> Session {
        Session {
            session_id: id.to_string(),
            vbw_hash: "deadbeef".into(),
            expires_at: unix_now() + 3600.0,
            allowed_tools: Some(vec!["echo".into()]),
            envelope_max: 3,
            envelope_window: 60,
            on_exceed: "throttle".into(),
            call_times: VecDeque::new(),
            terminated: false,
            suspended: false,
            justification: "gwt".into(),
            user_id: Some("user-1".into()),
            api_key_id: None,
            asset_id: Some("asset-1".into()),
            upstream_url: None,
            upstream_bearer: None,
            upstream_stream: None,
            session_token: Vec::new(),
            upstream_host: String::new(),
            upstream_port: 0,
            upstream_tls_spki_pin: None,
            tool_constraints: HashMap::new(),
            client_info: None,
            clientinfo_pin: true,
            hitl_pendings: HashMap::new(),
            mandate: None,
            transport: "direct".into(),
            require_seal: false,
        }
    }

    fn insert_session(state: &GatewayState, sess: Session) {
        let mut g = state.lock_inner();
        g.by_hash
            .insert(sess.vbw_hash.clone(), sess.session_id.clone());
        g.sessions.insert(sess.session_id.clone(), sess);
    }

    #[test]
    fn gwt_successful_tools_call_jsonl_strips_vauban_args() {
        let src = include_str!("main.rs");
        let start = src
            .find("audit JSONL sync failed after tools/call")
            .expect("success tools/call JSONL sync path");
        let window = &src[start.saturating_sub(500)..start];
        assert!(
            window.contains("strip_vauban_args") && window.contains("args.as_ref()"),
            "successful tools/call JSONL must record arguments after stripping arguments.vauban"
        );
    }

    /// V-1: tools/call hors whitelist → deny path `-32001` (no allow).
    #[test]
    fn gwt_v1_tools_call_outside_whitelist_denied() {
        let mut sess = base_session("s-v1");
        sess.allowed_tools = Some(vec!["echo".into()]);
        assert!(tool_allowed(&sess, "echo"));
        assert!(
            !tool_allowed(&sess, "delete_vm"),
            "V-1: tool outside whitelist must be denied"
        );
        sess.allowed_tools = None;
        assert!(
            !tool_allowed(&sess, "echo"),
            "V-1/M4: missing whitelist is fail-closed, never allow-all"
        );
        let err = jsonrpc_err(json!(1), -32001, "tool_not_allowed", None);
        assert_eq!(err["error"]["code"], -32001);
    }

    /// V-15 substrate: AccessGuard Timeout is never Granted (proxy open must deny).
    #[test]
    fn gwt_v15_accessguard_timeout_is_not_granted() {
        assert!(
            !AccessDecision::Timeout.is_granted(),
            "V-15: AccessGuard timeout must deny (no upstream)"
        );
        let src = include_str!("main.rs");
        assert!(
            src.contains("!decision.is_granted()") || src.contains("decision.is_granted()"),
            "proxy-mcp open must gate on AccessGuard is_granted"
        );
    }

    /// B-5: envelope on_exceed=suspend → `-32031` and session.suspended.
    #[test]
    fn gwt_b5_envelope_suspend_returns_32031() {
        let state = test_state();
        let mut sess = base_session("s-b5");
        sess.envelope_max = 2;
        sess.envelope_window = 60;
        sess.on_exceed = "suspend".into();
        let now = unix_now();
        sess.call_times.push_back(now);
        sess.call_times.push_back(now);
        insert_session(&state, sess);

        // Production path: work on a snapshot, never lock+recurse into GatewayState.
        let mut snap = {
            let g = state.inner.lock().unwrap();
            g.sessions.get("s-b5").unwrap().clone_snapshot()
        };
        let err = check_envelope(&state, &mut snap).expect("B-5: exceed+suspend must error");
        assert_eq!(err["error"]["code"], -32031);
        assert_eq!(err["error"]["message"], "session_suspended");
        let g = state.inner.lock().unwrap();
        assert!(
            g.sessions.get("s-b5").unwrap().suspended,
            "B-5: session must be suspended in gateway map"
        );
    }

    /// B-5 suite: Resume clears suspended so tools/call can proceed past gate.
    #[test]
    fn gwt_b5_resume_clears_suspended() {
        let state = test_state();
        let mut sess = base_session("s-b5r");
        sess.suspended = true;
        insert_session(&state, sess);
        assert!(state.resume_session("s-b5r", "admin-1"));
        let g = state.inner.lock().unwrap();
        assert!(!g.sessions.get("s-b5r").unwrap().suspended);
    }

    /// B-7: HITL tool → first call creates pending, returns Some (blocks upstream).
    #[tokio::test]
    async fn gwt_b7_hitl_first_call_blocks_upstream() {
        let state = test_state();
        let mut sess = base_session("s-b7");
        sess.tool_constraints.insert(
            "delete_vm".into(),
            ToolConstraint {
                input_schema: json!({"type": "object"}),
                forbidden_keys: vec![],
                hitl: true,
                require_plan: false,
                status: Some("approved".into()),
                schema_fingerprint: None,
            },
        );
        insert_session(&state, sess.clone_snapshot());

        let snap = {
            let g = state.inner.lock().unwrap();
            g.sessions.get("s-b7").unwrap().clone_snapshot()
        };
        let resp = handle_hitl_tools_call(
            &state,
            &snap,
            &json!(1),
            "delete_vm",
            Some(&json!({"id": "vm-1"})),
            &json!({}),
            None,
            false,
        )
        .await;
        assert!(
            resp.is_some(),
            "B-7: HITL must return JSON-RPC error (no upstream fallthrough)"
        );
        let body = to_bytes(resp.unwrap().into_body(), 64 * 1024)
            .await
            .unwrap();
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["error"]["code"], -32030);
        assert_eq!(v["error"]["message"], "tool_approval_required");
        assert!(v["error"]["data"]["pending_id"].as_str().is_some());

        let g = state.inner.lock().unwrap();
        assert_eq!(
            g.sessions.get("s-b7").unwrap().hitl_pendings.len(),
            1,
            "B-7: pending store must hold one entry"
        );
        let p = g
            .sessions
            .get("s-b7")
            .unwrap()
            .hitl_pendings
            .values()
            .next()
            .unwrap();
        assert_eq!(p.status, HitlStatus::Pending);
        assert_eq!(p.tool, "delete_vm");
    }

    /// B-11: clientInfo drift detection + terminate.
    #[tokio::test]
    async fn gwt_b11_clientinfo_drift_terminates() {
        let a = ClientInfo {
            name: "agent".into(),
            version: "1.0".into(),
        };
        let b = ClientInfo {
            name: "agent".into(),
            version: "2.0".into(),
        };
        assert_ne!(a, b, "B-11: different clientInfo must not compare equal");

        let state = test_state();
        let mut sess = base_session("s-b11");
        sess.client_info = Some(a);
        sess.clientinfo_pin = true;
        insert_session(&state, sess);
        state.terminate_session("s-b11", "clientinfo_drift");
        let g = state.inner.lock().unwrap();
        assert!(g.sessions.get("s-b11").unwrap().terminated);

        let src = include_str!("main.rs");
        assert!(
            src.contains("clientinfo_drift") && src.contains("terminate_session"),
            "B-11: initialize path must terminate on clientInfo drift"
        );
    }

    /// Helper: Session is not Clone; copy fields for HITL / envelope snapshots.
    impl Session {
        fn clone_snapshot(&self) -> Session {
            Session {
                session_id: self.session_id.clone(),
                vbw_hash: self.vbw_hash.clone(),
                expires_at: self.expires_at,
                allowed_tools: self.allowed_tools.clone(),
                envelope_max: self.envelope_max,
                envelope_window: self.envelope_window,
                on_exceed: self.on_exceed.clone(),
                call_times: self.call_times.clone(),
                terminated: self.terminated,
                suspended: self.suspended,
                justification: self.justification.clone(),
                user_id: self.user_id.clone(),
                api_key_id: self.api_key_id.clone(),
                asset_id: self.asset_id.clone(),
                upstream_url: self.upstream_url.clone(),
                upstream_bearer: self.upstream_bearer.clone(),
                upstream_stream: self.upstream_stream.clone(),
                session_token: self.session_token.clone(),
                upstream_host: self.upstream_host.clone(),
                upstream_port: self.upstream_port,
                upstream_tls_spki_pin: self.upstream_tls_spki_pin.clone(),
                tool_constraints: self.tool_constraints.clone(),
                client_info: self.client_info.clone(),
                clientinfo_pin: self.clientinfo_pin,
                hitl_pendings: self.hitl_pendings.clone(),
                mandate: self.mandate.clone(),
                transport: self.transport.clone(),
                require_seal: self.require_seal,
            }
        }
    }

    #[test]
    fn gwt_tls_pin_required_off_loopback() {
        assert!(is_loopback_upstream_host("127.0.0.1"));
        assert!(is_loopback_upstream_host("localhost"));
        assert!(is_loopback_upstream_host("::1"));
        assert!(is_loopback_upstream_host("[::1]"));
        assert!(!is_loopback_upstream_host("10.0.0.8"));
        assert!(!is_loopback_upstream_host("mcp.internal"));
        let src = include_str!("main.rs");
        assert!(
            src.contains("is_loopback_upstream_host")
                && src.contains("TLS pin required for non-loopback MCP upstream"),
            "plaintext HTTP on the brokered FD is lab-loopback only"
        );
        assert!(
            src.contains("max_body_bytes") && src.contains("DefaultBodyLimit::max"),
            "McpSessionOpen must bind max_body_bytes; hop-2 ingress must be capped"
        );
    }

    #[test]
    fn attack_lab_escape_strings_are_absent() {
        let src = include_str!("main.rs");
        for needle in [
            concat!("MCP_ALLOW_", "REQWEST_UPSTREAM"),
            concat!("MCP_DEV_", "CONTROL_PLANE"),
            concat!("MCP_LAB_", "AUTO_APPROVE_HITL"),
            concat!("MCP_CLIENTINFO_", "PIN"),
            concat!("route(\"/", "health\""),
            concat!("route(\"/", "session\""),
        ] {
            assert!(!src.contains(needle), "lab escape must be absent: {needle}");
        }
    }

    #[test]
    fn gwt_b5_empty_on_exceed_preserves_suspend() {
        let mut sess = base_session("s-b5-preserve");
        sess.on_exceed = "suspend".into();
        let widened = apply_session_update(
            &mut sess,
            None,
            Some("{}"),
            Some(120),
            Some(60),
            Some(String::new()),
            None,
            true,
        );
        assert!(!widened);
        assert_eq!(
            sess.on_exceed, "suspend",
            "empty envelope_on_exceed must not clobber suspend (recheck path)"
        );
    }

    #[test]
    fn gwt_phase_c_hitl_merge_on_update() {
        let mut sess = base_session("s-hitl-mid");
        sess.tool_constraints.insert(
            "danger".into(),
            ToolConstraint {
                input_schema: serde_json::json!({}),
                forbidden_keys: vec![],
                hitl: false,
                require_plan: false,
                status: None,
                schema_fingerprint: None,
            },
        );
        let _ = apply_session_update(
            &mut sess,
            None,
            Some(r#"{"danger":{"hitl":true,"input_schema":{}}}"#),
            None,
            None,
            None,
            None,
            true,
        );
        assert!(
            sess.tool_constraints["danger"].hitl,
            "McpSessionUpdate must enable HITL mid-session"
        );
    }

    #[test]
    fn gwt_b11_clientinfo_pin_defaults_on() {
        assert!(clientinfo_pin_from_env(), "clientInfo pin is always on");
        let src = include_str!("main.rs");
        assert!(
            src.contains("missing_client_info") && src.contains("clientinfo_drift"),
            "initialize must terminate on missing/drift clientInfo when pinned"
        );
    }

    #[test]
    fn gwt_step_inflight_is_not_perimeter_drift() {
        assert!(!mandate::is_perimeter_drift("step_inflight"));
        let src = include_str!("main.rs");
        assert!(
            src.contains("emit_mandate_perimeter_drift") && src.contains("is_perimeter_drift"),
            "IAM notify must filter CheckStep deny reasons"
        );
        assert!(
            src.contains("ERR_MISSION_EXPIRED"),
            "TTL expiry must use -32034, not the drift code"
        );
    }

    #[tokio::test]
    async fn gwt_perimeter_drift_terminates_session_immediately() {
        let state = test_state();
        let mut sess = base_session("s-drift");
        let contract = mandate::parse_contract(&serde_json::json!({
            "approval": "mission",
            "edges": [],
            "steps": [{
                "step_id": "1",
                "intent": "Echo the sealed lab message",
                "operation": "echo",
                "mode": "literal",
                "arguments": {"message": "seal-ok"}
            }]
        }))
        .unwrap();
        sess.mandate = Some(
            mandate::seal_mandate("m-d", "s-drift", "asset-1", &contract, unix_now()).unwrap(),
        );
        insert_session(&state, sess.clone_snapshot());
        let snap = {
            let g = state.inner.lock().unwrap();
            g.sessions.get("s-drift").unwrap().clone_snapshot()
        };
        let resp = handle_hitl_tools_call(
            &state,
            &snap,
            &json!(1),
            "echo",
            Some(&json!({"message": "DRIFT"})),
            &json!({}),
            None,
            true,
        )
        .await;
        assert!(resp.is_some());
        let body = to_bytes(resp.unwrap().into_body(), 64 * 1024)
            .await
            .unwrap();
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["error"]["code"], -32033);
        let g = state.inner.lock().unwrap();
        assert!(
            g.sessions.get("s-drift").unwrap().terminated,
            "perimeter drift must terminate the proxy session before web IAM"
        );
    }

    #[tokio::test]
    async fn gwt_step_inflight_does_not_terminate() {
        let state = test_state();
        let mut sess = base_session("s-inf");
        let contract = mandate::parse_contract(&serde_json::json!({
            "approval": "mission",
            "edges": [],
            "steps": [{
                "step_id": "1",
                "intent": "Echo the sealed lab message",
                "operation": "echo",
                "mode": "literal",
                "arguments": {"message": "seal-ok"}
            }]
        }))
        .unwrap();
        let mut m =
            mandate::seal_mandate("m-i", "s-inf", "asset-1", &contract, unix_now()).unwrap();
        let _ = mandate::check_step(&mut m, "echo", Some(&json!({"message": "seal-ok"})));
        sess.mandate = Some(m);
        insert_session(&state, sess.clone_snapshot());
        let snap = {
            let g = state.inner.lock().unwrap();
            g.sessions.get("s-inf").unwrap().clone_snapshot()
        };
        let resp = handle_hitl_tools_call(
            &state,
            &snap,
            &json!(2),
            "echo",
            Some(&json!({"message": "seal-ok"})),
            &json!({}),
            None,
            true,
        )
        .await;
        assert!(resp.is_some());
        let body = to_bytes(resp.unwrap().into_body(), 64 * 1024)
            .await
            .unwrap();
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["error"]["code"], -32010);
        let g = state.inner.lock().unwrap();
        assert!(
            !g.sessions.get("s-inf").unwrap().terminated,
            "step_inflight must not IAM-cut the session"
        );
    }

    #[test]
    fn gwt_mcp_rebroker_is_iacs_style() {
        let src = include_str!("main.rs");
        assert!(
            src.contains("post_json_on_brokered_fd")
                && src.contains("replace_brokered_upstream")
                && src.contains("is_dead_upstream_io"),
            "hop 2 MUST re-broker a dead FD instead of failing closed on first EPIPE"
        );
        let rb = include_str!("upstream_rebroker.rs");
        let impl_rb = rb.split("#[cfg(test)]").next().unwrap_or(rb);
        assert!(
            impl_rb.contains("target_service: Service::ProxyMcp")
                && impl_rb.contains("TcpConnectRequest")
                && !impl_rb.contains("TcpStream::connect"), // allow-post-sandbox: assertion text, not a connect
            "re-broker MUST use supervisor TcpConnect, never free connect"
        );
        assert!(
            !impl_rb.contains("std::net::TcpStream::connect") // allow-post-sandbox: assertion text, not a connect
                && !impl_rb.contains("tokio::net::TcpStream::connect"), // allow-post-sandbox: assertion text, not a connect
            "impl must not name a free connect"
        );
    }

    async fn http_peer(response_body: &'static str) -> tokio::net::TcpStream {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap(); // allow-post-sandbox: test fake upstream
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let Ok((mut s, _)) = listener.accept().await else {
                return;
            };
            let mut buf = vec![0u8; 8192];
            let _ = s.read(&mut buf).await;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{response_body}",
                response_body.len()
            );
            let _ = s.write_all(resp.as_bytes()).await;
        });
        tokio::net::TcpStream::connect(addr).await.unwrap() // allow-post-sandbox: test fake upstream
    }

    async fn dead_peer() -> tokio::net::TcpStream {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap(); // allow-post-sandbox: test fake upstream
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move {
            let (s, _) = listener.accept().await.unwrap();
            drop(s);
        });
        let client = tokio::net::TcpStream::connect(addr).await.unwrap(); // allow-post-sandbox: test fake upstream
        accept.await.unwrap();
        client
    }

    fn wrap_plain(tcp: tokio::net::TcpStream) -> Arc<AsyncMutex<upstream_http::UpstreamIo>> {
        Arc::new(AsyncMutex::new(upstream_http::UpstreamIo::Plain(tcp)))
    }

    fn wire_rebroker_that_injects(
        state: &GatewayState,
        pending: PendingConnections,
        session_id: &'static str,
        fd: std::os::fd::OwnedFd,
    ) {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let pending_inject = Arc::clone(&pending);
        tokio::spawn(async move {
            let _ = rx.recv().await;
            pending_inject
                .lock()
                .await
                .insert(session_id.to_string(), fd);
        });
        let _ = state
            .rebroker
            .set(Arc::new(McpUpstreamRebroker::new(tx, pending)));
    }

    /// First POST on a live hop-1 FD succeeds; no supervisor round-trip.
    #[tokio::test]
    async fn gwt_mcp_rebroker_e2e_first_post_ok() {
        let tcp = http_peer(r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#).await;
        let state = test_state();
        let mut sess = base_session("s-rb-ok");
        sess.upstream_stream = Some(wrap_plain(tcp));
        insert_session(&state, sess.clone_snapshot());
        let (status, v) = post_json_on_brokered_fd(&state, &sess, "127.0.0.1", &json!({}))
            .await
            .expect("live FD");
        assert_eq!(status, 200);
        assert_eq!(v["result"]["ok"], true);
    }

    /// Dead hop-1 FD → supervisor TcpConnect → one POST retry → 200.
    #[tokio::test]
    async fn gwt_mcp_rebroker_e2e_retries_once() {
        use std::os::fd::OwnedFd;
        let dead = dead_peer().await;
        let live = http_peer(r#"{"jsonrpc":"2.0","id":2,"result":{"rebrokered":true}}"#).await;
        let fd = OwnedFd::from(live.into_std().unwrap());

        let state = test_state();
        let pending: PendingConnections = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        wire_rebroker_that_injects(&state, pending, "s-rb-retry", fd);

        let mut sess = base_session("s-rb-retry");
        sess.upstream_stream = Some(wrap_plain(dead));
        sess.session_token = vec![7u8; 16];
        sess.upstream_host = "127.0.0.1".into();
        sess.upstream_port = 19001;
        insert_session(&state, sess.clone_snapshot());

        let (status, v) = post_json_on_brokered_fd(&state, &sess, "127.0.0.1", &json!({}))
            .await
            .expect("rebroker retry");
        assert_eq!(status, 200);
        assert_eq!(v["result"]["rebrokered"], true);
        let g = state.inner.lock().unwrap();
        assert!(
            g.sessions
                .get("s-rb-retry")
                .unwrap()
                .upstream_stream
                .is_some(),
            "live session must keep the new FD"
        );
    }

    #[tokio::test]
    async fn gwt_mcp_rebroker_e2e_unwired_fail_closed() {
        let dead = dead_peer().await;
        let state = test_state();
        let mut sess = base_session("s-rb-unwired");
        sess.upstream_stream = Some(wrap_plain(dead));
        sess.session_token = vec![1u8; 8];
        sess.upstream_host = "127.0.0.1".into();
        sess.upstream_port = 19001;
        let err = post_json_on_brokered_fd(&state, &sess, "127.0.0.1", &json!({}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("rebroker not wired"), "{err:#}");
    }

    #[tokio::test]
    async fn gwt_mcp_rebroker_e2e_no_stream() {
        let state = test_state();
        let sess = base_session("s-rb-none");
        let err = post_json_on_brokered_fd(&state, &sess, "127.0.0.1", &json!({}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("no brokered upstream stream"));
    }

    #[tokio::test]
    async fn gwt_mcp_rebroker_e2e_non_dead_does_not_retry() {
        let tcp = http_peer("not-json").await;
        let state = test_state();
        let mut sess = base_session("s-rb-json");
        sess.upstream_stream = Some(wrap_plain(tcp));
        let err = post_json_on_brokered_fd(&state, &sess, "127.0.0.1", &json!({}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("upstream JSON body"), "{err:#}");
        assert!(
            state.rebroker.get().is_none(),
            "must not wire / call rebroker"
        );
    }

    #[tokio::test]
    async fn gwt_mcp_rebroker_e2e_tls_pin_fail_closed() {
        use std::os::fd::OwnedFd;
        let live = http_peer("{}").await;
        let fd = OwnedFd::from(live.into_std().unwrap());
        let state = test_state();
        let pending: PendingConnections = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        wire_rebroker_that_injects(&state, pending, "s-rb-tls", fd);
        let mut sess = base_session("s-rb-tls");
        sess.session_token = vec![2u8; 8];
        sess.upstream_host = "127.0.0.1".into();
        sess.upstream_port = 19001;
        sess.upstream_tls_spki_pin = Some("not-a-pin".into());
        let err = replace_brokered_upstream(&state, &sess).await.unwrap_err();
        assert!(
            err.to_string().contains("SHA256") || err.to_string().contains("TLS"),
            "{err:#}"
        );
    }

    #[tokio::test]
    async fn gwt_mcp_rebroker_e2e_replace_without_session_row() {
        use std::os::fd::OwnedFd;
        let live = http_peer("{}").await;
        let fd = OwnedFd::from(live.into_std().unwrap());
        let state = test_state();
        let pending: PendingConnections = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        wire_rebroker_that_injects(&state, pending, "ghost", fd);
        let mut sess = base_session("ghost");
        sess.session_token = vec![3u8; 8];
        sess.upstream_host = "127.0.0.1".into();
        sess.upstream_port = 19001;
        let io = replace_brokered_upstream(&state, &sess)
            .await
            .expect("FD still returned when session map has no row");
        let _ = io;
    }

    #[test]
    fn gwt_lab_justification_matches_sec03() {
        let src = include_str!("main.rs");
        assert!(
            src.contains("justification.len() < 10 || justification.len() > 1000"),
            "session create must use 10..1000 like web/API"
        );
    }

    #[test]
    fn gwt_seal_uses_asset_id_not_upstream_url() {
        let src = include_str!("main.rs");
        assert!(
            src.contains("fn mandate_asset_id") && src.contains("asset_id: Some(asset_id.clone())"),
            "IPC open must persist asset UUID; seal must bind it"
        );
        assert!(
            !src.contains("sess.upstream_url.as_deref().unwrap_or(\"mcp\")"),
            "sealed_digest must not bind upstream_url"
        );
    }

    #[test]
    fn gwt_allow_upstream_short_circuits_hitl() {
        let src = include_str!("main.rs");
        assert!(
            src.contains("PdpGate::AllowUpstream => return None"),
            "access CheckStep Allow must go upstream, not fall into require_plan HITL"
        );
        assert!(
            src.contains("sync_local_mandate_after_pdp_allow"),
            "PDP Allow must consume Session.mandate or the next Seal is -32033"
        );
        assert!(
            src.contains("spawn_clear_mcp_mandate"),
            "session end must clear the access PDP store"
        );
    }

    #[test]
    fn gwt_agent_view_lists_arguments_vauban() {
        let src = include_str!("main.rs");
        assert!(
            src.contains("mod agent_view")
                && src.contains("filter_and_enrich_tools")
                && src.contains("strip_vauban_from_rpc_body")
                && src.contains("attach_visit_instructions"),
            "proxy must enrich tools/list and strip arguments.vauban before upstream"
        );
        let view = include_str!("agent_view.rs");
        assert!(
            view.contains("VAUBAN_ARGS_KEY")
                && view.contains("vauban_plan_schema")
                && view.contains("arguments.vauban.story"),
            "agent_view must advertise Story + Contract on Require plan tools"
        );
        assert!(
            view.contains("VISIT_IDENTITY")
                && view.contains("Callable tools are those in tools/list")
                && !view.contains("Allowed this visit:"),
            "initialize.instructions is identity, not a tool inventory"
        );
    }

    #[test]
    fn filter_tools_list_adds_vauban_on_require_plan() {
        let mut sess = base_session("s-list");
        sess.allowed_tools = Some(vec!["read_demo_file".into()]);
        sess.tool_constraints.insert(
            "read_demo_file".into(),
            ToolConstraint {
                input_schema: json!({}),
                forbidden_keys: vec![],
                hitl: true,
                require_plan: true,
                status: None,
                schema_fingerprint: None,
            },
        );
        let out = filter_tools_list(
            &sess,
            json!({
                "tools": [{
                    "name": "read_demo_file",
                    "inputSchema": {
                        "type": "object",
                        "required": ["name"],
                        "properties": { "name": { "type": "string" } }
                    }
                }]
            }),
        );
        assert!(
            out["tools"][0]["inputSchema"]["properties"]
                .get("vauban")
                .is_some()
        );
        assert!(
            out["tools"][0]["inputSchema"]["required"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v == "vauban")
        );
    }

    fn one_step_read_contract() -> mandate::Contract {
        mandate::parse_contract(&serde_json::json!({
            "approval": "mission",
            "edges": [],
            "steps": [{
                "step_id": "1",
                "intent": "Read the sealed lab hello file",
                "operation": "read_demo_file",
                "mode": "literal",
                "arguments": {"name": "hello.txt"}
            }]
        }))
        .unwrap()
    }

    fn complete_one_step_read(session_id: &str) -> mandate::MandateState {
        let mut m = mandate::seal_mandate(
            "m-done",
            session_id,
            "asset-1",
            &one_step_read_contract(),
            unix_now(),
        )
        .unwrap();
        let args = json!({"name": "hello.txt"});
        match mandate::check_step(&mut m, "read_demo_file", Some(&args)) {
            mandate::CheckStepOutcome::Allow {
                step_id,
                call_digest,
            } => {
                mandate::commit_step_result(&mut m, &step_id, &call_digest, json!({"ok": true}));
            }
            other => panic!("expected Allow, got {other:?}"),
        }
        assert!(mandate::all_steps_done(&m));
        assert!(!mandate::pep_mandate_active(&m));
        m
    }

    #[test]
    fn gwt_pdp_allow_sync_lets_next_seal_replace() {
        let state = test_state();
        let mut sess = base_session("s-sync-replace");
        let fresh = mandate::seal_mandate(
            "m-fresh",
            "s-sync-replace",
            "asset-1",
            &one_step_read_contract(),
            unix_now(),
        )
        .unwrap();
        assert!(mandate::pep_mandate_active(&fresh));
        sess.mandate = Some(fresh);
        insert_session(&state, sess);
        let args = json!({"name": "hello.txt"});
        sync_local_mandate_after_pdp_allow(&state, "s-sync-replace", "read_demo_file", Some(&args));
        {
            let mut g = state.inner.lock().unwrap();
            let m = g
                .sessions
                .get_mut("s-sync-replace")
                .unwrap()
                .mandate
                .as_mut()
                .unwrap();
            assert!(m.inflight.is_some(), "PDP Allow must set local inflight");
            if let Some((sid, dig)) = m.inflight.clone() {
                mandate::commit_step_result(m, &sid, &dig, json!({"ok": true}));
            }
            assert!(mandate::all_steps_done(m));
            let params = json!({
                "name": "read_demo_file",
                "arguments": {
                    "name": "secret.txt",
                    "vauban": {
                        "story": {
                            "summary": "Read the lab secret file after hello.",
                            "context": "Local MCP lab after all_steps_done of hello.txt.",
                            "objective": "Queue a new HITL for secret.txt only.",
                            "risks": "Reusing the hello mandate would -32033 this call."
                        },
                        "contract": {
                            "approval": "mission",
                            "steps": [{
                                "step_id": "1",
                                "operation": "read_demo_file",
                                "intent": "Read the sealed lab secret file now",
                                "mode": "literal",
                                "arguments": {"name": "secret.txt"}
                            }]
                        }
                    }
                }
            });
            assert_eq!(
                mandate::plan_mandate_pdp(Some(m), true, &params),
                mandate::MandatePdpPlan::Replace,
                "after PDP Allow+commit, a new Story/Contract must replace"
            );
        }
    }

    /// Without the PDP-Allow sync, Session.mandate stays unconsumed:
    /// the next Story+Contract is planned as CheckStep → -32033.
    #[test]
    fn gwt_stale_local_mandate_without_sync_stays_checkstep() {
        let fresh = mandate::seal_mandate(
            "m-stale",
            "s-stale",
            "asset-1",
            &one_step_read_contract(),
            unix_now(),
        )
        .unwrap();
        assert!(mandate::pep_mandate_active(&fresh));
        let params = json!({
            "name": "read_demo_file",
            "arguments": {
                "name": "secret.txt",
                "vauban": {
                    "story": {
                        "summary": "Read the lab secret file after hello.",
                        "context": "Local MCP lab after hello.txt finished.",
                        "objective": "This Seal must not CheckStep the stale hello mandate.",
                        "risks": "Unsynced Session.mandate after PDP Allow is -32033."
                    },
                    "contract": {
                        "approval": "mission",
                        "steps": [{
                            "step_id": "1",
                            "operation": "read_demo_file",
                            "intent": "Read the sealed lab secret file now",
                            "mode": "literal",
                            "arguments": {"name": "secret.txt"}
                        }]
                    }
                }
            }
        });
        assert_eq!(
            mandate::plan_mandate_pdp(Some(&fresh), true, &params),
            mandate::MandatePdpPlan::CheckStep,
            "unconsumed local mandate + new Seal must stay CheckStep (why sync exists)"
        );
    }

    #[test]
    fn gwt_filter_tools_list_rerequires_vauban_after_done() {
        let mut sess = base_session("s-list-done");
        sess.allowed_tools = Some(vec!["read_demo_file".into()]);
        sess.tool_constraints.insert(
            "read_demo_file".into(),
            ToolConstraint {
                input_schema: json!({}),
                forbidden_keys: vec![],
                hitl: true,
                require_plan: true,
                status: None,
                schema_fingerprint: None,
            },
        );
        sess.mandate = Some(complete_one_step_read("s-list-done"));
        let out = filter_tools_list(
            &sess,
            json!({
                "tools": [{
                    "name": "read_demo_file",
                    "inputSchema": {
                        "type": "object",
                        "required": ["name"],
                        "properties": { "name": { "type": "string" } }
                    }
                }]
            }),
        );
        assert!(
            out["tools"][0]["inputSchema"]["required"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v == "vauban"),
            "after all_steps_done, tools/list must re-require arguments.vauban"
        );
    }

    #[tokio::test]
    async fn require_plan_accepts_arguments_vauban() {
        let state = test_state();
        let mut sess = base_session("s-args-vauban");
        sess.allowed_tools = Some(vec!["echo".into()]);
        sess.tool_constraints.insert(
            "echo".into(),
            ToolConstraint {
                input_schema: json!({}),
                forbidden_keys: vec![],
                hitl: true,
                require_plan: true,
                status: None,
                schema_fingerprint: None,
            },
        );
        insert_session(&state, sess.clone_snapshot());
        let snap = {
            let g = state.inner.lock().unwrap();
            g.sessions.get("s-args-vauban").unwrap().clone_snapshot()
        };
        let params = json!({
            "name": "echo",
            "arguments": {
                "message": "seal-ok",
                "vauban": {
                    "story": {
                        "summary": "Run a short lab echo then clock check.",
                        "context": "Local MCP lab asset used for Mission Seal demos.",
                        "objective": "Prove sealed steps succeed and drift is denied.",
                        "risks": "Wrong Approve would allow the declared echo only here."
                    },
                    "contract": {
                        "approval": "mission",
                        "edges": [],
                        "steps": [{
                            "step_id": "1",
                            "intent": "Echo the sealed lab message",
                            "operation": "echo",
                            "mode": "literal",
                            "arguments": { "message": "seal-ok" }
                        }]
                    }
                }
            }
        });
        let args = mandate::strip_vauban_args(&params["arguments"]);
        let resp = handle_hitl_tools_call(
            &state,
            &snap,
            &json!(1),
            "echo",
            Some(&args),
            &params,
            None,
            true,
        )
        .await;
        assert!(resp.is_some());
        let body = to_bytes(resp.unwrap().into_body(), 64 * 1024)
            .await
            .unwrap();
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            v["error"]["code"], -32030,
            "arguments.vauban must queue HITL pending: {v}"
        );
    }

    #[tokio::test]
    async fn gwt_during_mission_echo_outside_contract_is_drift() {
        let state = test_state();
        let mut sess = base_session("s-echo-mid");
        sess.allowed_tools = Some(vec!["echo".into(), "read_demo_file".into()]);
        sess.mandate = Some(
            mandate::seal_mandate(
                "m-mid",
                "s-echo-mid",
                "asset-1",
                &one_step_read_contract(),
                unix_now(),
            )
            .unwrap(),
        );
        insert_session(&state, sess.clone_snapshot());
        let snap = {
            let g = state.inner.lock().unwrap();
            g.sessions.get("s-echo-mid").unwrap().clone_snapshot()
        };
        let resp = handle_hitl_tools_call(
            &state,
            &snap,
            &json!(1),
            "echo",
            Some(&json!({"message": "hello"})),
            &json!({}),
            None,
            true,
        )
        .await;
        let body = to_bytes(resp.unwrap().into_body(), 64 * 1024)
            .await
            .unwrap();
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["error"]["code"], -32033);
    }

    #[tokio::test]
    async fn gwt_after_done_plan_tool_without_vauban_is_missing_story_not_drift() {
        let state = test_state();
        let mut sess = base_session("s-done-story");
        sess.allowed_tools = Some(vec!["read_demo_file".into()]);
        sess.tool_constraints.insert(
            "read_demo_file".into(),
            ToolConstraint {
                input_schema: json!({}),
                forbidden_keys: vec![],
                hitl: true,
                require_plan: true,
                status: None,
                schema_fingerprint: None,
            },
        );
        sess.mandate = Some(complete_one_step_read("s-done-story"));
        insert_session(&state, sess.clone_snapshot());
        let snap = {
            let g = state.inner.lock().unwrap();
            g.sessions.get("s-done-story").unwrap().clone_snapshot()
        };
        let resp = handle_hitl_tools_call(
            &state,
            &snap,
            &json!(1),
            "read_demo_file",
            Some(&json!({"name": "hello.txt"})),
            &json!({"name": "read_demo_file", "arguments": {"name": "hello.txt"}}),
            None,
            true,
        )
        .await;
        let body = to_bytes(resp.unwrap().into_body(), 64 * 1024)
            .await
            .unwrap();
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["error"]["code"], -32602, "{v}");
        assert_ne!(v["error"]["code"], -32033);
        let detail = v["error"]["data"]["detail"].as_str().unwrap_or("");
        assert!(
            detail.contains("arguments.vauban.story"),
            "MissingStory must name arguments.vauban: {v}"
        );
        let g = state.inner.lock().unwrap();
        assert!(
            !g.sessions.get("s-done-story").unwrap().terminated,
            "MissingStory must not IAM-cut the session"
        );
    }

    #[tokio::test]
    async fn gwt_after_done_new_seal_replaces() {
        let state = test_state();
        let mut sess = base_session("s-replace");
        sess.allowed_tools = Some(vec!["read_demo_file".into()]);
        sess.tool_constraints.insert(
            "read_demo_file".into(),
            ToolConstraint {
                input_schema: json!({}),
                forbidden_keys: vec![],
                hitl: true,
                require_plan: true,
                status: None,
                schema_fingerprint: None,
            },
        );
        sess.mandate = Some(complete_one_step_read("s-replace"));
        insert_session(&state, sess.clone_snapshot());
        let snap = {
            let g = state.inner.lock().unwrap();
            g.sessions.get("s-replace").unwrap().clone_snapshot()
        };
        let params = json!({
            "name": "read_demo_file",
            "arguments": {
                "name": "hello.txt",
                "vauban": {
                    "story": {
                        "summary": "Read the lab hello file a second time.",
                        "context": "Local MCP lab asset after the first mission finished.",
                        "objective": "Prove a new Story plus Contract replaces the old seal.",
                        "risks": "A hostile Story must not expand the new Contract perimeter."
                    },
                    "contract": {
                        "approval": "mission",
                        "edges": [],
                        "steps": [{
                            "step_id": "1",
                            "intent": "Read the sealed lab hello file",
                            "operation": "read_demo_file",
                            "mode": "literal",
                            "arguments": { "name": "hello.txt" }
                        }]
                    }
                }
            }
        });
        let args = mandate::strip_vauban_args(&params["arguments"]);
        let resp = handle_hitl_tools_call(
            &state,
            &snap,
            &json!(2),
            "read_demo_file",
            Some(&args),
            &params,
            None,
            true,
        )
        .await;
        let body = to_bytes(resp.unwrap().into_body(), 64 * 1024)
            .await
            .unwrap();
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            v["error"]["code"], -32030,
            "completed mandate + new Story/Contract must queue a new HITL: {v}"
        );
    }

    #[tokio::test]
    async fn gwt_after_done_secret_seal_is_hitl_not_drift() {
        let state = test_state();
        let mut sess = base_session("s-replace-secret");
        sess.allowed_tools = Some(vec!["read_demo_file".into()]);
        sess.tool_constraints.insert(
            "read_demo_file".into(),
            ToolConstraint {
                input_schema: json!({}),
                forbidden_keys: vec![],
                hitl: true,
                require_plan: true,
                status: None,
                schema_fingerprint: None,
            },
        );
        sess.mandate = Some(complete_one_step_read("s-replace-secret"));
        insert_session(&state, sess.clone_snapshot());
        let snap = {
            let g = state.inner.lock().unwrap();
            g.sessions.get("s-replace-secret").unwrap().clone_snapshot()
        };
        let params = json!({
            "name": "read_demo_file",
            "arguments": {
                "name": "secret.txt",
                "vauban": {
                    "story": {
                        "summary": "Read the lab secret file after hello.",
                        "context": "Local MCP lab after all_steps_done of hello.txt.",
                        "objective": "Prove a new secret Seal is HITL Replace, not -32033.",
                        "risks": "CheckStep against the finished hello contract is IAM."
                    },
                    "contract": {
                        "approval": "mission",
                        "edges": [],
                        "steps": [{
                            "step_id": "1",
                            "intent": "Read the sealed lab secret file now",
                            "operation": "read_demo_file",
                            "mode": "literal",
                            "arguments": { "name": "secret.txt" }
                        }]
                    }
                }
            }
        });
        let args = mandate::strip_vauban_args(&params["arguments"]);
        let resp = handle_hitl_tools_call(
            &state,
            &snap,
            &json!(3),
            "read_demo_file",
            Some(&args),
            &params,
            None,
            true,
        )
        .await;
        let body = to_bytes(resp.unwrap().into_body(), 64 * 1024)
            .await
            .unwrap();
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            v["error"]["code"], -32030,
            "hello done + secret Story/Contract must be new HITL, not drift: {v}"
        );
        assert_ne!(v["error"]["code"], -32033);
        let g = state.inner.lock().unwrap();
        assert!(
            !g.sessions.get("s-replace-secret").unwrap().terminated,
            "Replace must not IAM-cut the session"
        );
    }

    #[test]
    fn gwt_missing_story_names_arguments_vauban() {
        let src = include_str!("main.rs");
        assert!(
            src.contains("arguments.vauban.story") && src.contains("pep_mandate_active"),
            "MissingStory and post-mission PEP must use arguments.vauban / pep_mandate_active"
        );
    }

    #[test]
    fn gwt_supervised_boot_refuses_without_access_or_lease() {
        let src = include_str!("main.rs");
        assert!(
            src.contains("AccessGuard required under supervisor (refusing to start)")
                && src.contains("recording FD lease required under supervisor"),
            "supervised MCP must fail-closed like SSH when AccessGuard or recording lease is missing"
        );
    }

    fn direct_ingress() -> Extension<McpIngress> {
        Extension(McpIngress::Direct {
            client_ip: "203.0.113.4".into(),
        })
    }

    fn bearer_headers(token: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        h
    }

    async fn mcp_tools_call(
        state: &GatewayState,
        token: &str,
        name: &str,
        arguments: Value,
    ) -> Value {
        let resp = handle_mcp(
            State(state.clone()),
            bearer_headers(token),
            Some(direct_ingress()),
            Json(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": { "name": name, "arguments": arguments }
            })),
        )
        .await;
        let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    fn session_with_token(id: &str, token: &str) -> Session {
        let mut sess = base_session(id);
        sess.vbw_hash = GatewayState::vbw_hash(token);
        sess
    }

    #[tokio::test]
    async fn gwt_handle_mcp_contract_step_falls_through_to_upstream() {
        let state = test_state();
        let token = "vbw_step_ok";
        let mut sess = session_with_token("s-http-allow", token);
        sess.allowed_tools = Some(vec!["read_demo_file".into()]);
        sess.mandate = Some(
            mandate::seal_mandate(
                "m-allow",
                "s-http-allow",
                "asset-1",
                &one_step_read_contract(),
                unix_now(),
            )
            .unwrap(),
        );
        insert_session(&state, sess);
        let v = mcp_tools_call(
            &state,
            token,
            "read_demo_file",
            json!({"name": "hello.txt"}),
        )
        .await;
        assert_ne!(v["error"]["code"], -32033, "{v}");
        assert_eq!(
            v["error"]["code"], -32010,
            "CheckStep allow then no FD: {v}"
        );
    }

    #[tokio::test]
    async fn gwt_handle_mcp_echo_after_done_skips_checkstep() {
        let state = test_state();
        let token = "vbw_done_echo";
        let mut sess = session_with_token("s-http-done", token);
        sess.allowed_tools = Some(vec!["echo".into(), "read_demo_file".into()]);
        sess.mandate = Some(complete_one_step_read("s-http-done"));
        insert_session(&state, sess);
        let v = mcp_tools_call(&state, token, "echo", json!({"message": "hi"})).await;
        assert_ne!(v["error"]["code"], -32033, "{v}");
        assert_eq!(
            v["error"]["code"], -32010,
            "no upstream FD after gate skip: {v}"
        );
    }

    #[tokio::test]
    async fn gwt_handle_mcp_echo_during_mission_is_drift() {
        let state = test_state();
        let token = "vbw_mid_echo";
        let mut sess = session_with_token("s-http-mid", token);
        sess.allowed_tools = Some(vec!["echo".into(), "read_demo_file".into()]);
        sess.mandate = Some(
            mandate::seal_mandate(
                "m-http",
                "s-http-mid",
                "asset-1",
                &one_step_read_contract(),
                unix_now(),
            )
            .unwrap(),
        );
        insert_session(&state, sess);
        let v = mcp_tools_call(&state, token, "echo", json!({"message": "hi"})).await;
        assert_eq!(v["error"]["code"], -32033, "{v}");
    }

    #[tokio::test]
    async fn gwt_handle_mcp_hitl_after_done_is_oneshot_not_drift() {
        let state = test_state();
        let token = "vbw_hitl_done";
        let mut sess = session_with_token("s-http-hitl", token);
        sess.allowed_tools = Some(vec!["hitl_demo".into(), "read_demo_file".into()]);
        sess.tool_constraints.insert(
            "hitl_demo".into(),
            ToolConstraint {
                input_schema: json!({}),
                forbidden_keys: vec![],
                hitl: true,
                require_plan: false,
                status: None,
                schema_fingerprint: None,
            },
        );
        sess.mandate = Some(complete_one_step_read("s-http-hitl"));
        insert_session(&state, sess);
        let v = mcp_tools_call(&state, token, "hitl_demo", json!({})).await;
        assert_eq!(v["error"]["code"], -32030, "{v}");
        assert!(
            !state.inner.lock().unwrap().sessions["s-http-hitl"].terminated,
            "HITL after done must not IAM-cut"
        );
    }

    #[tokio::test]
    async fn gwt_pdp_check_without_guard_is_local() {
        let state = test_state();
        let sess = base_session("s-pdp-noguard");
        insert_session(&state, sess.clone_snapshot());
        match pdp_check_via_access(
            &state,
            &sess,
            &json!(1),
            "echo",
            Some(&json!({})),
            &json!({}),
            false,
            unix_now(),
        )
        .await
        {
            PdpGate::ContinueLocal => {}
            PdpGate::AllowUpstream | PdpGate::Stop(_) => {
                panic!("expected ContinueLocal without AccessGuard")
            }
        }
    }

    #[tokio::test]
    async fn gwt_finalize_mandate_commit_and_rollback() {
        let state = test_state();
        let mut sess = base_session("s-fin");
        let mut m = mandate::seal_mandate(
            "m-fin",
            "s-fin",
            "asset-1",
            &one_step_read_contract(),
            unix_now(),
        )
        .unwrap();
        let args = json!({"name": "hello.txt"});
        match mandate::check_step(&mut m, "read_demo_file", Some(&args)) {
            mandate::CheckStepOutcome::Allow {
                step_id,
                call_digest,
            } => {
                sess.mandate = Some(m.clone());
                insert_session(&state, sess);
                finalize_mandate_upstream(&state, "s-fin", &json!({"ok": true}), true).await;
                {
                    let g = state.inner.lock().unwrap();
                    let live = g.sessions["s-fin"].mandate.as_ref().unwrap();
                    assert!(
                        live.results
                            .contains_key(&(step_id.clone(), call_digest.clone()))
                    );
                    assert!(mandate::all_steps_done(live));
                }
                let mut m2 = mandate::seal_mandate(
                    "m-fin2",
                    "s-fin2",
                    "asset-1",
                    &one_step_read_contract(),
                    unix_now(),
                )
                .unwrap();
                let _ = mandate::check_step(&mut m2, "read_demo_file", Some(&args));
                let mut sess2 = base_session("s-fin2");
                sess2.mandate = Some(m2);
                insert_session(&state, sess2);
                finalize_mandate_upstream(&state, "s-fin2", &json!({"ok": false}), false).await;
                let g = state.inner.lock().unwrap();
                let live = g.sessions["s-fin2"].mandate.as_ref().unwrap();
                assert!(live.inflight.is_none());
                assert!(!live.steps[0].consumed);
            }
            other => panic!("{other:?}"),
        }
        finalize_mandate_upstream(&state, "missing", &json!({}), true).await;
        let mut bare = base_session("s-fin-bare");
        bare.mandate = None;
        insert_session(&state, bare);
        finalize_mandate_upstream(&state, "s-fin-bare", &json!({}), true).await;
    }

    async fn oneshot_mcp(
        app: &Router,
        uri: &str,
        token: Option<&str>,
        body: &str,
    ) -> (u16, String) {
        use axum::body::Body;
        use tower::ServiceExt;
        let mut builder = axum::http::Request::builder().method("POST").uri(uri);
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        builder = builder.header("content-type", "application/json");
        let mut req = builder.body(Body::from(body.to_string())).unwrap();
        req.extensions_mut().insert(McpIngress::Direct {
            client_ip: "203.0.113.4".into(),
        });
        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status().as_u16();
        let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    /// Hop 2 on the real router, the way the data pipe calls it:
    /// `router.oneshot` with an ingress extension. A forged `vbw_` is
    /// refused and the lab control paths are not mounted.
    #[tokio::test]
    async fn e2e_post_mcp_relays_on_brokered_fd_lab_routes_absent() {
        let state = test_state();
        let token = "vbw_e2e_relay";
        let mut sess = session_with_token("s-e2e-relay", token);
        sess.allowed_tools = Some(vec!["echo".into()]);
        let peer =
            http_peer(r#"{"jsonrpc":"2.0","id":7,"result":{"tools":[{"name":"echo"}]}}"#).await;
        sess.upstream_stream = Some(wrap_plain(peer));
        sess.upstream_url = Some("http://127.0.0.1/mcp".into());
        insert_session(&state, sess);

        let app = build_router(state);
        let (health, _) = oneshot_mcp(&app, "/health", None, "").await;
        assert_eq!(health, 404, "POST /health must not exist on the leaf");
        let (session_status, _) = oneshot_mcp(&app, "/session", None, "{}").await;
        assert_eq!(session_status, 404, "lab /session must not exist");

        let forged = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#;
        let (forged_status, forged_body) =
            oneshot_mcp(&app, "/mcp", Some("vbw_forged"), forged).await;
        assert_eq!(forged_status, 401, "{forged_body}");

        let good = r#"{"jsonrpc":"2.0","id":7,"method":"tools/list","params":{}}"#;
        let (ok_status, ok_body) = oneshot_mcp(&app, "/mcp", Some(token), good).await;
        assert_eq!(ok_status, 200, "{ok_body}");
        assert!(ok_body.contains("echo"), "relayed tools/list: {ok_body}");
        assert!(
            !ok_body.contains("-32010"),
            "brokered FD must be used, got {ok_body}"
        );
    }
}
