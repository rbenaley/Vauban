//! IPC client for communication with vauban-access.
//!
//! Provides async methods to check access permissions via IPC pipes
//! to the Access service (Casbin enforcer).
//!
//! Transport/correlation is owned by [`CorrelatedIpcCore`] (no timeout —
//! INV-CORR-5).

use crate::error::{AppError, AppResult};
use crate::ipc::correlated::{CorrelatedIpcCore, deliver_or_warn};
use shared::messages::{
    AccessCheckResult, AccessCheckResultEntry, AccessRequest as AccessReq,
    AccessResponse as AccessResp, AccessRuleData, AccessRuleInfo, AccessibleGroupEntry,
    AccessibleSecretGroupEntry, ApprovalDecisionKind, ApprovalDenyReason, AssetGroupInfo,
    EwsDecisionKind, EwsDenyReason, GroupOption, IpcPage, IpcPageParams, Message, RbacResult,
    SecretAccessRuleData, SecretAccessRuleInfo, SecretGroupInfo, SessionAccessDecision,
    SessionAccessIntent, VaubanGroupInfo,
};
use std::collections::HashMap;
use std::io;
use std::os::unix::io::RawFd;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use tokio::sync::oneshot;
use tracing::{debug, warn};

/// Successful session-token mint from vauban-access, including the
/// access-rule constraint bits that previously required a separate
/// `CheckAccessMulti` round-trip on the SSH/RDP connect path
/// (policy eval 3→2).
#[derive(Debug, Clone)]
pub struct IssuedSessionToken {
    pub token: Vec<u8>,
    pub require_mfa: bool,
    pub require_approval: bool,
    pub max_session_duration: Option<i32>,
}

/// Async IPC client for vauban-access authorization checks.
pub struct AccessIpcClient {
    core: CorrelatedIpcCore,
    pending_requests: StdMutex<HashMap<u64, oneshot::Sender<RbacResult>>>,
    pending_access_requests: StdMutex<HashMap<u64, oneshot::Sender<AccessResp>>>,
}

impl AccessIpcClient {
    /// Create a new Access IPC client.
    ///
    /// The file descriptors are passed by the supervisor via topology pipes.
    pub fn new(read_fd: RawFd, write_fd: RawFd) -> io::Result<Arc<Self>> {
        Ok(Arc::new(Self {
            core: CorrelatedIpcCore::from_fds(read_fd, write_fd)?,
            pending_requests: StdMutex::new(HashMap::new()),
            pending_access_requests: StdMutex::new(HashMap::new()),
        }))
    }

    async fn call_rbac(&self, msg: Message, request_id: u64) -> AppResult<RbacResult> {
        self.core
            .request(&self.pending_requests, request_id, &msg, None)
            .await
            .map_err(|e| e.into_app_ipc())
    }

    async fn call_access(&self, msg: Message, request_id: u64) -> AppResult<AccessResp> {
        self.core
            .request(&self.pending_access_requests, request_id, &msg, None)
            .await
            .map_err(|e| e.into_app_ipc())
    }

    /// Check if a subject has permission to perform an action on a resource.
    ///
    /// Fail-closed: returns false on IPC errors.
    pub async fn check_permission(
        &self,
        subject: &str,
        resource: &str,
        action: &str,
    ) -> AppResult<bool> {
        let request_id = self.core.alloc_id();
        let msg = Message::RbacCheck {
            request_id,
            subject: subject.to_string(),
            object: resource.to_string(),
            action: action.to_string(),
        };

        debug!(
            request_id,
            subject, resource, action, "RbacCheck request sent"
        );

        let result = self.call_rbac(msg, request_id).await?;
        Ok(result.allowed)
    }

    async fn send_access_request(&self, request: AccessReq) -> AppResult<AccessResp> {
        let request_id = self.core.alloc_id();
        let msg = Message::AccessRequest {
            request_id,
            request,
        };
        self.call_access(msg, request_id).await
    }

    /// Drain all pages from a paginated IPC list endpoint into a single Vec.
    async fn drain_pages<T>(
        &self,
        mut make_request: impl FnMut(u32) -> AccessReq,
        extract_page: impl Fn(AccessResp) -> Result<IpcPage<T>, AppError>,
    ) -> AppResult<Vec<T>> {
        const MAX_DRAIN_ITEMS: usize = 50_000;
        let mut all = Vec::new();
        let mut offset = 0u32;
        loop {
            let resp = self.send_access_request(make_request(offset)).await?;
            let page = extract_page(resp)?;
            let n = page.items.len() as u32;
            all.extend(page.items);
            if !page.has_more || n == 0 {
                break;
            }
            if all.len() > MAX_DRAIN_ITEMS {
                return Err(AppError::Ipc(format!(
                    "IPC pagination drained {} items, exceeding safety limit {MAX_DRAIN_ITEMS}",
                    all.len()
                )));
            }
            offset = offset.saturating_add(n);
        }
        Ok(all)
    }

    // === Evaluation ===

    pub async fn check_access(
        &self,
        user_id: i32,
        asset_group_id: i32,
        protocol: &str,
    ) -> AppResult<AccessCheckResult> {
        let resp = self
            .send_access_request(AccessReq::CheckAccess {
                user_id,
                asset_group_id,
                protocol: protocol.to_string(),
            })
            .await?;
        match resp {
            AccessResp::AccessChecked(result) => Ok(result),
            AccessResp::Error(e) => Err(AppError::Ipc(e)),
            _ => Err(AppError::Ipc(
                "unexpected response for CheckAccess".to_string(),
            )),
        }
    }

    /// SECURITY: instance-level authorization for an existing
    /// `proxy_sessions` row. Combines existence + status, ownership,
    /// and access-rule re-check in a single round-trip. The Casbin
    /// `sessions:supervise` / `sessions:write` OR-overrides are
    /// layered on top by `services::session_access::verify`, NEVER
    /// here -- this method is intentionally low-level so the service
    /// remains the single seam where instance-level + functional
    /// authorization combine.
    ///
    /// Fail-closed: any IPC or unexpected response is collapsed to a
    /// `Denied(NotFound)` decision so a transient infrastructure issue
    /// cannot accidentally grant a session. The caller-side service
    /// further collapses every denial reason into a 404 (anti-
    /// enumeration) or 410 (`Gone`).
    pub async fn verify_session_access(
        &self,
        session_uuid: &str,
        requesting_user_uuid: &str,
        intent: SessionAccessIntent,
    ) -> AppResult<SessionAccessDecision> {
        let resp = self
            .send_access_request(AccessReq::VerifySessionAccess {
                session_uuid: session_uuid.to_string(),
                requesting_user_uuid: requesting_user_uuid.to_string(),
                intent,
            })
            .await?;
        match resp {
            AccessResp::SessionAccessChecked { decision } => Ok(decision),
            AccessResp::Error(e) => Err(AppError::Ipc(e)),
            _ => Err(AppError::Ipc(
                "unexpected response for VerifySessionAccess".to_string(),
            )),
        }
    }

    /// Request a cryptographic session token from vauban-access for a
    /// pending session-open. Used by the SSH/RDP/TCP-broker flows so
    /// that vauban-supervisor and the proxies can re-verify the
    /// authorization decision without having to trust vauban-web's
    /// in-memory state. See `docs/technical/Vauban_AccessGuard_Architecture_EN(1.0).md` §3.
    ///
    /// On success the reply also carries MFA / JIT / max-duration
    /// constraints from the mint-time `CheckAccessByUuid`, so connect
    /// handlers can branch without a preceding `can_access_asset` IPC.
    ///
    /// Fail-closed: returns `Err(AppError::Authorization)` for any
    /// non-`SessionTokenIssued` reply (denied, IPC error, malformed
    /// response). Callers MUST surface the same generic
    /// "Access denied" message to the user regardless of the cause --
    /// distinguishing "policy denied" from "minter is broken" would
    /// let a probe fingerprint the bastion.
    pub async fn issue_session_token(
        &self,
        params: shared::session_token::SessionTokenParams,
    ) -> AppResult<IssuedSessionToken> {
        let resp = self
            .send_access_request(AccessReq::IssueSessionToken {
                user_uuid: params.user_uuid,
                asset_uuid: params.asset_uuid,
                protocol: params.protocol,
                host: params.host,
                port: params.port,
                target_service: params.target_service,
                session_id: params.session_id,
            })
            .await?;
        match resp {
            AccessResp::SessionTokenIssued {
                token,
                require_mfa,
                require_approval,
                max_session_duration,
            } => Ok(IssuedSessionToken {
                token,
                require_mfa,
                require_approval,
                max_session_duration,
            }),
            AccessResp::SessionTokenDenied => {
                Err(AppError::Authorization("Access denied".to_string()))
            }
            AccessResp::Error(e) => Err(AppError::Ipc(e)),
            _ => Err(AppError::Ipc(
                "unexpected response for IssueSessionToken".to_string(),
            )),
        }
    }

    /// Request a session-token-shaped credential for a strictly
    /// READ-ONLY diagnostic operation that does not open an upstream
    /// SSH session (today: SSH host-key verify and admin host-key
    /// fetch). The returned token is wire-compatible with one minted
    /// by [`Self::issue_session_token`] and is accepted by the
    /// supervisor's TCP broker and the proxy's session-token gate
    /// without code changes.
    ///
    /// Authorisation contract: vauban-access gates ONLY on
    /// `caller_has_assets_manage = true` -- the access-rule re-check
    /// performed by `IssueSessionToken` is intentionally skipped. A
    /// non-`assets:manage` caller (or any serialization failure)
    /// collapses to `AccessResponse::SessionTokenDenied`, surfaced as
    /// `Err(AppError::Authorization("Access denied"))` so the wire
    /// reply is indistinguishable from a session-token denial.
    ///
    /// Pre-issue #34 the host-key paths used `IssueSessionToken`,
    /// which silently denied admins without an explicit access rule
    /// for the asset; the verify endpoint then fell back to a green
    /// "Verified" fragment that hid the missing live verification.
    /// Routing those callers through this verb closes the regression.
    pub async fn issue_diagnostic_token(
        &self,
        params: shared::session_token::SessionTokenParams,
        caller_has_assets_manage: bool,
    ) -> AppResult<Vec<u8>> {
        let resp = self
            .send_access_request(AccessReq::IssueDiagnosticToken {
                user_uuid: params.user_uuid,
                asset_uuid: params.asset_uuid,
                protocol: params.protocol,
                host: params.host,
                port: params.port,
                target_service: params.target_service,
                session_id: params.session_id,
                caller_has_assets_manage,
            })
            .await?;
        match resp {
            AccessResp::SessionTokenIssued { token, .. } => Ok(token),
            AccessResp::SessionTokenDenied => {
                Err(AppError::Authorization("Access denied".to_string()))
            }
            AccessResp::Error(e) => Err(AppError::Ipc(e)),
            _ => Err(AppError::Ipc(
                "unexpected response for IssueDiagnosticToken".to_string(),
            )),
        }
    }

    pub async fn check_access_multi(
        &self,
        user_id: i32,
        asset_group_ids: &[i32],
        protocol: &str,
    ) -> AppResult<Vec<AccessCheckResultEntry>> {
        let resp = self
            .send_access_request(AccessReq::CheckAccessMulti {
                user_id,
                asset_group_ids: asset_group_ids.to_vec(),
                protocol: protocol.to_string(),
            })
            .await?;
        match resp {
            AccessResp::AccessCheckedMulti(entries) => Ok(entries),
            AccessResp::Error(e) => Err(AppError::Ipc(e)),
            _ => Err(AppError::Ipc(
                "unexpected response for CheckAccessMulti".into(),
            )),
        }
    }

    /// Re-runs the same RBAC policy check that the proxy-side
    /// [`shared::access_guard::AccessGuard`] runs at session-open
    /// time, by sending [`AccessReq::CheckAccessByUuid`] over IPC.
    ///
    /// SECURITY: this is the same IPC payload AccessGuard sends, so
    /// any decision returned here is identical to what the proxy
    /// would obtain. Used by tests to assert parity, and available
    /// to other callers that need a UUID-keyed verdict without
    /// going through the full AccessGuard demultiplexer.
    pub async fn check_access_by_uuid(
        &self,
        user_uuid: &str,
        asset_uuid: &str,
        protocol: &str,
    ) -> AppResult<AccessCheckResult> {
        let resp = self
            .send_access_request(AccessReq::CheckAccessByUuid {
                user_uuid: user_uuid.to_string(),
                asset_uuid: asset_uuid.to_string(),
                protocol: protocol.to_string(),
            })
            .await?;
        match resp {
            AccessResp::AccessChecked(result) => Ok(result),
            AccessResp::Error(e) => Err(AppError::Ipc(e)),
            _ => Err(AppError::Ipc(
                "unexpected response for CheckAccessByUuid".into(),
            )),
        }
    }

    /// Read-only pre-flight: ask vauban-access whether `actor_user_uuid`
    /// is allowed to decide on the pending request `session_uuid`.
    ///
    /// Advisory only -- the authoritative re-check happens inside
    /// [`Self::record_approval_decision`]'s transaction.
    pub async fn check_approval_eligibility(
        &self,
        actor_user_uuid: &str,
        session_uuid: &str,
    ) -> AppResult<(bool, Option<ApprovalDenyReason>)> {
        let resp = self
            .send_access_request(AccessReq::CheckApprovalEligibility {
                actor_user_uuid: actor_user_uuid.to_string(),
                session_uuid: session_uuid.to_string(),
            })
            .await?;
        match resp {
            AccessResp::ApprovalEligibility { allowed, reason } => Ok((allowed, reason)),
            AccessResp::Error(e) => Err(AppError::Ipc(e)),
            _ => Err(AppError::Ipc(
                "unexpected response for CheckApprovalEligibility".into(),
            )),
        }
    }

    /// Atomically persist a JIT approval/rejection decision and the
    /// matching append-only audit row in vauban-access. Returns the
    /// `audit_log_id` on success, or the structured deny reason when
    /// the in-transaction re-check refused.
    ///
    /// `decision_ip` MUST already be the trusted-proxy-resolved client
    /// IP (see `crate::middleware::resolve_client_ip`). Forwarding raw
    /// `peer_addr` from the socket would let a request from behind a
    /// reverse proxy spoof its origin in the audit trail.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_approval_decision(
        &self,
        actor_user_uuid: &str,
        session_uuid: &str,
        decision: ApprovalDecisionKind,
        duration_override_seconds: Option<i32>,
        decision_reason: Option<String>,
        decision_ip: Option<String>,
        decision_user_agent: Option<String>,
        request_id: Option<String>,
    ) -> AppResult<Result<i64, ApprovalDenyReason>> {
        let resp = self
            .send_access_request(AccessReq::RecordApprovalDecision {
                actor_user_uuid: actor_user_uuid.to_string(),
                session_uuid: session_uuid.to_string(),
                decision,
                duration_override_seconds,
                decision_reason,
                decision_ip,
                decision_user_agent,
                request_id,
            })
            .await?;
        match resp {
            AccessResp::ApprovalRecorded { audit_log_id } => Ok(Ok(audit_log_id)),
            AccessResp::ApprovalDenied { reason } => Ok(Err(reason)),
            AccessResp::Error(e) => Err(AppError::Ipc(e)),
            _ => Err(AppError::Ipc(
                "unexpected response for RecordApprovalDecision".into(),
            )),
        }
    }

    // ===================================================================
    // IACS / EWS onboarding -- thin IPC wrappers calling the atomic
    // handlers in `vauban-access::iacs`. Every wrapper returns
    // `AppResult<Result<<success>, EwsDenyReason>>` so the handler can
    // pattern-match on (a) IPC errors and (b) structured business
    // denials separately.
    //
    // `actor_ip` MUST come from `middleware::resolve_client_ip` -- raw
    // peer_addr behind a reverse proxy would log a spoofable IP in the
    // audit trail.
    // ===================================================================

    /// Submit a new EWS onboarding request.
    #[allow(clippy::too_many_arguments)]
    pub async fn submit_ews_onboarding(
        &self,
        actor_user_uuid: &str,
        name: String,
        public_key: String,
        public_key_fingerprint: String,
        key_algo: String,
        justification: String,
        max_ews_per_user: u32,
        actor_ip: Option<String>,
    ) -> AppResult<Result<(String, i64), EwsDenyReason>> {
        let resp = self
            .send_access_request(AccessReq::SubmitEwsOnboarding {
                actor_user_uuid: actor_user_uuid.to_string(),
                name,
                public_key,
                public_key_fingerprint,
                key_algo,
                justification,
                max_ews_per_user,
                actor_ip,
            })
            .await?;
        match resp {
            AccessResp::EwsRequestSubmitted {
                request_uuid,
                audit_log_id,
            } => Ok(Ok((request_uuid, audit_log_id))),
            AccessResp::EwsDecisionDenied { reason } => Ok(Err(reason)),
            AccessResp::Error(e) => Err(AppError::Ipc(e)),
            _ => Err(AppError::Ipc(
                "unexpected response for SubmitEwsOnboarding".into(),
            )),
        }
    }

    /// Edit a pending EWS request.
    #[allow(clippy::too_many_arguments)]
    pub async fn edit_ews_request(
        &self,
        actor_user_uuid: &str,
        request_uuid: &str,
        name: String,
        public_key: String,
        public_key_fingerprint: String,
        key_algo: String,
        justification: String,
        actor_ip: Option<String>,
    ) -> AppResult<Result<i64, EwsDenyReason>> {
        let resp = self
            .send_access_request(AccessReq::EditEwsRequest {
                actor_user_uuid: actor_user_uuid.to_string(),
                request_uuid: request_uuid.to_string(),
                name,
                public_key,
                public_key_fingerprint,
                key_algo,
                justification,
                actor_ip,
            })
            .await?;
        match resp {
            AccessResp::EwsRequestEdited { audit_log_id } => Ok(Ok(audit_log_id)),
            AccessResp::EwsDecisionDenied { reason } => Ok(Err(reason)),
            AccessResp::Error(e) => Err(AppError::Ipc(e)),
            _ => Err(AppError::Ipc(
                "unexpected response for EditEwsRequest".into(),
            )),
        }
    }

    /// Cancel a pending EWS request.
    pub async fn cancel_ews_request(
        &self,
        actor_user_uuid: &str,
        request_uuid: &str,
        actor_ip: Option<String>,
    ) -> AppResult<Result<i64, EwsDenyReason>> {
        let resp = self
            .send_access_request(AccessReq::CancelEwsRequest {
                actor_user_uuid: actor_user_uuid.to_string(),
                request_uuid: request_uuid.to_string(),
                actor_ip,
            })
            .await?;
        match resp {
            AccessResp::EwsRequestCancelled { audit_log_id } => Ok(Ok(audit_log_id)),
            AccessResp::EwsDecisionDenied { reason } => Ok(Err(reason)),
            AccessResp::Error(e) => Err(AppError::Ipc(e)),
            _ => Err(AppError::Ipc(
                "unexpected response for CancelEwsRequest".into(),
            )),
        }
    }

    /// Approve / reject an EWS onboarding request. On approve the
    /// `Ok` payload carries the freshly created `ews.uuid`.
    pub async fn record_ews_decision(
        &self,
        actor_user_uuid: &str,
        request_uuid: &str,
        decision: EwsDecisionKind,
        decision_reason: Option<String>,
        actor_ip: Option<String>,
    ) -> AppResult<Result<(i64, Option<String>), EwsDenyReason>> {
        let resp = self
            .send_access_request(AccessReq::RecordEwsDecision {
                actor_user_uuid: actor_user_uuid.to_string(),
                request_uuid: request_uuid.to_string(),
                decision,
                decision_reason,
                actor_ip,
            })
            .await?;
        match resp {
            AccessResp::EwsDecisionRecorded {
                audit_log_id,
                ews_uuid,
            } => Ok(Ok((audit_log_id, ews_uuid))),
            AccessResp::EwsDecisionDenied { reason } => Ok(Err(reason)),
            AccessResp::Error(e) => Err(AppError::Ipc(e)),
            _ => Err(AppError::Ipc(
                "unexpected response for RecordEwsDecision".into(),
            )),
        }
    }

    /// Disable an active EWS (reversible).
    pub async fn disable_ews(
        &self,
        actor_user_uuid: &str,
        ews_uuid: &str,
        actor_ip: Option<String>,
    ) -> AppResult<Result<i64, EwsDenyReason>> {
        let resp = self
            .send_access_request(AccessReq::DisableEws {
                actor_user_uuid: actor_user_uuid.to_string(),
                ews_uuid: ews_uuid.to_string(),
                actor_ip,
            })
            .await?;
        match resp {
            AccessResp::EwsStateChanged { audit_log_id } => Ok(Ok(audit_log_id)),
            AccessResp::EwsDecisionDenied { reason } => Ok(Err(reason)),
            AccessResp::Error(e) => Err(AppError::Ipc(e)),
            _ => Err(AppError::Ipc("unexpected response for DisableEws".into())),
        }
    }

    /// Re-enable a disabled EWS.
    pub async fn enable_ews(
        &self,
        actor_user_uuid: &str,
        ews_uuid: &str,
        actor_ip: Option<String>,
    ) -> AppResult<Result<i64, EwsDenyReason>> {
        let resp = self
            .send_access_request(AccessReq::EnableEws {
                actor_user_uuid: actor_user_uuid.to_string(),
                ews_uuid: ews_uuid.to_string(),
                actor_ip,
            })
            .await?;
        match resp {
            AccessResp::EwsStateChanged { audit_log_id } => Ok(Ok(audit_log_id)),
            AccessResp::EwsDecisionDenied { reason } => Ok(Err(reason)),
            AccessResp::Error(e) => Err(AppError::Ipc(e)),
            _ => Err(AppError::Ipc("unexpected response for EnableEws".into())),
        }
    }

    /// Offboard an EWS (irreversible). `on_behalf_of_self == true`
    /// is the auto-offboard path (gated on `iacs_request`); `false`
    /// is the admin offboard path (gated on `iacs_manage`).
    pub async fn offboard_ews(
        &self,
        actor_user_uuid: &str,
        ews_uuid: &str,
        on_behalf_of_self: bool,
        decision_reason: Option<String>,
        actor_ip: Option<String>,
    ) -> AppResult<Result<i64, EwsDenyReason>> {
        let resp = self
            .send_access_request(AccessReq::OffboardEws {
                actor_user_uuid: actor_user_uuid.to_string(),
                ews_uuid: ews_uuid.to_string(),
                on_behalf_of_self,
                decision_reason,
                actor_ip,
            })
            .await?;
        match resp {
            AccessResp::EwsStateChanged { audit_log_id } => Ok(Ok(audit_log_id)),
            AccessResp::EwsDecisionDenied { reason } => Ok(Err(reason)),
            AccessResp::Error(e) => Err(AppError::Ipc(e)),
            _ => Err(AppError::Ipc("unexpected response for OffboardEws".into())),
        }
    }

    pub async fn list_accessible_groups(
        &self,
        user_id: i32,
    ) -> AppResult<Vec<AccessibleGroupEntry>> {
        self.drain_pages(
            |offset| AccessReq::ListAccessibleGroups {
                user_id,
                page: ipc_page(offset),
            },
            |resp| match resp {
                AccessResp::AccessibleGroupsPage(p) => Ok(p),
                AccessResp::Error(e) => Err(AppError::Ipc(e)),
                _ => Err(AppError::Ipc("unexpected response".into())),
            },
        )
        .await
    }

    // === Access Rules CRUD ===

    pub async fn create_access_rule(
        &self,
        data: AccessRuleData,
        actor_uuid: Option<String>,
    ) -> AppResult<AccessRuleInfo> {
        let resp = self
            .send_access_request(AccessReq::CreateAccessRule { data, actor_uuid })
            .await?;
        match resp {
            AccessResp::AccessRule(Ok(info)) => Ok(info),
            AccessResp::AccessRule(Err(e)) => Err(AppError::Ipc(e)),
            AccessResp::Error(e) => Err(AppError::Ipc(e)),
            _ => Err(AppError::Ipc("unexpected response".to_string())),
        }
    }

    pub async fn get_access_rule(&self, uuid: &str) -> AppResult<AccessRuleInfo> {
        let resp = self
            .send_access_request(AccessReq::GetAccessRule {
                uuid: uuid.to_string(),
            })
            .await?;
        match resp {
            AccessResp::AccessRule(Ok(info)) => Ok(info),
            AccessResp::AccessRule(Err(e)) => Err(AppError::Ipc(e)),
            AccessResp::Error(e) => Err(AppError::Ipc(e)),
            _ => Err(AppError::Ipc("unexpected response".to_string())),
        }
    }

    pub async fn list_access_rules(&self) -> AppResult<Vec<AccessRuleInfo>> {
        self.drain_pages(
            |offset| AccessReq::ListAccessRules {
                page: ipc_page(offset),
            },
            |resp| match resp {
                AccessResp::AccessRulePage(p) => Ok(p),
                AccessResp::Error(e) => Err(AppError::Ipc(e)),
                _ => Err(AppError::Ipc("unexpected response".into())),
            },
        )
        .await
    }

    pub async fn update_access_rule(
        &self,
        uuid: &str,
        data: AccessRuleData,
        actor_uuid: Option<String>,
    ) -> AppResult<AccessRuleInfo> {
        let resp = self
            .send_access_request(AccessReq::UpdateAccessRule {
                uuid: uuid.to_string(),
                data,
                actor_uuid,
            })
            .await?;
        match resp {
            AccessResp::AccessRule(Ok(info)) => Ok(info),
            AccessResp::AccessRule(Err(e)) => Err(AppError::Ipc(e)),
            AccessResp::Error(e) => Err(AppError::Ipc(e)),
            _ => Err(AppError::Ipc("unexpected response".to_string())),
        }
    }

    pub async fn delete_access_rule(&self, uuid: &str) -> AppResult<()> {
        let resp = self
            .send_access_request(AccessReq::DeleteAccessRule {
                uuid: uuid.to_string(),
            })
            .await?;
        match resp {
            AccessResp::Deleted(Ok(())) => Ok(()),
            AccessResp::Deleted(Err(e)) => Err(AppError::Ipc(e)),
            AccessResp::Error(e) => Err(AppError::Ipc(e)),
            _ => Err(AppError::Ipc("unexpected response".to_string())),
        }
    }

    // === Vauban Groups CRUD ===

    pub async fn create_vauban_group(
        &self,
        name: &str,
        description: Option<String>,
    ) -> AppResult<VaubanGroupInfo> {
        let resp = self
            .send_access_request(AccessReq::CreateVaubanGroup {
                name: name.to_string(),
                description,
            })
            .await?;
        match resp {
            AccessResp::VaubanGroup(Ok(info)) => Ok(info),
            AccessResp::VaubanGroup(Err(e)) => Err(AppError::Ipc(e)),
            AccessResp::Error(e) => Err(AppError::Ipc(e)),
            _ => Err(AppError::Ipc("unexpected response".to_string())),
        }
    }

    pub async fn get_vauban_group(&self, uuid: &str) -> AppResult<VaubanGroupInfo> {
        let resp = self
            .send_access_request(AccessReq::GetVaubanGroup {
                uuid: uuid.to_string(),
            })
            .await?;
        match resp {
            AccessResp::VaubanGroup(Ok(info)) => Ok(info),
            AccessResp::VaubanGroup(Err(e)) => Err(AppError::Ipc(e)),
            AccessResp::Error(e) => Err(AppError::Ipc(e)),
            _ => Err(AppError::Ipc("unexpected response".to_string())),
        }
    }

    pub async fn get_vauban_group_by_id(&self, id: i32) -> AppResult<VaubanGroupInfo> {
        let resp = self
            .send_access_request(AccessReq::GetVaubanGroupById { id })
            .await?;
        match resp {
            AccessResp::VaubanGroup(Ok(info)) => Ok(info),
            AccessResp::VaubanGroup(Err(e)) => Err(AppError::Ipc(e)),
            AccessResp::Error(e) => Err(AppError::Ipc(e)),
            _ => Err(AppError::Ipc("unexpected response".to_string())),
        }
    }

    pub async fn list_vauban_groups(&self) -> AppResult<Vec<VaubanGroupInfo>> {
        self.drain_pages(
            |offset| AccessReq::ListVaubanGroups {
                page: ipc_page(offset),
            },
            |resp| match resp {
                AccessResp::VaubanGroupPage(p) => Ok(p),
                AccessResp::Error(e) => Err(AppError::Ipc(e)),
                _ => Err(AppError::Ipc("unexpected response".into())),
            },
        )
        .await
    }

    pub async fn update_vauban_group(
        &self,
        uuid: &str,
        name: &str,
        description: Option<String>,
    ) -> AppResult<VaubanGroupInfo> {
        let resp = self
            .send_access_request(AccessReq::UpdateVaubanGroup {
                uuid: uuid.to_string(),
                name: name.to_string(),
                description,
            })
            .await?;
        match resp {
            AccessResp::VaubanGroup(Ok(info)) => Ok(info),
            AccessResp::VaubanGroup(Err(e)) => Err(AppError::Ipc(e)),
            AccessResp::Error(e) => Err(AppError::Ipc(e)),
            _ => Err(AppError::Ipc("unexpected response".to_string())),
        }
    }

    pub async fn delete_vauban_group(&self, uuid: &str) -> AppResult<()> {
        let resp = self
            .send_access_request(AccessReq::DeleteVaubanGroup {
                uuid: uuid.to_string(),
            })
            .await?;
        match resp {
            AccessResp::Deleted(Ok(())) => Ok(()),
            AccessResp::Deleted(Err(e)) => Err(AppError::Ipc(e)),
            AccessResp::Error(e) => Err(AppError::Ipc(e)),
            _ => Err(AppError::Ipc("unexpected response".to_string())),
        }
    }

    // === Group Membership ===

    pub async fn add_group_member(&self, group_id: i32, user_id: i32) -> AppResult<()> {
        let resp = self
            .send_access_request(AccessReq::AddGroupMember { group_id, user_id })
            .await?;
        match resp {
            AccessResp::Ok => Ok(()),
            AccessResp::Error(e) => Err(AppError::Ipc(e)),
            _ => Err(AppError::Ipc("unexpected response".to_string())),
        }
    }

    pub async fn remove_group_member(&self, group_id: i32, user_id: i32) -> AppResult<()> {
        let resp = self
            .send_access_request(AccessReq::RemoveGroupMember { group_id, user_id })
            .await?;
        match resp {
            AccessResp::Ok => Ok(()),
            AccessResp::Error(e) => Err(AppError::Ipc(e)),
            _ => Err(AppError::Ipc("unexpected response".to_string())),
        }
    }

    pub async fn list_group_members(&self, group_id: i32) -> AppResult<Vec<i32>> {
        self.drain_pages(
            |offset| AccessReq::ListGroupMembers {
                group_id,
                page: ipc_page(offset),
            },
            |resp| match resp {
                AccessResp::MemberListPage(p) => Ok(p),
                AccessResp::Error(e) => Err(AppError::Ipc(e)),
                _ => Err(AppError::Ipc("unexpected response".into())),
            },
        )
        .await
    }

    pub async fn list_user_groups(&self, user_id: i32) -> AppResult<Vec<VaubanGroupInfo>> {
        self.drain_pages(
            |offset| AccessReq::ListUserGroups {
                user_id,
                page: ipc_page(offset),
            },
            |resp| match resp {
                AccessResp::UserGroupPage(p) => Ok(p),
                AccessResp::Error(e) => Err(AppError::Ipc(e)),
                _ => Err(AppError::Ipc("unexpected response".into())),
            },
        )
        .await
    }

    // === Asset Groups CRUD ===

    pub async fn create_asset_group(
        &self,
        name: &str,
        slug: &str,
        description: Option<String>,
        color: &str,
        icon: &str,
        actor_uuid: Option<String>,
    ) -> AppResult<AssetGroupInfo> {
        let resp = self
            .send_access_request(AccessReq::CreateAssetGroup {
                name: name.to_string(),
                slug: slug.to_string(),
                description,
                color: color.to_string(),
                icon: icon.to_string(),
                actor_uuid,
            })
            .await?;
        match resp {
            AccessResp::AssetGroup(Ok(info)) => Ok(info),
            AccessResp::AssetGroup(Err(e)) => Err(AppError::Ipc(e)),
            AccessResp::Error(e) => Err(AppError::Ipc(e)),
            _ => Err(AppError::Ipc("unexpected response".to_string())),
        }
    }

    pub async fn get_asset_group(&self, uuid: &str) -> AppResult<AssetGroupInfo> {
        let resp = self
            .send_access_request(AccessReq::GetAssetGroup {
                uuid: uuid.to_string(),
            })
            .await?;
        match resp {
            AccessResp::AssetGroup(Ok(info)) => Ok(info),
            AccessResp::AssetGroup(Err(e)) => Err(AppError::Ipc(e)),
            AccessResp::Error(e) => Err(AppError::Ipc(e)),
            _ => Err(AppError::Ipc("unexpected response".to_string())),
        }
    }

    /// List user-managed asset groups (the default UI surface).
    ///
    /// Virtual asset groups (e.g. "All assets") are NEVER included by this
    /// path; if a caller needs them — currently only the access-rule
    /// editor — it must use [`Self::list_asset_groups_with_virtual`].
    pub async fn list_asset_groups(&self) -> AppResult<Vec<AssetGroupInfo>> {
        self.list_asset_groups_inner(false).await
    }

    /// Same as [`Self::list_asset_groups`] but virtual asset groups are
    /// included. Reserved for the access-rule editor and for boundary
    /// tests that pin the virtual-group exclusion semantics.
    pub async fn list_asset_groups_with_virtual(&self) -> AppResult<Vec<AssetGroupInfo>> {
        self.list_asset_groups_inner(true).await
    }

    async fn list_asset_groups_inner(
        &self,
        include_virtual: bool,
    ) -> AppResult<Vec<AssetGroupInfo>> {
        self.drain_pages(
            |offset| AccessReq::ListAssetGroups {
                page: ipc_page(offset),
                include_virtual,
            },
            |resp| match resp {
                AccessResp::AssetGroupPage(p) => Ok(p),
                AccessResp::Error(e) => Err(AppError::Ipc(e)),
                _ => Err(AppError::Ipc("unexpected response".into())),
            },
        )
        .await
    }

    // Signature mirrors the `AccessRequest::UpdateAssetGroup`
    // variant 1:1; collapsing the args into a struct here would
    // only push the same fan-out to the dispatch site (the call
    // graph already validates each field separately on the wire).
    // `actor_uuid` is the 8th arg added by issue #22.
    #[allow(clippy::too_many_arguments)]
    pub async fn update_asset_group(
        &self,
        uuid: &str,
        name: &str,
        slug: &str,
        description: Option<String>,
        color: &str,
        icon: &str,
        actor_uuid: Option<String>,
    ) -> AppResult<AssetGroupInfo> {
        let resp = self
            .send_access_request(AccessReq::UpdateAssetGroup {
                uuid: uuid.to_string(),
                name: name.to_string(),
                slug: slug.to_string(),
                description,
                actor_uuid,
                color: color.to_string(),
                icon: icon.to_string(),
            })
            .await?;
        match resp {
            AccessResp::AssetGroup(Ok(info)) => Ok(info),
            AccessResp::AssetGroup(Err(e)) => Err(AppError::Ipc(e)),
            AccessResp::Error(e) => Err(AppError::Ipc(e)),
            _ => Err(AppError::Ipc("unexpected response".to_string())),
        }
    }

    pub async fn delete_asset_group(&self, uuid: &str) -> AppResult<()> {
        let resp = self
            .send_access_request(AccessReq::DeleteAssetGroup {
                uuid: uuid.to_string(),
            })
            .await?;
        match resp {
            AccessResp::Deleted(Ok(())) => Ok(()),
            AccessResp::Deleted(Err(e)) => Err(AppError::Ipc(e)),
            AccessResp::Error(e) => Err(AppError::Ipc(e)),
            _ => Err(AppError::Ipc("unexpected response".to_string())),
        }
    }

    // === Support ===

    /// Load user/asset group options for ordinary dropdowns.
    ///
    /// Virtual asset groups stay hidden. The access-rule editor uses
    /// [`Self::get_group_options_with_virtual`] instead.
    pub async fn get_group_options(&self) -> AppResult<(Vec<GroupOption>, Vec<GroupOption>)> {
        self.get_group_options_inner(false).await
    }

    /// Same as [`Self::get_group_options`] but virtual asset groups are
    /// included in the asset-group list. Reserved for the access-rule
    /// create/edit forms — every other call site MUST use the plain
    /// `get_group_options`.
    pub async fn get_group_options_with_virtual(
        &self,
    ) -> AppResult<(Vec<GroupOption>, Vec<GroupOption>)> {
        self.get_group_options_inner(true).await
    }

    async fn get_group_options_inner(
        &self,
        include_virtual: bool,
    ) -> AppResult<(Vec<GroupOption>, Vec<GroupOption>)> {
        let user_groups = self
            .drain_pages(
                |offset| AccessReq::ListUserGroupOptions {
                    page: ipc_page(offset),
                },
                |resp| match resp {
                    AccessResp::UserGroupOptionsPage(p) => Ok(p),
                    AccessResp::Error(e) => Err(AppError::Ipc(e)),
                    _ => Err(AppError::Ipc("unexpected response".into())),
                },
            )
            .await?;
        let asset_groups = self
            .drain_pages(
                |offset| AccessReq::ListAssetGroupOptions {
                    page: ipc_page(offset),
                    include_virtual,
                },
                |resp| match resp {
                    AccessResp::AssetGroupOptionsPage(p) => Ok(p),
                    AccessResp::Error(e) => Err(AppError::Ipc(e)),
                    _ => Err(AppError::Ipc("unexpected response".into())),
                },
            )
            .await?;
        Ok((user_groups, asset_groups))
    }

    // === Secret Groups CRUD (organisational vault secrets) ===

    pub async fn create_secret_group(
        &self,
        name: &str,
        slug: &str,
        description: Option<String>,
        actor_uuid: Option<String>,
    ) -> AppResult<SecretGroupInfo> {
        let resp = self
            .send_access_request(AccessReq::CreateSecretGroup {
                name: name.to_string(),
                slug: slug.to_string(),
                description,
                actor_uuid,
            })
            .await?;
        match resp {
            AccessResp::SecretGroup(Ok(info)) => Ok(info),
            AccessResp::SecretGroup(Err(e)) => Err(AppError::Ipc(e)),
            AccessResp::Error(e) => Err(AppError::Ipc(e)),
            _ => Err(AppError::Ipc("unexpected response".to_string())),
        }
    }

    pub async fn get_secret_group(&self, uuid: &str) -> AppResult<SecretGroupInfo> {
        let resp = self
            .send_access_request(AccessReq::GetSecretGroup {
                uuid: uuid.to_string(),
            })
            .await?;
        match resp {
            AccessResp::SecretGroup(Ok(info)) => Ok(info),
            AccessResp::SecretGroup(Err(e)) => Err(AppError::Ipc(e)),
            AccessResp::Error(e) => Err(AppError::Ipc(e)),
            _ => Err(AppError::Ipc("unexpected response".to_string())),
        }
    }

    /// List user-managed secret groups (the default UI surface).
    ///
    /// The virtual "All secrets" group is NEVER included by this path;
    /// only the secret-access-rule editor may opt in via
    /// [`Self::list_secret_groups_with_virtual`].
    pub async fn list_secret_groups(&self) -> AppResult<Vec<SecretGroupInfo>> {
        self.list_secret_groups_inner(false).await
    }

    /// Same as [`Self::list_secret_groups`] but the virtual "All
    /// secrets" group is included. Reserved for the secret-access-rule
    /// editor and boundary tests.
    pub async fn list_secret_groups_with_virtual(&self) -> AppResult<Vec<SecretGroupInfo>> {
        self.list_secret_groups_inner(true).await
    }

    async fn list_secret_groups_inner(
        &self,
        include_virtual: bool,
    ) -> AppResult<Vec<SecretGroupInfo>> {
        self.drain_pages(
            |offset| AccessReq::ListSecretGroups {
                page: ipc_page(offset),
                include_virtual,
            },
            |resp| match resp {
                AccessResp::SecretGroupPage(p) => Ok(p),
                AccessResp::Error(e) => Err(AppError::Ipc(e)),
                _ => Err(AppError::Ipc("unexpected response".into())),
            },
        )
        .await
    }

    pub async fn update_secret_group(
        &self,
        uuid: &str,
        name: &str,
        slug: &str,
        description: Option<String>,
        actor_uuid: Option<String>,
    ) -> AppResult<SecretGroupInfo> {
        let resp = self
            .send_access_request(AccessReq::UpdateSecretGroup {
                uuid: uuid.to_string(),
                name: name.to_string(),
                slug: slug.to_string(),
                description,
                actor_uuid,
            })
            .await?;
        match resp {
            AccessResp::SecretGroup(Ok(info)) => Ok(info),
            AccessResp::SecretGroup(Err(e)) => Err(AppError::Ipc(e)),
            AccessResp::Error(e) => Err(AppError::Ipc(e)),
            _ => Err(AppError::Ipc("unexpected response".to_string())),
        }
    }

    pub async fn delete_secret_group(&self, uuid: &str) -> AppResult<()> {
        let resp = self
            .send_access_request(AccessReq::DeleteSecretGroup {
                uuid: uuid.to_string(),
            })
            .await?;
        match resp {
            AccessResp::Deleted(Ok(())) => Ok(()),
            AccessResp::Deleted(Err(e)) => Err(AppError::Ipc(e)),
            AccessResp::Error(e) => Err(AppError::Ipc(e)),
            _ => Err(AppError::Ipc("unexpected response".to_string())),
        }
    }

    /// Secret-group options for dropdowns. Virtual group hidden by
    /// default; the secret-access-rule editor opts in.
    pub async fn list_secret_group_options(
        &self,
        include_virtual: bool,
    ) -> AppResult<Vec<GroupOption>> {
        self.drain_pages(
            |offset| AccessReq::ListSecretGroupOptions {
                page: ipc_page(offset),
                include_virtual,
            },
            |resp| match resp {
                AccessResp::SecretGroupOptionsPage(p) => Ok(p),
                AccessResp::Error(e) => Err(AppError::Ipc(e)),
                _ => Err(AppError::Ipc("unexpected response".into())),
            },
        )
        .await
    }

    // === Secret Access Rules CRUD ===

    pub async fn create_secret_access_rule(
        &self,
        data: SecretAccessRuleData,
        actor_uuid: Option<String>,
    ) -> AppResult<SecretAccessRuleInfo> {
        let resp = self
            .send_access_request(AccessReq::CreateSecretAccessRule { data, actor_uuid })
            .await?;
        match resp {
            AccessResp::SecretAccessRule(Ok(info)) => Ok(info),
            AccessResp::SecretAccessRule(Err(e)) => Err(AppError::Ipc(e)),
            AccessResp::Error(e) => Err(AppError::Ipc(e)),
            _ => Err(AppError::Ipc("unexpected response".to_string())),
        }
    }

    pub async fn get_secret_access_rule(&self, uuid: &str) -> AppResult<SecretAccessRuleInfo> {
        let resp = self
            .send_access_request(AccessReq::GetSecretAccessRule {
                uuid: uuid.to_string(),
            })
            .await?;
        match resp {
            AccessResp::SecretAccessRule(Ok(info)) => Ok(info),
            AccessResp::SecretAccessRule(Err(e)) => Err(AppError::Ipc(e)),
            AccessResp::Error(e) => Err(AppError::Ipc(e)),
            _ => Err(AppError::Ipc("unexpected response".to_string())),
        }
    }

    pub async fn list_secret_access_rules(&self) -> AppResult<Vec<SecretAccessRuleInfo>> {
        self.drain_pages(
            |offset| AccessReq::ListSecretAccessRules {
                page: ipc_page(offset),
            },
            |resp| match resp {
                AccessResp::SecretAccessRulePage(p) => Ok(p),
                AccessResp::Error(e) => Err(AppError::Ipc(e)),
                _ => Err(AppError::Ipc("unexpected response".into())),
            },
        )
        .await
    }

    pub async fn update_secret_access_rule(
        &self,
        uuid: &str,
        data: SecretAccessRuleData,
        actor_uuid: Option<String>,
    ) -> AppResult<SecretAccessRuleInfo> {
        let resp = self
            .send_access_request(AccessReq::UpdateSecretAccessRule {
                uuid: uuid.to_string(),
                data,
                actor_uuid,
            })
            .await?;
        match resp {
            AccessResp::SecretAccessRule(Ok(info)) => Ok(info),
            AccessResp::SecretAccessRule(Err(e)) => Err(AppError::Ipc(e)),
            AccessResp::Error(e) => Err(AppError::Ipc(e)),
            _ => Err(AppError::Ipc("unexpected response".to_string())),
        }
    }

    pub async fn delete_secret_access_rule(&self, uuid: &str) -> AppResult<()> {
        let resp = self
            .send_access_request(AccessReq::DeleteSecretAccessRule {
                uuid: uuid.to_string(),
            })
            .await?;
        match resp {
            AccessResp::Deleted(Ok(())) => Ok(()),
            AccessResp::Deleted(Err(e)) => Err(AppError::Ipc(e)),
            AccessResp::Error(e) => Err(AppError::Ipc(e)),
            _ => Err(AppError::Ipc("unexpected response".to_string())),
        }
    }

    // === Secret access evaluation ===

    /// `source_asset_id` is the identity-verified provenance asset the
    /// M2M caller was matched to; only rules whose asset group contains
    /// it (or the virtual "All assets" group) participate.
    pub async fn list_accessible_secret_groups(
        &self,
        user_id: i32,
        source_asset_id: i32,
    ) -> AppResult<Vec<AccessibleSecretGroupEntry>> {
        self.drain_pages(
            |offset| AccessReq::ListAccessibleSecretGroups {
                user_id,
                source_asset_id,
                page: ipc_page(offset),
            },
            |resp| match resp {
                AccessResp::AccessibleSecretGroupsPage(p) => Ok(p),
                AccessResp::Error(e) => Err(AppError::Ipc(e)),
                _ => Err(AppError::Ipc("unexpected response".into())),
            },
        )
        .await
    }

    /// Fail-closed unit check: `false` on any IPC error or unexpected
    /// response shape, never an error the caller could interpret loosely.
    pub async fn check_secret_access_by_uuid(
        &self,
        user_uuid: &str,
        secret_uuid: &str,
        source_asset_id: i32,
    ) -> bool {
        let resp = self
            .send_access_request(AccessReq::CheckSecretAccessByUuid {
                user_uuid: user_uuid.to_string(),
                secret_uuid: secret_uuid.to_string(),
                source_asset_id,
            })
            .await;
        match resp {
            Ok(AccessResp::SecretAccessChecked { allowed }) => allowed,
            Ok(_) | Err(_) => false,
        }
    }

    /// Process incoming messages from the Access service.
    ///
    /// Should be spawned as a background task via `tokio::spawn`.
    pub async fn process_incoming(&self) -> AppResult<()> {
        self.core
            .process_loop(|msg| {
                self.handle_message(msg);
                async {}
            })
            .await
            .map_err(|e| e.into_app_ipc())
    }

    fn handle_message(&self, msg: Message) {
        match msg {
            Message::RbacResponse { request_id, result } => {
                deliver_or_warn(&self.pending_requests, request_id, result, "access");
            }
            Message::AccessResponse {
                request_id,
                response,
            } => {
                deliver_or_warn(
                    &self.pending_access_requests,
                    request_id,
                    response,
                    "access",
                );
            }
            other => {
                warn!("Unexpected message from Access service: {:?}", other);
            }
        }
    }
}

/// `limit == 0` lets vauban-access apply [`shared::messages::DEFAULT_IPC_PAGE_LIMIT`].
fn ipc_page(offset: u32) -> IpcPageParams {
    IpcPageParams { limit: 0, offset }
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn test_set_nonblocking() {
        let (read_fd, _write_fd) = nix::unistd::pipe().unwrap();
        let result = crate::ipc::correlated::set_nonblocking(read_fd.as_raw_fd());
        assert!(result.is_ok());

        use libc::{F_GETFL, O_NONBLOCK, fcntl};
        let flags = unsafe { fcntl(read_fd.as_raw_fd(), F_GETFL) };
        assert!(flags & O_NONBLOCK != 0);
    }

    #[test]
    fn test_request_id_counter_increments() {
        let counter = AtomicU64::new(1);
        let id1 = counter.fetch_add(1, Ordering::SeqCst);
        let id2 = counter.fetch_add(1, Ordering::SeqCst);
        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
    }
}
