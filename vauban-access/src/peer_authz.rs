//! Per-peer authorization for vauban-access requests (component x operation).
//!
//! Same trust model as `vauban-vault/src/authz.rs`: each peer talks to
//! vauban-access on a dedicated pipe created by the supervisor at fork time,
//! labelled at init from the env-var suffix (`"web"`, `"proxy_mcp"`, …). The
//! label is supervisor-attested and cannot be forged on the wire, so the
//! decision is taken on `(peer, verb)` before any handler runs.
//!
//! A peer may only send the verbs its role needs: a compromised MCP proxy
//! must not ask `IssueDiagnosticToken { caller_has_assets_manage: true }`
//! or edit access rules.
//!
//! # Matrix (fail-closed)
//!
//! - `supervisor`: `Control` only.
//! - `web`: `RbacCheck` and every `AccessRequest` except the Mission Seal PEP
//!   verbs, which belong to the MCP proxy (so `PruneMcpRuleTools` is web-only).
//! - `proxy_ssh` / `proxy_rdp` / `proxy_iacs`: `CheckAccessByUuid` (AccessGuard).
//! - `proxy_mcp`: `CheckAccessByUuid` + Mission Seal PEP verbs
//!   (`SealMcpMandate`, `CheckStepAuthorized`, `CommitMcpMandateStep`,
//!   `RollbackMcpMandateStep`, `ClearMcpMandate`).
//! - `auth`: nothing.
//! - unknown label / anything else: nothing.

use shared::messages::{AccessRequest, AccessResponse, Message, RbacResult};

/// A vauban-access peer, identified by its supervisor-attested channel.
/// Matched exhaustively by [`is_authorized`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessPeer {
    Supervisor,
    Web,
    ProxySsh,
    ProxyRdp,
    ProxyIacs,
    ProxyMcp,
    Auth,
}

impl AccessPeer {
    pub const COUNT: usize = 7;

    pub const ALL: [AccessPeer; Self::COUNT] = [
        AccessPeer::Supervisor,
        AccessPeer::Web,
        AccessPeer::ProxySsh,
        AccessPeer::ProxyRdp,
        AccessPeer::ProxyIacs,
        AccessPeer::ProxyMcp,
        AccessPeer::Auth,
    ];

    /// Map a `peer_channels` label to a peer. `Supervisor` is never reachable
    /// from a label: it is minted only for the supervisor control channel.
    #[must_use]
    pub fn from_channel_label(label: &str) -> Option<Self> {
        match label {
            "web" => Some(AccessPeer::Web),
            "proxy_ssh" => Some(AccessPeer::ProxySsh),
            "proxy_rdp" => Some(AccessPeer::ProxyRdp),
            "proxy_iacs" => Some(AccessPeer::ProxyIacs),
            "proxy_mcp" => Some(AccessPeer::ProxyMcp),
            "auth" => Some(AccessPeer::Auth),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            AccessPeer::Supervisor => "supervisor",
            AccessPeer::Web => "web",
            AccessPeer::ProxySsh => "proxy_ssh",
            AccessPeer::ProxyRdp => "proxy_rdp",
            AccessPeer::ProxyIacs => "proxy_iacs",
            AccessPeer::ProxyMcp => "proxy_mcp",
            AccessPeer::Auth => "auth",
        }
    }
}

/// Mission Seal PEP verbs: only the MCP proxy enforces a mandate.
fn is_mcp_pep_verb(req: &AccessRequest) -> bool {
    matches!(
        req,
        AccessRequest::SealMcpMandate { .. }
            | AccessRequest::CheckStepAuthorized { .. }
            | AccessRequest::CommitMcpMandateStep { .. }
            | AccessRequest::RollbackMcpMandateStep { .. }
            | AccessRequest::ClearMcpMandate { .. }
    )
}

/// The authorization decision for a `(peer, message)` couple.
#[must_use]
pub fn is_authorized(peer: AccessPeer, msg: &Message) -> bool {
    match (peer, msg) {
        (AccessPeer::Supervisor, Message::Control(_)) => true,

        (AccessPeer::Web, Message::RbacCheck { .. }) => true,
        (AccessPeer::Web, Message::AccessRequest { request, .. }) => !is_mcp_pep_verb(request),

        (
            AccessPeer::ProxySsh | AccessPeer::ProxyRdp | AccessPeer::ProxyIacs,
            Message::AccessRequest {
                request: AccessRequest::CheckAccessByUuid { .. },
                ..
            },
        ) => true,

        (AccessPeer::ProxyMcp, Message::AccessRequest { request, .. }) => {
            matches!(request, AccessRequest::CheckAccessByUuid { .. }) || is_mcp_pep_verb(request)
        }

        _ => false,
    }
}

/// Stable verb name for structured logging of a denied request.
#[must_use]
pub fn verb_name(msg: &Message) -> String {
    match msg {
        Message::Control(_) => "Control".to_string(),
        Message::RbacCheck { .. } => "RbacCheck".to_string(),
        Message::AccessRequest { request, .. } => {
            let dbg = format!("{request:?}");
            dbg.split([' ', '{', '(']).next().unwrap_or("").to_string()
        }
        _ => "other".to_string(),
    }
}

/// Typed refusal so the caller's pending request resolves instead of timing
/// out. Token verbs get `SessionTokenDenied` (what callers already map to a
/// deny); everything else an `Error`. `None` for messages with no reply.
#[must_use]
pub fn denied_response(msg: &Message) -> Option<Message> {
    const REASON: &str = "unauthorized: access verb denied for this peer";
    match msg {
        Message::RbacCheck { request_id, .. } => Some(Message::RbacResponse {
            request_id: *request_id,
            result: RbacResult {
                allowed: false,
                reason: Some(REASON.to_string()),
            },
        }),
        Message::AccessRequest {
            request_id,
            request,
        } => {
            let response = match request {
                AccessRequest::IssueSessionToken { .. }
                | AccessRequest::IssueDiagnosticToken { .. } => AccessResponse::SessionTokenDenied,
                _ => AccessResponse::Error(REASON.to_string()),
            };
            Some(Message::AccessResponse {
                request_id: *request_id,
                response,
            })
        }
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use shared::messages::{ControlMessage, IpcPageParams, Service};

    fn req(r: AccessRequest) -> Message {
        Message::AccessRequest {
            request_id: 9,
            request: r,
        }
    }
    fn by_uuid() -> Message {
        req(AccessRequest::CheckAccessByUuid {
            user_uuid: "u".into(),
            asset_uuid: "a".into(),
            protocol: "mcp".into(),
        })
    }
    fn diag() -> Message {
        req(AccessRequest::IssueDiagnosticToken {
            user_uuid: "u".into(),
            asset_uuid: "a".into(),
            protocol: "mcp".into(),
            host: "h".into(),
            port: 1,
            target_service: Service::ProxyMcp,
            session_id: "s".into(),
            caller_has_assets_manage: true,
        })
    }
    fn issue() -> Message {
        req(AccessRequest::IssueSessionToken {
            user_uuid: "u".into(),
            asset_uuid: "a".into(),
            protocol: "mcp".into(),
            host: "h".into(),
            port: 1,
            target_service: Service::ProxyMcp,
            session_id: "s".into(),
        })
    }
    fn list_rules() -> Message {
        req(AccessRequest::ListAccessRules {
            page: IpcPageParams {
                limit: 1,
                offset: 0,
            },
        })
    }
    fn prune_rule_tools() -> Message {
        req(AccessRequest::PruneMcpRuleTools {
            asset_group_ids: Some(vec![1]),
        })
    }
    fn pep_verbs() -> Vec<Message> {
        vec![
            req(AccessRequest::SealMcpMandate {
                session_id: "s".into(),
                mandate_id: "m".into(),
                asset_id: "a".into(),
                contract_json: "{}".into(),
                now_unix: 1.0,
            }),
            req(AccessRequest::CheckStepAuthorized {
                session_id: "s".into(),
                tool: "t".into(),
                arguments_json: "{}".into(),
                now_unix: 1.0,
            }),
            req(AccessRequest::CommitMcpMandateStep {
                session_id: "s".into(),
                result_json: "{}".into(),
            }),
            req(AccessRequest::RollbackMcpMandateStep {
                session_id: "s".into(),
            }),
            req(AccessRequest::ClearMcpMandate {
                session_id: "s".into(),
            }),
        ]
    }
    fn rbac() -> Message {
        Message::RbacCheck {
            request_id: 3,
            subject: "u".into(),
            object: "o".into(),
            action: "a".into(),
        }
    }
    fn ping() -> Message {
        Message::Control(ControlMessage::Ping { seq: 1 })
    }

    /// Independent expectation table (one typo cannot pass both).
    fn expected(peer: AccessPeer, kind: &str) -> bool {
        matches!(
            (peer, kind),
            (AccessPeer::Supervisor, "control")
                | (
                    AccessPeer::Web,
                    "rbac" | "by_uuid" | "diag" | "issue" | "admin"
                )
                | (
                    AccessPeer::ProxySsh | AccessPeer::ProxyRdp | AccessPeer::ProxyIacs,
                    "by_uuid"
                )
                | (AccessPeer::ProxyMcp, "by_uuid" | "pep")
        )
    }

    #[test]
    fn full_matrix_matches_expected() {
        let cases: Vec<(&str, Message)> = vec![
            ("control", ping()),
            ("rbac", rbac()),
            ("by_uuid", by_uuid()),
            ("diag", diag()),
            ("issue", issue()),
            ("admin", list_rules()),
            ("admin", prune_rule_tools()),
        ];
        for &peer in &AccessPeer::ALL {
            for (kind, msg) in &cases {
                assert_eq!(
                    is_authorized(peer, msg),
                    expected(peer, kind),
                    "peer={peer:?} kind={kind}"
                );
            }
            for msg in pep_verbs() {
                assert_eq!(
                    is_authorized(peer, &msg),
                    expected(peer, "pep"),
                    "peer={peer:?} pep"
                );
            }
        }
    }

    /// The MCP proxy cannot mint a diagnostic token by
    /// claiming `caller_has_assets_manage`, nor touch access rules.
    #[test]
    fn proxy_mcp_cannot_issue_diagnostic_token_or_admin() {
        assert!(!is_authorized(AccessPeer::ProxyMcp, &diag()));
        assert!(!is_authorized(AccessPeer::ProxyMcp, &issue()));
        assert!(!is_authorized(AccessPeer::ProxyMcp, &list_rules()));
        assert!(!is_authorized(AccessPeer::ProxyMcp, &rbac()));
        assert!(!is_authorized(AccessPeer::ProxyMcp, &ping()));
    }

    #[test]
    fn non_access_message_denied_for_everyone() {
        let other = Message::McpProxyReady;
        for &peer in &AccessPeer::ALL {
            assert!(!is_authorized(peer, &other));
        }
        assert!(denied_response(&other).is_none());
        assert!(denied_response(&ping()).is_none());
        assert_eq!(verb_name(&other), "other");
    }

    #[test]
    fn labels_round_trip_and_unknown_is_none() {
        for &peer in &AccessPeer::ALL {
            let back = AccessPeer::from_channel_label(peer.as_str());
            if peer == AccessPeer::Supervisor {
                assert_eq!(back, None);
            } else {
                assert_eq!(back, Some(peer));
            }
        }
        for label in ["", "vault", "audit", "WEB", "proxy_mcp "] {
            assert_eq!(AccessPeer::from_channel_label(label), None);
        }
        assert_eq!(AccessPeer::ALL.len(), AccessPeer::COUNT);
    }

    #[test]
    fn denied_responses_are_typed_and_carry_request_id() {
        match denied_response(&rbac()) {
            Some(Message::RbacResponse {
                request_id: 3,
                result,
            }) => {
                assert!(!result.allowed);
                assert!(result.reason.unwrap().contains("unauthorized"));
            }
            other => panic!("{other:?}"),
        }
        for m in [diag(), issue()] {
            match denied_response(&m) {
                Some(Message::AccessResponse {
                    request_id: 9,
                    response: AccessResponse::SessionTokenDenied,
                }) => {}
                other => panic!("{other:?}"),
            }
        }
        match denied_response(&list_rules()) {
            Some(Message::AccessResponse {
                request_id: 9,
                response: AccessResponse::Error(e),
            }) => assert!(e.contains("unauthorized")),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn verb_names_for_logging() {
        assert_eq!(verb_name(&ping()), "Control");
        assert_eq!(verb_name(&rbac()), "RbacCheck");
        assert_eq!(verb_name(&diag()), "IssueDiagnosticToken");
        assert_eq!(verb_name(&by_uuid()), "CheckAccessByUuid");
    }
}
