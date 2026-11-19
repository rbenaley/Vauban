//! Shared rules for a JIT access request.
//!
//! An access request is a `proxy_sessions` row in status `pending`. It
//! is listed under `/sessions/approvals` and decided in `vauban-access`.
//! Two surfaces create one: the web form
//! (`handlers::web::sessions::submit_access_request`) and the M2M API
//! (`handlers::api::sessions::create_session`). Both MUST build the row
//! from the helpers below so that a request carries the same guarantees
//! whichever door it came through:
//!
//! * the credential columns hold the [`PENDING_CREDENTIAL`] placeholder,
//!   never a caller-supplied value;
//! * the justification went through [`normalize_justification`];
//! * `max_session_duration` is copied from the access-rule evaluation,
//!   so the approval computes an `expires_at` horizon.

/// Minimum length, in bytes after trimming, of a request justification.
pub const MIN_JUSTIFICATION_LEN: usize = 10;

/// User-facing refusal when the justification is missing or too short.
pub const JUSTIFICATION_REQUIRED_MESSAGE: &str =
    "Justification is required (minimum 10 characters)";

/// Placeholder stored in `credential_id` / `credential_username` while a
/// request is pending. The real credential is resolved when the approved
/// grant is consumed by a connect handler.
pub const PENDING_CREDENTIAL: &str =
    crate::templates::sessions::presentation::PENDING_CREDENTIAL_ID;

/// Validate and sanitize a request justification.
///
/// Returns `None` when the value is absent, or shorter than
/// [`MIN_JUSTIFICATION_LEN`] bytes once trimmed, or shorter than that
/// once every HTML tag has been stripped (a justification made only of
/// markup carries no reviewable text). Otherwise returns the trimmed,
/// tag-free text ready to persist.
pub fn normalize_justification(raw: Option<&str>) -> Option<String> {
    let trimmed = raw?.trim();
    if trimmed.len() < MIN_JUSTIFICATION_LEN {
        return None;
    }
    let clean = crate::handlers::web::sanitize(trimmed);
    let clean = clean.trim();
    if clean.len() < MIN_JUSTIFICATION_LEN {
        return None;
    }
    Some(clean.to_string())
}

/// What an approved request grants to the session opened under it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedGrant {
    /// Justification the requester gave and the approver read.
    pub justification: Option<String>,
    /// Session duration the approver granted, in seconds.
    pub max_session_duration: Option<i32>,
}

/// Decision of the approval step of a session open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalGate {
    /// No rule granting this access requires an approval.
    NotRequired,
    /// An approval is required and the caller holds a live one.
    Granted(ApprovedGrant),
    /// An approval is required and the caller holds none: nothing is
    /// opened, the caller files a request.
    RequestNeeded,
}

/// The approval step, from the flag `vauban-access` returned for this
/// user, asset and protocol and from the caller's live grant, if any.
///
/// A grant never opens a session by itself: without the flag it is
/// ignored, so its duration and justification apply only to an open that
/// needed it.
pub fn approval_gate(require_approval: bool, grant: Option<ApprovedGrant>) -> ApprovalGate {
    match (require_approval, grant) {
        (false, _) => ApprovalGate::NotRequired,
        (true, Some(grant)) => ApprovalGate::Granted(grant),
        (true, None) => ApprovalGate::RequestNeeded,
    }
}

type Conn = diesel_async::pooled_connection::deadpool::Object<diesel_async::AsyncPgConnection>;

/// The caller's live approved request for `asset_id`: status `approved`,
/// its own (`user_id`), and not past its validity horizon at `now`.
///
/// A database error is no grant (fail-closed).
pub async fn find_approved_grant(
    conn: &mut Conn,
    user_id: i32,
    asset_id: i32,
    now: chrono::DateTime<chrono::Utc>,
) -> Option<ApprovedGrant> {
    use crate::schema::proxy_sessions;
    use diesel::prelude::*;
    use diesel_async::RunQueryDsl;

    proxy_sessions::table
        .filter(proxy_sessions::user_id.eq(user_id))
        .filter(proxy_sessions::asset_id.eq(asset_id))
        .filter(proxy_sessions::status.eq("approved"))
        .filter(
            proxy_sessions::expires_at
                .is_null()
                .or(proxy_sessions::expires_at.gt(now)),
        )
        .select((
            proxy_sessions::justification,
            proxy_sessions::max_session_duration,
        ))
        .first::<(Option<String>, Option<i32>)>(conn)
        .await
        .ok()
        .map(|(justification, max_session_duration)| ApprovedGrant {
            justification,
            max_session_duration,
        })
}

/// Refusal when an industrial request is filed without a workstation.
pub const NO_ACTIVE_EWS_MESSAGE: &str = "No active Engineering Workstation. Onboard one first.";

/// The two columns a row of type `iacs_tunnel` must carry, request rows
/// included (`proxy_sessions_iacs_consistency`): the industrial protocol
/// of the asset and the Engineering Workstation the tunnel is tied to.
///
/// The workstation is the requester's oldest active one, the same choice
/// `connect_iacs` makes. `None` when the requester has none: a tunnel
/// could not be opened under the approval anyway.
pub async fn iacs_request_columns(
    conn: &mut Conn,
    user_id: i32,
    asset_type: crate::models::asset::AssetType,
) -> Option<(String, uuid::Uuid)> {
    use crate::schema::ews;
    use diesel::prelude::*;
    use diesel_async::RunQueryDsl;

    let ews_uuid: uuid::Uuid = ews::table
        .filter(ews::user_id.eq(user_id))
        .filter(ews::disabled_at.is_null())
        .filter(ews::offboarded_at.is_null())
        .order(ews::created_at.asc())
        .select(ews::uuid)
        .first(conn)
        .await
        .ok()?;
    Some((iacs_protocol_label(asset_type), ews_uuid))
}

/// The `industrial_protocol` value of a tunnel to an asset of this type:
/// its protocol name, or `tcp` for the catch-all industrial type.
pub fn iacs_protocol_label(asset_type: crate::models::asset::AssetType) -> String {
    asset_type.iacs_protocol().map_or_else(
        || "tcp".to_string(),
        |protocol| protocol.as_str().to_string(),
    )
}

/// `HX-Trigger` event that opens the access request modal.
pub const REQUEST_MODAL_TRIGGER: &str = "show-access-request-modal";

/// Answer an HTMX connect request by opening the access request modal
/// for this asset. `asset_type` is the asset's type as the catalogue
/// renders it; the modal maps it to a session type.
pub fn request_modal_response(
    asset_uuid: &str,
    asset_type: &str,
    require_mfa: bool,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    let payload = serde_json::json!({
        REQUEST_MODAL_TRIGGER: {
            "asset_uuid": asset_uuid,
            "asset_type": asset_type,
            "require_mfa": require_mfa,
        }
    })
    .to_string();
    let value = axum::http::HeaderValue::from_str(&payload).unwrap_or_else(|_| {
        axum::http::HeaderValue::from_static(r#"{"show-access-request-modal":{}}"#)
    });
    (
        axum::http::StatusCode::OK,
        [(
            axum::http::header::HeaderName::from_static("hx-trigger"),
            value,
        )],
    )
        .into_response()
}

/// Refusal for a caller that cannot be shown the modal.
pub const APPROVAL_REQUIRED_MESSAGE: &str =
    "Access requires approval. Please submit an access request from the /assets catalogue.";

#[cfg(test)]
mod tests {
    use super::*;

    fn grant() -> ApprovedGrant {
        ApprovedGrant {
            justification: Some("planned maintenance".to_string()),
            max_session_duration: Some(600),
        }
    }

    #[test]
    fn test_approval_gate_not_required_ignores_a_grant() {
        assert_eq!(approval_gate(false, None), ApprovalGate::NotRequired);
        assert_eq!(
            approval_gate(false, Some(grant())),
            ApprovalGate::NotRequired
        );
    }

    #[test]
    fn test_approval_gate_grants_with_a_live_approval() {
        assert_eq!(
            approval_gate(true, Some(grant())),
            ApprovalGate::Granted(grant())
        );
    }

    #[test]
    fn attack_open_without_approval_is_rejected() {
        assert_eq!(approval_gate(true, None), ApprovalGate::RequestNeeded);
    }

    #[test]
    fn test_iacs_protocol_label_is_never_empty() {
        use crate::models::asset::AssetType;
        assert_eq!(iacs_protocol_label(AssetType::IacsModbus), "modbus");
        // The catch-all type has no protocol enum; the column is NOT NULL.
        assert_eq!(iacs_protocol_label(AssetType::Ssh), "tcp");
    }

    /// A request for an industrial asset must fill the columns the
    /// database requires of every `iacs_tunnel` row; without them the
    /// INSERT is refused and no request can be filed.
    #[test]
    fn the_request_handler_fills_the_iacs_columns() {
        let src = include_str!("../handlers/web/sessions.rs");
        let handler = src
            .split("pub async fn submit_access_request(")
            .nth(1)
            .and_then(|rest| rest.split("\n}\n").next())
            .unwrap_or_default();
        assert!(handler.contains("iacs_request_columns("));
        assert!(handler.contains("NO_ACTIVE_EWS_MESSAGE"));
        assert!(!handler.contains("industrial_protocol: None"));
        assert!(!handler.contains("ews_uuid: None"));
    }

    #[test]
    fn test_request_modal_response_names_the_asset() {
        let response = request_modal_response("a-b", "iacs_modbus", true);
        let header = response
            .headers()
            .get("hx-trigger")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let json: serde_json::Value = serde_json::from_str(&header).unwrap_or_default();
        assert_eq!(json[REQUEST_MODAL_TRIGGER]["asset_uuid"], "a-b");
        assert_eq!(json[REQUEST_MODAL_TRIGGER]["asset_type"], "iacs_modbus");
        assert_eq!(json[REQUEST_MODAL_TRIGGER]["require_mfa"], true);
    }

    /// Every web handler that opens a session reads the approval flag
    /// `vauban-access` returned. The IACS handler did not until 0.9.60.
    #[test]
    fn attack_every_open_path_reads_the_approval_flag() {
        for (name, src) in [
            ("ssh", include_str!("../handlers/web/ssh.rs")),
            ("rdp", include_str!("../handlers/web/rdp.rs")),
            ("iacs", include_str!("../handlers/web/iacs_tunnel.rs")),
        ] {
            assert!(
                src.contains("issued.require_approval"),
                "{name}: the approval flag of the session token is not read"
            );
        }
    }

    /// The IACS handler decides through the gate, on the caller's own
    /// grant, and leaves no tunnel row behind a refusal.
    #[test]
    fn the_iacs_open_goes_through_the_approval_gate() {
        let src = include_str!("../handlers/web/iacs_tunnel.rs");
        assert!(src.contains("approval_gate(issued.require_approval, grant)"));
        let lookup = src
            .split("find_approved_grant(")
            .nth(1)
            .and_then(|rest| rest.split(".await").next())
            .unwrap_or_default();
        assert!(lookup.contains("user_id"), "the grant is the caller's");
        assert!(lookup.contains("asset.id"), "the grant is for this asset");

        let refusal = src
            .split("ApprovalGate::RequestNeeded => {")
            .nth(1)
            .and_then(|rest| rest.split("ApprovalGate::Granted(grant) => {").next())
            .unwrap_or_default();
        let delete = refusal.find("diesel::delete(");
        let first_return = refusal.find("return ");
        assert!(delete.is_some(), "the refused open must delete its row");
        assert!(delete < first_return, "the row is deleted before answering");
    }

    mod prop {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            /// Whatever the grant holds, an open that needs an approval
            /// goes through only with one, and a grant alone decides
            /// nothing.
            #[test]
            fn proptest_approval_gate_never_opens_without_a_grant(
                require_approval in any::<bool>(),
                held in proptest::option::of((
                    proptest::option::of("[ -~]{0,40}"),
                    proptest::option::of(any::<i32>()),
                )),
            ) {
                let held = held.map(|(justification, max_session_duration)| ApprovedGrant {
                    justification,
                    max_session_duration,
                });
                let gate = approval_gate(require_approval, held.clone());
                match gate {
                    ApprovalGate::NotRequired => prop_assert!(!require_approval),
                    ApprovalGate::Granted(granted) => {
                        prop_assert!(require_approval);
                        prop_assert_eq!(Some(granted), held);
                    }
                    ApprovalGate::RequestNeeded => {
                        prop_assert!(require_approval);
                        prop_assert!(held.is_none());
                    }
                }
            }
        }
    }

    #[test]
    fn test_normalize_justification_absent_returns_none() {
        assert_eq!(normalize_justification(None), None);
    }

    #[test]
    fn test_normalize_justification_too_short_returns_none() {
        for raw in ["", "   ", "short", "123456789", "  123456789  "] {
            assert_eq!(normalize_justification(Some(raw)), None, "input: {raw:?}");
        }
    }

    #[test]
    fn test_normalize_justification_minimum_length_is_accepted() {
        assert_eq!(
            normalize_justification(Some("1234567890")),
            Some("1234567890".to_string())
        );
    }

    #[test]
    fn test_normalize_justification_trims_surrounding_whitespace() {
        assert_eq!(
            normalize_justification(Some("  routine maintenance \n")),
            Some("routine maintenance".to_string())
        );
    }

    #[test]
    fn test_normalize_justification_strips_html_tags() {
        let out = normalize_justification(Some("<b>routine</b> maintenance window"));
        assert_eq!(out, Some("routine maintenance window".to_string()));
    }

    #[test]
    fn test_normalize_justification_markup_only_is_rejected() {
        // 30+ bytes of markup, zero bytes of reviewable text.
        assert_eq!(
            normalize_justification(Some("<script></script><b></b><i></i>")),
            None
        );
    }

    #[test]
    fn test_pending_credential_matches_presentation_constant() {
        assert_eq!(PENDING_CREDENTIAL, "pending");
        assert!(crate::templates::sessions::presentation::is_jit_grant(
            PENDING_CREDENTIAL
        ));
    }

    #[test]
    fn test_justification_message_states_the_minimum() {
        assert!(JUSTIFICATION_REQUIRED_MESSAGE.contains(&MIN_JUSTIFICATION_LEN.to_string()));
    }
}
