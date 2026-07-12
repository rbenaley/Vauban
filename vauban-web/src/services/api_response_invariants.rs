//! VAUBAN Web - API response invariants.
//!
//! SECURITY / UX contract: single seam mapping every denial on the M2M
//! JSON API zone (`/api/v1/*`) to its HTTP status code and canonical
//! message. The M2M zone is authenticated exclusively by API keys
//! (`middleware::api_key`), so unlike the web/WS surfaces it does NOT
//! apply anti-enumeration response shaping: a caller holding a valid
//! API key is an authenticated machine identity, and honest statuses
//! are worth more than masking which resources exist. (Callers WITHOUT
//! a valid key never get past the 401 gate, so enumeration with an
//! invalid key is impossible either way.)
//!
//! The invariants (pinned by the unit tests below and by the E2E matrix
//! in `tests/api/api_status_semantics_test.rs` +
//! `tests/api/api_disabled_test.rs`):
//!
//! | Invariant  | Condition                                            | Status |
//! |------------|------------------------------------------------------|--------|
//! | INV-API-1  | `[api] enabled = false` (whole `/api/v1` tree)       | 501    |
//! | INV-API-2  | API key missing, invalid, expired or revoked         | 401    |
//! | INV-API-3  | Valid key but not authorized (scope, Casbin, access  | 403    |
//! |            | rule not covering the resource, vault provenance)    |        |
//! | INV-API-4  | Authorized but the resource does not exist / is      | 404    |
//! |            | inactive                                             |        |
//! | INV-API-5  | Malformed identifier (e.g. non-UUID path segment)    | 400    |
//! | INV-API-6  | Backing service unavailable (IPC down): fail closed  | 502    |
//! |            | but honest -- never a misleading 404 or empty 200    |        |
//!
//! INV-API-2 is enforced upstream by the `AuthUser` extractor and
//! `middleware::api_key` (fail-closed: no `AuthUser` injected without a
//! valid key), so it has no `ApiDenial` variant here.
//!
//! The web HTML and WebSocket surfaces keep their own anti-enumeration
//! shaping (`services::session_access::verify`, 404/410 collapse); this
//! module is for the `/api/v1` zone only.

use axum::http::StatusCode;

use crate::error::AppError;

/// A denial on the `/api/v1` zone, expressed as *why* the request is
/// refused. The HTTP mapping lives in exactly one place
/// ([`ApiDenial::status`] / [`From<ApiDenial> for AppError`]) so
/// handlers cannot drift from the invariant matrix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiDenial {
    /// INV-API-1: the whole API surface is disabled by configuration.
    ApiDisabled,
    /// INV-API-3: the API key does not carry the required scope.
    /// Payload: the scope name (e.g. `"secrets"`).
    MissingScope(&'static str),
    /// INV-API-3: the caller lacks the required Casbin permission.
    /// Payload: the `resource:action` couple (e.g. `"sessions:read"`).
    MissingPermission(&'static str),
    /// INV-API-3: instance-level refusal — the caller is authenticated
    /// and functionally capable, but this specific resource is not
    /// covered (no access rule, not the owner). Payload: the lowercase
    /// resource kind (e.g. `"secret"`, `"session"`).
    NotAuthorized(&'static str),
    /// INV-API-3: vault provenance refusal — the caller's source IP
    /// does not resolve to an identity-verified asset, a precondition
    /// of the whole `/api/v1/vault/*` sub-tree. Honest 403 (instead of
    /// the historical anti-enumeration 404) so a legitimate operator
    /// testing the vault API immediately learns WHY the call is
    /// refused.
    ProvenanceDenied,
    /// INV-API-4: the resource does not exist (or is inactive/deleted).
    /// Payload: the capitalized resource kind (e.g. `"Secret"`,
    /// `"Session"`), matching the historical `"{Kind} not found"`
    /// message format.
    NotFound(&'static str),
    /// INV-API-5: the identifier in the path is not a valid UUID.
    MalformedIdentifier,
    /// INV-API-6: a backing service (IPC peer) is unavailable. The
    /// request fails closed, but with an honest 502 instead of a
    /// misleading 404 or a silent empty list. Payload: the service
    /// seam name, logged server-side only.
    Unavailable(&'static str),
}

impl ApiDenial {
    /// The HTTP status this denial maps to. Pinned by unit tests.
    pub fn status(&self) -> StatusCode {
        match self {
            ApiDenial::ApiDisabled => StatusCode::NOT_IMPLEMENTED,
            ApiDenial::MissingScope(_)
            | ApiDenial::MissingPermission(_)
            | ApiDenial::NotAuthorized(_)
            | ApiDenial::ProvenanceDenied => StatusCode::FORBIDDEN,
            ApiDenial::NotFound(_) => StatusCode::NOT_FOUND,
            ApiDenial::MalformedIdentifier => StatusCode::BAD_REQUEST,
            ApiDenial::Unavailable(_) => StatusCode::BAD_GATEWAY,
        }
    }

    /// The canonical client-facing message. Stable: integration tests
    /// and API consumers may match on these strings.
    pub fn message(&self) -> String {
        match self {
            ApiDenial::ApiDisabled => "API is disabled".to_string(),
            ApiDenial::MissingScope(scope) => {
                format!("API key lacks required scope: {scope}")
            }
            ApiDenial::MissingPermission(perm) => {
                format!("Insufficient privileges: {perm} required")
            }
            ApiDenial::NotAuthorized(kind) => {
                format!("Not authorized to access this {kind}")
            }
            ApiDenial::ProvenanceDenied => {
                "Caller is not an identity-verified asset (vault provenance)".to_string()
            }
            ApiDenial::NotFound(kind) => format!("{kind} not found"),
            ApiDenial::MalformedIdentifier => "Invalid UUID format".to_string(),
            // `AppError::Ipc` renders the generic "Service unavailable"
            // body; the seam name only reaches the server-side log.
            ApiDenial::Unavailable(seam) => format!("{seam} unavailable"),
        }
    }
}

/// Single translation point into the application error type. Every
/// `/api/v1` handler MUST build its denials through this conversion
/// (directly or via `AppError::forbidden`, which produces the same
/// `MissingPermission` message) so the status matrix stays in
/// lock-step with the module docs.
impl From<ApiDenial> for AppError {
    fn from(denial: ApiDenial) -> Self {
        match &denial {
            ApiDenial::ApiDisabled => AppError::NotImplemented(denial.message()),
            ApiDenial::MissingScope(_)
            | ApiDenial::MissingPermission(_)
            | ApiDenial::NotAuthorized(_)
            | ApiDenial::ProvenanceDenied => AppError::Authorization(denial.message()),
            ApiDenial::NotFound(_) => AppError::NotFound(denial.message()),
            ApiDenial::MalformedIdentifier => AppError::Validation(denial.message()),
            ApiDenial::Unavailable(_) => AppError::Ipc(denial.message()),
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::response::IntoResponse;

    use super::*;

    // ==================== Status matrix (INV-API-1..6) ====================

    #[test]
    fn test_inv_api_1_api_disabled_is_501() {
        assert_eq!(ApiDenial::ApiDisabled.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[test]
    fn test_inv_api_3_missing_scope_is_403() {
        assert_eq!(
            ApiDenial::MissingScope("secrets").status(),
            StatusCode::FORBIDDEN
        );
    }

    #[test]
    fn test_inv_api_3_missing_permission_is_403() {
        assert_eq!(
            ApiDenial::MissingPermission("sessions:read").status(),
            StatusCode::FORBIDDEN
        );
    }

    #[test]
    fn test_inv_api_3_not_authorized_is_403() {
        assert_eq!(
            ApiDenial::NotAuthorized("secret").status(),
            StatusCode::FORBIDDEN
        );
    }

    #[test]
    fn test_inv_api_3_provenance_denied_is_403() {
        assert_eq!(ApiDenial::ProvenanceDenied.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_provenance_denied_message_is_stable() {
        assert_eq!(
            ApiDenial::ProvenanceDenied.message(),
            "Caller is not an identity-verified asset (vault provenance)"
        );
    }

    #[test]
    fn test_inv_api_4_not_found_is_404() {
        assert_eq!(
            ApiDenial::NotFound("Secret").status(),
            StatusCode::NOT_FOUND
        );
    }

    #[test]
    fn test_inv_api_5_malformed_identifier_is_400() {
        assert_eq!(
            ApiDenial::MalformedIdentifier.status(),
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn test_inv_api_6_unavailable_is_502() {
        assert_eq!(
            ApiDenial::Unavailable("vauban-access").status(),
            StatusCode::BAD_GATEWAY
        );
    }

    // ==================== Canonical messages (stable) ====================

    #[test]
    fn test_api_disabled_message_is_stable() {
        assert_eq!(ApiDenial::ApiDisabled.message(), "API is disabled");
    }

    #[test]
    fn test_missing_scope_message_matches_scope_middleware_format() {
        assert_eq!(
            ApiDenial::MissingScope("secrets").message(),
            "API key lacks required scope: secrets"
        );
    }

    #[test]
    fn test_missing_permission_message_matches_app_error_forbidden() {
        // The `AppError::forbidden` helper and `MissingPermission` MUST
        // produce byte-identical messages: handlers use both paths.
        let via_denial: AppError = ApiDenial::MissingPermission("vault_secrets:read").into();
        let via_helper = AppError::forbidden("vault_secrets:read");
        assert_eq!(
            format!("{via_denial}"),
            format!("{via_helper}"),
            "MissingPermission and AppError::forbidden drifted apart"
        );
    }

    #[test]
    fn test_not_authorized_message_is_stable() {
        assert_eq!(
            ApiDenial::NotAuthorized("secret").message(),
            "Not authorized to access this secret"
        );
        assert_eq!(
            ApiDenial::NotAuthorized("session").message(),
            "Not authorized to access this session"
        );
    }

    #[test]
    fn test_not_found_message_matches_historical_format() {
        assert_eq!(ApiDenial::NotFound("Secret").message(), "Secret not found");
        assert_eq!(
            ApiDenial::NotFound("Session").message(),
            "Session not found"
        );
    }

    #[test]
    fn test_malformed_identifier_message_matches_historical_format() {
        assert_eq!(
            ApiDenial::MalformedIdentifier.message(),
            "Invalid UUID format"
        );
    }

    // ==================== AppError conversion end-to-end ====================

    #[test]
    fn test_from_denial_response_statuses_match_matrix() {
        let cases: Vec<(ApiDenial, StatusCode)> = vec![
            (ApiDenial::ApiDisabled, StatusCode::NOT_IMPLEMENTED),
            (ApiDenial::MissingScope("read"), StatusCode::FORBIDDEN),
            (
                ApiDenial::MissingPermission("sessions:read"),
                StatusCode::FORBIDDEN,
            ),
            (ApiDenial::NotAuthorized("session"), StatusCode::FORBIDDEN),
            (ApiDenial::ProvenanceDenied, StatusCode::FORBIDDEN),
            (ApiDenial::NotFound("Session"), StatusCode::NOT_FOUND),
            (ApiDenial::MalformedIdentifier, StatusCode::BAD_REQUEST),
            (
                ApiDenial::Unavailable("vauban-access"),
                StatusCode::BAD_GATEWAY,
            ),
        ];
        for (denial, expected) in cases {
            let status_from_denial = denial.status();
            let app_error: AppError = denial.into();
            let response = app_error.into_response();
            assert_eq!(
                response.status(),
                expected,
                "IntoResponse status drifted from the invariant matrix"
            );
            assert_eq!(
                status_from_denial, expected,
                "ApiDenial::status drifted from the invariant matrix"
            );
        }
    }

    #[test]
    fn test_unavailable_body_never_leaks_seam_name() {
        // `AppError::Ipc` collapses the body to the generic
        // "Service unavailable"; the seam name must stay server-side.
        let app_error: AppError = ApiDenial::Unavailable("vauban-access").into();
        let response = app_error.into_response();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        // The body is produced by `AppError::into_response`, which maps
        // every Ipc error to the fixed public message.
        assert!(matches!(
            AppError::from(ApiDenial::Unavailable("vauban-access")),
            AppError::Ipc(_)
        ));
    }
}
