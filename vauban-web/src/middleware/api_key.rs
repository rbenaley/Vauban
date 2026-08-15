//! VAUBAN Web - API key (machine-to-machine) authentication for the
//! `/api/v1/*` zone (VAU-007).
//!
//! The REST API is machine-to-machine: it authenticates EXCLUSIVELY via
//! API keys (table `api_keys`, prefix `vbn_`), never via the human session
//! JWT. This module is the single seam that turns an untrusted credential
//! into an [`AuthUser`] plus the key's [`ApiKeyAuth`] scopes. The four
//! invariants behind the fix:
//!
//! - INV-1 (M2M-only): API keys are honored ONLY in the `/api/` zone (see
//!   [`crate::middleware::auth::auth_middleware`]); a human JWT never
//!   yields an `AuthUser` there, and a `vbn_` key never authenticates a
//!   web/WebSocket route.
//! - INV-2 (fail-closed): [`authenticate_api_key`] returns `Some` only for
//!   a key that is found, active, not expired, and whose owner is active;
//!   any failure yields `None` (no `AuthUser`, request falls through to a
//!   `401`). `last_used_*` is written only on success.
//! - INV-3 (scope <= role): [`api_scope_enforcement`] gates each request on
//!   the key's scope mapped from the HTTP method/zone; the effective
//!   authorization is this scope AND the owner's Casbin role
//!   (defense-in-depth, the scope never widens the role).
//! - INV-4 (single seam): the key lookup (`ApiKey::hash_key` /
//!   `api_keys.key_hash`) lives ONLY here; no `/api/v1/*` handler
//!   re-implements credential parsing or lookup.

use axum::extract::Request;
use axum::http::{HeaderMap, Method};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use ipnetwork::IpNetwork;
use uuid::Uuid;

use crate::AppState;
use crate::error::AppError;
use crate::middleware::auth::AuthUser;
use crate::models::api_key::{ApiKey, ApiKeyScope};

/// Canonical prefix of every Vauban API key (see [`ApiKey::generate_key`]).
pub const API_KEY_PREFIX: &str = "vbn_";

/// Scopes attached to the API key that authenticated the current request.
///
/// Inserted into the request extensions by
/// [`crate::middleware::auth::auth_middleware`] alongside the synthesized
/// [`AuthUser`]. Consumed by [`api_scope_enforcement`].
#[derive(Debug, Clone)]
pub struct ApiKeyAuth {
    pub scopes: Vec<ApiKeyScope>,
}

impl ApiKeyAuth {
    /// Whether the key grants at least the `required` scope.
    ///
    /// Two disjoint families:
    ///
    /// - `read` / `write` / `admin` are hierarchical among themselves
    ///   (`admin >= write >= read`);
    /// - `secrets` is an ISLAND: it is satisfied ONLY by a key that
    ///   carries the literal `secrets` scope, and it never satisfies any
    ///   rank of the hierarchy. In particular `admin` does NOT imply
    ///   `secrets` (an admin automation key must not be able to read
    ///   organisational secret values), and `secrets` does NOT imply
    ///   `read` (a secrets key is useless outside `/api/v1/vault/*`).
    pub fn satisfies(&self, required: ApiKeyScope) -> bool {
        match required {
            ApiKeyScope::Secrets => self.scopes.contains(&ApiKeyScope::Secrets),
            _ => self
                .scopes
                .iter()
                .filter_map(|granted| scope_rank(*granted))
                .any(|granted_rank| {
                    // `required` is hierarchical here, so its rank exists.
                    scope_rank(required).is_some_and(|r| granted_rank >= r)
                }),
        }
    }
}

/// Order the hierarchical scopes so the broader one covers the narrower
/// (`admin` covers `write` and `read`; `write` covers `read`). `Secrets`
/// deliberately has NO rank: it lives outside the hierarchy and is
/// matched by literal equality only (see [`ApiKeyAuth::satisfies`]).
fn scope_rank(scope: ApiKeyScope) -> Option<u8> {
    match scope {
        ApiKeyScope::Read => Some(0),
        ApiKeyScope::Write => Some(1),
        ApiKeyScope::Admin => Some(2),
        ApiKeyScope::Secrets => None,
    }
}

/// Parse the `scopes` JSONB column into typed scopes.
///
/// Mirrors [`ApiKey::scopes_vec`]: a non-array value defaults to `read`;
/// unknown entries are dropped. An explicit empty array yields no scope
/// (the key can then do nothing -- fail-closed).
fn parse_scopes(value: &serde_json::Value) -> Vec<ApiKeyScope> {
    match value.as_array() {
        Some(arr) => arr
            .iter()
            .filter_map(|v| v.as_str())
            .filter_map(ApiKeyScope::parse)
            .collect(),
        None => vec![ApiKeyScope::Read],
    }
}

/// Extract a raw API key from the request headers.
///
/// Accepts `X-API-Key: <key>` or `Authorization: Bearer vbn_...`. The
/// `Bearer` form requires the `vbn_` prefix so a human session JWT is
/// NEVER mistaken for an API key (INV-1). Returns `None` when no API key
/// credential is present.
pub fn extract_api_key(headers: &HeaderMap) -> Option<String> {
    if let Some(value) = headers.get("X-API-Key")
        && let Ok(key) = value.to_str()
        && !key.is_empty()
    {
        return Some(key.to_string());
    }

    if let Some(value) = headers.get("Authorization")
        && let Ok(auth) = value.to_str()
        && auth.len() >= 7
        && auth[..7].eq_ignore_ascii_case("bearer ")
    {
        let token = &auth[7..];
        if token.starts_with(API_KEY_PREFIX) {
            return Some(token.to_string());
        }
    }

    None
}

/// Authenticate a raw API key against the database.
///
/// Fail-closed (INV-2): returns `Some((AuthUser, scopes))` only when the
/// key is found, `is_active`, not expired, and its owner is `is_active`.
/// The synthesized `AuthUser` carries `mfa_verified = true` because an API
/// key is a machine credential minted by an already-authenticated human,
/// not a human login ceremony. On success, `last_used_at`/`last_used_ip`
/// are updated best-effort.
pub async fn authenticate_api_key(
    state: &AppState,
    raw_key: &str,
    client_ip: Option<IpNetwork>,
) -> Option<(AuthUser, Vec<ApiKeyScope>)> {
    use crate::schema::{api_keys, users};

    let key_hash = ApiKey::hash_key(raw_key);
    let mut conn = state.db_pool.get().await.ok()?;

    let (key_id, scopes_json, expires_at, user_uuid, username, is_superuser, is_staff): (
        i32,
        serde_json::Value,
        Option<DateTime<Utc>>,
        Uuid,
        String,
        bool,
        bool,
    ) = api_keys::table
        .inner_join(users::table.on(users::id.eq(api_keys::user_id)))
        .filter(api_keys::key_hash.eq(&key_hash))
        .filter(api_keys::is_active.eq(true))
        .filter(users::is_active.eq(true))
        .filter(users::is_deleted.eq(false))
        .select((
            api_keys::id,
            api_keys::scopes,
            api_keys::expires_at,
            users::uuid,
            users::username,
            users::is_superuser,
            users::is_staff,
        ))
        .first(&mut conn)
        .await
        .optional()
        .ok()
        .flatten()?;

    // Expiry is fail-closed: an expired key never authenticates.
    if let Some(expires_at) = expires_at
        && expires_at < Utc::now()
    {
        return None;
    }

    let scopes = parse_scopes(&scopes_json);

    // Best-effort usage bookkeeping (never blocks authentication).
    let _ = diesel::update(api_keys::table.filter(api_keys::id.eq(key_id)))
        .set((
            api_keys::last_used_at.eq(Utc::now()),
            api_keys::last_used_ip.eq(client_ip),
        ))
        .execute(&mut conn)
        .await;

    let user = AuthUser {
        uuid: user_uuid.to_string(),
        username,
        mfa_verified: true,
        is_superuser,
        is_staff,
    };

    Some((user, scopes))
}

/// Map an API request to the scope it requires.
///
/// Coarse model (INV-3): the vault-secrets M2M zone (`/api/v1/vault*`)
/// requires the isolated `secrets` scope regardless of method; the admin
/// zone (`/api/v1/accounts*` and any `/assets/manage*` path) requires
/// `admin`; other mutations (POST/PUT/PATCH/DELETE) require `write`;
/// safe methods require `read`.
pub fn required_scope(method: &Method, path: &str) -> ApiKeyScope {
    // Checked BEFORE the method match: every verb on the vault zone maps
    // to `Secrets`, so even a hypothetical future mutation route could
    // never be reached with a mere `write`/`admin` key.
    if path.starts_with("/api/v1/vault") {
        return ApiKeyScope::Secrets;
    }
    if path.starts_with("/api/v1/accounts") || path.contains("/assets/manage") {
        return ApiKeyScope::Admin;
    }
    match *method {
        Method::GET | Method::HEAD | Method::OPTIONS => ApiKeyScope::Read,
        _ => ApiKeyScope::Write,
    }
}

/// Layer (mounted on the `/api/v1` router) that enforces the API key scope.
///
/// When the request was authenticated by an API key (an [`ApiKeyAuth`] is
/// present), the key must satisfy [`required_scope`] or the request is
/// rejected with `403`. When no API key is present this is a pass-through:
/// the downstream [`AuthUser`] extractor then produces the `401`.
pub async fn api_scope_enforcement(request: Request, next: Next) -> Response {
    if let Some(api_auth) = request.extensions().get::<ApiKeyAuth>().cloned() {
        let required = required_scope(request.method(), request.uri().path());
        if !api_auth.satisfies(required) {
            return AppError::Authorization(format!(
                "API key lacks required scope: {}",
                required.as_str()
            ))
            .into_response();
        }
    }
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderValue, Method};

    fn headers_with(name: &str, value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
        h
    }

    // ==================== extract_api_key ====================

    #[test]
    fn extract_from_x_api_key_header() {
        let h = headers_with("X-API-Key", "vbn_deadbeef");
        assert_eq!(extract_api_key(&h), Some("vbn_deadbeef".to_string()));
    }

    #[test]
    fn extract_from_bearer_with_vbn_prefix() {
        let h = headers_with("Authorization", "Bearer vbn_cafe1234");
        assert_eq!(extract_api_key(&h), Some("vbn_cafe1234".to_string()));
    }

    #[test]
    fn extract_bearer_is_case_insensitive_on_scheme() {
        for scheme in ["Bearer ", "bearer ", "BEARER "] {
            let h = headers_with("Authorization", &format!("{scheme}vbn_x"));
            assert_eq!(extract_api_key(&h), Some("vbn_x".to_string()));
        }
    }

    #[test]
    fn extract_rejects_jwt_bearer() {
        // A human JWT must never be mistaken for an API key (INV-1).
        let h = headers_with("Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig");
        assert_eq!(extract_api_key(&h), None);
    }

    #[test]
    fn extract_none_when_absent() {
        assert_eq!(extract_api_key(&HeaderMap::new()), None);
    }

    #[test]
    fn extract_none_on_empty_x_api_key() {
        let h = headers_with("X-API-Key", "");
        assert_eq!(extract_api_key(&h), None);
    }

    // ==================== required_scope ====================

    #[test]
    fn required_scope_read_on_safe_methods() {
        assert_eq!(
            required_scope(&Method::GET, "/api/v1/assets"),
            ApiKeyScope::Read
        );
        assert_eq!(
            required_scope(&Method::HEAD, "/api/v1/sessions"),
            ApiKeyScope::Read
        );
    }

    #[test]
    fn required_scope_write_on_mutations() {
        for m in [Method::POST, Method::PUT, Method::PATCH, Method::DELETE] {
            assert_eq!(
                required_scope(&m, "/api/v1/sessions"),
                ApiKeyScope::Write,
                "method {m} on a non-admin path must require write"
            );
        }
    }

    #[test]
    fn required_scope_admin_on_accounts_zone() {
        assert_eq!(
            required_scope(&Method::GET, "/api/v1/accounts"),
            ApiKeyScope::Admin
        );
        assert_eq!(
            required_scope(&Method::POST, "/api/v1/accounts"),
            ApiKeyScope::Admin
        );
    }

    #[test]
    fn required_scope_admin_on_manage_zone() {
        assert_eq!(
            required_scope(&Method::GET, "/api/v1/assets/manage/groups"),
            ApiKeyScope::Admin
        );
        assert_eq!(
            required_scope(&Method::POST, "/api/v1/assets/manage/"),
            ApiKeyScope::Admin
        );
    }

    // ==================== ApiKeyAuth::satisfies (hierarchy) ====================

    fn auth(scopes: &[ApiKeyScope]) -> ApiKeyAuth {
        ApiKeyAuth {
            scopes: scopes.to_vec(),
        }
    }

    #[test]
    fn admin_scope_satisfies_everything() {
        let a = auth(&[ApiKeyScope::Admin]);
        assert!(a.satisfies(ApiKeyScope::Read));
        assert!(a.satisfies(ApiKeyScope::Write));
        assert!(a.satisfies(ApiKeyScope::Admin));
    }

    #[test]
    fn write_scope_satisfies_read_and_write_not_admin() {
        let a = auth(&[ApiKeyScope::Write]);
        assert!(a.satisfies(ApiKeyScope::Read));
        assert!(a.satisfies(ApiKeyScope::Write));
        assert!(!a.satisfies(ApiKeyScope::Admin));
    }

    #[test]
    fn read_scope_satisfies_only_read() {
        let a = auth(&[ApiKeyScope::Read]);
        assert!(a.satisfies(ApiKeyScope::Read));
        assert!(!a.satisfies(ApiKeyScope::Write));
        assert!(!a.satisfies(ApiKeyScope::Admin));
    }

    #[test]
    fn empty_scopes_satisfy_nothing() {
        let a = auth(&[]);
        assert!(!a.satisfies(ApiKeyScope::Read));
        assert!(!a.satisfies(ApiKeyScope::Write));
        assert!(!a.satisfies(ApiKeyScope::Admin));
        assert!(!a.satisfies(ApiKeyScope::Secrets));
    }

    // ==================== Secrets isolation matrix ====================

    /// SECURITY: `secrets` is an island. Full cartesian matrix between
    /// the four scopes: only the literal `secrets` scope satisfies the
    /// `Secrets` requirement, and `secrets` satisfies nothing else.
    #[test]
    fn secrets_scope_is_isolated_from_hierarchy() {
        // No hierarchical scope satisfies Secrets -- not even admin.
        for granted in [ApiKeyScope::Read, ApiKeyScope::Write, ApiKeyScope::Admin] {
            assert!(
                !auth(&[granted]).satisfies(ApiKeyScope::Secrets),
                "{granted:?} must NOT satisfy Secrets"
            );
        }
        // Secrets satisfies only Secrets.
        let s = auth(&[ApiKeyScope::Secrets]);
        assert!(s.satisfies(ApiKeyScope::Secrets));
        assert!(!s.satisfies(ApiKeyScope::Read));
        assert!(!s.satisfies(ApiKeyScope::Write));
        assert!(!s.satisfies(ApiKeyScope::Admin));
    }

    /// A key carrying BOTH families keeps both capabilities (the union
    /// semantics of multi-scope keys is preserved).
    #[test]
    fn combined_secrets_and_read_key_satisfies_both() {
        let a = auth(&[ApiKeyScope::Secrets, ApiKeyScope::Read]);
        assert!(a.satisfies(ApiKeyScope::Secrets));
        assert!(a.satisfies(ApiKeyScope::Read));
        assert!(!a.satisfies(ApiKeyScope::Write));
    }

    #[test]
    fn required_scope_secrets_on_vault_zone_all_methods() {
        for m in [
            Method::GET,
            Method::HEAD,
            Method::OPTIONS,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
        ] {
            assert_eq!(
                required_scope(&m, "/api/v1/vault/secrets"),
                ApiKeyScope::Secrets,
                "method {m} on the vault zone must require the secrets scope"
            );
        }
        assert_eq!(
            required_scope(&Method::GET, "/api/v1/vault/secrets/abc/value"),
            ApiKeyScope::Secrets
        );
    }

    #[test]
    fn parse_scopes_defaults_to_read_for_non_array() {
        assert_eq!(
            parse_scopes(&serde_json::json!("nonsense")),
            vec![ApiKeyScope::Read]
        );
    }

    #[test]
    fn parse_scopes_drops_unknown_entries() {
        assert_eq!(
            parse_scopes(&serde_json::json!(["read", 42, "bogus", "admin"])),
            vec![ApiKeyScope::Read, ApiKeyScope::Admin]
        );
    }
}
