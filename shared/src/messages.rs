//! IPC message types for inter-process communication between Vauban services.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use zeroize::Zeroize;

/// A string wrapper for sensitive data transported via IPC.
///
/// `SensitiveString` provides three security properties:
/// - **Zeroize on drop**: the backing memory is overwritten with zeros when the
///   value goes out of scope, preventing credential remnants in freed memory.
/// - **Redacted Debug**: `format!("{:?}", val)` prints `[REDACTED]` instead of
///   the secret value, so credentials never leak through logging.
/// - **Transparent serde**: `#[serde(transparent)]` ensures bincode
///   serialization is byte-identical to a plain `String`, avoiding any IPC
///   protocol change.
///
/// This type is used exclusively inside `Message::SshSessionOpen` for the
/// credential fields (`password`, `private_key`, `passphrase`).
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SensitiveString(String);

impl SensitiveString {
    /// Create a new `SensitiveString` from a plain `String`.
    pub fn new(s: String) -> Self {
        Self(s)
    }

    /// Consume `self` and return the inner `String`.
    ///
    /// The caller takes ownership and responsibility for the secret material.
    /// Note: because `self` is consumed (not dropped), the destructor does
    /// **not** run -- the returned `String` must be consumed or zeroized by
    /// the caller.
    pub fn into_inner(self) -> String {
        // Use ManuallyDrop to prevent the Drop impl from zeroizing the
        // string we are about to hand out.
        let md = std::mem::ManuallyDrop::new(self);
        // SAFETY: we own the value and `ManuallyDrop` is repr(transparent).
        unsafe { std::ptr::read(&md.0) }
    }

    /// Borrow the inner string as `&str`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SensitiveString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[REDACTED]")
    }
}

impl Drop for SensitiveString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl PartialEq for SensitiveString {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl From<String> for SensitiveString {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for SensitiveString {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

/// Service identifier for routing messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Service {
    Supervisor,
    Web,
    Auth,
    Access,
    Vault,
    Audit,
    ProxySsh,
    ProxyRdp,
    /// IACS tunnel proxy. Hosts the russh sshd that EWS hosts connect
    /// to with `ssh -L`, and brokers the upstream TCP connection to
    /// the industrial asset (`asset.hostname:asset.port`) via the
    /// supervisor's SCM_RIGHTS broker. See
    /// `docs/technical/Vauban_IACS_Proxy_Architecture_EN(1.0).md`.
    ProxyIacs,
}

impl Service {
    /// Stable on-the-wire discriminant used by `shared::session_token` to
    /// bind a [`SessionToken`](crate::session_token::SessionToken) to its
    /// target service. Values MUST stay frozen across releases; appending
    /// a new service is fine, renumbering an existing one is a wire
    /// break.
    pub const fn as_token_discriminant(self) -> u8 {
        match self {
            Service::Supervisor => 0,
            Service::Web => 1,
            Service::Auth => 2,
            Service::Access => 3,
            Service::Vault => 4,
            Service::Audit => 5,
            Service::ProxySsh => 6,
            Service::ProxyRdp => 7,
            Service::ProxyIacs => 8,
        }
    }
}

/// Control messages between supervisor and services.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ControlMessage {
    /// Request to drain: stop accepting new requests.
    Drain,

    /// Response: service is now idle.
    DrainComplete { pending_requests: u32 },

    /// Heartbeat request from supervisor.
    Ping { seq: u64 },

    /// Heartbeat response from service.
    Pong { seq: u64, stats: ServiceStats },

    /// Immediate shutdown requested.
    Shutdown,
}

/// Service health statistics reported in Pong messages.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServiceStats {
    pub uptime_secs: u64,
    pub requests_processed: u64,
    pub requests_failed: u64,
    pub active_connections: u32,
    pub pending_requests: u32,
}

/// Authentication result from vauban-auth.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthResult {
    Success {
        user_id: String,
        session_id: String,
        roles: Vec<String>,
    },
    Failure {
        reason: String,
    },
    MfaRequired {
        challenge_id: String,
    },
}

/// RBAC authorization result from vauban-access.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RbacResult {
    pub allowed: bool,
    pub reason: Option<String>,
}

/// Outcome of an LDAP simple-bind performed by vauban-auth.
///
/// The web layer collapses every non-`Success` variant to a single generic
/// "invalid credentials" response to avoid account/directory enumeration
/// (SEC-04/05); the distinct variants exist only for internal logging.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LdapBindOutcome {
    /// Bind succeeded (LDAP resultCode 0).
    Success,
    /// Credentials rejected by the directory (resultCode 49) or any other
    /// bind-level rejection.
    InvalidCredentials,
    /// The directory could not be reached (broker / connect / timeout failure).
    Unreachable,
    /// TLS handshake or certificate validation failed.
    TlsError,
}

/// Access check result from vauban-access (instance-level authorization).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessCheckResult {
    pub allowed: bool,
    pub require_mfa: bool,
    pub require_approval: bool,
    pub max_session_duration: Option<i32>,
}

/// Single entry in a batch access check result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessCheckResultEntry {
    pub asset_group_id: i32,
    pub result: AccessCheckResult,
}

/// Entry describing which asset groups a user can access and with which protocols.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessibleGroupEntry {
    pub asset_group_id: i32,
    pub protocols: Vec<String>,
}

/// Data for creating or updating an access rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessRuleData {
    pub name: String,
    pub description: Option<String>,
    pub user_group_id: i32,
    pub asset_group_id: i32,
    pub allowed_protocols: Vec<String>,
    pub valid_from: Option<String>,
    pub valid_until: Option<String>,
    pub require_mfa: bool,
    pub require_approval: bool,
    pub max_session_duration: Option<i32>,
    pub is_active: bool,
    pub priority: i32,
}

/// Full info about an access rule (returned from queries).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessRuleInfo {
    pub uuid: String,
    pub name: String,
    pub description: Option<String>,
    pub user_group_id: i32,
    pub user_group_uuid: String,
    pub user_group_name: String,
    pub asset_group_id: i32,
    pub asset_group_uuid: String,
    pub asset_group_name: String,
    pub allowed_protocols: Vec<String>,
    pub valid_from: Option<String>,
    pub valid_until: Option<String>,
    pub require_mfa: bool,
    pub require_approval: bool,
    pub max_session_duration: Option<i32>,
    pub is_active: bool,
    pub priority: i32,
    pub created_at: String,
    pub updated_at: String,
}

/// Data for creating or updating a secret access rule (organisational
/// vault-secrets counterpart of [`AccessRuleData`]). Deliberately leaner:
/// no protocols, no MFA, no JIT approval, no session duration -- the
/// consumer is an M2M API key retrieving secret values, not a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretAccessRuleData {
    pub name: String,
    pub description: Option<String>,
    pub user_group_id: i32,
    pub secret_group_id: i32,
    /// Provenance dimension: the rule only grants when the M2M caller's
    /// source IP matches an identity-verified asset that is a member of
    /// this asset group (the virtual "All assets" group means "any known
    /// asset", never "any IP").
    pub asset_group_id: i32,
    pub valid_from: Option<String>,
    pub valid_until: Option<String>,
    pub is_active: bool,
    pub priority: i32,
}

/// Full info about a secret access rule (returned from queries).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretAccessRuleInfo {
    pub uuid: String,
    pub name: String,
    pub description: Option<String>,
    pub user_group_id: i32,
    pub user_group_uuid: String,
    pub user_group_name: String,
    pub secret_group_id: i32,
    pub secret_group_uuid: String,
    pub secret_group_name: String,
    pub asset_group_id: i32,
    pub asset_group_uuid: String,
    pub asset_group_name: String,
    /// `kind` of the provenance asset group (`static` / `all`); lets the
    /// admin UI compute the eclipse lint without extra round-trips.
    pub asset_group_kind: String,
    pub valid_from: Option<String>,
    pub valid_until: Option<String>,
    pub is_active: bool,
    pub priority: i32,
    pub created_at: String,
    pub updated_at: String,
}

/// Info about a vauban group (user group).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaubanGroupInfo {
    pub id: i32,
    pub uuid: String,
    pub name: String,
    pub description: Option<String>,
    pub source: String,
    pub external_id: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub last_synced: Option<String>,
    pub member_count: i64,
}

/// Reserved UUID of the singleton "All assets" virtual asset group.
///
/// Mnemonic: the suffix `…0a11` reads as "all". The row is seeded by the
/// `20260424000000_virtual_asset_group_all` migration with `kind = "all"`,
/// guarded by Postgres triggers (no membership rows, no mutation, no
/// deletion), and resolved at access-decision time to every non-deleted
/// asset (subject to the rule's `allowed_protocols` filter).
///
/// `vauban-access` and `vauban-web` both load the row's internal `id` once
/// at boot via `OnceLock` and fail loud if it is missing.
pub const ALL_ASSETS_GROUP_UUID: &str = "00000000-0000-0000-0000-000000000a11";

/// Marker value used by [`AssetGroupInfo::kind`] for ordinary user-managed
/// groups. The DB CHECK constraint pins the same vocabulary.
pub const ASSET_GROUP_KIND_STATIC: &str = "static";

/// Marker value used by [`AssetGroupInfo::kind`] for the virtual "All
/// assets" singleton.
pub const ASSET_GROUP_KIND_ALL: &str = "all";

/// Reserved UUID of the singleton "All secrets" virtual secret group.
///
/// Mnemonic: the suffix `…5ec4e7a11` reads as "secret all". The row is
/// seeded by the `20260711000000_vault_secrets` migration with
/// `kind = "all"`, guarded by Postgres triggers (no membership rows, no
/// mutation, no deletion), and resolved at access-decision time to every
/// active organisational secret.
pub const ALL_SECRETS_GROUP_UUID: &str = "00000000-0000-0000-0000-0005ec4e7a11";

/// Marker value used by [`SecretGroupInfo::kind`] for ordinary user-managed
/// secret groups. The DB CHECK constraint pins the same vocabulary.
pub const SECRET_GROUP_KIND_STATIC: &str = "static";

/// Marker value used by [`SecretGroupInfo::kind`] for the virtual "All
/// secrets" singleton.
pub const SECRET_GROUP_KIND_ALL: &str = "all";

/// Info about a secret group (organisational vault secrets).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretGroupInfo {
    pub id: i32,
    pub uuid: String,
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    /// Discriminator: [`SECRET_GROUP_KIND_STATIC`] for ordinary groups,
    /// [`SECRET_GROUP_KIND_ALL`] for the virtual "All secrets" singleton.
    #[serde(default = "default_secret_group_kind")]
    pub kind: String,
    pub created_at: String,
    pub updated_at: String,
    /// Number of secrets attached via `secret_secret_groups` (0 for the
    /// virtual group -- its semantics is "everything", not a list).
    pub member_count: i64,
}

fn default_secret_group_kind() -> String {
    SECRET_GROUP_KIND_STATIC.to_string()
}

/// Info about an asset group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetGroupInfo {
    pub id: i32,
    pub uuid: String,
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub color: String,
    pub icon: String,
    pub created_at: String,
    pub updated_at: String,
    /// Discriminator: [`ASSET_GROUP_KIND_STATIC`] for ordinary groups,
    /// [`ASSET_GROUP_KIND_ALL`] for the virtual "All assets" singleton.
    /// Defaulted via `serde(default)` so older serialized payloads still
    /// deserialize as static groups (forward-compatible IPC shape).
    #[serde(default = "default_asset_group_kind")]
    pub kind: String,
}

fn default_asset_group_kind() -> String {
    ASSET_GROUP_KIND_STATIC.to_string()
}

/// Minimal group info for form dropdowns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupOption {
    pub id: i32,
    pub uuid: String,
    pub name: String,
    /// Discriminator for ordinary user-managed groups
    /// ([`ASSET_GROUP_KIND_STATIC`]) vs. system-managed virtual groups
    /// (e.g. [`ASSET_GROUP_KIND_ALL`]). Defaulted via `serde(default)` so
    /// older payloads still deserialize as static groups.
    ///
    /// Only the access-rule editor's asset-group dropdown ever surfaces
    /// virtual groups (and renders a "Virtual" badge accordingly); every
    /// other dropdown caller leaves [`AccessRequest::ListAssetGroupOptions::include_virtual`]
    /// at its default `false` so virtual groups stay hidden.
    #[serde(default = "default_asset_group_kind")]
    pub kind: String,
}

/// Default page size for IPC list requests when `limit` is 0.
pub const DEFAULT_IPC_PAGE_LIMIT: u32 = 256;

/// Hard maximum rows per IPC list page (handlers clamp to this).
pub const MAX_IPC_PAGE_LIMIT: u32 = 1024;

/// Pagination parameters for IPC list requests (`limit` 0 means [`DEFAULT_IPC_PAGE_LIMIT`]).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct IpcPageParams {
    pub limit: u32,
    pub offset: u32,
}

/// One page of list results from vauban-access.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcPage<T> {
    pub items: Vec<T>,
    pub has_more: bool,
}

/// Decision kind for the JIT approval workflow. Pinned in `shared`
/// so every layer (vauban-access policy engine, vauban-web handlers,
/// templates) speaks the same vocabulary -- no string-typed dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalDecisionKind {
    Approve,
    Reject,
    /// Revoke an APPROVED grant (terminal): blocks new sessions
    /// instantly and lets the web layer cascade-terminate live ones.
    Revoke,
    /// Recompute an APPROVED grant's window: `expires_at =
    /// approved_at + duration`, in either direction (extend or
    /// shorten). Live sessions are clamped by the web layer, never
    /// extended.
    UpdateDuration,
}

impl ApprovalDecisionKind {
    /// Canonical SQL/text rendering used by the audit log's
    /// `decision` column and by structural pin tests.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Reject => "reject",
            Self::Revoke => "revoke",
            Self::UpdateDuration => "update_duration",
        }
    }
}

/// Structured reason returned when an approval is denied. Pinned in
/// `shared` (rather than a free-form `String`) so vauban-web can
/// surface a localised flash message and tests can pin every
/// adversarial path to a stable variant. The set is intentionally
/// closed: every new deny path forces an explicit Rust enum
/// addition + a Tier-2 IPC test update.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalDenyReason {
    /// The actor is the requester (separation-of-duties violation).
    /// Independently re-asserted by a CHECK constraint on
    /// `proxy_sessions` (`approved_by_id <> user_id` and the
    /// symmetric reject constraint) so even a malicious vauban-web
    /// or a raw psql session cannot bypass it.
    SelfApproval,
    /// The session is no longer in `status='pending'` (already
    /// approved, already rejected, expired, ...).
    SessionNotPending,
    /// The grant is not in `status='approved'` (pending, already
    /// revoked, expired, ...) -- returned by the post-approval verbs
    /// (revoke / update_duration), which only operate on live grants.
    SessionNotApproved,
    /// No `proxy_sessions` row matches the supplied UUID.
    SessionNotFound,
    /// The underlying `access_rules` row no longer requires
    /// approval (was edited or deleted between request and
    /// decision); the request is moot.
    RuleNoLongerRequiresApproval,
    /// The requester account has been disabled, soft-deleted, or
    /// otherwise made ineligible.
    RequesterDisabled,
}

impl ApprovalDenyReason {
    /// Human-readable label for flash messages and audit-log
    /// rendering. Not used as a primary key by callers (they
    /// `match` on the variant) but pinned for UI consistency.
    pub fn as_message(&self) -> &'static str {
        match self {
            Self::SelfApproval => {
                "You cannot decide on your own access request (separation of duties)"
            }
            Self::SessionNotPending => "This request has already been processed",
            Self::SessionNotApproved => "This grant is not active (already revoked or expired)",
            Self::SessionNotFound => "Request not found",
            Self::RuleNoLongerRequiresApproval => {
                "The underlying access rule no longer requires approval"
            }
            Self::RequesterDisabled => "The requester account is no longer active",
        }
    }
}

/// IACS / EWS onboarding decision kind. Pinned in `shared` so every
/// layer (vauban-access transactional decision, vauban-web handler,
/// templates) speaks the same vocabulary -- no string-typed dispatch.
///
/// Wire compatibility: append-only. Adding a variant requires a
/// downstream `match` update in `vauban-access` and a Casbin policy
/// review.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EwsDecisionKind {
    Approve,
    Reject,
}

impl EwsDecisionKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Reject => "reject",
        }
    }
}

/// Structured reason returned when an IACS / EWS write operation
/// (submit, edit, cancel, approve, reject, disable, enable, offboard)
/// is denied by the in-transaction re-check on the `vauban-access`
/// side. Pinned in `shared` so vauban-web can surface a localised
/// flash message and tests can pin every adversarial path to a stable
/// variant.
///
/// Wire compatibility: append-only. Every new deny path forces an
/// explicit Rust enum addition + a Tier-2 IPC test update.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EwsDenyReason {
    /// The supplied UUID does not match any `ews_onboarding_requests`
    /// row.
    RequestNotFound,
    /// The supplied UUID does not match any `ews` row.
    EwsNotFound,
    /// The request is no longer in `status='pending'` (already
    /// approved, rejected, or cancelled). Edit / cancel / decide all
    /// share this denial.
    RequestNotPending,
    /// The EWS row is already offboarded (irreversible). Disable /
    /// enable / offboard reject; only the audit trail can still be
    /// read.
    EwsAlreadyOffboarded,
    /// The fingerprint is currently locked by another active or
    /// disabled EWS row, OR by another pending request the actor
    /// did not own. Surface verbatim in the form so the requester
    /// rotates their key.
    KeyAlreadyUsed,
    /// The requester already owns `industrial.max_ews_per_user`
    /// active or pending EWS rows. The cap is enforced inside the
    /// `SubmitEwsOnboarding` transaction.
    MaxEwsPerUserReached,
    /// Caller cannot mutate this resource (e.g. user trying to edit
    /// or cancel another user's pending request, or auto-offboard an
    /// EWS that is not theirs). Anti-enumeration: the handler should
    /// collapse this into a 404.
    NotOwner,
    /// The user account referenced by the request / EWS has been
    /// disabled or soft-deleted between the time the row was created
    /// and the decision; the operation is moot.
    TargetUserDisabled,
}

impl EwsDenyReason {
    /// Human-readable label for flash messages. Not used as a primary
    /// key by callers (they `match` on the variant) but pinned for UI
    /// consistency.
    pub fn as_message(&self) -> &'static str {
        match self {
            Self::RequestNotFound => "Onboarding request not found",
            Self::EwsNotFound => "EWS not found",
            Self::RequestNotPending => "This request has already been processed",
            Self::EwsAlreadyOffboarded => {
                "This EWS has already been offboarded; offboarding is irreversible"
            }
            Self::KeyAlreadyUsed => {
                "This SSH public key is already registered against another active EWS"
            }
            Self::MaxEwsPerUserReached => {
                "You have reached the maximum number of EWS allowed per user"
            }
            Self::NotOwner => "You cannot perform this action on another user's resource",
            Self::TargetUserDisabled => "The target user account is no longer active",
        }
    }
}

/// Caller intent for `AccessRequest::VerifySessionAccess`. Advisory
/// for the policy decision (each variant returns the same instance-
/// level decision); used by vauban-access for structured audit logs
/// and by vauban-web's `services::session_access::verify` to layer
/// the right Casbin OR-override on top of the response.
///
/// Wire compatibility: append-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionAccessIntent {
    /// User opens a viewer page (`GET /sessions/terminal/{uuid}` or
    /// `GET /sessions/rdp/{uuid}`). Casbin OR-override:
    /// `sessions:supervise`.
    OpenViewer,
    /// WebSocket upgrade (`/ws/terminal/{uuid}`, `/ws/rdp/{uuid}`,
    /// `/ws/session/{uuid}`). Casbin OR-override: `sessions:supervise`.
    ConsumeWs,
    /// JSON metadata read (`GET /api/v1/sessions/{uuid}` or session
    /// detail page). Casbin OR-override: `sessions:supervise`.
    ReadMetadata,
    /// Termination request (`POST /sessions/{uuid}/terminate`, web or
    /// API). Casbin OR-override: `sessions:write`.
    Terminate,
}

/// Reason a `VerifySessionAccess` request was denied. The vauban-web
/// service collapses these into either `404` (NotFound, NotOwner,
/// AccessRuleRevoked - anti-enumeration) or `410` (Gone) so the
/// client cannot fingerprint the bastion.
///
/// Wire compatibility: append-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionDenialReason {
    /// No `proxy_sessions` row matches the supplied UUID.
    NotFound,
    /// Session exists but is in a non-connectable status
    /// (`terminated`, `expired`, or `disconnected`).
    Gone,
    /// Session exists but `proxy_sessions.user_id` does not match the
    /// requesting user. The Casbin OR-override may still grant access
    /// upstream (vauban-web layer).
    NotOwner,
    /// Session exists and is owned by the caller, but the access rule
    /// that originally authorised the (user, asset, protocol) tuple
    /// is no longer applicable (deactivated, expired, not yet valid,
    /// or protocol mismatch). Fail-fast guarantees a revoked rule
    /// stops a session at the next page-load or WS handshake.
    AccessRuleRevoked,
}

/// Authoritative instance-level decision returned by vauban-access for
/// `AccessRequest::VerifySessionAccess`.
///
/// Wire compatibility: append-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionAccessDecision {
    Allowed,
    Denied(SessionDenialReason),
}

/// Access control request sent to vauban-access.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AccessRequest {
    CheckAccess {
        user_id: i32,
        asset_group_id: i32,
        protocol: String,
    },
    ListAccessibleGroups {
        user_id: i32,
        page: IpcPageParams,
    },

    CreateAccessRule {
        data: AccessRuleData,
        /// Issue #22 — caller's UUID (from the JWT `sub` claim) used
        /// to populate `created_by_id` / `updated_by_id` on the new
        /// row. `None` falls back to the muted em-dash on the
        /// Metadata UI; vauban-access NEVER refuses a write because
        /// of a missing or unresolvable actor.
        #[serde(default)]
        actor_uuid: Option<String>,
    },
    GetAccessRule {
        uuid: String,
    },
    ListAccessRules {
        page: IpcPageParams,
    },
    UpdateAccessRule {
        uuid: String,
        data: AccessRuleData,
        /// Issue #22 — see `CreateAccessRule.actor_uuid`. Re-stamps
        /// `updated_by_id` on every successful update.
        #[serde(default)]
        actor_uuid: Option<String>,
    },
    DeleteAccessRule {
        uuid: String,
    },

    CreateVaubanGroup {
        name: String,
        description: Option<String>,
    },
    GetVaubanGroup {
        uuid: String,
    },
    GetVaubanGroupById {
        id: i32,
    },
    ListVaubanGroups {
        page: IpcPageParams,
    },
    UpdateVaubanGroup {
        uuid: String,
        name: String,
        description: Option<String>,
    },
    DeleteVaubanGroup {
        uuid: String,
    },

    AddGroupMember {
        group_id: i32,
        user_id: i32,
    },
    RemoveGroupMember {
        group_id: i32,
        user_id: i32,
    },
    ListGroupMembers {
        group_id: i32,
        page: IpcPageParams,
    },
    ListUserGroups {
        user_id: i32,
        page: IpcPageParams,
    },

    CreateAssetGroup {
        name: String,
        slug: String,
        description: Option<String>,
        color: String,
        icon: String,
        /// Issue #22 — see `CreateAccessRule.actor_uuid`.
        #[serde(default)]
        actor_uuid: Option<String>,
    },
    GetAssetGroup {
        uuid: String,
    },
    ListAssetGroups {
        page: IpcPageParams,
        /// When `true`, virtual asset groups (e.g. "All assets") are
        /// included in the result alongside ordinary static groups; only
        /// the access-rule editor opts in. Every other call site (asset-
        /// group index, dropdowns scoped to user-managed groups, etc.)
        /// must leave this `false`.
        ///
        /// `serde(default)` keeps older serialized payloads compatible.
        #[serde(default)]
        include_virtual: bool,
    },
    UpdateAssetGroup {
        uuid: String,
        name: String,
        slug: String,
        description: Option<String>,
        color: String,
        icon: String,
        /// Issue #22 — re-stamps `updated_by_id` on every
        /// successful update. See `CreateAccessRule.actor_uuid`.
        #[serde(default)]
        actor_uuid: Option<String>,
    },
    DeleteAssetGroup {
        uuid: String,
    },

    ListUserGroupOptions {
        page: IpcPageParams,
    },
    ListAssetGroupOptions {
        page: IpcPageParams,
        /// When `true`, virtual asset groups (e.g. "All assets") are
        /// included in the dropdown payload alongside ordinary static
        /// groups. Only the access-rule create/edit editor opts in.
        ///
        /// `serde(default)` keeps older callers binary-compatible.
        #[serde(default)]
        include_virtual: bool,
    },

    CheckAccessMulti {
        user_id: i32,
        asset_group_ids: Vec<i32>,
        protocol: String,
    },

    /// SECURITY: UUID-addressed authorization check for callers that have no
    /// database access (e.g. `vauban-proxy-ssh` running under Capsicum, which
    /// receives `Message::SshSessionOpen { user_id: <uuid>, asset_id: <uuid> }`
    /// directly from `vauban-web` and must re-verify the request before
    /// opening the upstream SSH connection -- defense-in-depth so a
    /// compromised vauban-web cannot single-handedly authorise an SSH
    /// session). vauban-access resolves the UUIDs to internal `i32` ids and
    /// then runs the same `CheckAccess` policy as the i32-addressed verb.
    /// Fail-closed: any DB lookup error or unknown UUID yields
    /// `AccessChecked { allowed: false }`.
    ///
    /// MUST stay near the END of this enum to preserve the bincode
    /// discriminant indices of the existing variants (wire compatibility
    /// with already deployed peers). New variants must be appended after
    /// this one rather than inserted in the middle.
    CheckAccessByUuid {
        user_uuid: String,
        asset_uuid: String,
        protocol: String,
    },

    /// SECURITY: Mint a cryptographic session token attesting that
    /// vauban-access has just authorised the (user, asset, protocol,
    /// host, port, target_service, session_id) tuple. The supervisor
    /// will verify the token before performing the TCP connect, and
    /// the proxy will verify it before invoking
    /// `shared::access_guard::AccessGuard::authorize`.
    ///
    /// Issued by vauban-web on the session-open path, after Layer 1
    /// (`CheckAccess`) succeeds. The handler in vauban-access re-runs
    /// the same policy as `CheckAccessByUuid` then mints a
    /// `shared::session_token::SessionToken` (BLAKE3 keyed MAC). The
    /// caller MUST treat any non-`SessionTokenIssued` response as a
    /// fail-closed denial.
    ///
    /// Wire compatibility: appended after `CheckAccessByUuid`. New
    /// variants MUST keep being appended at the end.
    IssueSessionToken {
        user_uuid: String,
        asset_uuid: String,
        protocol: String,
        host: String,
        port: u16,
        target_service: Service,
        session_id: String,
    },

    /// SECURITY: Pre-flight eligibility check for an admin about to
    /// approve or reject a JIT access request. Pure read; no DB write.
    ///
    /// Centralises the policy decision so handlers in `vauban-web` only
    /// surface the structured `ApprovalDenyReason` and never duplicate
    /// the rule logic. The same checks are re-run inside the
    /// `RecordApprovalDecision` transaction (TOCTOU defense) so a
    /// successful eligibility response is purely advisory and never
    /// authoritative.
    ///
    /// Wire compatibility: appended after `IssueSessionToken`. New
    /// variants MUST keep being appended at the end.
    CheckApprovalEligibility {
        actor_user_uuid: String,
        session_uuid: String,
    },

    /// SECURITY: Atomically persist an approval/rejection decision for
    /// a pending session AND insert the matching append-only row in
    /// `approval_audit_log`. Both operations run in a single Diesel
    /// transaction; any sub-step failure rolls back the whole thing
    /// and leaves the session in `pending` (no half-state, no orphan
    /// audit row, fail-closed).
    ///
    /// `decision_ip` MUST already be the trusted-proxy-resolved IP
    /// (callers should pass the value produced by
    /// `vauban_web::middleware::resolve_client_ip`); `vauban-access`
    /// has no way to re-derive it.
    ///
    /// Wire compatibility: appended after `CheckApprovalEligibility`.
    RecordApprovalDecision {
        actor_user_uuid: String,
        session_uuid: String,
        decision: ApprovalDecisionKind,
        /// Approve-only; ignored when `decision == Reject`. When
        /// `Some`, replaces the value originally copied from the
        /// access rule. `None` keeps the existing value untouched.
        duration_override_seconds: Option<i32>,
        decision_reason: Option<String>,
        decision_ip: Option<String>,
        decision_user_agent: Option<String>,
        request_id: Option<String>,
    },

    /// SECURITY: Instance-level authorization for callers that already
    /// hold a `proxy_sessions.uuid` and want to consume it (HTML viewer
    /// page, WebSocket upgrade, JSON metadata read, terminate). vauban-
    /// access combines (a) session existence + connectable status, (b)
    /// ownership of the session by the caller, and (c) re-evaluation of
    /// the matching access rule (`is_active`, `valid_from`,
    /// `valid_until`, protocol coverage) against the asset of the
    /// session. All callers that touch an existing proxy_session MUST
    /// route through this RPC -- direct DB lookups in vauban-web are
    /// forbidden by the `check_session_access_centralized.sh` lint.
    ///
    /// `intent` is purely advisory for vauban-access (used in audit
    /// logs); the actual decision is identical for all four variants
    /// because Casbin permissions like `sessions:supervise` /
    /// `sessions:write` are combined with the response on the
    /// vauban-web side via `services::session_access::verify`.
    ///
    /// Wire compatibility: appended after `RecordApprovalDecision`. New
    /// variants MUST keep being appended at the end.
    VerifySessionAccess {
        session_uuid: String,
        requesting_user_uuid: String,
        intent: SessionAccessIntent,
    },

    /// SECURITY: Mint a session-token-shaped credential for a strictly
    /// READ-ONLY diagnostic operation that does NOT open an actual SSH
    /// session (today: SSH host-key verify and admin host-key fetch).
    ///
    /// The wire format and crypto match `IssueSessionToken` (same MAC
    /// key, same anti-replay nonce, same `target_service`/`session_id`
    /// bindings) so the supervisor's TCP broker and the proxy's
    /// session-token gate accept it without modification. What changes
    /// is the AUTHORISATION step on the vauban-access side:
    ///
    /// - `IssueSessionToken` re-runs `CheckAccessByUuid` (user must
    ///   match an active access rule for the asset/protocol).
    /// - `IssueDiagnosticToken` skips the access-rule re-check and
    ///   gates ONLY on `caller_has_assets_manage = true`. Pre-issue
    ///   #34 the host-key verify/fetch path used the session-token
    ///   verb, which silently denied admins that did not happen to
    ///   have an explicit access rule for the asset; the verify
    ///   endpoint then fell back to a green "Verified" fragment based
    ///   on the stored fingerprint, hiding the fact that nothing was
    ///   live-verified. See `docs/technical/Vauban_AccessGuard_
    ///   Architecture_EN(1.0).md` §3 for the contract.
    ///
    /// `caller_has_assets_manage` MUST be sourced from the request-
    /// scoped `PermissionContext` (Casbin) on the vauban-web side; we
    /// pass it explicitly because vauban-access does not own the
    /// Casbin enforcer. A compromised vauban-web is contained by the
    /// rest of the AccessGuard chain (TCP broker token check, proxy
    /// `AccessGuard::authorize`).
    ///
    /// Wire compatibility: appended after `VerifySessionAccess`. New
    /// variants MUST keep being appended at the end.
    IssueDiagnosticToken {
        user_uuid: String,
        asset_uuid: String,
        protocol: String,
        host: String,
        port: u16,
        target_service: Service,
        session_id: String,
        caller_has_assets_manage: bool,
    },

    // ===================================================================
    // IACS / EWS onboarding -- atomic decisions executed in vauban-access.
    //
    // Every variant runs in a `SERIALIZABLE` Diesel transaction with
    // automatic 40001 retry, mirrors the JIT `RecordApprovalDecision`
    // pattern, and inserts the matching `ews_audit_log` row in the same
    // transaction so the audit trail can never drift from the business
    // state. The PostgreSQL `block_ews_audit_log_mutation` trigger pins
    // the append-only contract at the lowest layer.
    //
    // Anti-enumeration: every "not yours" denial collapses to
    // `EwsDenyReason::NotOwner` (handler turns it into 404).
    //
    // Wire compatibility: appended after `IssueDiagnosticToken`. New
    // variants MUST keep being appended at the end.
    // ===================================================================
    /// Submit a new EWS onboarding request. Validates uniqueness of the
    /// fingerprint inside the transaction (TOCTOU defense), enforces
    /// `max_ews_per_user` if non-zero, snapshots the actor for the
    /// `submitted` audit row.
    SubmitEwsOnboarding {
        actor_user_uuid: String,
        name: String,
        public_key: String,
        public_key_fingerprint: String,
        key_algo: String,
        justification: String,
        /// Mirror of `config.industrial.max_ews_per_user`. `0` means no
        /// cap. Passed explicitly so `vauban-access` does not need to
        /// own the TOML config; a compromised vauban-web is contained
        /// by the rest of the audit chain.
        max_ews_per_user: u32,
        actor_ip: Option<String>,
    },

    /// Edit a pending request the actor owns. The CHECK constraint
    /// `ews_request_decision_consistency` and an in-transaction
    /// `status = 'pending' AND user_id = actor` re-check defend
    /// against TOCTOU concurrent decision.
    EditEwsRequest {
        actor_user_uuid: String,
        request_uuid: String,
        name: String,
        public_key: String,
        public_key_fingerprint: String,
        key_algo: String,
        justification: String,
        actor_ip: Option<String>,
    },

    /// Cancel a pending request the actor owns. Soft transition to
    /// `status='cancelled'` (the row stays for audit; a fresh
    /// re-submission is a NEW row).
    CancelEwsRequest {
        actor_user_uuid: String,
        request_uuid: String,
        actor_ip: Option<String>,
    },

    /// Persist an admin's approval / rejection decision on a pending
    /// request AND insert the matching `ews_audit_log` row. On
    /// approve, also creates the `ews` row in the same transaction;
    /// on reject, requires `decision_reason` (validated server-side).
    RecordEwsDecision {
        actor_user_uuid: String,
        request_uuid: String,
        decision: EwsDecisionKind,
        /// Mandatory when `decision == Reject`; ignored otherwise.
        decision_reason: Option<String>,
        actor_ip: Option<String>,
    },

    /// Suspend an active EWS (reversible). Disabling does NOT release
    /// the public-key fingerprint -- only offboarding does (see
    /// `OffboardEws`). The `ews_audit_log` row carries `event='disabled'`.
    DisableEws {
        actor_user_uuid: String,
        ews_uuid: String,
        actor_ip: Option<String>,
    },

    /// Re-enable a disabled EWS. The `ews_audit_log` row carries
    /// `event='enabled'`.
    EnableEws {
        actor_user_uuid: String,
        ews_uuid: String,
        actor_ip: Option<String>,
    },

    /// Offboard an EWS (irreversible soft-delete). Releases the
    /// fingerprint so the user can re-submit the same key on a fresh
    /// onboarding request. The hook `terminate_ssh_tunnels_for_ews`
    /// is invoked from the same transaction (no-op stub for this
    /// preliminary iteration; long-running SSH tunnels from the EWS
    /// to Vauban will arrive with the IACS asset feature).
    ///
    /// `on_behalf_of_self == true` means the user is auto-offboarding
    /// their own EWS via `/iacs/{uuid}/offboard-self` (gated on
    /// `iacs_request`); `false` means an admin offboard via
    /// `/iacs/{uuid}/offboard` (gated on `iacs_manage`). Both write
    /// the same audit row but the `decision_reason` defaults differ.
    OffboardEws {
        actor_user_uuid: String,
        ews_uuid: String,
        on_behalf_of_self: bool,
        decision_reason: Option<String>,
        actor_ip: Option<String>,
    },

    // ===================================================================
    // Organisational vault secrets -- group-to-group access control,
    // 100% parallel to the asset machinery (secret_groups /
    // secret_secret_groups / secret_access_rules). vauban-access is the
    // single evaluation oracle; vauban-web NEVER evaluates
    // secret_access_rules in SQL.
    //
    // Wire compatibility: appended after `OffboardEws`. New variants
    // MUST keep being appended at the end.
    // ===================================================================
    /// Create a static secret group. `kind` is always forced to
    /// `static` server-side; the virtual "All secrets" singleton is
    /// seeded by migration only.
    CreateSecretGroup {
        name: String,
        slug: String,
        description: Option<String>,
        /// Issue #22 — see `CreateAccessRule.actor_uuid`.
        #[serde(default)]
        actor_uuid: Option<String>,
    },
    GetSecretGroup {
        uuid: String,
    },
    ListSecretGroups {
        page: IpcPageParams,
        /// When `true`, the virtual "All secrets" group is included in
        /// the result alongside ordinary static groups; only the
        /// secret-access-rule editor opts in.
        #[serde(default)]
        include_virtual: bool,
    },
    UpdateSecretGroup {
        uuid: String,
        name: String,
        slug: String,
        description: Option<String>,
        #[serde(default)]
        actor_uuid: Option<String>,
    },
    DeleteSecretGroup {
        uuid: String,
    },
    ListSecretGroupOptions {
        page: IpcPageParams,
        /// See `ListSecretGroups.include_virtual`.
        #[serde(default)]
        include_virtual: bool,
    },

    CreateSecretAccessRule {
        data: SecretAccessRuleData,
        #[serde(default)]
        actor_uuid: Option<String>,
    },
    GetSecretAccessRule {
        uuid: String,
    },
    ListSecretAccessRules {
        page: IpcPageParams,
    },
    UpdateSecretAccessRule {
        uuid: String,
        data: SecretAccessRuleData,
        #[serde(default)]
        actor_uuid: Option<String>,
    },
    DeleteSecretAccessRule {
        uuid: String,
    },

    /// Bulk list-filter primitive: which secret groups can `user_id`
    /// access right now, calling from `source_asset_id`? Same two-phase
    /// pattern as `ListAccessibleGroups`: vauban-access returns the
    /// accessible `secret_groups.id` values (with the virtual singleton
    /// resolved server-side to a dedicated marker entry), and vauban-web
    /// joins them to concrete secret ids locally.
    ///
    /// `source_asset_id` is the identity-verified asset the M2M caller
    /// was matched to (provenance). Only rules whose `asset_group_id`
    /// contains that asset (or the virtual "All assets" group) count.
    ListAccessibleSecretGroups {
        user_id: i32,
        source_asset_id: i32,
        page: IpcPageParams,
    },

    /// Unit check before revealing one secret's value: does an active
    /// secret_access_rule (valid window, active flag, virtual group
    /// included) cover `(user_uuid, secret_uuid)` for a call originating
    /// from `source_asset_id`? Fail-closed: any DB lookup error or
    /// unknown UUID yields `allowed: false`. There is deliberately NO
    /// Casbin/read_all bypass here: even a superuser must be covered by
    /// a rule.
    CheckSecretAccessByUuid {
        user_uuid: String,
        secret_uuid: String,
        source_asset_id: i32,
    },
}

/// Access control response from vauban-access.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AccessResponse {
    AccessChecked(AccessCheckResult),
    AccessibleGroupsPage(IpcPage<AccessibleGroupEntry>),

    AccessRule(Result<AccessRuleInfo, String>),
    AccessRulePage(IpcPage<AccessRuleInfo>),

    VaubanGroup(Result<VaubanGroupInfo, String>),
    VaubanGroupPage(IpcPage<VaubanGroupInfo>),

    MemberListPage(IpcPage<i32>),
    UserGroupPage(IpcPage<VaubanGroupInfo>),

    AssetGroup(Result<AssetGroupInfo, String>),
    AssetGroupPage(IpcPage<AssetGroupInfo>),

    UserGroupOptionsPage(IpcPage<GroupOption>),
    AssetGroupOptionsPage(IpcPage<GroupOption>),

    Ok,
    Deleted(Result<(), String>),
    Error(String),

    AccessCheckedMulti(Vec<AccessCheckResultEntry>),

    /// Successful response to `AccessRequest::IssueSessionToken`. The
    /// payload is the bincode-serialized `shared::session_token::SessionToken`
    /// (kept as `Vec<u8>` so the wire-format module sits cleanly behind
    /// its own feature flag and `messages.rs` does not need to depend on
    /// the crypto stack).
    SessionTokenIssued {
        token: Vec<u8>,
    },

    /// Fail-closed reply to `AccessRequest::IssueSessionToken`. Returned
    /// either when the policy denies the request or when token minting
    /// fails for any reason (DB error, malformed UUID, key not loaded,
    /// ...). The caller MUST surface the same generic "Access denied"
    /// reply regardless of the underlying cause -- distinguishing
    /// "policy denied" from "minter is broken" would let a probe
    /// fingerprint the bastion.
    SessionTokenDenied,

    /// Reply to `AccessRequest::CheckApprovalEligibility`. When
    /// `allowed == true`, `reason` is `None`; otherwise `reason`
    /// names the structured deny cause (separation of duties,
    /// session not pending, ...). Advisory only -- the authoritative
    /// re-check happens inside `RecordApprovalDecision`'s transaction.
    ///
    /// Wire compatibility: appended after `SessionTokenDenied`.
    ApprovalEligibility {
        allowed: bool,
        reason: Option<ApprovalDenyReason>,
    },

    /// Successful reply to `AccessRequest::RecordApprovalDecision`.
    /// `audit_log_id` is the primary key of the freshly inserted
    /// `approval_audit_log` row, useful for cross-referencing with
    /// the HTTP request_id at the call site.
    ApprovalRecorded {
        audit_log_id: i64,
    },

    /// Fail-closed reply to `AccessRequest::RecordApprovalDecision`.
    /// Returned when the in-transaction re-check denies (e.g. the
    /// session was approved by a peer in the meantime, or the
    /// requester removed the rule, or the actor is the requester).
    /// The session remains in its previous state.
    ApprovalDenied {
        reason: ApprovalDenyReason,
    },

    /// Reply to `AccessRequest::VerifySessionAccess`. The decision is
    /// authoritative for the instance-level slice (existence, status,
    /// ownership, access-rule). vauban-web layers the Casbin
    /// `sessions:supervise` / `sessions:write` OR-overrides on top.
    ///
    /// Wire compatibility: appended after `ApprovalDenied`.
    SessionAccessChecked {
        decision: SessionAccessDecision,
    },

    // ===================================================================
    // IACS / EWS onboarding replies. Wire compatibility: appended at
    // the end. Each variant pairs with one or more `AccessRequest`
    // siblings (above). On any in-transaction re-check failure, the
    // reply is `EwsDecisionDenied { reason }`; success replies carry
    // the freshly-inserted `audit_log_id` so vauban-web can cross-
    // reference with the HTTP request_id.
    // ===================================================================
    /// Successful reply to `SubmitEwsOnboarding`.
    EwsRequestSubmitted {
        request_uuid: String,
        audit_log_id: i64,
    },
    /// Successful reply to `EditEwsRequest`.
    EwsRequestEdited {
        audit_log_id: i64,
    },
    /// Successful reply to `CancelEwsRequest`.
    EwsRequestCancelled {
        audit_log_id: i64,
    },
    /// Successful reply to `RecordEwsDecision`. `ews_uuid` is `Some`
    /// on Approve (the freshly-created `ews` row) and `None` on
    /// Reject.
    EwsDecisionRecorded {
        audit_log_id: i64,
        ews_uuid: Option<String>,
    },
    /// Successful reply to `DisableEws`, `EnableEws`, and `OffboardEws`.
    EwsStateChanged {
        audit_log_id: i64,
    },
    /// Fail-closed reply for every IACS write operation. The session/
    /// EWS row remains in its previous state.
    EwsDecisionDenied {
        reason: EwsDenyReason,
    },

    // ===================================================================
    // Organisational vault secrets replies. Wire compatibility:
    // appended at the end.
    // ===================================================================
    SecretGroup(Result<SecretGroupInfo, String>),
    SecretGroupPage(IpcPage<SecretGroupInfo>),
    SecretGroupOptionsPage(IpcPage<GroupOption>),

    SecretAccessRule(Result<SecretAccessRuleInfo, String>),
    SecretAccessRulePage(IpcPage<SecretAccessRuleInfo>),

    /// Reply to `ListAccessibleSecretGroups`. Entries carry the
    /// accessible secret-group ids; when a rule targets the virtual
    /// "All secrets" group, its entry is [`AccessibleSecretGroupEntry`]
    /// with `is_virtual_all == true` (vauban-web then resolves it to
    /// every active secret).
    AccessibleSecretGroupsPage(IpcPage<AccessibleSecretGroupEntry>),

    /// Reply to `CheckSecretAccessByUuid`. Fail-closed boolean.
    SecretAccessChecked {
        allowed: bool,
    },
}

/// Entry describing one secret group a user can access.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct AccessibleSecretGroupEntry {
    pub secret_group_id: i32,
    /// `true` when this entry is the virtual "All secrets" singleton:
    /// the caller must resolve it to every active secret instead of
    /// joining `secret_secret_groups`.
    pub is_virtual_all: bool,
}

/// Seed user data for admin commands.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeedUser {
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub is_superuser: bool,
    pub is_staff: bool,
}

/// Seed asset data for admin commands.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeedAsset {
    pub name: String,
    pub hostname: String,
    pub port: i32,
    pub asset_type: String,
    pub group_id: Option<i32>,
    pub description: Option<String>,
}

/// Seed session data for admin commands.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeedSession {
    pub user_id: i32,
    pub asset_id: i32,
    pub session_type: String,
}

/// Unencrypted secret entry returned by ListUnencryptedSecrets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnencryptedSecretEntry {
    pub entry_type: String,
    pub id: i32,
    pub value: String,
}

/// Admin command sent to services via IPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AdminCommand {
    CreateUser {
        username: String,
        email: String,
        password_hash: String,
        is_superuser: bool,
        is_staff: bool,
    },
    ResetPassword {
        username: String,
        password_hash: String,
    },
    ResetMfa {
        username: String,
    },
    ListUnencryptedSecrets,
    UpdateUserMfaSecret {
        user_id: i32,
        encrypted_secret: String,
    },
    UpdateAssetConnectionConfig {
        asset_id: i32,
        encrypted_config: String,
    },
    SeedUsers {
        users: Vec<SeedUser>,
    },
    SeedAssets {
        assets: Vec<SeedAsset>,
    },
    SeedSessions {
        sessions: Vec<SeedSession>,
    },
}

/// Admin command response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AdminResponse {
    Ok,
    Created { uuid: String },
    UnencryptedSecrets(Vec<UnencryptedSecretEntry>),
    Error(String),
}

/// Audit event types for vauban-audit.
///
/// Wire format: bincode serializes a fieldless enum by its variant INDEX, so
/// NEW variants MUST be appended at the END (never inserted/reordered) to keep
/// already-persisted WORM records and in-flight messages decodable.
/// [`AuditEventType::category`] is an exhaustive match (no `_` arm) so a new
/// variant fails to compile until it is classified; [`AuditEventType::COUNT`]
/// + the `audit_event_type_count_is_pinned` drift test pin the cardinality.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditEventType {
    // ---- auth (indices 0-1 frozen: emitted by proxy-ssh / web) ----
    AuthSuccess,
    AuthFailure,
    SessionStart,
    SessionEnd,
    CommandExecuted,
    AccessDenied,
    PolicyChange,
    // ---- appended for VAU-003 (broad web instrumentation) ----
    Logout,
    // MFA
    MfaEnrolled,
    MfaReset,
    MfaChallengePassed,
    MfaChallengeFailed,
    // sessions (web-side authorization decisions)
    SessionRequested,
    SessionTerminated,
    // user management
    UserCreated,
    UserUpdated,
    UserDeleted,
    UserActivated,
    UserDeactivated,
    RoleChanged,
    PasswordChanged,
    // access rules
    AccessRuleCreated,
    AccessRuleUpdated,
    AccessRuleDeleted,
    // user groups
    GroupCreated,
    GroupUpdated,
    GroupDeleted,
    GroupMemberAdded,
    GroupMemberRemoved,
    // asset groups
    AssetGroupCreated,
    AssetGroupUpdated,
    AssetGroupDeleted,
    AssetGroupMemberAdded,
    AssetGroupMemberRemoved,
    // assets
    AssetCreated,
    AssetUpdated,
    AssetDeleted,
    // JIT approvals
    ApprovalRequested,
    ApprovalGranted,
    ApprovalDenied,
    ApprovalCancelled,
    // ---- appended for VAU-008 (MFA setup hardening) ----
    // A TOTP secret was (re)generated during MFA setup (POST /mfa/setup/init,
    // CSRF + password step-up gated). Distinct from `MfaEnrolled`, which marks
    // the user confirming a valid code. Appended at the end to keep existing
    // wire discriminants stable.
    MfaSecretGenerated,
    // ---- appended for JIT grant revocation (post-approval verbs) ----
    // An APPROVED grant was revoked by an admin (terminal state; live
    // sessions are cascade-terminated). Appended at the end to keep
    // existing wire discriminants stable.
    ApprovalRevoked,
    // An APPROVED grant's window was recomputed (extend or shorten).
    ApprovalDurationUpdated,
    // ---- appended for organisational Vault Secrets (M2M API + admin) ----
    // Appended at the end to keep existing wire discriminants stable.
    /// An organisational secret row was created (web admin zone).
    VaultSecretCreated,
    /// Secret metadata and/or value updated (value change bumps `version`).
    VaultSecretUpdated,
    /// Secret hard-deleted (row removed; this WORM record is the trace).
    VaultSecretDeleted,
    /// Secret VALUE revealed through `GET /api/v1/vault/secrets/{uuid}/value`.
    /// Security-critical: emitted via `emit_audit_critical` (durable ack
    /// before the plaintext leaves the process).
    VaultSecretRead,
    /// Secret group lifecycle (admin zone, static groups only).
    SecretGroupCreated,
    SecretGroupUpdated,
    SecretGroupDeleted,
    /// Membership changes on `secret_secret_groups`.
    SecretGroupMemberAdded,
    SecretGroupMemberRemoved,
    /// Secret access rule lifecycle (group-to-group grants).
    SecretAccessRuleCreated,
    SecretAccessRuleUpdated,
    SecretAccessRuleDeleted,
    /// M2M vault API call denied because the caller's source IP could
    /// not be matched to a known, identity-verifiable asset (provenance
    /// gate). Non-blocking warn-level emission: the deny already
    /// happened, the audit is best-effort.
    VaultProvenanceDenied,
    /// A provenance candidate asset answered the active host-identity
    /// challenge with a fingerprint that does NOT match the pinned one
    /// (possible MITM / IP squatting). Security-critical: emitted via
    /// `emit_audit_critical` and NEVER cached.
    VaultHostIdentityMismatch,
}

impl AuditEventType {
    /// Number of variants. Pinned by `audit_event_type_count_is_pinned`.
    pub const COUNT: usize = 58;

    /// Every variant, for table-driven tests and drift checks.
    pub const ALL: [AuditEventType; Self::COUNT] = [
        AuditEventType::AuthSuccess,
        AuditEventType::AuthFailure,
        AuditEventType::SessionStart,
        AuditEventType::SessionEnd,
        AuditEventType::CommandExecuted,
        AuditEventType::AccessDenied,
        AuditEventType::PolicyChange,
        AuditEventType::Logout,
        AuditEventType::MfaEnrolled,
        AuditEventType::MfaReset,
        AuditEventType::MfaChallengePassed,
        AuditEventType::MfaChallengeFailed,
        AuditEventType::SessionRequested,
        AuditEventType::SessionTerminated,
        AuditEventType::UserCreated,
        AuditEventType::UserUpdated,
        AuditEventType::UserDeleted,
        AuditEventType::UserActivated,
        AuditEventType::UserDeactivated,
        AuditEventType::RoleChanged,
        AuditEventType::PasswordChanged,
        AuditEventType::AccessRuleCreated,
        AuditEventType::AccessRuleUpdated,
        AuditEventType::AccessRuleDeleted,
        AuditEventType::GroupCreated,
        AuditEventType::GroupUpdated,
        AuditEventType::GroupDeleted,
        AuditEventType::GroupMemberAdded,
        AuditEventType::GroupMemberRemoved,
        AuditEventType::AssetGroupCreated,
        AuditEventType::AssetGroupUpdated,
        AuditEventType::AssetGroupDeleted,
        AuditEventType::AssetGroupMemberAdded,
        AuditEventType::AssetGroupMemberRemoved,
        AuditEventType::AssetCreated,
        AuditEventType::AssetUpdated,
        AuditEventType::AssetDeleted,
        AuditEventType::ApprovalRequested,
        AuditEventType::ApprovalGranted,
        AuditEventType::ApprovalDenied,
        AuditEventType::ApprovalCancelled,
        AuditEventType::MfaSecretGenerated,
        AuditEventType::ApprovalRevoked,
        AuditEventType::ApprovalDurationUpdated,
        AuditEventType::VaultSecretCreated,
        AuditEventType::VaultSecretUpdated,
        AuditEventType::VaultSecretDeleted,
        AuditEventType::VaultSecretRead,
        AuditEventType::SecretGroupCreated,
        AuditEventType::SecretGroupUpdated,
        AuditEventType::SecretGroupDeleted,
        AuditEventType::SecretGroupMemberAdded,
        AuditEventType::SecretGroupMemberRemoved,
        AuditEventType::SecretAccessRuleCreated,
        AuditEventType::SecretAccessRuleUpdated,
        AuditEventType::SecretAccessRuleDeleted,
        AuditEventType::VaultProvenanceDenied,
        AuditEventType::VaultHostIdentityMismatch,
    ];

    /// Coarse category, for log pivoting and the drift test. EXHAUSTIVE match
    /// (no `_` arm): a new variant must be classified or the build fails.
    #[must_use]
    pub fn category(&self) -> &'static str {
        match self {
            AuditEventType::AuthSuccess | AuditEventType::AuthFailure | AuditEventType::Logout => {
                "auth"
            }
            AuditEventType::MfaEnrolled
            | AuditEventType::MfaReset
            | AuditEventType::MfaChallengePassed
            | AuditEventType::MfaChallengeFailed
            | AuditEventType::MfaSecretGenerated => "mfa",
            AuditEventType::SessionStart
            | AuditEventType::SessionEnd
            | AuditEventType::SessionRequested
            | AuditEventType::SessionTerminated
            | AuditEventType::CommandExecuted => "session",
            AuditEventType::UserCreated
            | AuditEventType::UserUpdated
            | AuditEventType::UserDeleted
            | AuditEventType::UserActivated
            | AuditEventType::UserDeactivated
            | AuditEventType::RoleChanged
            | AuditEventType::PasswordChanged => "user",
            AuditEventType::AccessRuleCreated
            | AuditEventType::AccessRuleUpdated
            | AuditEventType::AccessRuleDeleted
            | AuditEventType::GroupCreated
            | AuditEventType::GroupUpdated
            | AuditEventType::GroupDeleted
            | AuditEventType::GroupMemberAdded
            | AuditEventType::GroupMemberRemoved
            | AuditEventType::AssetGroupCreated
            | AuditEventType::AssetGroupUpdated
            | AuditEventType::AssetGroupDeleted
            | AuditEventType::AssetGroupMemberAdded
            | AuditEventType::AssetGroupMemberRemoved
            | AuditEventType::PolicyChange => "policy",
            AuditEventType::AssetCreated
            | AuditEventType::AssetUpdated
            | AuditEventType::AssetDeleted => "asset",
            AuditEventType::ApprovalRequested
            | AuditEventType::ApprovalGranted
            | AuditEventType::ApprovalDenied
            | AuditEventType::ApprovalCancelled
            | AuditEventType::ApprovalRevoked
            | AuditEventType::ApprovalDurationUpdated => "approval",
            AuditEventType::VaultSecretCreated
            | AuditEventType::VaultSecretUpdated
            | AuditEventType::VaultSecretDeleted
            | AuditEventType::VaultSecretRead
            | AuditEventType::SecretGroupCreated
            | AuditEventType::SecretGroupUpdated
            | AuditEventType::SecretGroupDeleted
            | AuditEventType::SecretGroupMemberAdded
            | AuditEventType::SecretGroupMemberRemoved
            | AuditEventType::SecretAccessRuleCreated
            | AuditEventType::SecretAccessRuleUpdated
            | AuditEventType::SecretAccessRuleDeleted
            | AuditEventType::VaultProvenanceDenied
            | AuditEventType::VaultHostIdentityMismatch => "vault",
            AuditEventType::AccessDenied => "denied",
        }
    }
}

/// Input events for RDP sessions, sent from browser to proxy.
///
/// Scancodes follow the PS/2 Set 1 encoding (same as IronRDP FastPath).
/// Extended keys (arrows, numpad enter, etc.) use 0xE0xx codes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RdpInputEvent {
    /// Key pressed (scancode = PS/2 Set 1 make code).
    KeyPressed { scancode: u16 },
    /// Key released.
    KeyReleased { scancode: u16 },
    /// Mouse moved to absolute position.
    MouseMove { x: u16, y: u16 },
    /// Mouse button pressed (0=left, 1=middle, 2=right).
    MouseButtonPressed { button: u8 },
    /// Mouse button released.
    MouseButtonReleased { button: u8 },
    /// Mouse wheel scroll (vertical=true for Y axis, amount is direction).
    WheelScroll { vertical: bool, amount: i16 },

    // ── High-level variants from web frontend ─────────────────────
    // The proxy converts these into the low-level variants above.
    /// Mouse button with position (from web frontend).
    MouseButton {
        button: u8,
        pressed: bool,
        x: u16,
        y: u16,
    },
    /// Mouse wheel with raw delta (from web frontend).
    MouseWheel { delta_x: i16, delta_y: i16 },
    /// Keyboard event with JavaScript key code (from web frontend).
    /// The proxy maps `code` to a PS/2 scancode.
    Keyboard {
        code: String,
        key: String,
        pressed: bool,
        shift: bool,
        ctrl: bool,
        alt: bool,
        meta: bool,
        /// Browser lock-key states (`KeyboardEvent.getModifierState`).
        /// The proxy emits an RDP Synchronize Event when they drift from
        /// the last state it synchronized. `serde(default)` keeps older
        /// senders (no lock fields) decodable.
        #[serde(default)]
        caps_lock: bool,
        #[serde(default)]
        num_lock: bool,
        #[serde(default)]
        scroll_lock: bool,
    },
    /// Release every held key and mouse button (stuck-modifier fix).
    ///
    /// Sent when the browser canvas loses focus (blur, tab switch) or when
    /// a WebSocket (re)connects to an existing proxy session: the keyup
    /// events for held modifiers never reach the canvas in those cases, so
    /// the RDP server would otherwise believe Shift/Ctrl/Alt/Meta are held
    /// forever.
    ReleaseAll,
}

/// Direction of a captured IACS relay chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IacsRecordingDirection {
    /// Bytes flowing from the EWS toward the industrial asset.
    EwsToAsset,
    /// Bytes flowing from the asset toward the EWS.
    AssetToEws,
}

/// SSH recording event type for asciicast v2 format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SshRecordingEvent {
    /// Server output ("o" in asciicast).
    Output,
    /// User input, redacted by proxy before sending ("i" in asciicast).
    Input,
    /// Terminal resize ("r" in asciicast).
    Resize,
}

/// All IPC messages exchanged between services.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    // ========== Control messages ==========
    Control(ControlMessage),

    // ========== Authentication (Web -> Auth) ==========
    AuthRequest {
        request_id: u64,
        username: String,
        /// Credential type varies: password hash, token, etc.
        credential: Vec<u8>,
        source_ip: IpAddr,
    },
    AuthResponse {
        request_id: u64,
        result: AuthResult,
    },

    /// MFA verification (Web -> Auth)
    MfaVerify {
        request_id: u64,
        challenge_id: String,
        code: String,
    },
    MfaVerifyResponse {
        request_id: u64,
        success: bool,
        session_id: Option<String>,
    },

    // ========== Password hashing (Web -> Auth) ==========
    /// Verify a password against a stored Argon2id hash.
    AuthVerifyPassword {
        request_id: u64,
        password_hash: String,
        password: SensitiveString,
    },
    AuthVerifyPasswordResponse {
        request_id: u64,
        valid: bool,
    },

    /// Hash a plaintext password with Argon2id.
    AuthHashPassword {
        request_id: u64,
        password: SensitiveString,
    },
    AuthHashPasswordResponse {
        request_id: u64,
        hash: Option<String>,
        error: Option<String>,
    },

    // ========== RBAC (Web/Auth/Proxy -> Rbac) ==========
    RbacCheck {
        request_id: u64,
        subject: String,
        object: String,
        action: String,
    },
    RbacResponse {
        request_id: u64,
        result: RbacResult,
    },

    // ========== Vault Crypto (Any service -> Vault) ==========
    //
    // SECURITY: Earlier revisions defined `VaultGetSecret` / `VaultGetCredential`
    // (and their `*Response` counterparts) as legacy fail-open placeholders that
    // returned `data: None` / `credential: None` silently. They were removed in
    // the post-MFA security pass because:
    //   1. No production code path consumed them.
    //   2. A future caller that interpreted `Ok(None)` as "no credential needed"
    //      would silently bypass authentication for the affected asset.
    // All credential / secret access must go through the encrypted-transit verbs
    // below (`VaultEncrypt` / `VaultDecrypt` / `VaultMfa*`).
    /// Encrypt plaintext with a named key domain.
    VaultEncrypt {
        request_id: u64,
        /// Key domain: "credentials", "mfa", etc.
        domain: String,
        /// Plaintext to encrypt.
        /// Wrapped in `SensitiveString` for zeroize-on-drop during IPC transport.
        plaintext: SensitiveString,
    },
    VaultEncryptResponse {
        request_id: u64,
        /// Versioned ciphertext (e.g. "v1:BASE64..."), None on error.
        ciphertext: Option<String>,
        error: Option<String>,
    },

    /// Decrypt ciphertext with a named key domain.
    VaultDecrypt {
        request_id: u64,
        /// Key domain: "credentials", "mfa", etc.
        domain: String,
        /// Versioned ciphertext as stored in the database.
        ciphertext: String,
    },
    VaultDecryptResponse {
        request_id: u64,
        /// Decrypted plaintext, None on error.
        /// Wrapped in `SensitiveString` for zeroize-on-drop during IPC transport.
        plaintext: Option<SensitiveString>,
        error: Option<String>,
    },

    // ========== Vault MFA (Web -> Vault) ==========
    /// Generate a new TOTP secret, encrypt it, and return both forms.
    /// The vault generates the secret, encrypts it for DB storage, and returns
    /// the plaintext as a `SensitiveString` (zeroize-on-drop) so the web layer
    /// can generate the QR code locally. QR generation is NOT done in the vault.
    VaultMfaGenerate {
        request_id: u64,
        /// Username (unused by vault, passed through for consistency).
        username: String,
        /// Issuer (unused by vault, passed through for consistency).
        issuer: String,
    },
    VaultMfaGenerateResponse {
        request_id: u64,
        /// Encrypted TOTP secret (store in DB as mfa_secret).
        encrypted_secret: Option<String>,
        /// Plaintext TOTP secret in base32 for QR code generation by the web layer.
        /// Wrapped in `SensitiveString` for zeroize-on-drop during IPC transport.
        plaintext_secret: Option<SensitiveString>,
        error: Option<String>,
    },

    /// Verify a TOTP code against an encrypted secret.
    VaultMfaVerify {
        request_id: u64,
        /// Encrypted TOTP secret as stored in DB.
        encrypted_secret: String,
        /// 6-digit TOTP code entered by the user.
        code: String,
    },
    VaultMfaVerifyResponse {
        request_id: u64,
        /// true if the code is valid for the current or adjacent time step.
        valid: bool,
        error: Option<String>,
    },

    /// Decrypt an encrypted TOTP secret and return the plaintext.
    /// Used by vauban-web to re-generate QR codes from existing encrypted secrets.
    VaultMfaGetSecret {
        request_id: u64,
        /// Encrypted TOTP secret as stored in DB.
        encrypted_secret: String,
    },
    VaultMfaGetSecretResponse {
        request_id: u64,
        /// Decrypted TOTP secret in base32, wrapped in `SensitiveString` for zeroize-on-drop.
        plaintext_secret: Option<SensitiveString>,
        error: Option<String>,
    },

    // ========== Audit (Web/Proxy -> Audit) ==========
    AuditEvent {
        timestamp: u64,
        event_type: AuditEventType,
        user_id: Option<String>,
        session_id: Option<String>,
        source_ip: Option<IpAddr>,
        details: String,
    },
    /// Acknowledgement from audit service: the event was durably persisted to
    /// the WORM log (hash-chained) before this ack was sent.
    AuditAck {
        timestamp: u64,
    },
    /// Negative acknowledgement: the audit service could NOT persist the event
    /// (broker failure, write error, ...). The producer MUST treat a security-
    /// sensitive event as failed when it receives this (fail-closed). Correlated
    /// by `timestamp` like `AuditAck`.
    AuditNack {
        timestamp: u64,
        error: String,
    },

    /// Session recording chunk (Proxy -> Audit).
    SessionRecordingChunk {
        session_id: String,
        sequence: u64,
        data: Vec<u8>,
    },

    // ========== SSH Session (Web <-> ProxySsh) ==========
    /// Request to open an SSH session.
    SshSessionOpen {
        request_id: u64,
        /// UUID generated by vauban-web.
        session_id: String,
        /// Authenticated Vauban user ID.
        user_id: String,
        /// Asset UUID from database.
        asset_id: String,
        /// Target hostname or IP address.
        asset_host: String,
        /// SSH port (default 22).
        asset_port: u16,
        /// SSH username on target server.
        username: String,
        /// Terminal width in columns.
        terminal_cols: u16,
        /// Terminal height in rows.
        terminal_rows: u16,
        /// Authentication type: "password" or "ssh_key".
        auth_type: String,
        /// SECURITY (#4 - zero clear-text credentials on the web->proxy
        /// IPC): the three credential fields below are NO LONGER the
        /// secrets themselves. They are the **vault ciphertexts**
        /// (`"v1:BASE64..."`) exactly as stored in
        /// `assets.connection_config`. vauban-web ships them verbatim
        /// (it never decrypts), and vauban-proxy-ssh materialises the
        /// plaintext via its decrypt-only `VaultDecryptClient` moments
        /// before building the russh credential, inside its own
        /// sandboxed address space. A ciphertext is not a secret (it is
        /// useless without the vault master key), so these are plain
        /// `String` and may appear in Debug / logs.
        ///
        /// Vault ciphertext of the password (if auth_type == "password").
        password_ciphertext: Option<String>,
        /// Vault ciphertext of the PEM private key (if auth_type == "ssh_key").
        private_key_ciphertext: Option<String>,
        /// Vault ciphertext of the private-key passphrase (optional).
        passphrase_ciphertext: Option<String>,
        /// Expected SSH host key in OpenSSH format (e.g. "ssh-ed25519 AAAA...").
        /// If set, the proxy MUST verify the server key matches before continuing.
        /// If None, host key verification is skipped (insecure, logged as warning).
        expected_host_key: Option<String>,
        /// SECURITY: Bincode-serialized `shared::session_token::SessionToken`
        /// minted by vauban-access. The proxy MUST verify this token
        /// (user_uuid, asset_uuid, protocol = "ssh", session_id) before
        /// invoking `AccessGuard::authorize`. Empty vector or any
        /// verification failure MUST collapse to a fail-closed denial.
        /// See `docs/technical/Vauban_AccessGuard_Architecture_EN(1.0).md` §3.
        session_token: Vec<u8>,
    },

    /// Response confirming session opened or error.
    SshSessionOpened {
        request_id: u64,
        session_id: String,
        success: bool,
        /// Error message if success is false.
        error: Option<String>,
    },

    /// Bidirectional terminal data (Web <-> ProxySsh).
    SshData {
        session_id: String,
        data: Vec<u8>,
    },

    /// Request to close an SSH session.
    SshSessionClose {
        session_id: String,
    },

    /// Terminal resize event.
    SshResize {
        session_id: String,
        cols: u16,
        rows: u16,
    },

    // ========== SSH Host Key (Web <-> ProxySsh) ==========
    /// Request to fetch the SSH host key from a target server.
    /// The proxy performs a minimal SSH handshake (key exchange only, no auth)
    /// and returns the server's public key.
    SshFetchHostKey {
        request_id: u64,
        /// Target hostname or IP address.
        asset_host: String,
        /// SSH port.
        asset_port: u16,
    },

    /// Response with the fetched SSH host key.
    SshHostKeyResult {
        request_id: u64,
        success: bool,
        /// Host key in OpenSSH format (e.g. "ssh-ed25519 AAAA...").
        host_key: Option<String>,
        /// SHA-256 fingerprint for display (e.g. "SHA256:abc123...").
        key_fingerprint: Option<String>,
        /// Error message if success is false.
        error: Option<String>,
    },

    // ========== RDP Session (Web <-> ProxyRdp) ==========
    /// Request to open an RDP session.
    RdpSessionOpen {
        request_id: u64,
        /// UUID generated by vauban-web.
        session_id: String,
        /// Authenticated Vauban user ID.
        user_id: String,
        /// Asset UUID from database.
        asset_id: String,
        /// Target hostname or IP address.
        asset_host: String,
        /// RDP port (default 3389).
        asset_port: u16,
        /// RDP username on target server.
        username: String,
        /// Password for RDP authentication.
        /// Wrapped in `SensitiveString` for zeroize-on-drop and redacted Debug.
        password: Option<SensitiveString>,
        /// Windows domain (optional).
        domain: Option<String>,
        /// Requested desktop width in pixels.
        desktop_width: u16,
        /// Requested desktop height in pixels.
        desktop_height: u16,
        /// VAU-001: pinned SHA-256 fingerprint of the target server's TLS
        /// `SubjectPublicKeyInfo` (format `SHA256:<base64>`), sourced from
        /// `assets.connection_config.rdp_server_cert_fingerprint`. The proxy
        /// MUST refuse the TLS handshake (fail-closed) unless the live
        /// server SPKI matches. `None` / empty MUST collapse to a
        /// fail-closed denial (no session without a pinned certificate),
        /// mirroring the SSH `expected_host_key` contract.
        expected_cert_fingerprint: Option<String>,
        /// SECURITY: Bincode-serialized `shared::session_token::SessionToken`
        /// minted by vauban-access. The proxy MUST verify this token
        /// (user_uuid, asset_uuid, protocol = "rdp", session_id) before
        /// invoking `AccessGuard::authorize`. Empty vector or any
        /// verification failure MUST collapse to a fail-closed denial.
        /// See `docs/technical/Vauban_AccessGuard_Architecture_EN(1.0).md` §3.
        session_token: Vec<u8>,
    },

    /// Response confirming RDP session opened or error.
    RdpSessionOpened {
        request_id: u64,
        session_id: String,
        success: bool,
        /// Actual desktop width negotiated with server.
        desktop_width: u16,
        /// Actual desktop height negotiated with server.
        desktop_height: u16,
        /// Error message if success is false.
        error: Option<String>,
    },

    // ========== RDP Server Certificate (Web <-> ProxyRdp) ==========
    /// VAU-001: request to fetch the TLS server certificate SPKI from a
    /// target RDP server (TOFU pinning workflow). The proxy performs the
    /// minimal RDP/X.224 negotiation + TLS upgrade with an accept-any
    /// verifier (no certificate is pinned yet), extracts the server SPKI,
    /// and closes the connection WITHOUT CredSSP/NLA. Mirrors
    /// `SshFetchHostKey`.
    RdpFetchServerCert {
        request_id: u64,
        asset_host: String,
        asset_port: u16,
    },

    /// Response carrying the fetched RDP server SPKI + fingerprint.
    /// Mirrors `SshHostKeyResult`.
    RdpServerCertResult {
        request_id: u64,
        success: bool,
        /// Base64-encoded `SubjectPublicKeyInfo` DER (forensic / display).
        server_spki: Option<String>,
        /// `SHA256:<base64>` fingerprint of the SPKI (comparison value).
        cert_fingerprint: Option<String>,
        /// Error message if success is false.
        error: Option<String>,
    },

    // ========== IACS Tunnel (Web -> ProxyIacs) ==========
    //
    // The IACS tunnel lifecycle is staged:
    //
    // 1. vauban-web validates the asset / EWS / quotas / access-rule
    //    and mints a `SessionToken` via vauban-access bound to
    //    (host=asset.hostname, port=asset.port, target_service=ProxyIacs,
    //    session_id, user, asset, "iacs_tunnel").
    // 2. vauban-web emits `IacsTunnelOpen` to vauban-proxy-iacs with
    //    the per-asset target plus the EWS public-key fingerprint
    //    pinned in the EWS row (so the proxy can authenticate the
    //    `ssh -L` handshake without DB access).
    // 3. vauban-proxy-iacs verifies the token in `Verifier::Proxy`
    //    role, stores the entry in `PendingSessions`, replies
    //    `IacsTunnelOpened { success: true }`. The wait for the EWS
    //    handshake is asynchronous from the IPC roundtrip's view.
    // 4. When the EWS opens its `direct-tcpip`, vauban-proxy-iacs
    //    re-checks via `AccessGuard` (defense-in-depth) then sends
    //    `TcpConnectRequest { target_service: ProxyIacs, host, port,
    //    session_token }` to the supervisor. The supervisor
    //    DNS-resolves and connects, then hands the FD back via
    //    SCM_RIGHTS.
    // 5. On EWS close (or watchdog termination via
    //    `IacsTunnelTerminate`), vauban-proxy-iacs emits
    //    `IacsTunnelClosed` with the byte counters.
    /// Open a new IACS tunnel pending entry.
    IacsTunnelOpen {
        request_id: u64,
        /// `proxy_sessions.uuid` -- the EWS will use this string as
        /// the SSH `user` field at handshake time.
        session_id: String,
        /// Owning user UUID (`users.uuid`).
        user_uuid: String,
        /// Industrial asset UUID (`assets.uuid`).
        asset_uuid: String,
        /// EWS UUID (`ews.uuid`) pinned by vauban-web before the
        /// IPC send; vauban-proxy-iacs trusts this value.
        ews_uuid: String,
        /// SHA-256 hex (lowercase, 64 chars) of the EWS public-key
        /// wire encoding. Sole authentication criterion in
        /// `auth_publickey` on the proxy side.
        ews_pubkey_fp: String,
        /// Asset hostname (FQDN or IP). Resolved by the supervisor
        /// at `TcpConnectRequest` time. NEVER resolved on the proxy
        /// (post-Capsicum, no DNS).
        asset_host: String,
        /// Asset port.
        asset_port: u16,
        /// Industrial protocol label (`modbus`, `opcua`, `tcp`,
        /// ...). Stored in `proxy_sessions.industrial_protocol`;
        /// not used by the proxy for routing.
        industrial_protocol: String,
        /// TTL in seconds for the pending entry, mirrors
        /// `industrial.iacs_tunnel.waiting_client_ttl_seconds`.
        ttl_seconds: u32,
        /// Bincode-serialised `shared::session_token::SessionToken`
        /// minted by vauban-access in `Verifier::Proxy` role for
        /// vauban-proxy-iacs. The proxy verifies it locally before
        /// inserting into `PendingSessions`, then re-presents it on
        /// the supervisor `TcpConnectRequest` (the supervisor
        /// re-verifies it in `Verifier::Supervisor` role).
        session_token: Vec<u8>,
    },

    /// Acknowledgement from vauban-proxy-iacs that the pending
    /// entry was inserted (or rejected).
    IacsTunnelOpened {
        request_id: u64,
        session_id: String,
        success: bool,
        /// Optional human-readable error (logged but never sent to
        /// the EWS).
        error: Option<String>,
    },

    /// Lifecycle close event emitted by vauban-proxy-iacs (EWS
    /// disconnected, watchdog terminated, internal error).
    IacsTunnelClosed {
        request_id: u64,
        session_id: String,
        /// Free-form structured reason (`ews_disconnect`,
        /// `terminated`, `expired`, `error: <msg>`).
        reason: String,
        bytes_in: u64,
        bytes_out: u64,
        /// EWS source IP, if known (set after the SSH handshake).
        peer_ip: Option<String>,
    },

    /// Force-terminate a live IACS tunnel. Sent by vauban-web's
    /// revocation watchdog when the owning EWS or user becomes
    /// disabled / offboarded mid-session. Idempotent: a second
    /// terminate for an already-closed session is a no-op.
    IacsTunnelTerminate {
        request_id: u64,
        session_id: String,
        /// Free-form reason logged on both sides
        /// (`ews_disabled`, `user_disabled`, `access_revoked`,
        /// `admin_terminate`).
        reason: String,
    },

    /// Periodic stats / lifecycle update from vauban-proxy-iacs
    /// to vauban-web, fanned out on `WsChannel::SessionLive(uuid)`.
    /// The 5 s tick frequency means this is a high-volume message
    /// type; vauban-web routes it through `BroadcastService::send_periodic`
    /// so the broadcast log is coalesced (`websocket-logging.mdc`).
    IacsTunnelStatusUpdate {
        session_id: String,
        /// `tunnel_active`, `tunnel_stats`, `tunnel_closed`.
        status: String,
        bytes_in: u64,
        bytes_out: u64,
        peer_ip: Option<String>,
    },

    /// Bitmap region update from RDP session (ProxyRdp -> Web).
    /// Contains a PNG-encoded image of the updated screen region.
    RdpDisplayUpdate {
        session_id: String,
        /// X coordinate of the updated region.
        x: u16,
        /// Y coordinate of the updated region.
        y: u16,
        /// Width of the updated region.
        width: u16,
        /// Height of the updated region.
        height: u16,
        /// PNG-encoded bitmap data for the region.
        png_data: Vec<u8>,
    },

    /// Input event from browser to RDP session (Web -> ProxyRdp).
    RdpInput {
        session_id: String,
        input: RdpInputEvent,
    },

    /// Desktop resize request (Web -> ProxyRdp).
    RdpResize {
        session_id: String,
        width: u16,
        height: u16,
    },

    /// Desktop size changed notification (ProxyRdp -> Web).
    /// Sent after a successful resize (DeactivateAll/Reactivation).
    RdpDesktopResize {
        session_id: String,
        width: u16,
        height: u16,
    },

    /// H.264 encoded video frame (ProxyRdp -> Web).
    /// Can also be forwarded to vauban-audit for session recording.
    RdpVideoFrame {
        session_id: String,
        /// Monotonic timestamp in microseconds from session start.
        timestamp_us: u64,
        /// true = I-frame (keyframe), false = P-frame (delta).
        is_keyframe: bool,
        /// Frame dimensions (can change after resize).
        width: u16,
        height: u16,
        /// H.264 NAL unit(s) for this frame.
        data: Vec<u8>,
    },

    /// Enable or disable H.264 video mode for a session (Web -> ProxyRdp).
    ///
    /// The encoder bitrate is configured at the proxy level via the supervisor
    /// (VAUBAN_RDP_VIDEO_BITRATE_BPS), not through this message.
    RdpSetVideoMode {
        session_id: String,
        enabled: bool,
    },

    /// Request to close an RDP session.
    RdpSessionClose {
        session_id: String,
    },

    // ========== RDP Recording (ProxyRdp -> Audit) ==========
    /// Signal vauban-audit to start recording a new RDP session.
    RdpRecordingStart {
        session_id: String,
        width: u16,
        height: u16,
    },

    /// Signal vauban-audit to finalize the fMP4 recording file.
    RdpRecordingEnd {
        session_id: String,
    },

    // ========== SSH Recording (ProxySsh -> Audit) ==========
    /// Signal vauban-audit to start recording a new SSH session (asciicast v2).
    SshRecordingStart {
        session_id: String,
        width: u16,
        height: u16,
        asset_name: String,
        username: String,
    },

    /// A single SSH recording event (output, redacted input, or resize).
    SshRecordingData {
        session_id: String,
        timestamp_us: u64,
        event_type: SshRecordingEvent,
        data: Vec<u8>,
    },

    /// Signal vauban-audit to finalize the asciicast recording file.
    SshRecordingEnd {
        session_id: String,
    },

    // ========== IACS Recording (ProxyIacs <-> Audit) ==========
    /// Signal vauban-audit to start recording a new `direct-tcpip` channel.
    ///
    /// `client_ip` / `client_port` carry the SSH `direct-tcpip`
    /// originator (the EWS application's perceived local socket).
    /// `server_ip` / `server_port` carry the resolved upstream
    /// endpoint of the brokered TCP fd (or `target_host` /
    /// `target_port` when the resolution is not available). These
    /// four values feed the synthetic IPv4/IPv6 + TCP layer that
    /// `vauban-audit` reconstructs around every captured chunk so
    /// the resulting `.pcap` files dissect natively in
    /// tcpdump / Wireshark / Zeek.
    ///
    /// `connected_at_us` is the wall-clock anchor of the tunnel's
    /// `tunnel_active` transition (= `proxy_sessions.connected_at`).
    /// Audit derives `YYYY/MM/UUID/` from this value rather than
    /// `now()` so the directory layout cannot drift across a
    /// month boundary.
    IacsRecordingChannelStart {
        session_id: String,
        channel_id: u32,
        target_host: String,
        target_port: u16,
        opened_at_us: u64,
        client_ip: String,
        client_port: u16,
        server_ip: String,
        server_port: u16,
        connected_at_us: u64,
    },

    /// A batch of relay bytes for one IACS channel (ProxyIacs -> Audit).
    IacsRecordingData {
        session_id: String,
        channel_id: u32,
        batch_seq: u64,
        direction: IacsRecordingDirection,
        timestamp_us: u64,
        data: Vec<u8>,
    },

    /// Acknowledgement that a batch has been durably persisted (Audit -> ProxyIacs).
    IacsRecordingDataAck {
        session_id: String,
        channel_id: u32,
        batch_seq: u64,
    },

    /// Signal vauban-audit to finalize one channel PCAP (gzip via supervisor).
    IacsRecordingChannelEnd {
        session_id: String,
        channel_id: u32,
        closed_at_us: u64,
    },

    /// Signal vauban-audit to finalize the session bundle (`meta.json`).
    IacsRecordingSessionEnd {
        session_id: String,
    },

    // ========== Recording File Requests (Service -> Supervisor) ==========
    /// Request the supervisor to open/create a recording file and send its FD
    /// via SCM_RIGHTS. Used by audit (create, write) and web (open, read-only).
    RecordingFileRequest {
        request_id: u64,
        session_id: String,
        /// Path relative to the recording storage root (e.g. "2026/02/session.mp4").
        relative_path: String,
        /// When true, opens an existing file read-only (web playback).
        /// When false, creates a new file for writing (audit recording).
        read_only: bool,
    },

    /// Response to a RecordingFileRequest. On success, the file descriptor
    /// has already been sent via SCM_RIGHTS on the fd_passing socket.
    RecordingFileResponse {
        request_id: u64,
        session_id: String,
        success: bool,
        error: Option<String>,
    },

    // ========== Audit WORM log file (Audit -> Supervisor) ==========
    /// Request the supervisor to open the WORM audit-log segment APPEND-ONLY
    /// and send its FD via SCM_RIGHTS. Unlike `RecordingFileRequest`, the path
    /// is NOT a caller-controlled relative path: the supervisor builds it from
    /// a FIXED `audit/` subtree plus a strictly-validated `segment_name`
    /// (no `..`, no absolute path), and opens with `O_APPEND|O_CREAT` (never
    /// `O_TRUNC`). This is the only durable sink for the tamper-evident audit
    /// chain and is structurally immune to the recording path-traversal class.
    AuditLogFileRequest {
        request_id: u64,
        /// Segment file name relative to the audit subtree, e.g.
        /// "2026/06/audit-0001.jsonl". Validated by the supervisor.
        segment_name: String,
    },
    /// Response to an AuditLogFileRequest. On success the append-only FD has
    /// already been sent via SCM_RIGHTS on the fd_passing socket.
    AuditLogFileResponse {
        request_id: u64,
        success: bool,
        error: Option<String>,
    },

    /// Request the supervisor to gzip a PCAP file and remove the raw source.
    /// Used by vauban-audit after a channel closes (Capsicum-safe).
    RecordingFileGzipRequest {
        request_id: u64,
        session_id: String,
        src_relative: String,
        dst_relative: String,
    },

    /// Response to a RecordingFileGzipRequest.
    RecordingFileGzipResponse {
        request_id: u64,
        session_id: String,
        success: bool,
        dst_size: u64,
        blake3_hex: Option<String>,
        error: Option<String>,
    },

    /// Request the supervisor to delete a recording directory or legacy flat
    /// file under the recording storage root. Used by vauban-web retention
    /// reaper only (web service).
    RecordingDeleteRequest {
        request_id: u64,
        session_id: String,
        /// Path relative to the recording storage root (e.g. "2026/05/uuid/"
        /// or "2026/02/uuid.mp4").
        relative_path: String,
    },

    /// Response to a RecordingDeleteRequest.
    RecordingDeleteResponse {
        request_id: u64,
        session_id: String,
        success: bool,
        /// Best-effort bytes reclaimed on disk.
        bytes_freed: u64,
        error: Option<String>,
    },

    // ========== ACME Certificate Management (Web <-> Supervisor) ==========
    /// Request the supervisor to perform ACME certificate renewal.
    /// The supervisor handles the ACME protocol (instant-acme) and coordinates
    /// TLS-ALPN-01 challenges via AcmeChallengeInstall/Remove messages.
    AcmeRenewRequest {
        request_id: u64,
        /// ACME directory URL (e.g. Let's Encrypt, ZeroSSL).
        directory_url: String,
        /// Domain names to obtain certificates for.
        domains: Vec<String>,
        /// Contact email for the ACME account.
        email: String,
        /// Path to the persisted ACME account key.
        account_key_path: String,
        /// Path to write the certificate PEM.
        cert_path: String,
        /// Path to write the private key PEM.
        key_path: String,
        /// ZeroSSL EAB key ID (if applicable).
        eab_kid: Option<String>,
        /// ZeroSSL EAB HMAC key (if applicable).
        eab_hmac_key: Option<SensitiveString>,
    },

    /// Response from supervisor after ACME renewal attempt.
    AcmeRenewResponse {
        request_id: u64,
        success: bool,
        /// Error message if renewal failed.
        error: Option<String>,
        /// PEM-encoded certificate chain (for in-memory activation).
        cert_pem: Option<String>,
        /// PEM-encoded private key (for in-memory activation).
        key_pem: Option<SensitiveString>,
    },

    /// Supervisor instructs web to install a TLS-ALPN-01 challenge certificate.
    /// The web resolver must serve this cert when ALPN is "acme-tls/1" and SNI matches.
    AcmeChallengeInstall {
        request_id: u64,
        /// Domain being validated.
        domain: String,
        /// DER-encoded challenge certificate (self-signed, with acmeIdentifier extension).
        challenge_cert_der: Vec<u8>,
        /// DER-encoded private key for the challenge certificate.
        challenge_key_der: Vec<u8>,
    },

    /// Supervisor instructs web to remove a TLS-ALPN-01 challenge certificate.
    AcmeChallengeRemove {
        request_id: u64,
        /// Domain whose challenge cert should be removed.
        domain: String,
    },

    /// Supervisor instructs web to activate a new production certificate in memory.
    /// This allows zero-downtime certificate rotation without restarting the server.
    AcmeCertActivate {
        request_id: u64,
        /// PEM-encoded certificate chain.
        cert_pem: String,
        /// PEM-encoded private key.
        key_pem: SensitiveString,
    },

    // ========== TLS Certificate Provisioning (Supervisor -> Web) ==========
    /// Supervisor provides TLS certificate data to vauban-web at startup.
    /// The supervisor reads (or generates) the cert/key files as root,
    /// then sends the PEM data so vauban-web never needs filesystem access
    /// to the certs directory.
    TlsCertProvision {
        /// PEM-encoded certificate chain.
        cert_pem: String,
        /// PEM-encoded private key.
        key_pem: SensitiveString,
    },

    // ========== TCP Connection Brokering (Web -> Supervisor -> Proxy) ==========
    /// Request supervisor to establish a TCP connection on behalf of the sandboxed proxy.
    ///
    /// The supervisor performs DNS resolution and TCP connect, then passes the
    /// connected socket FD to the proxy via SCM_RIGHTS over a Unix socket pair.
    /// This allows sandboxed processes (Capsicum) to receive pre-established connections
    /// without requiring network access.
    TcpConnectRequest {
        request_id: u64,
        /// Session ID to correlate the FD with subsequent SshSessionOpen.
        session_id: String,
        /// Target hostname (DNS resolution performed by supervisor).
        host: String,
        /// Target port.
        port: u16,
        /// Target service that will receive the FD (e.g., Service::ProxySsh, Service::ProxyRdp).
        target_service: Service,
        /// SECURITY: Bincode-serialized `shared::session_token::SessionToken`.
        /// The supervisor MUST verify this token (host, port, target_service,
        /// session_id) before performing DNS resolution and `connect()`. An
        /// empty vector or any verification failure MUST collapse to a
        /// fail-closed denial in `handle_tcp_connect_request`. See
        /// `docs/technical/Vauban_AccessGuard_Architecture_EN(1.0).md` §3.
        session_token: Vec<u8>,
    },

    /// Response from supervisor after establishing (or failing) TCP connection.
    ///
    /// If success is true, the FD has been sent to the target service via SCM_RIGHTS.
    /// The target service should have already received the FD before this message arrives.
    TcpConnectResponse {
        request_id: u64,
        session_id: String,
        success: bool,
        /// Error message if connection failed (DNS resolution, connection refused, etc.).
        error: Option<String>,
    },

    // ========== Access Control (Web <-> Access) ==========
    AccessRequest {
        request_id: u64,
        request: AccessRequest,
    },
    AccessResponse {
        request_id: u64,
        response: AccessResponse,
    },

    // ========== Admin Commands (Supervisor -> Services) ==========
    AdminCommand {
        request_id: u64,
        command: AdminCommand,
    },
    AdminResponse {
        request_id: u64,
        response: AdminResponse,
    },

    // ========== LDAP Authentication (Web <-> Auth, Supervisor -> Auth) ==========
    //
    // WIRE COMPATIBILITY: these variants are APPENDED at the end of the enum.
    // Bincode encodes enum variants by ordinal index, so new variants MUST be
    // added here (never inserted in the middle) to preserve the discriminants
    // of already-deployed peers.
    /// Web asks auth to perform an LDAP simple bind for `username`.
    ///
    /// The password is carried in a [`SensitiveString`] (zeroized on drop,
    /// redacted in `Debug`). Auth builds the bind DN from its configured
    /// `dn_template`, requests a brokered TCP socket from the supervisor,
    /// terminates TLS itself, and performs the bind. The plaintext password
    /// never enters the supervisor (root TCB).
    AuthLdapBind {
        request_id: u64,
        username: String,
        password: SensitiveString,
    },
    /// Auth's response to [`Message::AuthLdapBind`].
    AuthLdapBindResponse {
        request_id: u64,
        outcome: LdapBindOutcome,
    },

    /// Supervisor provisions the LDAP configuration + trust anchor to auth at
    /// startup, BEFORE auth enters its sandbox (mirrors
    /// [`Message::TlsCertProvision`]). The CA PEM is trust material, not a
    /// secret; no bind password is shipped in v1 (direct bind via
    /// `dn_template`).
    AuthLdapProvision {
        /// `ldaps://host:port` of the directory.
        url: String,
        /// DN/UPN template; `{username}` is substituted at bind time.
        dn_template: String,
        /// PEM-encoded CA bundle used to validate the directory's TLS cert.
        ca_pem: String,
        /// Per-attempt timeout budget in seconds.
        timeout_secs: u64,
    },

    // ========== SSH key onboarding (Web <-> ProxySsh) ==========
    //
    // These two verbs power the asset SSH key-based auth flow's
    // "Push public key" (generated source) and "Test key-based
    // authentication" (existing source) buttons. Like SshSessionOpen
    // they carry vault CIPHERTEXTS only (#4): the proxy decrypts the
    // one-shot password / private key via its decrypt-only
    // VaultDecryptClient. Appended at the END of the enum to preserve
    // the bincode discriminant indices of every variant above (wire
    // compat with already-deployed peers).
    /// Append `public_key` to the target's `~/.ssh/authorized_keys` over
    /// a one-shot password-authenticated SSH session, then disconnect.
    /// Idempotent server-side (`grep -qxF || echo >>`). Host key pinning
    /// is mandatory: `expected_host_key` MUST match or the proxy refuses
    /// (anti-MITM, since we authenticate with a password).
    SshPushPublicKey {
        request_id: u64,
        /// Target hostname or IP address.
        asset_host: String,
        /// SSH port (default 22).
        asset_port: u16,
        /// SSH username on target server.
        username: String,
        /// OpenSSH public key line to install (clear text, not a secret).
        public_key: String,
        /// Vault ciphertext of the one-shot password (typed in the modal).
        password_ciphertext: String,
        /// Pinned host key in OpenSSH format. MUST be present and match.
        expected_host_key: Option<String>,
    },

    /// Response to [`Message::SshPushPublicKey`].
    SshPushPublicKeyResult {
        request_id: u64,
        success: bool,
        /// Error message if success is false (auth refused, host
        /// unreachable, host-key mismatch, exec non-zero, ...).
        error: Option<String>,
    },

    /// Open a one-shot SSH session authenticating with the private key
    /// (key-based auth dry-run), then disconnect. Used by the "Test
    /// key-based authentication" button for the `existing` source. Host
    /// key pinning is mandatory.
    SshTestKeyAuth {
        request_id: u64,
        /// Target hostname or IP address.
        asset_host: String,
        /// SSH port (default 22).
        asset_port: u16,
        /// SSH username on target server.
        username: String,
        /// Vault ciphertext of the PEM private key.
        private_key_ciphertext: String,
        /// Vault ciphertext of the private-key passphrase (optional).
        passphrase_ciphertext: Option<String>,
        /// Pinned host key in OpenSSH format. MUST be present and match.
        expected_host_key: Option<String>,
    },

    /// Response to [`Message::SshTestKeyAuth`].
    SshTestKeyAuthResult {
        request_id: u64,
        success: bool,
        /// Error message if success is false.
        error: Option<String>,
    },
}

impl Message {
    /// Get the request ID if this message has one.
    pub fn request_id(&self) -> Option<u64> {
        match self {
            Message::AuthRequest { request_id, .. }
            | Message::AuthResponse { request_id, .. }
            | Message::MfaVerify { request_id, .. }
            | Message::MfaVerifyResponse { request_id, .. }
            | Message::AuthVerifyPassword { request_id, .. }
            | Message::AuthVerifyPasswordResponse { request_id, .. }
            | Message::AuthHashPassword { request_id, .. }
            | Message::AuthHashPasswordResponse { request_id, .. }
            | Message::RbacCheck { request_id, .. }
            | Message::RbacResponse { request_id, .. }
            | Message::VaultEncrypt { request_id, .. }
            | Message::VaultEncryptResponse { request_id, .. }
            | Message::VaultDecrypt { request_id, .. }
            | Message::VaultDecryptResponse { request_id, .. }
            | Message::VaultMfaGenerate { request_id, .. }
            | Message::VaultMfaGenerateResponse { request_id, .. }
            | Message::VaultMfaVerify { request_id, .. }
            | Message::VaultMfaVerifyResponse { request_id, .. }
            | Message::VaultMfaGetSecret { request_id, .. }
            | Message::VaultMfaGetSecretResponse { request_id, .. }
            | Message::SshSessionOpen { request_id, .. }
            | Message::SshSessionOpened { request_id, .. }
            | Message::SshFetchHostKey { request_id, .. }
            | Message::SshHostKeyResult { request_id, .. }
            | Message::RdpSessionOpen { request_id, .. }
            | Message::RdpSessionOpened { request_id, .. }
            | Message::RdpFetchServerCert { request_id, .. }
            | Message::RdpServerCertResult { request_id, .. }
            | Message::IacsTunnelOpen { request_id, .. }
            | Message::IacsTunnelOpened { request_id, .. }
            | Message::IacsTunnelClosed { request_id, .. }
            | Message::IacsTunnelTerminate { request_id, .. }
            | Message::AcmeRenewRequest { request_id, .. }
            | Message::AcmeRenewResponse { request_id, .. }
            | Message::AcmeChallengeInstall { request_id, .. }
            | Message::AcmeChallengeRemove { request_id, .. }
            | Message::AcmeCertActivate { request_id, .. }
            | Message::AuditLogFileRequest { request_id, .. }
            | Message::AuditLogFileResponse { request_id, .. }
            | Message::TcpConnectRequest { request_id, .. }
            | Message::TcpConnectResponse { request_id, .. }
            | Message::AccessRequest { request_id, .. }
            | Message::AccessResponse { request_id, .. }
            | Message::AdminCommand { request_id, .. }
            | Message::AdminResponse { request_id, .. }
            | Message::AuthLdapBind { request_id, .. }
            | Message::AuthLdapBindResponse { request_id, .. }
            | Message::SshPushPublicKey { request_id, .. }
            | Message::SshPushPublicKeyResult { request_id, .. }
            | Message::SshTestKeyAuth { request_id, .. }
            | Message::SshTestKeyAuthResult { request_id, .. } => Some(*request_id),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    // Helper functions for bincode 3.0 serialization
    fn serialize<T: serde::Serialize>(value: &T) -> Vec<u8> {
        bincode::serde::encode_to_vec(value, bincode::config::standard()).unwrap()
    }

    fn deserialize<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> T {
        let (value, _): (T, _) =
            bincode::serde::decode_from_slice(bytes, bincode::config::standard()).unwrap();
        value
    }

    // ==================== Service Tests ====================

    #[test]
    fn test_service_enum_variants() {
        let services = [
            Service::Supervisor,
            Service::Web,
            Service::Auth,
            Service::Access,
            Service::Vault,
            Service::Audit,
            Service::ProxySsh,
            Service::ProxyRdp,
            Service::ProxyIacs,
        ];
        assert_eq!(services.len(), 9);
    }

    /// Drift pin: the wire discriminants are an immutable contract
    /// between vauban-access (token mint), the proxies (token verify
    /// at the bord), and the supervisor (token verify before broker
    /// SCM_RIGHTS). Renumbering an existing variant is a wire break;
    /// adding a new one MUST come with a new branch in this test so
    /// the reviewer is forced to confirm the value.
    #[test]
    fn service_token_discriminants_are_frozen() {
        assert_eq!(Service::Supervisor.as_token_discriminant(), 0);
        assert_eq!(Service::Web.as_token_discriminant(), 1);
        assert_eq!(Service::Auth.as_token_discriminant(), 2);
        assert_eq!(Service::Access.as_token_discriminant(), 3);
        assert_eq!(Service::Vault.as_token_discriminant(), 4);
        assert_eq!(Service::Audit.as_token_discriminant(), 5);
        assert_eq!(Service::ProxySsh.as_token_discriminant(), 6);
        assert_eq!(Service::ProxyRdp.as_token_discriminant(), 7);
        assert_eq!(Service::ProxyIacs.as_token_discriminant(), 8);
    }

    /// Pinned variant count -- adding a new Service MUST update this
    /// test alongside `service_token_discriminants_are_frozen` and
    /// the supervisor TOPOLOGY drift tests.
    #[test]
    fn service_enum_count_pinned() {
        let all = [
            Service::Supervisor,
            Service::Web,
            Service::Auth,
            Service::Access,
            Service::Vault,
            Service::Audit,
            Service::ProxySsh,
            Service::ProxyRdp,
            Service::ProxyIacs,
        ];
        assert_eq!(
            all.len(),
            9,
            "Service enum has changed -- update topology, mailer whitelist, broker gate, and proxy_*::env_suffix"
        );
    }

    #[test]
    fn test_service_equality() {
        assert_eq!(Service::Web, Service::Web);
        assert_ne!(Service::Web, Service::Auth);
    }

    #[test]
    fn test_service_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(Service::Web);
        set.insert(Service::Auth);
        set.insert(Service::Web); // Duplicate
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_service_serialization() {
        let service = Service::Auth;
        let serialized = serialize(&service);
        let deserialized: Service = deserialize(&serialized);
        assert_eq!(service, deserialized);
    }

    // ==================== ControlMessage Tests ====================

    #[test]
    fn test_control_message_drain() {
        let msg = ControlMessage::Drain;
        let serialized = serialize(&msg);
        let deserialized: ControlMessage = deserialize(&serialized);
        assert!(matches!(deserialized, ControlMessage::Drain));
    }

    #[test]
    fn test_control_message_drain_complete() {
        let msg = ControlMessage::DrainComplete {
            pending_requests: 5,
        };
        let serialized = serialize(&msg);
        let deserialized: ControlMessage = deserialize(&serialized);
        if let ControlMessage::DrainComplete { pending_requests } = deserialized {
            assert_eq!(pending_requests, 5);
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_control_message_ping_pong() {
        let ping = ControlMessage::Ping { seq: 42 };
        let stats = ServiceStats {
            uptime_secs: 100,
            requests_processed: 1000,
            requests_failed: 5,
            active_connections: 10,
            pending_requests: 2,
        };
        let pong = ControlMessage::Pong { seq: 42, stats };

        let ping_serialized = serialize(&ping);
        let pong_serialized = serialize(&pong);

        let ping_deser: ControlMessage = deserialize(&ping_serialized);
        let pong_deser: ControlMessage = deserialize(&pong_serialized);

        if let ControlMessage::Ping { seq } = ping_deser {
            assert_eq!(seq, 42);
        } else {
            panic!("Wrong variant");
        }

        if let ControlMessage::Pong { seq, stats } = pong_deser {
            assert_eq!(seq, 42);
            assert_eq!(stats.uptime_secs, 100);
            assert_eq!(stats.requests_processed, 1000);
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_control_message_shutdown() {
        let msg = ControlMessage::Shutdown;
        let serialized = serialize(&msg);
        let deserialized: ControlMessage = deserialize(&serialized);
        assert!(matches!(deserialized, ControlMessage::Shutdown));
    }

    // ==================== ServiceStats Tests ====================

    #[test]
    fn test_service_stats_default() {
        let stats = ServiceStats::default();
        assert_eq!(stats.uptime_secs, 0);
        assert_eq!(stats.requests_processed, 0);
        assert_eq!(stats.requests_failed, 0);
        assert_eq!(stats.active_connections, 0);
        assert_eq!(stats.pending_requests, 0);
    }

    #[test]
    fn test_service_stats_serialization() {
        let stats = ServiceStats {
            uptime_secs: 3600,
            requests_processed: 10000,
            requests_failed: 50,
            active_connections: 25,
            pending_requests: 3,
        };
        let serialized = serialize(&stats);
        let deserialized: ServiceStats = deserialize(&serialized);
        assert_eq!(stats.uptime_secs, deserialized.uptime_secs);
        assert_eq!(stats.requests_processed, deserialized.requests_processed);
    }

    // ==================== AuthResult Tests ====================

    #[test]
    fn test_auth_result_success() {
        let result = AuthResult::Success {
            user_id: "user123".to_string(),
            session_id: "sess456".to_string(),
            roles: vec!["admin".to_string(), "user".to_string()],
        };
        let serialized = serialize(&result);
        let deserialized: AuthResult = deserialize(&serialized);
        if let AuthResult::Success { user_id, roles, .. } = deserialized {
            assert_eq!(user_id, "user123");
            assert_eq!(roles.len(), 2);
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_auth_result_failure() {
        let result = AuthResult::Failure {
            reason: "Invalid password".to_string(),
        };
        let serialized = serialize(&result);
        let deserialized: AuthResult = deserialize(&serialized);
        if let AuthResult::Failure { reason } = deserialized {
            assert_eq!(reason, "Invalid password");
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_auth_result_mfa_required() {
        let result = AuthResult::MfaRequired {
            challenge_id: "chal789".to_string(),
        };
        let serialized = serialize(&result);
        let deserialized: AuthResult = deserialize(&serialized);
        if let AuthResult::MfaRequired { challenge_id } = deserialized {
            assert_eq!(challenge_id, "chal789");
        } else {
            panic!("Wrong variant");
        }
    }

    // ==================== RbacResult Tests ====================

    #[test]
    fn test_rbac_result_allowed() {
        let result = RbacResult {
            allowed: true,
            reason: None,
        };
        let serialized = serialize(&result);
        let deserialized: RbacResult = deserialize(&serialized);
        assert!(deserialized.allowed);
        assert!(deserialized.reason.is_none());
    }

    #[test]
    fn test_rbac_result_denied_with_reason() {
        let result = RbacResult {
            allowed: false,
            reason: Some("Insufficient permissions".to_string()),
        };
        let serialized = serialize(&result);
        let deserialized: RbacResult = deserialize(&serialized);
        assert!(!deserialized.allowed);
        assert_eq!(deserialized.reason.unwrap(), "Insufficient permissions");
    }

    // ==================== AuditEventType Tests ====================

    #[test]
    fn test_audit_event_types() {
        // The first 7 indices are FROZEN (proxy-ssh / web already emit them on
        // the wire); new VAU-003 variants are appended after.
        let events = [
            AuditEventType::AuthSuccess,
            AuditEventType::AuthFailure,
            AuditEventType::SessionStart,
            AuditEventType::SessionEnd,
            AuditEventType::CommandExecuted,
            AuditEventType::AccessDenied,
            AuditEventType::PolicyChange,
        ];

        for event in events {
            let serialized = serialize(&event);
            let _: AuditEventType = deserialize(&serialized);
        }
    }

    #[test]
    fn audit_event_type_count_is_pinned() {
        // Drift guard: ALL must list every variant and match COUNT. Bump COUNT
        // and ALL together when appending a variant (never reorder existing
        // ones -- bincode encodes the index).
        assert_eq!(AuditEventType::ALL.len(), AuditEventType::COUNT);
        assert_eq!(AuditEventType::COUNT, 58);
    }

    #[test]
    fn audit_event_type_first_seven_indices_are_frozen() {
        // bincode encodes a fieldless enum by index; pin the wire bytes of the
        // pre-VAU-003 variants so an inadvertent reorder is caught.
        for (idx, ev) in AuditEventType::ALL.iter().take(7).enumerate() {
            let bytes = serialize(ev);
            assert_eq!(
                bytes[0] as usize, idx,
                "variant {ev:?} must keep wire index {idx}"
            );
        }
    }

    #[test]
    fn audit_event_type_every_variant_has_a_category_and_roundtrips() {
        for ev in AuditEventType::ALL {
            // category() is exhaustive; just ensure it is non-empty.
            assert!(!ev.category().is_empty());
            let serialized = serialize(&ev);
            let back: AuditEventType = deserialize(&serialized);
            assert_eq!(back, ev);
        }
    }

    #[test]
    fn test_message_audit_nack() {
        let msg = Message::AuditNack {
            timestamp: 1234,
            error: "broker unavailable".to_string(),
        };
        assert!(msg.request_id().is_none());
        let serialized = serialize(&msg);
        let back: Message = deserialize(&serialized);
        assert!(matches!(
            back,
            Message::AuditNack {
                timestamp: 1234,
                ..
            }
        ));
    }

    #[test]
    fn test_message_audit_log_file_request_carries_request_id() {
        let msg = Message::AuditLogFileRequest {
            request_id: 77,
            segment_name: "2026/06/audit-0001.jsonl".to_string(),
        };
        assert_eq!(msg.request_id(), Some(77));
        let resp = Message::AuditLogFileResponse {
            request_id: 77,
            success: true,
            error: None,
        };
        assert_eq!(resp.request_id(), Some(77));
    }

    // ==================== Message Tests ====================

    #[test]
    fn test_message_control() {
        let msg = Message::Control(ControlMessage::Ping { seq: 1 });
        assert!(msg.request_id().is_none());
    }

    #[test]
    fn test_message_auth_request() {
        let msg = Message::AuthRequest {
            request_id: 100,
            username: "testuser".to_string(),
            credential: vec![1, 2, 3, 4],
            source_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        };
        assert_eq!(msg.request_id(), Some(100));

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::AuthRequest {
            username,
            source_ip,
            ..
        } = deserialized
        {
            assert_eq!(username, "testuser");
            assert_eq!(source_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_rbac_check() {
        let msg = Message::RbacCheck {
            request_id: 200,
            subject: "user:alice".to_string(),
            object: "asset:server1".to_string(),
            action: "ssh".to_string(),
        };
        assert_eq!(msg.request_id(), Some(200));
    }

    /// SECURITY (regression): the legacy fail-open Vault verbs
    /// (`VaultGetSecret`, `VaultGetCredential`, and their `*Response`
    /// counterparts) MUST NOT come back. Reconstruct the forbidden tokens at
    /// runtime so this test never matches against itself.
    #[test]
    fn test_messages_do_not_define_legacy_vault_variants() {
        let source = include_str!("messages.rs");
        let prefix = "Vault";
        for suffix in [
            "GetSecret",
            "SecretResponse",
            "GetCredential",
            "CredentialResponse",
        ] {
            let forbidden = format!("{}{}", prefix, suffix);
            let needle = format!("{} {{", forbidden);
            assert!(
                !source.contains(&needle),
                "shared/messages.rs must not redefine the legacy Vault variant `{}` \
                 (it returned data/credential: None silently and was removed for \
                 security; use VaultEncrypt/VaultDecrypt/VaultMfa* instead)",
                forbidden
            );
            let pat_id = format!("Message::{} {{ request_id, .. }}", forbidden);
            assert!(
                !source.contains(&pat_id),
                "shared/messages.rs must not include the legacy Vault variant `{}` \
                 in the request_id() match (it should not exist at all)",
                forbidden
            );
        }
    }

    #[test]
    fn test_message_audit_event() {
        let msg = Message::AuditEvent {
            timestamp: 1706140800,
            event_type: AuditEventType::SessionStart,
            user_id: Some("alice".to_string()),
            session_id: Some("sess123".to_string()),
            source_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            details: "SSH session started".to_string(),
        };
        // AuditEvent has no request_id
        assert!(msg.request_id().is_none());
    }

    #[test]
    fn test_message_session_recording_chunk() {
        let msg = Message::SessionRecordingChunk {
            session_id: "sess123".to_string(),
            sequence: 42,
            data: vec![0; 1024],
        };
        // SessionRecordingChunk has no request_id
        assert!(msg.request_id().is_none());

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::SessionRecordingChunk {
            session_id,
            sequence,
            data,
        } = deserialized
        {
            assert_eq!(session_id, "sess123");
            assert_eq!(sequence, 42);
            assert_eq!(data.len(), 1024);
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_mfa_verify() {
        let msg = Message::MfaVerify {
            request_id: 400,
            challenge_id: "chal123".to_string(),
            code: "123456".to_string(),
        };
        assert_eq!(msg.request_id(), Some(400));
    }

    #[test]
    fn test_message_mfa_verify_response_success() {
        let msg = Message::MfaVerifyResponse {
            request_id: 400,
            success: true,
            session_id: Some("sess456".to_string()),
        };
        assert_eq!(msg.request_id(), Some(400));
    }

    #[test]
    fn test_message_mfa_verify_response_failure() {
        let msg = Message::MfaVerifyResponse {
            request_id: 401,
            success: false,
            session_id: None,
        };
        assert_eq!(msg.request_id(), Some(401));
    }

    // ==================== Serialization Size Tests ====================

    #[test]
    fn test_message_serialization_size_ping() {
        let msg = Message::Control(ControlMessage::Ping { seq: u64::MAX });
        let serialized = serialize(&msg);
        // Ping should be small
        assert!(serialized.len() < 32);
    }

    #[test]
    fn test_message_serialization_roundtrip_all_variants() {
        let messages: Vec<Message> = vec![
            Message::Control(ControlMessage::Drain),
            Message::Control(ControlMessage::Shutdown),
            Message::AuthRequest {
                request_id: 1,
                username: "test".to_string(),
                credential: vec![],
                source_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            },
            Message::AuthResponse {
                request_id: 1,
                result: AuthResult::Failure {
                    reason: "test".to_string(),
                },
            },
            Message::RbacCheck {
                request_id: 2,
                subject: "s".to_string(),
                object: "o".to_string(),
                action: "a".to_string(),
            },
            Message::RbacResponse {
                request_id: 2,
                result: RbacResult {
                    allowed: true,
                    reason: None,
                },
            },
            Message::AuditAck { timestamp: 12345 },
        ];

        for msg in messages {
            let serialized = serialize(&msg);
            let deserialized: Message = deserialize(&serialized);
            // Just verify it doesn't panic
            let _ = deserialized.request_id();
        }
    }

    // ==================== SSH Session Message Tests ====================

    #[test]
    fn test_message_ssh_session_open() {
        let msg = Message::SshSessionOpen {
            request_id: 500,
            session_id: "sess-uuid-123".to_string(),
            user_id: "user-uuid-456".to_string(),
            asset_id: "asset-uuid-789".to_string(),
            asset_host: "192.168.1.100".to_string(),
            asset_port: 22,
            username: "admin".to_string(),
            terminal_cols: 80,
            terminal_rows: 24,
            auth_type: "password".to_string(),
            password_ciphertext: Some("v1:CIPHERTEXT".to_string()),
            private_key_ciphertext: None,
            passphrase_ciphertext: None,
            expected_host_key: Some("ssh-ed25519 AAAA...".to_string()),
            session_token: Vec::new(),
        };
        assert_eq!(msg.request_id(), Some(500));

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::SshSessionOpen {
            request_id,
            session_id,
            user_id,
            asset_host,
            asset_port,
            username,
            terminal_cols,
            terminal_rows,
            auth_type,
            password_ciphertext,
            ..
        } = deserialized
        {
            assert_eq!(request_id, 500);
            assert_eq!(session_id, "sess-uuid-123");
            assert_eq!(user_id, "user-uuid-456");
            assert_eq!(asset_host, "192.168.1.100");
            assert_eq!(asset_port, 22);
            assert_eq!(username, "admin");
            assert_eq!(terminal_cols, 80);
            assert_eq!(terminal_rows, 24);
            assert_eq!(auth_type, "password");
            assert_eq!(password_ciphertext.as_deref(), Some("v1:CIPHERTEXT"));
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_ssh_session_opened_success() {
        let msg = Message::SshSessionOpened {
            request_id: 500,
            session_id: "sess-uuid-123".to_string(),
            success: true,
            error: None,
        };
        assert_eq!(msg.request_id(), Some(500));

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::SshSessionOpened { success, error, .. } = deserialized {
            assert!(success);
            assert!(error.is_none());
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_ssh_session_opened_failure() {
        let msg = Message::SshSessionOpened {
            request_id: 501,
            session_id: "sess-uuid-123".to_string(),
            success: false,
            error: Some("Connection refused".to_string()),
        };
        assert_eq!(msg.request_id(), Some(501));

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::SshSessionOpened { success, error, .. } = deserialized {
            assert!(!success);
            assert_eq!(error, Some("Connection refused".to_string()));
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_ssh_data() {
        let msg = Message::SshData {
            session_id: "sess-uuid-123".to_string(),
            data: vec![0x1b, 0x5b, 0x48], // ESC[H - cursor home
        };
        // SshData has no request_id
        assert!(msg.request_id().is_none());

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::SshData { session_id, data } = deserialized {
            assert_eq!(session_id, "sess-uuid-123");
            assert_eq!(data, vec![0x1b, 0x5b, 0x48]);
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_ssh_session_close() {
        let msg = Message::SshSessionClose {
            session_id: "sess-uuid-123".to_string(),
        };
        // SshSessionClose has no request_id
        assert!(msg.request_id().is_none());

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::SshSessionClose { session_id } = deserialized {
            assert_eq!(session_id, "sess-uuid-123");
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_ssh_resize() {
        let msg = Message::SshResize {
            session_id: "sess-uuid-123".to_string(),
            cols: 120,
            rows: 40,
        };
        // SshResize has no request_id
        assert!(msg.request_id().is_none());

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::SshResize {
            session_id,
            cols,
            rows,
        } = deserialized
        {
            assert_eq!(session_id, "sess-uuid-123");
            assert_eq!(cols, 120);
            assert_eq!(rows, 40);
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_ssh_messages_serialization_roundtrip() {
        let messages: Vec<Message> = vec![
            Message::SshSessionOpen {
                request_id: 1,
                session_id: "s1".to_string(),
                user_id: "u1".to_string(),
                asset_id: "a1".to_string(),
                asset_host: "host".to_string(),
                asset_port: 22,
                username: "user".to_string(),
                terminal_cols: 80,
                terminal_rows: 24,
                auth_type: "password".to_string(),
                password_ciphertext: Some("v1:pass".to_string()),
                private_key_ciphertext: None,
                passphrase_ciphertext: None,
                expected_host_key: None,
                session_token: Vec::new(),
            },
            Message::SshSessionOpened {
                request_id: 1,
                session_id: "s1".to_string(),
                success: true,
                error: None,
            },
            Message::SshData {
                session_id: "s1".to_string(),
                data: b"hello".to_vec(),
            },
            Message::SshResize {
                session_id: "s1".to_string(),
                cols: 100,
                rows: 30,
            },
            Message::SshSessionClose {
                session_id: "s1".to_string(),
            },
        ];

        for msg in messages {
            let serialized = serialize(&msg);
            let deserialized: Message = deserialize(&serialized);
            // Just verify it doesn't panic
            let _ = deserialized.request_id();
        }
    }

    // ==================== TCP Connection Brokering Tests ====================

    #[test]
    fn test_message_tcp_connect_request() {
        let msg = Message::TcpConnectRequest {
            request_id: 600,
            session_id: "sess-tcp-123".to_string(),
            host: "example.com".to_string(),
            port: 22,
            target_service: Service::ProxySsh,
            session_token: Vec::new(),
        };
        assert_eq!(msg.request_id(), Some(600));

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::TcpConnectRequest {
            request_id,
            session_id,
            host,
            port,
            target_service,
            ..
        } = deserialized
        {
            assert_eq!(request_id, 600);
            assert_eq!(session_id, "sess-tcp-123");
            assert_eq!(host, "example.com");
            assert_eq!(port, 22);
            assert_eq!(target_service, Service::ProxySsh);
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_tcp_connect_response_success() {
        let msg = Message::TcpConnectResponse {
            request_id: 600,
            session_id: "sess-tcp-123".to_string(),
            success: true,
            error: None,
        };
        assert_eq!(msg.request_id(), Some(600));

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::TcpConnectResponse {
            request_id,
            success,
            error,
            ..
        } = deserialized
        {
            assert_eq!(request_id, 600);
            assert!(success);
            assert!(error.is_none());
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_tcp_connect_response_failure() {
        let msg = Message::TcpConnectResponse {
            request_id: 601,
            session_id: "sess-tcp-456".to_string(),
            success: false,
            error: Some("DNS resolution failed: unknown host".to_string()),
        };
        assert_eq!(msg.request_id(), Some(601));

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::TcpConnectResponse { success, error, .. } = deserialized {
            assert!(!success);
            assert_eq!(
                error,
                Some("DNS resolution failed: unknown host".to_string())
            );
        } else {
            panic!("Wrong variant");
        }
    }

    // ==================== LDAP Authentication Tests ====================

    #[test]
    fn test_message_auth_ldap_bind_roundtrip() {
        let msg = Message::AuthLdapBind {
            request_id: 700,
            username: "alice".to_string(),
            password: SensitiveString::new("s3cr3t".to_string()),
        };
        assert_eq!(msg.request_id(), Some(700));

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::AuthLdapBind {
            request_id,
            username,
            password,
        } = deserialized
        {
            assert_eq!(request_id, 700);
            assert_eq!(username, "alice");
            assert_eq!(password.as_str(), "s3cr3t");
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_auth_ldap_bind_password_redacted_in_debug() {
        let msg = Message::AuthLdapBind {
            request_id: 701,
            username: "bob".to_string(),
            password: SensitiveString::new("do-not-leak".to_string()),
        };
        let debug = format!("{:?}", msg);
        assert!(
            !debug.contains("do-not-leak"),
            "LDAP bind password must be redacted in Debug output, got: {debug}"
        );
    }

    #[test]
    fn test_message_auth_ldap_bind_response_roundtrip() {
        for outcome in [
            LdapBindOutcome::Success,
            LdapBindOutcome::InvalidCredentials,
            LdapBindOutcome::Unreachable,
            LdapBindOutcome::TlsError,
        ] {
            let msg = Message::AuthLdapBindResponse {
                request_id: 702,
                outcome,
            };
            assert_eq!(msg.request_id(), Some(702));

            let serialized = serialize(&msg);
            let deserialized: Message = deserialize(&serialized);
            if let Message::AuthLdapBindResponse {
                request_id,
                outcome: got,
            } = deserialized
            {
                assert_eq!(request_id, 702);
                assert_eq!(got, outcome);
            } else {
                panic!("Wrong variant");
            }
        }
    }

    #[test]
    fn test_message_auth_ldap_provision_roundtrip() {
        let msg = Message::AuthLdapProvision {
            url: "ldaps://dc1.example.com:636".to_string(),
            dn_template: "{username}@example.com".to_string(),
            ca_pem: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n".to_string(),
            timeout_secs: 5,
        };
        // Provisioning carries no request_id (like TlsCertProvision).
        assert_eq!(msg.request_id(), None);

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::AuthLdapProvision {
            url,
            dn_template,
            ca_pem,
            timeout_secs,
        } = deserialized
        {
            assert_eq!(url, "ldaps://dc1.example.com:636");
            assert_eq!(dn_template, "{username}@example.com");
            assert!(ca_pem.contains("BEGIN CERTIFICATE"));
            assert_eq!(timeout_secs, 5);
        } else {
            panic!("Wrong variant");
        }
    }

    /// WIRE COMPATIBILITY pin: the LDAP variants are the LAST three in the
    /// `Message` enum. Bincode encodes variants by ordinal index, so they
    /// MUST stay appended at the end (any earlier insertion shifts every
    /// subsequent discriminant and breaks already-deployed peers). This test
    /// fails loudly if a future variant is inserted after them in the source.
    #[test]
    fn test_ldap_message_variants_are_appended_last() {
        // Encoding a value whose discriminant is the maximum currently known
        // must round-trip; if a variant is inserted *after* AuthLdapProvision,
        // this still passes, but the companion source-ordering comment +
        // the explicit indices below document the contract.
        let provision = Message::AuthLdapProvision {
            url: "ldaps://x:636".to_string(),
            dn_template: "{username}".to_string(),
            ca_pem: String::new(),
            timeout_secs: 1,
        };
        let bytes = serialize(&provision);
        let decoded: Message = deserialize(&bytes);
        assert!(matches!(decoded, Message::AuthLdapProvision { .. }));
    }

    #[test]
    fn test_tcp_connect_messages_serialization_roundtrip() {
        let messages: Vec<Message> = vec![
            Message::TcpConnectRequest {
                request_id: 1,
                session_id: "s1".to_string(),
                host: "192.168.1.100".to_string(),
                port: 22,
                target_service: Service::ProxySsh,
                session_token: Vec::new(),
            },
            Message::TcpConnectRequest {
                request_id: 2,
                session_id: "s2".to_string(),
                host: "rdp-server.internal".to_string(),
                port: 3389,
                target_service: Service::ProxyRdp,
                session_token: Vec::new(),
            },
            Message::TcpConnectResponse {
                request_id: 1,
                session_id: "s1".to_string(),
                success: true,
                error: None,
            },
            Message::TcpConnectResponse {
                request_id: 2,
                session_id: "s2".to_string(),
                success: false,
                error: Some("Connection refused".to_string()),
            },
        ];

        for msg in messages {
            let serialized = serialize(&msg);
            let deserialized: Message = deserialize(&serialized);
            // Verify request_id extraction works
            assert!(deserialized.request_id().is_some());
        }
    }

    // ==================== SSH Host Key Message Tests ====================

    #[test]
    fn test_message_ssh_fetch_host_key() {
        let msg = Message::SshFetchHostKey {
            request_id: 700,
            asset_host: "10.0.0.1".to_string(),
            asset_port: 22,
        };
        assert_eq!(msg.request_id(), Some(700));

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::SshFetchHostKey {
            request_id,
            asset_host,
            asset_port,
        } = deserialized
        {
            assert_eq!(request_id, 700);
            assert_eq!(asset_host, "10.0.0.1");
            assert_eq!(asset_port, 22);
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_ssh_host_key_result_success() {
        let msg = Message::SshHostKeyResult {
            request_id: 700,
            success: true,
            host_key: Some("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA".to_string()),
            key_fingerprint: Some("SHA256:abcdef123456".to_string()),
            error: None,
        };
        assert_eq!(msg.request_id(), Some(700));

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::SshHostKeyResult {
            success,
            host_key,
            key_fingerprint,
            error,
            ..
        } = deserialized
        {
            assert!(success);
            assert!(host_key.unwrap().contains("ssh-ed25519"));
            assert!(key_fingerprint.unwrap().contains("SHA256"));
            assert!(error.is_none());
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_ssh_host_key_result_failure() {
        let msg = Message::SshHostKeyResult {
            request_id: 701,
            success: false,
            host_key: None,
            key_fingerprint: None,
            error: Some("Connection refused".to_string()),
        };
        assert_eq!(msg.request_id(), Some(701));

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::SshHostKeyResult { success, error, .. } = deserialized {
            assert!(!success);
            assert_eq!(error, Some("Connection refused".to_string()));
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_ssh_session_open_with_host_key() {
        let msg = Message::SshSessionOpen {
            request_id: 800,
            session_id: "s1".to_string(),
            user_id: "u1".to_string(),
            asset_id: "a1".to_string(),
            asset_host: "host".to_string(),
            asset_port: 22,
            username: "user".to_string(),
            terminal_cols: 80,
            terminal_rows: 24,
            auth_type: "password".to_string(),
            password_ciphertext: Some("v1:pass".to_string()),
            private_key_ciphertext: None,
            passphrase_ciphertext: None,
            expected_host_key: Some("ssh-ed25519 AAAA...test".to_string()),
            session_token: Vec::new(),
        };

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::SshSessionOpen {
            expected_host_key, ..
        } = deserialized
        {
            assert_eq!(
                expected_host_key,
                Some("ssh-ed25519 AAAA...test".to_string())
            );
        } else {
            panic!("Wrong variant");
        }
    }

    // ==================== Vault Crypto Message Tests ====================

    #[test]
    fn test_message_vault_encrypt() {
        let msg = Message::VaultEncrypt {
            request_id: 900,
            domain: "credentials".to_string(),
            plaintext: SensitiveString::new("my-secret-password".to_string()),
        };
        assert_eq!(msg.request_id(), Some(900));

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::VaultEncrypt {
            request_id,
            domain,
            plaintext,
        } = deserialized
        {
            assert_eq!(request_id, 900);
            assert_eq!(domain, "credentials");
            assert_eq!(plaintext.as_str(), "my-secret-password");
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_vault_encrypt_response_success() {
        let msg = Message::VaultEncryptResponse {
            request_id: 900,
            ciphertext: Some("v1:SGVsbG8gV29ybGQ=".to_string()),
            error: None,
        };
        assert_eq!(msg.request_id(), Some(900));
    }

    #[test]
    fn test_message_vault_encrypt_response_error() {
        let msg = Message::VaultEncryptResponse {
            request_id: 901,
            ciphertext: None,
            error: Some("Unknown domain".to_string()),
        };
        assert_eq!(msg.request_id(), Some(901));
    }

    #[test]
    fn test_message_vault_decrypt() {
        let msg = Message::VaultDecrypt {
            request_id: 910,
            domain: "mfa".to_string(),
            ciphertext: "v1:SGVsbG8gV29ybGQ=".to_string(),
        };
        assert_eq!(msg.request_id(), Some(910));
    }

    #[test]
    fn test_message_vault_decrypt_response_success() {
        let msg = Message::VaultDecryptResponse {
            request_id: 910,
            plaintext: Some(SensitiveString::new("decrypted-value".to_string())),
            error: None,
        };
        assert_eq!(msg.request_id(), Some(910));

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::VaultDecryptResponse {
            plaintext, error, ..
        } = deserialized
        {
            assert_eq!(
                plaintext.as_ref().map(|s| s.as_str()),
                Some("decrypted-value")
            );
            assert!(error.is_none());
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_vault_decrypt_response_debug_redacted() {
        let msg = Message::VaultDecryptResponse {
            request_id: 911,
            plaintext: Some(SensitiveString::new("super-secret".to_string())),
            error: None,
        };
        let debug = format!("{:?}", msg);
        assert!(
            !debug.contains("super-secret"),
            "VaultDecryptResponse Debug must NOT contain plaintext"
        );
        assert!(debug.contains("REDACTED"));
    }

    #[test]
    fn test_message_vault_mfa_generate() {
        let msg = Message::VaultMfaGenerate {
            request_id: 920,
            username: "alice".to_string(),
            issuer: "VAUBAN".to_string(),
        };
        assert_eq!(msg.request_id(), Some(920));

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::VaultMfaGenerate {
            username, issuer, ..
        } = deserialized
        {
            assert_eq!(username, "alice");
            assert_eq!(issuer, "VAUBAN");
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_vault_mfa_generate_response() {
        let msg = Message::VaultMfaGenerateResponse {
            request_id: 920,
            encrypted_secret: Some("v1:encrypted".to_string()),
            plaintext_secret: Some(SensitiveString::new("JBSWY3DPEHPK3PXP".to_string())),
            error: None,
        };
        assert_eq!(msg.request_id(), Some(920));
    }

    #[test]
    fn test_message_vault_mfa_verify() {
        let msg = Message::VaultMfaVerify {
            request_id: 930,
            encrypted_secret: "v1:encrypted-totp".to_string(),
            code: "123456".to_string(),
        };
        assert_eq!(msg.request_id(), Some(930));
    }

    #[test]
    fn test_message_vault_mfa_verify_response() {
        let msg = Message::VaultMfaVerifyResponse {
            request_id: 930,
            valid: true,
            error: None,
        };
        assert_eq!(msg.request_id(), Some(930));

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::VaultMfaVerifyResponse { valid, error, .. } = deserialized {
            assert!(valid);
            assert!(error.is_none());
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_vault_mfa_get_secret() {
        let msg = Message::VaultMfaGetSecret {
            request_id: 940,
            encrypted_secret: "v1:encrypted-totp".to_string(),
        };
        assert_eq!(msg.request_id(), Some(940));
    }

    #[test]
    fn test_message_vault_mfa_get_secret_response() {
        let msg = Message::VaultMfaGetSecretResponse {
            request_id: 940,
            plaintext_secret: Some(SensitiveString::new("JBSWY3DPEHPK3PXP".to_string())),
            error: None,
        };
        assert_eq!(msg.request_id(), Some(940));
    }

    #[test]
    fn test_vault_crypto_messages_serialization_roundtrip() {
        let messages: Vec<Message> = vec![
            Message::VaultEncrypt {
                request_id: 1,
                domain: "credentials".to_string(),
                plaintext: SensitiveString::new("secret".to_string()),
            },
            Message::VaultEncryptResponse {
                request_id: 1,
                ciphertext: Some("v1:abc".to_string()),
                error: None,
            },
            Message::VaultDecrypt {
                request_id: 2,
                domain: "mfa".to_string(),
                ciphertext: "v1:abc".to_string(),
            },
            Message::VaultDecryptResponse {
                request_id: 2,
                plaintext: Some(SensitiveString::new("secret".to_string())),
                error: None,
            },
            Message::VaultMfaGenerate {
                request_id: 3,
                username: "user".to_string(),
                issuer: "VAUBAN".to_string(),
            },
            Message::VaultMfaGenerateResponse {
                request_id: 3,
                encrypted_secret: Some("v1:enc".to_string()),
                plaintext_secret: Some(SensitiveString::new("JBSWY3DPEHPK3PXP".to_string())),
                error: None,
            },
            Message::VaultMfaVerify {
                request_id: 4,
                encrypted_secret: "v1:enc".to_string(),
                code: "123456".to_string(),
            },
            Message::VaultMfaVerifyResponse {
                request_id: 4,
                valid: true,
                error: None,
            },
            Message::VaultMfaGetSecret {
                request_id: 5,
                encrypted_secret: "v1:enc".to_string(),
            },
            Message::VaultMfaGetSecretResponse {
                request_id: 5,
                plaintext_secret: Some(SensitiveString::new("JBSWY3DPEHPK3PXP".to_string())),
                error: None,
            },
        ];

        for msg in messages {
            let serialized = serialize(&msg);
            let deserialized: Message = deserialize(&serialized);
            assert!(deserialized.request_id().is_some());
        }
    }

    #[test]
    fn test_message_vault_encrypt_debug_redacts_plaintext() {
        let msg = Message::VaultEncrypt {
            request_id: 950,
            domain: "credentials".to_string(),
            plaintext: SensitiveString::new("top-secret-password".to_string()),
        };
        let debug = format!("{:?}", msg);
        assert!(
            !debug.contains("top-secret-password"),
            "VaultEncrypt Debug must NOT contain plaintext"
        );
        assert!(debug.contains("REDACTED"));
    }

    #[test]
    fn test_message_ssh_session_open_without_host_key() {
        let msg = Message::SshSessionOpen {
            request_id: 801,
            session_id: "s1".to_string(),
            user_id: "u1".to_string(),
            asset_id: "a1".to_string(),
            asset_host: "host".to_string(),
            asset_port: 22,
            username: "user".to_string(),
            terminal_cols: 80,
            terminal_rows: 24,
            auth_type: "password".to_string(),
            password_ciphertext: Some("v1:pass".to_string()),
            private_key_ciphertext: None,
            passphrase_ciphertext: None,
            expected_host_key: None,
            session_token: Vec::new(),
        };

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::SshSessionOpen {
            expected_host_key, ..
        } = deserialized
        {
            assert!(expected_host_key.is_none());
        } else {
            panic!("Wrong variant");
        }
    }

    // ==================== RDP Messages Tests ====================

    #[test]
    fn test_message_rdp_session_open() {
        let msg = Message::RdpSessionOpen {
            request_id: 700,
            session_id: "rdp-sess-123".to_string(),
            user_id: "user-uuid-456".to_string(),
            asset_id: "asset-uuid-789".to_string(),
            asset_host: "10.0.0.50".to_string(),
            asset_port: 3389,
            username: "administrator".to_string(),
            password: Some(SensitiveString::new("rdp-secret".to_string())),
            domain: Some("WORKGROUP".to_string()),
            desktop_width: 1920,
            desktop_height: 1080,
            expected_cert_fingerprint: Some("SHA256:dGVzdA==".to_string()),
            session_token: Vec::new(),
        };
        assert_eq!(msg.request_id(), Some(700));

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::RdpSessionOpen {
            request_id,
            session_id,
            user_id,
            asset_host,
            asset_port,
            username,
            password,
            domain,
            desktop_width,
            desktop_height,
            ..
        } = deserialized
        {
            assert_eq!(request_id, 700);
            assert_eq!(session_id, "rdp-sess-123");
            assert_eq!(user_id, "user-uuid-456");
            assert_eq!(asset_host, "10.0.0.50");
            assert_eq!(asset_port, 3389);
            assert_eq!(username, "administrator");
            assert_eq!(password.as_ref().map(|s| s.as_str()), Some("rdp-secret"));
            assert_eq!(domain.as_deref(), Some("WORKGROUP"));
            assert_eq!(desktop_width, 1920);
            assert_eq!(desktop_height, 1080);
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_rdp_session_open_no_domain() {
        let msg = Message::RdpSessionOpen {
            request_id: 701,
            session_id: "rdp-no-dom".to_string(),
            user_id: "u1".to_string(),
            asset_id: "a1".to_string(),
            asset_host: "host".to_string(),
            asset_port: 3389,
            username: "user".to_string(),
            password: None,
            domain: None,
            desktop_width: 1280,
            desktop_height: 720,
            expected_cert_fingerprint: None,
            session_token: Vec::new(),
        };

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::RdpSessionOpen {
            password, domain, ..
        } = deserialized
        {
            assert!(password.is_none());
            assert!(domain.is_none());
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_rdp_session_opened_success() {
        let msg = Message::RdpSessionOpened {
            request_id: 700,
            session_id: "rdp-sess-123".to_string(),
            success: true,
            desktop_width: 1920,
            desktop_height: 1080,
            error: None,
        };
        assert_eq!(msg.request_id(), Some(700));

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::RdpSessionOpened {
            success,
            desktop_width,
            desktop_height,
            error,
            ..
        } = deserialized
        {
            assert!(success);
            assert_eq!(desktop_width, 1920);
            assert_eq!(desktop_height, 1080);
            assert!(error.is_none());
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_rdp_session_opened_failure() {
        let msg = Message::RdpSessionOpened {
            request_id: 700,
            session_id: "rdp-sess-123".to_string(),
            success: false,
            desktop_width: 0,
            desktop_height: 0,
            error: Some("Authentication failed".to_string()),
        };

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::RdpSessionOpened { success, error, .. } = deserialized {
            assert!(!success);
            assert_eq!(error.as_deref(), Some("Authentication failed"));
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_rdp_display_update() {
        let png_data = vec![0x89, 0x50, 0x4E, 0x47]; // PNG magic bytes
        let msg = Message::RdpDisplayUpdate {
            session_id: "rdp-sess-123".to_string(),
            x: 100,
            y: 200,
            width: 640,
            height: 480,
            png_data: png_data.clone(),
        };

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::RdpDisplayUpdate {
            session_id,
            x,
            y,
            width,
            height,
            png_data: data,
        } = deserialized
        {
            assert_eq!(session_id, "rdp-sess-123");
            assert_eq!(x, 100);
            assert_eq!(y, 200);
            assert_eq!(width, 640);
            assert_eq!(height, 480);
            assert_eq!(data, png_data);
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_rdp_video_frame() {
        let h264_data = vec![0x00, 0x00, 0x00, 0x01, 0x67, 0x42]; // NAL start code + SPS
        let msg = Message::RdpVideoFrame {
            session_id: "rdp-vid-123".to_string(),
            timestamp_us: 16666,
            is_keyframe: true,
            width: 1920,
            height: 1080,
            data: h264_data.clone(),
        };

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::RdpVideoFrame {
            session_id,
            timestamp_us,
            is_keyframe,
            width,
            height,
            data,
        } = deserialized
        {
            assert_eq!(session_id, "rdp-vid-123");
            assert_eq!(timestamp_us, 16666);
            assert!(is_keyframe);
            assert_eq!(width, 1920);
            assert_eq!(height, 1080);
            assert_eq!(data, h264_data);
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_rdp_video_frame_delta() {
        let msg = Message::RdpVideoFrame {
            session_id: "s1".to_string(),
            timestamp_us: 33333,
            is_keyframe: false,
            width: 1280,
            height: 720,
            data: vec![0x00, 0x00, 0x01, 0x41],
        };

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::RdpVideoFrame {
            is_keyframe,
            timestamp_us,
            ..
        } = deserialized
        {
            assert!(!is_keyframe);
            assert_eq!(timestamp_us, 33333);
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_rdp_input_mouse_move() {
        let msg = Message::RdpInput {
            session_id: "rdp-sess".to_string(),
            input: RdpInputEvent::MouseMove { x: 500, y: 300 },
        };

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::RdpInput { session_id, input } = deserialized {
            assert_eq!(session_id, "rdp-sess");
            if let RdpInputEvent::MouseMove { x, y } = input {
                assert_eq!(x, 500);
                assert_eq!(y, 300);
            } else {
                panic!("Wrong input variant");
            }
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_rdp_input_key_pressed() {
        let msg = Message::RdpInput {
            session_id: "rdp-sess".to_string(),
            input: RdpInputEvent::KeyPressed { scancode: 0x1E },
        };

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::RdpInput { input, .. } = deserialized {
            if let RdpInputEvent::KeyPressed { scancode } = input {
                assert_eq!(scancode, 0x1E); // 'A' key
            } else {
                panic!("Wrong input variant");
            }
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_rdp_input_keyboard_high_level() {
        let msg = Message::RdpInput {
            session_id: "rdp-sess".to_string(),
            input: RdpInputEvent::Keyboard {
                code: "KeyA".to_string(),
                key: "a".to_string(),
                pressed: true,
                shift: false,
                ctrl: false,
                alt: false,
                meta: false,
                caps_lock: true,
                num_lock: false,
                scroll_lock: false,
            },
        };

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::RdpInput { input, .. } = deserialized {
            if let RdpInputEvent::Keyboard {
                code,
                key,
                pressed,
                shift,
                ctrl,
                alt,
                meta,
                caps_lock,
                num_lock,
                scroll_lock,
            } = input
            {
                assert_eq!(code, "KeyA");
                assert_eq!(key, "a");
                assert!(pressed);
                assert!(!shift);
                assert!(!ctrl);
                assert!(!alt);
                assert!(!meta);
                assert!(caps_lock);
                assert!(!num_lock);
                assert!(!scroll_lock);
            } else {
                panic!("Wrong input variant");
            }
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_rdp_input_release_all_round_trip() {
        // Stuck-modifier fix: ReleaseAll must survive the IPC round-trip.
        let msg = Message::RdpInput {
            session_id: "rdp-sess".to_string(),
            input: RdpInputEvent::ReleaseAll,
        };

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::RdpInput { session_id, input } = deserialized {
            assert_eq!(session_id, "rdp-sess");
            assert!(matches!(input, RdpInputEvent::ReleaseAll));
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_rdp_input_mouse_button_high_level() {
        let msg = Message::RdpInput {
            session_id: "rdp-sess".to_string(),
            input: RdpInputEvent::MouseButton {
                button: 0,
                pressed: true,
                x: 100,
                y: 200,
            },
        };

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::RdpInput { input, .. } = deserialized {
            if let RdpInputEvent::MouseButton {
                button,
                pressed,
                x,
                y,
            } = input
            {
                assert_eq!(button, 0);
                assert!(pressed);
                assert_eq!(x, 100);
                assert_eq!(y, 200);
            } else {
                panic!("Wrong input variant");
            }
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_rdp_input_mouse_wheel_high_level() {
        let msg = Message::RdpInput {
            session_id: "rdp-sess".to_string(),
            input: RdpInputEvent::MouseWheel {
                delta_x: 0,
                delta_y: -120,
            },
        };

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::RdpInput { input, .. } = deserialized {
            if let RdpInputEvent::MouseWheel { delta_x, delta_y } = input {
                assert_eq!(delta_x, 0);
                assert_eq!(delta_y, -120);
            } else {
                panic!("Wrong input variant");
            }
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_rdp_resize() {
        let msg = Message::RdpResize {
            session_id: "rdp-sess".to_string(),
            width: 1920,
            height: 1080,
        };

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::RdpResize {
            session_id,
            width,
            height,
        } = deserialized
        {
            assert_eq!(session_id, "rdp-sess");
            assert_eq!(width, 1920);
            assert_eq!(height, 1080);
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_rdp_set_video_mode() {
        let msg = Message::RdpSetVideoMode {
            session_id: "rdp-sess-456".to_string(),
            enabled: true,
        };

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::RdpSetVideoMode {
            session_id,
            enabled,
        } = deserialized
        {
            assert_eq!(session_id, "rdp-sess-456");
            assert!(enabled);
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_rdp_set_video_mode_disabled() {
        let msg = Message::RdpSetVideoMode {
            session_id: "rdp-sess-789".to_string(),
            enabled: false,
        };

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::RdpSetVideoMode { enabled, .. } = deserialized {
            assert!(!enabled);
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_rdp_session_close() {
        let msg = Message::RdpSessionClose {
            session_id: "rdp-sess-123".to_string(),
        };

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::RdpSessionClose { session_id } = deserialized {
            assert_eq!(session_id, "rdp-sess-123");
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_rdp_messages_serialization_roundtrip() {
        let messages: Vec<Message> = vec![
            Message::RdpSessionOpen {
                request_id: 1,
                session_id: "s1".to_string(),
                user_id: "u1".to_string(),
                asset_id: "a1".to_string(),
                asset_host: "host".to_string(),
                asset_port: 3389,
                username: "user".to_string(),
                password: Some(SensitiveString::new("pass".to_string())),
                domain: Some("DOMAIN".to_string()),
                desktop_width: 1280,
                desktop_height: 720,
                expected_cert_fingerprint: None,
                session_token: Vec::new(),
            },
            Message::RdpSessionOpened {
                request_id: 1,
                session_id: "s1".to_string(),
                success: true,
                desktop_width: 1280,
                desktop_height: 720,
                error: None,
            },
            Message::RdpDisplayUpdate {
                session_id: "s1".to_string(),
                x: 0,
                y: 0,
                width: 100,
                height: 100,
                png_data: vec![1, 2, 3],
            },
            Message::RdpInput {
                session_id: "s1".to_string(),
                input: RdpInputEvent::MouseMove { x: 10, y: 20 },
            },
            Message::RdpResize {
                session_id: "s1".to_string(),
                width: 1920,
                height: 1080,
            },
            Message::RdpVideoFrame {
                session_id: "s1".to_string(),
                timestamp_us: 16666,
                is_keyframe: true,
                width: 1920,
                height: 1080,
                data: vec![0, 0, 0, 1],
            },
            Message::RdpSessionClose {
                session_id: "s1".to_string(),
            },
        ];

        for msg in messages {
            let serialized = serialize(&msg);
            let deserialized: Message = deserialize(&serialized);
            let _ = deserialized.request_id();
        }
    }

    #[test]
    fn test_rdp_input_event_all_variants_serialize() {
        let events = vec![
            RdpInputEvent::KeyPressed { scancode: 0x1E },
            RdpInputEvent::KeyReleased { scancode: 0x1E },
            RdpInputEvent::MouseMove { x: 100, y: 200 },
            RdpInputEvent::MouseButtonPressed { button: 0 },
            RdpInputEvent::MouseButtonReleased { button: 2 },
            RdpInputEvent::WheelScroll {
                vertical: true,
                amount: 120,
            },
            RdpInputEvent::MouseButton {
                button: 1,
                pressed: true,
                x: 50,
                y: 60,
            },
            RdpInputEvent::MouseWheel {
                delta_x: 10,
                delta_y: -20,
            },
            RdpInputEvent::Keyboard {
                code: "Enter".to_string(),
                key: "Enter".to_string(),
                pressed: true,
                shift: false,
                ctrl: true,
                alt: false,
                meta: false,
                caps_lock: false,
                num_lock: true,
                scroll_lock: false,
            },
            RdpInputEvent::ReleaseAll,
        ];

        for event in events {
            let serialized = serialize(&event);
            let deserialized: RdpInputEvent = deserialize(&serialized);
            let _ = format!("{:?}", deserialized);
        }
    }

    #[test]
    fn test_message_rdp_session_open_password_redacted_in_debug() {
        let msg = Message::RdpSessionOpen {
            request_id: 900,
            session_id: "debug-rdp".to_string(),
            user_id: "u1".to_string(),
            asset_id: "a1".to_string(),
            asset_host: "host".to_string(),
            asset_port: 3389,
            username: "admin".to_string(),
            password: Some(SensitiveString::new("super-secret-rdp-pwd".to_string())),
            domain: None,
            desktop_width: 1280,
            desktop_height: 720,
            expected_cert_fingerprint: None,
            session_token: Vec::new(),
        };
        let debug = format!("{:?}", msg);
        assert!(
            !debug.contains("super-secret-rdp-pwd"),
            "RDP Message Debug must NOT contain password"
        );
        assert!(
            debug.contains("REDACTED"),
            "RDP password must show [REDACTED]"
        );
    }

    // ==================== RDP Recording Message Tests ====================

    #[test]
    fn test_message_rdp_recording_start() {
        let msg = Message::RdpRecordingStart {
            session_id: "rdp-rec-123".to_string(),
            width: 1920,
            height: 1080,
        };
        assert!(msg.request_id().is_none());

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::RdpRecordingStart {
            session_id,
            width,
            height,
        } = deserialized
        {
            assert_eq!(session_id, "rdp-rec-123");
            assert_eq!(width, 1920);
            assert_eq!(height, 1080);
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_rdp_recording_end() {
        let msg = Message::RdpRecordingEnd {
            session_id: "rdp-rec-123".to_string(),
        };
        assert!(msg.request_id().is_none());

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::RdpRecordingEnd { session_id } = deserialized {
            assert_eq!(session_id, "rdp-rec-123");
        } else {
            panic!("Wrong variant");
        }
    }

    // ==================== SSH Recording Message Tests ====================

    #[test]
    fn test_ssh_recording_event_serialization() {
        for event in [
            SshRecordingEvent::Output,
            SshRecordingEvent::Input,
            SshRecordingEvent::Resize,
        ] {
            let serialized = serialize(&event);
            let deserialized: SshRecordingEvent = deserialize(&serialized);
            assert_eq!(deserialized, event);
        }
    }

    #[test]
    fn test_message_ssh_recording_start_roundtrip() {
        let msg = Message::SshRecordingStart {
            session_id: "ssh-rec-456".to_string(),
            width: 120,
            height: 40,
            asset_name: "prod-server".to_string(),
            username: "admin".to_string(),
        };
        assert!(msg.request_id().is_none());

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::SshRecordingStart {
            session_id,
            width,
            height,
            asset_name,
            username,
        } = deserialized
        {
            assert_eq!(session_id, "ssh-rec-456");
            assert_eq!(width, 120);
            assert_eq!(height, 40);
            assert_eq!(asset_name, "prod-server");
            assert_eq!(username, "admin");
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_ssh_recording_data_output_roundtrip() {
        let msg = Message::SshRecordingData {
            session_id: "ssh-rec-456".to_string(),
            timestamp_us: 1_234_567,
            event_type: SshRecordingEvent::Output,
            data: b"hello world\r\n".to_vec(),
        };
        assert!(msg.request_id().is_none());

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::SshRecordingData {
            session_id,
            timestamp_us,
            event_type,
            data,
        } = deserialized
        {
            assert_eq!(session_id, "ssh-rec-456");
            assert_eq!(timestamp_us, 1_234_567);
            assert_eq!(event_type, SshRecordingEvent::Output);
            assert_eq!(data, b"hello world\r\n");
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_ssh_recording_data_input_roundtrip() {
        let msg = Message::SshRecordingData {
            session_id: "ssh-rec-456".to_string(),
            timestamp_us: 2_000_000,
            event_type: SshRecordingEvent::Input,
            data: b"[REDACTED]\r\n".to_vec(),
        };
        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::SshRecordingData {
            event_type, data, ..
        } = deserialized
        {
            assert_eq!(event_type, SshRecordingEvent::Input);
            assert_eq!(data, b"[REDACTED]\r\n");
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_ssh_recording_data_resize_roundtrip() {
        let msg = Message::SshRecordingData {
            session_id: "ssh-rec-456".to_string(),
            timestamp_us: 5_100_000,
            event_type: SshRecordingEvent::Resize,
            data: b"160x50".to_vec(),
        };
        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::SshRecordingData {
            event_type, data, ..
        } = deserialized
        {
            assert_eq!(event_type, SshRecordingEvent::Resize);
            assert_eq!(data, b"160x50");
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_ssh_recording_end_roundtrip() {
        let msg = Message::SshRecordingEnd {
            session_id: "ssh-rec-456".to_string(),
        };
        assert!(msg.request_id().is_none());

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::SshRecordingEnd { session_id } = deserialized {
            assert_eq!(session_id, "ssh-rec-456");
        } else {
            panic!("Wrong variant");
        }
    }

    // ==================== IACS Recording Tests ====================

    #[test]
    fn test_iacs_recording_direction_roundtrip() {
        for dir in [
            IacsRecordingDirection::EwsToAsset,
            IacsRecordingDirection::AssetToEws,
        ] {
            let serialized = serialize(&dir);
            let deserialized: IacsRecordingDirection = deserialize(&serialized);
            assert_eq!(dir, deserialized);
        }
    }

    #[test]
    fn test_message_iacs_recording_channel_start_roundtrip() {
        let msg = Message::IacsRecordingChannelStart {
            session_id: "iacs-1".to_string(),
            channel_id: 1,
            target_host: "plc.local".to_string(),
            target_port: 502,
            opened_at_us: 1000,
            client_ip: "127.0.0.1".to_string(),
            client_port: 51_234,
            server_ip: "10.20.30.40".to_string(),
            server_port: 502,
            connected_at_us: 999_000,
        };
        let deserialized: Message = deserialize(&serialize(&msg));
        if let Message::IacsRecordingChannelStart {
            session_id,
            channel_id,
            target_host,
            target_port,
            opened_at_us,
            client_ip,
            client_port,
            server_ip,
            server_port,
            connected_at_us,
        } = deserialized
        {
            assert_eq!(session_id, "iacs-1");
            assert_eq!(channel_id, 1);
            assert_eq!(target_host, "plc.local");
            assert_eq!(target_port, 502);
            assert_eq!(opened_at_us, 1000);
            assert_eq!(client_ip, "127.0.0.1");
            assert_eq!(client_port, 51_234);
            assert_eq!(server_ip, "10.20.30.40");
            assert_eq!(server_port, 502);
            assert_eq!(connected_at_us, 999_000);
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_iacs_recording_channel_start_ipv6_roundtrip() {
        let msg = Message::IacsRecordingChannelStart {
            session_id: "iacs-2".to_string(),
            channel_id: 7,
            target_host: "plc6.example.invalid".to_string(),
            target_port: 4840,
            opened_at_us: 0,
            client_ip: "fe80::1".to_string(),
            client_port: 49_152,
            server_ip: "2001:db8::42".to_string(),
            server_port: 4840,
            connected_at_us: 1_700_000_000_000_000,
        };
        let deserialized: Message = deserialize(&serialize(&msg));
        if let Message::IacsRecordingChannelStart {
            client_ip,
            server_ip,
            connected_at_us,
            ..
        } = deserialized
        {
            assert_eq!(client_ip, "fe80::1");
            assert_eq!(server_ip, "2001:db8::42");
            assert_eq!(connected_at_us, 1_700_000_000_000_000);
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_iacs_recording_data_roundtrip() {
        let msg = Message::IacsRecordingData {
            session_id: "iacs-1".to_string(),
            channel_id: 2,
            batch_seq: 7,
            direction: IacsRecordingDirection::EwsToAsset,
            timestamp_us: 42_000,
            data: vec![0x00, 0x01, 0x02],
        };
        let deserialized: Message = deserialize(&serialize(&msg));
        if let Message::IacsRecordingData {
            batch_seq,
            direction,
            data,
            ..
        } = deserialized
        {
            assert_eq!(batch_seq, 7);
            assert_eq!(direction, IacsRecordingDirection::EwsToAsset);
            assert_eq!(data, vec![0x00, 0x01, 0x02]);
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_iacs_recording_data_ack_roundtrip() {
        let msg = Message::IacsRecordingDataAck {
            session_id: "iacs-1".to_string(),
            channel_id: 2,
            batch_seq: 7,
        };
        let deserialized: Message = deserialize(&serialize(&msg));
        if let Message::IacsRecordingDataAck {
            session_id,
            channel_id,
            batch_seq,
        } = deserialized
        {
            assert_eq!(session_id, "iacs-1");
            assert_eq!(channel_id, 2);
            assert_eq!(batch_seq, 7);
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_iacs_recording_channel_end_roundtrip() {
        let msg = Message::IacsRecordingChannelEnd {
            session_id: "iacs-1".to_string(),
            channel_id: 2,
            closed_at_us: 99_000,
        };
        let deserialized: Message = deserialize(&serialize(&msg));
        if let Message::IacsRecordingChannelEnd { closed_at_us, .. } = deserialized {
            assert_eq!(closed_at_us, 99_000);
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_iacs_recording_session_end_roundtrip() {
        let msg = Message::IacsRecordingSessionEnd {
            session_id: "iacs-1".to_string(),
        };
        let deserialized: Message = deserialize(&serialize(&msg));
        assert!(matches!(
            deserialized,
            Message::IacsRecordingSessionEnd { .. }
        ));
    }

    #[test]
    fn test_message_recording_file_gzip_request_roundtrip() {
        let msg = Message::RecordingFileGzipRequest {
            request_id: 9,
            session_id: "iacs-1".to_string(),
            src_relative: "2026/05/iacs-1/channels/001.pcap".to_string(),
            dst_relative: "2026/05/iacs-1/channels/001.pcap.gz".to_string(),
        };
        let deserialized: Message = deserialize(&serialize(&msg));
        if let Message::RecordingFileGzipRequest {
            request_id,
            src_relative,
            dst_relative,
            ..
        } = deserialized
        {
            assert_eq!(request_id, 9);
            assert_eq!(src_relative, "2026/05/iacs-1/channels/001.pcap");
            assert_eq!(dst_relative, "2026/05/iacs-1/channels/001.pcap.gz");
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_recording_file_gzip_response_roundtrip() {
        let msg = Message::RecordingFileGzipResponse {
            request_id: 9,
            session_id: "iacs-1".to_string(),
            success: true,
            dst_size: 1234,
            blake3_hex: Some("ab".repeat(32)),
            error: None,
        };
        let deserialized: Message = deserialize(&serialize(&msg));
        if let Message::RecordingFileGzipResponse {
            success,
            dst_size,
            blake3_hex,
            ..
        } = deserialized
        {
            assert!(success);
            assert_eq!(dst_size, 1234);
            assert_eq!(blake3_hex.as_deref(), Some("ab".repeat(32).as_str()));
        } else {
            panic!("Wrong variant");
        }
    }

    // ==================== Recording File Request Tests ====================

    #[test]
    fn test_message_recording_file_request() {
        let msg = Message::RecordingFileRequest {
            request_id: 42,
            session_id: "rec-123".to_string(),
            relative_path: "2026/02/rec-123.mp4".to_string(),
            read_only: false,
        };
        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::RecordingFileRequest {
            request_id,
            session_id,
            relative_path,
            read_only,
        } = deserialized
        {
            assert_eq!(request_id, 42);
            assert_eq!(session_id, "rec-123");
            assert_eq!(relative_path, "2026/02/rec-123.mp4");
            assert!(!read_only);
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_recording_file_response() {
        let msg = Message::RecordingFileResponse {
            request_id: 42,
            session_id: "rec-123".to_string(),
            success: true,
            error: None,
        };
        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::RecordingFileResponse {
            request_id,
            session_id,
            success,
            error,
        } = deserialized
        {
            assert_eq!(request_id, 42);
            assert_eq!(session_id, "rec-123");
            assert!(success);
            assert!(error.is_none());
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_recording_delete_request_roundtrip() {
        let msg = Message::RecordingDeleteRequest {
            request_id: 7,
            session_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            relative_path: "2026/05/550e8400-e29b-41d4-a716-446655440000/".to_string(),
        };
        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::RecordingDeleteRequest {
            request_id,
            session_id,
            relative_path,
        } = deserialized
        {
            assert_eq!(request_id, 7);
            assert!(session_id.contains("550e8400"));
            assert!(relative_path.ends_with('/'));
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_recording_delete_response_roundtrip() {
        let msg = Message::RecordingDeleteResponse {
            request_id: 7,
            session_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            success: true,
            bytes_freed: 12345,
            error: None,
        };
        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::RecordingDeleteResponse {
            request_id,
            success,
            bytes_freed,
            error,
            ..
        } = deserialized
        {
            assert_eq!(request_id, 7);
            assert!(success);
            assert_eq!(bytes_freed, 12345);
            assert!(error.is_none());
        } else {
            panic!("Wrong variant");
        }
    }

    // ==================== ACME Message Tests ====================

    #[test]
    fn test_message_acme_renew_request() {
        let msg = Message::AcmeRenewRequest {
            request_id: 2000,
            directory_url: "https://acme-v02.api.letsencrypt.org/directory".to_string(),
            domains: vec!["example.com".to_string(), "www.example.com".to_string()],
            email: "admin@example.com".to_string(),
            account_key_path: "/etc/vauban/acme/account.pem".to_string(),
            cert_path: "/etc/vauban/certs/server.crt".to_string(),
            key_path: "/etc/vauban/certs/server.key".to_string(),
            eab_kid: None,
            eab_hmac_key: None,
        };
        assert_eq!(msg.request_id(), Some(2000));

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::AcmeRenewRequest {
            request_id,
            domains,
            email,
            ..
        } = deserialized
        {
            assert_eq!(request_id, 2000);
            assert_eq!(domains.len(), 2);
            assert_eq!(email, "admin@example.com");
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_acme_renew_response_success() {
        let msg = Message::AcmeRenewResponse {
            request_id: 2000,
            success: true,
            error: None,
            cert_pem: Some(
                "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----".to_string(),
            ),
            key_pem: Some(SensitiveString::new(
                "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----".to_string(),
            )),
        };
        assert_eq!(msg.request_id(), Some(2000));

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::AcmeRenewResponse {
            success,
            cert_pem,
            key_pem,
            ..
        } = deserialized
        {
            assert!(success);
            assert!(cert_pem.is_some());
            assert!(key_pem.is_some());
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_acme_renew_response_failure() {
        let msg = Message::AcmeRenewResponse {
            request_id: 2001,
            success: false,
            error: Some("Challenge failed: DNS unreachable".to_string()),
            cert_pem: None,
            key_pem: None,
        };
        assert_eq!(msg.request_id(), Some(2001));
    }

    #[test]
    fn test_message_acme_renew_response_debug_redacts_key() {
        let msg = Message::AcmeRenewResponse {
            request_id: 2002,
            success: true,
            error: None,
            cert_pem: Some("cert-data".to_string()),
            key_pem: Some(SensitiveString::new("super-secret-key".to_string())),
        };
        let debug = format!("{:?}", msg);
        assert!(
            !debug.contains("super-secret-key"),
            "AcmeRenewResponse Debug must NOT contain private key"
        );
        assert!(debug.contains("REDACTED"));
    }

    #[test]
    fn test_message_acme_challenge_install() {
        let msg = Message::AcmeChallengeInstall {
            request_id: 2010,
            domain: "example.com".to_string(),
            challenge_cert_der: vec![0x30, 0x82, 0x01],
            challenge_key_der: vec![0x30, 0x82, 0x02],
        };
        assert_eq!(msg.request_id(), Some(2010));

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::AcmeChallengeInstall {
            domain,
            challenge_cert_der,
            ..
        } = deserialized
        {
            assert_eq!(domain, "example.com");
            assert_eq!(challenge_cert_der, vec![0x30, 0x82, 0x01]);
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_acme_challenge_remove() {
        let msg = Message::AcmeChallengeRemove {
            request_id: 2011,
            domain: "example.com".to_string(),
        };
        assert_eq!(msg.request_id(), Some(2011));

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::AcmeChallengeRemove { domain, .. } = deserialized {
            assert_eq!(domain, "example.com");
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_acme_cert_activate() {
        let msg = Message::AcmeCertActivate {
            request_id: 2020,
            cert_pem: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----".to_string(),
            key_pem: SensitiveString::new(
                "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----".to_string(),
            ),
        };
        assert_eq!(msg.request_id(), Some(2020));

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::AcmeCertActivate {
            cert_pem, key_pem, ..
        } = deserialized
        {
            assert!(cert_pem.contains("CERTIFICATE"));
            assert!(key_pem.as_str().contains("PRIVATE KEY"));
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_acme_cert_activate_debug_redacts_key() {
        let msg = Message::AcmeCertActivate {
            request_id: 2021,
            cert_pem: "cert".to_string(),
            key_pem: SensitiveString::new("private-key-material".to_string()),
        };
        let debug = format!("{:?}", msg);
        assert!(
            !debug.contains("private-key-material"),
            "AcmeCertActivate Debug must NOT contain private key"
        );
        assert!(debug.contains("REDACTED"));
    }

    #[test]
    fn test_message_tls_cert_provision_roundtrip() {
        let msg = Message::TlsCertProvision {
            cert_pem: "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----".to_string(),
            key_pem: SensitiveString::new(
                "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----".to_string(),
            ),
        };
        assert_eq!(msg.request_id(), None);

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::TlsCertProvision { cert_pem, key_pem } = deserialized {
            assert!(cert_pem.contains("CERTIFICATE"));
            assert!(key_pem.as_str().contains("PRIVATE KEY"));
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_tls_cert_provision_debug_redacts_key() {
        let msg = Message::TlsCertProvision {
            cert_pem: "cert-data".to_string(),
            key_pem: SensitiveString::new("secret-key-material".to_string()),
        };
        let debug = format!("{:?}", msg);
        assert!(
            !debug.contains("secret-key-material"),
            "TlsCertProvision Debug must NOT contain private key"
        );
        assert!(debug.contains("REDACTED"));
    }

    #[test]
    fn test_message_acme_renew_request_with_eab() {
        let msg = Message::AcmeRenewRequest {
            request_id: 2030,
            directory_url: "https://acme.zerossl.com/v2/DV90".to_string(),
            domains: vec!["zerossl.example.com".to_string()],
            email: "admin@example.com".to_string(),
            account_key_path: "/etc/vauban/acme/account.pem".to_string(),
            cert_path: "/etc/vauban/certs/server.crt".to_string(),
            key_path: "/etc/vauban/certs/server.key".to_string(),
            eab_kid: Some("kid_12345".to_string()),
            eab_hmac_key: Some(SensitiveString::new("hmac_secret_key".to_string())),
        };
        assert_eq!(msg.request_id(), Some(2030));

        let debug = format!("{:?}", msg);
        assert!(
            !debug.contains("hmac_secret_key"),
            "ACME EAB HMAC key must be redacted in debug"
        );
    }

    #[test]
    fn test_acme_messages_serialization_roundtrip() {
        let messages: Vec<Message> = vec![
            Message::AcmeRenewRequest {
                request_id: 1,
                directory_url: "https://acme.test".to_string(),
                domains: vec!["test.com".to_string()],
                email: "test@test.com".to_string(),
                account_key_path: "/tmp/account.pem".to_string(),
                cert_path: "/tmp/cert.pem".to_string(),
                key_path: "/tmp/key.pem".to_string(),
                eab_kid: None,
                eab_hmac_key: None,
            },
            Message::AcmeRenewResponse {
                request_id: 1,
                success: true,
                error: None,
                cert_pem: Some("cert".to_string()),
                key_pem: Some(SensitiveString::new("key".to_string())),
            },
            Message::AcmeChallengeInstall {
                request_id: 2,
                domain: "test.com".to_string(),
                challenge_cert_der: vec![1, 2, 3],
                challenge_key_der: vec![4, 5, 6],
            },
            Message::AcmeChallengeRemove {
                request_id: 3,
                domain: "test.com".to_string(),
            },
            Message::AcmeCertActivate {
                request_id: 4,
                cert_pem: "cert".to_string(),
                key_pem: SensitiveString::new("key".to_string()),
            },
        ];

        for msg in messages {
            let serialized = serialize(&msg);
            let deserialized: Message = deserialize(&serialized);
            assert!(deserialized.request_id().is_some());
        }
    }

    // ==================== SensitiveString Tests ====================

    #[test]
    fn test_sensitive_string_debug_redacts() {
        let secret = SensitiveString::new("my-password".to_string());
        let debug = format!("{:?}", secret);
        assert_eq!(
            debug, "[REDACTED]",
            "SensitiveString Debug must show [REDACTED]"
        );
        assert!(
            !debug.contains("my-password"),
            "SensitiveString Debug must NOT contain the actual secret"
        );
    }

    #[test]
    fn test_sensitive_string_into_inner() {
        let secret = SensitiveString::new("secret-value".to_string());
        let inner = secret.into_inner();
        assert_eq!(inner, "secret-value");
    }

    #[test]
    fn test_sensitive_string_as_str() {
        let secret = SensitiveString::new("hello".to_string());
        assert_eq!(secret.as_str(), "hello");
    }

    #[test]
    fn test_sensitive_string_clone() {
        let original = SensitiveString::new("cloneable".to_string());
        let cloned = original.clone();
        assert_eq!(original.as_str(), cloned.as_str());
    }

    #[test]
    fn test_sensitive_string_partial_eq() {
        let a = SensitiveString::new("same".to_string());
        let b = SensitiveString::new("same".to_string());
        let c = SensitiveString::new("different".to_string());
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_sensitive_string_from_string() {
        let s: SensitiveString = "from-str".into();
        assert_eq!(s.as_str(), "from-str");

        let s2: SensitiveString = String::from("from-string").into();
        assert_eq!(s2.as_str(), "from-string");
    }

    #[test]
    fn test_sensitive_string_serde_roundtrip() {
        let original = SensitiveString::new("serde-test".to_string());
        let serialized = serialize(&original);
        let deserialized: SensitiveString = deserialize(&serialized);
        assert_eq!(deserialized.as_str(), "serde-test");
    }

    #[test]
    fn test_sensitive_string_in_message_debug_redacted() {
        // NOTE: SshSessionOpen no longer carries SensitiveString secrets
        // (it ships vault ciphertexts now, see #4). RdpSessionOpen is the
        // canonical Message that still embeds a SensitiveString password,
        // so it is the right vehicle to pin the redaction contract.
        let msg = Message::RdpSessionOpen {
            request_id: 999,
            session_id: "debug-test".to_string(),
            user_id: "u1".to_string(),
            asset_id: "a1".to_string(),
            asset_host: "host".to_string(),
            asset_port: 3389,
            username: "user".to_string(),
            password: Some(SensitiveString::new("super-secret-pwd".to_string())),
            domain: None,
            desktop_width: 1280,
            desktop_height: 720,
            expected_cert_fingerprint: None,
            session_token: Vec::new(),
        };
        let debug = format!("{:?}", msg);
        assert!(
            !debug.contains("super-secret-pwd"),
            "Message Debug must NOT contain password"
        );
        assert!(
            debug.contains("REDACTED"),
            "Message Debug must show [REDACTED]"
        );
    }

    #[test]
    fn test_sensitive_string_message_serde_roundtrip() {
        let msg = Message::RdpSessionOpen {
            request_id: 1000,
            session_id: "rt-test".to_string(),
            user_id: "u1".to_string(),
            asset_id: "a1".to_string(),
            asset_host: "host".to_string(),
            asset_port: 3389,
            username: "user".to_string(),
            password: Some(SensitiveString::new("roundtrip-pwd".to_string())),
            domain: None,
            desktop_width: 1280,
            desktop_height: 720,
            expected_cert_fingerprint: None,
            session_token: Vec::new(),
        };
        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::RdpSessionOpen { password, .. } = deserialized {
            assert_eq!(
                password.as_ref().map(|s| s.as_str()),
                Some("roundtrip-pwd"),
                "SensitiveString must survive IPC serialization roundtrip"
            );
        } else {
            panic!("Wrong variant");
        }
    }

    // ==================== Access Control Message Tests ====================

    #[test]
    fn test_access_check_result_serialization() {
        let result = AccessCheckResult {
            allowed: true,
            require_mfa: false,
            require_approval: true,
            max_session_duration: Some(3600),
        };
        let serialized = serialize(&result);
        let deserialized: AccessCheckResult = deserialize(&serialized);
        assert!(deserialized.allowed);
        assert!(!deserialized.require_mfa);
        assert!(deserialized.require_approval);
        assert_eq!(deserialized.max_session_duration, Some(3600));
    }

    #[test]
    fn test_access_request_check_access() {
        let req = AccessRequest::CheckAccess {
            user_id: 1,
            asset_group_id: 2,
            protocol: "ssh".to_string(),
        };
        let serialized = serialize(&req);
        let deserialized: AccessRequest = deserialize(&serialized);
        if let AccessRequest::CheckAccess {
            user_id,
            asset_group_id,
            protocol,
        } = deserialized
        {
            assert_eq!(user_id, 1);
            assert_eq!(asset_group_id, 2);
            assert_eq!(protocol, "ssh");
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_access_request_list_accessible_groups() {
        let page = IpcPageParams {
            limit: 10,
            offset: 0,
        };
        let req = AccessRequest::ListAccessibleGroups { user_id: 42, page };
        let serialized = serialize(&req);
        let deserialized: AccessRequest = deserialize(&serialized);
        if let AccessRequest::ListAccessibleGroups { user_id, page: p } = deserialized {
            assert_eq!(user_id, 42);
            assert_eq!(p.limit, 10);
            assert_eq!(p.offset, 0);
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_access_request_create_rule() {
        let data = AccessRuleData {
            name: "Test Rule".to_string(),
            description: Some("desc".to_string()),
            user_group_id: 1,
            asset_group_id: 2,
            allowed_protocols: vec!["ssh".to_string(), "rdp".to_string()],
            valid_from: None,
            valid_until: None,
            require_mfa: true,
            require_approval: false,
            max_session_duration: Some(7200),
            is_active: true,
            priority: 10,
        };
        let req = AccessRequest::CreateAccessRule {
            data,
            actor_uuid: None,
        };
        let serialized = serialize(&req);
        let deserialized: AccessRequest = deserialize(&serialized);
        if let AccessRequest::CreateAccessRule { data, .. } = deserialized {
            assert_eq!(data.name, "Test Rule");
            assert_eq!(data.allowed_protocols.len(), 2);
            assert!(data.require_mfa);
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_access_request_all_variants_serialize() {
        let p = IpcPageParams {
            limit: 10,
            offset: 0,
        };
        let requests: Vec<AccessRequest> = vec![
            AccessRequest::CheckAccess {
                user_id: 1,
                asset_group_id: 1,
                protocol: "ssh".to_string(),
            },
            AccessRequest::CheckAccessMulti {
                user_id: 1,
                asset_group_ids: vec![1, 2],
                protocol: "ssh".to_string(),
            },
            AccessRequest::ListAccessibleGroups {
                user_id: 1,
                page: p,
            },
            AccessRequest::CreateAccessRule {
                data: AccessRuleData {
                    name: "r".to_string(),
                    description: None,
                    user_group_id: 1,
                    asset_group_id: 1,
                    allowed_protocols: vec![],
                    valid_from: None,
                    valid_until: None,
                    require_mfa: false,
                    require_approval: false,
                    max_session_duration: None,
                    is_active: true,
                    priority: 0,
                },
                actor_uuid: None,
            },
            AccessRequest::GetAccessRule {
                uuid: "u".to_string(),
            },
            AccessRequest::ListAccessRules { page: p },
            AccessRequest::UpdateAccessRule {
                uuid: "u".to_string(),
                data: AccessRuleData {
                    name: "r".to_string(),
                    description: None,
                    user_group_id: 1,
                    asset_group_id: 1,
                    allowed_protocols: vec![],
                    valid_from: None,
                    valid_until: None,
                    require_mfa: false,
                    require_approval: false,
                    max_session_duration: None,
                    is_active: true,
                    priority: 0,
                },
                actor_uuid: None,
            },
            AccessRequest::DeleteAccessRule {
                uuid: "u".to_string(),
            },
            AccessRequest::CreateVaubanGroup {
                name: "g".to_string(),
                description: None,
            },
            AccessRequest::GetVaubanGroup {
                uuid: "u".to_string(),
            },
            AccessRequest::GetVaubanGroupById { id: 1 },
            AccessRequest::ListVaubanGroups { page: p },
            AccessRequest::UpdateVaubanGroup {
                uuid: "u".to_string(),
                name: "g".to_string(),
                description: None,
            },
            AccessRequest::DeleteVaubanGroup {
                uuid: "u".to_string(),
            },
            AccessRequest::AddGroupMember {
                group_id: 1,
                user_id: 1,
            },
            AccessRequest::RemoveGroupMember {
                group_id: 1,
                user_id: 1,
            },
            AccessRequest::ListGroupMembers {
                group_id: 1,
                page: p,
            },
            AccessRequest::ListUserGroups {
                user_id: 1,
                page: p,
            },
            AccessRequest::CreateAssetGroup {
                name: "ag".to_string(),
                slug: "ag".to_string(),
                description: None,
                color: "#000".to_string(),
                icon: "server".to_string(),
                actor_uuid: None,
            },
            AccessRequest::GetAssetGroup {
                uuid: "u".to_string(),
            },
            AccessRequest::ListAssetGroups {
                page: p,
                include_virtual: false,
            },
            AccessRequest::UpdateAssetGroup {
                uuid: "u".to_string(),
                name: "ag".to_string(),
                slug: "ag".to_string(),
                description: None,
                color: "#000".to_string(),
                icon: "server".to_string(),
                actor_uuid: None,
            },
            AccessRequest::DeleteAssetGroup {
                uuid: "u".to_string(),
            },
            AccessRequest::ListUserGroupOptions { page: p },
            AccessRequest::ListAssetGroupOptions {
                page: p,
                include_virtual: false,
            },
        ];
        assert_eq!(requests.len(), 25);
        for req in requests {
            let serialized = serialize(&req);
            let _: AccessRequest = deserialize(&serialized);
        }
    }

    #[test]
    fn test_access_response_all_variants_serialize() {
        let responses: Vec<AccessResponse> = vec![
            AccessResponse::AccessChecked(AccessCheckResult {
                allowed: true,
                require_mfa: false,
                require_approval: false,
                max_session_duration: None,
            }),
            AccessResponse::AccessCheckedMulti(vec![AccessCheckResultEntry {
                asset_group_id: 1,
                result: AccessCheckResult {
                    allowed: true,
                    require_mfa: false,
                    require_approval: false,
                    max_session_duration: None,
                },
            }]),
            AccessResponse::AccessibleGroupsPage(IpcPage {
                items: vec![AccessibleGroupEntry {
                    asset_group_id: 1,
                    protocols: vec!["ssh".to_string()],
                }],
                has_more: false,
            }),
            AccessResponse::AccessRule(Ok(AccessRuleInfo {
                uuid: "u".to_string(),
                name: "r".to_string(),
                description: None,
                user_group_id: 1,
                user_group_uuid: "ug-uuid".to_string(),
                user_group_name: "ug".to_string(),
                asset_group_id: 1,
                asset_group_uuid: "ag-uuid".to_string(),
                asset_group_name: "ag".to_string(),
                allowed_protocols: vec![],
                valid_from: None,
                valid_until: None,
                require_mfa: false,
                require_approval: false,
                max_session_duration: None,
                is_active: true,
                priority: 0,
                created_at: "now".to_string(),
                updated_at: "now".to_string(),
            })),
            AccessResponse::AccessRulePage(IpcPage {
                items: vec![],
                has_more: false,
            }),
            AccessResponse::VaubanGroup(Ok(VaubanGroupInfo {
                id: 1,
                uuid: "u".to_string(),
                name: "g".to_string(),
                description: None,
                source: "local".to_string(),
                external_id: None,
                created_at: "now".to_string(),
                updated_at: "now".to_string(),
                last_synced: None,
                member_count: 5,
            })),
            AccessResponse::VaubanGroupPage(IpcPage {
                items: vec![],
                has_more: false,
            }),
            AccessResponse::MemberListPage(IpcPage {
                items: vec![1, 2, 3],
                has_more: false,
            }),
            AccessResponse::UserGroupPage(IpcPage {
                items: vec![],
                has_more: false,
            }),
            AccessResponse::AssetGroup(Ok(AssetGroupInfo {
                id: 1,
                uuid: "u".to_string(),
                name: "ag".to_string(),
                slug: "ag".to_string(),
                description: None,
                color: "#000".to_string(),
                icon: "server".to_string(),
                created_at: "now".to_string(),
                updated_at: "now".to_string(),
                kind: ASSET_GROUP_KIND_STATIC.to_string(),
            })),
            AccessResponse::AssetGroupPage(IpcPage {
                items: vec![],
                has_more: false,
            }),
            AccessResponse::UserGroupOptionsPage(IpcPage {
                items: vec![],
                has_more: false,
            }),
            AccessResponse::AssetGroupOptionsPage(IpcPage {
                items: vec![],
                has_more: false,
            }),
            AccessResponse::Ok,
            AccessResponse::Deleted(Ok(())),
            AccessResponse::Error("err".to_string()),
        ];
        assert_eq!(responses.len(), 16);
        for resp in responses {
            let serialized = serialize(&resp);
            let _: AccessResponse = deserialize(&serialized);
        }
    }

    /// Extract the bincode variant discriminant (first byte for indices < 251).
    fn bincode_variant_index(bytes: &[u8]) -> u8 {
        bytes[0]
    }

    /// Bincode encodes enum variants by ordinal index.
    /// Inserting a variant in the middle shifts all subsequent indices,
    /// breaking wire compatibility between different builds.
    /// New variants MUST be appended at the END of the enum.
    #[test]
    fn test_access_request_bincode_variant_indices_stable() {
        let p = IpcPageParams {
            limit: 10,
            offset: 0,
        };
        let dummy_data = AccessRuleData {
            name: "r".into(),
            description: None,
            user_group_id: 1,
            asset_group_id: 1,
            allowed_protocols: vec![],
            valid_from: None,
            valid_until: None,
            require_mfa: false,
            require_approval: false,
            max_session_duration: None,
            is_active: true,
            priority: 0,
        };
        let expected: Vec<(&str, u8, AccessRequest)> = vec![
            (
                "CheckAccess",
                0,
                AccessRequest::CheckAccess {
                    user_id: 1,
                    asset_group_id: 1,
                    protocol: "ssh".into(),
                },
            ),
            (
                "ListAccessibleGroups",
                1,
                AccessRequest::ListAccessibleGroups {
                    user_id: 1,
                    page: p,
                },
            ),
            (
                "CreateAccessRule",
                2,
                AccessRequest::CreateAccessRule {
                    data: dummy_data.clone(),
                    actor_uuid: None,
                },
            ),
            (
                "GetAccessRule",
                3,
                AccessRequest::GetAccessRule { uuid: "u".into() },
            ),
            (
                "ListAccessRules",
                4,
                AccessRequest::ListAccessRules { page: p },
            ),
            (
                "UpdateAccessRule",
                5,
                AccessRequest::UpdateAccessRule {
                    uuid: "u".into(),
                    data: dummy_data,
                    actor_uuid: None,
                },
            ),
            (
                "DeleteAccessRule",
                6,
                AccessRequest::DeleteAccessRule { uuid: "u".into() },
            ),
            (
                "CreateVaubanGroup",
                7,
                AccessRequest::CreateVaubanGroup {
                    name: "g".into(),
                    description: None,
                },
            ),
            (
                "GetVaubanGroup",
                8,
                AccessRequest::GetVaubanGroup { uuid: "u".into() },
            ),
            (
                "GetVaubanGroupById",
                9,
                AccessRequest::GetVaubanGroupById { id: 1 },
            ),
            (
                "ListVaubanGroups",
                10,
                AccessRequest::ListVaubanGroups { page: p },
            ),
            (
                "UpdateVaubanGroup",
                11,
                AccessRequest::UpdateVaubanGroup {
                    uuid: "u".into(),
                    name: "g".into(),
                    description: None,
                },
            ),
            (
                "DeleteVaubanGroup",
                12,
                AccessRequest::DeleteVaubanGroup { uuid: "u".into() },
            ),
            (
                "AddGroupMember",
                13,
                AccessRequest::AddGroupMember {
                    group_id: 1,
                    user_id: 1,
                },
            ),
            (
                "RemoveGroupMember",
                14,
                AccessRequest::RemoveGroupMember {
                    group_id: 1,
                    user_id: 1,
                },
            ),
            (
                "ListGroupMembers",
                15,
                AccessRequest::ListGroupMembers {
                    group_id: 1,
                    page: p,
                },
            ),
            (
                "ListUserGroups",
                16,
                AccessRequest::ListUserGroups {
                    user_id: 1,
                    page: p,
                },
            ),
            (
                "CreateAssetGroup",
                17,
                AccessRequest::CreateAssetGroup {
                    name: "ag".into(),
                    slug: "ag".into(),
                    description: None,
                    color: "#000".into(),
                    icon: "server".into(),
                    actor_uuid: None,
                },
            ),
            (
                "GetAssetGroup",
                18,
                AccessRequest::GetAssetGroup { uuid: "u".into() },
            ),
            (
                "ListAssetGroups",
                19,
                AccessRequest::ListAssetGroups {
                    page: p,
                    include_virtual: false,
                },
            ),
            (
                "UpdateAssetGroup",
                20,
                AccessRequest::UpdateAssetGroup {
                    uuid: "u".into(),
                    name: "ag".into(),
                    slug: "ag".into(),
                    description: None,
                    color: "#000".into(),
                    icon: "server".into(),
                    actor_uuid: None,
                },
            ),
            (
                "DeleteAssetGroup",
                21,
                AccessRequest::DeleteAssetGroup { uuid: "u".into() },
            ),
            (
                "ListUserGroupOptions",
                22,
                AccessRequest::ListUserGroupOptions { page: p },
            ),
            (
                "ListAssetGroupOptions",
                23,
                AccessRequest::ListAssetGroupOptions {
                    page: p,
                    include_virtual: false,
                },
            ),
            (
                "CheckAccessMulti",
                24,
                AccessRequest::CheckAccessMulti {
                    user_id: 1,
                    asset_group_ids: vec![1],
                    protocol: "ssh".into(),
                },
            ),
            (
                "CheckAccessByUuid",
                25,
                AccessRequest::CheckAccessByUuid {
                    user_uuid: "u".into(),
                    asset_uuid: "a".into(),
                    protocol: "ssh".into(),
                },
            ),
        ];
        for (name, idx, variant) in &expected {
            let bytes = serialize(variant);
            let actual = bincode_variant_index(&bytes);
            assert_eq!(
                actual, *idx,
                "AccessRequest::{name} has bincode index {actual} but expected {idx}. \
                 New variants MUST be appended at the END of the enum to preserve wire compatibility."
            );
        }
    }

    #[test]
    fn test_access_response_bincode_variant_indices_stable() {
        let empty_page_i32: IpcPage<i32> = IpcPage {
            items: vec![],
            has_more: false,
        };
        let empty_page_vg: IpcPage<VaubanGroupInfo> = IpcPage {
            items: vec![],
            has_more: false,
        };
        let empty_page_ag: IpcPage<AssetGroupInfo> = IpcPage {
            items: vec![],
            has_more: false,
        };
        let empty_page_ri: IpcPage<AccessRuleInfo> = IpcPage {
            items: vec![],
            has_more: false,
        };
        let empty_page_go: IpcPage<GroupOption> = IpcPage {
            items: vec![],
            has_more: false,
        };
        let empty_page_ae: IpcPage<AccessibleGroupEntry> = IpcPage {
            items: vec![],
            has_more: false,
        };

        let expected: Vec<(&str, u8, AccessResponse)> = vec![
            (
                "AccessChecked",
                0,
                AccessResponse::AccessChecked(AccessCheckResult {
                    allowed: false,
                    require_mfa: false,
                    require_approval: false,
                    max_session_duration: None,
                }),
            ),
            (
                "AccessibleGroupsPage",
                1,
                AccessResponse::AccessibleGroupsPage(empty_page_ae),
            ),
            ("AccessRule", 2, AccessResponse::AccessRule(Err("e".into()))),
            (
                "AccessRulePage",
                3,
                AccessResponse::AccessRulePage(empty_page_ri),
            ),
            (
                "VaubanGroup",
                4,
                AccessResponse::VaubanGroup(Err("e".into())),
            ),
            (
                "VaubanGroupPage",
                5,
                AccessResponse::VaubanGroupPage(empty_page_vg),
            ),
            (
                "MemberListPage",
                6,
                AccessResponse::MemberListPage(empty_page_i32),
            ),
            (
                "UserGroupPage",
                7,
                AccessResponse::UserGroupPage(IpcPage {
                    items: vec![],
                    has_more: false,
                }),
            ),
            ("AssetGroup", 8, AccessResponse::AssetGroup(Err("e".into()))),
            (
                "AssetGroupPage",
                9,
                AccessResponse::AssetGroupPage(empty_page_ag),
            ),
            (
                "UserGroupOptionsPage",
                10,
                AccessResponse::UserGroupOptionsPage(empty_page_go.clone()),
            ),
            (
                "AssetGroupOptionsPage",
                11,
                AccessResponse::AssetGroupOptionsPage(empty_page_go),
            ),
            ("Ok", 12, AccessResponse::Ok),
            ("Deleted", 13, AccessResponse::Deleted(Ok(()))),
            ("Error", 14, AccessResponse::Error("e".into())),
            (
                "AccessCheckedMulti",
                15,
                AccessResponse::AccessCheckedMulti(vec![]),
            ),
        ];
        for (name, idx, variant) in &expected {
            let bytes = serialize(variant);
            let actual = bincode_variant_index(&bytes);
            assert_eq!(
                actual, *idx,
                "AccessResponse::{name} has bincode index {actual} but expected {idx}. \
                 New variants MUST be appended at the END of the enum to preserve wire compatibility."
            );
        }
    }

    #[test]
    fn test_message_access_request_roundtrip() {
        let msg = Message::AccessRequest {
            request_id: 3000,
            request: AccessRequest::CheckAccess {
                user_id: 5,
                asset_group_id: 10,
                protocol: "rdp".to_string(),
            },
        };
        assert_eq!(msg.request_id(), Some(3000));
        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::AccessRequest {
            request_id,
            request,
        } = deserialized
        {
            assert_eq!(request_id, 3000);
            if let AccessRequest::CheckAccess { user_id, .. } = request {
                assert_eq!(user_id, 5);
            } else {
                panic!("Wrong inner variant");
            }
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_access_response_roundtrip() {
        let msg = Message::AccessResponse {
            request_id: 3001,
            response: AccessResponse::AccessChecked(AccessCheckResult {
                allowed: true,
                require_mfa: true,
                require_approval: false,
                max_session_duration: Some(1800),
            }),
        };
        assert_eq!(msg.request_id(), Some(3001));
        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::AccessResponse {
            response: AccessResponse::AccessChecked(result),
            ..
        } = deserialized
        {
            assert!(result.allowed);
            assert!(result.require_mfa);
            assert_eq!(result.max_session_duration, Some(1800));
        } else {
            panic!("Wrong variant");
        }
    }

    // ==================== Admin Command Message Tests ====================

    #[test]
    fn test_admin_command_create_user() {
        let cmd = AdminCommand::CreateUser {
            username: "admin".to_string(),
            email: "admin@test.com".to_string(),
            password_hash: "argon2:hash".to_string(),
            is_superuser: true,
            is_staff: true,
        };
        let serialized = serialize(&cmd);
        let deserialized: AdminCommand = deserialize(&serialized);
        if let AdminCommand::CreateUser {
            username,
            is_superuser,
            ..
        } = deserialized
        {
            assert_eq!(username, "admin");
            assert!(is_superuser);
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_admin_command_all_variants_serialize() {
        let commands: Vec<AdminCommand> = vec![
            AdminCommand::CreateUser {
                username: "u".to_string(),
                email: "e@e".to_string(),
                password_hash: "h".to_string(),
                is_superuser: false,
                is_staff: false,
            },
            AdminCommand::ResetPassword {
                username: "u".to_string(),
                password_hash: "h".to_string(),
            },
            AdminCommand::ResetMfa {
                username: "u".to_string(),
            },
            AdminCommand::ListUnencryptedSecrets,
            AdminCommand::UpdateUserMfaSecret {
                user_id: 1,
                encrypted_secret: "s".to_string(),
            },
            AdminCommand::UpdateAssetConnectionConfig {
                asset_id: 1,
                encrypted_config: "c".to_string(),
            },
            AdminCommand::SeedUsers { users: vec![] },
            AdminCommand::SeedAssets { assets: vec![] },
            AdminCommand::SeedSessions { sessions: vec![] },
        ];
        assert_eq!(commands.len(), 9);
        for cmd in commands {
            let serialized = serialize(&cmd);
            let _: AdminCommand = deserialize(&serialized);
        }
    }

    #[test]
    fn test_admin_response_all_variants_serialize() {
        let responses: Vec<AdminResponse> = vec![
            AdminResponse::Ok,
            AdminResponse::Created {
                uuid: "uuid-123".to_string(),
            },
            AdminResponse::UnencryptedSecrets(vec![UnencryptedSecretEntry {
                entry_type: "mfa".to_string(),
                id: 1,
                value: "secret".to_string(),
            }]),
            AdminResponse::Error("something failed".to_string()),
        ];
        assert_eq!(responses.len(), 4);
        for resp in responses {
            let serialized = serialize(&resp);
            let _: AdminResponse = deserialize(&serialized);
        }
    }

    #[test]
    fn test_message_admin_command_roundtrip() {
        let msg = Message::AdminCommand {
            request_id: 4000,
            command: AdminCommand::ResetPassword {
                username: "alice".to_string(),
                password_hash: "argon2:newhash".to_string(),
            },
        };
        assert_eq!(msg.request_id(), Some(4000));
        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::AdminCommand {
            request_id,
            command,
        } = deserialized
        {
            assert_eq!(request_id, 4000);
            if let AdminCommand::ResetPassword { username, .. } = command {
                assert_eq!(username, "alice");
            } else {
                panic!("Wrong inner variant");
            }
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_admin_response_roundtrip() {
        let msg = Message::AdminResponse {
            request_id: 4001,
            response: AdminResponse::Created {
                uuid: "new-uuid".to_string(),
            },
        };
        assert_eq!(msg.request_id(), Some(4001));
        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::AdminResponse {
            response: AdminResponse::Created { uuid },
            ..
        } = deserialized
        {
            assert_eq!(uuid, "new-uuid");
        } else {
            panic!("Wrong variant");
        }
    }
}
