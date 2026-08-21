//! Toasty models for the VCP customer portal.

use toasty::{Deferred, Model};

/// Default maximum user accounts per client company (`org.max_accounts_per_org`).
pub const MAX_USERS_PER_COMPANY: usize = 5;

/// Default max for LTS / Industrial LTS subscription counters
/// (`org.max_lts_subscriptions`).
pub const MAX_LTS_SUBSCRIPTIONS_DEFAULT: usize = 99;

/// Reserved org slug for Vauban Support client-preview chrome (not a billable tenant).
pub const RESERVED_ORG_SLUG: &str = "vauban";

/// `User.portal_role` for Vauban Support staff (Casbin `role:admin`).
pub const PORTAL_ROLE_ADMIN: &str = "admin";

/// `User.portal_role` for client accounts (Casbin subject uses membership
/// `role:org`; distinct from staff even when both strings are `"org"` in
/// different columns).
pub const PORTAL_ROLE_ORG: &str = "org";

/// `Membership.role` for every org membership (Casbin `role:org`).
pub const MEMBERSHIP_ROLE_ORG: &str = "org";

/// Closed catalogue for [`User::portal_role`].
pub fn is_allowed_portal_role(portal_role: &str) -> bool {
    portal_role == PORTAL_ROLE_ADMIN || portal_role == PORTAL_ROLE_ORG
}

/// Vauban Support staff class (`portal_role = admin`).
pub fn is_portal_admin(portal_role: &str) -> bool {
    portal_role == PORTAL_ROLE_ADMIN
}

/// Client account class (`portal_role = org`).
pub fn is_portal_org(portal_role: &str) -> bool {
    portal_role == PORTAL_ROLE_ORG
}

/// `Release.organization_id` sentinel: generally available to all orgs.
pub const RELEASE_GA_ORG_ID: u64 = 0;

pub const DOC_STATUS_DRAFT: &str = "DRAFT";
pub const DOC_STATUS_PUBLISHED: &str = "PUBLISHED";

/// `Release.status` when the build is visible on customer Builds lists.
pub const RELEASE_STATUS_PUBLISHED: &str = "PUBLISHED";
/// `Release.status` when unpublished (admin-only; hidden from customers).
pub const RELEASE_STATUS_HIDDEN: &str = "HIDDEN";
/// `Release.status` while the C1 upload ceremony is in flight: the row only
/// exists to key the helper blob and is rolled back unless the ceremony
/// commits. Never listed in the admin Release manager, never sent to clients.
pub const RELEASE_STATUS_STAGING: &str = "STAGING";

/// Category options for admin compose (Concept select).
pub const DOC_CATEGORIES: &[&str] = &[
    "Getting started",
    "Deployment",
    "Security",
    "API",
    "Operations",
];

/// `User.deleted_at` sentinel: account is active (not soft-deleted).
pub const USER_NOT_DELETED: i64 = 0;

/// `MagicLinkToken.consumed_at` sentinel: token not yet used.
pub const MAGIC_LINK_NOT_CONSUMED: i64 = 0;

#[derive(Debug, Clone, Model)]
pub struct User {
    #[key]
    #[auto]
    pub id: u64,

    #[unique]
    pub email: String,

    pub display_name: String,

    /// [`PORTAL_ROLE_ORG`] for clients; [`PORTAL_ROLE_ADMIN`] for Vauban Support.
    pub portal_role: String,

    /// Unix timestamp when soft-deleted; [`USER_NOT_DELETED`] when active.
    pub deleted_at: i64,
}

/// One-shot magic-link token (DB stores hash only; raw token is emailed).
#[derive(Debug, Clone, Model)]
#[table = "magic_link_tokens"]
pub struct MagicLinkToken {
    #[key]
    pub token_hash: String,

    #[index]
    pub user_id: u64,

    /// Unix timestamp when the token expires.
    #[index]
    pub expires_at: i64,

    /// Unix timestamp when consumed; [`MAGIC_LINK_NOT_CONSUMED`] until then.
    pub consumed_at: i64,

    pub created_at: i64,
}

impl User {
    /// Whether this account may log in or receive magic links.
    pub fn is_active(&self) -> bool {
        self.deleted_at == USER_NOT_DELETED
    }
}

/// Persisted Topcoat session: SHA-256 token hash (hex) + expiry, never the raw token.
#[derive(Debug, Clone, Model)]
#[table = "auth_sessions"]
pub struct AuthSession {
    #[key]
    pub token_hash: String,

    #[index]
    pub user_id: u64,

    /// Unix timestamp (seconds) when the session expires.
    pub expires_at: i64,
}

#[derive(Debug, Clone, Model)]
pub struct Organization {
    #[key]
    #[auto]
    pub id: u64,

    #[unique]
    pub slug: String,

    pub name: String,

    pub address: String,

    pub vat: String,

    pub plan_label: String,

    pub supported_builds: String,

    pub lts_subscriptions: i32,

    pub industrial_lts_subscriptions: i32,

    /// Full name of the technical contact person.
    pub technical_contact_name: String,

    /// Email of the technical contact (Mailbox-validated when non-empty).
    pub technical_contact_email: String,

    pub status: String,
}

#[derive(Debug, Clone, Model)]
pub struct Membership {
    #[key]
    #[auto]
    pub id: u64,

    #[index]
    pub user_id: u64,

    #[index]
    pub organization_id: u64,

    /// Casbin subject role without prefix; always [`MEMBERSHIP_ROLE_ORG`].
    pub role: String,
}

#[derive(Debug, Clone, Model)]
pub struct DocArticle {
    #[key]
    #[auto]
    pub id: u64,

    pub title: String,

    pub summary: String,

    pub category: String,

    /// Shared across versions of the same article (not unique).
    #[index]
    pub slug: String,

    pub version: String,

    pub status: String,

    /// Dialect body (headings, fences, callouts); deferred on list, include on detail.
    pub body: Deferred<String>,

    /// Unix timestamp (seconds) of last update.
    pub updated_at: i64,
}

#[derive(Debug, Clone, Model)]
pub struct Release {
    #[key]
    #[auto]
    pub id: u64,

    pub version: String,

    pub channel: String,

    pub released_on: String,

    pub status: String,

    pub notes: String,

    /// [`RELEASE_GA_ORG_ID`] for GA; otherwise the target organization id.
    pub organization_id: u64,

    /// Semver sort components (see `release_pkg::version_sort_fields`).
    pub v_major: u64,
    pub v_minor: u64,
    pub v_patch: u64,
    /// `1` when product track is industrial LTS; else `0` (SQL tie-break).
    pub is_industrial: u64,
    /// `1` when `version` has a `-client` suffix; else `0`.
    pub has_client_suffix: u64,
    pub client_suffix: String,

    /// Immutable product family: `Stable`, `LTS`, or `LTS.industrial`.
    /// Survives lifecycle `channel = EOL`.
    pub product_track: String,
}

/// Portal mirror of blob digests/sizes (SoT lives in helper SQLite `meta.sqlite`).
#[derive(Debug, Clone, Model)]
#[table = "storage_objects"]
#[unique(scope, object_key)]
pub struct StorageObject {
    #[key]
    #[auto]
    pub id: u64,

    /// `"release"` or `"image"`.
    pub scope: String,

    /// Opaque key: release id decimal, or `{org_id}/{uuid}.{ext}` for images.
    pub object_key: String,

    /// Required for images; [`None`]/scope] for releases (Toasty: use 0 sentinel?).
    /// Stored as 0 for releases (no org ownership).
    #[index]
    pub organization_id: u64,

    /// Lowercase 64-char hex SHA-256.
    pub sha256: String,

    pub size_bytes: u64,

    /// Image content type / ext (`png` / `jpeg` / `webp`); empty for releases.
    pub content_type: String,

    pub created_at: i64,

    pub updated_at: i64,
}

/// `StorageObject.scope` for release artifacts.
pub const STORAGE_SCOPE_RELEASE: &str = "release";
/// `StorageObject.scope` for tenant images.
pub const STORAGE_SCOPE_IMAGE: &str = "image";
/// `StorageObject.organization_id` when the blob is not org-scoped (releases).
pub const STORAGE_ORG_NONE: u64 = 0;

pub const ISSUE_COMMENT_KIND_COMMENT: &str = "comment";
pub const ISSUE_COMMENT_KIND_STATUS: &str = "status_change";
pub const ISSUE_ROLE_REPORTER: &str = "reporter";
pub const ISSUE_ROLE_SUPPORT: &str = "support";
pub const ISSUE_ROLE_SYSTEM: &str = "system";

/// Issue lifecycle statuses (free-text in DB; keep UI chips aligned).
pub const ISSUE_STATUS_OPEN: &str = "Open";
pub const ISSUE_STATUS_IN_ANALYSIS: &str = "In analysis";
pub const ISSUE_STATUS_RESOLVED: &str = "Resolved";
pub const ISSUE_STATUS_CLOSED: &str = "Closed";

/// Initial optimistic-lock token for new issues (ADR 006).
pub const ISSUE_VERSION_INITIAL: u64 = 1;

#[derive(Debug, Clone, Model)]
#[unique(organization_id, key)]
pub struct Issue {
    #[key]
    #[auto]
    pub id: u64,

    pub key: String,

    pub title: String,

    pub component: String,

    pub severity: String,

    pub status: String,

    pub organization_id: u64,

    /// Free-text report details from the issue form (opening message).
    pub details: String,

    /// User who opened the issue.
    pub opened_by_user_id: u64,

    /// Unix timestamp (seconds) when the issue was created.
    pub created_at: i64,

    /// Unix timestamp (seconds) of last update (reply or status change).
    pub updated_at: i64,

    /// Optimistic concurrency token (Toasty `#[version]` / ADR 006).
    /// Instance updates condition on this value and bump it atomically.
    #[version]
    pub version: u64,
}

#[derive(Debug, Clone, Model)]
#[table = "issue_comments"]
pub struct IssueComment {
    #[key]
    #[auto]
    pub id: u64,

    #[index]
    pub issue_id: u64,

    /// Author user id (0 for system rows without a user).
    pub author_user_id: u64,

    /// `reporter`, `support`, or `system`.
    pub author_role: String,

    pub body: String,

    /// `comment` or `status_change`.
    pub kind: String,

    /// Unix timestamp (seconds).
    pub created_at: i64,

    /// Unix timestamp when the body was last edited; [`COMMENT_NOT_EDITED`] if never.
    pub edited_at: i64,
}

/// `IssueComment.edited_at` sentinel: body never edited after create.
pub const COMMENT_NOT_EDITED: i64 = 0;

/// Default for `[issues].max_attachments_per_comment` (liaison rows; blobs
/// stay under org quota). Prefer the live config value at request time.
pub const DEFAULT_MAX_ATTACHMENTS_PER_COMMENT: usize = 5;

/// Backward-compatible alias used by older tests / call sites.
pub const MAX_ISSUE_ATTACHMENTS: usize = DEFAULT_MAX_ATTACHMENTS_PER_COMMENT;

/// `issue_attachments.issue_comment_id` for images on the opening description
/// (not a real `issue_comments` row).
pub const ISSUE_ATTACHMENT_OPENER_COMMENT_ID: u64 = 0;

/// Join row: issue ↔ tenant image already stored via `storage_objects` / helper.
#[derive(Debug, Clone, Model)]
#[table = "issue_attachments"]
#[unique(issue_id, image_id)]
pub struct IssueAttachment {
    #[key]
    #[auto]
    pub id: u64,

    #[index]
    pub issue_id: u64,

    #[index]
    pub organization_id: u64,

    /// Owning comment id, or [`ISSUE_ATTACHMENT_OPENER_COMMENT_ID`] for the
    /// opening description bubble.
    #[index]
    pub issue_comment_id: u64,

    /// Lowercase UUID image id (matches helper / `storage_objects` key).
    pub image_id: String,

    /// Normalized ext: `png` / `jpeg` / `webp`.
    pub ext: String,

    pub uploaded_by_user_id: u64,

    /// Unix timestamp (seconds).
    pub created_at: i64,

    /// Display order within the issue (ascending).
    pub sort_order: i64,
}

/// `IssueMailOutbox.source_id` when the event is issue create (no comment row).
pub const ISSUE_MAIL_SOURCE_CREATE: u64 = 0;

/// Pending / failed issue notification row. `sent_at == 0` means not delivered.
#[derive(Debug, Clone, Model)]
#[table = "issue_mail_outbox"]
#[unique(issue_id, event, source_id, recipient_user_id)]
pub struct IssueMailOutbox {
    #[key]
    #[auto]
    pub id: u64,

    #[index]
    pub issue_id: u64,

    /// `create` / `comment` / `support_comment` / `status`.
    pub event: String,

    /// Comment id, or [`ISSUE_MAIL_SOURCE_CREATE`].
    pub source_id: u64,

    pub actor_user_id: u64,

    pub recipient_user_id: u64,

    pub created_at: i64,

    /// Unix seconds when delivered; `0` while pending.
    #[index]
    pub sent_at: i64,

    pub attempts: u64,

    /// Truncated last SMTP error (never a full comment body).
    pub last_error: String,

    #[version]
    pub version: u64,
}

/// TTL for Concept-style ephemeral download links (seconds).
pub const EPH_DOWNLOAD_TTL_SECS: i64 = 5 * 60;

/// Server-issued short-lived download token (display stub until CDN exists).
#[derive(Debug, Clone, Model)]
#[table = "ephemeral_downloads"]
pub struct EphemeralDownload {
    #[key]
    #[auto]
    pub id: u64,

    #[unique]
    pub token: String,

    #[index]
    pub user_id: u64,

    #[index]
    pub organization_id: u64,

    /// Release version string the link is scoped to.
    pub release_version: String,

    /// Unix timestamp (seconds) when the token expires.
    pub expires_at: i64,

    /// Unix timestamp (seconds) when the token was issued.
    pub created_at: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn portal_role_catalogue_is_closed() {
        assert!(is_allowed_portal_role(PORTAL_ROLE_ADMIN));
        assert!(is_allowed_portal_role(PORTAL_ROLE_ORG));
        assert!(!is_allowed_portal_role(""));
        assert!(!is_allowed_portal_role("member"));
        assert!(!is_allowed_portal_role("staff"));
        assert!(is_portal_admin(PORTAL_ROLE_ADMIN));
        assert!(!is_portal_admin(PORTAL_ROLE_ORG));
        assert!(is_portal_org(PORTAL_ROLE_ORG));
        assert!(!is_portal_org(PORTAL_ROLE_ADMIN));
    }
}
