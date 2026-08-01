//! Toasty models for the VCP customer portal.

use toasty::{Deferred, Model};

/// Maximum user accounts provisioned per client company (mockup rule).
pub const MAX_USERS_PER_COMPANY: usize = 5;

/// Reserved org slug for Vauban Support client-preview chrome (not a billable tenant).
pub const RESERVED_ORG_SLUG: &str = "vauban";

/// `User.portal_role` for Vauban Support staff (Casbin `role:admin`).
pub const PORTAL_ROLE_ADMIN: &str = "admin";

/// `Membership.role` for every org membership (Casbin `role:org`).
pub const MEMBERSHIP_ROLE_ORG: &str = "org";

/// `Release.organization_id` sentinel: generally available to all orgs.
pub const RELEASE_GA_ORG_ID: u64 = 0;

pub const DOC_STATUS_DRAFT: &str = "DRAFT";
pub const DOC_STATUS_PUBLISHED: &str = "PUBLISHED";

/// `Release.status` when the build is visible on customer Builds lists.
pub const RELEASE_STATUS_PUBLISHED: &str = "PUBLISHED";
/// `Release.status` when unpublished (admin-only; hidden from customers).
pub const RELEASE_STATUS_HIDDEN: &str = "HIDDEN";

/// Category options for admin compose (Concept select).
pub const DOC_CATEGORIES: &[&str] = &[
    "Getting started",
    "Deployment",
    "Security",
    "API",
    "Operations",
];

#[derive(Debug, Clone, Model)]
pub struct User {
    #[key]
    #[auto]
    pub id: u64,

    #[unique]
    pub email: String,

    pub display_name: String,

    pub password_hash: String,

    /// Empty for client users; [`PORTAL_ROLE_ADMIN`] for Vauban Support staff.
    pub portal_role: String,
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

    pub technical_contact: String,

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

    pub size_mb: String,

    /// Full package SHA-256 hex digest (or `"pending"` before publish artifacts exist).
    pub sha256: String,

    pub status: String,

    pub notes: String,

    /// [`RELEASE_GA_ORG_ID`] for GA; otherwise the target organization id.
    pub organization_id: u64,
}

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

#[derive(Debug, Clone, Model)]
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
