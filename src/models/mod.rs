//! Toasty models for the VCP portal scaffold.

use toasty::Model;

/// Maximum user accounts provisioned per client company (mockup rule).
pub const MAX_USERS_PER_COMPANY: usize = 5;

#[derive(Debug, Clone, Model)]
pub struct User {
    #[key]
    #[auto]
    pub id: u64,

    #[unique]
    pub email: String,

    pub display_name: String,

    pub password_hash: String,
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

    /// Casbin subject role without prefix, e.g. `member` or `admin`.
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

    pub slug: String,

    pub version: String,

    pub status: String,
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

    pub signature_prefix: String,

    pub status: String,

    pub notes: String,
}

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
}
