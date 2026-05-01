//! Email outbox model.
//!
//! Persistent queue of emails to send. Rows are inserted in the same
//! transaction as the business event that triggers them (transactional
//! outbox pattern, see `vauban-db/migrations/20260501000000_email_outbox/`)
//! and drained by the dispatcher task in `crate::tasks::mailer`.

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::schema::email_outbox;

/// Status of a row in `email_outbox`.
///
/// Mirrors the DB-level CHECK constraint `email_outbox_status_valid`.
/// Adding a variant here MUST come with a migration that relaxes the
/// CHECK and updates `idx_email_outbox_pending_due` accordingly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutboxStatus {
    /// Eligible for delivery once `next_retry_at <= NOW()`.
    Pending,
    /// Successfully delivered to the MTA.
    Sent,
    /// Permanently failed (5xx, or attempts >= max_attempts).
    Failed,
    /// Cancelled by an operator (admin UI, future PR).
    Cancelled,
}

impl OutboxStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Sent => "sent",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(Self::Pending),
            "sent" => Some(Self::Sent),
            "failed" => Some(Self::Failed),
            "cancelled" => Some(Self::Cancelled),
            _ => None,
        }
    }
}

/// Outbox row read from the database.
#[derive(Debug, Clone, Queryable, Selectable, Identifiable)]
#[diesel(table_name = email_outbox)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct OutboxEntry {
    pub id: i64,
    pub event_id: Uuid,
    pub event_kind: String,
    pub recipient: String,
    pub recipient_name: String,
    pub subject: String,
    pub body_text: String,
    pub body_html: Option<String>,
    pub status: String,
    pub attempts: i32,
    pub max_attempts: i32,
    pub next_retry_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub sent_at: Option<DateTime<Utc>>,
}

impl OutboxEntry {
    /// Typed accessor that falls back to `Pending` if a manual SQL edit
    /// inserted an unknown literal (the CHECK should prevent it but be
    /// defensive in code that reads the column).
    pub fn status_typed(&self) -> OutboxStatus {
        OutboxStatus::parse(&self.status).unwrap_or(OutboxStatus::Pending)
    }
}

/// New row prepared for insertion. Always validate `recipient`,
/// `recipient_name`, and `subject` for CR/LF before constructing this
/// (see `crate::services::mailer::sanitize_header_value`). The DB
/// CHECK constraints are a hard floor, not an excuse to skip the
/// application-side check.
#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = email_outbox)]
pub struct NewOutboxEntry {
    pub event_id: Uuid,
    pub event_kind: String,
    pub recipient: String,
    pub recipient_name: String,
    pub subject: String,
    pub body_text: String,
    pub body_html: Option<String>,
    pub max_attempts: i32,
}

/// Update applied after each delivery attempt.
#[derive(Debug, Clone, AsChangeset)]
#[diesel(table_name = email_outbox)]
pub struct OutboxAttemptUpdate {
    pub status: String,
    pub attempts: i32,
    pub next_retry_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub sent_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outbox_status_roundtrip_all_variants() {
        for v in [
            OutboxStatus::Pending,
            OutboxStatus::Sent,
            OutboxStatus::Failed,
            OutboxStatus::Cancelled,
        ] {
            assert_eq!(OutboxStatus::parse(v.as_str()), Some(v));
        }
    }

    #[test]
    fn outbox_status_parse_unknown_returns_none() {
        assert_eq!(OutboxStatus::parse("delivered"), None);
        assert_eq!(OutboxStatus::parse(""), None);
        assert_eq!(OutboxStatus::parse("PENDING"), None);
    }

    #[test]
    fn outbox_status_as_str_is_lowercase_ascii() {
        for v in [
            OutboxStatus::Pending,
            OutboxStatus::Sent,
            OutboxStatus::Failed,
            OutboxStatus::Cancelled,
        ] {
            let s = v.as_str();
            assert!(s.bytes().all(|b| b.is_ascii_lowercase()));
        }
    }

    #[test]
    fn entry_status_typed_falls_back_to_pending_on_unknown_literal() {
        let entry = OutboxEntry {
            id: 1,
            event_id: Uuid::nil(),
            event_kind: "test".into(),
            recipient: "a@b.c".into(),
            recipient_name: String::new(),
            subject: "s".into(),
            body_text: "t".into(),
            body_html: None,
            status: "weirdvalue".into(),
            attempts: 0,
            max_attempts: 5,
            next_retry_at: None,
            last_error: None,
            created_at: Utc::now(),
            sent_at: None,
        };
        assert_eq!(entry.status_typed(), OutboxStatus::Pending);
    }

    #[test]
    fn entry_status_typed_recognizes_known_literal() {
        let mut entry = OutboxEntry {
            id: 1,
            event_id: Uuid::nil(),
            event_kind: "test".into(),
            recipient: "a@b.c".into(),
            recipient_name: String::new(),
            subject: "s".into(),
            body_text: "t".into(),
            body_html: None,
            status: "pending".into(),
            attempts: 0,
            max_attempts: 5,
            next_retry_at: None,
            last_error: None,
            created_at: Utc::now(),
            sent_at: None,
        };
        assert_eq!(entry.status_typed(), OutboxStatus::Pending);
        entry.status = "sent".into();
        assert_eq!(entry.status_typed(), OutboxStatus::Sent);
        entry.status = "failed".into();
        assert_eq!(entry.status_typed(), OutboxStatus::Failed);
        entry.status = "cancelled".into();
        assert_eq!(entry.status_typed(), OutboxStatus::Cancelled);
    }
}
