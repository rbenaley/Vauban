//! TRUSTED R1 — contestation of an R0 access decision.
//!
//! Hang off `proxy_sessions.decision_id`. Overturn restores group
//! eligibility only (never resurrects the old `vbw_`).

use crate::schema::access_contestations;
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde::Serialize;
use uuid::Uuid;

pub const STATUS_OPEN: &str = "open";
pub const STATUS_UNDER_REVIEW: &str = "under_review";
pub const STATUS_UPHELD: &str = "upheld";
pub const STATUS_OVERTURNED: &str = "overturned";

#[derive(Debug, Clone, Queryable, Selectable, Identifiable, Serialize)]
#[diesel(table_name = access_contestations)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct AccessContestation {
    pub id: i64,
    pub uuid: Uuid,
    pub decision_id: String,
    pub session_uuid: Uuid,
    pub subject_user_id: i32,
    pub status: String,
    pub opened_by_id: i32,
    pub opened_at: DateTime<Utc>,
    pub open_reason: String,
    pub claimed_by_id: Option<i32>,
    pub claimed_at: Option<DateTime<Utc>>,
    pub resolved_by_id: Option<i32>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub resolution_note: Option<String>,
    pub restore_group_id: Option<i32>,
    pub restore_applied_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = access_contestations)]
pub struct NewAccessContestation {
    pub uuid: Uuid,
    pub decision_id: String,
    pub session_uuid: Uuid,
    pub subject_user_id: i32,
    pub status: String,
    pub opened_by_id: i32,
    pub open_reason: String,
}

impl AccessContestation {
    pub fn is_open_queue(&self) -> bool {
        self.status == STATUS_OPEN || self.status == STATUS_UNDER_REVIEW
    }

    pub fn status_label(&self) -> &'static str {
        status_label(&self.status)
    }
}

pub fn status_label(status: &str) -> &'static str {
    match status {
        STATUS_OPEN => "Open",
        STATUS_UNDER_REVIEW => "Under review",
        STATUS_UPHELD => "Upheld",
        STATUS_OVERTURNED => "Overturned",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_status_has_a_label_and_a_stray_value_is_unknown() {
        assert_eq!(status_label(STATUS_OPEN), "Open");
        assert_eq!(status_label(STATUS_UNDER_REVIEW), "Under review");
        assert_eq!(status_label(STATUS_UPHELD), "Upheld");
        assert_eq!(status_label(STATUS_OVERTURNED), "Overturned");
        assert_eq!(status_label("archived"), "Unknown");
    }
}
