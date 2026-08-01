//! Issue close / reopen status helpers (shared by org + admin detail).

use toasty::Db;

use crate::models::{
    ISSUE_COMMENT_KIND_STATUS, ISSUE_ROLE_SYSTEM, ISSUE_STATUS_CLOSED, ISSUE_STATUS_OPEN,
    ISSUE_STATUS_RESOLVED, Issue, IssueComment,
};

/// Timeline divider body when an issue is closed.
pub const ISSUE_TIMELINE_CLOSED: &str = "Closed";

/// Timeline divider body when an issue is reopened.
pub const ISSUE_TIMELINE_REOPENED: &str = "Reopened";

/// True when replies must be blocked (`Closed` or `Resolved`).
pub fn issue_is_closed(status: &str) -> bool {
    status.eq_ignore_ascii_case(ISSUE_STATUS_CLOSED)
        || status.eq_ignore_ascii_case(ISSUE_STATUS_RESOLVED)
}

/// Persist a status change and append a `status_change` timeline row.
pub async fn apply_issue_status(
    db: &mut Db,
    issue: &mut Issue,
    new_status: &str,
    timeline_body: &str,
) -> anyhow::Result<()> {
    let now = crate::db::now_unix();
    issue
        .update()
        .status(new_status.to_owned())
        .updated_at(now)
        .exec(db)
        .await?;
    toasty::create!(IssueComment {
        issue_id: issue.id,
        author_user_id: 0,
        author_role: ISSUE_ROLE_SYSTEM.to_owned(),
        body: timeline_body.to_owned(),
        kind: ISSUE_COMMENT_KIND_STATUS.to_owned(),
        created_at: now,
    })
    .exec(db)
    .await?;
    issue.status = new_status.to_owned();
    issue.updated_at = now;
    Ok(())
}

/// Close an open issue (no-op when already closed/resolved).
pub async fn close_issue_status(db: &mut Db, issue: &mut Issue) -> anyhow::Result<bool> {
    if issue_is_closed(&issue.status) {
        return Ok(false);
    }
    apply_issue_status(db, issue, ISSUE_STATUS_CLOSED, ISSUE_TIMELINE_CLOSED).await?;
    Ok(true)
}

/// Reopen a closed/resolved issue (no-op when already open).
pub async fn reopen_issue_status(db: &mut Db, issue: &mut Issue) -> anyhow::Result<bool> {
    if !issue_is_closed(&issue.status) {
        return Ok(false);
    }
    apply_issue_status(db, issue, ISSUE_STATUS_OPEN, ISSUE_TIMELINE_REOPENED).await?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_is_closed_matrix() {
        assert!(issue_is_closed("Closed"));
        assert!(issue_is_closed("closed"));
        assert!(issue_is_closed("CLOSED"));
        assert!(issue_is_closed("Resolved"));
        assert!(issue_is_closed("resolved"));
        assert!(!issue_is_closed("Open"));
        assert!(!issue_is_closed("In analysis"));
        assert!(!issue_is_closed(""));
    }

    #[test]
    fn status_constants_match_ui_labels() {
        assert_eq!(ISSUE_STATUS_OPEN, "Open");
        assert_eq!(ISSUE_STATUS_CLOSED, "Closed");
        assert_eq!(ISSUE_STATUS_RESOLVED, "Resolved");
        assert_eq!(ISSUE_TIMELINE_CLOSED, "Closed");
        assert_eq!(ISSUE_TIMELINE_REOPENED, "Reopened");
    }
}
