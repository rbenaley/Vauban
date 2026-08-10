//! Issue lifecycle status helpers (shared by org + admin detail).
//!
//! Status mutations go through [`advance_issue`] (FSM + Toasty `#[version]`
//! OCC). See ADR 006 and
//! `docs/technical/VCP_Issue_Lifecycle_FSM_Architecture_EN(1.0).md` §6.

use toasty::Db;

use crate::issue_fsm::{IssueEvent, IssueState, TransitionError, timeline_body};
use crate::models::{
    ISSUE_COMMENT_KIND_STATUS, ISSUE_ROLE_SYSTEM, ISSUE_STATUS_CLOSED, ISSUE_STATUS_RESOLVED,
    Issue, IssueComment,
};

/// Timeline divider body when an issue is closed.
pub const ISSUE_TIMELINE_CLOSED: &str = "Closed";

/// Timeline divider body when an issue is reopened.
pub const ISSUE_TIMELINE_REOPENED: &str = "Reopened";

/// Soft query flag when CAS retries are exhausted.
pub const ISSUE_ERR_CONFLICT: &str = "conflict";

/// Bounded OCC retries (including the first attempt).
pub const ADVANCE_MAX_ATTEMPTS: u32 = 3;

/// True when replies must be blocked (`Closed` or `Resolved`).
pub fn issue_is_closed(status: &str) -> bool {
    status.eq_ignore_ascii_case(ISSUE_STATUS_CLOSED)
        || status.eq_ignore_ascii_case(ISSUE_STATUS_RESOLVED)
}

/// Persistence / FSM errors for lifecycle advances.
#[derive(Debug)]
pub enum PersistError {
    Fsm(TransitionError),
    Conflict,
    UnknownStatus(String),
    Db(String),
}

impl std::fmt::Display for PersistError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PersistError::Fsm(e) => write!(f, "{e}"),
            PersistError::Conflict => f.write_str("issue status conflict"),
            PersistError::UnknownStatus(s) => write!(f, "unknown issue status: {s}"),
            PersistError::Db(e) => write!(f, "database error: {e}"),
        }
    }
}

impl std::error::Error for PersistError {}

/// Result of a non-conflicting advance attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdvanceOutcome {
    Applied(IssueState),
    /// Close while already Closed / Reopen while already open-side — HTTP no-op.
    Noop,
}

/// HTTP-layer idempotent no-ops (FSM still returns `InvalidTransition`).
fn is_http_noop(state: IssueState, event: IssueEvent) -> bool {
    matches!(
        (state, event),
        (IssueState::Closed, IssueEvent::Close)
            | (IssueState::Open, IssueEvent::Reopen)
            | (IssueState::InAnalysis, IssueEvent::Reopen)
    )
}

fn map_db(err: toasty::Error) -> PersistError {
    if err.is_condition_failed() {
        PersistError::Conflict
    } else {
        PersistError::Db(err.to_string())
    }
}

/// Advance lifecycle once (no retry). Reloads are the caller's job on Conflict.
///
/// Uses Toasty **instance** `update()` so `#[version]` conditions the write
/// and bumps the counter. Timeline insert runs in the same transaction.
pub async fn advance_issue(
    db: &mut Db,
    issue: &mut Issue,
    event: IssueEvent,
) -> Result<AdvanceOutcome, PersistError> {
    let state = IssueState::try_from(issue.status.as_str())
        .map_err(|_| PersistError::UnknownStatus(issue.status.clone()))?;

    let new_state = match state.transition(event) {
        Ok(s) => s,
        Err(_) if is_http_noop(state, event) => return Ok(AdvanceOutcome::Noop),
        Err(e) => return Err(PersistError::Fsm(e)),
    };

    let body = timeline_body(event, new_state).to_owned();
    let now = crate::db::now_unix();
    let new_status = new_state.as_str().to_owned();

    let mut tx = db.transaction().await.map_err(map_db)?;

    if let Err(err) = issue
        .update()
        .status(new_status.clone())
        .updated_at(now)
        .exec(&mut tx)
        .await
    {
        // Drop / rollback the tx; OCC mismatch is Conflict.
        return Err(map_db(err));
    }

    toasty::create!(IssueComment {
        issue_id: issue.id,
        author_user_id: 0,
        author_role: ISSUE_ROLE_SYSTEM.to_owned(),
        body,
        kind: ISSUE_COMMENT_KIND_STATUS.to_owned(),
        created_at: now,
    })
    .exec(&mut tx)
    .await
    .map_err(map_db)?;

    tx.commit().await.map_err(map_db)?;

    // Instance update reloads changed fields (including bumped `version`).
    issue.status = new_status;
    issue.updated_at = now;
    Ok(AdvanceOutcome::Applied(new_state))
}

/// Reload issue by id, then advance with bounded Conflict retries.
pub async fn advance_issue_with_retry(
    db: &mut Db,
    issue_id: u64,
    event: IssueEvent,
) -> Result<(Issue, AdvanceOutcome), PersistError> {
    for attempt in 0..ADVANCE_MAX_ATTEMPTS {
        let mut issue = load_issue_by_id(db, issue_id)
            .await?
            .ok_or_else(|| PersistError::Db(format!("issue id {issue_id} missing")))?;
        match advance_issue(db, &mut issue, event).await {
            Ok(outcome) => return Ok((issue, outcome)),
            Err(PersistError::Conflict) if attempt + 1 < ADVANCE_MAX_ATTEMPTS => continue,
            Err(e) => return Err(e),
        }
    }
    Err(PersistError::Conflict)
}

async fn load_issue_by_id(db: &mut Db, issue_id: u64) -> Result<Option<Issue>, PersistError> {
    let rows = Issue::all()
        .filter(Issue::fields().id().eq(issue_id))
        .limit(1)
        .exec(db)
        .await
        .map_err(map_db)?;
    Ok(rows.into_iter().next())
}

/// Convenience: Close event via advance (single attempt).
pub async fn close_issue_status(
    db: &mut Db,
    issue: &mut Issue,
) -> Result<AdvanceOutcome, PersistError> {
    advance_issue(db, issue, IssueEvent::Close).await
}

/// Convenience: Reopen event via advance.
pub async fn reopen_issue_status(
    db: &mut Db,
    issue: &mut Issue,
) -> Result<AdvanceOutcome, PersistError> {
    advance_issue(db, issue, IssueEvent::Reopen).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::issue_fsm::IssueEvent;

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
        assert_eq!(ISSUE_TIMELINE_CLOSED, "Closed");
        assert_eq!(ISSUE_TIMELINE_REOPENED, "Reopened");
        assert_eq!(ISSUE_ERR_CONFLICT, "conflict");
    }

    #[test]
    fn http_noop_matrix() {
        assert!(is_http_noop(IssueState::Closed, IssueEvent::Close));
        assert!(is_http_noop(IssueState::Open, IssueEvent::Reopen));
        assert!(is_http_noop(IssueState::InAnalysis, IssueEvent::Reopen));
        assert!(!is_http_noop(IssueState::Resolved, IssueEvent::Close));
        assert!(!is_http_noop(IssueState::Open, IssueEvent::Close));
    }
}
