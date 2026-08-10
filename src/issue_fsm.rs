//! Pure issue lifecycle FSM (no Topcoat / Toasty / HTTP).
//!
//! Normative graph: `docs/technical/VCP_Issue_Lifecycle_FSM_Architecture_EN(1.0).md`.

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fmt;

use crate::models::{
    ISSUE_STATUS_CLOSED, ISSUE_STATUS_IN_ANALYSIS, ISSUE_STATUS_OPEN, ISSUE_STATUS_RESOLVED,
};

/// Canonical issue lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IssueState {
    Open,
    InAnalysis,
    Resolved,
    Closed,
}

/// Discrete lifecycle events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IssueEvent {
    StartAnalysis,
    Resolve,
    Close,
    Reopen,
}

/// Illegal edge (no capability/role guards in the FSM — see ADR 005).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransitionError {
    InvalidTransition { from: IssueState, event: IssueEvent },
}

impl fmt::Display for TransitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransitionError::InvalidTransition { from, event } => {
                write!(f, "invalid transition: {event:?} from {from:?}")
            }
        }
    }
}

impl std::error::Error for TransitionError {}

impl IssueState {
    /// Exhaustive transition table. Takes `self` by value so `Err` never
    /// mutates the caller's source state.
    pub fn transition(self, event: IssueEvent) -> Result<IssueState, TransitionError> {
        use IssueEvent::*;
        use IssueState::*;
        match (self, event) {
            (Open, StartAnalysis) => Ok(InAnalysis),
            (InAnalysis, Resolve) => Ok(Resolved),
            (Resolved, Close) => Ok(Closed),
            (Resolved, Reopen) => Ok(InAnalysis),
            (Closed, Reopen) => Ok(Open),
            _ => Err(TransitionError::InvalidTransition { from: self, event }),
        }
    }

    /// Wire label written to Postgres / UI chips.
    pub const fn as_str(self) -> &'static str {
        match self {
            IssueState::Open => ISSUE_STATUS_OPEN,
            IssueState::InAnalysis => ISSUE_STATUS_IN_ANALYSIS,
            IssueState::Resolved => ISSUE_STATUS_RESOLVED,
            IssueState::Closed => ISSUE_STATUS_CLOSED,
        }
    }
}

impl fmt::Display for IssueState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl TryFrom<&str> for IssueState {
    type Error = ();

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.eq_ignore_ascii_case(ISSUE_STATUS_OPEN) {
            Ok(IssueState::Open)
        } else if value.eq_ignore_ascii_case(ISSUE_STATUS_IN_ANALYSIS) {
            Ok(IssueState::InAnalysis)
        } else if value.eq_ignore_ascii_case(ISSUE_STATUS_RESOLVED) {
            Ok(IssueState::Resolved)
        } else if value.eq_ignore_ascii_case(ISSUE_STATUS_CLOSED) {
            Ok(IssueState::Closed)
        } else {
            Err(())
        }
    }
}

/// All events in a stable order (for UI probing / proptest).
pub const ALL_EVENTS: &[IssueEvent] = &[
    IssueEvent::StartAnalysis,
    IssueEvent::Resolve,
    IssueEvent::Close,
    IssueEvent::Reopen,
];

/// Events for which `transition(state, event)` succeeds.
pub fn next_events(state: IssueState) -> Vec<IssueEvent> {
    ALL_EVENTS
        .iter()
        .copied()
        .filter(|e| state.transition(*e).is_ok())
        .collect()
}

/// Timeline `status_change` body after a successful transition (arch §8).
pub fn timeline_body(event: IssueEvent, new_state: IssueState) -> &'static str {
    match event {
        IssueEvent::StartAnalysis => "Moved to analysis",
        IssueEvent::Resolve => "Resolved",
        IssueEvent::Close => "Closed",
        IssueEvent::Reopen => match new_state {
            IssueState::Open | IssueState::InAnalysis => "Reopened",
            IssueState::Resolved | IssueState::Closed => "Reopened",
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legal_edges() {
        assert_eq!(
            IssueState::Open.transition(IssueEvent::StartAnalysis),
            Ok(IssueState::InAnalysis)
        );
        assert_eq!(
            IssueState::InAnalysis.transition(IssueEvent::Resolve),
            Ok(IssueState::Resolved)
        );
        assert_eq!(
            IssueState::Resolved.transition(IssueEvent::Close),
            Ok(IssueState::Closed)
        );
        assert_eq!(
            IssueState::Resolved.transition(IssueEvent::Reopen),
            Ok(IssueState::InAnalysis)
        );
        assert_eq!(
            IssueState::Closed.transition(IssueEvent::Reopen),
            Ok(IssueState::Open)
        );
    }

    #[test]
    fn illegal_close_from_open() {
        assert!(matches!(
            IssueState::Open.transition(IssueEvent::Close),
            Err(TransitionError::InvalidTransition { .. })
        ));
    }

    #[test]
    fn illegal_resolve_from_open() {
        assert!(matches!(
            IssueState::Open.transition(IssueEvent::Resolve),
            Err(TransitionError::InvalidTransition { .. })
        ));
    }

    #[test]
    fn wire_round_trip() {
        for state in [
            IssueState::Open,
            IssueState::InAnalysis,
            IssueState::Resolved,
            IssueState::Closed,
        ] {
            let s = state.as_str();
            assert_eq!(IssueState::try_from(s), Ok(state));
        }
        assert_eq!(
            IssueState::try_from("in analysis"),
            Ok(IssueState::InAnalysis)
        );
        assert_eq!(IssueState::try_from("bogus"), Err(()));
    }

    #[test]
    fn next_events_mirrors_transition() {
        for state in [
            IssueState::Open,
            IssueState::InAnalysis,
            IssueState::Resolved,
            IssueState::Closed,
        ] {
            let listed = next_events(state);
            for e in ALL_EVENTS {
                let ok = state.transition(*e).is_ok();
                assert_eq!(listed.contains(e), ok, "{state:?} / {e:?}");
            }
        }
    }

    #[test]
    fn timeline_bodies() {
        assert_eq!(
            timeline_body(IssueEvent::StartAnalysis, IssueState::InAnalysis),
            "Moved to analysis"
        );
        assert_eq!(
            timeline_body(IssueEvent::Resolve, IssueState::Resolved),
            "Resolved"
        );
        assert_eq!(
            timeline_body(IssueEvent::Close, IssueState::Closed),
            "Closed"
        );
        assert_eq!(
            timeline_body(IssueEvent::Reopen, IssueState::InAnalysis),
            "Reopened"
        );
        assert_eq!(
            timeline_body(IssueEvent::Reopen, IssueState::Open),
            "Reopened"
        );
    }

    #[test]
    fn total_never_panics() {
        for state in [
            IssueState::Open,
            IssueState::InAnalysis,
            IssueState::Resolved,
            IssueState::Closed,
        ] {
            for event in ALL_EVENTS {
                let _ = state.transition(*event);
            }
        }
    }
}
