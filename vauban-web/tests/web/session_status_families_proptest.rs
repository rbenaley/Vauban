//! Property-based invariants for `SessionStatus` family consts (Lot D).
//!
//! Pins the closed vocabulary families introduced in
//! `models::session::SessionStatus`: every `*_AS_STR` slice must agree
//! with its predicate method, and nested families must stay subsets
//! of their parent live surface.

use proptest::prelude::*;
use vauban_web::models::session::SessionStatus;

fn any_session_status() -> impl Strategy<Value = SessionStatus> {
    proptest::sample::select(SessionStatus::ALL.to_vec())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn is_live_matches_live_as_str(status in any_session_status()) {
        let s = status.as_str();
        prop_assert_eq!(status.is_live(), SessionStatus::LIVE_AS_STR.contains(&s));
    }

    #[test]
    fn parse_strict_round_trips_all_variants(status in any_session_status()) {
        prop_assert_eq!(SessionStatus::parse_strict(status.as_str()), Some(status));
    }

    #[test]
    fn operator_active_implies_live(status in any_session_status()) {
        if status.is_operator_active() {
            prop_assert!(status.is_live());
        }
    }

    #[test]
    fn iacs_open_implies_live(status in any_session_status()) {
        if status.is_iacs_open() {
            prop_assert!(status.is_live());
        }
    }

    #[test]
    fn waiting_ttl_implies_iacs_open(status in any_session_status()) {
        if status.is_waiting_ttl() {
            prop_assert!(status.is_iacs_open());
        }
    }

    #[test]
    fn iacs_auth_implies_iacs_open(status in any_session_status()) {
        if status.is_iacs_authenticated() {
            prop_assert!(status.is_iacs_open());
        }
    }

    #[test]
    fn ssh_rdp_inflight_implies_live(status in any_session_status()) {
        if status.is_ssh_rdp_inflight() {
            prop_assert!(status.is_live());
        }
    }
}
