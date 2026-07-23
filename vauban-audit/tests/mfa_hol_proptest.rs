//! Property tests for the MFA / audit HOL broker budget.
//!
//! Pure function under test: [`vauban_audit::broker_timeout_fits_under_critical_ack`].

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use proptest::prelude::*;
use vauban_audit::{
    SUPERVISOR_BROKER_TIMEOUT_SECS, WEB_CRITICAL_ACK_TIMEOUT_SECS,
    broker_timeout_fits_under_critical_ack, production_broker_budget_is_safe,
};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Safe iff broker is at least 1s and strictly below the web ACK budget.
    #[test]
    fn broker_budget_predicate_matches_spec(
        broker in 0u64..=60,
        critical in 0u64..=60,
    ) {
        let expected = broker >= 1 && broker < critical;
        assert_eq!(
            broker_timeout_fits_under_critical_ack(broker, critical),
            expected,
            "broker={broker} critical={critical}"
        );
    }

    /// Any broker timeout in `1..critical` is accepted for critical >= 2.
    #[test]
    fn every_strictly_smaller_positive_broker_is_safe(
        critical in 2u64..=60,
        broker in 1u64..=59,
    ) {
        prop_assume!(broker < critical);
        prop_assert!(broker_timeout_fits_under_critical_ack(broker, critical));
    }

    /// Equality never fits (no slack for WORM append + IPC).
    #[test]
    fn equal_budgets_never_fit(secs in 0u64..=60) {
        prop_assert!(!broker_timeout_fits_under_critical_ack(secs, secs));
    }
}

#[test]
fn production_constants_locked_and_safe() {
    assert!(production_broker_budget_is_safe());
    assert_eq!(SUPERVISOR_BROKER_TIMEOUT_SECS, 2);
    assert_eq!(WEB_CRITICAL_ACK_TIMEOUT_SECS, 5);
    // Cross-check: web pub const must stay in lock-step (lint also greps it).
    assert_eq!(
        WEB_CRITICAL_ACK_TIMEOUT_SECS,
        vauban_web_critical_ack_secs_from_source(),
        "audit WEB_CRITICAL_ACK_TIMEOUT_SECS drifted from vauban-web source"
    );
}

/// Read web's `CRITICAL_ACK_TIMEOUT_SECS` from source so the two crates
/// cannot silently diverge (integration test has no link-time dep on the
/// constant until web is built; grepping keeps the pin hermetic).
fn vauban_web_critical_ack_secs_from_source() -> u64 {
    let path =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../vauban-web/src/ipc/audit.rs");
    let body = std::fs::read_to_string(&path).expect("read web audit.rs");
    for line in body.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("pub const CRITICAL_ACK_TIMEOUT_SECS: u64 = ") {
            let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            return digits.parse().expect("parse CRITICAL_ACK_TIMEOUT_SECS");
        }
    }
    panic!("CRITICAL_ACK_TIMEOUT_SECS not found in {}", path.display());
}
