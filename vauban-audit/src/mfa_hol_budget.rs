//! Budget invariants for MFA / fail-closed audit ACK head-of-line safety.
//!
//! `vauban-web` awaits a durable `AuditAck` for at most
//! [`WEB_CRITICAL_ACK_TIMEOUT_SECS`] (see `CRITICAL_ACK_TIMEOUT` in
//! `vauban-web/src/ipc/audit.rs`). The audit main loop must never block
//! longer than that on a supervisor broker wait, or MFA escalation
//! fails closed with `audit ack timed out`.
//!
//! Pure helpers here are the single source of truth for the numeric
//! budget; `main.rs` and the lint / proptest / battle suites all pin
//! against them.

/// Max seconds the audit main loop may wait for a supervisor broker
/// reply (FD open / unlink / SCM_RIGHTS) before failing the request.
pub const SUPERVISOR_BROKER_TIMEOUT_SECS: u64 = 2;

/// Mirror of web `CRITICAL_ACK_TIMEOUT` (seconds). Kept here so the
/// audit crate can assert the broker budget fits underneath without
/// depending on `vauban-web`.
pub const WEB_CRITICAL_ACK_TIMEOUT_SECS: u64 = 5;

/// `true` iff a broker wait of `broker_secs` cannot exhaust the web
/// fail-closed ACK budget of `critical_ack_secs`.
///
/// Requires a strictly positive broker timeout (zero would busy-spin
/// or disable the guard) and a strict inequality so at least one
/// second of slack remains for WORM append + IPC round-trip after the
/// broker returns.
#[must_use]
pub fn broker_timeout_fits_under_critical_ack(
    broker_secs: u64,
    critical_ack_secs: u64,
) -> bool {
    broker_secs >= 1 && broker_secs < critical_ack_secs
}

/// Production budget pair used by `main.rs`.
#[must_use]
pub fn production_broker_budget_is_safe() -> bool {
    broker_timeout_fits_under_critical_ack(
        SUPERVISOR_BROKER_TIMEOUT_SECS,
        WEB_CRITICAL_ACK_TIMEOUT_SECS,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_budget_is_safe() {
        assert!(production_broker_budget_is_safe());
        assert_eq!(SUPERVISOR_BROKER_TIMEOUT_SECS, 2);
        assert_eq!(WEB_CRITICAL_ACK_TIMEOUT_SECS, 5);
    }

    #[test]
    fn zero_broker_is_rejected() {
        assert!(!broker_timeout_fits_under_critical_ack(0, 5));
    }

    #[test]
    fn equal_budgets_are_rejected() {
        assert!(!broker_timeout_fits_under_critical_ack(5, 5));
    }

    #[test]
    fn broker_above_critical_is_rejected() {
        assert!(!broker_timeout_fits_under_critical_ack(6, 5));
    }

    #[test]
    fn battle_cases_safe_pairs() {
        for (b, c) in [(1, 2), (1, 5), (2, 5), (3, 10), (4, 5)] {
            assert!(
                broker_timeout_fits_under_critical_ack(b, c),
                "expected safe: broker={b} critical={c}"
            );
        }
    }

    #[test]
    fn battle_cases_unsafe_pairs() {
        for (b, c) in [(0, 5), (5, 5), (6, 5), (1, 1), (2, 2)] {
            assert!(
                !broker_timeout_fits_under_critical_ack(b, c),
                "expected unsafe: broker={b} critical={c}"
            );
        }
    }
}
