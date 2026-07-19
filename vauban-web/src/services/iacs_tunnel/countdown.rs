//! `waiting_client` countdown derivation for the IACS tunnel status
//! page.
//!
//! The status page shows the operator how long they have left to run
//! the `ssh -L ...` command before the revocation watchdog flips the
//! `waiting_client` row to `expired` (see
//! [`super::revocation`]). The single source of truth for the
//! deadline is `proxy_sessions.created_at +
//! [industrial.iacs_tunnel].waiting_client_ttl_seconds` -- the SAME
//! reference the watchdog uses for its SQL cutoff
//! (`created_at < now - ttl`). Computing the remaining time from the
//! page-load instant instead would drift on every refresh.
//!
//! The value is rendered once server-side and then ticked down
//! client-side by the Alpine `iacsTunnelStatus` component; it is a
//! pure UX hint. Enforcement stays with the watchdog (DB flip) and
//! the proxy-side `PendingTunnel.deadline` (auth rejection) -- a
//! client that freezes its JavaScript clock gains nothing.

use chrono::{DateTime, Utc};

/// Seconds left before the `waiting_client` row becomes reapable by
/// the revocation watchdog.
///
/// Returns `None` when `ttl_seconds == 0`: the operator disabled the
/// TTL, the watchdog never reaps `waiting_client` rows, and the page
/// must not render a countdown at all.
///
/// Otherwise returns `Some(r)` with `0 <= r <= ttl_seconds`:
///
/// * `r == ttl` for a row created "now" (or with `created_at` in the
///   future -- DB/app clock skew clamps to the full window rather
///   than overflowing past it);
/// * `r == 0` once the watchdog cutoff (`created_at <= now - ttl`)
///   has been reached; the caller renders the expired state.
///
/// Saturating arithmetic keeps the function total for any pair of
/// `chrono` instants.
pub fn remaining_waiting_seconds(
    created_at: DateTime<Utc>,
    now: DateTime<Utc>,
    ttl_seconds: u32,
) -> Option<i64> {
    if ttl_seconds == 0 {
        return None;
    }
    let ttl = i64::from(ttl_seconds);
    let elapsed = now.signed_duration_since(created_at).num_seconds();
    Some(ttl.saturating_sub(elapsed).clamp(0, ttl))
}

/// Server-side twin of the Alpine `formatCountdown` helper in
/// `templates/sessions/iacs_tunnel_status.html`. Renders the initial
/// label so the page paints a meaningful value before the first
/// client-side tick (and for no-JS browsers).
///
/// Format: `M:SS` below one hour, `H:MM:SS` above. Negative inputs
/// collapse to `0:00` (defensive only -- the caller clamps).
pub fn format_countdown_label(seconds: i64) -> String {
    let s = seconds.max(0);
    let h = s / 3600;
    let m = (s % 3600) / 60;
    let sec = s % 60;
    if h > 0 {
        format!("{h}:{m:02}:{sec:02}")
    } else {
        format!("{m}:{sec:02}")
    }
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone};
    use proptest::prelude::*;

    use super::*;

    fn at(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(secs, 0).unwrap()
    }

    // ---------------------------------------------------------------
    // Battle-tested edge cases
    // ---------------------------------------------------------------

    #[test]
    fn test_remaining_with_disabled_ttl_returns_none() {
        assert_eq!(remaining_waiting_seconds(at(1_000), at(2_000), 0), None);
    }

    #[test]
    fn test_remaining_for_fresh_row_returns_full_ttl() {
        assert_eq!(
            remaining_waiting_seconds(at(1_000), at(1_000), 300),
            Some(300)
        );
    }

    #[test]
    fn test_remaining_counts_down_with_elapsed_time() {
        assert_eq!(
            remaining_waiting_seconds(at(1_000), at(1_290), 300),
            Some(10)
        );
    }

    #[test]
    fn test_remaining_at_exact_deadline_is_zero() {
        assert_eq!(
            remaining_waiting_seconds(at(1_000), at(1_300), 300),
            Some(0)
        );
    }

    #[test]
    fn test_remaining_past_deadline_clamps_to_zero() {
        assert_eq!(
            remaining_waiting_seconds(at(1_000), at(999_999), 300),
            Some(0)
        );
    }

    #[test]
    fn test_remaining_with_future_created_at_clamps_to_ttl() {
        // DB clock ahead of the app clock: never render MORE than the
        // configured window.
        assert_eq!(
            remaining_waiting_seconds(at(5_000), at(1_000), 300),
            Some(300)
        );
    }

    #[test]
    fn test_remaining_with_max_ttl_does_not_overflow() {
        assert_eq!(
            remaining_waiting_seconds(at(0), at(0), u32::MAX),
            Some(i64::from(u32::MAX))
        );
        assert_eq!(
            remaining_waiting_seconds(at(0), at(i64::from(u32::MAX)), u32::MAX),
            Some(0)
        );
    }

    #[test]
    fn test_remaining_with_extreme_chrono_bounds_is_total() {
        // chrono's representable range is ~ +/-262_000 years; the
        // helper must stay total (no panic, in-range result) at both
        // ends.
        let min = DateTime::<Utc>::MIN_UTC;
        let max = DateTime::<Utc>::MAX_UTC;
        assert_eq!(remaining_waiting_seconds(min, max, 300), Some(0));
        assert_eq!(remaining_waiting_seconds(max, min, 300), Some(300));
    }

    #[test]
    fn test_format_countdown_label_minute_second_form() {
        assert_eq!(format_countdown_label(0), "0:00");
        assert_eq!(format_countdown_label(9), "0:09");
        assert_eq!(format_countdown_label(60), "1:00");
        assert_eq!(format_countdown_label(272), "4:32");
        assert_eq!(format_countdown_label(3_599), "59:59");
    }

    #[test]
    fn test_format_countdown_label_hour_form() {
        assert_eq!(format_countdown_label(3_600), "1:00:00");
        assert_eq!(format_countdown_label(3_661), "1:01:01");
        assert_eq!(format_countdown_label(12 * 3_600), "12:00:00");
    }

    #[test]
    fn test_format_countdown_label_negative_collapses_to_zero() {
        assert_eq!(format_countdown_label(-1), "0:00");
        assert_eq!(format_countdown_label(i64::MIN), "0:00");
    }

    // ---------------------------------------------------------------
    // Invariant-based (proptest)
    // ---------------------------------------------------------------

    // Timestamps stay inside a generous but chrono-safe window
    // (~ +/-30_000 years around the epoch).
    const TS_RANGE: std::ops::RangeInclusive<i64> = -1_000_000_000_000..=1_000_000_000_000;

    proptest! {
        /// `ttl == 0` disables the countdown for EVERY instant pair.
        #[test]
        fn prop_disabled_ttl_is_always_none(
            created in TS_RANGE,
            now in TS_RANGE,
        ) {
            prop_assert_eq!(remaining_waiting_seconds(at(created), at(now), 0), None);
        }

        /// With an enabled TTL the result is always `Some(r)` with
        /// `0 <= r <= ttl` -- the page can never render a negative
        /// countdown nor one longer than the configured window.
        #[test]
        fn prop_remaining_is_bounded_by_zero_and_ttl(
            created in TS_RANGE,
            now in TS_RANGE,
            ttl in 1u32..,
        ) {
            let r = remaining_waiting_seconds(at(created), at(now), ttl)
                .expect("enabled TTL must yield Some");
            prop_assert!(r >= 0, "remaining {} must be >= 0", r);
            prop_assert!(
                r <= i64::from(ttl),
                "remaining {} must be <= ttl {}",
                r,
                ttl
            );
        }

        /// Time only moves the countdown down: for `now2 >= now1`,
        /// `remaining(now2) <= remaining(now1)`.
        #[test]
        fn prop_remaining_is_monotone_non_increasing_in_now(
            created in TS_RANGE,
            now1 in TS_RANGE,
            delta in 0i64..=1_000_000,
            ttl in 1u32..,
        ) {
            let r1 = remaining_waiting_seconds(at(created), at(now1), ttl).unwrap();
            let r2 = remaining_waiting_seconds(at(created), at(now1 + delta), ttl).unwrap();
            prop_assert!(
                r2 <= r1,
                "remaining must not grow as time passes: r1={} r2={} delta={}",
                r1,
                r2,
                delta
            );
        }

        /// Lock-step with the revocation watchdog: a strictly
        /// positive countdown implies the row is NOT reapable yet
        /// (the watchdog SQL predicate is
        /// `created_at < now - ttl`), and a row the watchdog would
        /// reap always renders `0`.
        #[test]
        fn prop_positive_remaining_implies_watchdog_has_not_expired_row(
            created in TS_RANGE,
            now in TS_RANGE,
            ttl in 1u32..,
        ) {
            let r = remaining_waiting_seconds(at(created), at(now), ttl).unwrap();
            let watchdog_would_reap = at(created) < at(now) - Duration::seconds(i64::from(ttl));
            if r > 0 {
                prop_assert!(
                    !watchdog_would_reap,
                    "page shows {}s left but the watchdog cutoff already passed",
                    r
                );
            }
            if watchdog_would_reap {
                prop_assert_eq!(
                    r, 0,
                    "a watchdog-reapable row must render a zero countdown"
                );
            }
        }

        /// Exact arithmetic on the nominal (skew-free) path: for
        /// `0 <= elapsed <= ttl`, `remaining == ttl - elapsed`.
        #[test]
        fn prop_nominal_path_is_exact(
            created in TS_RANGE,
            ttl in 1u32..=u32::MAX / 2,
            frac in 0.0f64..=1.0,
        ) {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let elapsed = (f64::from(ttl) * frac) as i64;
            let r = remaining_waiting_seconds(
                at(created),
                at(created + elapsed),
                ttl,
            )
            .unwrap();
            prop_assert_eq!(r, i64::from(ttl) - elapsed);
        }

        /// The server-side label formatter is total, and round-trips
        /// its components (`H*3600 + M*60 + S == input`) for every
        /// non-negative input.
        #[test]
        fn prop_format_countdown_label_round_trips(secs in 0i64..=2_000_000) {
            let label = format_countdown_label(secs);
            let parts: Vec<i64> = label
                .split(':')
                .map(|p| p.parse().expect("numeric component"))
                .collect();
            let total = match parts.as_slice() {
                [m, s] => m * 60 + s,
                [h, m, s] => h * 3600 + m * 60 + s,
                other => {
                    return Err(TestCaseError::fail(format!(
                        "unexpected label shape: {other:?}"
                    )));
                }
            };
            prop_assert_eq!(total, secs);
            // Trailing components are zero-padded to two digits so the
            // label never visually "jumps" width during a tick.
            for trailing in &parts[1..] {
                prop_assert!(*trailing < 60);
            }
        }
    }
}
