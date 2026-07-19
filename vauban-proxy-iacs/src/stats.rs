//! Pure accounting logic for the periodic per-session traffic
//! reports (`IacsTunnelStatusUpdate { status = "tunnel_stats" }`).
//!
//! ## Why (July 2026, status-page counters stuck at zero)
//!
//! The privsep proxy only ever emitted TWO messages per EWS login:
//! one `tunnel_active` at the first `direct-tcpip` open (with
//! hard-coded zero counters) and one `IacsTunnelClosed` at handler
//! drop (with the final totals). The 5 s stats tick existed only in
//! the legacy in-process sshd that lived in `vauban-web`, so on the
//! production path the status page showed `0 B` for the whole
//! session. This module + the ticker in [`crate::server`] port the
//! tick to the proxy.
//!
//! ## Accounting model
//!
//! Per-EWS-login traffic is split across two sources:
//!
//! * `session_total_bytes_in/out` -- bytes of every ALREADY-CLOSED
//!   `direct-tcpip` channel, flushed by the relay teardown task
//!   (`fetch_add` after `tokio::join!` on both directions);
//! * the live [`TunnelHandle`](crate::registry::TunnelHandle)
//!   counters in the registry -- bytes of the channel currently
//!   relaying (if any).
//!
//! A closed handle may transiently still sit in the registry AFTER
//! its bytes were flushed into the totals (the registry entry is
//! only removed at handler drop): counting it again would
//! double-report. [`cumulative_bytes`] therefore skips closed
//! handles. Symmetrically, the flush and the `close()` are not
//! atomic w.r.t. the ticker, so a tick can land in the window where
//! the bytes are counted in BOTH (flushed and not-yet-closed) or in
//! NEITHER (closed and not-yet-flushed). [`MonotonicReport`] absorbs
//! both races: reported values never go backwards, and a transient
//! over-count is bounded by the final authoritative
//! `IacsTunnelClosed` totals arriving last on the same ordered IPC
//! channel.
//!
//! Everything here is pure and synchronous -- the invariants are
//! pinned by the unit + proptest suites at the bottom.

use std::time::Duration;

/// Production interval between two `tunnel_stats` reports for one
/// EWS login. Mirrors the 5 s tick of the legacy in-process sshd
/// (and stays well under the `websocket-logging.mdc` 1 Hz
/// `send_periodic` threshold on the vauban-web side).
pub const STATS_INTERVAL: Duration = Duration::from_secs(5);

/// Cumulative `(bytes_in, bytes_out)` for one EWS login: totals of
/// the closed channels plus the counters of the live (not-closed)
/// handles. Closed handles are skipped -- their bytes are (or are
/// about to be) flushed into the totals by the relay teardown task.
///
/// Saturating: a hostile or bugged counter cannot panic the ticker.
pub fn cumulative_bytes(
    closed_total_in: u64,
    closed_total_out: u64,
    live_handles: impl IntoIterator<Item = (u64, u64, bool)>,
) -> (u64, u64) {
    let mut bytes_in = closed_total_in;
    let mut bytes_out = closed_total_out;
    for (h_in, h_out, is_closed) in live_handles {
        if is_closed {
            continue;
        }
        bytes_in = bytes_in.saturating_add(h_in);
        bytes_out = bytes_out.saturating_add(h_out);
    }
    (bytes_in, bytes_out)
}

/// Monotonic clamp across successive reports of one EWS login.
///
/// The flush/close race described in the module docs means a raw
/// tick sample can be momentarily LOWER than the previous one (bytes
/// left the live handle but have not landed in the totals yet). A
/// counter that visibly goes backwards on the status page reads as
/// data corruption to the operator, so each component is clamped to
/// its own running maximum.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct MonotonicReport {
    last_in: u64,
    last_out: u64,
}

impl MonotonicReport {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold one raw sample into the running maximum and return the
    /// value to report.
    pub fn next(&mut self, sample_in: u64, sample_out: u64) -> (u64, u64) {
        self.last_in = self.last_in.max(sample_in);
        self.last_out = self.last_out.max(sample_out);
        (self.last_in, self.last_out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----------------------------------------------------------------
    // Unit -- battle cases.
    // ----------------------------------------------------------------

    /// The exact production symptom: totals still zero (no channel
    /// closed yet) but a live channel is relaying. The tick MUST
    /// surface the live counters, not zero.
    #[test]
    fn live_channel_bytes_are_visible_before_first_close() {
        assert_eq!(
            cumulative_bytes(0, 0, [(1500, 300, false)]),
            (1500, 300),
            "live traffic must be reported while the channel is open"
        );
    }

    /// A closed handle still sitting in the registry after its bytes
    /// were flushed into the totals MUST NOT be counted twice.
    #[test]
    fn closed_handles_are_skipped_to_avoid_double_count() {
        assert_eq!(
            cumulative_bytes(1500, 300, [(1500, 300, true)]),
            (1500, 300)
        );
    }

    /// Mixed shape: one closed channel already flushed (in totals),
    /// one live channel relaying.
    #[test]
    fn totals_and_live_handles_add_up() {
        assert_eq!(
            cumulative_bytes(1000, 2000, [(500, 70, false), (999, 999, true)]),
            (1500, 2070)
        );
    }

    /// No handles at all (channel closed, registry entry removed):
    /// the totals stand alone.
    #[test]
    fn no_live_handles_reports_totals() {
        assert_eq!(cumulative_bytes(42, 7, []), (42, 7));
    }

    /// Hostile counters cannot panic the ticker.
    #[test]
    fn cumulative_saturates_instead_of_overflowing() {
        assert_eq!(
            cumulative_bytes(u64::MAX, u64::MAX, [(u64::MAX, u64::MAX, false)]),
            (u64::MAX, u64::MAX)
        );
    }

    /// The flush/close race: a raw sample lower than the previous
    /// one (bytes momentarily in neither source) must not surface as
    /// a counter going backwards.
    #[test]
    fn monotonic_report_absorbs_transient_dips() {
        let mut r = MonotonicReport::new();
        assert_eq!(r.next(1500, 300), (1500, 300));
        // Channel closed: handle skipped, totals not yet flushed.
        assert_eq!(r.next(0, 0), (1500, 300), "dip must be clamped");
        // Totals flushed, traffic resumed on a new channel.
        assert_eq!(r.next(1600, 350), (1600, 350));
    }

    // ----------------------------------------------------------------
    // Invariant-based (proptest).
    // ----------------------------------------------------------------

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        fn handles() -> impl Strategy<Value = Vec<(u64, u64, bool)>> {
            proptest::collection::vec((any::<u64>(), any::<u64>(), any::<bool>()), 0..8)
        }

        proptest! {
            /// INVARIANT 1 -- totality: no input (including u64::MAX
            /// bombs) can panic or overflow.
            #[test]
            fn cumulative_is_total(
                t_in in any::<u64>(),
                t_out in any::<u64>(),
                hs in handles(),
            ) {
                let _ = cumulative_bytes(t_in, t_out, hs);
            }

            /// INVARIANT 2 -- the report never under-counts the
            /// already-flushed totals: whatever the live handles
            /// look like, `cumulative >= totals`.
            #[test]
            fn cumulative_is_at_least_the_totals(
                t_in in any::<u64>(),
                t_out in any::<u64>(),
                hs in handles(),
            ) {
                let (c_in, c_out) = cumulative_bytes(t_in, t_out, hs);
                prop_assert!(c_in >= t_in);
                prop_assert!(c_out >= t_out);
            }

            /// INVARIANT 3 -- closed handles are invisible: filtering
            /// them out of the input does not change the result
            /// (no double-count path exists).
            #[test]
            fn closed_handles_never_contribute(
                t_in in 0u64..1 << 40,
                t_out in 0u64..1 << 40,
                hs in handles(),
            ) {
                let all = cumulative_bytes(t_in, t_out, hs.clone());
                let open_only =
                    cumulative_bytes(t_in, t_out, hs.into_iter().filter(|h| !h.2));
                prop_assert_eq!(all, open_only);
            }

            /// INVARIANT 4 -- the clamped report sequence is
            /// non-decreasing for ARBITRARY raw sample sequences
            /// (the status page counter can never go backwards).
            #[test]
            fn report_sequence_is_monotonic(
                samples in proptest::collection::vec((any::<u64>(), any::<u64>()), 1..32),
            ) {
                let mut r = MonotonicReport::new();
                let mut prev = (0u64, 0u64);
                for (s_in, s_out) in samples {
                    let cur = r.next(s_in, s_out);
                    prop_assert!(cur.0 >= prev.0, "bytes_in went backwards");
                    prop_assert!(cur.1 >= prev.1, "bytes_out went backwards");
                    prop_assert!(cur.0 >= s_in && cur.1 >= s_out,
                        "report must never be below the current raw sample");
                    prev = cur;
                }
            }

            /// INVARIANT 5 -- idempotence: replaying the same sample
            /// does not move the report (a stalled tunnel shows a
            /// stable counter, not a creeping one).
            #[test]
            fn report_is_idempotent_on_repeated_samples(
                s_in in any::<u64>(),
                s_out in any::<u64>(),
            ) {
                let mut r = MonotonicReport::new();
                let first = r.next(s_in, s_out);
                prop_assert_eq!(r.next(s_in, s_out), first);
            }
        }
    }
}
