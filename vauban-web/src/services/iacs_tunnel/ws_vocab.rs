//! Canonical WebSocket wire vocabulary for the IACS tunnel status
//! page (`WsChannel::SessionLive(<uuid>)` consumers), plus a pure
//! Rust model of the client-side state machine.
//!
//! ## Why this module exists (July 2026 incident)
//!
//! Two independent emitters push IACS lifecycle events on the same
//! per-session channel:
//!
//! * the in-process dev sshd
//!   ([`super::server`]) emitted `{"type": "tunnel_active" | "tunnel_stats"
//!   | "tunnel_closed"}`,
//! * the production privsep pump ([`crate::ipc::proxy_iacs`])
//!   emitted `{"type": "iacs_tunnel_status", "status": ...}` and
//!   `{"type": "iacs_tunnel_closed"}`.
//!
//! The Alpine component (`iacsTunnelStatus` in
//! `static/js/vauban-components.js`) only understood the first
//! vocabulary. In production (under vauban-supervisor) the page
//! therefore NEVER reacted: the `waiting_client` countdown kept
//! ticking while the tunnel was active, and at zero the pill flipped
//! to a false "expired". The divergence was invisible pre-CSP-fix
//! because the component lived in an inline `<script>` that the CSP
//! blocked from ever executing.
//!
//! This module is now the single source of truth: BOTH emitters
//! reference the constants below, and
//! `tests/web/iacs_ws_vocab_test.rs` pins (a) that the legacy
//! `iacs_tunnel_*` envelope never reappears, and (b) that the JS
//! component handles every constant.
//!
//! ## Client state machine (JS twin)
//!
//! [`ClientState::apply_event`] mirrors `iacsTunnelStatus.handle()`
//! byte-for-byte in behaviour -- keep the two in lock-step. The Rust
//! twin exists so the transition table can be unit- and
//! property-tested (the JS runs only in a browser).

/// Tunnel became active: the EWS opened its first `direct-tcpip`
/// channel. Carries `peer_ip` (EWS source) when known.
pub const TYPE_TUNNEL_ACTIVE: &str = "tunnel_active";

/// Periodic byte counters (`bytes_in` / `bytes_out`); no lifecycle
/// transition.
pub const TYPE_TUNNEL_STATS: &str = "tunnel_stats";

/// Tunnel closed (EWS disconnect, watchdog termination, error).
/// Carries the final byte counters.
pub const TYPE_TUNNEL_CLOSED: &str = "tunnel_closed";

/// Every event type a `SessionLive` IACS consumer must handle.
pub const ALL_TYPES: [&str; 3] = [TYPE_TUNNEL_ACTIVE, TYPE_TUNNEL_STATS, TYPE_TUNNEL_CLOSED];

/// Map an IPC `IacsTunnelStatusUpdate.status` value to the wire
/// event type. Known statuses pass through; anything unknown is
/// demoted to a stats event (fail-safe: the client model treats it
/// as byte counters only, no lifecycle transition can be forged by
/// an unexpected status string).
pub fn event_type_for_status(status: &str) -> &'static str {
    match status {
        s if s == TYPE_TUNNEL_ACTIVE => TYPE_TUNNEL_ACTIVE,
        s if s == TYPE_TUNNEL_CLOSED => TYPE_TUNNEL_CLOSED,
        _ => TYPE_TUNNEL_STATS,
    }
}

/// Client-side lifecycle status, mirroring the `status` string of
/// the Alpine component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientStatus {
    /// Session created, EWS not connected yet (countdown may run).
    WaitingClient,
    /// EWS relaying traffic (duration timer runs).
    TunnelActive,
    /// Authoritative server-side close -- ABSORBING state.
    Terminated,
    /// Local optimistic flip when the countdown hits zero. NOT
    /// absorbing: a late `tunnel_active` push recovers it (the EWS
    /// connected in the reap window; the server is the authority).
    Expired,
}

impl ClientStatus {
    pub fn parse(s: &str) -> Self {
        match s {
            "tunnel_active" => Self::TunnelActive,
            "terminated" => Self::Terminated,
            "expired" => Self::Expired,
            // Fail towards the waiting pill: unknown server-rendered
            // statuses show the neutral state, exactly like the JS
            // component's fallback `x-show` arm.
            _ => Self::WaitingClient,
        }
    }
}

/// Pure model of the Alpine component's reactive state: which pill
/// is shown and which timers run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientState {
    pub status: ClientStatus,
    /// The waiting-deadline countdown interval is live.
    pub countdown_running: bool,
    /// The `duration` wall-clock interval is live.
    pub duration_running: bool,
}

impl ClientState {
    /// State right after `init()` given the server-rendered status
    /// and countdown seed (`remaining >= 0` means "countdown
    /// enabled" -- the `-1` sentinel disables it).
    pub fn initial(server_status: &str, remaining_seed: i64) -> Self {
        let status = ClientStatus::parse(server_status);
        Self {
            status,
            countdown_running: status == ClientStatus::WaitingClient && remaining_seed >= 0,
            duration_running: status == ClientStatus::TunnelActive,
        }
    }

    /// Apply one incoming WS event. Twin of
    /// `iacsTunnelStatus.handle()` -- keep in lock-step with
    /// `static/js/vauban-components.js`.
    #[must_use]
    pub fn apply_event(self, event_type: &str) -> Self {
        match event_type {
            t if t == TYPE_TUNNEL_ACTIVE => {
                // Terminated is authoritative-final: a replayed or
                // out-of-order activation must not resurrect a
                // closed tunnel. Expired is only the local
                // optimistic guess, so activation recovers it.
                if self.status == ClientStatus::Terminated {
                    return self;
                }
                Self {
                    status: ClientStatus::TunnelActive,
                    countdown_running: false,
                    duration_running: true,
                }
            }
            t if t == TYPE_TUNNEL_CLOSED => Self {
                status: ClientStatus::Terminated,
                countdown_running: false,
                duration_running: false,
            },
            // Stats and any unknown type: byte counters only, no
            // lifecycle transition (fail-safe against future or
            // malformed message types).
            _ => self,
        }
    }

    /// The countdown interval ticked down to zero: flip to the
    /// local optimistic `expired` pill. Only meaningful while
    /// waiting; twin of `expireNow()` guarded by the
    /// `status !== 'waiting_client'` check in `startCountdown()`.
    #[must_use]
    pub fn expire_tick(self) -> Self {
        if self.status != ClientStatus::WaitingClient {
            return Self {
                countdown_running: false,
                ..self
            };
        }
        Self {
            status: ClientStatus::Expired,
            countdown_running: false,
            duration_running: self.duration_running,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn waiting() -> ClientState {
        ClientState::initial("waiting_client", 300)
    }

    // ----------------------------------------------------------------
    // Unit: the exact production bug scenario.
    // ----------------------------------------------------------------

    /// The July 2026 bug: EWS connects while the page is waiting.
    /// The activation event MUST stop the countdown and flip the
    /// pill -- the countdown may never keep running over an active
    /// tunnel.
    #[test]
    fn activation_stops_countdown_and_flips_pill() {
        let s = waiting().apply_event(TYPE_TUNNEL_ACTIVE);
        assert_eq!(s.status, ClientStatus::TunnelActive);
        assert!(!s.countdown_running, "countdown must stop on activation");
        assert!(s.duration_running, "duration timer must start");
    }

    /// Race: local countdown hit zero (optimistic `expired`) but the
    /// EWS actually connected inside the reap window. The server
    /// push is authoritative and must recover the pill.
    #[test]
    fn activation_recovers_local_optimistic_expiry() {
        let s = waiting().expire_tick().apply_event(TYPE_TUNNEL_ACTIVE);
        assert_eq!(s.status, ClientStatus::TunnelActive);
    }

    /// Terminated is absorbing: a replayed activation after the
    /// authoritative close must not resurrect the tunnel pill.
    #[test]
    fn terminated_is_absorbing() {
        let s = waiting()
            .apply_event(TYPE_TUNNEL_ACTIVE)
            .apply_event(TYPE_TUNNEL_CLOSED)
            .apply_event(TYPE_TUNNEL_ACTIVE);
        assert_eq!(s.status, ClientStatus::Terminated);
        assert!(!s.countdown_running);
        assert!(!s.duration_running);
    }

    /// EWS never connects: close arrives straight from waiting
    /// (watchdog reap). Countdown must stop.
    #[test]
    fn close_from_waiting_stops_countdown() {
        let s = waiting().apply_event(TYPE_TUNNEL_CLOSED);
        assert_eq!(s.status, ClientStatus::Terminated);
        assert!(!s.countdown_running);
    }

    /// Stats events never transition the lifecycle.
    #[test]
    fn stats_is_a_pure_counter_update() {
        assert_eq!(waiting().apply_event(TYPE_TUNNEL_STATS), waiting());
        let active = waiting().apply_event(TYPE_TUNNEL_ACTIVE);
        assert_eq!(active.apply_event(TYPE_TUNNEL_STATS), active);
    }

    /// Battle cases: garbage, legacy vocabulary, and empty types are
    /// all no-ops (the legacy `iacs_tunnel_status` envelope must
    /// never transition anything if it ever reappears on the wire).
    #[test]
    fn unknown_and_legacy_types_are_noops() {
        for evt in [
            "",
            "iacs_tunnel_status",
            "iacs_tunnel_closed",
            "TUNNEL_ACTIVE",
            "tunnel_active ",
            "recording_hydrated",
            "🦀",
        ] {
            assert_eq!(waiting().apply_event(evt), waiting(), "evt={evt:?}");
        }
    }

    /// Server-rendered seeds: countdown only arms on
    /// `waiting_client` with a non-negative seed.
    #[test]
    fn initial_state_matrix() {
        assert!(ClientState::initial("waiting_client", 300).countdown_running);
        assert!(!ClientState::initial("waiting_client", -1).countdown_running);
        assert!(!ClientState::initial("tunnel_active", 300).countdown_running);
        assert!(ClientState::initial("tunnel_active", -1).duration_running);
        assert!(!ClientState::initial("terminated", 300).countdown_running);
        // Unknown server statuses fall back to the waiting pill.
        assert_eq!(
            ClientState::initial("connecting", -1).status,
            ClientStatus::WaitingClient
        );
    }

    /// IPC status -> wire type mapping: knowns pass through, unknown
    /// strings demote to stats (cannot forge a lifecycle
    /// transition).
    #[test]
    fn event_type_for_status_mapping() {
        assert_eq!(event_type_for_status("tunnel_active"), TYPE_TUNNEL_ACTIVE);
        assert_eq!(event_type_for_status("tunnel_closed"), TYPE_TUNNEL_CLOSED);
        assert_eq!(event_type_for_status("tunnel_stats"), TYPE_TUNNEL_STATS);
        assert_eq!(event_type_for_status("garbage"), TYPE_TUNNEL_STATS);
        assert_eq!(event_type_for_status(""), TYPE_TUNNEL_STATS);
    }

    // ----------------------------------------------------------------
    // Invariant-based (proptest)
    // ----------------------------------------------------------------

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        /// One arbitrary step: a wire event or a countdown tick.
        #[derive(Debug, Clone)]
        enum Step {
            Event(String),
            ExpireTick,
        }

        fn step_strategy() -> impl Strategy<Value = Step> {
            prop_oneof![
                // Canonical vocabulary (weighted so sequences are
                // realistic), legacy envelope, and pure garbage.
                4 => prop_oneof![
                    Just(TYPE_TUNNEL_ACTIVE.to_string()),
                    Just(TYPE_TUNNEL_STATS.to_string()),
                    Just(TYPE_TUNNEL_CLOSED.to_string()),
                ].prop_map(Step::Event),
                2 => "[a-z_]{0,20}".prop_map(Step::Event),
                1 => Just(Step::Event("iacs_tunnel_status".to_string())),
                1 => Just(Step::ExpireTick),
            ]
        }

        fn initial_strategy() -> impl Strategy<Value = ClientState> {
            (
                prop_oneof![
                    Just("waiting_client"),
                    Just("tunnel_active"),
                    Just("terminated"),
                    Just("expired"),
                    Just("weird_status"),
                ],
                -1i64..=7200,
            )
                .prop_map(|(s, seed)| ClientState::initial(s, seed))
        }

        fn run(mut state: ClientState, steps: &[Step]) -> ClientState {
            for step in steps {
                state = match step {
                    Step::Event(t) => state.apply_event(t),
                    Step::ExpireTick => state.expire_tick(),
                };
            }
            state
        }

        proptest! {
            /// INVARIANT 1 -- the user-visible bug, generalized: after
            /// ANY sequence of events, the countdown may only be
            /// running while the pill shows `waiting_client`. A
            /// countdown ticking over an active/closed/expired tunnel
            /// is unrepresentable.
            #[test]
            fn countdown_only_runs_while_waiting(
                init in initial_strategy(),
                steps in proptest::collection::vec(step_strategy(), 0..25),
            ) {
                let s = run(init, &steps);
                prop_assert!(
                    !s.countdown_running || s.status == ClientStatus::WaitingClient,
                    "countdown running in {s:?} after {steps:?}"
                );
            }

            /// INVARIANT 2 -- the duration timer runs if and only if
            /// the pill shows `tunnel_active`.
            #[test]
            fn duration_iff_active(
                init in initial_strategy(),
                steps in proptest::collection::vec(step_strategy(), 0..25),
            ) {
                let s = run(init, &steps);
                prop_assert_eq!(
                    s.duration_running,
                    s.status == ClientStatus::TunnelActive,
                    "duration/status divergence in {:?} after {:?}", s, steps
                );
            }

            /// INVARIANT 3 -- `terminated` is absorbing: once the
            /// authoritative close lands, NO subsequent step may
            /// change the pill.
            #[test]
            fn terminated_absorbs_everything(
                init in initial_strategy(),
                steps in proptest::collection::vec(step_strategy(), 0..25),
            ) {
                let closed = init.apply_event(TYPE_TUNNEL_CLOSED);
                let s = run(closed, &steps);
                prop_assert_eq!(s.status, ClientStatus::Terminated);
                prop_assert!(!s.countdown_running);
                prop_assert!(!s.duration_running);
            }

            /// INVARIANT 4 -- events are idempotent: replaying the
            /// same event twice lands in the same state as once
            /// (IPC re-delivery safety).
            #[test]
            fn events_are_idempotent(
                init in initial_strategy(),
                evt in "[a-z_]{0,20}",
            ) {
                let once = init.apply_event(&evt);
                prop_assert_eq!(once.apply_event(&evt), once, "evt={:?}", evt);
            }

            /// INVARIANT 5 -- only canonical lifecycle types can
            /// transition the pill; every other string is a no-op.
            #[test]
            fn only_canonical_types_transition(
                init in initial_strategy(),
                evt in "[a-zA-Z_ ]{0,24}",
            ) {
                prop_assume!(evt != TYPE_TUNNEL_ACTIVE && evt != TYPE_TUNNEL_CLOSED);
                prop_assert_eq!(init.apply_event(&evt), init, "evt={:?}", evt);
            }

            /// INVARIANT 6 -- `event_type_for_status` is total and
            /// closed over the canonical vocabulary: whatever the
            /// proxy reports, the wire type is always one of
            /// `ALL_TYPES`.
            #[test]
            fn wire_type_is_always_canonical(status in "\\PC{0,32}") {
                let t = event_type_for_status(&status);
                prop_assert!(ALL_TYPES.contains(&t), "status={:?} -> {:?}", status, t);
            }
        }
    }
}
