//! Property tests for [`vauban_web::ipc::pump_exit_policy`].

#![allow(clippy::unwrap_used)]

use proptest::prelude::*;
use vauban_web::ipc::{PumpExit, pump_exit_policy};

proptest! {
    #[test]
    fn shutdown_never_requests_respawn(ended: bool) {
        prop_assert_eq!(pump_exit_policy(true, ended), PumpExit::Quiet);
    }

    #[test]
    fn live_end_always_requests_respawn(ended: bool) {
        prop_assert_eq!(pump_exit_policy(false, ended), PumpExit::RequestRespawn);
    }
}
