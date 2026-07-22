//! Property tests: pre-opened WORM appends; broker budget still under web ACK.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use proptest::prelude::*;
use vauban_audit::worm::{AuditRecord, GENESIS_HASH, WormLog};
use vauban_audit::{SUPERVISOR_BROKER_TIMEOUT_SECS, WEB_CRITICAL_ACK_TIMEOUT_SECS};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn prop_preopened_worm_appends_without_broker(
        n in 1usize..=16,
        seed in any::<u8>(),
    ) {
        // Post-eager-boot: worm already installed; N appends never need a
        // supervisor broker open (pure CPU + fsync).
        let f = tempfile::tempfile().unwrap();
        let mut worm = WormLog::new(f, "prop/seg.jsonl".into(), GENESIS_HASH, 0);
        let head0 = worm.head();
        for i in 0..n {
            let record = AuditRecord {
                timestamp: 1_000 + i as u64,
                event_type: format!("Evt{seed}"),
                user_id: Some("u".into()),
                session_id: None,
                source_ip: None,
                details: format!("d{i}"),
            };
            worm.append_event(&record).unwrap();
        }
        assert_ne!(worm.head(), head0);
        assert_eq!(worm.records_in_segment(), n as u64);
    }

    #[test]
    fn prop_broker_budget_still_under_web_critical(_slack in 1u64..=10) {
        const {
            assert!(SUPERVISOR_BROKER_TIMEOUT_SECS < WEB_CRITICAL_ACK_TIMEOUT_SECS);
        }
    }
}
