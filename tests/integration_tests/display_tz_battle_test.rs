//! Contention: concurrent format_local calls stay correct.

use std::sync::Arc;

use chrono::{TimeZone, Utc};
use chrono_tz::Tz;
use tokio::sync::Barrier;
use vcp::tz::format_local;

#[tokio::test]
async fn battle_concurrent_format_local() {
    let n = 16usize;
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::with_capacity(n);
    let dt = Utc.with_ymd_and_hms(2026, 6, 23, 12, 0, 0).unwrap();

    for _ in 0..n {
        let barrier = barrier.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let utc = format_local(dt, Tz::UTC);
            let paris = format_local(dt, Tz::Europe__Paris);
            assert!(utc.contains("12:00"));
            assert!(paris.contains("14:00") || paris.contains("13:00"));
            assert_ne!(utc, paris);
        }));
    }

    for h in handles {
        h.await.expect("join");
    }
}
