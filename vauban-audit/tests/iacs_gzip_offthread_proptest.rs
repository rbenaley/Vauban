//! Property tests for off-thread IACS gzip CPU + pending barrier.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use flate2::read::GzDecoder;
use proptest::prelude::*;
use std::io::{Read, Write};
use tempfile::NamedTempFile;
use vauban_audit::{GzipCpuJob, PendingGzipTracker, run_gzip_cpu};

fn write_src(bytes: &[u8]) -> std::fs::File {
    let mut f = NamedTempFile::new().unwrap().into_file();
    f.write_all(bytes).unwrap();
    f.sync_all().unwrap();
    f
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn prop_run_gzip_cpu_roundtrips_random_payloads(
        len in 0usize..=4096,
        seed in any::<u8>(),
    ) {
        let payload: Vec<u8> = (0..len).map(|i| seed.wrapping_add(i as u8)).collect();
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_owned();
        let outcome = run_gzip_cpu(GzipCpuJob {
            session_id: "prop".into(),
            channel_id: 7,
            src: write_src(&payload),
            dst: tmp.reopen().unwrap(),
            src_relative: "raw.pcap".into(),
            dst_relative: "raw.pcap.gz".into(),
        });
        let (size, hex) = outcome.result.expect("gzip ok");
        assert_eq!(hex.len(), 64);
        let compressed = std::fs::read(&path).unwrap();
        assert_eq!(compressed.len() as u64, size);
        assert_eq!(blake3::hash(&compressed).to_hex().as_str(), hex);
        let mut dec = GzDecoder::new(&compressed[..]);
        let mut out = Vec::new();
        dec.read_to_end(&mut out).unwrap();
        assert_eq!(out, payload);
    }

    #[test]
    fn prop_pending_barrier_releases_only_at_zero(n in 1usize..=16) {
        let mut t = PendingGzipTracker::new();
        let sid = "s";
        assert!(t.session_end_unblocked(sid));
        for _ in 0..n {
            t.enqueue(sid);
        }
        assert!(!t.session_end_unblocked(sid));
        assert_eq!(t.pending_for(sid), n);
        for i in 0..n {
            let left = t.complete(sid);
            assert_eq!(left, n - 1 - i);
            if i + 1 < n {
                assert!(!t.session_end_unblocked(sid));
            }
        }
        assert!(t.session_end_unblocked(sid));
        assert_eq!(t.total_pending(), 0);
    }
}
