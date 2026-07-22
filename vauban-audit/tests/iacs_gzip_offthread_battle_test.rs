//! Battle tests: gzip worker progresses while "main" drains work;
//! SessionEnd barrier; wake-pipe coalescing.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::io::Write;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;
use vauban_audit::{
    GzipCpuJob, PendingGzipTracker, drain_wakeup, run_gzip_cpu, spawn_gzip_worker, wakeup_pipe,
};

fn large_payload(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 251) as u8).collect()
}

fn write_src(bytes: &[u8]) -> std::fs::File {
    let mut f = NamedTempFile::new().unwrap().into_file();
    f.write_all(bytes).unwrap();
    f.sync_all().unwrap();
    f
}

#[test]
fn battle_web_drain_progresses_while_worker_gzips() {
    let payload = large_payload(512 * 1024);
    let web_ticks = Arc::new(AtomicUsize::new(0));
    let barrier = Arc::new(Barrier::new(2));

    let ticks = Arc::clone(&web_ticks);
    let b_main = Arc::clone(&barrier);
    let main_thread = thread::spawn(move || {
        b_main.wait();
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            ticks.fetch_add(1, Ordering::SeqCst);
            thread::sleep(Duration::from_millis(1));
            if ticks.load(Ordering::SeqCst) > 50 {
                break;
            }
        }
    });

    let b_worker = Arc::clone(&barrier);
    let worker = thread::spawn(move || {
        b_worker.wait();
        let tmp = NamedTempFile::new().unwrap();
        let outcome = run_gzip_cpu(GzipCpuJob {
            session_id: "battle".into(),
            channel_id: 1,
            src: write_src(&payload),
            dst: tmp.reopen().unwrap(),
            src_relative: "a.pcap".into(),
            dst_relative: "a.pcap.gz".into(),
        });
        outcome.result.expect("gzip ok");
    });

    main_thread.join().unwrap();
    worker.join().unwrap();
    assert!(
        web_ticks.load(Ordering::SeqCst) > 10,
        "simulated web drain must progress during gzip CPU"
    );
}

#[test]
fn battle_session_end_deferred_until_two_jobs_complete() {
    let mut pending = PendingGzipTracker::new();
    let mut deferred = false;
    pending.enqueue("s");
    pending.enqueue("s");
    if !pending.session_end_unblocked("s") {
        deferred = true;
    }
    assert!(deferred);
    assert_eq!(pending.complete("s"), 1);
    assert!(!pending.session_end_unblocked("s"));
    assert_eq!(pending.complete("s"), 0);
    assert!(pending.session_end_unblocked("s"));
}

#[test]
fn battle_wake_pipe_coalesces_multiple_dones() {
    let (wake_read, wake_write) = wakeup_pipe().unwrap();
    let (job_tx, job_rx) = mpsc::channel();
    let (outcome_tx, outcome_rx) = mpsc::channel();
    let handle = spawn_gzip_worker(job_rx, outcome_tx, wake_write).unwrap();

    for channel_id in 1u32..=3 {
        let tmp = NamedTempFile::new().unwrap();
        job_tx
            .send(GzipCpuJob {
                session_id: "coalesce".into(),
                channel_id,
                src: write_src(b"pcap-bytes"),
                dst: tmp.reopen().unwrap(),
                src_relative: format!("{channel_id}.pcap"),
                dst_relative: format!("{channel_id}.pcap.gz"),
            })
            .unwrap();
    }
    drop(job_tx);

    let mut got = 0usize;
    let deadline = Instant::now() + Duration::from_secs(5);
    while got < 3 && Instant::now() < deadline {
        // Single poll-style drain can collect multiple wake bytes.
        drain_wakeup(wake_read.as_raw_fd());
        while outcome_rx.try_recv().is_ok() {
            got += 1;
        }
        if got < 3 {
            thread::sleep(Duration::from_millis(5));
        }
    }
    assert_eq!(got, 3, "all outcomes delivered");
    // Extra drain is a no-op (WouldBlock).
    drain_wakeup(wake_read.as_raw_fd());
    handle.join().unwrap();
}
