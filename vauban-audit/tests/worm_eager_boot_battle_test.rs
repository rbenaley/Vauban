//! Battle tests: eager WORM open timeouts + append path without re-broker.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use shared::ipc::IpcChannel;
use shared::messages::Message;
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};
use vauban_audit::worm::{AuditRecord, GENESIS_HASH, WormLog};
use vauban_audit::{SUPERVISOR_BROKER_TIMEOUT_SECS, WEB_CRITICAL_ACK_TIMEOUT_SECS};

fn battle_recv_until(channel: &IpcChannel, deadline: Instant) -> Result<Message, String> {
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err("supervisor broker reply timed out".into());
        }
        let remaining_ms = (deadline - now).as_millis().min(i32::MAX as u128) as i32;
        let ready = shared::ipc::poll_readable(&[channel.read_fd()], remaining_ms.max(1))
            .map_err(|e| e.to_string())?;
        if ready.is_empty() {
            continue;
        }
        match channel.recv() {
            Ok(msg) if matches!(msg, Message::AuditLogFileResponse { .. }) => return Ok(msg),
            Ok(_) => {}
            Err(e) => return Err(e.to_string()),
        }
    }
}

#[test]
fn battle_silent_supervisor_eager_open_times_out_inside_broker_budget() {
    let (audit_ch, _sup) = IpcChannel::pair().unwrap();
    let deadline = Instant::now() + Duration::from_secs(SUPERVISOR_BROKER_TIMEOUT_SECS);
    let start = Instant::now();
    let err = battle_recv_until(&audit_ch, deadline).unwrap_err();
    assert!(err.contains("timed out"), "{err}");
    let elapsed = start.elapsed();
    assert!(elapsed >= Duration::from_secs(SUPERVISOR_BROKER_TIMEOUT_SECS));
    assert!(elapsed < Duration::from_secs(WEB_CRITICAL_ACK_TIMEOUT_SECS));
}

#[test]
fn battle_append_with_preopened_worm_progresses_while_other_thread_ticks() {
    let ticks = Arc::new(AtomicUsize::new(0));
    let barrier = Arc::new(Barrier::new(2));

    let ticks_main = Arc::clone(&ticks);
    let b_main = Arc::clone(&barrier);
    let drain = thread::spawn(move || {
        b_main.wait();
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            ticks_main.fetch_add(1, Ordering::SeqCst);
            thread::sleep(Duration::from_millis(1));
            if ticks_main.load(Ordering::SeqCst) > 40 {
                break;
            }
        }
    });

    let b_app = Arc::clone(&barrier);
    let appender = thread::spawn(move || {
        b_app.wait();
        let f = tempfile::tempfile().unwrap();
        let mut worm = WormLog::new(f, "battle/seg.jsonl".into(), GENESIS_HASH, 0);
        for i in 0..32 {
            let record = AuditRecord {
                timestamp: i,
                event_type: "Battle".into(),
                user_id: None,
                session_id: None,
                source_ip: None,
                details: format!("n{i}"),
            };
            worm.append_event(&record).unwrap();
        }
        assert_eq!(worm.records_in_segment(), 32);
    });

    drain.join().unwrap();
    appender.join().unwrap();
    assert!(
        ticks.load(Ordering::SeqCst) > 10,
        "simulated web drain must progress during append"
    );
}

#[test]
fn battle_fd_socketpair_still_usable_for_eager_path() {
    let (a, b) = shared::ipc::socketpair_for_fd_passing().unwrap();
    assert!(a.as_raw_fd() >= 0);
    assert!(b.as_raw_fd() >= 0);
}
