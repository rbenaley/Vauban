//! Battle tests: timed supervisor broker waits under adversarial conditions.
//!
//! These exercise the production helpers inside the `vauban-audit` binary
//! via subprocess-free unit coverage in `main.rs` plus pipe-level scenarios
//! reconstructed here with the same timeout budget constants.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use shared::ipc::IpcChannel;
use shared::messages::{ControlMessage, Message, ServiceStats};
use std::os::unix::io::AsRawFd;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};
use vauban_audit::{SUPERVISOR_BROKER_TIMEOUT_SECS, WEB_CRITICAL_ACK_TIMEOUT_SECS};

/// Mirror of production timed wait (poll + deadline). Kept local so the
/// battle harness does not depend on binary-private symbols, while still
/// validating the deadline contract the main loop relies on.
fn battle_recv_until_deadline(
    channel: &IpcChannel,
    deadline: Instant,
    mut pred: impl FnMut(&Message) -> bool,
) -> Result<Message, String> {
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err("supervisor broker reply timed out".into());
        }
        let remaining_ms = (deadline - now).as_millis().min(i32::MAX as u128) as i32;
        let ready = shared::ipc::poll_readable(&[channel.read_fd()], remaining_ms.max(1))
            .map_err(|e| e.to_string())?;
        if ready.is_empty() {
            if Instant::now() >= deadline {
                return Err("supervisor broker reply timed out".into());
            }
            continue;
        }
        match channel.recv() {
            Ok(Message::Control(ControlMessage::Ping { seq })) => {
                let _ = channel.send(&Message::Control(ControlMessage::Pong {
                    seq,
                    stats: ServiceStats {
                        uptime_secs: 0,
                        requests_processed: 0,
                        requests_failed: 0,
                        active_connections: 0,
                        pending_requests: 0,
                        recording_ack_timeouts: 0,
                        recording_ack_dropped: 0,
                        recording_try_send_full: 0,
                        recording_ack_wait_ms_max: 0,
                    },
                }));
            }
            Ok(msg) if pred(&msg) => return Ok(msg),
            Ok(_) => {}
            Err(e) => return Err(e.to_string()),
        }
    }
}

#[test]
fn battle_silent_supervisor_times_out_inside_broker_budget() {
    let (audit_ch, _sup) = IpcChannel::pair().unwrap();
    let deadline = Instant::now() + Duration::from_secs(SUPERVISOR_BROKER_TIMEOUT_SECS);
    let start = Instant::now();
    let err = battle_recv_until_deadline(&audit_ch, deadline, |_| false).unwrap_err();
    assert!(err.contains("timed out"), "{err}");
    let elapsed = start.elapsed();
    assert!(elapsed >= Duration::from_secs(SUPERVISOR_BROKER_TIMEOUT_SECS));
    assert!(elapsed < Duration::from_secs(WEB_CRITICAL_ACK_TIMEOUT_SECS));
}

#[test]
fn battle_pings_during_wait_do_not_extend_past_deadline() {
    let (audit_ch, sup_ch) = IpcChannel::pair().unwrap();
    // Keep the supervisor end alive for the full deadline so the wait
    // ends on timeout (not ConnectionClosed when the pinger drops).
    let pinger = thread::spawn(move || {
        let end = Instant::now() + Duration::from_secs(SUPERVISOR_BROKER_TIMEOUT_SECS + 1);
        let mut seq = 0u64;
        while Instant::now() < end {
            let _ = sup_ch.send(&Message::Control(ControlMessage::Ping { seq }));
            seq = seq.wrapping_add(1);
            thread::sleep(Duration::from_millis(80));
        }
        // Hold the channel until the waiter has timed out.
        thread::sleep(Duration::from_millis(200));
        drop(sup_ch);
    });
    let deadline = Instant::now() + Duration::from_secs(SUPERVISOR_BROKER_TIMEOUT_SECS);
    let start = Instant::now();
    let err = battle_recv_until_deadline(&audit_ch, deadline, |m| {
        matches!(m, Message::AuditLogFileResponse { .. })
    })
    .unwrap_err();
    assert!(err.contains("timed out"), "{err}");
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(WEB_CRITICAL_ACK_TIMEOUT_SECS),
        "pings must not push wait past web ACK budget: {elapsed:?}"
    );
    let _ = pinger.join();
}

#[test]
fn battle_unexpected_messages_then_matching_reply_still_delivers() {
    let (audit_ch, sup_ch) = IpcChannel::pair().unwrap();
    thread::spawn(move || {
        let _ = sup_ch.send(&Message::Control(ControlMessage::Ping { seq: 1 }));
        let _ = sup_ch.send(&Message::IacsProxyHealth {
            ack_timeouts: 0,
            ack_dropped: 0,
            ack_wait_ms_max: 0,
        });
        let _ = sup_ch.send(&Message::AuditLogFileResponse {
            request_id: 0,
            success: true,
            error: None,
        });
    });
    let deadline = Instant::now() + Duration::from_secs(SUPERVISOR_BROKER_TIMEOUT_SECS);
    let msg = battle_recv_until_deadline(&audit_ch, deadline, |m| {
        matches!(m, Message::AuditLogFileResponse { .. })
    })
    .expect("matching reply");
    assert!(matches!(
        msg,
        Message::AuditLogFileResponse {
            success: true,
            ..
        }
    ));
}

#[test]
fn battle_concurrent_waiters_each_respect_own_deadline() {
    let n = 4usize;
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::new();
    for _ in 0..n {
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let (audit_ch, _sup) = IpcChannel::pair().unwrap();
            barrier.wait();
            let deadline = Instant::now() + Duration::from_secs(SUPERVISOR_BROKER_TIMEOUT_SECS);
            let start = Instant::now();
            let err = battle_recv_until_deadline(&audit_ch, deadline, |_| false).unwrap_err();
            assert!(err.contains("timed out"));
            let elapsed = start.elapsed();
            assert!(elapsed < Duration::from_secs(WEB_CRITICAL_ACK_TIMEOUT_SECS));
            elapsed
        }));
    }
    for h in handles {
        let _ = h.join().expect("join");
    }
}

#[test]
fn battle_budget_slack_leaves_room_for_worm_append() {
    // At least 2s of slack after a max-length broker wait before web gives up.
    let slack = WEB_CRITICAL_ACK_TIMEOUT_SECS.saturating_sub(SUPERVISOR_BROKER_TIMEOUT_SECS);
    assert!(
        slack >= 2,
        "need >=2s slack for append+IPC after broker returns; got {slack}s"
    );
    // fd socketpair still creatable (SCM_RIGHTS path not broken on this host).
    let (a, b) = shared::ipc::socketpair_for_fd_passing().unwrap();
    assert!(a.as_raw_fd() >= 0);
    assert!(b.as_raw_fd() >= 0);
}
