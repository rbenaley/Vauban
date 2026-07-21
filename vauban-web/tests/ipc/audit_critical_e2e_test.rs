//! E2E + battle coverage for fail-closed `AuditClient::emit_critical`.
//!
//! Simulates the web↔audit pipe the MFA path depends on: a durable
//! `AuditAck` must resolve the oneshot; silence / Nack must fail closed
//! inside [`CRITICAL_ACK_TIMEOUT_SECS`]; concurrent criticals stay
//! bijective on timestamp.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use shared::ipc::IpcChannel;
use shared::messages::{AuditEventType, Message};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use vauban_web::ipc::audit::{AuditClient, AuditEvent, CRITICAL_ACK_TIMEOUT_SECS};

fn client_with_mock() -> (Arc<AuditClient>, IpcChannel) {
    let (web_side, audit_side) = IpcChannel::pair().unwrap();
    let r = web_side.read_fd();
    let w = web_side.write_fd();
    std::mem::forget(web_side);
    let client = AuditClient::new(r, w).unwrap();
    (client, audit_side)
}

fn spawn_pump(client: Arc<AuditClient>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let _ = client.process_incoming().await;
    })
}

#[tokio::test]
async fn e2e_emit_critical_resolves_when_audit_acks() {
    let (client, mock) = client_with_mock();
    let pump = spawn_pump(Arc::clone(&client));

    let mock_task = tokio::task::spawn_blocking(move || {
        let msg = mock.recv().unwrap();
        if let Message::AuditEvent {
            timestamp,
            event_type,
            ..
        } = msg
        {
            assert!(matches!(event_type, AuditEventType::MfaChallengePassed));
            mock.send(&Message::AuditAck { timestamp }).unwrap();
        } else {
            panic!("expected AuditEvent, got {msg:?}");
        }
    });

    let res = client
        .emit_critical(
            AuditEvent::new(AuditEventType::MfaChallengePassed, "{}").user("alice"),
        )
        .await;
    mock_task.await.unwrap();
    assert!(res.is_ok(), "{res:?}");
    pump.abort();
}

#[tokio::test]
async fn e2e_emit_critical_fails_closed_on_nack() {
    let (client, mock) = client_with_mock();
    let pump = spawn_pump(Arc::clone(&client));

    let mock_task = tokio::task::spawn_blocking(move || {
        let msg = mock.recv().unwrap();
        if let Message::AuditEvent { timestamp, .. } = msg {
            mock.send(&Message::AuditNack {
                timestamp,
                error: "worm segment open failed: disk full".into(),
            })
            .unwrap();
        }
    });

    let err = client
        .emit_critical(AuditEvent::new(AuditEventType::MfaChallengePassed, "{}"))
        .await
        .expect_err("nack");
    mock_task.await.unwrap();
    assert!(
        err.contains("NACK") || err.contains("Nack") || err.contains("NACKed"),
        "{err}"
    );
    pump.abort();
}

#[tokio::test]
async fn e2e_emit_critical_times_out_when_audit_silent() {
    let (client, mock) = client_with_mock();
    let pump = spawn_pump(Arc::clone(&client));
    // Hold the mock so the pipe stays open but never Acks.
    let _keep = mock;

    let start = Instant::now();
    let err = client
        .emit_critical(AuditEvent::new(AuditEventType::MfaChallengePassed, "{}"))
        .await
        .expect_err("timeout");
    let elapsed = start.elapsed();
    assert!(err.contains("timed out"), "{err}");
    assert!(
        elapsed >= Duration::from_secs(CRITICAL_ACK_TIMEOUT_SECS),
        "elapsed {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(CRITICAL_ACK_TIMEOUT_SECS + 3),
        "elapsed {elapsed:?} far past budget"
    );
    pump.abort();
}

#[tokio::test]
async fn battle_late_ack_after_timeout_does_not_poison_next_critical() {
    let (client, mock) = client_with_mock();
    let pump = spawn_pump(Arc::clone(&client));

    let mock_task = thread::spawn(move || {
        // First event: answer after the web timeout.
        let msg = mock.recv().unwrap();
        let ts1 = match msg {
            Message::AuditEvent { timestamp, .. } => timestamp,
            other => panic!("expected AuditEvent, got {other:?}"),
        };
        thread::sleep(Duration::from_secs(CRITICAL_ACK_TIMEOUT_SECS + 1));
        let _ = mock.send(&Message::AuditAck { timestamp: ts1 });

        // Second event: Ack promptly.
        let msg = mock.recv().unwrap();
        let ts2 = match msg {
            Message::AuditEvent { timestamp, .. } => timestamp,
            other => panic!("expected AuditEvent, got {other:?}"),
        };
        mock.send(&Message::AuditAck { timestamp: ts2 }).unwrap();
    });

    let err = client
        .emit_critical(AuditEvent::new(AuditEventType::MfaChallengePassed, "{}"))
        .await
        .expect_err("first must time out");
    assert!(err.contains("timed out"), "{err}");

    let res = client
        .emit_critical(AuditEvent::new(AuditEventType::AuthSuccess, r#"{"flow":"retry"}"#))
        .await;
    assert!(res.is_ok(), "second critical must succeed after late ack: {res:?}");
    mock_task.join().unwrap();
    pump.abort();
}

#[tokio::test]
async fn battle_concurrent_criticals_bijection_on_timestamp() {
    let (client, mock) = client_with_mock();
    let pump = spawn_pump(Arc::clone(&client));
    let n = 8usize;

    let mock_task = thread::spawn(move || {
        let mut stamps = Vec::with_capacity(n);
        for _ in 0..n {
            match mock.recv().unwrap() {
                Message::AuditEvent { timestamp, .. } => stamps.push(timestamp),
                other => panic!("unexpected {other:?}"),
            }
        }
        // Shuffle reply order (deterministic LCG).
        let mut order = stamps;
        let mut state = 0xC0FFEE_u64;
        for i in (1..order.len()).rev() {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1);
            let j = (state as usize) % (i + 1);
            order.swap(i, j);
        }
        for timestamp in order {
            mock.send(&Message::AuditAck { timestamp }).unwrap();
        }
    });

    let mut handles = Vec::new();
    for i in 0..n {
        let client = Arc::clone(&client);
        handles.push(tokio::spawn(async move {
            client
                .emit_critical(
                    AuditEvent::new(AuditEventType::MfaChallengePassed, format!(r#"{{"i":{i}}}"#))
                        .user(format!("u{i}")),
                )
                .await
        }));
    }

    for h in handles {
        let res = h.await.unwrap();
        assert!(res.is_ok(), "{res:?}");
    }
    mock_task.join().unwrap();
    pump.abort();
}

#[tokio::test]
async fn battle_ack_budget_exceeds_audit_broker_timeout() {
    // Cross-crate numeric invariant used by staging MFA: audit broker
    // waits (2s) must finish with slack before web gives up (5s).
    assert!(CRITICAL_ACK_TIMEOUT_SECS > 2);
    assert_eq!(CRITICAL_ACK_TIMEOUT_SECS, 5);
}
