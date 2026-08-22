//! E2E: supervisor `Shutdown` must interrupt the sealed mailer idle wait
//! and an in-flight SMTP broker poll, without waiting `poll_interval_secs`
//! or `broker_timeout_secs`.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use shared::ipc::IpcChannel;
use shared::messages::{ControlMessage, Message};
use tokio::time::Instant;
use vauban_mailer::broker::request_smtp_connect;
use vauban_mailer::outbox::wait_for_tick_or_control;

#[tokio::test]
async fn e2e_shutdown_during_idle_wait_exits_before_poll_interval() {
    let (parent, child) = IpcChannel::pair().expect("ipc pair");
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_task = Arc::clone(&shutdown);
    let next_tick = Instant::now() + Duration::from_secs(30);
    let started = std::time::Instant::now();
    let waiter = tokio::spawn(async move {
        wait_for_tick_or_control(&child, &shutdown_task, next_tick).await;
        shutdown_task.load(Ordering::SeqCst)
    });
    tokio::time::sleep(Duration::from_millis(25)).await;
    parent
        .send(&Message::Control(ControlMessage::Shutdown))
        .expect("send Shutdown");
    let flagged = tokio::time::timeout(Duration::from_secs(2), waiter)
        .await
        .expect("idle wait must finish well before the 30s tick")
        .expect("waiter");
    assert!(flagged);
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_shutdown_during_broker_wait_is_honored() {
    let (parent, child) = IpcChannel::pair().expect("ipc pair");
    let shutdown = Arc::new(AtomicBool::new(false));
    let (keep_fd, _peer) = std::os::unix::net::UnixStream::pair().expect("socketpair");
    let fd = keep_fd.as_raw_fd();
    let shutdown_task = Arc::clone(&shutdown);
    let started = std::time::Instant::now();
    let broker = tokio::spawn(async move {
        request_smtp_connect(&child, fd, "smtp.test", 25, 30, &shutdown_task).await
    });
    tokio::time::sleep(Duration::from_millis(25)).await;
    parent
        .send(&Message::Control(ControlMessage::Shutdown))
        .expect("send Shutdown");
    let result = tokio::time::timeout(Duration::from_secs(2), broker)
        .await
        .expect("broker wait must abort on Shutdown")
        .expect("broker task");
    match result {
        Err(msg) => assert!(
            msg.contains("shutdown"),
            "broker error must name shutdown, got {msg}"
        ),
        Ok(_) => panic!("broker must not succeed after Shutdown"),
    }
    assert!(shutdown.load(Ordering::SeqCst));
    assert!(started.elapsed() < Duration::from_secs(2));
    drop(keep_fd);
}

#[tokio::test]
async fn e2e_ping_during_idle_wait_does_not_set_shutdown() {
    let (parent, child) = IpcChannel::pair().expect("ipc pair");
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_task = Arc::clone(&shutdown);
    let next_tick = Instant::now() + Duration::from_millis(150);
    let waiter = tokio::spawn(async move {
        wait_for_tick_or_control(&child, &shutdown_task, next_tick).await;
        shutdown_task.load(Ordering::SeqCst)
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    parent
        .send(&Message::Control(ControlMessage::Ping { seq: 99 }))
        .expect("send Ping");
    let flagged = tokio::time::timeout(Duration::from_secs(2), waiter)
        .await
        .expect("tick must still fire")
        .expect("waiter");
    assert!(!flagged, "Ping must not trip Shutdown");
    match parent.recv().expect("pong") {
        Message::Control(ControlMessage::Pong { seq, .. }) => assert_eq!(seq, 99),
        other => panic!("expected Pong, got {other:?}"),
    }
}
