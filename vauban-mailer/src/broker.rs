//! Supervisor-brokered SMTP TCP connect (Service::Mailer target).

use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use shared::ipc::{IpcChannel, poll_readable, recv_fd};
use shared::messages::{ControlMessage, Message, Service};
use tokio::net::TcpStream;
use tracing::info;

/// Ask the supervisor to connect to the configured SMTP relay and return a
/// non-blocking tokio TCP stream received via SCM_RIGHTS.
pub async fn request_smtp_connect(
    supervisor: &IpcChannel,
    fd_passing_socket: i32,
    host: &str,
    port: u16,
    broker_timeout_secs: u64,
    shutdown: &AtomicBool,
) -> Result<TcpStream, String> {
    let request_id: u64 = rand::random();
    let session_id = format!("mailer-{:016x}", rand::random::<u64>());
    let msg = Message::TcpConnectRequest {
        request_id,
        session_id,
        host: host.to_string(),
        port,
        target_service: Service::Mailer,
        session_token: Vec::new(),
    };
    supervisor
        .send(&msg)
        .map_err(|e| format!("send TcpConnectRequest: {e}"))?;

    let deadline = std::time::Instant::now() + Duration::from_secs(broker_timeout_secs.max(1));
    loop {
        if shutdown.load(Ordering::SeqCst) {
            return Err("shutdown requested".into());
        }
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err("SMTP broker request timeout".into());
        }
        let ms = remaining.as_millis().min(i32::MAX as u128) as i32;
        let ready = poll_readable(&[supervisor.read_fd()], ms)
            .map_err(|e| format!("poll supervisor: {e}"))?;
        if ready.is_empty() {
            continue;
        }
        match supervisor.recv() {
            Ok(Message::Control(ctrl)) => {
                if answer_control(supervisor, ctrl, shutdown) {
                    return Err("shutdown requested".into());
                }
            }
            Ok(Message::TcpConnectResponse {
                request_id: rid,
                success,
                error,
                ..
            }) if rid == request_id => {
                if !success {
                    return Err(error.unwrap_or_else(|| "broker refused".into()));
                }
                let owned = recv_fd_with_poll(fd_passing_socket, Duration::from_secs(2))?;
                let std_stream = unsafe { std::net::TcpStream::from_raw_fd(owned.into_raw_fd()) };
                std_stream
                    .set_nonblocking(true)
                    .map_err(|e| format!("set_nonblocking: {e}"))?;
                return TcpStream::from_std(std_stream)
                    .map_err(|e| format!("TcpStream::from_std: {e}"));
            }
            Ok(_) => {}
            Err(e) => return Err(format!("recv broker response: {e}")),
        }
    }
}

fn recv_fd_with_poll(fd_socket: i32, timeout: Duration) -> Result<OwnedFd, String> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err("no SCM_RIGHTS FD after broker success".into());
        }
        let ms = remaining.as_millis().min(i32::MAX as u128) as i32;
        match poll_readable(&[fd_socket], ms) {
            Ok(ready) if !ready.is_empty() => {
                return recv_fd(fd_socket).map_err(|e| format!("recv_fd: {e}"));
            }
            Ok(_) => {}
            Err(e) => return Err(format!("poll fd socket: {e}")),
        }
    }
}

/// Handle a supervisor control message on the sealed-leaf channel.
///
/// Returns `true` when `Shutdown` was received so the caller can leave
/// a blocking broker wait instead of swallowing the signal.
pub fn answer_control(supervisor: &IpcChannel, msg: ControlMessage, shutdown: &AtomicBool) -> bool {
    match msg {
        ControlMessage::Ping { seq } => {
            let _ = supervisor.send(&Message::Control(ControlMessage::Pong {
                seq,
                stats: shared::messages::ServiceStats::default(),
            }));
            false
        }
        ControlMessage::Drain => {
            let _ = supervisor.send(&Message::Control(ControlMessage::DrainComplete {
                pending_requests: 0,
            }));
            false
        }
        ControlMessage::Shutdown => {
            info!("Shutdown requested, setting graceful shutdown flag");
            shutdown.store(true, Ordering::SeqCst);
            true
        }
        ControlMessage::DrainComplete { .. } | ControlMessage::Pong { .. } => false,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use shared::messages::Message;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    #[test]
    fn broker_targets_service_mailer() {
        let src = include_str!("broker.rs");
        assert!(
            src.contains("target_service: Service::Mailer"),
            "SMTP broker MUST target Service::Mailer"
        );
    }

    #[test]
    fn answer_control_shutdown_sets_flag() {
        let (parent, child) = IpcChannel::pair().expect("ipc pair");
        let shutdown = AtomicBool::new(false);
        assert!(answer_control(&child, ControlMessage::Shutdown, &shutdown));
        assert!(shutdown.load(Ordering::SeqCst));
        drop(parent);
    }

    #[test]
    fn answer_control_ping_replies_pong_without_shutdown() {
        let (parent, child) = IpcChannel::pair().expect("ipc pair");
        let shutdown = AtomicBool::new(false);
        assert!(!answer_control(
            &child,
            ControlMessage::Ping { seq: 42 },
            &shutdown
        ));
        assert!(!shutdown.load(Ordering::SeqCst));
        match parent.recv().expect("pong") {
            Message::Control(ControlMessage::Pong { seq, .. }) => assert_eq!(seq, 42),
            other => panic!("expected Pong, got {other:?}"),
        }
    }

    #[test]
    fn answer_control_drain_replies_complete_without_shutdown() {
        let (parent, child) = IpcChannel::pair().expect("ipc pair");
        let shutdown = AtomicBool::new(false);
        assert!(!answer_control(&child, ControlMessage::Drain, &shutdown));
        assert!(!shutdown.load(Ordering::SeqCst));
        match parent.recv().expect("drain complete") {
            Message::Control(ControlMessage::DrainComplete { pending_requests }) => {
                assert_eq!(pending_requests, 0);
            }
            other => panic!("expected DrainComplete, got {other:?}"),
        }
    }

    #[test]
    fn answer_control_pong_and_drain_complete_are_ignored() {
        let (parent, child) = IpcChannel::pair().expect("ipc pair");
        let shutdown = AtomicBool::new(false);
        assert!(!answer_control(
            &child,
            ControlMessage::Pong {
                seq: 1,
                stats: shared::messages::ServiceStats::default(),
            },
            &shutdown
        ));
        assert!(!answer_control(
            &child,
            ControlMessage::DrainComplete {
                pending_requests: 3
            },
            &shutdown
        ));
        assert!(!shutdown.load(Ordering::SeqCst));
        drop(parent);
    }

    #[test]
    fn inv_answer_control_does_not_swallow_shutdown() {
        let src = include_str!("broker.rs");
        assert!(
            src.contains("ControlMessage::Shutdown =>"),
            "answer_control must match Shutdown explicitly"
        );
        let swallow = format!("| {} => {{}}", "ControlMessage::Shutdown");
        assert!(
            !src.contains(&swallow),
            "Shutdown must not be folded into a no-op arm"
        );
        assert!(
            src.contains("shutdown.store(true, Ordering::SeqCst)"),
            "Shutdown must set the shared flag"
        );
        assert!(
            src.contains("\"Shutdown requested, setting graceful shutdown flag\""),
            "Shutdown must log the same INFO literal as the other leaves"
        );
        assert!(
            src.contains("if answer_control(supervisor, ctrl, shutdown)"),
            "broker wait must honor answer_control's Shutdown return"
        );
        assert!(
            src.contains("return Err(\"shutdown requested\".into())"),
            "broker wait must abort on Shutdown"
        );
    }

    fn control_from_byte(b: u8) -> ControlMessage {
        match b % 5 {
            0 => ControlMessage::Drain,
            1 => ControlMessage::DrainComplete {
                pending_requests: u32::from(b),
            },
            2 => ControlMessage::Ping { seq: u64::from(b) },
            3 => ControlMessage::Pong {
                seq: u64::from(b),
                stats: shared::messages::ServiceStats::default(),
            },
            _ => ControlMessage::Shutdown,
        }
    }

    proptest::proptest! {
        #![proptest_config(proptest::test_runner::Config::with_cases(48))]

        #[test]
        fn answer_control_shutdown_in_any_sequence_sets_flag(bytes in proptest::collection::vec(0u8..20, 1..16)) {
            let (parent, child) = IpcChannel::pair().expect("ipc pair");
            let shutdown = AtomicBool::new(false);
            let mut saw_shutdown = false;
            for b in &bytes {
                let msg = control_from_byte(*b);
                if matches!(msg, ControlMessage::Shutdown) {
                    saw_shutdown = true;
                }
                let _ = answer_control(&child, msg, &shutdown);
                while parent.try_recv().is_ok() {}
            }
            proptest::prop_assert_eq!(shutdown.load(Ordering::SeqCst), saw_shutdown);
            drop(parent);
        }
    }

    #[test]
    fn battle_answer_control_shutdown_under_contention() {
        use std::sync::Barrier;
        use std::thread;

        let shutdown = Arc::new(AtomicBool::new(false));
        let barrier = Arc::new(Barrier::new(8));
        let mut handles = Vec::new();
        for t in 0..8 {
            let shutdown = Arc::clone(&shutdown);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                let (parent, child) = IpcChannel::pair().expect("ipc pair");
                barrier.wait();
                for i in 0..64 {
                    let msg = if i == 31 && t == 3 {
                        ControlMessage::Shutdown
                    } else if i % 2 == 0 {
                        ControlMessage::Ping {
                            seq: (t * 64 + i) as u64,
                        }
                    } else {
                        ControlMessage::Drain
                    };
                    let _ = answer_control(&child, msg, &shutdown);
                }
                drop(parent);
            }));
        }
        for h in handles {
            h.join().expect("battle thread");
        }
        assert!(
            shutdown.load(Ordering::SeqCst),
            "the injected Shutdown must win under contention"
        );
    }
}
