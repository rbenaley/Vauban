//! Supervisor-brokered SMTP TCP connect (Service::Mailer target).

use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd};
use std::time::Duration;

use shared::ipc::{IpcChannel, poll_readable, recv_fd};
use shared::messages::{ControlMessage, Message, Service};
use tokio::net::TcpStream;

/// Ask the supervisor to connect to the configured SMTP relay and return a
/// non-blocking tokio TCP stream received via SCM_RIGHTS.
pub async fn request_smtp_connect(
    supervisor: &IpcChannel,
    fd_passing_socket: i32,
    host: &str,
    port: u16,
    broker_timeout_secs: u64,
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
            Ok(Message::Control(ctrl)) => answer_control(supervisor, ctrl),
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

/// Handle control messages during blocking broker waits (heartbeats).
pub fn answer_control(supervisor: &IpcChannel, msg: ControlMessage) {
    match msg {
        ControlMessage::Ping { seq } => {
            let _ = supervisor.send(&Message::Control(ControlMessage::Pong {
                seq,
                stats: shared::messages::ServiceStats::default(),
            }));
        }
        ControlMessage::Drain => {
            let _ = supervisor.send(&Message::Control(ControlMessage::DrainComplete {
                pending_requests: 0,
            }));
        }
        ControlMessage::DrainComplete { .. }
        | ControlMessage::Pong { .. }
        | ControlMessage::Shutdown => {}
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn broker_targets_service_mailer() {
        let src = include_str!("broker.rs");
        assert!(
            src.contains("target_service: Service::Mailer"),
            "SMTP broker MUST target Service::Mailer"
        );
    }
}
