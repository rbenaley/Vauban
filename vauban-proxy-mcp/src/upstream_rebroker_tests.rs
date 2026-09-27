// Relax strict clippy lints in test code where unwrap/expect/panic are idiomatic.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::print_stdout,
        clippy::print_stderr
    )
)]

use super::*;
use anyhow::anyhow;
use std::sync::Arc;

fn rb() -> (McpUpstreamRebroker, mpsc::UnboundedReceiver<Message>) {
    let (tx, rx) = mpsc::unbounded_channel();
    let rb = McpUpstreamRebroker::new(
        tx,
        Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
    );
    (rb, rx)
}

fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(fut)
}

#[test]
fn dead_pipe_detects_header_eof_and_epipe() {
    assert!(is_dead_upstream_io(&anyhow!(
        "upstream closed before HTTP headers"
    )));
    assert!(is_dead_upstream_io(&anyhow!("Broken pipe (os error 32)")));
    assert!(is_dead_upstream_io(&anyhow!("Connection reset by peer")));
    assert!(!is_dead_upstream_io(&anyhow!("upstream JSON body")));
    assert!(!is_dead_upstream_io(&anyhow!("HTTP headers too large")));
    for kind in [
        io::ErrorKind::BrokenPipe,
        io::ErrorKind::ConnectionReset,
        io::ErrorKind::UnexpectedEof,
        io::ErrorKind::ConnectionAborted,
    ] {
        let e = io::Error::new(kind, "peer");
        assert!(is_dead_upstream_io(&e.into()), "{kind:?} must be dead-pipe");
    }
    let other = io::Error::other("not a pipe");
    assert!(!is_dead_upstream_io(&other.into()));
}

#[test]
fn rebroker_emits_proxy_mcp_tcp_connect() {
    let impl_src = include_str!("upstream_rebroker.rs");
    assert!(
        impl_src.contains("target_service: Service::ProxyMcp"),
        "re-broker MUST ask supervisor for ProxyMcp, never free connect"
    );
    assert!(
        impl_src.contains("TcpConnectRequest"),
        "re-broker MUST use existing IPC verb"
    );
    assert!(
        !impl_src.contains("TcpStream::connect"),
        "re-broker MUST NOT dial upstream"
    );
}

#[test]
fn rebroker_refuses_missing_bind_without_ipc() {
    let (rb, mut rx) = rb();
    for (host, port, token) in [
        ("", 19001, vec![1u8; 8]),
        ("127.0.0.1", 0, vec![1u8; 8]),
        ("127.0.0.1", 19001, vec![]),
    ] {
        let err = block_on(rb.open("sid", host, port, &token)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert!(
            err.to_string().contains("missing host/port/session_token"),
            "{err}"
        );
    }
    assert!(rx.try_recv().is_err(), "gate must not emit TcpConnect");
}

#[test]
fn rebroker_fails_when_supervisor_tx_closed() {
    let (tx, rx) = mpsc::unbounded_channel();
    drop(rx);
    let rb = McpUpstreamRebroker::new(
        tx,
        Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
    );
    let err = block_on(rb.open("sid", "127.0.0.1", 19001, &[1u8; 8])).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::Other);
    assert!(err.to_string().contains("supervisor_tx"), "{err}");
}

#[test]
fn rebroker_times_out_when_supervisor_silent() {
    let (mut rb, mut rx) = rb();
    rb.fd_wait = Duration::from_millis(80);
    let err = block_on(rb.open("sid-timeout", "127.0.0.1", 19001, &[1u8; 8])).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    assert!(err.to_string().contains("no brokered FD"), "{err}");
    let msg = rx.try_recv().expect("TcpConnectRequest");
    assert!(
        matches!(
            msg,
            Message::TcpConnectRequest {
                target_service: Service::ProxyMcp,
                ..
            }
        ),
        "{msg:?}"
    );
    if let Message::TcpConnectRequest { session_id, .. } = msg {
        assert_eq!(session_id, "sid-timeout");
    }
}

#[test]
fn rebroker_open_claims_supervisor_fd() {
    use std::os::fd::OwnedFd;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let _client = std::net::TcpStream::connect(addr).unwrap();
    let (server, _) = listener.accept().unwrap();
    let fd = OwnedFd::from(server);

    let pending: PendingConnections =
        Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
    let (tx, mut rx) = mpsc::unbounded_channel();
    let mut rb = McpUpstreamRebroker::new(tx, Arc::clone(&pending));
    rb.fd_wait = Duration::from_secs(2);

    let token = vec![0u8; 32];
    let pending_inject = Arc::clone(&pending);
    block_on(async move {
        tokio::spawn(async move {
            let msg = rx.recv().await.expect("TcpConnectRequest");
            assert!(
                matches!(
                    msg,
                    Message::TcpConnectRequest {
                        target_service: Service::ProxyMcp,
                        ..
                    }
                ),
                "{msg:?}"
            );
            if let Message::TcpConnectRequest {
                session_id,
                host,
                port,
                session_token,
                request_id,
                ..
            } = msg
            {
                assert_eq!(session_id, "sess-rebroker");
                assert_eq!(host, "127.0.0.1");
                assert_eq!(port, 19001);
                assert_eq!(session_token.len(), 32);
                assert_eq!(request_id, 1);
            }
            pending_inject
                .lock()
                .await
                .insert("sess-rebroker".into(), fd);
        });
        let stream = rb
            .open("sess-rebroker", "127.0.0.1", 19001, &token)
            .await
            .expect("brokered FD");
        let _ = stream;
    });
}
