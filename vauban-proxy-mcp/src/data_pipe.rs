//! Hop-2 bytes on the dedicated web data pipe.
//!
//! The leaf has no TCP listener. `vauban-web` sends one
//! [`Message::McpRelayRequest`] plus ordered [`Message::McpRelayBody`]
//! chunks; this module reassembles them and feeds the existing `/mcp`
//! router. Responses go back as chunks on the same pipe.

use axum::body::Body;
use axum::http::{HeaderValue, Request, StatusCode};
use shared::ipc::{IpcChannel, IpcError};
use shared::messages::{MCP_PIPE_CHUNK_BYTES, Message};
use shared::pipe_store::EXIT_CODE_RESPAWN;
use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::process::ExitCode;
use std::sync::Arc;
use tokio::sync::{Semaphore, mpsc};
use tower::ServiceExt;
use tracing::info;

pub const RELAY_MAX_INFLIGHT: usize = 64;

/// Who delivered this hop-2 request. Missing on the router is fail-closed.
#[derive(Clone, Debug)]
pub enum McpIngress {
    Direct {
        #[allow(dead_code)]
        client_ip: String,
    },
    Tunnel {
        #[allow(dead_code)]
        tunnel_id: u64,
        #[allow(dead_code)]
        client_ip: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssembleError {
    Header,
    Oversize,
    UnknownRelay,
    Protocol,
}

#[derive(Debug)]
struct Inflight {
    client_ip: String,
    authorization: String,
    content_type: String,
    accept: String,
    mcp_session_id: Option<String>,
    mcp_protocol_version: Option<String>,
    body_len: u32,
    chunks: BTreeMap<u32, Vec<u8>>,
    saw_last: bool,
    last_seq: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssembledRelay {
    pub relay_id: u64,
    pub client_ip: String,
    pub authorization: String,
    pub content_type: String,
    pub accept: String,
    pub mcp_session_id: Option<String>,
    pub mcp_protocol_version: Option<String>,
    pub body: Vec<u8>,
}

/// Reassembles concurrent relays. Chunks may arrive out of order.
#[derive(Default)]
pub struct RelayAssembler {
    inflight: BTreeMap<u64, Inflight>,
}

impl RelayAssembler {
    pub fn push(&mut self, msg: &Message) -> Result<Option<AssembledRelay>, (u64, AssembleError)> {
        match msg {
            Message::McpRelayRequest {
                relay_id,
                client_ip,
                authorization,
                content_type,
                accept,
                mcp_session_id,
                mcp_protocol_version,
                body_len,
            } => {
                if !header_ok(authorization.as_str())
                    || !header_safe(content_type)
                    || !header_safe(accept)
                    || mcp_session_id.as_deref().is_some_and(|s| !header_safe(s))
                    || mcp_protocol_version
                        .as_deref()
                        .is_some_and(|s| !header_safe(s))
                {
                    return Err((*relay_id, AssembleError::Header));
                }
                if *body_len as usize > crate::upstream_http::MAX_UPSTREAM_BODY_BYTES {
                    return Err((*relay_id, AssembleError::Oversize));
                }
                self.inflight.insert(
                    *relay_id,
                    Inflight {
                        client_ip: client_ip.clone(),
                        authorization: authorization.as_str().to_string(),
                        content_type: content_type.clone(),
                        accept: accept.clone(),
                        mcp_session_id: mcp_session_id.clone(),
                        mcp_protocol_version: mcp_protocol_version.clone(),
                        body_len: *body_len,
                        chunks: BTreeMap::new(),
                        saw_last: false,
                        last_seq: None,
                    },
                );
                if *body_len == 0 {
                    return Ok(self.take_if_complete(*relay_id));
                }
                Ok(None)
            }
            Message::McpRelayBody {
                relay_id,
                seq,
                last,
                data,
            } => {
                let Some(slot) = self.inflight.get_mut(relay_id) else {
                    return Err((*relay_id, AssembleError::UnknownRelay));
                };
                if slot.chunks.contains_key(seq) {
                    return Err((*relay_id, AssembleError::Protocol));
                }
                if let Some(last_seq) = slot.last_seq
                    && *seq > last_seq
                {
                    return Err((*relay_id, AssembleError::Protocol));
                }
                if *last {
                    if slot.saw_last {
                        return Err((*relay_id, AssembleError::Protocol));
                    }
                    slot.saw_last = true;
                    slot.last_seq = Some(*seq);
                }
                slot.chunks.insert(*seq, data.clone());
                let total: usize = slot.chunks.values().map(Vec::len).sum();
                if total > slot.body_len as usize {
                    return Err((*relay_id, AssembleError::Oversize));
                }
                Ok(self.take_if_complete(*relay_id))
            }
            _ => Ok(None),
        }
    }

    fn take_if_complete(&mut self, relay_id: u64) -> Option<AssembledRelay> {
        let ready = self.inflight.get(&relay_id).is_some_and(|slot| {
            let total: usize = slot.chunks.values().map(Vec::len).sum();
            let contiguous = slot.chunks.keys().copied().eq(0..slot.chunks.len() as u32);
            (slot.body_len == 0 || slot.saw_last) && contiguous && total == slot.body_len as usize
        });
        if !ready {
            return None;
        }
        let slot = self.inflight.remove(&relay_id)?;
        let mut body = Vec::with_capacity(slot.body_len as usize);
        for chunk in slot.chunks.into_values() {
            body.extend(chunk);
        }
        Some(AssembledRelay {
            relay_id,
            client_ip: slot.client_ip,
            authorization: slot.authorization,
            content_type: slot.content_type,
            accept: slot.accept,
            mcp_session_id: slot.mcp_session_id,
            mcp_protocol_version: slot.mcp_protocol_version,
            body,
        })
    }
}

/// Visible-ASCII header value. Empty is allowed for optional headers.
pub fn header_safe(value: &str) -> bool {
    value
        .chars()
        .all(|c| c == '\t' || (c >= ' ' && c != '\u{7f}'))
}

/// Non-empty [`header_safe`] value (Authorization).
pub fn header_ok(value: &str) -> bool {
    !value.is_empty() && header_safe(value)
}

pub fn build_relay_request(relay: &AssembledRelay) -> Result<Request<Body>, ()> {
    if !header_ok(&relay.authorization) {
        return Err(());
    }
    let mut builder = Request::builder().method("POST").uri("/mcp").header(
        "authorization",
        HeaderValue::from_str(&relay.authorization).map_err(|_| ())?,
    );
    if !relay.content_type.is_empty() && header_safe(&relay.content_type) {
        builder = builder.header(
            "content-type",
            HeaderValue::from_str(&relay.content_type).map_err(|_| ())?,
        );
    }
    if !relay.accept.is_empty() && header_safe(&relay.accept) {
        builder = builder.header(
            "accept",
            HeaderValue::from_str(&relay.accept).map_err(|_| ())?,
        );
    }
    if let Some(sid) = relay
        .mcp_session_id
        .as_deref()
        .filter(|s| !s.is_empty() && header_safe(s))
    {
        builder = builder.header(
            "mcp-session-id",
            HeaderValue::from_str(sid).map_err(|_| ())?,
        );
    }
    if let Some(ver) = relay
        .mcp_protocol_version
        .as_deref()
        .filter(|s| !s.is_empty() && header_safe(s))
    {
        builder = builder.header(
            "mcp-protocol-version",
            HeaderValue::from_str(ver).map_err(|_| ())?,
        );
    }
    let mut req = builder
        .body(Body::from(relay.body.clone()))
        .map_err(|_| ())?;
    req.extensions_mut().insert(McpIngress::Direct {
        client_ip: relay.client_ip.clone(),
    });
    Ok(req)
}

pub fn chunk_bytes(data: &[u8]) -> Vec<Vec<u8>> {
    if data.is_empty() {
        return Vec::new();
    }
    data.chunks(MCP_PIPE_CHUNK_BYTES)
        .map(|c| c.to_vec())
        .collect()
}

fn would_block(err: &IpcError) -> bool {
    matches!(err, IpcError::Io(e) if e.kind() == ErrorKind::WouldBlock)
}

/// What one poll of the data pipe should do.
///
/// Supervisor shutdown wins over a dead peer: exiting 0 keeps the
/// supervisor from treating a graceful stop as [`EXIT_CODE_RESPAWN`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DataLoopPoll {
    Continue,
    Shutdown,
    Respawn,
}

fn classify_data_poll(shutdown_ready: bool, recv_is_terminal: bool) -> DataLoopPoll {
    if shutdown_ready {
        DataLoopPoll::Shutdown
    } else if recv_is_terminal {
        DataLoopPoll::Respawn
    } else {
        DataLoopPoll::Continue
    }
}

fn shutdown_is_ready(rx: &mut tokio::sync::broadcast::Receiver<()>) -> bool {
    match rx.try_recv() {
        Ok(())
        | Err(tokio::sync::broadcast::error::TryRecvError::Lagged(_))
        | Err(tokio::sync::broadcast::error::TryRecvError::Closed) => true,
        Err(tokio::sync::broadcast::error::TryRecvError::Empty) => false,
    }
}

/// Read the data pipe until supervisor shutdown or the peer closes.
///
/// Shutdown returns success. An unexpected close returns
/// [`EXIT_CODE_RESPAWN`] so the supervisor replaces the pipe.
pub async fn data_ipc_loop(
    channel: IpcChannel,
    router: axum::Router,
    max_inflight: usize,
    max_tunnels: usize,
    relay_timeout: std::time::Duration,
    mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
) -> ExitCode {
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
    let writer = Arc::new(channel);
    let reader = Arc::clone(&writer);
    let writer_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if writer.send(&msg).is_err() {
                break;
            }
        }
    });
    let permits = Arc::new(Semaphore::new(max_inflight.max(1)));
    let mut assembler = RelayAssembler::default();
    let mut tunnels: std::collections::HashMap<u64, mpsc::Sender<Vec<u8>>> =
        std::collections::HashMap::new();
    loop {
        let recv = reader.try_recv();
        let terminal = match &recv {
            Err(e) if would_block(e) => false,
            Err(_) => true,
            Ok(_) => false,
        };
        match classify_data_poll(shutdown_is_ready(&mut shutdown_rx), terminal) {
            DataLoopPoll::Shutdown => {
                info!("MCP data pipe stopping for shutdown");
                drop(tx);
                let _ = writer_task.await;
                return ExitCode::SUCCESS;
            }
            DataLoopPoll::Respawn => {
                info!("MCP data pipe closed, requesting respawn");
                drop(tx);
                let _ = writer_task.await;
                return ExitCode::from(EXIT_CODE_RESPAWN as u8);
            }
            DataLoopPoll::Continue => {}
        }
        match recv {
            Ok(Message::McpTunnelOpen {
                tunnel_id,
                client_ip,
            }) => {
                if tunnels.len() >= max_tunnels.max(1) {
                    let _ = tx.send(Message::McpTunnelClose {
                        tunnel_id,
                        reason: "max_tunnels".into(),
                    });
                    continue;
                }
                let Some(config) = crate::tunnel::identity() else {
                    let _ = tx.send(Message::McpTunnelClose {
                        tunnel_id,
                        reason: "no_identity".into(),
                    });
                    continue;
                };
                let (stream, mut ends) = crate::tunnel::PipeStream::pair();
                tunnels.insert(tunnel_id, ends.inbound);
                let router = router.clone();
                let tx_out = tx.clone();
                tokio::spawn(async move {
                    let tx_bytes = tx_out.clone();
                    tokio::spawn(async move {
                        while let Some(data) = ends.outbound.recv().await {
                            if tx_bytes
                                .send(Message::McpTunnelData { tunnel_id, data })
                                .is_err()
                            {
                                break;
                            }
                        }
                    });
                    crate::tunnel::serve_tunnel(
                        config,
                        stream,
                        router,
                        McpIngress::Tunnel {
                            tunnel_id,
                            client_ip,
                        },
                    )
                    .await;
                });
            }
            Ok(Message::McpTunnelData { tunnel_id, data }) => {
                if let Some(inbound) = tunnels.get(&tunnel_id) {
                    let _ = inbound.try_send(data);
                }
            }
            Ok(Message::McpTunnelClose { tunnel_id, .. }) => {
                tunnels.remove(&tunnel_id);
            }
            Ok(msg) => match assembler.push(&msg) {
                Ok(Some(relay)) => {
                    let permit = permits.clone().acquire_owned().await;
                    let Ok(permit) = permit else {
                        return ExitCode::from(EXIT_CODE_RESPAWN as u8);
                    };
                    let router = router.clone();
                    let tx = tx.clone();
                    tokio::spawn(async move {
                        serve_one(router, relay, tx, relay_timeout).await;
                        drop(permit);
                    });
                }
                Ok(None) => {}
                Err((relay_id, reason)) => {
                    assembler.inflight.remove(&relay_id);
                    let _ = tx.send(Message::McpRelayAbort {
                        relay_id,
                        reason: format!("{reason:?}"),
                    });
                }
            },
            Err(e) if would_block(&e) => {
                tokio::time::sleep(std::time::Duration::from_millis(2)).await;
            }
            Err(_) => {
                info!("MCP data pipe closed, requesting respawn");
                drop(tx);
                let _ = writer_task.await;
                return ExitCode::from(EXIT_CODE_RESPAWN as u8);
            }
        }
    }
}

async fn serve_one(
    router: axum::Router,
    relay: AssembledRelay,
    tx: mpsc::UnboundedSender<Message>,
    relay_timeout: std::time::Duration,
) {
    let relay_id = relay.relay_id;
    let req = match build_relay_request(&relay) {
        Ok(req) => req,
        Err(()) => {
            let _ = tx.send(Message::McpRelayAbort {
                relay_id,
                reason: "header".into(),
            });
            return;
        }
    };
    let response = match tokio::time::timeout(relay_timeout, router.oneshot(req)).await {
        Ok(Ok(resp)) => resp,
        Ok(Err(infallible)) => match infallible {},
        Err(_) => {
            let _ = tx.send(Message::McpRelayAbort {
                relay_id,
                reason: "timeout".into(),
            });
            return;
        }
    };
    let status = response.status();
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json")
        .to_string();
    let mcp_session_id = response
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let body = axum::body::to_bytes(
        response.into_body(),
        crate::upstream_http::MAX_UPSTREAM_BODY_BYTES,
    )
    .await
    .unwrap_or_default();
    let http_status = if status == StatusCode::OK {
        200
    } else {
        status.as_u16()
    };
    let _ = tx.send(Message::McpRelayResponse {
        relay_id,
        status: http_status,
        content_type,
        mcp_session_id,
        body_len: body.len() as u32,
    });
    let chunks = chunk_bytes(&body);
    let last_index = chunks.len().saturating_sub(1);
    for (seq, data) in chunks.into_iter().enumerate() {
        let _ = tx.send(Message::McpRelayBody {
            relay_id,
            seq: seq as u32,
            last: seq == last_index,
            data,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared::messages::SensitiveString;

    fn request(id: u64, auth: &str, body_len: u32) -> Message {
        Message::McpRelayRequest {
            relay_id: id,
            client_ip: "203.0.113.8".into(),
            authorization: SensitiveString::new(auth.into()),
            content_type: "application/json".into(),
            accept: "application/json".into(),
            mcp_session_id: None,
            mcp_protocol_version: Some("2025-03-26".into()),
            body_len,
        }
    }

    fn chunk(id: u64, seq: u32, last: bool, data: &[u8]) -> Message {
        Message::McpRelayBody {
            relay_id: id,
            seq,
            last,
            data: data.to_vec(),
        }
    }

    #[test]
    fn out_of_order_chunks_reassemble_per_relay() {
        let mut asm = RelayAssembler::default();
        assert!(asm.push(&request(1, "Bearer vbw_a", 5)).unwrap().is_none());
        assert!(asm.push(&request(2, "Bearer vbw_b", 3)).unwrap().is_none());
        assert!(asm.push(&chunk(1, 1, true, b"XY")).unwrap().is_none());
        assert!(asm.push(&chunk(2, 0, true, b"zzz")).unwrap().is_some());
        let done = asm.push(&chunk(1, 0, false, b"abc")).unwrap().unwrap();
        assert_eq!(done.relay_id, 1);
        assert_eq!(done.body, b"abcXY");
    }

    #[test]
    fn attack_relay_header_crlf_is_rejected() {
        let mut asm = RelayAssembler::default();
        let err = asm
            .push(&request(9, "Bearer vbw_a\r\nX-Injected: 1", 0))
            .unwrap_err();
        assert_eq!(err.1, AssembleError::Header);
    }

    #[test]
    fn oversize_body_is_rejected() {
        let mut asm = RelayAssembler::default();
        let huge = (crate::upstream_http::MAX_UPSTREAM_BODY_BYTES as u32).saturating_add(1);
        let err = asm.push(&request(3, "Bearer vbw_a", huge)).unwrap_err();
        assert_eq!(err.1, AssembleError::Oversize);
    }

    #[test]
    fn empty_body_completes_on_the_request() {
        let mut asm = RelayAssembler::default();
        let done = asm.push(&request(4, "Bearer vbw_a", 0)).unwrap().unwrap();
        assert!(done.body.is_empty());
    }

    #[test]
    fn shutdown_arm_returns_success_not_respawn() {
        let src = include_str!("data_pipe.rs");
        let prod = src.split("mod tests").next().unwrap_or(src);
        let shutdown_arm = prod
            .find("DataLoopPoll::Shutdown =>")
            .expect("shutdown arm");
        let respawn_arm = prod.find("DataLoopPoll::Respawn =>").expect("respawn arm");
        assert!(shutdown_arm < respawn_arm);
        let arm = &prod[shutdown_arm..respawn_arm];
        assert!(arm.contains("ExitCode::SUCCESS"));
        assert!(
            !arm.contains("EXIT_CODE_RESPAWN"),
            "a supervisor Shutdown must not ask the supervisor to respawn the leaf"
        );
    }

    proptest::proptest! {
        #[test]
        fn shutdown_dominates_a_terminal_recv(terminal in proptest::bool::ANY) {
            proptest::prop_assert_eq!(
                classify_data_poll(true, terminal),
                DataLoopPoll::Shutdown
            );
        }

        #[test]
        fn peer_close_respawns_only_without_shutdown(terminal in proptest::bool::ANY) {
            let poll = classify_data_poll(false, terminal);
            if terminal {
                proptest::prop_assert_eq!(poll, DataLoopPoll::Respawn);
            } else {
                proptest::prop_assert_eq!(poll, DataLoopPoll::Continue);
            }
        }
    }

    #[test]
    fn battle_classify_stable_under_threads() {
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let barrier = std::sync::Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                classify_data_poll(true, true) == DataLoopPoll::Shutdown
                    && classify_data_poll(false, true) == DataLoopPoll::Respawn
                    && classify_data_poll(false, false) == DataLoopPoll::Continue
            }));
        }
        for handle in handles {
            assert!(handle.join().expect("thread"));
        }
    }

    #[tokio::test]
    async fn shutdown_stops_data_ipc_loop_without_respawn() {
        let (leaf, peer) = shared::ipc::IpcChannel::pair().unwrap();
        let (tx, rx) = tokio::sync::broadcast::channel(1);
        let sender = tx.clone();
        tokio::spawn(async move {
            tokio::task::yield_now().await;
            let _ = sender.send(());
        });
        let started = std::time::Instant::now();
        let code = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            data_ipc_loop(
                leaf,
                axum::Router::new(),
                4,
                4,
                std::time::Duration::from_secs(1),
                rx,
            ),
        )
        .await
        .expect("data loop timed out");
        assert_eq!(code, ExitCode::SUCCESS);
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        drop(peer);
        drop(tx);
    }

    #[tokio::test]
    async fn peer_close_requests_respawn() {
        let (leaf, peer) = shared::ipc::IpcChannel::pair().unwrap();
        drop(peer);
        let (_tx, rx) = tokio::sync::broadcast::channel(1);
        let code = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            data_ipc_loop(
                leaf,
                axum::Router::new(),
                4,
                4,
                std::time::Duration::from_secs(1),
                rx,
            ),
        )
        .await
        .expect("data loop timed out");
        assert_eq!(code, ExitCode::from(EXIT_CODE_RESPAWN as u8));
    }

    #[tokio::test]
    async fn shutdown_wins_over_a_closed_data_pipe() {
        let (leaf, peer) = shared::ipc::IpcChannel::pair().unwrap();
        drop(peer);
        let (tx, rx) = tokio::sync::broadcast::channel(1);
        tx.send(()).unwrap();
        let code = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            data_ipc_loop(
                leaf,
                axum::Router::new(),
                4,
                4,
                std::time::Duration::from_secs(1),
                rx,
            ),
        )
        .await
        .expect("data loop timed out");
        assert_eq!(code, ExitCode::SUCCESS);
        drop(tx);
    }
}
