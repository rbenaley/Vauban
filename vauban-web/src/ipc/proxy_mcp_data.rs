//! Hop-2 data pipe (web -> proxy-mcp).
//!
//! Distinct from the control pipe. One writer task, correlated by
//! `relay_id`. Bodies are chunked under `MCP_PIPE_CHUNK_BYTES`.

use crate::error::{AppError, AppResult};
use shared::correlated_ipc::CorrelatedIpcCore;
use shared::messages::{MCP_PIPE_CHUNK_BYTES, Message, SensitiveString};
use std::collections::HashMap;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

const RELAY_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug)]
pub struct RelayRequest {
    pub client_ip: String,
    pub authorization: String,
    pub content_type: String,
    pub accept: String,
    pub mcp_session_id: Option<String>,
    pub mcp_protocol_version: Option<String>,
    pub body: Vec<u8>,
}

#[derive(Debug)]
pub struct RelayedHttp {
    pub status: u16,
    pub content_type: String,
    pub mcp_session_id: Option<String>,
    pub body: Vec<u8>,
}

struct Inflight {
    status: Option<u16>,
    content_type: String,
    mcp_session_id: Option<String>,
    body_len: u32,
    chunks: HashMap<u32, Vec<u8>>,
    waiter: Option<oneshot::Sender<AppResult<RelayedHttp>>>,
}

pub struct ProxyMcpDataClient {
    core: CorrelatedIpcCore,
    next_id: AtomicU64,
    inflight: StdMutex<HashMap<u64, Inflight>>,
    tunnels: StdMutex<HashMap<u64, mpsc::UnboundedSender<Vec<u8>>>>,
    writer_tx: mpsc::UnboundedSender<Message>,
}

impl ProxyMcpDataClient {
    pub fn new(read_fd: RawFd, write_fd: RawFd) -> std::io::Result<Arc<Self>> {
        let core = CorrelatedIpcCore::from_fds(read_fd, write_fd)?;
        let writer = core.channel_arc();
        let (writer_tx, mut writer_rx) = mpsc::unbounded_channel::<Message>();
        tokio::spawn(async move {
            while let Some(msg) = writer_rx.recv().await {
                if writer.send(&msg).is_err() {
                    break;
                }
            }
        });
        Ok(Arc::new(Self {
            core,
            next_id: AtomicU64::new(1),
            inflight: StdMutex::new(HashMap::new()),
            tunnels: StdMutex::new(HashMap::new()),
            writer_tx,
        }))
    }

    pub async fn relay(&self, request: RelayRequest) -> AppResult<RelayedHttp> {
        let relay_id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = oneshot::channel();
        {
            let mut map = self.inflight.lock().unwrap_or_else(|p| p.into_inner());
            map.insert(
                relay_id,
                Inflight {
                    status: None,
                    content_type: String::new(),
                    mcp_session_id: None,
                    body_len: request.body.len() as u32,
                    chunks: HashMap::new(),
                    waiter: Some(tx),
                },
            );
        }
        self.writer_tx
            .send(Message::McpRelayRequest {
                relay_id,
                client_ip: request.client_ip.clone(),
                authorization: SensitiveString::new(request.authorization.clone()),
                content_type: request.content_type.clone(),
                accept: request.accept.clone(),
                mcp_session_id: request.mcp_session_id.clone(),
                mcp_protocol_version: request.mcp_protocol_version.clone(),
                body_len: request.body.len() as u32,
            })
            .map_err(|_| AppError::Internal(anyhow::anyhow!("mcp data pipe closed")))?;
        let pieces: Vec<&[u8]> = request.body.chunks(MCP_PIPE_CHUNK_BYTES).collect();
        for (seq, chunk) in pieces.iter().enumerate() {
            self.writer_tx
                .send(Message::McpRelayBody {
                    relay_id,
                    seq: seq as u32,
                    last: seq + 1 == pieces.len(),
                    data: chunk.to_vec(),
                })
                .map_err(|_| AppError::Internal(anyhow::anyhow!("mcp data pipe closed")))?;
        }
        match tokio::time::timeout(RELAY_TIMEOUT, rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(AppError::Internal(anyhow::anyhow!(
                "mcp relay waiter dropped"
            ))),
            Err(_) => {
                if let Ok(mut map) = self.inflight.lock() {
                    map.remove(&relay_id);
                }
                Err(AppError::Internal(anyhow::anyhow!("mcp relay timed out")))
            }
        }
    }

    pub fn tunnel_count(&self) -> usize {
        self.tunnels
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    pub fn open_tunnel(
        &self,
        client_ip: String,
    ) -> AppResult<(u64, mpsc::UnboundedReceiver<Vec<u8>>)> {
        let tunnel_id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = mpsc::unbounded_channel();
        self.tunnels
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(tunnel_id, tx);
        self.writer_tx
            .send(Message::McpTunnelOpen {
                tunnel_id,
                client_ip,
            })
            .map_err(|_| AppError::Internal(anyhow::anyhow!("mcp data pipe closed")))?;
        Ok((tunnel_id, rx))
    }

    pub fn send_tunnel(&self, tunnel_id: u64, data: Vec<u8>) -> AppResult<()> {
        self.writer_tx
            .send(Message::McpTunnelData { tunnel_id, data })
            .map_err(|_| AppError::Internal(anyhow::anyhow!("mcp data pipe closed")))
    }

    pub fn close_tunnel(&self, tunnel_id: u64, reason: &str) {
        if let Ok(mut map) = self.tunnels.lock() {
            map.remove(&tunnel_id);
        }
        let _ = self.writer_tx.send(Message::McpTunnelClose {
            tunnel_id,
            reason: reason.to_string(),
        });
    }

    pub async fn process_incoming(&self) -> AppResult<()> {
        self.core
            .process_loop(|msg| async {
                self.on_message(msg);
            })
            .await
            .map_err(|e| AppError::Internal(anyhow::anyhow!("mcp data pump: {e}")))
    }

    fn on_message(&self, msg: Message) {
        match msg {
            Message::McpRelayResponse {
                relay_id,
                status,
                content_type,
                mcp_session_id,
                body_len,
            } => {
                let mut map = self.inflight.lock().unwrap_or_else(|p| p.into_inner());
                if let Some(slot) = map.get_mut(&relay_id) {
                    slot.status = Some(status);
                    slot.content_type = content_type;
                    slot.mcp_session_id = mcp_session_id;
                    slot.body_len = body_len;
                    if body_len == 0 {
                        Self::finish(&mut map, relay_id);
                    }
                }
            }
            Message::McpRelayBody {
                relay_id,
                seq,
                data,
                ..
            } => {
                let mut map = self.inflight.lock().unwrap_or_else(|p| p.into_inner());
                if let Some(slot) = map.get_mut(&relay_id) {
                    slot.chunks.insert(seq, data);
                    let total: usize = slot.chunks.values().map(Vec::len).sum();
                    if slot.status.is_some() && total == slot.body_len as usize {
                        Self::finish(&mut map, relay_id);
                    }
                }
            }
            Message::McpTunnelData { tunnel_id, data } => {
                if let Ok(map) = self.tunnels.lock()
                    && let Some(tx) = map.get(&tunnel_id)
                {
                    let _ = tx.send(data);
                }
            }
            Message::McpTunnelClose { tunnel_id, .. } => {
                if let Ok(mut map) = self.tunnels.lock() {
                    map.remove(&tunnel_id);
                }
            }
            Message::McpRelayAbort { relay_id, reason } => {
                let mut map = self.inflight.lock().unwrap_or_else(|p| p.into_inner());
                if let Some(mut slot) = map.remove(&relay_id)
                    && let Some(waiter) = slot.waiter.take()
                {
                    let _ = waiter.send(Err(AppError::Internal(anyhow::anyhow!(
                        "mcp relay aborted: {reason}"
                    ))));
                }
            }
            _ => {}
        }
    }

    fn finish(map: &mut HashMap<u64, Inflight>, relay_id: u64) {
        let Some(mut slot) = map.remove(&relay_id) else {
            return;
        };
        let Some(waiter) = slot.waiter.take() else {
            return;
        };
        let mut body = Vec::new();
        let mut seq = 0u32;
        while let Some(chunk) = slot.chunks.remove(&seq) {
            body.extend(chunk);
            seq += 1;
        }
        let _ = waiter.send(Ok(RelayedHttp {
            status: slot.status.unwrap_or(502),
            content_type: slot.content_type,
            mcp_session_id: slot.mcp_session_id,
            body,
        }));
    }
}
