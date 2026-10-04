//! Inner TLS terminated in the leaf.
//!
//! `vauban-web` relays ciphertext bytes. The leaf holds the only copy of
//! the internal identity (provisioned by the supervisor) and speaks HTTP
//! to the same `/mcp` router used by the direct relay.

use crate::data_pipe::McpIngress;
use base64::Engine;
use std::io::{self, ErrorKind};
use std::pin::Pin;
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::server::ServerConfig;
use tokio_rustls::rustls::version::TLS13;
use tower::ServiceExt;

/// Queue depth of client bytes per tunnel. A full queue closes the tunnel.
pub const TUNNEL_INBOUND_QUEUE: usize = 32;

pub const TUNNEL_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

pub const DEFAULT_TUNNEL_IDLE: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, Copy)]
pub struct TunnelTimeouts {
    pub handshake: Duration,
    pub idle: Duration,
}

impl Default for TunnelTimeouts {
    fn default() -> Self {
        Self {
            handshake: TUNNEL_HANDSHAKE_TIMEOUT,
            idle: DEFAULT_TUNNEL_IDLE,
        }
    }
}

/// Last time a byte crossed the tunnel, in either direction.
#[derive(Clone)]
pub struct Activity(Arc<StdMutex<Instant>>);

impl Activity {
    fn new() -> Self {
        Self(Arc::new(StdMutex::new(Instant::now())))
    }

    fn touch(&self) {
        *self.0.lock().unwrap_or_else(|p| p.into_inner()) = Instant::now();
    }

    fn last(&self) -> Instant {
        *self.0.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Resolves once no byte has moved for `idle`.
    pub async fn idle_for(&self, idle: Duration) {
        loop {
            let deadline = self.last() + idle;
            if Instant::now() >= deadline {
                return;
            }
            tokio::time::sleep_until(deadline).await;
        }
    }
}

/// Bytes the web process forwards for one tunnel, in both directions.
pub struct PipeStream {
    rx: mpsc::Receiver<Vec<u8>>,
    tx: mpsc::UnboundedSender<Vec<u8>>,
    buf: Vec<u8>,
    pos: usize,
    activity: Activity,
}

impl PipeStream {
    pub fn pair() -> (Self, TunnelEnds) {
        let (in_tx, in_rx) = mpsc::channel(TUNNEL_INBOUND_QUEUE);
        let (out_tx, out_rx) = mpsc::unbounded_channel();
        (
            Self {
                rx: in_rx,
                tx: out_tx,
                buf: Vec::new(),
                pos: 0,
                activity: Activity::new(),
            },
            TunnelEnds {
                inbound: in_tx,
                outbound: out_rx,
            },
        )
    }

    pub fn activity(&self) -> Activity {
        self.activity.clone()
    }
}

/// The data-pipe side of a [`PipeStream`].
pub struct TunnelEnds {
    pub inbound: mpsc::Sender<Vec<u8>>,
    pub outbound: mpsc::UnboundedReceiver<Vec<u8>>,
}

impl AsyncRead for PipeStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.pos < this.buf.len() {
            let n = (this.buf.len() - this.pos).min(buf.remaining());
            buf.put_slice(&this.buf[this.pos..this.pos + n]);
            this.pos += n;
            if this.pos == this.buf.len() {
                this.buf.clear();
                this.pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        match Pin::new(&mut this.rx).poll_recv(cx) {
            Poll::Ready(Some(bytes)) => {
                this.activity.touch();
                this.buf = bytes;
                this.pos = 0;
                Pin::new(this).poll_read(cx, buf)
            }
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for PipeStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.activity.touch();
        match self.tx.send(buf.to_vec()) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(_) => Poll::Ready(Err(io::Error::new(ErrorKind::BrokenPipe, "tunnel closed"))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

static IDENTITY: OnceLock<Arc<ServerConfig>> = OnceLock::new();

/// Remember the supervisor-provisioned identity. The first one wins.
pub fn install_identity(cert_der: Vec<u8>, key_pem: &str) -> Result<(), String> {
    let config = server_config(cert_der, key_pem)?;
    let _ = IDENTITY.set(config);
    Ok(())
}

pub fn identity() -> Option<Arc<ServerConfig>> {
    IDENTITY.get().cloned()
}

/// TLS 1.3 only. `cert_der` is the leaf certificate; `key_pem` is PKCS#8.
pub fn server_config(cert_der: Vec<u8>, key_pem: &str) -> Result<Arc<ServerConfig>, String> {
    let key_der = pem_body(key_pem)?;
    let key = PrivateKeyDer::try_from(key_der).map_err(|e| format!("identity key: {e}"))?;
    let cert = CertificateDer::from(cert_der);
    ServerConfig::builder_with_protocol_versions(&[&TLS13])
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .map(Arc::new)
        .map_err(|e| format!("tunnel server config: {e}"))
}

fn pem_body(pem: &str) -> Result<Vec<u8>, String> {
    let b64: String = pem
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("-----"))
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| format!("identity pem: {e}"))
}

/// Accept one inner TLS connection and serve the MCP router on it.
/// Returns why the tunnel ended; the caller reports it to web.
pub async fn serve_tunnel(
    config: Arc<ServerConfig>,
    stream: PipeStream,
    router: axum::Router,
    ingress: McpIngress,
    timeouts: TunnelTimeouts,
) -> &'static str {
    let activity = stream.activity();
    let acceptor = TlsAcceptor::from(config);
    let tls = match tokio::time::timeout(timeouts.handshake, acceptor.accept(stream)).await {
        Ok(Ok(tls)) => tls,
        Ok(Err(_)) => return "handshake_failed",
        Err(_) => return "handshake_timeout",
    };
    let io = hyper_util::rt::TokioIo::new(tls);
    let service = TunnelService { router, ingress };
    let connection = hyper::server::conn::http1::Builder::new().serve_connection(io, service);
    tokio::select! {
        _ = connection => "done",
        () = activity.idle_for(timeouts.idle) => "idle",
    }
}

struct TunnelService {
    router: axum::Router,
    ingress: McpIngress,
}

impl hyper::service::Service<hyper::Request<hyper::body::Incoming>> for TunnelService {
    type Response = axum::response::Response;
    type Error = std::convert::Infallible;
    type Future =
        Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, mut req: hyper::Request<hyper::body::Incoming>) -> Self::Future {
        req.extensions_mut().insert(self.ingress.clone());
        let router = self.router.clone();
        Box::pin(async move {
            let req = req.map(axum::body::Body::new);
            Ok(match router.oneshot(req).await {
                Ok(resp) => resp,
                Err(infallible) => match infallible {},
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;
    use tokio::io::duplex;
    use tokio_rustls::TlsConnector;

    fn test_identity() -> (Vec<u8>, String, String) {
        let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
        let key = rcgen::KeyPair::generate().expect("key");
        let cert = rcgen::CertificateParams::new(vec!["vauban-proxy-mcp.internal".into()])
            .expect("params")
            .self_signed(&key)
            .expect("cert");
        let der = cert.der().to_vec();
        let pin = crate::tls_pin::spki_sha256_fingerprint(&cert.der().clone()).expect("pin");
        (der, key.serialize_pem(), pin)
    }

    #[tokio::test]
    async fn attack_tunnel_spki_mismatch_is_rejected() {
        let (der, key_pem, pin) = test_identity();
        let server = server_config(der, &key_pem).expect("server");
        let (client_io, server_io) = duplex(4096);
        let acceptor = TlsAcceptor::from(server);
        let server_task = tokio::spawn(async move { acceptor.accept(server_io).await });
        let bad =
            crate::tls_pin::build_tls_config("SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=")
                .expect("cfg");
        let connect = TlsConnector::from(bad)
            .connect(
                "vauban-proxy-mcp.internal".try_into().expect("name"),
                client_io,
            )
            .await;
        assert!(
            connect.is_err(),
            "a mismatched SPKI pin must refuse the handshake"
        );
        let _ = server_task.await;
        assert!(pin.starts_with("SHA256:"));
    }

    #[test]
    fn pipe_stream_round_trips_bytes() {
        let (stream, ends) = PipeStream::pair();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("rt");
        rt.block_on(async move {
            ends.inbound.send(b"abc".to_vec()).await.expect("send");
            drop(ends.inbound);
            let mut got = Vec::new();
            let mut stream = stream;
            tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut got)
                .await
                .expect("read");
            assert_eq!(got, b"abc");
        });
    }

    #[test]
    fn battle_sixteen_pipe_streams() {
        let barrier = Arc::new(Barrier::new(16));
        let mut joins = Vec::new();
        for i in 0..16 {
            let barrier = Arc::clone(&barrier);
            joins.push(std::thread::spawn(move || {
                barrier.wait();
                let (stream, ends) = PipeStream::pair();
                let payload = vec![i as u8; 64];
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("rt");
                rt.block_on(async move {
                    ends.inbound.send(payload.clone()).await.expect("send");
                    drop(ends.inbound);
                    let mut got = Vec::new();
                    let mut stream = stream;
                    tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut got)
                        .await
                        .expect("read");
                    assert_eq!(got, payload);
                });
            }));
        }
        for join in joins {
            join.join().expect("thread");
        }
    }
}
