//! One visit: hop 1, then either direct HTTPS posts or one inner tunnel.

use crate::hop::{self, Hop1};
use crate::inner::{mcp_post, mcp_post_pinned};
use crate::tofu::{self, TofuDecision};
use futures_util::{Sink, Stream};
use secrecy::ExposeSecret;
use std::path::PathBuf;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

pub fn known_hosts_path() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("vauban").join("known_mcp_hosts")
}

pub fn accept_pin(host: &str, advertised: &str, path: &PathBuf) -> Result<String, String> {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let mut store = tofu::parse_store(&text);
    match tofu::observe(&mut store, host, advertised) {
        TofuDecision::Mismatch => Err(format!(
            "MCP tunnel pin for {host} changed; refusing. Stored pin stays in {}",
            path.display()
        )),
        TofuDecision::Learned => {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            std::fs::write(path, tofu::render_store(&store)).map_err(|e| e.to_string())?;
            tracing::info!(host, pin = %advertised, "learned MCP tunnel pin");
            Ok(advertised.to_string())
        }
        TofuDecision::Match => Ok(advertised.to_string()),
    }
}

fn host_of(url: &str) -> Result<String, String> {
    let rest = url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_start_matches("wss://")
        .trim_start_matches("ws://");
    let host = rest.split(['/', ':']).next().filter(|s| !s.is_empty());
    host.map(str::to_string)
        .ok_or_else(|| format!("no host in {url}"))
}

struct WsIo {
    inner: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    buf: Vec<u8>,
    pos: usize,
}

impl AsyncRead for WsIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.pos < this.buf.len() {
            let n = (this.buf.len() - this.pos).min(buf.remaining());
            buf.put_slice(&this.buf[this.pos..this.pos + n]);
            this.pos += n;
            return Poll::Ready(Ok(()));
        }
        match Pin::new(&mut this.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(Message::Binary(bytes)))) => {
                this.buf = bytes.to_vec();
                this.pos = 0;
                Pin::new(this).poll_read(cx, buf)
            }
            Poll::Ready(Some(Ok(_))) => Poll::Pending,
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(std::io::Error::other(e.to_string()))),
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for WsIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_ready(cx) {
            Poll::Ready(Ok(())) => {
                let n = buf.len();
                match Pin::new(&mut this.inner).start_send(Message::Binary(buf.to_vec().into())) {
                    Ok(()) => Poll::Ready(Ok(n)),
                    Err(e) => Poll::Ready(Err(std::io::Error::other(e.to_string()))),
                }
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(e.to_string()))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_flush(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(e.to_string()))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_close(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(e.to_string()))),
            Poll::Pending => Poll::Pending,
        }
    }
}

pub async fn post_direct(
    client: &reqwest::Client,
    hop: &Hop1,
    body: &str,
) -> Result<String, String> {
    let response = client
        .post(&hop.url)
        .header(
            "authorization",
            format!("Bearer {}", hop.bearer.expose_secret()),
        )
        .header("content-type", "application/json")
        .body(body.to_string())
        .send()
        .await
        .map_err(|e| format!("direct hop 2: {e}"))?;
    response
        .text()
        .await
        .map_err(|e| format!("direct body: {e}"))
}

pub async fn post_tunnel(hop: &Hop1, body: &str, hosts: &PathBuf) -> Result<String, String> {
    let pin = hop
        .tunnel_spki
        .as_deref()
        .ok_or("hop 1 did not return tunnel_spki")?;
    let host = host_of(&hop.url)?;
    let pin = accept_pin(&host, pin, hosts)?;
    let ws_url = hop::tunnel_ws_url(&hop.url);
    let (ws, _) = connect_async(&ws_url)
        .await
        .map_err(|e| format!("tunnel websocket: {e}"))?;
    let io = WsIo {
        inner: ws,
        buf: Vec::new(),
        pos: 0,
    };
    mcp_post_pinned(io, &host, &pin, hop.bearer.expose_secret(), body.as_bytes()).await
}

/// Used by tests that already hold a byte stream (no WebSocket).
pub async fn post_on_stream<S>(stream: S, bearer: &str, body: &str) -> Result<String, String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    mcp_post(stream, bearer, body.as_bytes()).await
}
