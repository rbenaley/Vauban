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

//! HTTP/1.1 JSON POST over an already-connected stream (brokered FD).
//! Works on plaintext TCP or TLS-wrapped streams (no free `connect`).

use anyhow::{Context, Result, bail};
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

/// Upstream I/O after open: plaintext HTTP (lab) or TLS+SPKI (prod).
pub enum UpstreamIo {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl std::fmt::Debug for UpstreamIo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpstreamIo::Plain(_) => f.write_str("UpstreamIo::Plain(..)"),
            UpstreamIo::Tls(_) => f.write_str("UpstreamIo::Tls(..)"),
        }
    }
}

impl AsyncRead for UpstreamIo {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            UpstreamIo::Plain(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            UpstreamIo::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for UpstreamIo {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        match self.get_mut() {
            UpstreamIo::Plain(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            UpstreamIo::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            UpstreamIo::Plain(s) => std::pin::Pin::new(s).poll_flush(cx),
            UpstreamIo::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            UpstreamIo::Plain(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            UpstreamIo::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

/// Hop-2 / upstream MCP body cap (matches web `MAX_BODY_BYTES`).
pub const MAX_UPSTREAM_BODY_BYTES: usize = 1_048_576;

/// POST `path` with JSON body; return (status, parsed JSON body).
pub async fn post_json<S>(
    stream: &mut S,
    host: &str,
    path: &str,
    bearer: Option<&str>,
    body: &Value,
) -> Result<(u16, Value)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let payload = serde_json::to_vec(body).context("serialize upstream body")?;
    let mut req = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nAccept: application/json\r\nContent-Length: {}\r\nConnection: keep-alive\r\n",
        payload.len()
    );
    if let Some(token) = bearer {
        req.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    req.push_str("\r\n");

    stream.write_all(req.as_bytes()).await?;
    stream.write_all(&payload).await?;
    stream.flush().await?;

    let mut buf = Vec::with_capacity(8192);
    let mut tmp = [0u8; 4096];
    let header_end;
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            bail!("upstream closed before HTTP headers");
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_header_end(&buf) {
            header_end = pos;
            break;
        }
        if buf.len() > 64 * 1024 {
            bail!("upstream HTTP headers too large");
        }
    }

    let header_bytes = &buf[..header_end];
    let header_str = std::str::from_utf8(header_bytes).context("HTTP headers not utf8")?;
    let status = parse_status_line(header_str)?;
    let content_length = parse_content_length(header_str).unwrap_or(0);
    if content_length > MAX_UPSTREAM_BODY_BYTES {
        bail!("upstream HTTP body exceeds max_body_bytes");
    }

    let mut body_buf = buf[header_end..].to_vec();
    if body_buf.len() > MAX_UPSTREAM_BODY_BYTES {
        bail!("upstream HTTP body exceeds max_body_bytes");
    }
    while body_buf.len() < content_length {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        body_buf.extend_from_slice(&tmp[..n]);
        if body_buf.len() > MAX_UPSTREAM_BODY_BYTES {
            bail!("upstream HTTP body exceeds max_body_bytes");
        }
    }
    if content_length > 0 {
        body_buf.truncate(content_length);
    }

    if body_buf.is_empty() {
        return Ok((status, Value::Null));
    }
    let value: Value = serde_json::from_slice(&body_buf).context("upstream JSON body")?;
    Ok((status, value))
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

fn parse_status_line(headers: &str) -> Result<u16> {
    let line = headers.lines().next().unwrap_or("");
    let code = line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .context("HTTP status line")?;
    Ok(code)
}

fn parse_content_length(headers: &str) -> Option<usize> {
    for line in headers.lines() {
        let lower = line.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("content-length:") {
            return rest.trim().parse().ok();
        }
    }
    None
}
