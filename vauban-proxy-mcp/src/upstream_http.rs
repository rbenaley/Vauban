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

//! MCP Streamable HTTP client over an already-connected TLS stream (brokered FD).
//! hyper HTTP/1.1: Content-Length, chunked and SSE responses, `Mcp-Session-Id`
//! carried across requests and re-brokered connections, one deadline per request.

use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::client::conn::http1;
use hyper::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HOST, HeaderName, HeaderValue};
use hyper::{Method, Request, Uri};
use hyper_util::rt::TokioIo;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;

/// Hop-2 / upstream MCP body cap (matches web `MAX_BODY_BYTES`).
pub const MAX_UPSTREAM_BODY_BYTES: usize = 1_048_576;
/// Deadline for `tools/call` (lock wait + request + response body).
pub const TOOLS_CALL_TIMEOUT: Duration = Duration::from_secs(60);
/// Deadline for every other method.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

const MCP_SESSION_ID: HeaderName = HeaderName::from_static("mcp-session-id");
const ACCEPT_MCP: HeaderValue = HeaderValue::from_static("application/json, text/event-stream");
const JSON: HeaderValue = HeaderValue::from_static("application/json");

/// Per-method upstream deadlines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeouts {
    pub tools_call: Duration,
    pub other: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            tools_call: TOOLS_CALL_TIMEOUT,
            other: DEFAULT_TIMEOUT,
        }
    }
}

impl Timeouts {
    pub fn for_method(&self, method: &str) -> Duration {
        if method == "tools/call" {
            self.tools_call
        } else {
            self.other
        }
    }
}

/// `Host` value for the upstream (IPv6 literals bracketed).
pub fn upstream_authority(host: &str, port: u16) -> String {
    let host = host.trim();
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UpstreamError {
    #[error("upstream timeout after {}s", .0.as_secs())]
    Timeout(Duration),
    #[error("upstream connection closed before the request was sent: {0}")]
    NotSent(String),
    #[error("upstream connection lost after the request was sent: {0}")]
    Lost(String),
    #[error("upstream HTTP {status} without a JSON-RPC body")]
    Http { status: u16 },
    #[error("upstream protocol error: {0}")]
    Protocol(String),
    #[error("{0}")]
    Unavailable(String),
}

impl UpstreamError {
    /// The request never reached the upstream: re-broker and resend is safe.
    pub fn retry_safe(&self) -> bool {
        matches!(self, Self::NotSent(_))
    }

    /// The connection is gone; only idempotent methods may be replayed.
    pub fn is_dead(&self) -> bool {
        matches!(self, Self::NotSent(_) | Self::Lost(_))
    }

    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::Timeout(_) => "upstream_timeout",
            Self::NotSent(_) | Self::Lost(_) | Self::Unavailable(_) => "upstream_unavailable",
            Self::Http { .. } => "upstream_http_error",
            Self::Protocol(_) => "upstream_protocol_error",
        }
    }
}

struct Connection {
    sender: http1::SendRequest<Full<Bytes>>,
    driver: JoinHandle<()>,
    poisoned: bool,
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

/// One brokered upstream connection plus the MCP session it carries.
pub struct Upstream {
    conn: AsyncMutex<Connection>,
    authority: HeaderValue,
    session_id: Mutex<Option<HeaderValue>>,
}

impl std::fmt::Debug for Upstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Upstream(..)")
    }
}

impl Upstream {
    /// HTTP/1.1 handshake on an already-connected stream (no `connect`).
    pub async fn handshake<IO>(io: IO, authority: &str) -> Result<Self, UpstreamError>
    where
        IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let authority = HeaderValue::from_str(authority)
            .map_err(|_| UpstreamError::Protocol("invalid upstream authority".into()))?;
        let (sender, conn) = http1::handshake(TokioIo::new(io))
            .await
            .map_err(|e| UpstreamError::NotSent(e.to_string()))?;
        let driver = tokio::spawn(async move {
            let _ = conn.await;
        });
        Ok(Self {
            conn: AsyncMutex::new(Connection {
                sender,
                driver,
                poisoned: false,
            }),
            authority,
            session_id: Mutex::new(None),
        })
    }

    /// Keep the upstream `Mcp-Session-Id` when a dead connection is replaced.
    pub fn with_session_id(self, session_id: Option<HeaderValue>) -> Self {
        *self
            .session_id
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = session_id;
        self
    }

    pub fn session_id(&self) -> Option<HeaderValue> {
        self.session_id
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// POST `/mcp`. `timeout` covers the wait for the connection and the full
    /// response; on expiry the connection is poisoned so the next call re-brokers.
    pub async fn post(
        &self,
        bearer: Option<&str>,
        body: &Value,
        timeout: Duration,
    ) -> Result<(u16, Value), UpstreamError> {
        let deadline = tokio::time::Instant::now() + timeout;
        let mut conn = tokio::time::timeout_at(deadline, self.conn.lock())
            .await
            .map_err(|_| UpstreamError::Timeout(timeout))?;
        if conn.poisoned {
            return Err(UpstreamError::NotSent(
                "connection poisoned by an earlier timeout".into(),
            ));
        }
        let req = self.request(bearer, body)?;
        match tokio::time::timeout_at(deadline, self.exchange(&mut conn, req, body.get("id"))).await
        {
            Ok(r) => r,
            Err(_) => {
                conn.poisoned = true;
                Err(UpstreamError::Timeout(timeout))
            }
        }
    }

    fn request(
        &self,
        bearer: Option<&str>,
        body: &Value,
    ) -> Result<Request<Full<Bytes>>, UpstreamError> {
        let mut req = Request::new(Full::new(Bytes::from(body.to_string())));
        *req.method_mut() = Method::POST;
        *req.uri_mut() = Uri::from_static("/mcp");
        let h = req.headers_mut();
        h.insert(HOST, self.authority.clone());
        h.insert(CONTENT_TYPE, JSON);
        h.insert(ACCEPT, ACCEPT_MCP);
        if let Some(sid) = self.session_id() {
            h.insert(MCP_SESSION_ID, sid);
        }
        if let Some(token) = bearer {
            let mut v = HeaderValue::from_str(&format!("Bearer {token}")).map_err(|_| {
                UpstreamError::Protocol("upstream bearer contains forbidden header bytes".into())
            })?;
            v.set_sensitive(true);
            h.insert(AUTHORIZATION, v);
        }
        Ok(req)
    }

    async fn exchange(
        &self,
        conn: &mut Connection,
        req: Request<Full<Bytes>>,
        id: Option<&Value>,
    ) -> Result<(u16, Value), UpstreamError> {
        conn.sender
            .ready()
            .await
            .map_err(|e| UpstreamError::NotSent(e.to_string()))?;
        let resp = match conn.sender.try_send_request(req).await {
            Ok(resp) => resp,
            Err(mut e) => {
                let kind: fn(String) -> UpstreamError = if e.take_message().is_some() {
                    UpstreamError::NotSent
                } else {
                    UpstreamError::Lost
                };
                return Err(kind(e.into_error().to_string()));
            }
        };
        let status = resp.status().as_u16();
        if let Some(sid) = resp.headers().get(MCP_SESSION_ID) {
            *self
                .session_id
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(sid.clone());
        }
        let is_sse = resp
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.trim_start().starts_with("text/event-stream"));
        let bytes = read_body(resp.into_body(), is_sse, id).await?;
        decode(status, is_sse, &bytes, id)
    }
}

/// Reads at most [`MAX_UPSTREAM_BODY_BYTES`]; an SSE stream stops at the
/// JSON-RPC response matching `id` (the server may keep the stream open).
async fn read_body(
    mut body: Incoming,
    is_sse: bool,
    id: Option<&Value>,
) -> Result<Vec<u8>, UpstreamError> {
    let mut buf = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|e| UpstreamError::Lost(e.to_string()))?;
        if let Ok(data) = frame.into_data() {
            if buf.len() + data.len() > MAX_UPSTREAM_BODY_BYTES {
                return Err(UpstreamError::Protocol(
                    "upstream HTTP body exceeds max_body_bytes".into(),
                ));
            }
            buf.extend_from_slice(&data);
            if is_sse && pick_response(sse_messages(&buf, true), id).is_some() {
                break;
            }
        }
    }
    Ok(buf)
}

fn decode(
    status: u16,
    is_sse: bool,
    bytes: &[u8],
    id: Option<&Value>,
) -> Result<(u16, Value), UpstreamError> {
    if is_sse {
        return pick_response(sse_messages(bytes, false), id)
            .map(|v| (status, v))
            .ok_or_else(|| {
                UpstreamError::Protocol("SSE stream ended without a JSON-RPC response".into())
            });
    }
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Ok((status, Value::Null));
    }
    match serde_json::from_slice(bytes) {
        Ok(v) => Ok((status, v)),
        Err(_) if !(200..300).contains(&status) => Err(UpstreamError::Http { status }),
        Err(e) => Err(UpstreamError::Protocol(format!("upstream JSON body: {e}"))),
    }
}

/// JSON payloads of the SSE events in `buf`. With `complete_only`, the
/// trailing event without its blank-line terminator is ignored.
fn sse_messages(buf: &[u8], complete_only: bool) -> Vec<Value> {
    let text = String::from_utf8_lossy(buf).replace("\r\n", "\n");
    let mut events: Vec<&str> = text.split("\n\n").collect();
    if complete_only {
        events.pop();
    }
    events
        .into_iter()
        .filter_map(|event| {
            let data: Vec<&str> = event
                .lines()
                .filter_map(|l| l.strip_prefix("data:"))
                .map(|d| d.strip_prefix(' ').unwrap_or(d))
                .collect();
            serde_json::from_str(&data.join("\n")).ok()
        })
        .collect()
}

fn pick_response(messages: Vec<Value>, id: Option<&Value>) -> Option<Value> {
    messages.into_iter().find(|m| match id {
        Some(id) => {
            m.get("id") == Some(id) && (m.get("result").is_some() || m.get("error").is_some())
        }
        None => true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// One-shot plaintext HTTP peer: reads one request, writes `raw`, then
    /// keeps the socket open for `linger`.
    async fn raw_peer(raw: Vec<u8>, linger: Duration) -> tokio::net::TcpStream {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 16 * 1024];
            let _ = s.read(&mut buf).await;
            let _ = s.write_all(&raw).await;
            tokio::time::sleep(linger).await;
        });
        tokio::net::TcpStream::connect(addr).await.unwrap()
    }

    async fn upstream(raw: &str) -> Upstream {
        let tcp = raw_peer(raw.as_bytes().to_vec(), Duration::from_millis(200)).await;
        Upstream::handshake(tcp, "127.0.0.1:1").await.unwrap()
    }

    fn rpc(id: u64) -> Value {
        json!({"jsonrpc": "2.0", "id": id, "method": "tools/list"})
    }

    #[test]
    fn timeouts_and_authority() {
        let t = Timeouts::default();
        assert_eq!(t.for_method("tools/call"), TOOLS_CALL_TIMEOUT);
        assert_eq!(t.for_method("tools/list"), DEFAULT_TIMEOUT);
        assert_eq!(upstream_authority(" mcp.lan ", 443), "mcp.lan:443");
        assert_eq!(upstream_authority("::1", 9), "[::1]:9");
        assert_eq!(upstream_authority("[::1]", 9), "[::1]:9");
    }

    #[test]
    fn error_classification() {
        let all = [
            UpstreamError::Timeout(Duration::from_secs(60)),
            UpstreamError::NotSent("x".into()),
            UpstreamError::Lost("x".into()),
            UpstreamError::Http { status: 502 },
            UpstreamError::Protocol("x".into()),
            UpstreamError::Unavailable("x".into()),
        ];
        let codes: Vec<_> = all.iter().map(UpstreamError::reason_code).collect();
        assert_eq!(
            codes,
            [
                "upstream_timeout",
                "upstream_unavailable",
                "upstream_unavailable",
                "upstream_http_error",
                "upstream_protocol_error",
                "upstream_unavailable"
            ]
        );
        let safe: Vec<_> = all.iter().map(UpstreamError::retry_safe).collect();
        assert_eq!(safe, [false, true, false, false, false, false]);
        let dead: Vec<_> = all.iter().map(UpstreamError::is_dead).collect();
        assert_eq!(dead, [false, true, true, false, false, false]);
        assert_eq!(all[0].to_string(), "upstream timeout after 60s");
    }

    #[tokio::test]
    async fn debug_hides_connection() {
        let up = upstream("HTTP/1.1 200 OK\r\n\r\n").await;
        assert_eq!(format!("{up:?}"), "Upstream(..)");
    }

    #[tokio::test]
    async fn content_length_json() {
        let body = r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#;
        let up = upstream(&format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        ))
        .await;
        let (status, v) = up
            .post(Some("tok"), &rpc(1), DEFAULT_TIMEOUT)
            .await
            .unwrap();
        assert_eq!(status, 200);
        assert_eq!(v["result"]["ok"], true);
    }

    #[tokio::test]
    async fn chunked_json() {
        let up = upstream(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n\
             10\r\n{\"jsonrpc\":\"2.0\"\r\n13\r\n,\"id\":1,\"result\":7}\r\n0\r\n\r\n",
        )
        .await;
        let (_, v) = up.post(None, &rpc(1), DEFAULT_TIMEOUT).await.unwrap();
        assert_eq!(v["result"], 7);
    }

    #[tokio::test]
    async fn sse_picks_matching_response_and_stops_on_open_stream() {
        let tcp = raw_peer(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n\
              event: message\r\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\r\n\r\n\
              data: {\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"x\":1}}\n\n"
                .to_vec(),
            Duration::from_secs(30),
        )
        .await;
        let up = Upstream::handshake(tcp, "h:1").await.unwrap();
        let (status, v) = up
            .post(None, &rpc(3), Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!((status, &v["result"]["x"]), (200, &json!(1)));
    }

    #[tokio::test]
    async fn chunked_trailers_are_skipped() {
        let up = upstream(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nTrailer: X-T\r\n\r\n\
             8\r\n{\"id\":1}\r\n0\r\nX-T: 1\r\n\r\n",
        )
        .await;
        let (_, v) = up.post(None, &rpc(1), DEFAULT_TIMEOUT).await.unwrap();
        assert_eq!(v["id"], 1);
    }

    #[test]
    fn sse_parsing_rules() {
        let stream = b"event: message\r\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"n\"}\r\n\r\n\
                       data: {\"jsonrpc\":\"2.0\",\ndata: \"id\":3,\"result\":1}\n\n\
                       data: not-json\n\ndata: {\"id\":4,\"result\":2}";
        let complete = sse_messages(stream, true);
        assert_eq!(complete.len(), 2);
        assert_eq!(complete[1]["result"], 1);
        assert_eq!(sse_messages(stream, false).len(), 3);
        let id3 = json!(3);
        assert_eq!(
            pick_response(complete.clone(), Some(&id3)).unwrap()["result"],
            1
        );
        assert!(pick_response(complete.clone(), Some(&json!(9))).is_none());
        assert_eq!(pick_response(complete, None).unwrap()["method"], "n");
        let error_reply = vec![json!({"id": 3, "error": {"code": 1}})];
        assert!(pick_response(error_reply, Some(&id3)).is_some());
        assert!(pick_response(vec![json!({"id": 3})], Some(&id3)).is_none());
    }

    #[test]
    fn decode_rules() {
        assert_eq!(
            decode(202, false, b" \n", None).unwrap(),
            (202, Value::Null)
        );
        assert_eq!(
            decode(401, false, b"denied", None).unwrap_err(),
            UpstreamError::Http { status: 401 }
        );
        assert!(matches!(
            decode(200, false, b"denied", None).unwrap_err(),
            UpstreamError::Protocol(m) if m.starts_with("upstream JSON body")
        ));
        assert_eq!(decode(400, false, b"{\"e\":1}", None).unwrap().0, 400);
        assert!(matches!(
            decode(200, true, b"data: nope\n\n", Some(&json!(1))).unwrap_err(),
            UpstreamError::Protocol(m) if m.contains("SSE")
        ));
        let (s, v) = decode(200, true, b"data: {\"id\":1,\"result\":0}", Some(&json!(1))).unwrap();
        assert_eq!((s, v["result"].as_i64()), (200, Some(0)));
    }

    #[tokio::test]
    async fn session_id_is_captured_sent_and_carried() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = std::sync::Arc::new(Mutex::new(Vec::<String>::new()));
        let seen_srv = seen.clone();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            for i in 0..2 {
                let mut buf = vec![0u8; 8192];
                let n = s.read(&mut buf).await.unwrap();
                seen_srv
                    .lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&buf[..n]).to_ascii_lowercase());
                let sid = if i == 0 {
                    "Mcp-Session-Id: abc\r\n"
                } else {
                    ""
                };
                let resp = format!("HTTP/1.1 202 Accepted\r\n{sid}Content-Length: 0\r\n\r\n");
                s.write_all(resp.as_bytes()).await.unwrap();
            }
        });
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let up = Upstream::handshake(tcp, "h:1").await.unwrap();
        assert!(up.session_id().is_none());
        up.post(Some("s3cret"), &rpc(1), DEFAULT_TIMEOUT)
            .await
            .unwrap();
        assert_eq!(up.session_id().unwrap(), "abc");
        up.post(None, &rpc(2), DEFAULT_TIMEOUT).await.unwrap();
        let seen = seen.lock().unwrap().clone();
        assert!(seen[0].contains("authorization: bearer s3cret"));
        assert!(seen[0].contains("accept: application/json, text/event-stream"));
        assert!(seen[0].contains("host: h:1"));
        assert!(!seen[0].contains("mcp-session-id"));
        assert!(seen[1].contains("mcp-session-id: abc"));

        let other = upstream("HTTP/1.1 200 OK\r\n\r\n").await;
        let carried = other.with_session_id(Some(HeaderValue::from_static("abc")));
        assert_eq!(carried.session_id().unwrap(), "abc");
    }

    #[tokio::test]
    async fn bearer_with_crlf_is_refused_before_any_io() {
        let up = upstream("HTTP/1.1 200 OK\r\n\r\n").await;
        let err = up
            .post(Some("x\r\nX-Evil: 1"), &rpc(1), DEFAULT_TIMEOUT)
            .await
            .unwrap_err();
        assert!(matches!(err, UpstreamError::Protocol(m) if m.contains("bearer")));
    }

    #[tokio::test]
    async fn invalid_authority_is_refused() {
        let tcp = raw_peer(Vec::new(), Duration::ZERO).await;
        let err = Upstream::handshake(tcp, "bad\nhost").await.unwrap_err();
        assert!(matches!(err, UpstreamError::Protocol(_)));
    }

    #[tokio::test]
    async fn oversized_body_is_refused() {
        let big = MAX_UPSTREAM_BODY_BYTES + 1;
        let mut raw = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {big}\r\n\r\n"
        )
        .into_bytes();
        raw.extend(std::iter::repeat_n(b' ', big));
        let tcp = raw_peer(raw, Duration::from_millis(500)).await;
        let up = Upstream::handshake(tcp, "h:1").await.unwrap();
        let err = up.post(None, &rpc(1), DEFAULT_TIMEOUT).await.unwrap_err();
        assert!(matches!(err, UpstreamError::Protocol(m) if m.contains("max_body_bytes")));
    }

    #[tokio::test]
    async fn timeout_poisons_connection() {
        let tcp = raw_peer(Vec::new(), Duration::from_secs(30)).await;
        let up = Upstream::handshake(tcp, "h:1").await.unwrap();
        let t = Duration::from_millis(100);
        assert_eq!(
            up.post(None, &rpc(1), t).await.unwrap_err(),
            UpstreamError::Timeout(t)
        );
        let err = up.post(None, &rpc(2), t).await.unwrap_err();
        assert!(err.retry_safe(), "{err}");
    }

    #[tokio::test]
    async fn lock_wait_counts_against_deadline() {
        let tcp = raw_peer(Vec::new(), Duration::from_secs(30)).await;
        let up = std::sync::Arc::new(Upstream::handshake(tcp, "h:1").await.unwrap());
        let busy = up.clone();
        let holder =
            tokio::spawn(async move { busy.post(None, &rpc(1), Duration::from_secs(2)).await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        let t = Duration::from_millis(100);
        assert_eq!(
            up.post(None, &rpc(2), t).await.unwrap_err(),
            UpstreamError::Timeout(t)
        );
        holder.abort();
    }

    #[tokio::test]
    async fn closed_peer_is_not_sent_or_lost() {
        let tcp = raw_peer(Vec::new(), Duration::ZERO).await;
        let up = Upstream::handshake(tcp, "h:1").await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let err = up.post(None, &rpc(1), DEFAULT_TIMEOUT).await.unwrap_err();
        assert!(err.is_dead(), "{err}");
        let again = up.post(None, &rpc(2), DEFAULT_TIMEOUT).await.unwrap_err();
        assert!(again.retry_safe(), "{again}");
    }

    #[tokio::test]
    async fn truncated_body_is_lost() {
        let up = upstream(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 50\r\n\r\n{\"id\":1",
        )
        .await;
        let err = up.post(None, &rpc(1), DEFAULT_TIMEOUT).await.unwrap_err();
        assert!(matches!(err, UpstreamError::Lost(_)), "{err}");
    }
}
