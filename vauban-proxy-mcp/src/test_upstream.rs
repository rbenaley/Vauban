#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]

//! Scriptable MCP upstream over TLS for proxy e2e tests.
//!
//! Self-signed `localhost` certificate (rcgen); the SPKI pin is exposed so
//! the proxy dials it through `tls_pin::connect_pinned` exactly like a
//! production upstream. One HTTP/1.1 keep-alive connection per client;
//! every request body and header set is recorded for assertions.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::{ServerConfig, crypto::aws_lc_rs};

/// How the upstream frames a JSON-RPC response body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Framing {
    ContentLength,
    Chunked,
    Sse,
}

/// Scenario knobs, mutable while the server runs.
#[derive(Clone, Debug)]
pub struct Mode {
    pub framing: Framing,
    /// When set, `initialize` returns this `Mcp-Session-Id` and every later
    /// request without it gets HTTP 400.
    pub session_id: Option<String>,
    /// Sleep before answering `tools/call`.
    pub call_delay: Option<Duration>,
    /// Read a `tools/call` request, count it, then close without answering.
    pub drop_after_call: bool,
    /// Close without answering `initialize`.
    pub drop_on_initialize: bool,
    /// `initialize.result.instructions`.
    pub instructions: Option<String>,
    /// Per-tool description overrides (rug-pull scenario).
    pub descriptions: HashMap<String, String>,
}

impl Default for Mode {
    fn default() -> Self {
        Self {
            framing: Framing::ContentLength,
            session_id: None,
            call_delay: None,
            drop_after_call: false,
            drop_on_initialize: false,
            instructions: Some("Fake upstream for Vauban tests.".into()),
            descriptions: HashMap::new(),
        }
    }
}

/// One recorded request.
#[derive(Clone, Debug)]
pub struct Received {
    pub headers: HashMap<String, String>,
    pub body: Value,
}

#[derive(Default)]
struct Shared {
    mode: Mode,
    received: Vec<Received>,
    tool_calls: u32,
}

/// Running fake upstream.
pub struct FakeUpstream {
    pub addr: SocketAddr,
    pub spki_pin: String,
    shared: Arc<Mutex<Shared>>,
}

pub const DEFAULT_TOOLS: &[(&str, &str)] = &[
    ("echo", "Echo the arguments back."),
    ("delete_task", "Delete one task by id."),
];

pub fn default_description(name: &str) -> &'static str {
    DEFAULT_TOOLS
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, d)| *d)
        .unwrap_or("")
}

pub fn tool_input_schema() -> Value {
    json!({"type": "object"})
}

fn server_config() -> (Arc<ServerConfig>, CertificateDer<'static>) {
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
    let cfg = ServerConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .unwrap();
    (Arc::new(cfg), cert_der)
}

impl FakeUpstream {
    pub async fn start(mode: Mode) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (cfg, cert_der) = server_config();
        let spki_pin = crate::tls_pin::spki_sha256_fingerprint(&cert_der).unwrap();
        let shared = Arc::new(Mutex::new(Shared {
            mode,
            ..Shared::default()
        }));
        let acceptor = TlsAcceptor::from(cfg);
        let srv_shared = Arc::clone(&shared);
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                let shared = Arc::clone(&srv_shared);
                tokio::spawn(async move {
                    if let Ok(tls) = acceptor.accept(tcp).await {
                        serve_connection(tls, shared).await;
                    }
                });
            }
        });
        Self {
            addr,
            spki_pin,
            shared,
        }
    }

    /// Raw TCP connection to the upstream (what the supervisor brokers).
    pub async fn tcp(&self) -> TcpStream {
        TcpStream::connect(self.addr).await.unwrap()
    }

    pub fn set_mode(&self, f: impl FnOnce(&mut Mode)) {
        f(&mut self.shared.lock().unwrap().mode);
    }

    pub fn received(&self) -> Vec<Received> {
        self.shared.lock().unwrap().received.clone()
    }

    pub fn tool_calls(&self) -> u32 {
        self.shared.lock().unwrap().tool_calls
    }
}

async fn read_request<S: AsyncRead + Unpin>(
    s: &mut S,
    buf: &mut Vec<u8>,
) -> Option<(HashMap<String, String>, Vec<u8>)> {
    let mut tmp = [0u8; 4096];
    let header_end = loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        let n = s.read(&mut tmp).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut headers = HashMap::new();
    for line in head.lines().skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    let len: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    while buf.len() < header_end + len {
        let n = s.read(&mut tmp).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    let body = buf[header_end..header_end + len].to_vec();
    buf.drain(..header_end + len);
    Some((headers, body))
}

async fn write_response<S: AsyncWrite + Unpin>(
    s: &mut S,
    status: u16,
    framing: Framing,
    extra_headers: &[(String, String)],
    body: Option<&Value>,
) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        _ => "Status",
    };
    let mut head = format!("HTTP/1.1 {status} {reason}\r\n");
    for (k, v) in extra_headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    let Some(body) = body else {
        head.push_str("Content-Length: 0\r\n\r\n");
        s.write_all(head.as_bytes()).await?;
        return s.flush().await;
    };
    let json = serde_json::to_vec(body).unwrap();
    match framing {
        Framing::ContentLength => {
            head.push_str("Content-Type: application/json\r\n");
            head.push_str(&format!("Content-Length: {}\r\n\r\n", json.len()));
            s.write_all(head.as_bytes()).await?;
            s.write_all(&json).await?;
        }
        Framing::Chunked => {
            head.push_str("Content-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n");
            s.write_all(head.as_bytes()).await?;
            let mid = json.len() / 2;
            for part in [&json[..mid], &json[mid..]] {
                s.write_all(format!("{:x}\r\n", part.len()).as_bytes())
                    .await?;
                s.write_all(part).await?;
                s.write_all(b"\r\n").await?;
            }
            s.write_all(b"0\r\n\r\n").await?;
        }
        Framing::Sse => {
            let event = format!(
                "event: message\r\ndata: {{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{{}}}}\r\n\r\n\
                 event: message\r\ndata: {}\r\n\r\n",
                String::from_utf8_lossy(&json)
            );
            head.push_str("Content-Type: text/event-stream\r\n");
            head.push_str(&format!("Content-Length: {}\r\n\r\n", event.len()));
            s.write_all(head.as_bytes()).await?;
            s.write_all(event.as_bytes()).await?;
        }
    }
    s.flush().await
}

fn tools_list(mode: &Mode) -> Value {
    let tools: Vec<Value> = DEFAULT_TOOLS
        .iter()
        .map(|(name, desc)| {
            let d = mode
                .descriptions
                .get(*name)
                .cloned()
                .unwrap_or_else(|| (*desc).to_string());
            json!({"name": name, "description": d, "inputSchema": tool_input_schema()})
        })
        .collect();
    json!({ "tools": tools })
}

async fn serve_connection<S: AsyncRead + AsyncWrite + Unpin>(mut s: S, shared: Arc<Mutex<Shared>>) {
    let mut buf = Vec::new();
    while let Some((headers, raw)) = read_request(&mut s, &mut buf).await {
        let body: Value = serde_json::from_slice(&raw).unwrap_or(Value::Null);
        let method = body
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let id = body.get("id").cloned().unwrap_or(Value::Null);
        let mode = {
            let mut g = shared.lock().unwrap();
            g.received.push(Received {
                headers: headers.clone(),
                body: body.clone(),
            });
            if method == "tools/call" {
                g.tool_calls += 1;
            }
            g.mode.clone()
        };

        let accepts_sse = headers
            .get("accept")
            .is_some_and(|a| a.contains("text/event-stream") && a.contains("application/json"));
        if mode.framing == Framing::Sse && !accepts_sse {
            if write_response(&mut s, 406, Framing::ContentLength, &[], None)
                .await
                .is_err()
            {
                return;
            }
            continue;
        }

        let mut extra = Vec::new();
        if let Some(sid) = &mode.session_id {
            if method == "initialize" {
                extra.push(("Mcp-Session-Id".to_string(), sid.clone()));
            } else if headers.get("mcp-session-id") != Some(sid) {
                let err = json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32600, "message": "missing session"}});
                if write_response(&mut s, 400, Framing::ContentLength, &[], Some(&err))
                    .await
                    .is_err()
                {
                    return;
                }
                continue;
            }
        }

        if method.starts_with("notifications/") {
            if write_response(&mut s, 202, Framing::ContentLength, &extra, None)
                .await
                .is_err()
            {
                return;
            }
            continue;
        }

        let result = match method.as_str() {
            "initialize" => {
                if mode.drop_on_initialize {
                    return;
                }
                let mut r = json!({
                    "protocolVersion": "2025-03-26",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "fake-upstream", "version": "1"},
                });
                if let Some(i) = &mode.instructions {
                    r["instructions"] = json!(i);
                }
                r
            }
            "tools/list" => tools_list(&mode),
            "tools/call" => {
                if mode.drop_after_call {
                    return;
                }
                if let Some(d) = mode.call_delay {
                    tokio::time::sleep(d).await;
                }
                let args = body
                    .pointer("/params/arguments")
                    .cloned()
                    .unwrap_or(json!({}));
                json!({"content": [{"type": "text", "text": args.to_string()}]})
            }
            _ => {
                let err = json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": "method_not_found"}});
                if write_response(&mut s, 200, mode.framing, &extra, Some(&err))
                    .await
                    .is_err()
                {
                    return;
                }
                continue;
            }
        };
        let resp = json!({"jsonrpc": "2.0", "id": id, "result": result});
        if write_response(&mut s, 200, mode.framing, &extra, Some(&resp))
            .await
            .is_err()
        {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fake_upstream_serves_initialize_over_pinned_tls() {
        let up = FakeUpstream::start(Mode::default()).await;
        let tcp = up.tcp().await;
        let tls = crate::tls_pin::connect_pinned(tcp, "localhost", &up.spki_pin)
            .await
            .unwrap();
        let client = crate::upstream_http::Upstream::handshake(tls, "localhost")
            .await
            .unwrap();
        let init = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}});
        let (status, v) = client
            .post(None, &init, crate::upstream_http::DEFAULT_TIMEOUT)
            .await
            .unwrap();
        assert_eq!(status, 200);
        assert_eq!(v["result"]["serverInfo"]["name"], "fake-upstream");
        assert_eq!(up.received().len(), 1);
    }

    #[tokio::test]
    async fn fake_upstream_rejects_wrong_pin() {
        let up = FakeUpstream::start(Mode::default()).await;
        let tcp = up.tcp().await;
        let wrong = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        assert!(
            crate::tls_pin::connect_pinned(tcp, "localhost", wrong)
                .await
                .is_err()
        );
    }
}
