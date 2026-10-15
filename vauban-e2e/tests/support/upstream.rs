//! The MCP server behind the bastion: HTTPS on loopback with a self-signed
//! `localhost` certificate, so `proxy-mcp` dials it through the supervisor
//! and checks its SPKI pin exactly as in production (ADR 010). Plain
//! HTTP/1.1 keep-alive JSON-RPC; every request is recorded.

use anyhow::{Context, Result};
use base64::Engine;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::crypto::aws_lc_rs;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// Catalogue served on `tools/list`, one tool per access-rule mode.
pub const TOOLS: &[(&str, &str)] = &[
    ("echo", "Echo the arguments back."),
    ("lookup", "Look up one record by id."),
    ("delete_task", "Delete one task by id."),
    ("deploy", "Deploy a release to an environment."),
    ("drop_db", "Drop a database."),
];

pub const INSTRUCTIONS: &str = "E2E upstream: answer briefly.";

#[derive(Default)]
struct Shared {
    descriptions: HashMap<String, String>,
    received: Vec<Value>,
}

pub struct FakeUpstream {
    pub port: u16,
    /// `SHA256:<base64>` of the certificate's SubjectPublicKeyInfo.
    pub spki_pin: String,
    shared: Arc<Mutex<Shared>>,
}

impl FakeUpstream {
    pub async fn start() -> Result<Self> {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let cert =
            rcgen::CertificateParams::new(vec!["localhost".to_string()])?.self_signed(&key)?;
        let spki_pin = format!(
            "SHA256:{}",
            base64::engine::general_purpose::STANDARD.encode(Sha256::digest(
                rcgen::PublicKeyData::subject_public_key_info(&key)
            ))
        );
        let cfg = ServerConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert.der().to_vec())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            )?;
        let acceptor = TlsAcceptor::from(Arc::new(cfg));
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let shared = Arc::new(Mutex::new(Shared::default()));
        let srv = Arc::clone(&shared);
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                let shared = Arc::clone(&srv);
                tokio::spawn(async move {
                    if let Ok(tls) = acceptor.accept(tcp).await {
                        serve(tls, shared).await;
                    }
                });
            }
        });
        Ok(Self {
            port,
            spki_pin,
            shared,
        })
    }

    /// Changes what `tools/list` says about `tool` (a rug pull); `None`
    /// restores the original description.
    pub fn set_description(&self, tool: &str, description: Option<&str>) {
        let mut g = self.shared.lock().expect("upstream lock");
        match description {
            Some(d) => g.descriptions.insert(tool.into(), d.into()),
            None => g.descriptions.remove(tool),
        };
    }

    /// `params.arguments` of every `tools/call` of `tool` that reached here.
    pub fn calls(&self, tool: &str) -> Vec<Value> {
        self.shared
            .lock()
            .expect("upstream lock")
            .received
            .iter()
            .filter(|b| b["method"] == "tools/call" && b["params"]["name"] == tool)
            .map(|b| b["params"]["arguments"].clone())
            .collect()
    }

    /// Every request body received so far.
    pub fn received(&self) -> Vec<Value> {
        self.shared.lock().expect("upstream lock").received.clone()
    }
}

async fn read_request<S: AsyncRead + Unpin>(s: &mut S, buf: &mut Vec<u8>) -> Option<Vec<u8>> {
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
    let head = String::from_utf8_lossy(&buf[..header_end]).to_ascii_lowercase();
    let len: usize = head
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .and_then(|v| v.trim().parse().ok())
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
    Some(body)
}

async fn write_json<S: AsyncWrite + Unpin>(s: &mut S, status: u16, body: Option<&Value>) -> bool {
    let bytes = body.map(|b| b.to_string()).unwrap_or_default();
    let mut head = format!(
        "HTTP/1.1 {status} OK\r\nContent-Length: {}\r\n",
        bytes.len()
    );
    if body.is_some() {
        head.push_str("Content-Type: application/json\r\n");
    }
    head.push_str("\r\n");
    s.write_all(head.as_bytes()).await.is_ok()
        && s.write_all(bytes.as_bytes()).await.is_ok()
        && s.flush().await.is_ok()
}

async fn serve<S: AsyncRead + AsyncWrite + Unpin>(mut s: S, shared: Arc<Mutex<Shared>>) {
    let mut buf = Vec::new();
    while let Some(raw) = read_request(&mut s, &mut buf).await {
        let body: Value = serde_json::from_slice(&raw).unwrap_or(Value::Null);
        let method = body["method"].as_str().unwrap_or("").to_string();
        let descriptions = {
            let mut g = shared.lock().expect("upstream lock");
            g.received.push(body.clone());
            g.descriptions.clone()
        };
        if method.starts_with("notifications/") {
            if !write_json(&mut s, 202, None).await {
                return;
            }
            continue;
        }
        let result = match method.as_str() {
            "initialize" => json!({
                "protocolVersion": "2025-03-26",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "e2e-upstream", "version": "1"},
                "instructions": INSTRUCTIONS,
            }),
            "tools/list" => {
                let tools: Vec<Value> = TOOLS
                    .iter()
                    .map(|(name, d)| {
                        let d = descriptions.get(*name).map_or(*d, String::as_str);
                        json!({"name": name, "description": d, "inputSchema": {"type": "object"}})
                    })
                    .collect();
                json!({ "tools": tools })
            }
            "tools/call" => {
                let args = body
                    .pointer("/params/arguments")
                    .cloned()
                    .unwrap_or(json!({}));
                json!({"content": [{"type": "text", "text": args.to_string()}]})
            }
            _ => {
                let err = json!({"jsonrpc": "2.0", "id": body["id"], "error": {"code": -32601, "message": "method_not_found"}});
                if !write_json(&mut s, 200, Some(&err)).await {
                    return;
                }
                continue;
            }
        };
        let resp = json!({"jsonrpc": "2.0", "id": body["id"], "result": result});
        if !write_json(&mut s, 200, Some(&resp)).await {
            return;
        }
    }
}

/// Agent-side client: hop 1 with a `vbn_` key, hop 2 with the `vbw_`.
pub struct Agent {
    http: reqwest::Client,
    origin: String,
}

/// One open visit (hop 1 answer).
pub struct Visit {
    http: reqwest::Client,
    pub session_id: String,
    pub url: String,
    pub bearer: String,
    next_id: std::sync::atomic::AtomicU64,
}

impl Agent {
    pub fn new(origin: &str) -> Result<Self> {
        let http = reqwest::Client::builder()
            .tls_danger_accept_invalid_certs(true)
            .build()?;
        Ok(Self {
            http,
            origin: origin.to_string(),
        })
    }

    /// Raw hop 1: status and body (JSON when it parses, else the text).
    pub async fn open_raw(&self, auth: Option<&str>, body: &Value) -> Result<(u16, Value)> {
        let mut req = self
            .http
            .post(format!("{}/api/v1/mcp/sessions", self.origin))
            .json(body);
        if let Some(a) = auth {
            req = req.header("Authorization", a);
        }
        let resp = req.send().await?;
        let status = resp.status().as_u16();
        let text = resp.text().await?;
        Ok((
            status,
            serde_json::from_str(&text).unwrap_or(Value::String(text)),
        ))
    }

    /// Hop 1 that must succeed.
    pub async fn open(&self, key: &str, asset: &str, justification: &str) -> Result<Visit> {
        let (status, v) = self
            .open_raw(
                Some(&format!("Bearer {key}")),
                &json!({"asset_id": asset, "justification": justification}),
            )
            .await?;
        anyhow::ensure!(status == 200, "hop 1 -> {status}: {v}");
        let field = |k: &str| {
            v[k].as_str()
                .map(str::to_string)
                .with_context(|| format!("hop 1 answer without {k}: {v}"))
        };
        Ok(Visit {
            http: self.http.clone(),
            session_id: field("session_id")?,
            url: field("url")?,
            bearer: field("bearer")?,
            next_id: 1.into(),
        })
    }

    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// A visit opened elsewhere (the Connect page shows URL and bearer).
    pub fn visit(&self, session_id: &str, url: &str, bearer: &str) -> Visit {
        Visit {
            http: self.http.clone(),
            session_id: session_id.into(),
            url: url.into(),
            bearer: bearer.into(),
            next_id: 1.into(),
        }
    }

    /// Hop 2 with an arbitrary `Authorization` header.
    pub async fn post_mcp(&self, auth: Option<&str>, body: &Value) -> Result<(u16, Value)> {
        let mut req = self.http.post(format!("{}/mcp", self.origin)).json(body);
        if let Some(a) = auth {
            req = req.header("Authorization", a);
        }
        let resp = req.send().await?;
        let status = resp.status().as_u16();
        let text = resp.text().await?;
        Ok((
            status,
            serde_json::from_str(&text).unwrap_or(Value::String(text)),
        ))
    }
}

impl Visit {
    /// One JSON-RPC request; status and the decoded answer.
    pub async fn rpc(&self, method: &str, params: Value) -> Result<(u16, Value)> {
        let id = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let resp = self
            .http
            .post(&self.url)
            .bearer_auth(&self.bearer)
            .header("Accept", "application/json, text/event-stream")
            .json(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))
            .send()
            .await?;
        let status = resp.status().as_u16();
        let text = resp.text().await?;
        Ok((
            status,
            serde_json::from_str(&text).unwrap_or(Value::String(text)),
        ))
    }

    pub async fn initialize(&self) -> Result<Value> {
        let (status, v) = self
            .rpc(
                "initialize",
                json!({"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "e2e", "version": "1"}}),
            )
            .await?;
        anyhow::ensure!(status == 200, "initialize -> {status}: {v}");
        Ok(v)
    }

    /// Tools advertised to the agent, by name.
    pub async fn tools(&self) -> Result<HashMap<String, Value>> {
        let (status, v) = self.rpc("tools/list", json!({})).await?;
        anyhow::ensure!(status == 200, "tools/list -> {status}: {v}");
        let tools = v["result"]["tools"]
            .as_array()
            .with_context(|| format!("tools/list without tools: {v}"))?;
        Ok(tools
            .iter()
            .map(|t| (t["name"].as_str().unwrap_or("").to_string(), t.clone()))
            .collect())
    }

    pub async fn call(&self, tool: &str, arguments: Value) -> Result<(u16, Value)> {
        self.rpc("tools/call", json!({"name": tool, "arguments": arguments}))
            .await
    }
}

/// JSON-RPC error code of an answer, if any.
pub fn error_code(v: &Value) -> Option<i64> {
    v["error"]["code"].as_i64()
}
