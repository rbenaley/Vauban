//! One visit: hop 1, then either direct HTTPS posts or one inner tunnel.

use crate::hop::{self, Hop1};
use crate::inner::{mcp_post, mcp_post_pinned};
use crate::tofu::{self, TofuDecision};
use futures_util::{Sink, Stream};
use secrecy::ExposeSecret;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{Connector, connect_async_tls_with_config};

pub fn known_hosts_path() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("vauban").join("known_mcp_hosts")
}

/// Compare `advertised` with the pin stored for `origin` (an
/// [`tofu::origin_key`] of `--url`), learning it on first use.
pub fn accept_pin(origin: &str, advertised: &str, path: &Path) -> Result<String, String> {
    if tofu::origin_key(&format!("https://{origin}")).as_deref() != Ok(origin) {
        return Err(format!("{origin} is not a host:port origin; refusing"));
    }
    if let Some(parent) = path.parent() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .map_err(|e| format!("known hosts dir: {e}"))?;
    }
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(path.with_extension("lock"))
        .map_err(|e| format!("known hosts lock: {e}"))?;
    lock.lock().map_err(|e| format!("known hosts lock: {e}"))?;
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(format!("known hosts: {e}")),
    };
    let mut store = tofu::parse_store(&text);
    let legacy = tofu::legacy_keys(&store, origin);
    match tofu::observe(&mut store, origin, advertised) {
        TofuDecision::Mismatch if !store.contains_key(origin) => Err(format!(
            "MCP tunnel pin for {origin} differs from the legacy line `{}`; refusing. \
             Stored pin stays in {}",
            legacy.join("`, `"),
            path.display()
        )),
        TofuDecision::Mismatch => Err(format!(
            "MCP tunnel pin for {origin} changed; refusing. Stored pin stays in {}",
            path.display()
        )),
        TofuDecision::Learned => {
            write_store_atomic(path, &tofu::render_store(&store))?;
            tracing::info!(origin, pin = %advertised, "learned MCP tunnel pin; compare it with the asset page");
            Ok(advertised.to_string())
        }
        TofuDecision::Migrated => {
            write_store_atomic(path, &tofu::render_store(&store))?;
            tracing::info!(origin, legacy = %legacy.join(","), "migrated legacy MCP tunnel pin");
            Ok(advertised.to_string())
        }
        TofuDecision::Match => Ok(advertised.to_string()),
    }
}

/// Temp file in the same directory, mode 0600, then rename.
fn write_store_atomic(path: &Path, text: &str) -> Result<(), String> {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("known hosts path has no file name")?;
    let tmp = path.with_file_name(format!(
        ".{name}.{}.{}.tmp",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let written = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("known hosts write: {e}"));
    }
    Ok(())
}

/// Inner-TLS bytes over binary WebSocket frames. Control frames (the
/// bastion pings at once) are skipped, never surfaced as "no data".
struct WsIo<T> {
    inner: tokio_tungstenite::WebSocketStream<T>,
    buf: Vec<u8>,
    pos: usize,
}

impl<T> WsIo<T> {
    fn new(inner: tokio_tungstenite::WebSocketStream<T>) -> Self {
        Self {
            inner,
            buf: Vec::new(),
            pos: 0,
        }
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for WsIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
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
                }
                Poll::Ready(Some(Ok(Message::Close(_)))) | Poll::Ready(None) => {
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(Ok(_))) => {}
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(std::io::Error::other(e.to_string())));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncWrite for WsIo<T> {
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
        .map_err(|e| format!("direct hop 2: {}", crate::error_chain(&e)))?;
    response
        .text()
        .await
        .map_err(|e| format!("direct body: {e}"))
}

/// `cli_origin` is [`tofu::origin_key`] of `--url`. The pin is filed
/// under it, whatever URL hop 1 returned.
pub async fn post_tunnel(
    hop: &Hop1,
    cli_origin: &str,
    body: &str,
    hosts: &Path,
    tls: &std::sync::Arc<rustls::ClientConfig>,
) -> Result<String, String> {
    let pin = hop
        .tunnel_spki
        .as_deref()
        .ok_or("hop 1 did not return tunnel_spki")?;
    if tofu::origin_key(&hop.url)? != cli_origin {
        return Err("hop 2 url is not on the --url origin; refusing".into());
    }
    let pin = accept_pin(cli_origin, pin, hosts)?;
    let host = tofu::origin_host(cli_origin);
    let ws_url = hop::tunnel_ws_url(&hop.url)?;
    let (ws, _) = connect_async_tls_with_config(
        &ws_url,
        None,
        false,
        Some(Connector::Rustls(std::sync::Arc::clone(tls))),
    )
    .await
    .map_err(|e| format!("tunnel websocket: {}", crate::error_chain(&e)))?;
    mcp_post_pinned(
        WsIo::new(ws),
        host,
        &pin,
        hop.bearer.expose_secret(),
        body.as_bytes(),
    )
    .await
}

/// Used by tests that already hold a byte stream (no WebSocket).
pub async fn post_on_stream<S>(stream: S, bearer: &str, body: &str) -> Result<String, String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    mcp_post(stream, bearer, body.as_bytes()).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::{SinkExt, StreamExt};
    use tokio::io::AsyncReadExt;
    use tokio_tungstenite::WebSocketStream;
    use tokio_tungstenite::tungstenite::protocol::Role;

    /// The bastion pings before the first TLS record: the read must wait
    /// for the binary frame, not stall on the ping.
    #[tokio::test]
    async fn control_frames_do_not_stall_the_tunnel_read() {
        let (client, server) = tokio::io::duplex(4096);
        let mut server = WebSocketStream::from_raw_socket(server, Role::Server, None).await;
        let client = WebSocketStream::from_raw_socket(client, Role::Client, None).await;
        let mut io = WsIo::new(client);
        tokio::spawn(async move {
            server.send(Message::Ping(vec![].into())).await.unwrap();
            server.send(Message::Text("noise".into())).await.unwrap();
            server
                .send(Message::Binary(b"hello".to_vec().into()))
                .await
                .unwrap();
            server.send(Message::Close(None)).await.unwrap();
            while server.next().await.is_some() {}
        });
        let mut got = [0u8; 5];
        tokio::time::timeout(std::time::Duration::from_secs(5), io.read_exact(&mut got))
            .await
            .expect("tunnel read stalled on a control frame")
            .unwrap();
        assert_eq!(&got, b"hello");
        let mut rest = Vec::new();
        io.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty(), "Close must read as end of stream");
    }

    use std::os::unix::fs::PermissionsExt;
    use std::sync::{Arc, Barrier};

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "vauban-mcp-{name}-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
        ));
        dir.join("vauban").join("known_mcp_hosts")
    }

    #[test]
    fn learned_pin_is_written_0600_and_matches_after() {
        let path = scratch("learn");
        assert!(accept_pin("b.example:443", "SHA256:aaaa", &path).is_ok());
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert!(accept_pin("b.example:443", "SHA256:aaaa", &path).is_ok());
        assert!(accept_pin("b.example:443", "SHA256:bbbb", &path).is_err());
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text, "b.example:443 SHA256:aaaa\n");
    }

    #[test]
    fn battle_eight_writers_keep_one_entry_per_origin() {
        let path = Arc::new(scratch("battle"));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            path.as_ref(),
            "shared.example SHA256:s0\nH3.example SHA256:pin3\n",
        )
        .unwrap();
        let barrier = Arc::new(Barrier::new(8));
        let mut joins = Vec::new();
        for i in 0..8 {
            let path = Arc::clone(&path);
            let barrier = Arc::clone(&barrier);
            joins.push(std::thread::spawn(move || {
                barrier.wait();
                let own = format!("h{i}.example:443");
                accept_pin(&own, &format!("SHA256:pin{i}"), &path).unwrap();
                let shared = accept_pin("shared.example:443", &format!("SHA256:s{i}"), &path);
                (i, shared.is_ok())
            }));
        }
        let winners: Vec<usize> = joins
            .into_iter()
            .map(|j| j.join().unwrap())
            .filter(|(_, ok)| *ok)
            .map(|(i, _)| i)
            .collect();
        assert_eq!(
            winners,
            vec![0],
            "only the legacy pin of shared.example is accepted"
        );
        let store = tofu::parse_store(&std::fs::read_to_string(path.as_ref()).unwrap());
        assert_eq!(store.len(), 9);
        assert!(
            store.keys().all(|k| k.contains(':')),
            "no port-less line survives: {store:?}"
        );
        assert_eq!(
            store.get("shared.example:443").map(String::as_str),
            Some("SHA256:s0")
        );
        for i in 0..8 {
            assert_eq!(
                store.get(&format!("h{i}.example:443")).map(String::as_str),
                Some(format!("SHA256:pin{i}").as_str())
            );
        }
        let leftovers = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .count();
        assert_eq!(leftovers, 0);
    }

    #[test]
    fn legacy_file_is_migrated_once_and_written_0600() {
        let path = scratch("migrate");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "B.example SHA256:aaaa\nc.example:443 SHA256:cccc\n").unwrap();
        assert!(accept_pin("b.example:8443", "SHA256:aaaa", &path).is_ok());
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            text,
            "b.example:8443 SHA256:aaaa\nc.example:443 SHA256:cccc\n"
        );
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert!(accept_pin("b.example:8443", "SHA256:aaaa", &path).is_ok());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
    }

    #[test]
    fn legacy_mismatch_names_the_line_and_keeps_the_file() {
        let path = scratch("legacy-mismatch");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let before = "Bastion.example SHA256:aaaa\n";
        std::fs::write(&path, before).unwrap();
        let err = accept_pin("bastion.example:443", "SHA256:evil", &path).unwrap_err();
        assert!(err.contains("legacy line `Bastion.example`"), "{err}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
    }

    #[tokio::test]
    async fn attack_hop1_cannot_plant_a_legacy_line() {
        let path = scratch("plant");
        for bare in [
            "evil.example",
            "Evil.Example:443",
            "evil.example.:443",
            "evil.example:0443",
        ] {
            assert!(accept_pin(bare, "SHA256:aaaa", &path).is_err(), "{bare}");
        }
        assert!(!path.exists(), "a refused origin must not create the store");

        let hop = Hop1 {
            url: "https://evil.example/mcp".into(),
            bearer: secrecy::SecretString::from("vbw_x".to_string()),
            transport: "tunnel".into(),
            tunnel_spki: Some("SHA256:evil".into()),
        };
        let tls = crate::trust::client_config(&[]).expect("tls");
        let err = post_tunnel(&hop, "b.example:443", "{}", &path, &tls)
            .await
            .unwrap_err();
        assert!(err.contains("not on the --url origin"), "{err}");
        assert!(!path.exists());

        accept_pin("b.example:443", "SHA256:aaaa", &path).unwrap();
        let store = tofu::parse_store(&std::fs::read_to_string(&path).unwrap());
        assert!(
            store.keys().all(|k| k.contains(':')),
            "only host:port keys are ever written: {store:?}"
        );
    }

    #[test]
    fn battle_eight_writers_migrate_a_legacy_file_once() {
        let path = Arc::new(scratch("battle-legacy"));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path.as_ref(), "shared.example SHA256:ssss\n").unwrap();
        let barrier = Arc::new(Barrier::new(8));
        let joins: Vec<_> = (0..8)
            .map(|i| {
                let path = Arc::clone(&path);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    let pin = if i % 2 == 0 {
                        "SHA256:ssss"
                    } else {
                        "SHA256:evil"
                    };
                    accept_pin("shared.example:443", pin, &path).is_ok() == (i % 2 == 0)
                })
            })
            .collect();
        for join in joins {
            assert!(join.join().unwrap(), "same pin accepted, other pin refused");
        }
        let text = std::fs::read_to_string(path.as_ref()).unwrap();
        assert_eq!(
            text, "shared.example:443 SHA256:ssss\n",
            "one host:port line, no legacy line"
        );
    }

    #[test]
    fn tunnel_key_comes_from_the_cli_origin() {
        let src = include_str!("session.rs");
        let prod = src.split("#[cfg(test)]").next().unwrap();
        let start = prod.find("pub async fn post_tunnel(").unwrap();
        let body = &prod[start..];
        assert!(body.contains("accept_pin(cli_origin,"));
        assert!(!body.contains("host_of("));
        assert!(!prod.contains("\"http://\""));
        assert!(!prod.contains("\"ws://\""));
        assert!(!prod.contains("std::fs::write("));
        for write in [
            "store.get(",
            "store.insert(",
            "store.remove(",
            "store.entry(",
        ] {
            assert!(
                !prod.contains(write),
                "the TOFU map belongs to tofu.rs ({write})"
            );
        }
        let accept = prod.find("pub fn accept_pin(").unwrap();
        let accept = &prod[accept..];
        assert!(
            accept.contains(
                "tofu::origin_key(&format!(\"https://{origin}\")).as_deref() != Ok(origin)"
            )
        );
        assert!(accept.contains("TofuDecision::Migrated => {\n            write_store_atomic("));
    }
}
