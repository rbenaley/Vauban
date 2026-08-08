//! E2E: self-signed SMTP stub — accept_invalid_certs true delivers, false fails.

use std::sync::Arc;

use rcgen::{CertificateParams, KeyPair};
use rustls::ServerConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use topcoat::context::Cx;
use topcoat::mail::{Mail, Mailbox, Transport};
use vcp::config::{MailConfig, SmtpEncryption};
use vcp::mailer::build_smtp_transport;

use crate::common::install_crypto_once;

fn self_signed_server_config() -> Arc<ServerConfig> {
    let key_pair = KeyPair::generate().expect("key");
    let params = CertificateParams::new(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])
        .expect("params");
    let cert = params.self_signed(&key_pair).expect("cert");
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
    let mut cfg = ServerConfig::builder_with_protocol_versions(&[
        &rustls::version::TLS13,
        &rustls::version::TLS12,
    ])
    .with_no_client_auth()
    .with_single_cert(vec![cert_der], key_der)
    .expect("server config");
    cfg.alpn_protocols.clear();
    Arc::new(cfg)
}

async fn write_smtp_line<W: AsyncWrite + Unpin>(w: &mut W, line: &str) {
    w.write_all(line.as_bytes()).await.expect("write");
    w.write_all(b"\r\n").await.expect("crlf");
    w.flush().await.expect("flush");
}

async fn read_smtp_line<R: AsyncRead + Unpin>(r: &mut BufReader<R>) -> String {
    let mut line = String::new();
    r.read_line(&mut line).await.expect("read line");
    line
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

/// SMTP dialogue on an already-encrypted stream.
///
/// `send_greeting`: true for implicit TLS (SMTPS); false after STARTTLS
/// upgrade (RFC 3207 — client EHLO resumes without a second 220).
async fn handle_encrypted_smtp<S>(mut stream: S, send_greeting: bool)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if send_greeting {
        write_smtp_line(&mut stream, "220 localhost ESMTP vcp-stub").await;
    }
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    let mut data_mode = false;
    loop {
        let n = match stream.read(&mut tmp).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };
        buf.extend_from_slice(&tmp[..n]);
        while let Some(idx) = find_crlf(&buf) {
            let line = buf.drain(..=idx + 1).collect::<Vec<u8>>();
            let line_str = String::from_utf8_lossy(&line).into_owned();
            if data_mode {
                if line_str == ".\r\n" || line_str.trim_end() == "." {
                    data_mode = false;
                    write_smtp_line(&mut stream, "250 OK").await;
                }
                continue;
            }
            let upper = line_str.to_ascii_uppercase();
            if upper.starts_with("EHLO") || upper.starts_with("HELO") {
                write_smtp_line(&mut stream, "250-localhost").await;
                write_smtp_line(&mut stream, "250 OK").await;
            } else if upper.starts_with("MAIL FROM") || upper.starts_with("RCPT TO") {
                write_smtp_line(&mut stream, "250 OK").await;
            } else if upper.starts_with("DATA") {
                write_smtp_line(&mut stream, "354 End data with <CR><LF>.<CR><LF>").await;
                data_mode = true;
            } else if upper.starts_with("QUIT") {
                write_smtp_line(&mut stream, "221 Bye").await;
                return;
            } else if upper.starts_with("RSET") || upper.starts_with("NOOP") {
                write_smtp_line(&mut stream, "250 OK").await;
            } else {
                write_smtp_line(&mut stream, "502 Command not implemented").await;
            }
        }
    }
}

async fn spawn_implicit_tls_stub() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let acceptor = TlsAcceptor::from(self_signed_server_config());
    tokio::spawn(async move {
        if let Ok((tcp, _)) = listener.accept().await
            && let Ok(tls) = acceptor.accept(tcp).await
        {
            handle_encrypted_smtp(tls, true).await;
        }
    });
    port
}

async fn spawn_starttls_stub() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let acceptor = TlsAcceptor::from(self_signed_server_config());
    tokio::spawn(async move {
        let Ok((mut tcp, _)) = listener.accept().await else {
            return;
        };
        write_smtp_line(&mut tcp, "220 localhost ESMTP vcp-stub").await;
        let mut reader = BufReader::new(&mut tcp);
        loop {
            let line = read_smtp_line(&mut reader).await;
            let upper = line.to_ascii_uppercase();
            if upper.starts_with("EHLO") || upper.starts_with("HELO") {
                write_smtp_line(reader.get_mut(), "250-localhost").await;
                write_smtp_line(reader.get_mut(), "250-STARTTLS").await;
                write_smtp_line(reader.get_mut(), "250 OK").await;
            } else if upper.starts_with("STARTTLS") {
                write_smtp_line(reader.get_mut(), "220 Ready to start TLS").await;
                break;
            } else if line.is_empty() {
                return;
            } else {
                write_smtp_line(reader.get_mut(), "502 Command not implemented").await;
            }
        }
        drop(reader);
        if let Ok(tls) = acceptor.accept(tcp).await {
            handle_encrypted_smtp(tls, false).await;
        }
    });
    port
}

fn error_chain(err: &dyn std::error::Error) -> String {
    let mut out = err.to_string();
    let mut source = err.source();
    while let Some(inner) = source {
        out.push_str(": ");
        out.push_str(&inner.to_string());
        source = inner.source();
    }
    out
}

async fn try_send(cfg: &MailConfig) -> Result<(), String> {
    let transport = build_smtp_transport(cfg).map_err(|e| e.to_string())?;
    let cx = Cx::default();
    let mail = Mail::builder()
        .from(Mailbox::new("noreply@example.com").map_err(|e| e.to_string())?)
        .to([Mailbox::new("user@example.com").map_err(|e| e.to_string())?])
        .subject("vcp smtp stub probe")
        .text("hello from e2e")
        .message_id("<probe@localhost>")
        .build();
    transport
        .send(&cx, mail)
        .await
        .map(|_| ())
        .map_err(|e| error_chain(e.as_ref()))
}

#[tokio::test]
async fn e2e_implicit_tls_accept_invalid_true_delivers() {
    install_crypto_once();
    let port = spawn_implicit_tls_stub().await;
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let cfg = MailConfig {
        smtp_host: "127.0.0.1".to_owned(),
        smtp_port: port,
        smtp_encryption: SmtpEncryption::Tls,
        smtp_username: String::new(),
        smtp_password: String::new(),
        smtp_accept_invalid_certs: true,
    };
    try_send(&cfg)
        .await
        .expect("self-signed SMTPS should succeed with accept_invalid");
}

#[tokio::test]
async fn e2e_implicit_tls_accept_invalid_false_rejects() {
    install_crypto_once();
    let port = spawn_implicit_tls_stub().await;
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let cfg = MailConfig {
        smtp_host: "127.0.0.1".to_owned(),
        smtp_port: port,
        smtp_encryption: SmtpEncryption::Tls,
        smtp_username: String::new(),
        smtp_password: String::new(),
        smtp_accept_invalid_certs: false,
    };
    let err = try_send(&cfg)
        .await
        .expect_err("untrusted cert must fail without accept_invalid");
    let lower = err.to_ascii_lowercase();
    assert!(
        lower.contains("certificate")
            || lower.contains("tls")
            || lower.contains("handshake")
            || lower.contains("invalid"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn e2e_starttls_accept_invalid_true_delivers() {
    install_crypto_once();
    let port = spawn_starttls_stub().await;
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let cfg = MailConfig {
        smtp_host: "127.0.0.1".to_owned(),
        smtp_port: port,
        smtp_encryption: SmtpEncryption::Starttls,
        smtp_username: String::new(),
        smtp_password: String::new(),
        smtp_accept_invalid_certs: true,
    };
    try_send(&cfg)
        .await
        .expect("self-signed STARTTLS should succeed with accept_invalid");
}

#[tokio::test]
async fn e2e_starttls_accept_invalid_false_rejects() {
    install_crypto_once();
    let port = spawn_starttls_stub().await;
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let cfg = MailConfig {
        smtp_host: "127.0.0.1".to_owned(),
        smtp_port: port,
        smtp_encryption: SmtpEncryption::Starttls,
        smtp_username: String::new(),
        smtp_password: String::new(),
        smtp_accept_invalid_certs: false,
    };
    let err = try_send(&cfg)
        .await
        .expect_err("untrusted STARTTLS cert must fail without accept_invalid");
    let lower = err.to_ascii_lowercase();
    assert!(
        lower.contains("certificate")
            || lower.contains("tls")
            || lower.contains("handshake")
            || lower.contains("invalid")
            || lower.contains("starttls"),
        "unexpected error: {err}"
    );
}
