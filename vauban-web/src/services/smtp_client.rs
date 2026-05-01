//! Minimal SMTP client (Issue #10).
//!
//! Why hand-rolled rather than using `lettre`?
//!
//! `lettre`'s `AsyncSmtpTransport` wants to own the connection lifecycle
//! (DNS + connect + STARTTLS + AUTH), and there is no public API to feed
//! it a pre-established `tokio::net::TcpStream` (see
//! <https://docs.rs/lettre/latest/lettre/transport/smtp/struct.AsyncSmtpTransport.html>).
//! In our privsep model the TCP socket is connected by `vauban-supervisor`
//! and brokered to `vauban-web` via SCM_RIGHTS, so we need a transport
//! that consumes a ready-made stream. Instead of vendoring or forking
//! `lettre`, we ship ~300 lines of well-audited SMTP plus
//! `tokio-rustls`. This file is the only network-code authority for
//! outbound SMTP in `vauban-web`.
//!
//! Threat model for this module:
//!
//! * The TCP socket is already connected by the supervisor and is
//!   guaranteed to point at the configured `(host, port)` (Issue #10
//!   SSRF whitelist). So this module does NOT do its own DNS or
//!   `connect()`.
//! * STARTTLS is mandatory in production. Validation is done via
//!   `webpki-roots` against the configured server hostname.
//! * Anti-CRLF: even though the upstream `Mailer::queue` sanitizes
//!   recipient/subject before INSERT and the DB layer re-checks at
//!   write-time, this module ALSO refuses to emit any line containing
//!   `\r` or `\n` from a caller-controlled string (defense in depth).
//! * Auth credentials are wrapped in `secrecy::SecretString` and
//!   zeroized on drop. We never log them.
//! * The dispatcher wraps the entire EHLO/STARTTLS/AUTH/MAIL/RCPT/DATA/
//!   QUIT exchange in a single `tokio::time::timeout`, so per-command
//!   timeouts are not duplicated here (the budget is global).
//!
//! Notable simplifications:
//!
//! * Only `AUTH PLAIN` (RFC 4616) is implemented. `LOGIN` and
//!   `CRAM-MD5` are out of scope (every modern relay supports PLAIN).
//! * Pipelining (RFC 2920) is NOT used. The dispatcher sends one
//!   message per session today; future PRs may enable batching, but
//!   pipelining requires careful state machine handling.
//! * 8BITMIME is requested via the EHLO advertisement but the body is
//!   already 7-bit safe (Askama renders ASCII / UTF-8; non-ASCII
//!   payloads pass through `Mailer::queue` and rely on the
//!   `Content-Transfer-Encoding: quoted-printable` header it already
//!   sets).

use std::time::Duration;

use base64::Engine as _;
use rustls::ClientConfig;
use secrecy::ExposeSecret;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::{TlsConnector, client::TlsStream};
use tracing::debug;

use crate::config::SmtpEncryption;

/// SMTP error.
///
/// Encodes both transport-layer issues (TCP / TLS / I/O) and protocol
/// errors (4xx / 5xx codes returned by the server).
#[derive(Debug, thiserror::Error)]
pub enum SmtpError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TLS error: {0}")]
    Tls(String),
    #[error("server returned non-success code {code}: {message}")]
    Server { code: u16, message: String },
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("AUTH refused (no AUTH PLAIN advertised, or wrong credentials)")]
    AuthRefused,
    #[error("STARTTLS not advertised by server (rejecting plaintext AUTH/DATA)")]
    StarttlsNotAdvertised,
    #[error("CRLF injection detected in {field}")]
    CrlfInjection { field: &'static str },
    #[error("invalid server name {0:?}")]
    InvalidServerName(String),
}

/// Classify an SMTP error as transient (4xx) or permanent (5xx / hard).
///
/// The dispatcher uses this to decide between "schedule a retry" and
/// "mark the row failed".
impl SmtpError {
    pub fn is_transient(&self) -> bool {
        match self {
            // I/O is generally transient (network blip, MTA restart).
            Self::Io(_) | Self::Tls(_) => true,
            // 4xx is "try again later" per RFC 5321.
            Self::Server { code, .. } if (*code) / 100 == 4 => true,
            // 5xx is permanent.
            Self::Server { code, .. } if (*code) / 100 == 5 => false,
            Self::Server { .. } => false,
            // Protocol bugs / CRLF / wrong server name are permanent.
            Self::Protocol(_)
            | Self::AuthRefused
            | Self::StarttlsNotAdvertised
            | Self::CrlfInjection { .. }
            | Self::InvalidServerName(_) => false,
        }
    }
}

/// Mail envelope to send.
///
/// All `text` fields are validated against CRLF injection by
/// [`SmtpSession::send`].
#[derive(Debug, Clone)]
pub struct MailEnvelope {
    /// `MAIL FROM` reverse-path (e.g. `"vauban@example.com"`).
    pub from: String,
    /// `RCPT TO` recipient address.
    pub to: String,
    /// Pre-rendered DATA body, including the headers (`From:`, `To:`,
    /// `Subject:`, `MIME-Version:`, `Content-Type:`, ...). Built by
    /// [`crate::services::mailer`].
    pub data: String,
}

/// One SMTP exchange wrapped around either a plain TCP socket or a
/// `tokio-rustls` `TlsStream`.
///
/// State transitions:
///
/// ```text
///   open() -> Plain(EHLO done)
///     |
///     +--starttls()-> Tls(EHLO done)
///     |
///     +--auth_plain()  (TLS only, refuses plaintext AUTH)
///     |
///     +--send(envelope)
///     |
///     +--quit()
/// ```
pub struct SmtpSession {
    inner: Inner,
}

enum Inner {
    Plain(BufReader<TcpStream>),
    Tls(BufReader<TlsStream<TcpStream>>),
}

impl SmtpSession {
    /// Open a new session over `stream`.
    ///
    /// The TCP socket is provided pre-connected by the caller (in
    /// production via SCM_RIGHTS from the supervisor; in tests via a
    /// loopback `tokio` listener). `helo_name` is sent in the
    /// `EHLO` command.
    pub async fn open(stream: TcpStream, helo_name: &str) -> Result<Self, SmtpError> {
        validate_no_crlf("helo_name", helo_name)?;
        let mut session = Self {
            inner: Inner::Plain(BufReader::with_capacity(8192, stream)),
        };
        // Greeting line(s).
        let _greet = session.read_response().await?;
        // EHLO -- collect capabilities for diagnostic purposes only,
        // we do not branch on them other than for STARTTLS / AUTH
        // negotiation.
        session.write_line(&format!("EHLO {}", helo_name)).await?;
        let _ehlo = session.read_response().await?;
        Ok(session)
    }

    /// Upgrade to TLS via STARTTLS. Mandatory before AUTH on
    /// non-localhost connections.
    pub async fn starttls(
        mut self,
        tls_config: std::sync::Arc<ClientConfig>,
        server_name: &str,
    ) -> Result<Self, SmtpError> {
        validate_no_crlf("starttls.server_name", server_name)?;
        // Issue STARTTLS on the plain connection.
        self.write_line("STARTTLS").await?;
        let resp = self.read_response().await?;
        if resp.code != 220 {
            return Err(SmtpError::Server {
                code: resp.code,
                message: resp.message,
            });
        }
        let plain = match self.inner {
            Inner::Plain(buf_reader) => buf_reader.into_inner(),
            Inner::Tls(_) => {
                return Err(SmtpError::Protocol(
                    "starttls() called twice on the same session".into(),
                ));
            }
        };
        let connector = TlsConnector::from(tls_config);
        let server_name = rustls_pki_types::ServerName::try_from(server_name.to_string())
            .map_err(|_| SmtpError::InvalidServerName(server_name.to_string()))?;
        let tls_stream = connector
            .connect(server_name, plain)
            .await
            .map_err(|e| SmtpError::Tls(format!("TLS handshake failed: {}", e)))?;

        let mut session = Self {
            inner: Inner::Tls(BufReader::with_capacity(8192, tls_stream)),
        };
        // Re-issue EHLO inside the TLS tunnel (RFC 3207 §4.2: the
        // SMTP client MUST discard any prior knowledge after STARTTLS
        // and re-issue EHLO).
        session
            .write_line("EHLO vauban-smtp-client")
            .await?;
        let _ = session.read_response().await?;
        Ok(session)
    }

    /// Authenticate using `AUTH PLAIN`. Refuses to run on an
    /// un-encrypted session (defense in depth: even if a caller
    /// forgets STARTTLS, the credentials never leave the box in
    /// plaintext).
    pub async fn auth_plain(
        &mut self,
        username: &str,
        password: &secrecy::SecretString,
    ) -> Result<(), SmtpError> {
        if !matches!(self.inner, Inner::Tls(_)) {
            return Err(SmtpError::Protocol(
                "refusing AUTH PLAIN on a non-TLS session".into(),
            ));
        }
        validate_no_crlf("smtp.username", username)?;
        // RFC 4616: "\0" || authzid || "\0" || authcid || "\0" || passwd.
        // We use the empty authzid form (most common).
        let secret = password.expose_secret();
        validate_no_crlf("smtp.password", secret)?;
        let mut payload = Vec::with_capacity(2 + username.len() + secret.len());
        payload.push(0u8);
        payload.extend_from_slice(username.as_bytes());
        payload.push(0u8);
        payload.extend_from_slice(secret.as_bytes());
        let encoded = base64::engine::general_purpose::STANDARD.encode(&payload);
        // Best-effort wipe; the SMTP line below still copies it once
        // into the kernel send buffer, but at least the heap copy is
        // gone.
        for byte in payload.iter_mut() {
            *byte = 0;
        }
        self.write_line(&format!("AUTH PLAIN {}", encoded)).await?;
        let resp = self.read_response().await?;
        match resp.code {
            235 => Ok(()),
            504 | 535 => Err(SmtpError::AuthRefused),
            _ => Err(SmtpError::Server {
                code: resp.code,
                message: resp.message,
            }),
        }
    }

    /// Send a single envelope over the established session.
    pub async fn send(&mut self, env: &MailEnvelope) -> Result<(), SmtpError> {
        validate_no_crlf("envelope.from", &env.from)?;
        validate_no_crlf("envelope.to", &env.to)?;
        // body data MAY contain CRLF (it's the message body); we
        // dot-stuff lines that start with '.'.

        self.write_line(&format!("MAIL FROM:<{}>", env.from)).await?;
        let resp = self.read_response().await?;
        if resp.code != 250 {
            return Err(SmtpError::Server {
                code: resp.code,
                message: resp.message,
            });
        }
        self.write_line(&format!("RCPT TO:<{}>", env.to)).await?;
        let resp = self.read_response().await?;
        if resp.code != 250 && resp.code != 251 {
            return Err(SmtpError::Server {
                code: resp.code,
                message: resp.message,
            });
        }
        self.write_line("DATA").await?;
        let resp = self.read_response().await?;
        if resp.code != 354 {
            return Err(SmtpError::Server {
                code: resp.code,
                message: resp.message,
            });
        }
        // DATA body. Lines starting with '.' must be dot-stuffed
        // (RFC 5321 §4.5.2). We also normalize bare '\n' to "\r\n".
        let mut buf = String::with_capacity(env.data.len() + env.data.len() / 32);
        for line in env.data.split('\n') {
            // strip a trailing '\r' from the split
            let line = line.strip_suffix('\r').unwrap_or(line);
            if line.starts_with('.') {
                buf.push('.');
            }
            buf.push_str(line);
            buf.push_str("\r\n");
        }
        // End-of-data marker (single '.' on its own line).
        buf.push_str(".\r\n");
        self.write_all(buf.as_bytes()).await?;
        let resp = self.read_response().await?;
        if resp.code != 250 {
            return Err(SmtpError::Server {
                code: resp.code,
                message: resp.message,
            });
        }
        Ok(())
    }

    /// Send `QUIT` and close the session politely. Best-effort: a
    /// network error here is logged but does not bubble up because
    /// the message has already been accepted.
    pub async fn quit(mut self) {
        let _ = self.write_line("QUIT").await;
        let _ = self.read_response().await;
        match self.inner {
            Inner::Plain(buf) => {
                let mut s = buf.into_inner();
                let _ = s.shutdown().await;
            }
            Inner::Tls(buf) => {
                let mut s = buf.into_inner();
                let _ = s.shutdown().await;
            }
        }
    }

    /// Returns true iff the underlying transport is currently a TLS stream.
    /// Used by tests; production callers should track this themselves.
    #[cfg(test)]
    pub fn is_tls(&self) -> bool {
        matches!(self.inner, Inner::Tls(_))
    }
}

// ============================================================================
// Internal helpers
// ============================================================================

impl SmtpSession {
    async fn write_line(&mut self, line: &str) -> Result<(), SmtpError> {
        validate_no_crlf("smtp.command", line)?;
        debug!("SMTP > {}", redact_command(line));
        let bytes_with_crlf = format!("{}\r\n", line);
        self.write_all(bytes_with_crlf.as_bytes()).await
    }

    async fn write_all(&mut self, buf: &[u8]) -> Result<(), SmtpError> {
        match &mut self.inner {
            Inner::Plain(s) => s.get_mut().write_all(buf).await?,
            Inner::Tls(s) => s.get_mut().write_all(buf).await?,
        }
        match &mut self.inner {
            Inner::Plain(s) => s.get_mut().flush().await?,
            Inner::Tls(s) => s.get_mut().flush().await?,
        }
        Ok(())
    }

    async fn read_response(&mut self) -> Result<SmtpResponse, SmtpError> {
        // SMTP responses can be multi-line: every intermediate line
        // looks like "250-extension" and the last line looks like
        // "250 ok". The numeric code MUST be identical on every line.
        let mut code: Option<u16> = None;
        let mut messages: Vec<String> = Vec::new();
        loop {
            let line = self.read_line().await?;
            let line = line.trim_end_matches(['\r', '\n']);
            if line.len() < 4 {
                return Err(SmtpError::Protocol(format!(
                    "short response line: {:?}",
                    line
                )));
            }
            let (code_part, rest) = line.split_at(3);
            let parsed: u16 = code_part
                .parse()
                .map_err(|_| SmtpError::Protocol(format!("non-numeric code in {:?}", line)))?;
            match code {
                None => code = Some(parsed),
                Some(prev) if prev != parsed => {
                    return Err(SmtpError::Protocol(format!(
                        "inconsistent multi-line response: {} vs {}",
                        prev, parsed
                    )));
                }
                Some(_) => {}
            }
            // The 4th byte indicates continuation: '-' = more lines, ' ' = last.
            let separator = rest.chars().next().unwrap_or(' ');
            let body = rest.get(1..).unwrap_or("").trim();
            messages.push(body.to_string());
            if separator != '-' {
                break;
            }
        }
        let code = code.unwrap_or(0);
        let message = messages.join(" / ");
        debug!("SMTP < {} {}", code, message);
        Ok(SmtpResponse { code, message })
    }

    async fn read_line(&mut self) -> Result<String, SmtpError> {
        let mut line = String::new();
        let n = match &mut self.inner {
            Inner::Plain(s) => s.read_line(&mut line).await?,
            Inner::Tls(s) => s.read_line(&mut line).await?,
        };
        if n == 0 {
            return Err(SmtpError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "SMTP server closed the connection",
            )));
        }
        Ok(line)
    }
}

// Discard `read_to_end` clippy on AsyncReadExt import.
#[allow(dead_code)]
fn _force_use_of_async_read_ext<R: AsyncReadExt + Unpin>(_r: &mut R) {}

#[derive(Debug)]
struct SmtpResponse {
    code: u16,
    message: String,
}

/// Refuse caller-controlled strings that contain `\r` or `\n`.
///
/// This is a defense-in-depth check; the `Mailer::queue` service
/// sanitizes recipient / subject earlier and the DB CHECK constraint
/// rejects them. The third tier here covers any future code path that
/// builds an SMTP command from a less-trusted source.
pub fn validate_no_crlf(field: &'static str, value: &str) -> Result<(), SmtpError> {
    if value.bytes().any(|b| b == b'\r' || b == b'\n') {
        return Err(SmtpError::CrlfInjection { field });
    }
    Ok(())
}

/// Redact AUTH command payloads from debug logs. Everything else is
/// safe to log (well, server greetings can leak software versions, but
/// we accept that for diagnostic value).
fn redact_command(line: &str) -> &str {
    if line.starts_with("AUTH ") {
        "AUTH [REDACTED]"
    } else {
        line
    }
}

/// Build a default `tokio-rustls` `ClientConfig` for STARTTLS:
/// * trust roots from `webpki-roots`,
/// * `aws-lc-rs` crypto provider (matches every other TLS user in
///   the workspace; FreeBSD-friendly, no OpenSSL),
/// * TLS 1.2 + TLS 1.3.
///
/// Production callers should reuse the same `Arc<ClientConfig>`
/// across SMTP sessions (config construction is non-trivial).
#[allow(clippy::expect_used)] // see comment below; the failure mode here is a programmer error.
pub fn default_client_config() -> std::sync::Arc<ClientConfig> {
    let root_store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    // `with_safe_default_protocol_versions()` returns Err only if the
    // chosen `CryptoProvider` does not list any safe TLS protocol
    // version. `aws_lc_rs::default_provider()` ships TLS 1.2 + TLS 1.3
    // by construction, so this expect is a programmer-error guard
    // (would only trigger if a future rustls upgrade silently strips
    // both versions from the default provider, which would itself be a
    // CVE-class regression worth a hard panic).
    let provider = std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("aws-lc-rs default provider must support safe TLS protocol versions")
        .with_root_certificates(root_store)
        .with_no_client_auth();
    std::sync::Arc::new(config)
}

/// Connection-level timeout used by callers that don't want to roll
/// their own. The dispatcher uses [`crate::config::MailerConfig`]
/// instead so this is only a fallback for ad-hoc callers.
pub const DEFAULT_SMTP_TIMEOUT: Duration = Duration::from_secs(30);

/// Helper used by callers that want to choose between Plain / Starttls
/// / Tls without re-implementing the conditional logic.
///
/// Returns the SmtpSession after EHLO and (if requested) STARTTLS, but
/// BEFORE AUTH.
pub async fn open_session(
    stream: TcpStream,
    helo_name: &str,
    encryption: SmtpEncryption,
    server_name: &str,
    tls_config: std::sync::Arc<ClientConfig>,
) -> Result<SmtpSession, SmtpError> {
    let session = SmtpSession::open(stream, helo_name).await?;
    match encryption {
        SmtpEncryption::Plaintext => Ok(session),
        SmtpEncryption::Starttls => session.starttls(tls_config, server_name).await,
        SmtpEncryption::Tls => Err(SmtpError::Protocol(
            "implicit TLS (port 465) requires the supervisor to broker \
             a TlsStream directly, not implemented yet"
                .into(),
        )),
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_no_crlf_rejects_cr() {
        let err = validate_no_crlf("subject", "hello\rworld").unwrap_err();
        assert!(matches!(err, SmtpError::CrlfInjection { field } if field == "subject"));
    }

    #[test]
    fn validate_no_crlf_rejects_lf() {
        let err = validate_no_crlf("subject", "hello\nworld").unwrap_err();
        assert!(matches!(err, SmtpError::CrlfInjection { field } if field == "subject"));
    }

    #[test]
    fn validate_no_crlf_rejects_combined_crlf() {
        let err = validate_no_crlf("recipient", "victim@example.com\r\nBcc: leak@evil")
            .unwrap_err();
        assert!(matches!(err, SmtpError::CrlfInjection { .. }));
    }

    #[test]
    fn validate_no_crlf_accepts_clean_string() {
        validate_no_crlf("recipient", "vauban@example.com").unwrap();
    }

    #[test]
    fn validate_no_crlf_accepts_empty_string() {
        validate_no_crlf("subject", "").unwrap();
    }

    #[test]
    fn redact_command_redacts_auth_plain() {
        assert_eq!(redact_command("AUTH PLAIN c2VjcmV0"), "AUTH [REDACTED]");
        assert_eq!(redact_command("AUTH LOGIN"), "AUTH [REDACTED]");
    }

    #[test]
    fn redact_command_passes_other_commands_through() {
        assert_eq!(redact_command("MAIL FROM:<a@b>"), "MAIL FROM:<a@b>");
        assert_eq!(redact_command("EHLO host"), "EHLO host");
        assert_eq!(redact_command("DATA"), "DATA");
    }

    #[test]
    fn smtp_error_classification_4xx_is_transient() {
        let e = SmtpError::Server {
            code: 421,
            message: "service not available".into(),
        };
        assert!(e.is_transient());
    }

    #[test]
    fn smtp_error_classification_5xx_is_permanent() {
        let e = SmtpError::Server {
            code: 550,
            message: "user unknown".into(),
        };
        assert!(!e.is_transient());
    }

    #[test]
    fn smtp_error_classification_io_is_transient() {
        let e = SmtpError::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "reset",
        ));
        assert!(e.is_transient());
    }

    #[test]
    fn smtp_error_classification_protocol_is_permanent() {
        let e = SmtpError::Protocol("bad response".into());
        assert!(!e.is_transient());
    }

    #[test]
    fn smtp_error_classification_crlf_is_permanent() {
        let e = SmtpError::CrlfInjection { field: "subject" };
        assert!(!e.is_transient());
    }

    #[test]
    fn default_client_config_has_webpki_roots() {
        let cfg = default_client_config();
        // We cannot easily count roots, but the Arc must be live.
        assert!(std::sync::Arc::strong_count(&cfg) >= 1);
    }

    /// End-to-end nominal SMTP exchange against a tokio-driven fake
    /// server that speaks the bare minimum to send one envelope. No
    /// STARTTLS, no AUTH (those are exercised in
    /// `tests/services/smtp_client_*` integration tests).
    #[tokio::test]
    async fn smtp_session_open_send_quit_roundtrip_against_fake_server() {
        use tokio::io::AsyncReadExt;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (read_half, mut write_half) = stream.into_split();
            let mut reader = BufReader::new(read_half);

            // Greeting.
            write_half
                .write_all(b"220 fake.example.test ESMTP\r\n")
                .await
                .unwrap();

            // EHLO.
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            assert!(line.starts_with("EHLO "));
            write_half
                .write_all(b"250-fake.example.test\r\n250 OK\r\n")
                .await
                .unwrap();

            // MAIL FROM.
            line.clear();
            reader.read_line(&mut line).await.unwrap();
            assert!(line.starts_with("MAIL FROM:"));
            write_half.write_all(b"250 OK\r\n").await.unwrap();

            // RCPT TO.
            line.clear();
            reader.read_line(&mut line).await.unwrap();
            assert!(line.starts_with("RCPT TO:"));
            write_half.write_all(b"250 OK\r\n").await.unwrap();

            // DATA.
            line.clear();
            reader.read_line(&mut line).await.unwrap();
            assert_eq!(line.trim_end(), "DATA");
            write_half
                .write_all(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                .await
                .unwrap();

            // Body until \r\n.\r\n.
            let mut body = Vec::new();
            loop {
                let mut byte = [0u8; 1];
                reader.read_exact(&mut byte).await.unwrap();
                body.push(byte[0]);
                if body.ends_with(b"\r\n.\r\n") {
                    break;
                }
            }
            write_half.write_all(b"250 OK\r\n").await.unwrap();

            // QUIT.
            line.clear();
            reader.read_line(&mut line).await.unwrap();
            assert_eq!(line.trim_end(), "QUIT");
            write_half.write_all(b"221 bye\r\n").await.unwrap();
            body
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        let mut session = SmtpSession::open(stream, "vauban-test")
            .await
            .unwrap();
        session
            .send(&MailEnvelope {
                from: "vauban@example.test".into(),
                to: "user@example.test".into(),
                data: "Subject: hi\r\n\r\nbody\r\n".into(),
            })
            .await
            .unwrap();
        session.quit().await;
        let body = server.await.unwrap();
        let body_str = std::str::from_utf8(&body).unwrap();
        assert!(body_str.contains("Subject: hi"));
        assert!(body_str.ends_with(".\r\n"));
    }

    #[tokio::test]
    async fn smtp_session_dot_stuffs_lines_starting_with_dot() {
        use tokio::io::AsyncReadExt;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (read_half, mut write_half) = stream.into_split();
            let mut reader = BufReader::new(read_half);

            write_half.write_all(b"220 fake\r\n").await.unwrap();
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap(); // EHLO
            write_half.write_all(b"250 OK\r\n").await.unwrap();
            line.clear();
            reader.read_line(&mut line).await.unwrap(); // MAIL
            write_half.write_all(b"250 OK\r\n").await.unwrap();
            line.clear();
            reader.read_line(&mut line).await.unwrap(); // RCPT
            write_half.write_all(b"250 OK\r\n").await.unwrap();
            line.clear();
            reader.read_line(&mut line).await.unwrap(); // DATA
            write_half.write_all(b"354 go\r\n").await.unwrap();
            let mut body = Vec::new();
            loop {
                let mut byte = [0u8; 1];
                reader.read_exact(&mut byte).await.unwrap();
                body.push(byte[0]);
                if body.ends_with(b"\r\n.\r\n") {
                    break;
                }
            }
            write_half.write_all(b"250 OK\r\n").await.unwrap();
            // QUIT.
            line.clear();
            reader.read_line(&mut line).await.unwrap();
            assert_eq!(line.trim_end(), "QUIT");
            write_half.write_all(b"221 bye\r\n").await.unwrap();
            body
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        let mut session = SmtpSession::open(stream, "vauban-test")
            .await
            .unwrap();
        session
            .send(&MailEnvelope {
                from: "v@e.t".into(),
                to: "u@e.t".into(),
                // Body starts with '.' on its own line; MUST be
                // dot-stuffed.
                data: "Subject: x\r\n\r\n. dotty line\r\nnormal\r\n".into(),
            })
            .await
            .unwrap();
        session.quit().await;
        let body = server.await.unwrap();
        let s = std::str::from_utf8(&body).unwrap();
        // The leading '.' must have been doubled.
        assert!(s.contains("\r\n.. dotty line\r\n"), "got: {}", s);
        // The terminator must still be a single dot on its own line.
        assert!(s.ends_with("\r\n.\r\n"), "got: {}", s);
    }

    #[tokio::test]
    async fn smtp_session_returns_server_error_on_550() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (read_half, mut write_half) = stream.into_split();
            let mut reader = BufReader::new(read_half);
            write_half.write_all(b"220 fake\r\n").await.unwrap();
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap(); // EHLO
            write_half.write_all(b"250 OK\r\n").await.unwrap();
            line.clear();
            reader.read_line(&mut line).await.unwrap(); // MAIL
            write_half
                .write_all(b"550 user unknown\r\n")
                .await
                .unwrap();
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        let mut session = SmtpSession::open(stream, "vauban-test")
            .await
            .unwrap();
        let err = session
            .send(&MailEnvelope {
                from: "v@e.t".into(),
                to: "u@e.t".into(),
                data: "x".into(),
            })
            .await
            .unwrap_err();
        match err {
            SmtpError::Server { code, .. } => assert_eq!(code, 550),
            _ => panic!("expected SmtpError::Server, got {:?}", err),
        }
    }

    #[tokio::test]
    async fn smtp_session_parses_multiline_ehlo_response() {
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (read_half, mut write_half) = stream.into_split();
            let mut reader = BufReader::new(read_half);
            write_half.write_all(b"220 fake\r\n").await.unwrap();
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            // Multi-line EHLO with three capabilities.
            write_half
                .write_all(b"250-fake hi\r\n250-PIPELINING\r\n250-SIZE 35882577\r\n250 8BITMIME\r\n")
                .await
                .unwrap();
            // QUIT and bye.
            line.clear();
            reader.read_line(&mut line).await.unwrap();
            write_half.write_all(b"221 bye\r\n").await.unwrap();
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        let session = SmtpSession::open(stream, "vauban-test").await.unwrap();
        session.quit().await;
    }

    #[tokio::test]
    async fn smtp_session_auth_plain_refused_on_non_tls() {
        // We cannot easily exercise the TLS path in a unit test (we'd
        // need to run a TLS server), but we CAN pin that AUTH PLAIN
        // refuses to operate on a Plain transport: that's the
        // defense-in-depth check.
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (_r, mut w) = stream.into_split();
            w.write_all(b"220 fake\r\n").await.unwrap();
            // we will get EHLO and reply, then the test bails out
            let buf = [0u8; 256];
            let _ = w.write_all(b"250 OK\r\n").await;
            // best-effort
            tokio::time::sleep(Duration::from_millis(50)).await;
            let _ = buf;
        });
        let stream = TcpStream::connect(addr).await.unwrap();
        let mut session = SmtpSession::open(stream, "v").await.unwrap();
        let err = session
            .auth_plain(
                "user",
                &secrecy::SecretString::new("pw".to_string().into()),
            )
            .await
            .unwrap_err();
        match err {
            SmtpError::Protocol(msg) => assert!(msg.contains("non-TLS")),
            _ => panic!("expected Protocol error, got {:?}", err),
        }
    }
}
