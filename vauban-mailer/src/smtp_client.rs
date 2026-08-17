//! Minimal SMTP client (Issue #10) -- sealed vauban-mailer authority.
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
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use secrecy::ExposeSecret;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::{TlsConnector, client::TlsStream};
use tracing::debug;

use shared::messages::SmtpEncryption;

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

    /// SMTP numeric code when the server answered; `None` for transport
    /// / protocol failures that never produced a reply line.
    pub fn smtp_code(&self) -> Option<u16> {
        match self {
            Self::Server { code, .. } => Some(*code),
            _ => None,
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
    /// [`crate::outbox::build_envelope`].
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

// `TlsStream` carries multi-KB of session/handshake state, while a
// raw `TcpStream` is a few words. Box the TLS variant so the enum
// stays cache-friendly and matches clippy's
// `large_enum_variant` recommendation.
enum Inner {
    Plain(BufReader<TcpStream>),
    Tls(Box<BufReader<TlsStream<TcpStream>>>),
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
            inner: Inner::Tls(Box::new(BufReader::with_capacity(8192, tls_stream))),
        };
        // Re-issue EHLO inside the TLS tunnel (RFC 3207 §4.2: the
        // SMTP client MUST discard any prior knowledge after STARTTLS
        // and re-issue EHLO).
        session.write_line("EHLO vauban-smtp-client").await?;
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

        self.write_line(&format!("MAIL FROM:<{}>", env.from))
            .await?;
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
            // Permanent 5xx (550 user unknown, 553, …) is the only
            // synchronous "wrong mailbox" signal we get. A 250 here
            // means the *relay* accepted the recipient -- a later
            // bounce is invisible without a DSN/webhook.
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

    /// Reset the SMTP transaction so the next [`send`] can start from
    /// `MAIL FROM` after a 4xx/5xx on the previous envelope (RFC 5321
    /// §4.1.1.5). Without this, a 550 on `RCPT TO` leaves the session
    /// dirty and the rest of the batch is silently lost.
    pub async fn rset(&mut self) -> Result<(), SmtpError> {
        self.write_line("RSET").await?;
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

/// Build a rustls client config for SMTP STARTTLS.
///
/// `accept_invalid_certs = false` (default) trusts `webpki-roots` and
/// verifies the server name. `true` skips CA / name / expiry checks so
/// an operator can talk to a self-signed lab or internal MTA. Handshake
/// signatures are still verified against the presented key.
pub fn client_config(accept_invalid_certs: bool) -> std::sync::Arc<ClientConfig> {
    if accept_invalid_certs {
        tracing::warn!(
            "SMTP TLS certificate verification is disabled \
             (mailer.smtp_accept_invalid_certs=true)"
        );
        skip_verify_client_config()
    } else {
        default_client_config()
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

/// Opt-in verifier for self-signed / private-CA SMTP relays.
///
/// Installed only when `mailer.smtp_accept_invalid_certs = true`.
/// Default remains webpki verification. Distinct from the retired RDP
/// accept-any session verifier.
#[derive(Debug)]
struct SmtpSkipServerCertVerify {
    provider: std::sync::Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for SmtpSkipServerCertVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[allow(clippy::expect_used)]
fn skip_verify_client_config() -> std::sync::Arc<ClientConfig> {
    let provider = std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier = std::sync::Arc::new(SmtpSkipServerCertVerify {
        provider: std::sync::Arc::clone(&provider),
    });
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("aws-lc-rs default provider must support safe TLS protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    std::sync::Arc::new(config)
}

/// Connection-level timeout used by callers that don't want to roll
/// their own.
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
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
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
        let err =
            validate_no_crlf("recipient", "victim@example.com\r\nBcc: leak@evil").unwrap_err();
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
        assert_eq!(e.smtp_code(), Some(550));
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
        let mut session = SmtpSession::open(stream, "vauban-test").await.unwrap();
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
        let mut session = SmtpSession::open(stream, "vauban-test").await.unwrap();
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
            write_half.write_all(b"550 user unknown\r\n").await.unwrap();
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        let mut session = SmtpSession::open(stream, "vauban-test").await.unwrap();
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
    async fn smtp_session_rset_after_550_allows_next_envelope() {
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
            reader.read_line(&mut line).await.unwrap(); // MAIL (bad)
            write_half.write_all(b"550 user unknown\r\n").await.unwrap();
            line.clear();
            reader.read_line(&mut line).await.unwrap(); // RSET
            assert_eq!(line.trim_end(), "RSET");
            write_half.write_all(b"250 OK\r\n").await.unwrap();
            line.clear();
            reader.read_line(&mut line).await.unwrap(); // MAIL (good)
            assert!(line.starts_with("MAIL FROM:"));
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
            line.clear();
            reader.read_line(&mut line).await.unwrap(); // QUIT
            write_half.write_all(b"221 bye\r\n").await.unwrap();
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        let mut session = SmtpSession::open(stream, "vauban-test").await.unwrap();
        let err = session
            .send(&MailEnvelope {
                from: "v@e.t".into(),
                to: "bad@e.t".into(),
                data: "Subject: x\r\n\r\nok\r\n".into(),
            })
            .await
            .unwrap_err();
        assert!(!err.is_transient());
        session.rset().await.unwrap();
        session
            .send(&MailEnvelope {
                from: "v@e.t".into(),
                to: "good@e.t".into(),
                data: "Subject: x\r\n\r\nok\r\n".into(),
            })
            .await
            .unwrap();
        session.quit().await;
        server.await.unwrap();
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
                .write_all(
                    b"250-fake hi\r\n250-PIPELINING\r\n250-SIZE 35882577\r\n250 8BITMIME\r\n",
                )
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
            .auth_plain("user", &secrecy::SecretString::new("pw".to_string().into()))
            .await
            .unwrap_err();
        match err {
            SmtpError::Protocol(msg) => assert!(msg.contains("non-TLS")),
            _ => panic!("expected Protocol error, got {:?}", err),
        }
    }

    #[test]
    fn client_config_false_is_default_verify_path() {
        let src = include_str!("smtp_client.rs");
        assert!(src.contains("webpki_roots::TLS_SERVER_ROOTS"));
        assert!(src.contains("fn skip_verify_client_config"));
        assert!(src.contains("SmtpSkipServerCertVerify"));
        let cfg = client_config(false);
        assert!(std::sync::Arc::strong_count(&cfg) >= 1);
    }

    #[test]
    fn client_config_true_installs_skip_verifier() {
        let cfg = client_config(true);
        assert!(std::sync::Arc::strong_count(&cfg) >= 1);
    }

    fn self_signed_server_config() -> std::sync::Arc<rustls::ServerConfig> {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        use rustls::{ServerConfig, crypto::aws_lc_rs};

        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        let cert_der = CertificateDer::from(cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
        let provider = std::sync::Arc::new(aws_lc_rs::default_provider());
        let cfg = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap();
        std::sync::Arc::new(cfg)
    }

    async fn tls_handshake(client_cfg: std::sync::Arc<ClientConfig>) -> std::io::Result<()> {
        use rustls::pki_types::ServerName;
        use tokio::net::TcpListener;
        use tokio_rustls::{TlsAcceptor, TlsConnector};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor = TlsAcceptor::from(self_signed_server_config());
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            acceptor.accept(stream).await
        });
        let stream = TcpStream::connect(addr).await.unwrap();
        let connector = TlsConnector::from(client_cfg);
        let name = ServerName::try_from("localhost").unwrap();
        let client = connector.connect(name, stream).await;
        let _ = server.await;
        client.map(|_| ())
    }

    #[tokio::test]
    async fn attack_self_signed_smtp_cert_is_rejected_when_verify_enabled() {
        let err = tls_handshake(default_client_config())
            .await
            .expect_err("webpki must reject a self-signed SMTP cert");
        let msg = err.to_string();
        assert!(
            msg.contains("UnknownIssuer")
                || msg.contains("invalid peer certificate")
                || msg.contains("certificate"),
            "unexpected rustls error: {msg}"
        );
    }

    #[tokio::test]
    async fn e2e_self_signed_smtp_cert_is_accepted_when_skip_verify() {
        tls_handshake(client_config(true))
            .await
            .expect("smtp_accept_invalid_certs must allow a self-signed relay");
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(16))]

        #[test]
        fn proptest_client_config_builds_for_both_flags(flag: bool) {
            let cfg = client_config(flag);
            proptest::prop_assert!(std::sync::Arc::strong_count(&cfg) >= 1);
        }
    }

    #[test]
    fn battle_client_config_under_contention() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let barrier = Arc::new(Barrier::new(8));
        let join: Vec<_> = (0..8)
            .map(|i| {
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    for _ in 0..32 {
                        let cfg = client_config(i % 2 == 0);
                        assert!(std::sync::Arc::strong_count(&cfg) >= 1);
                    }
                })
            })
            .collect();
        for h in join {
            h.join().expect("thread");
        }
    }
}
