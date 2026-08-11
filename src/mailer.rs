//! SMTP transport builder and transactional mail helpers (magic links).

use std::str::FromStr;
use std::sync::Arc;

use lettre::{
    Address, AsyncSmtpTransport, AsyncTransport, Tokio1Executor,
    address::Envelope,
    transport::smtp::{
        authentication::Credentials,
        client::{Tls, TlsParameters},
    },
};
use topcoat::{
    Result,
    context::{Cx, app_context, try_app_context},
    mail::{Mail, Mailbox, Receipt, SendError, Transport, TransportFuture, send},
};

use crate::{
    config::{Config, MagicLinksConfig, MailConfig, SmtpEncryption},
    mail_circuit::MailCircuitBreaker,
};

/// lettre-backed SMTP transport configured from `[mail]`.
///
/// Topcoat's `SmtpTransport` builder does not expose certificate-verification
/// knobs; this type sets `TlsParameters` (including
/// `dangerous_accept_invalid_certs`) for both STARTTLS and implicit TLS.
pub struct ConfiguredSmtpTransport {
    inner: AsyncSmtpTransport<Tokio1Executor>,
}

impl Transport for ConfiguredSmtpTransport {
    fn send<'a>(&'a self, cx: &'a Cx, mail: Mail) -> TransportFuture<'a> {
        Box::pin(async move {
            let raw = mail.formatted(cx)?;
            let envelope = smtp_envelope(&mail).map_err(SendError::delivery)?;
            self.inner
                .send_raw(&envelope, &raw)
                .await
                .map_err(SendError::delivery)?;
            Ok(Receipt::new(message_id_from_raw(&raw)))
        })
    }
}

/// Build an SMTP transport from `[mail]` settings.
pub fn build_smtp_transport(cfg: &MailConfig) -> anyhow::Result<ConfiguredSmtpTransport> {
    let host = cfg.smtp_host.trim();
    if host.is_empty() {
        anyhow::bail!("mail.smtp_host must not be empty");
    }

    if cfg.smtp_accept_invalid_certs {
        tracing::warn!(
            smtp_host = %host,
            smtp_encryption = cfg.smtp_encryption.as_str(),
            "mail.smtp_accept_invalid_certs=true: SMTP peer certificates are not verified"
        );
    }

    let mut builder = match cfg.smtp_encryption {
        SmtpEncryption::Plaintext => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host),
        SmtpEncryption::Starttls => {
            let params = tls_parameters(host, cfg.smtp_accept_invalid_certs)?;
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host).tls(Tls::Required(params))
        }
        SmtpEncryption::Tls => {
            let params = tls_parameters(host, cfg.smtp_accept_invalid_certs)?;
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host).tls(Tls::Wrapper(params))
        }
    };

    builder = builder.port(cfg.smtp_port);
    if !cfg.smtp_username.is_empty() {
        builder = builder.credentials(Credentials::new(
            cfg.smtp_username.clone(),
            cfg.smtp_password.clone(),
        ));
    }

    Ok(ConfiguredSmtpTransport {
        inner: builder.build(),
    })
}

fn tls_parameters(host: &str, accept_invalid: bool) -> anyhow::Result<TlsParameters> {
    if accept_invalid {
        TlsParameters::builder(host.to_owned())
            .dangerous_accept_invalid_certs(true)
            .build()
            .map_err(|e| anyhow::anyhow!("SMTP TLS parameters failed: {e}"))
    } else {
        TlsParameters::new(host.to_owned())
            .map_err(|e| anyhow::anyhow!("SMTP TLS parameters failed: {e}"))
    }
}

fn smtp_envelope(
    mail: &Mail,
) -> std::result::Result<Envelope, Box<dyn std::error::Error + Send + Sync>> {
    let from = mail
        .from()
        .ok_or_else(|| "mail has no From address".to_owned())?;
    let from_addr = Address::from_str(from.address())?;
    let mut recipients = Vec::new();
    for mb in mail.to().iter().chain(mail.cc()).chain(mail.bcc()) {
        recipients.push(Address::from_str(mb.address())?);
    }
    Ok(Envelope::new(Some(from_addr), recipients)?)
}

fn message_id_from_raw(raw: &[u8]) -> String {
    let text = String::from_utf8_lossy(raw);
    for line in text.lines() {
        if line.len() >= 11 && line[..11].eq_ignore_ascii_case("message-id:") {
            return line[11..].trim().to_owned();
        }
    }
    "<unknown@localhost>".to_owned()
}

fn from_mailbox(ml: &MagicLinksConfig) -> Result<Mailbox> {
    if ml.from_name.trim().is_empty() {
        Ok(Mailbox::new(ml.from_address.trim())?)
    } else {
        Ok(Mailbox::named(ml.from_name.trim(), ml.from_address.trim())?)
    }
}

fn reply_to_mailbox(ml: &MagicLinksConfig) -> Result<Option<Mailbox>> {
    let reply = ml.reply_to.trim();
    if reply.is_empty() {
        return Ok(None);
    }
    Ok(Some(Mailbox::new(reply)?))
}

fn magic_link_url(public_origin: &str, raw_token: &str) -> String {
    let origin = public_origin.trim_end_matches('/');
    format!("{origin}/login/magic?token={raw_token}")
}

/// Sign-in magic link (login form request).
pub async fn send_login_magic_link(
    cx: &Cx,
    ml: &MagicLinksConfig,
    public_origin: &str,
    to_email: &str,
    raw_token: &str,
) -> Result<()> {
    let url = magic_link_url(public_origin, raw_token);
    let body = format!(
        "Sign in to the Vauban Customer Portal:\n\n{url}\n\n\
         This link expires in {} minutes and can be used only once.\n\
         If you did not request this, you can ignore this email.\n",
        ml.token_ttl_secs.div_ceil(60)
    );
    send_text_mail(cx, ml, to_email, "Sign in to Vauban Customer Portal", &body).await
}

/// Invitation when a company account is created or revived.
pub async fn send_invitation_mail(
    cx: &Cx,
    ml: &MagicLinksConfig,
    public_origin: &str,
    to_email: &str,
    org_name: &str,
    raw_token: &str,
) -> Result<()> {
    let url = magic_link_url(public_origin, raw_token);
    let body = format!(
        "You have been invited to the Vauban Customer Portal for {org_name}.\n\n\
         Sign in with this link:\n\n{url}\n\n\
         This link expires in {} minutes and can be used only once.\n",
        ml.token_ttl_secs.div_ceil(60)
    );
    send_text_mail(
        cx,
        ml,
        to_email,
        &format!("Invitation to {org_name} — Vauban Customer Portal"),
        &body,
    )
    .await
}

/// Access revoked when a company membership is removed (org-scoped notice).
pub async fn send_revocation_mail(
    cx: &Cx,
    ml: &MagicLinksConfig,
    to_email: &str,
    org_name: &str,
) -> Result<()> {
    let body = format!(
        "Your access to the Vauban Customer Portal for {org_name} has been removed.\n\n\
         If you believe this is a mistake, contact your administrator.\n"
    );
    send_text_mail(
        cx,
        ml,
        to_email,
        &format!("Access removed — {org_name}"),
        &body,
    )
    .await
}

async fn send_text_mail(
    cx: &Cx,
    ml: &MagicLinksConfig,
    to_email: &str,
    subject: &str,
    body: &str,
) -> Result<()> {
    let from = from_mailbox(ml)?;
    let to = Mailbox::new(to_email.trim())?;
    let mut builder = Mail::builder()
        .from(from)
        .to([to])
        .subject(subject)
        .text(body);
    if let Some(reply) = reply_to_mailbox(ml)? {
        builder = builder.reply_to([reply]);
    }
    match send(cx, builder.build()).await {
        Ok(receipt) => {
            if let Some(breaker) = try_app_context::<Arc<MailCircuitBreaker>>(cx) {
                breaker.record_success();
            }
            let mail = &app_context::<Arc<Config>>(cx).mail;
            tracing::debug!(
                to = %to_email,
                smtp_host = %mail.smtp_host,
                smtp_port = mail.smtp_port,
                smtp_encryption = mail.smtp_encryption.as_str(),
                message_id = %receipt.message_id(),
                "smtp mail delivered"
            );
            Ok(())
        }
        Err(err) => {
            if let Some(breaker) = try_app_context::<Arc<MailCircuitBreaker>>(cx) {
                breaker.record_failure();
            }
            tracing::error!(
                to = %to_email,
                error = %err,
                "failed to send transactional mail"
            );
            Err(err)
        }
    }
}

/// Encryption mode selected for a given [`MailConfig`] (unit / invariant tests).
pub fn encryption_mode(cfg: &MailConfig) -> SmtpEncryption {
    cfg.smtp_encryption
}

/// Whether peer certificate verification is disabled (unit / invariant tests).
pub fn accepts_invalid_certs(cfg: &MailConfig) -> bool {
    cfg.smtp_accept_invalid_certs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SmtpEncryption;
    use std::sync::{Arc, Barrier};
    use std::thread;

    fn sample_mail(encryption: SmtpEncryption, accept_invalid: bool, port: u16) -> MailConfig {
        MailConfig {
            smtp_host: "localhost".to_owned(),
            smtp_port: port,
            smtp_encryption: encryption,
            smtp_username: String::new(),
            smtp_password: String::new(),
            smtp_accept_invalid_certs: accept_invalid,
            circuit_failure_threshold: 3,
            circuit_open_secs: 60,
        }
    }

    // AsyncSmtpTransport pool Drop needs a Tokio runtime.
    #[tokio::test]
    async fn build_smtp_plaintext_mailpit_shape() {
        let cfg = sample_mail(SmtpEncryption::Plaintext, false, 1025);
        assert_eq!(encryption_mode(&cfg), SmtpEncryption::Plaintext);
        assert!(!accepts_invalid_certs(&cfg));
        let _transport = build_smtp_transport(&cfg).expect("plaintext builder");
    }

    #[tokio::test]
    async fn build_smtp_starttls_with_and_without_accept_invalid() {
        for accept in [false, true] {
            let cfg = sample_mail(SmtpEncryption::Starttls, accept, 587);
            assert_eq!(encryption_mode(&cfg), SmtpEncryption::Starttls);
            assert_eq!(accepts_invalid_certs(&cfg), accept);
            let _transport = build_smtp_transport(&cfg).expect("starttls builder");
        }
    }

    #[tokio::test]
    async fn build_smtp_tls_with_and_without_accept_invalid() {
        for accept in [false, true] {
            let cfg = sample_mail(SmtpEncryption::Tls, accept, 465);
            assert_eq!(encryption_mode(&cfg), SmtpEncryption::Tls);
            assert_eq!(accepts_invalid_certs(&cfg), accept);
            let _transport = build_smtp_transport(&cfg).expect("tls builder");
        }
    }

    #[tokio::test]
    async fn build_smtp_starttls_tem_shape() {
        let cfg = MailConfig {
            smtp_host: "smtp.tem.scaleway.com".to_owned(),
            smtp_port: 587,
            smtp_encryption: SmtpEncryption::Starttls,
            smtp_username: "project-id".to_owned(),
            smtp_password: "secret".to_owned(),
            smtp_accept_invalid_certs: false,
            circuit_failure_threshold: 3,
            circuit_open_secs: 60,
        };
        assert_eq!(encryption_mode(&cfg), SmtpEncryption::Starttls);
        let _transport = build_smtp_transport(&cfg).expect("starttls builder");
    }

    #[tokio::test]
    async fn build_smtp_tls_shape() {
        let cfg = MailConfig {
            smtp_host: "smtp.tem.scaleway.com".to_owned(),
            smtp_port: 465,
            smtp_encryption: SmtpEncryption::Tls,
            smtp_username: "project-id".to_owned(),
            smtp_password: "secret".to_owned(),
            smtp_accept_invalid_certs: false,
            circuit_failure_threshold: 3,
            circuit_open_secs: 60,
        };
        assert_eq!(encryption_mode(&cfg), SmtpEncryption::Tls);
        let _transport = build_smtp_transport(&cfg).expect("tls builder");
    }

    #[test]
    fn magic_link_url_strips_trailing_slash() {
        assert_eq!(
            magic_link_url("https://access.vauban.sh/", "abc"),
            "https://access.vauban.sh/login/magic?token=abc"
        );
    }

    #[test]
    fn message_id_parser_reads_header() {
        let raw = b"From: a@b\r\nMessage-ID: <x@y>\r\n\r\nbody";
        assert_eq!(message_id_from_raw(raw), "<x@y>");
    }

    #[test]
    fn battle_parallel_build_smtp_transport() {
        let barrier = Arc::new(Barrier::new(4));
        let mut handles = Vec::new();
        for (enc, accept) in [
            (SmtpEncryption::Starttls, false),
            (SmtpEncryption::Starttls, true),
            (SmtpEncryption::Tls, false),
            (SmtpEncryption::Tls, true),
        ] {
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("runtime");
                barrier.wait();
                let cfg = sample_mail(
                    enc,
                    accept,
                    if enc == SmtpEncryption::Tls { 465 } else { 587 },
                );
                rt.block_on(async {
                    build_smtp_transport(&cfg).expect("build ok");
                });
            }));
        }
        for h in handles {
            h.join().expect("thread");
        }
    }
}
