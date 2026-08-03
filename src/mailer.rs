//! SMTP transport builder and transactional mail helpers (magic links).

use std::sync::Arc;

use topcoat::{
    Result,
    context::{Cx, app_context},
    mail::{Mail, Mailbox, SmtpTransport, send},
};

use crate::config::{Config, MagicLinksConfig, MailConfig, SmtpEncryption};

/// Build a Topcoat [`SmtpTransport`] from `[mail]` settings.
pub fn build_smtp_transport(cfg: &MailConfig) -> anyhow::Result<SmtpTransport> {
    let host = cfg.smtp_host.trim();
    if host.is_empty() {
        anyhow::bail!("mail.smtp_host must not be empty");
    }

    let mut builder = match cfg.smtp_encryption {
        SmtpEncryption::Plaintext => SmtpTransport::unencrypted(host),
        SmtpEncryption::Starttls => SmtpTransport::starttls(host)
            .map_err(|e| anyhow::anyhow!("SMTP STARTTLS setup failed: {e}"))?,
        SmtpEncryption::Tls => {
            SmtpTransport::relay(host).map_err(|e| anyhow::anyhow!("SMTP TLS setup failed: {e}"))?
        }
    };

    builder = builder.port(cfg.smtp_port);
    if !cfg.smtp_username.is_empty() {
        builder = builder.credentials(&cfg.smtp_username, &cfg.smtp_password);
    }
    Ok(builder.build())
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
    let receipt = send(cx, builder.build()).await?;
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

/// Encryption mode selected for a given [`MailConfig`] (unit / invariant tests).
pub fn encryption_mode(cfg: &MailConfig) -> SmtpEncryption {
    cfg.smtp_encryption
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SmtpEncryption;

    // SmtpTransport pool Drop needs a Tokio runtime (lettre Tokio1Executor).
    #[tokio::test]
    async fn build_smtp_plaintext_mailpit_shape() {
        let cfg = MailConfig {
            smtp_host: "localhost".to_owned(),
            smtp_port: 1025,
            smtp_encryption: SmtpEncryption::Plaintext,
            smtp_username: String::new(),
            smtp_password: String::new(),
        };
        assert_eq!(encryption_mode(&cfg), SmtpEncryption::Plaintext);
        let _transport = build_smtp_transport(&cfg).expect("plaintext builder");
    }

    #[tokio::test]
    async fn build_smtp_starttls_tem_shape() {
        let cfg = MailConfig {
            smtp_host: "smtp.tem.scaleway.com".to_owned(),
            smtp_port: 587,
            smtp_encryption: SmtpEncryption::Starttls,
            smtp_username: "project-id".to_owned(),
            smtp_password: "secret".to_owned(),
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
}
