//! Wait for supervisor `MailerSmtpProvision` before sandbox seal.

use std::time::{Duration, Instant};

use anyhow::Context;
use secrecy::SecretString;
use shared::ipc::{IpcChannel, poll_readable};
use shared::messages::{Message, SensitiveString, SmtpEncryption};

/// Runtime mailer configuration built from the supervisor provision message.
#[derive(Clone)]
pub struct MailerRuntime {
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_encryption: SmtpEncryption,
    pub smtp_username: String,
    pub smtp_password: SecretString,
    pub helo_name: String,
    pub from_address: String,
    pub from_name: String,
    pub reply_to: String,
    pub poll_interval_secs: u64,
    pub batch_size: i64,
    pub max_attempts: i32,
    pub smtp_timeout_secs: u64,
    pub broker_timeout_secs: u64,
}

impl MailerRuntime {
    pub fn effective_helo(&self) -> &str {
        if self.helo_name.is_empty() {
            "vauban"
        } else {
            self.helo_name.as_str()
        }
    }
}

impl From<MailerSmtpProvisionFields> for MailerRuntime {
    fn from(p: MailerSmtpProvisionFields) -> Self {
        Self {
            smtp_host: p.smtp_host,
            smtp_port: p.smtp_port,
            smtp_encryption: p.smtp_encryption,
            smtp_username: p.smtp_username,
            smtp_password: SecretString::from(p.smtp_password.as_str().to_string()),
            helo_name: p.helo_name,
            from_address: p.from_address,
            from_name: p.from_name,
            reply_to: p.reply_to,
            poll_interval_secs: p.poll_interval_secs,
            batch_size: p.batch_size,
            max_attempts: p.max_attempts,
            smtp_timeout_secs: p.smtp_timeout_secs,
            broker_timeout_secs: p.broker_timeout_secs,
        }
    }
}

struct MailerSmtpProvisionFields {
    smtp_host: String,
    smtp_port: u16,
    smtp_encryption: SmtpEncryption,
    smtp_username: String,
    smtp_password: SensitiveString,
    helo_name: String,
    from_address: String,
    from_name: String,
    reply_to: String,
    poll_interval_secs: u64,
    batch_size: i64,
    max_attempts: i32,
    smtp_timeout_secs: u64,
    broker_timeout_secs: u64,
}

/// Block (pre-seal) until the supervisor sends `MailerSmtpProvision`.
pub fn wait_for_mailer_provision(supervisor: &IpcChannel) -> anyhow::Result<MailerRuntime> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            anyhow::bail!("timed out waiting for MailerSmtpProvision from supervisor");
        }
        let ms = remaining.as_millis().min(i32::MAX as u128) as i32;
        let ready = poll_readable(&[supervisor.read_fd()], ms)
            .context("poll error while waiting for MailerSmtpProvision")?;
        if ready.is_empty() {
            continue;
        }
        match supervisor.recv() {
            Ok(Message::MailerSmtpProvision {
                smtp_host,
                smtp_port,
                smtp_encryption,
                smtp_username,
                smtp_password,
                helo_name,
                from_address,
                from_name,
                reply_to,
                poll_interval_secs,
                batch_size,
                max_attempts,
                smtp_timeout_secs,
                broker_timeout_secs,
            }) => {
                return Ok(MailerRuntime::from(MailerSmtpProvisionFields {
                    smtp_host,
                    smtp_port,
                    smtp_encryption,
                    smtp_username,
                    smtp_password,
                    helo_name,
                    from_address,
                    from_name,
                    reply_to,
                    poll_interval_secs,
                    batch_size,
                    max_attempts,
                    smtp_timeout_secs,
                    broker_timeout_secs,
                }));
            }
            Ok(_) => continue,
            Err(e) => anyhow::bail!("IPC error while awaiting MailerSmtpProvision: {e}"),
        }
    }
}
