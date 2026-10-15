//! The authenticator app of every test account: remembers the secret shown
//! at enrolment and never hands out the same time-step twice (Vauban
//! rejects a replayed code).

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use totp_rs::{Algorithm, Secret, TOTP};

const STEP: u64 = 30;

#[derive(Default)]
pub struct Authenticator {
    accounts: Mutex<HashMap<String, (String, u64)>>,
}

impl Authenticator {
    pub fn enrol(&self, user: &str, base32: &str) {
        self.accounts
            .lock()
            .expect("authenticator lock")
            .insert(user.to_string(), (base32.trim().to_string(), 0));
    }

    pub fn knows(&self, user: &str) -> bool {
        self.accounts
            .lock()
            .expect("authenticator lock")
            .contains_key(user)
    }

    /// A code from a time-step this account has not used yet.
    pub async fn code(&self, user: &str) -> Result<String> {
        loop {
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            let step = now / STEP;
            let wait = {
                let mut accounts = self.accounts.lock().expect("authenticator lock");
                let (secret, last) = accounts
                    .get_mut(user)
                    .with_context(|| format!("{user} never enrolled"))?;
                if *last < step {
                    *last = step;
                    let bytes = Secret::Encoded(secret.clone())
                        .to_bytes()
                        .map_err(|e| anyhow::anyhow!("bad base32 secret: {e:?}"))?;
                    let totp = TOTP::new_unchecked(Algorithm::SHA1, 6, 1, STEP, bytes);
                    return Ok(totp.generate(now));
                }
                (step + 1) * STEP - now
            };
            tokio::time::sleep(Duration::from_secs(wait) + Duration::from_millis(200)).await;
        }
    }
}
