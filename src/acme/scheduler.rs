//! ACME certificate renewal scheduler (ported from Vauban; in-process renew).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::time::Duration;

use tokio::sync::Notify;
use tracing::{error, info, warn};

use crate::acme::worker::{RenewRequest, renew};
use crate::config::AcmeConfig;
use crate::tls::AcmeResolver;

#[derive(Debug)]
pub struct CertInfo {
    pub not_after_epoch: i64,
    pub self_signed: bool,
}

pub struct CertExpiry {
    not_after_epoch: AtomicI64,
    self_signed: AtomicBool,
    waker: Notify,
}

impl CertExpiry {
    pub fn new(info: CertInfo) -> Self {
        Self {
            not_after_epoch: AtomicI64::new(info.not_after_epoch),
            self_signed: AtomicBool::new(info.self_signed),
            waker: Notify::new(),
        }
    }

    pub fn seconds_remaining(&self) -> i64 {
        let not_after = self.not_after_epoch.load(Ordering::Relaxed);
        let now = chrono::Utc::now().timestamp();
        not_after - now
    }

    pub fn days_remaining(&self) -> u32 {
        let secs = self.seconds_remaining();
        if secs <= 0 { 0 } else { (secs / 86400) as u32 }
    }

    /// Days until notAfter for operator logs. `None` when the cert is
    /// self-signed: rcgen bootstrap PEMs use a multi-century notAfter, so a
    /// raw day count (e.g. 755831) is noise.
    pub fn days_remaining_for_log(&self) -> Option<u32> {
        if self.is_self_signed() {
            None
        } else {
            Some(self.days_remaining())
        }
    }

    pub fn is_self_signed(&self) -> bool {
        self.self_signed.load(Ordering::Relaxed)
    }

    pub fn update_from_der(&self, cert_der: &[u8]) {
        match parse_x509_cert_info(cert_der) {
            Ok(info) => {
                self.not_after_epoch
                    .store(info.not_after_epoch, Ordering::Relaxed);
                self.self_signed.store(info.self_signed, Ordering::Relaxed);
                log_cert_metadata_updated(self);
                self.waker.notify_one();
            }
            Err(e) => warn!(error = %e, "Failed to parse metadata from new certificate"),
        }
    }

    pub async fn notified(&self) {
        self.waker.notified().await;
    }
}

pub fn extract_cert_info(cert_path: &str) -> Result<CertInfo, String> {
    use rustls_pki_types::CertificateDer;
    use rustls_pki_types::pem::PemObject;
    use std::fs::File;
    use std::io::BufReader;

    let file = File::open(cert_path).map_err(|e| format!("Cannot open {cert_path}: {e}"))?;
    let mut reader = BufReader::new(file);
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_reader_iter(&mut reader)
        .filter_map(|c| c.ok())
        .collect();
    let cert_der = certs
        .first()
        .ok_or_else(|| "No certificate found in PEM file".to_string())?;
    parse_x509_cert_info(cert_der.as_ref())
}

pub fn start_acme_monitoring(
    acme_config: AcmeConfig,
    cert_path: String,
    key_path: String,
    resolver: Arc<AcmeResolver>,
    cert_expiry: Arc<CertExpiry>,
) {
    log_scheduler_started(&acme_config, &cert_expiry);

    tokio::spawn(async move {
        renewal_scheduler(acme_config, cert_path, key_path, resolver, cert_expiry).await;
    });
}

fn log_scheduler_started(acme_config: &AcmeConfig, cert_expiry: &CertExpiry) {
    match cert_expiry.days_remaining_for_log() {
        Some(days_remaining) => info!(
            days_remaining,
            self_signed = false,
            renew_before_hours = acme_config.renew_before_hours,
            "ACME renewal scheduler started"
        ),
        None => info!(
            self_signed = true,
            renew_before_hours = acme_config.renew_before_hours,
            "ACME renewal scheduler started (bootstrap self-signed; days_remaining omitted)"
        ),
    }
}

fn log_cert_metadata_updated(cert_expiry: &CertExpiry) {
    match cert_expiry.days_remaining_for_log() {
        Some(days_remaining) => info!(
            days_remaining,
            self_signed = false,
            "Certificate metadata updated in memory"
        ),
        None => info!(
            self_signed = true,
            "Certificate metadata updated in memory (self-signed; days_remaining omitted)"
        ),
    }
}

async fn renewal_scheduler(
    acme_config: AcmeConfig,
    cert_path: String,
    key_path: String,
    resolver: Arc<AcmeResolver>,
    cert_expiry: Arc<CertExpiry>,
) {
    loop {
        if cert_expiry.is_self_signed() {
            warn!("Current certificate is self-signed, requesting ACME renewal immediately");
            request_renewal(
                &acme_config,
                &cert_path,
                &key_path,
                resolver.clone(),
                cert_expiry.clone(),
            )
            .await;
            cert_expiry.notified().await;
            continue;
        }

        let threshold_secs = i64::from(acme_config.renew_before_hours) * 3600;
        let secs_remaining = cert_expiry.seconds_remaining();
        let secs_until_renewal = secs_remaining - threshold_secs;

        if secs_until_renewal > 0 {
            let wake_in = Duration::from_secs(secs_until_renewal as u64);
            info!(
                days_remaining = cert_expiry.days_remaining(),
                renew_in_days = secs_until_renewal / 86400,
                "Certificate valid, renewal scheduled"
            );
            tokio::select! {
                () = tokio::time::sleep(wake_in) => {}
                () = cert_expiry.notified() => continue,
            }
        }

        warn!(
            days_remaining = cert_expiry.days_remaining(),
            renew_before_hours = acme_config.renew_before_hours,
            "Certificate renewal needed"
        );
        request_renewal(
            &acme_config,
            &cert_path,
            &key_path,
            resolver.clone(),
            cert_expiry.clone(),
        )
        .await;
        cert_expiry.notified().await;
    }
}

async fn request_renewal(
    acme_config: &AcmeConfig,
    cert_path: &str,
    key_path: &str,
    resolver: Arc<AcmeResolver>,
    cert_expiry: Arc<CertExpiry>,
) {
    let request = RenewRequest {
        acme: acme_config.clone(),
        cert_path: cert_path.to_owned(),
        key_path: key_path.to_owned(),
    };
    if let Err(error) = renew(request, resolver, cert_expiry).await {
        error!(%error, "ACME renewal failed");
        // Back off so a tight loop does not hammer the CA.
        tokio::time::sleep(Duration::from_secs(60)).await;
    }
}

fn parse_x509_cert_info(der: &[u8]) -> Result<CertInfo, String> {
    let mut pos = 0;
    let (_, _cert_end) = parse_tag_length(der, &mut pos, 0x30)?;
    let (_, _tbs_end) = parse_tag_length(der, &mut pos, 0x30)?;

    if pos < der.len() && der[pos] == 0xA0 {
        let (len, _) = parse_tag_length(der, &mut pos, 0xA0)?;
        pos += len;
    }

    skip_tlv(der, &mut pos)?;
    skip_tlv(der, &mut pos)?;

    let issuer_start = pos;
    skip_tlv(der, &mut pos)?;
    let issuer_bytes = &der[issuer_start..pos];

    let (_, _val_end) = parse_tag_length(der, &mut pos, 0x30)?;
    skip_tlv(der, &mut pos)?;

    let tag = *der.get(pos).ok_or("Unexpected end of DER")?;
    let (len, _) = parse_tag_length(der, &mut pos, tag)?;
    let time_bytes = der.get(pos..pos + len).ok_or("notAfter value truncated")?;
    let not_after = parse_asn1_time(tag, time_bytes)?;
    pos += len;

    let subject_start = pos;
    skip_tlv(der, &mut pos)?;
    let subject_bytes = &der[subject_start..pos];

    Ok(CertInfo {
        not_after_epoch: not_after.timestamp(),
        self_signed: issuer_bytes == subject_bytes,
    })
}

fn parse_tag_length(
    der: &[u8],
    pos: &mut usize,
    expected_tag: u8,
) -> Result<(usize, usize), String> {
    let tag = *der.get(*pos).ok_or("Unexpected end of DER at tag")?;
    if tag != expected_tag {
        return Err(format!(
            "Expected tag 0x{expected_tag:02X}, got 0x{tag:02X} at offset {pos}"
        ));
    }
    *pos += 1;

    let first = *der.get(*pos).ok_or("Unexpected end of DER at length")? as usize;
    *pos += 1;

    let len = if first < 0x80 {
        first
    } else {
        let num_bytes = first & 0x7F;
        let mut length = 0usize;
        for _ in 0..num_bytes {
            length = (length << 8)
                | (*der
                    .get(*pos)
                    .ok_or("Unexpected end of DER in long length")? as usize);
            *pos += 1;
        }
        length
    };

    Ok((len, *pos + len))
}

fn skip_tlv(der: &[u8], pos: &mut usize) -> Result<(), String> {
    let _tag = *der.get(*pos).ok_or("Unexpected end of DER at tag")?;
    *pos += 1;
    let first = *der.get(*pos).ok_or("Unexpected end of DER at length")? as usize;
    *pos += 1;
    let len = if first < 0x80 {
        first
    } else {
        let num_bytes = first & 0x7F;
        let mut length = 0usize;
        for _ in 0..num_bytes {
            length = (length << 8)
                | (*der
                    .get(*pos)
                    .ok_or("Unexpected end of DER in long length")? as usize);
            *pos += 1;
        }
        length
    };
    *pos += len;
    Ok(())
}

fn parse_asn1_time(tag: u8, bytes: &[u8]) -> Result<chrono::DateTime<chrono::Utc>, String> {
    let s = std::str::from_utf8(bytes).map_err(|e| format!("Invalid time string: {e}"))?;
    match tag {
        0x17 => {
            if s.len() < 13 {
                return Err(format!("UTCTime too short: {s}"));
            }
            let year: i32 = s[0..2]
                .parse()
                .map_err(|_| "Invalid UTCTime year".to_string())?;
            let year = if year >= 50 { 1900 + year } else { 2000 + year };
            parse_datetime_components(year, &s[2..12])
        }
        0x18 => {
            if s.len() < 15 {
                return Err(format!("GeneralizedTime too short: {s}"));
            }
            let year: i32 = s[0..4]
                .parse()
                .map_err(|_| "Invalid GeneralizedTime year".to_string())?;
            parse_datetime_components(year, &s[4..14])
        }
        _ => Err(format!("Unknown time tag: 0x{tag:02X}")),
    }
}

fn parse_datetime_components(
    year: i32,
    mmddhhmmss: &str,
) -> Result<chrono::DateTime<chrono::Utc>, String> {
    use chrono::TimeZone;
    let month: u32 = mmddhhmmss[0..2]
        .parse()
        .map_err(|_| "Invalid month".to_string())?;
    let day: u32 = mmddhhmmss[2..4]
        .parse()
        .map_err(|_| "Invalid day".to_string())?;
    let hour: u32 = mmddhhmmss[4..6]
        .parse()
        .map_err(|_| "Invalid hour".to_string())?;
    let min: u32 = mmddhhmmss[6..8]
        .parse()
        .map_err(|_| "Invalid minute".to_string())?;
    let sec: u32 = mmddhhmmss[8..10]
        .parse()
        .map_err(|_| "Invalid second".to_string())?;
    chrono::Utc
        .with_ymd_and_hms(year, month, day, hour, min, sec)
        .single()
        .ok_or_else(|| {
            format!("Invalid date: {year}-{month:02}-{day:02} {hour:02}:{min:02}:{sec:02}")
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;

    #[test]
    fn days_remaining_for_log_omits_self_signed() {
        let now = chrono::Utc::now().timestamp();
        let expiry = CertExpiry::new(CertInfo {
            // Far-future notAfter like rcgen bootstrap (~755k days).
            not_after_epoch: now + 755_831 * 86400,
            self_signed: true,
        });
        assert!(expiry.days_remaining() > 100_000);
        assert_eq!(expiry.days_remaining_for_log(), None);
    }

    #[test]
    fn days_remaining_for_log_includes_ca_issued() {
        let now = chrono::Utc::now().timestamp();
        let expiry = CertExpiry::new(CertInfo {
            not_after_epoch: now + 90 * 86400,
            self_signed: false,
        });
        let days = expiry.days_remaining_for_log().expect("Some");
        assert!((89..=90).contains(&days), "days={days}");
    }

    #[test]
    fn inv_scheduler_start_log_omits_days_when_self_signed() {
        let src = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/acme/scheduler.rs"
        ));
        assert!(src.contains("days_remaining_for_log"));
        assert!(src.contains("days_remaining omitted"));
        let start_fn = src
            .find("fn log_scheduler_started")
            .expect("log_scheduler_started");
        let body = &src[start_fn..start_fn + 500];
        assert!(
            body.contains("days_remaining_for_log"),
            "scheduler start must gate days_remaining on self_signed"
        );
    }

    #[test]
    fn battle_parallel_days_remaining_for_log() {
        let barrier = Arc::new(Barrier::new(4));
        let mut handles = Vec::new();
        for self_signed in [true, true, false, false] {
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                let now = chrono::Utc::now().timestamp();
                let expiry = CertExpiry::new(CertInfo {
                    not_after_epoch: now + 30 * 86400,
                    self_signed,
                });
                barrier.wait();
                if self_signed {
                    assert_eq!(expiry.days_remaining_for_log(), None);
                } else {
                    assert!(expiry.days_remaining_for_log().is_some());
                }
            }));
        }
        for h in handles {
            h.join().expect("thread");
        }
    }
}
