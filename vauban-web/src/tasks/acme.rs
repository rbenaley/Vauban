//! ACME certificate renewal scheduler.
//!
//! The certificate `notAfter` timestamp and self-signed status are extracted
//! **once at startup** (before Capsicum `cap_enter()`) and stored in
//! `CertExpiry`. Instead of polling, the task computes the exact moment
//! when renewal is needed (`notAfter - renew_before_hours`) and sleeps
//! until then.
//!
//! If the current certificate is self-signed (issuer == subject), renewal
//! is requested **immediately** at startup to obtain a real ACME certificate.
//!
//! When a new certificate is activated via IPC (`AcmeCertActivate`), the
//! stored timestamp is updated and the task is woken via `Notify` to
//! recalculate its next wake-up.
//!
//! The actual ACME protocol execution (account management, order creation,
//! TLS-ALPN-01 challenge, CSR finalization) is handled by the supervisor.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::time::Duration;
use tokio::sync::Notify;
use tracing::{error, info, warn};

use crate::acme::resolver::AcmeResolver;
use crate::config::AcmeConfig;
use crate::ipc::SupervisorClient;

/// Parsed certificate metadata extracted before sandbox entry.
#[derive(Debug)]
pub struct CertInfo {
    /// Unix timestamp of the certificate's `notAfter` field.
    pub not_after_epoch: i64,
    /// `true` if the certificate issuer == subject (self-signed).
    pub self_signed: bool,
}

/// Certificate expiry state, shareable between the scheduler and IPC handler.
///
/// Stores the `notAfter` timestamp as a Unix epoch (seconds) and whether
/// the certificate is self-signed. When a new certificate is activated,
/// the IPC handler updates both fields and wakes the scheduler via `Notify`.
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

    /// Seconds remaining until certificate expiration.
    pub fn seconds_remaining(&self) -> i64 {
        let not_after = self.not_after_epoch.load(Ordering::Relaxed);
        let now = chrono::Utc::now().timestamp();
        not_after - now
    }

    /// Days remaining until certificate expiration (floored, 0 if expired).
    pub fn days_remaining(&self) -> u32 {
        let secs = self.seconds_remaining();
        if secs <= 0 { 0 } else { (secs / 86400) as u32 }
    }

    /// Whether the current certificate is self-signed.
    pub fn is_self_signed(&self) -> bool {
        self.self_signed.load(Ordering::Relaxed)
    }

    /// Update from a DER-encoded certificate and wake the scheduler.
    /// Called by the IPC handler when `AcmeCertActivate` arrives.
    pub fn update_from_der(&self, cert_der: &[u8]) {
        match parse_x509_cert_info(cert_der) {
            Ok(info) => {
                self.not_after_epoch
                    .store(info.not_after_epoch, Ordering::Relaxed);
                self.self_signed.store(info.self_signed, Ordering::Relaxed);
                let days = self.days_remaining();
                info!(
                    days_remaining = days,
                    self_signed = info.self_signed,
                    "Certificate metadata updated in memory"
                );
                self.waker.notify_one();
            }
            Err(e) => {
                warn!(error = %e, "Failed to parse metadata from new certificate");
            }
        }
    }

    /// Wait until the certificate metadata changes (new certificate activated).
    pub async fn notified(&self) {
        self.waker.notified().await;
    }
}

/// Extract certificate metadata from a PEM file.
///
/// **Must be called before `cap_enter()`** since it performs file I/O.
pub fn extract_cert_info(cert_path: &str) -> Result<CertInfo, String> {
    use rustls_pki_types::CertificateDer;
    use rustls_pki_types::pem::PemObject;
    use std::fs::File;
    use std::io::BufReader;

    let file = File::open(cert_path).map_err(|e| format!("Cannot open {}: {}", cert_path, e))?;
    let mut reader = BufReader::new(file);
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_reader_iter(&mut reader)
        .filter_map(|c| c.ok())
        .collect();

    let cert_der = certs
        .first()
        .ok_or_else(|| "No certificate found in PEM file".to_string())?;

    parse_x509_cert_info(cert_der.as_ref())
}

/// Extract certificate metadata from PEM data in memory (no filesystem access).
/// Used when the supervisor provides cert data via IPC.
pub fn extract_cert_info_from_pem(cert_pem: &str) -> Result<CertInfo, String> {
    use rustls_pki_types::CertificateDer;
    use rustls_pki_types::pem::PemObject;

    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .filter_map(|c| c.ok())
        .collect();

    let cert_der = certs
        .first()
        .ok_or_else(|| "No certificate found in PEM data".to_string())?;

    parse_x509_cert_info(cert_der.as_ref())
}

/// Start the ACME certificate renewal scheduler.
///
/// `cert_expiry` must be computed before `cap_enter()` via `extract_cert_info()`.
///
/// If the current certificate is self-signed, renewal is requested immediately
/// to obtain a real ACME-signed certificate. Otherwise the task sleeps until
/// exactly `renew_before_hours` hours before expiration.
pub async fn start_acme_monitoring(
    acme_config: AcmeConfig,
    cert_path: String,
    key_path: String,
    supervisor: Option<Arc<SupervisorClient>>,
    _resolver: Arc<AcmeResolver>,
    cert_expiry: Arc<CertExpiry>,
) {
    let days = cert_expiry.days_remaining();
    let self_signed = cert_expiry.is_self_signed();
    info!(
        days_remaining = days,
        self_signed = self_signed,
        renew_before_hours = acme_config.renew_before_hours,
        "ACME renewal scheduler started"
    );

    tokio::spawn(async move {
        renewal_scheduler(acme_config, cert_path, key_path, supervisor, cert_expiry).await;
    });
}

/// Renewal scheduler: sleeps until renewal is needed, then requests it.
///
/// On first iteration, if the certificate is self-signed, renewal is
/// requested immediately without waiting. After `AcmeCertActivate`
/// updates `CertExpiry`, subsequent iterations use the real expiry.
async fn renewal_scheduler(
    acme_config: AcmeConfig,
    cert_path: String,
    key_path: String,
    supervisor: Option<Arc<SupervisorClient>>,
    cert_expiry: Arc<CertExpiry>,
) {
    loop {
        // Self-signed certificates must be replaced immediately.
        if cert_expiry.is_self_signed() {
            warn!("Current certificate is self-signed, requesting ACME renewal immediately");
            request_renewal(&acme_config, &cert_path, &key_path, &supervisor).await;
            cert_expiry.notified().await;
            continue;
        }

        let threshold_secs = i64::from(acme_config.renew_before_hours) * 3600;
        let secs_remaining = cert_expiry.seconds_remaining();
        let secs_until_renewal = secs_remaining - threshold_secs;

        if secs_until_renewal > 0 {
            let wake_in = Duration::from_secs(secs_until_renewal as u64);
            let days = cert_expiry.days_remaining();
            let renew_in_days = secs_until_renewal / 86400;
            info!(
                days_remaining = days,
                renew_in_days = renew_in_days,
                "Certificate valid, renewal scheduled"
            );

            tokio::select! {
                () = tokio::time::sleep(wake_in) => {
                    // Time to renew.
                }
                () = cert_expiry.notified() => {
                    // New certificate activated, recalculate.
                    continue;
                }
            }
        }

        let days = cert_expiry.days_remaining();
        warn!(
            days_remaining = days,
            renew_before_hours = acme_config.renew_before_hours,
            "Certificate renewal needed"
        );
        request_renewal(&acme_config, &cert_path, &key_path, &supervisor).await;

        cert_expiry.notified().await;
    }
}

/// Minimal ASN.1 parser to extract certificate metadata.
///
/// Returns the `notAfter` timestamp and whether the certificate is
/// self-signed (issuer raw bytes == subject raw bytes).
///
/// Parses the X.509 DER structure through: version, serialNumber,
/// signature algorithm, issuer, validity, and subject.
fn parse_x509_cert_info(der: &[u8]) -> Result<CertInfo, String> {
    // TBSCertificate ::= SEQUENCE {
    //   version         [0] EXPLICIT INTEGER DEFAULT v1,
    //   serialNumber         INTEGER,
    //   signature            AlgorithmIdentifier,
    //   issuer               Name,          -- capture raw bytes
    //   validity             Validity,      -- extract notAfter
    //   subject              Name,          -- capture raw bytes
    //   ...
    // }

    let mut pos = 0;

    // Outer SEQUENCE (Certificate)
    let (_, _cert_end) = parse_tag_length(der, &mut pos, 0x30)?;

    // TBSCertificate SEQUENCE
    let (_, _tbs_end) = parse_tag_length(der, &mut pos, 0x30)?;

    // version [0] EXPLICIT - optional, skip if present
    if pos < der.len() && der[pos] == 0xA0 {
        let (len, _) = parse_tag_length(der, &mut pos, 0xA0)?;
        pos += len;
    }

    // serialNumber INTEGER - skip
    skip_tlv(der, &mut pos)?;

    // signature AlgorithmIdentifier SEQUENCE - skip
    skip_tlv(der, &mut pos)?;

    // issuer Name SEQUENCE - capture raw TLV bytes
    let issuer_start = pos;
    skip_tlv(der, &mut pos)?;
    let issuer_bytes = &der[issuer_start..pos];

    // validity Validity SEQUENCE
    let (_, _val_end) = parse_tag_length(der, &mut pos, 0x30)?;

    // notBefore Time - skip
    skip_tlv(der, &mut pos)?;

    // notAfter Time
    let tag = *der.get(pos).ok_or("Unexpected end of DER")?;
    let (len, _) = parse_tag_length(der, &mut pos, tag)?;
    let time_bytes = der.get(pos..pos + len).ok_or("notAfter value truncated")?;
    let not_after = parse_asn1_time(tag, time_bytes)?;
    pos += len;

    // subject Name SEQUENCE - capture raw TLV bytes
    let subject_start = pos;
    skip_tlv(der, &mut pos)?;
    let subject_bytes = &der[subject_start..pos];

    Ok(CertInfo {
        not_after_epoch: not_after.timestamp(),
        self_signed: issuer_bytes == subject_bytes,
    })
}

/// Parse an ASN.1 tag and length, returning (content_length, end_position).
fn parse_tag_length(
    der: &[u8],
    pos: &mut usize,
    expected_tag: u8,
) -> Result<(usize, usize), String> {
    let tag = *der.get(*pos).ok_or("Unexpected end of DER at tag")?;
    if tag != expected_tag {
        return Err(format!(
            "Expected tag 0x{:02X}, got 0x{:02X} at offset {}",
            expected_tag, tag, *pos
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

/// Skip a complete TLV (tag-length-value) element.
fn skip_tlv(der: &[u8], pos: &mut usize) -> Result<(), String> {
    // Read tag
    let _tag = *der.get(*pos).ok_or("Unexpected end of DER at tag")?;
    *pos += 1;

    // Read length
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

/// Parse an ASN.1 UTCTime or GeneralizedTime into a chrono DateTime.
fn parse_asn1_time(tag: u8, bytes: &[u8]) -> Result<chrono::DateTime<chrono::Utc>, String> {
    let s = std::str::from_utf8(bytes).map_err(|e| format!("Invalid time string: {}", e))?;

    match tag {
        // UTCTime: YYMMDDHHMMSSZ
        0x17 => {
            if s.len() < 13 {
                return Err(format!("UTCTime too short: {}", s));
            }
            let year: i32 = s[0..2]
                .parse()
                .map_err(|_| "Invalid UTCTime year".to_string())?;
            let year = if year >= 50 { 1900 + year } else { 2000 + year };
            parse_datetime_components(year, &s[2..12])
        }
        // GeneralizedTime: YYYYMMDDHHMMSSZ
        0x18 => {
            if s.len() < 15 {
                return Err(format!("GeneralizedTime too short: {}", s));
            }
            let year: i32 = s[0..4]
                .parse()
                .map_err(|_| "Invalid GeneralizedTime year".to_string())?;
            parse_datetime_components(year, &s[4..14])
        }
        _ => Err(format!("Unknown time tag: 0x{:02X}", tag)),
    }
}

/// Parse MMDDHHMMSS components into a DateTime.
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
            format!(
                "Invalid date: {}-{:02}-{:02} {:02}:{:02}:{:02}",
                year, month, day, hour, min, sec
            )
        })
}

/// Request certificate renewal from the supervisor via IPC.
async fn request_renewal(
    acme_config: &AcmeConfig,
    cert_path: &str,
    key_path: &str,
    supervisor: &Option<Arc<SupervisorClient>>,
) {
    let Some(sup) = supervisor else {
        warn!("ACME renewal needed but no supervisor connection available");
        return;
    };

    let directory_url = match acme_config.resolve_directory_url() {
        Ok(url) => url,
        Err(e) => {
            error!(error = %e, "Failed to resolve ACME directory URL");
            return;
        }
    };

    let msg = shared::messages::Message::AcmeRenewRequest {
        request_id: 0, // Will be assigned by supervisor client
        directory_url,
        domains: acme_config.domains.clone(),
        email: acme_config.email.clone(),
        account_key_path: acme_config.account_key_path.clone(),
        cert_path: cert_path.to_string(),
        key_path: key_path.to_string(),
        eab_kid: acme_config.eab_kid.as_ref().map(String::from),
        eab_hmac_key: acme_config
            .eab_hmac_key
            .as_ref()
            .map(|s| shared::messages::SensitiveString::new(s.to_string())),
    };

    info!(
        domains = ?acme_config.domains,
        directory = %acme_config.directory_url,
        "Requesting certificate renewal from supervisor"
    );

    // Send renewal request via supervisor IPC channel.
    // The response will be handled asynchronously via the IPC loop
    // which processes AcmeChallengeInstall, AcmeChallengeRemove,
    // and AcmeCertActivate messages.
    if let Err(e) = sup.inner().channel.send(&msg) {
        error!(error = %e, "Failed to send ACME renewal request to supervisor");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== ASN.1 low-level parser tests ====================

    #[test]
    fn test_parse_utc_time() {
        let result = parse_asn1_time(0x17, b"260301120000Z");
        assert!(result.is_ok());
        let dt = result.unwrap();
        assert_eq!(
            dt.format("%Y-%m-%d %H:%M:%S").to_string(),
            "2026-03-01 12:00:00"
        );
    }

    #[test]
    fn test_parse_generalized_time() {
        let result = parse_asn1_time(0x18, b"20260301120000Z");
        assert!(result.is_ok());
        let dt = result.unwrap();
        assert_eq!(
            dt.format("%Y-%m-%d %H:%M:%S").to_string(),
            "2026-03-01 12:00:00"
        );
    }

    #[test]
    fn test_parse_utc_time_y2k_pivot() {
        let result = parse_asn1_time(0x17, b"990101000000Z");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().format("%Y").to_string(), "1999");

        let result = parse_asn1_time(0x17, b"490101000000Z");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().format("%Y").to_string(), "2049");
    }

    #[test]
    fn test_parse_asn1_time_boundary_year_50() {
        // Year 50 should be 1950 per RFC 5280
        let result = parse_asn1_time(0x17, b"500101000000Z");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().format("%Y").to_string(), "1950");
    }

    #[test]
    fn test_parse_asn1_time_invalid_tag() {
        let result = parse_asn1_time(0x01, b"not-a-time");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unknown time tag"));
    }

    #[test]
    fn test_parse_asn1_time_utc_too_short() {
        let result = parse_asn1_time(0x17, b"26");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_asn1_time_generalized_too_short() {
        let result = parse_asn1_time(0x18, b"202603");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_asn1_time_invalid_utf8() {
        let result = parse_asn1_time(
            0x17,
            &[
                0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8, 0xF7, 0xF6, 0xF5, 0xF4, 0xF3,
            ],
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid time string"));
    }

    #[test]
    fn test_parse_datetime_components_valid() {
        let result = parse_datetime_components(2026, "0615143022");
        assert!(result.is_ok());
        let dt = result.unwrap();
        assert_eq!(
            dt.format("%Y-%m-%d %H:%M:%S").to_string(),
            "2026-06-15 14:30:22"
        );
    }

    #[test]
    fn test_parse_datetime_components_invalid_month() {
        let result = parse_datetime_components(2026, "1301000000");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_datetime_components_invalid_day() {
        let result = parse_datetime_components(2026, "0232000000");
        assert!(result.is_err());
    }

    #[test]
    fn test_skip_tlv_simple() {
        let der = [0x02, 0x03, 0x01, 0x02, 0x03, 0xFF];
        let mut pos = 0;
        skip_tlv(&der, &mut pos).unwrap();
        assert_eq!(pos, 5);
    }

    #[test]
    fn test_skip_tlv_empty_value() {
        let der = [0x05, 0x00]; // NULL TLV
        let mut pos = 0;
        skip_tlv(&der, &mut pos).unwrap();
        assert_eq!(pos, 2);
    }

    #[test]
    fn test_skip_tlv_truncated() {
        let der = [0x02]; // tag only, no length
        let mut pos = 0;
        assert!(skip_tlv(&der, &mut pos).is_err());
    }

    #[test]
    fn test_parse_tag_length_short_form() {
        let der = [0x30, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05];
        let mut pos = 0;
        let (len, end) = parse_tag_length(&der, &mut pos, 0x30).unwrap();
        assert_eq!(len, 5);
        assert_eq!(end, 7);
        assert_eq!(pos, 2);
    }

    #[test]
    fn test_parse_tag_length_long_form() {
        // Tag 0x30, long-form length: 0x81 0x80 = 128 bytes
        let mut der = vec![0x30, 0x81, 0x80];
        der.extend(vec![0x00; 128]);
        let mut pos = 0;
        let (len, end) = parse_tag_length(&der, &mut pos, 0x30).unwrap();
        assert_eq!(len, 128);
        assert_eq!(end, 131); // 3 bytes header + 128 bytes content
        assert_eq!(pos, 3);
    }

    #[test]
    fn test_parse_tag_length_wrong_tag() {
        let der = [0x31, 0x05];
        let mut pos = 0;
        let result = parse_tag_length(&der, &mut pos, 0x30);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Expected tag"));
    }

    #[test]
    fn test_parse_tag_length_empty_input() {
        let der: [u8; 0] = [];
        let mut pos = 0;
        assert!(parse_tag_length(&der, &mut pos, 0x30).is_err());
    }

    // ==================== X.509 cert info parser tests (with rcgen) ====================

    /// Generate a self-signed certificate valid for `days` days from now.
    fn generate_self_signed_cert(cn: &str, days: u32) -> Vec<u8> {
        use rcgen::{CertificateParams, DnType, KeyPair};

        let key_pair = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec![cn.to_string()]).unwrap();
        params.distinguished_name.push(DnType::CommonName, cn);
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::hours(1);
        params.not_after = now + time::Duration::days(i64::from(days));
        let cert = params.self_signed(&key_pair).unwrap();
        cert.der().to_vec()
    }

    /// Generate a CA-signed certificate (issuer != subject).
    fn generate_ca_signed_cert(cn: &str, days: u32) -> Vec<u8> {
        use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};

        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(vec![]).unwrap();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Test CA");
        ca_params
            .distinguished_name
            .push(DnType::OrganizationName, "Test Org");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_issuer = Issuer::from_params(&ca_params, &ca_key);

        let ee_key = KeyPair::generate().unwrap();
        let mut ee_params = CertificateParams::new(vec![cn.to_string()]).unwrap();
        ee_params.distinguished_name.push(DnType::CommonName, cn);
        let now = time::OffsetDateTime::now_utc();
        ee_params.not_before = now - time::Duration::hours(1);
        ee_params.not_after = now + time::Duration::days(i64::from(days));

        let ee_cert = ee_params.signed_by(&ee_key, &ca_issuer).unwrap();
        ee_cert.der().to_vec()
    }

    #[test]
    fn test_parse_self_signed_cert_detected() {
        let der = generate_self_signed_cert("localhost", 90);
        let info = parse_x509_cert_info(&der).unwrap();
        assert!(
            info.self_signed,
            "Self-signed cert must have self_signed=true"
        );
        assert!(info.not_after_epoch > 0, "not_after_epoch must be positive");
    }

    #[test]
    fn test_parse_ca_signed_cert_not_self_signed() {
        let der = generate_ca_signed_cert("example.com", 90);
        let info = parse_x509_cert_info(&der).unwrap();
        assert!(
            !info.self_signed,
            "CA-signed cert must have self_signed=false"
        );
        assert!(info.not_after_epoch > 0);
    }

    #[test]
    fn test_parse_cert_expiry_approximate() {
        let days = 60u32;
        let der = generate_self_signed_cert("test.local", days);
        let info = parse_x509_cert_info(&der).unwrap();

        let now = chrono::Utc::now().timestamp();
        let expected_min = now + i64::from(days - 1) * 86400;
        let expected_max = now + i64::from(days + 1) * 86400;
        assert!(
            info.not_after_epoch >= expected_min && info.not_after_epoch <= expected_max,
            "notAfter should be ~{} days from now, got delta={}s",
            days,
            info.not_after_epoch - now
        );
    }

    #[test]
    fn test_parse_cert_info_invalid_der() {
        assert!(parse_x509_cert_info(&[]).is_err());
        assert!(parse_x509_cert_info(&[0x30, 0x00]).is_err());
        assert!(parse_x509_cert_info(&[0xFF, 0xFF, 0xFF]).is_err());
    }

    // ==================== CertExpiry state tests ====================

    #[test]
    fn test_cert_expiry_self_signed() {
        let info = CertInfo {
            not_after_epoch: chrono::Utc::now().timestamp() + 86400,
            self_signed: true,
        };
        let expiry = CertExpiry::new(info);
        assert!(expiry.is_self_signed());
        assert_eq!(expiry.days_remaining(), 1);
    }

    #[test]
    fn test_cert_expiry_not_self_signed() {
        let info = CertInfo {
            not_after_epoch: chrono::Utc::now().timestamp() + 30 * 86400,
            self_signed: false,
        };
        let expiry = CertExpiry::new(info);
        assert!(!expiry.is_self_signed());
        assert!(expiry.days_remaining() >= 29 && expiry.days_remaining() <= 30);
    }

    #[test]
    fn test_cert_expiry_already_expired() {
        let info = CertInfo {
            not_after_epoch: chrono::Utc::now().timestamp() - 3600,
            self_signed: false,
        };
        let expiry = CertExpiry::new(info);
        assert_eq!(expiry.days_remaining(), 0);
        assert!(expiry.seconds_remaining() < 0);
    }

    #[test]
    fn test_cert_expiry_epoch_zero() {
        let info = CertInfo {
            not_after_epoch: 0,
            self_signed: true,
        };
        let expiry = CertExpiry::new(info);
        assert_eq!(expiry.days_remaining(), 0);
        assert!(expiry.seconds_remaining() < 0);
        assert!(expiry.is_self_signed());
    }

    #[test]
    fn test_cert_expiry_update_from_der() {
        let info = CertInfo {
            not_after_epoch: 0,
            self_signed: true,
        };
        let expiry = CertExpiry::new(info);
        assert!(expiry.is_self_signed());
        assert_eq!(expiry.days_remaining(), 0);

        // Update with a real CA-signed cert
        let der = generate_ca_signed_cert("updated.com", 90);
        expiry.update_from_der(&der);

        assert!(
            !expiry.is_self_signed(),
            "Must become non-self-signed after update"
        );
        assert!(expiry.days_remaining() >= 88, "Must reflect new expiry");
    }

    #[test]
    fn test_cert_expiry_update_from_invalid_der_keeps_old_values() {
        let info = CertInfo {
            not_after_epoch: chrono::Utc::now().timestamp() + 86400,
            self_signed: false,
        };
        let expiry = CertExpiry::new(info);
        let days_before = expiry.days_remaining();

        expiry.update_from_der(&[0xFF, 0xFF]);

        assert_eq!(
            expiry.days_remaining(),
            days_before,
            "Invalid DER must not change state"
        );
        assert!(!expiry.is_self_signed());
    }

    #[tokio::test]
    async fn test_cert_expiry_notify_wakes_waiter() {
        let info = CertInfo {
            not_after_epoch: 0,
            self_signed: true,
        };
        let expiry = Arc::new(CertExpiry::new(info));
        let expiry2 = Arc::clone(&expiry);

        let handle = tokio::spawn(async move {
            expiry2.notified().await;
            expiry2.days_remaining()
        });

        // Give the waiter time to register
        tokio::time::sleep(Duration::from_millis(50)).await;

        let der = generate_self_signed_cert("notify-test.local", 45);
        expiry.update_from_der(&der);

        let days = handle.await.unwrap();
        assert!(days >= 43, "Waiter should see updated expiry, got {}", days);
    }

    // ==================== extract_cert_info (file I/O) tests ====================

    #[test]
    fn test_extract_cert_info_self_signed_pem() {
        use rcgen::{CertificateParams, DnType, KeyPair};
        use std::io::Write;

        let key_pair = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, "localhost");
        let cert = params.self_signed(&key_pair).unwrap();

        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        tmpfile.write_all(cert.pem().as_bytes()).unwrap();

        let info = extract_cert_info(tmpfile.path().to_str().unwrap()).unwrap();
        assert!(info.self_signed);
        assert!(info.not_after_epoch > 0);
    }

    #[test]
    fn test_extract_cert_info_ca_signed_pem() {
        use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
        use std::io::Write;

        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(vec![]).unwrap();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Test CA");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_issuer = Issuer::from_params(&ca_params, &ca_key);

        let ee_key = KeyPair::generate().unwrap();
        let mut ee_params = CertificateParams::new(vec!["signed.example.com".to_string()]).unwrap();
        ee_params
            .distinguished_name
            .push(DnType::CommonName, "signed.example.com");
        let ee_cert = ee_params.signed_by(&ee_key, &ca_issuer).unwrap();

        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        tmpfile.write_all(ee_cert.pem().as_bytes()).unwrap();

        let info = extract_cert_info(tmpfile.path().to_str().unwrap()).unwrap();
        assert!(!info.self_signed);
    }

    #[test]
    fn test_extract_cert_info_nonexistent_file() {
        let result = extract_cert_info("/nonexistent/path/cert.pem");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Cannot open"));
    }

    #[test]
    fn test_extract_cert_info_empty_file() {
        let tmpfile = tempfile::NamedTempFile::new().unwrap();
        let result = extract_cert_info(tmpfile.path().to_str().unwrap());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No certificate"));
    }

    #[test]
    fn test_extract_cert_info_garbage_file() {
        use std::io::Write;
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        tmpfile.write_all(b"not a PEM certificate at all").unwrap();
        let result = extract_cert_info(tmpfile.path().to_str().unwrap());
        assert!(result.is_err());
    }

    // ==================== extract_cert_info_from_pem Tests ====================

    #[test]
    fn test_extract_cert_info_from_pem_self_signed() {
        use rcgen::{CertificateParams, DnType, KeyPair};

        let key_pair = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, "self-signed-test");
        let cert = params.self_signed(&key_pair).unwrap();
        let cert_pem = cert.pem();

        let info = extract_cert_info_from_pem(&cert_pem).unwrap();
        assert!(info.self_signed, "Should detect self-signed");
        assert!(info.not_after_epoch > 0, "Should have valid expiry");
    }

    #[test]
    fn test_extract_cert_info_from_pem_empty() {
        let result = extract_cert_info_from_pem("");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No certificate found"));
    }

    #[test]
    fn test_extract_cert_info_from_pem_garbage() {
        let result = extract_cert_info_from_pem("not a PEM certificate");
        assert!(result.is_err());
    }
}
