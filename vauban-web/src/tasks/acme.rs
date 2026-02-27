//! ACME certificate monitoring task.
//!
//! Periodically checks the production TLS certificate expiry and requests
//! renewal from the supervisor via IPC when the certificate is approaching
//! its expiration threshold.
//!
//! The actual ACME protocol execution (account management, order creation,
//! TLS-ALPN-01 challenge, CSR finalization) is handled by the supervisor.
//! This task only orchestrates the timing of renewal requests.

use std::sync::Arc;
use std::time::Duration;
use tokio::time::interval;
use tracing::{error, info, warn};

use crate::acme::resolver::AcmeResolver;
use crate::config::AcmeConfig;
use crate::ipc::SupervisorClient;

/// Start the ACME certificate monitoring task.
///
/// This spawns a background tokio task that periodically:
/// 1. Reads the certificate from `cert_path` and checks its expiry
/// 2. If the certificate expires within `renew_before_days`, sends an
///    `AcmeRenewRequest` to the supervisor via IPC
/// 3. The supervisor handles the ACME protocol and sends back certificate
///    updates via `AcmeChallengeInstall`, `AcmeChallengeRemove`, and
///    `AcmeCertActivate` messages (handled by the IPC loop)
pub async fn start_acme_monitoring(
    acme_config: AcmeConfig,
    cert_path: String,
    key_path: String,
    supervisor: Option<Arc<SupervisorClient>>,
    _resolver: Arc<AcmeResolver>,
) {
    let check_interval_secs = acme_config.check_interval_hours * 3600;

    tokio::spawn(async move {
        cert_expiry_monitor(acme_config, cert_path, key_path, check_interval_secs, supervisor).await;
    });

    info!(
        check_interval_hours = check_interval_secs / 3600,
        "ACME certificate monitoring task started"
    );
}

/// Certificate expiry monitoring loop.
async fn cert_expiry_monitor(
    acme_config: AcmeConfig,
    cert_path: String,
    key_path: String,
    check_interval_secs: u64,
    supervisor: Option<Arc<SupervisorClient>>,
) {
    let mut ticker = interval(Duration::from_secs(check_interval_secs));

    loop {
        ticker.tick().await;

        match check_cert_expiry_days(&cert_path) {
            Ok(days_remaining) => {
                if days_remaining <= acme_config.renew_before_days {
                    warn!(
                        days_remaining = days_remaining,
                        threshold = acme_config.renew_before_days,
                        "Certificate renewal needed"
                    );
                    request_renewal(&acme_config, &cert_path, &key_path, &supervisor).await;
                } else {
                    info!(
                        days_remaining = days_remaining,
                        threshold = acme_config.renew_before_days,
                        "Certificate valid, no renewal needed"
                    );
                }
            }
            Err(e) => {
                error!(error = %e, cert_path = %cert_path, "Failed to check certificate expiry");
            }
        }
    }
}

/// Check how many days until the certificate expires.
///
/// Reads the PEM certificate file and extracts the `notAfter` field.
fn check_cert_expiry_days(cert_path: &str) -> Result<u32, String> {
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::CertificateDer;
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

    // Parse the X.509 certificate to extract notAfter
    // We use a minimal ASN.1 parser to avoid adding x509-parser as a dependency.
    // The notAfter field is at a fixed offset in the TBSCertificate structure.
    parse_x509_not_after_days(cert_der.as_ref())
}

/// Minimal ASN.1 parser to extract days until certificate expiry.
///
/// Parses enough of the X.509 DER structure to reach the Validity
/// sequence and extract the `notAfter` time field.
fn parse_x509_not_after_days(der: &[u8]) -> Result<u32, String> {
    // X.509 Certificate structure (RFC 5280):
    // Certificate ::= SEQUENCE {
    //   tbsCertificate       TBSCertificate,     -- SEQUENCE
    //   signatureAlgorithm   AlgorithmIdentifier, -- SEQUENCE
    //   signatureValue       BIT STRING
    // }
    //
    // TBSCertificate ::= SEQUENCE {
    //   version         [0] EXPLICIT INTEGER DEFAULT v1,
    //   serialNumber         INTEGER,
    //   signature            AlgorithmIdentifier,
    //   issuer               Name,
    //   validity             Validity,            -- <-- we want this
    //   ...
    // }
    //
    // Validity ::= SEQUENCE {
    //   notBefore      Time,
    //   notAfter       Time   -- <-- specifically this
    // }
    //
    // Time ::= CHOICE { utcTime UTCTime, generalTime GeneralizedTime }

    let mut pos = 0;

    // Outer SEQUENCE (Certificate)
    let (_, cert_end) = parse_tag_length(der, &mut pos, 0x30)?;
    let _ = cert_end;

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

    // issuer Name SEQUENCE - skip
    skip_tlv(der, &mut pos)?;

    // validity Validity SEQUENCE
    let (_, _val_end) = parse_tag_length(der, &mut pos, 0x30)?;

    // notBefore Time - skip
    skip_tlv(der, &mut pos)?;

    // notAfter Time
    let tag = *der.get(pos).ok_or("Unexpected end of DER")?;
    let (len, _) = parse_tag_length(der, &mut pos, tag)?;
    let time_bytes = der
        .get(pos..pos + len)
        .ok_or("notAfter value truncated")?;

    let not_after = parse_asn1_time(tag, time_bytes)?;
    let now = chrono::Utc::now();
    let duration = not_after.signed_duration_since(now);

    if duration.num_days() < 0 {
        Ok(0)
    } else {
        Ok(duration.num_days() as u32)
    }
}

/// Parse an ASN.1 tag and length, returning (content_length, end_position).
fn parse_tag_length(der: &[u8], pos: &mut usize, expected_tag: u8) -> Result<(usize, usize), String> {
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
                | (*der.get(*pos).ok_or("Unexpected end of DER in long length")? as usize);
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
                | (*der.get(*pos).ok_or("Unexpected end of DER in long length")? as usize);
            *pos += 1;
        }
        length
    };

    *pos += len;
    Ok(())
}

/// Parse an ASN.1 UTCTime or GeneralizedTime into a chrono DateTime.
fn parse_asn1_time(
    tag: u8,
    bytes: &[u8],
) -> Result<chrono::DateTime<chrono::Utc>, String> {
    let s =
        std::str::from_utf8(bytes).map_err(|e| format!("Invalid time string: {}", e))?;

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
        .ok_or_else(|| format!("Invalid date: {}-{:02}-{:02} {:02}:{:02}:{:02}", year, month, day, hour, min, sec))
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
        provider = acme_config.provider.as_str(),
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

    #[test]
    fn test_parse_utc_time() {
        // UTCTime: 260301120000Z (March 1, 2026 12:00:00 UTC)
        let result = parse_asn1_time(0x17, b"260301120000Z");
        assert!(result.is_ok());
        let dt = result.unwrap();
        assert_eq!(dt.format("%Y-%m-%d %H:%M:%S").to_string(), "2026-03-01 12:00:00");
    }

    #[test]
    fn test_parse_generalized_time() {
        // GeneralizedTime: 20260301120000Z
        let result = parse_asn1_time(0x18, b"20260301120000Z");
        assert!(result.is_ok());
        let dt = result.unwrap();
        assert_eq!(dt.format("%Y-%m-%d %H:%M:%S").to_string(), "2026-03-01 12:00:00");
    }

    #[test]
    fn test_parse_utc_time_y2k_pivot() {
        // Year 99 should be 1999
        let result = parse_asn1_time(0x17, b"990101000000Z");
        assert!(result.is_ok());
        let dt = result.unwrap();
        assert_eq!(dt.format("%Y").to_string(), "1999");

        // Year 49 should be 2049
        let result = parse_asn1_time(0x17, b"490101000000Z");
        assert!(result.is_ok());
        let dt = result.unwrap();
        assert_eq!(dt.format("%Y").to_string(), "2049");
    }

    #[test]
    fn test_parse_asn1_time_invalid_tag() {
        let result = parse_asn1_time(0x01, b"not-a-time");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unknown time tag"));
    }

    #[test]
    fn test_parse_asn1_time_too_short() {
        let result = parse_asn1_time(0x17, b"26");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_datetime_components_valid() {
        let result = parse_datetime_components(2026, "0615143022");
        assert!(result.is_ok());
        let dt = result.unwrap();
        assert_eq!(dt.format("%Y-%m-%d %H:%M:%S").to_string(), "2026-06-15 14:30:22");
    }

    #[test]
    fn test_skip_tlv_simple() {
        // Tag 0x02, length 3, value [0x01, 0x02, 0x03]
        let der = [0x02, 0x03, 0x01, 0x02, 0x03, 0xFF];
        let mut pos = 0;
        skip_tlv(&der, &mut pos).unwrap();
        assert_eq!(pos, 5);
    }

    #[test]
    fn test_parse_tag_length_short() {
        let der = [0x30, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05];
        let mut pos = 0;
        let (len, end) = parse_tag_length(&der, &mut pos, 0x30).unwrap();
        assert_eq!(len, 5);
        assert_eq!(end, 7);
        assert_eq!(pos, 2);
    }

    #[test]
    fn test_parse_tag_length_wrong_tag() {
        let der = [0x31, 0x05];
        let mut pos = 0;
        let result = parse_tag_length(&der, &mut pos, 0x30);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Expected tag"));
    }
}
