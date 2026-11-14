//! The NLA authentication settings of an RDP asset: mode, target name and
//! domain. One service for the two write paths (the `/assets/manage` form
//! and the `/api/v1/assets/manage` JSON API), so they cannot disagree on
//! what a valid Kerberos asset is.
//!
//! * The mode is a closed set ([`RdpAuthMode`]). A value outside it is
//!   REFUSED. It is never folded into `ntlm`: a typo in `kerberos` must
//!   not silently produce an NTLM asset.
//! * A Kerberos mode needs a fully-qualified target name (the SPN is
//!   `TERMSRV/<fqdn>`) and the DNS name of the domain (the realm). The
//!   realm rule is [`shared::kerberos::normalize_realm`], the same
//!   function the RDP proxy applies at session open.
//!
//! The settings live in `connection_config` under `rdp_auth_mode` and
//! `domain`.

use shared::messages::RdpAuthMode;

/// `connection_config` key of the mode.
pub const MODE_KEY: &str = "rdp_auth_mode";
/// `connection_config` key of the domain.
pub const DOMAIN_KEY: &str = "domain";
/// Longest domain accepted in any mode (DNS name limit).
pub const MAX_DOMAIN_LEN: usize = 255;

/// Why a mode / hostname / domain combination is refused. The `Display`
/// text is the operator-facing message.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RdpAuthSettingsError {
    #[error(
        "Unknown RDP authentication mode: expected one of ntlm, kerberos, kerberos_restricted_admin"
    )]
    UnknownMode,
    #[error("rdp_auth_mode and rdp_domain only apply to RDP assets")]
    NotAnRdpAsset,
    #[error("{0}")]
    Hostname(String),
    #[error("{0}")]
    Domain(String),
}

/// The settings to store on an RDP asset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RdpAuthSettings {
    pub mode: RdpAuthMode,
    /// `None` when the asset has no domain (local account, NTLM only).
    pub domain: Option<String>,
}

/// Parse a mode sent by a client. Absent or blank means "not sent";
/// anything else must be a canonical mode string.
pub fn parse_requested_mode(
    input: Option<&str>,
) -> Result<Option<RdpAuthMode>, RdpAuthSettingsError> {
    match input.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(None),
        Some(raw) => RdpAuthMode::parse(raw)
            .map(Some)
            .ok_or(RdpAuthSettingsError::UnknownMode),
    }
}

/// The mode stored on an asset. A row written before the field existed,
/// or holding a value outside the closed set, reads as the default.
pub fn stored_mode(config: &serde_json::Value) -> RdpAuthMode {
    config
        .get(MODE_KEY)
        .and_then(serde_json::Value::as_str)
        .and_then(RdpAuthMode::parse)
        .unwrap_or_default()
}

/// The non-empty domain stored on an asset.
pub fn stored_domain(config: &serde_json::Value) -> Option<String> {
    config
        .get(DOMAIN_KEY)
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Fail-closed FQDN check for the Kerberos modes.
///
/// Kerberos ties the ticket to the target's Service Principal Name
/// (`TERMSRV/<fqdn>`), which an IP literal or a short name cannot
/// satisfy. Rejected here, at write time, rather than opaquely at
/// connect time.
pub fn validate_kerberos_fqdn(hostname: &str) -> Result<(), String> {
    let host = hostname.trim();
    if host.is_empty() {
        return Err("A fully-qualified hostname is required for Kerberos RDP".to_string());
    }
    // Reject bracketed / bare IP literals: Kerberos needs a DNS name.
    let unbracketed = host.trim_start_matches('[').trim_end_matches(']');
    if unbracketed.parse::<std::net::IpAddr>().is_ok() {
        return Err(format!(
            "Kerberos RDP requires a fully-qualified hostname (SPN TERMSRV/<fqdn>), \
             not an IP address: {host}"
        ));
    }
    if !host.contains('.') {
        return Err(format!(
            "Kerberos RDP requires a fully-qualified hostname (e.g. host.example.com), \
             got a short name: {host}"
        ));
    }
    // The name becomes the SPN `TERMSRV/<host>`: it must be a host name
    // and nothing else. Dot-separated labels of letters, digits, hyphens
    // and underscores (the project's hostname rule allows `_`), no empty
    // label, no hyphen at a label edge, so no port, no trailing dot and no
    // SPN or URL delimiter. The last label must not be a number, which
    // rules out the short IPv4 forms a resolver accepts (`10.1`,
    // `192.168.1`, `0x7f.0.0.1`).
    let label_ok = |label: &str| {
        !label.is_empty()
            && label.len() <= shared::kerberos::MAX_REALM_LABEL_LEN
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    };
    let last_label_is_a_name = host.rsplit('.').next().is_some_and(|label| {
        label.chars().any(|c| c.is_ascii_alphabetic())
            && !label.starts_with("0x")
            && !label.starts_with("0X")
    });
    if !host.split('.').all(label_ok) || !last_label_is_a_name {
        return Err(
            "Kerberos RDP requires a fully-qualified DNS hostname: letters, digits, \
             hyphens and underscores in dot-separated labels, without a port or a trailing dot"
                .to_string(),
        );
    }
    Ok(())
}

/// Fail-closed domain check for the Kerberos modes.
///
/// `sspi` derives the Kerberos realm from the asset's domain by
/// upper-casing it, unchecked: an absent domain yields an EMPTY realm and
/// a NetBIOS short name (`CORP`) is sent as-is. The domain must therefore
/// be present and be the DNS name of the domain. Single seam:
/// [`shared::kerberos::normalize_realm`].
pub fn validate_kerberos_domain(domain: Option<&str>) -> Result<(), String> {
    shared::kerberos::normalize_realm(domain.unwrap_or_default())
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Checks that hold in every mode: a domain is a short single-line name.
fn validate_any_domain(domain: Option<&str>) -> Result<(), String> {
    let Some(domain) = domain else {
        return Ok(());
    };
    if domain.len() > MAX_DOMAIN_LEN {
        return Err(format!(
            "Domain must be at most {MAX_DOMAIN_LEN} characters"
        ));
    }
    if domain.chars().any(char::is_control) {
        return Err("Domain must not contain control characters".to_string());
    }
    Ok(())
}

/// Everything a (mode, hostname, domain) triple must satisfy.
pub fn validate(
    mode: RdpAuthMode,
    hostname: &str,
    domain: Option<&str>,
) -> Result<(), RdpAuthSettingsError> {
    validate_any_domain(domain).map_err(RdpAuthSettingsError::Domain)?;
    if !mode.uses_kerberos() {
        return Ok(());
    }
    validate_kerberos_fqdn(hostname).map_err(RdpAuthSettingsError::Hostname)?;
    validate_kerberos_domain(domain).map_err(RdpAuthSettingsError::Domain)
}

/// Resolve and validate the settings of an RDP asset for a write.
///
/// * `requested_mode`: absent or blank keeps the stored mode (the default
///   on a create); an unknown value is refused.
/// * `requested_domain`: absent keeps the stored domain; an empty string
///   clears it.
/// * `stored`: the asset's current `connection_config`, `None` on create.
/// * `hostname`: the hostname the asset will have AFTER the write.
///
/// The result is validated as a whole, so changing only the hostname of
/// a Kerberos asset to an IP address is refused too.
pub fn resolve(
    requested_mode: Option<&str>,
    requested_domain: Option<&str>,
    stored: Option<&serde_json::Value>,
    hostname: &str,
) -> Result<RdpAuthSettings, RdpAuthSettingsError> {
    let mode = match parse_requested_mode(requested_mode)? {
        Some(mode) => mode,
        None => stored.map(stored_mode).unwrap_or_default(),
    };
    let domain = match requested_domain {
        Some(raw) => Some(raw.trim().to_string()).filter(|d| !d.is_empty()),
        None => stored.and_then(stored_domain),
    };
    validate(mode, hostname, domain.as_deref())?;
    Ok(RdpAuthSettings { mode, domain })
}

/// Refuse RDP-only fields sent for an asset that is not RDP.
pub fn refuse_on_non_rdp(
    requested_mode: Option<&str>,
    requested_domain: Option<&str>,
) -> Result<(), RdpAuthSettingsError> {
    if requested_mode.is_some() || requested_domain.is_some() {
        return Err(RdpAuthSettingsError::NotAnRdpAsset);
    }
    Ok(())
}

/// Write the settings into a `connection_config` object. Returns whether
/// the object changed. A config that is not a JSON object is replaced by
/// one.
pub fn apply(config: &mut serde_json::Value, settings: &RdpAuthSettings) -> bool {
    if !config.is_object() {
        *config = serde_json::json!({});
    }
    let before = config.clone();
    if let Some(obj) = config.as_object_mut() {
        obj.insert(
            MODE_KEY.to_string(),
            serde_json::Value::String(settings.mode.as_str().to_string()),
        );
        match &settings.domain {
            Some(domain) => {
                obj.insert(
                    DOMAIN_KEY.to_string(),
                    serde_json::Value::String(domain.clone()),
                );
            }
            None => {
                obj.remove(DOMAIN_KEY);
            }
        }
    }
    *config != before
}

/// Short label of a mode, for list badges.
pub const fn badge_label(mode: RdpAuthMode) -> &'static str {
    match mode {
        RdpAuthMode::Ntlm => "NTLM",
        RdpAuthMode::KerberosRestrictedAdmin => "Kerberos RA",
        RdpAuthMode::Kerberos => "Kerberos",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const FQDN: &str = "srv01.corp.example.com";
    const REALM: &str = "corp.example.com";
    const KERBEROS_MODES: [RdpAuthMode; 2] =
        [RdpAuthMode::Kerberos, RdpAuthMode::KerberosRestrictedAdmin];

    #[test]
    fn test_parse_requested_mode_accepts_canonical_and_blank() {
        assert_eq!(parse_requested_mode(None), Ok(None));
        assert_eq!(parse_requested_mode(Some("")), Ok(None));
        assert_eq!(parse_requested_mode(Some("   ")), Ok(None));
        for mode in RdpAuthMode::ALL {
            assert_eq!(parse_requested_mode(Some(mode.as_str())), Ok(Some(mode)));
            let padded = format!("  {}  ", mode.as_str());
            assert_eq!(parse_requested_mode(Some(&padded)), Ok(Some(mode)));
        }
    }

    /// An unknown mode is refused, never folded into NTLM.
    #[test]
    fn attack_unknown_mode_silently_stored_as_ntlm_is_rejected() {
        for raw in [
            "Kerberos",
            "KERBEROS",
            "kerbeross",
            "kerberos-restricted-admin",
            "kerberos_restricted",
            "negotiate",
            "ntlmv2",
            "0",
            "null",
            "kerberos\u{0}",
            "ntlm,kerberos",
        ] {
            assert_eq!(
                parse_requested_mode(Some(raw)),
                Err(RdpAuthSettingsError::UnknownMode),
                "{raw:?}"
            );
            assert_eq!(
                resolve(Some(raw), Some(REALM), None, FQDN),
                Err(RdpAuthSettingsError::UnknownMode),
                "{raw:?}"
            );
        }
    }

    #[test]
    fn test_stored_mode_reads_the_closed_set_only() {
        assert_eq!(stored_mode(&json!({})), RdpAuthMode::Ntlm);
        assert_eq!(stored_mode(&json!(null)), RdpAuthMode::Ntlm);
        assert_eq!(stored_mode(&json!({"rdp_auth_mode": 3})), RdpAuthMode::Ntlm);
        assert_eq!(
            stored_mode(&json!({"rdp_auth_mode": "bogus"})),
            RdpAuthMode::Ntlm
        );
        for mode in RdpAuthMode::ALL {
            assert_eq!(stored_mode(&json!({"rdp_auth_mode": mode.as_str()})), mode);
        }
    }

    #[test]
    fn test_resolve_create_defaults_to_ntlm_without_domain() {
        let settings = resolve(None, None, None, "192.0.2.10");
        assert_eq!(
            settings,
            Ok(RdpAuthSettings {
                mode: RdpAuthMode::Ntlm,
                domain: None
            })
        );
        // NTLM keeps accepting a NetBIOS domain and an IP target.
        let settings = resolve(Some("ntlm"), Some("CORP"), None, "192.0.2.10");
        assert_eq!(settings.map(|s| s.domain), Ok(Some("CORP".to_string())));
    }

    #[test]
    fn test_resolve_accepts_a_complete_kerberos_asset() {
        for mode in KERBEROS_MODES {
            let settings = resolve(Some(mode.as_str()), Some(REALM), None, FQDN);
            assert_eq!(
                settings,
                Ok(RdpAuthSettings {
                    mode,
                    domain: Some(REALM.to_string())
                })
            );
        }
    }

    #[test]
    fn attack_kerberos_without_fqdn_or_realm_is_rejected() {
        for mode in KERBEROS_MODES {
            let m = Some(mode.as_str());
            for host in [
                "192.0.2.10",
                "[2001:db8::1]",
                "2001:db8::1",
                "srv01",
                "",
                "  ",
            ] {
                assert!(
                    matches!(
                        resolve(m, Some(REALM), None, host),
                        Err(RdpAuthSettingsError::Hostname(_))
                    ),
                    "{mode:?} {host:?}"
                );
            }
            for domain in [
                None,
                Some(""),
                Some("  "),
                Some("CORP"),
                Some("corp.example.com@evil.test"),
                Some("corp..example.com"),
            ] {
                assert!(
                    matches!(
                        resolve(m, domain, None, FQDN),
                        Err(RdpAuthSettingsError::Domain(_))
                    ),
                    "{mode:?} {domain:?}"
                );
            }
        }
    }

    /// An update is validated on the EFFECTIVE triple: the stored mode
    /// still binds when the request only changes the hostname or clears
    /// the domain.
    #[test]
    fn attack_partial_update_that_breaks_a_kerberos_asset_is_rejected() {
        for mode in KERBEROS_MODES {
            let stored = json!({"rdp_auth_mode": mode.as_str(), "domain": REALM});
            // Hostname alone, to an IP.
            assert!(matches!(
                resolve(None, None, Some(&stored), "192.0.2.10"),
                Err(RdpAuthSettingsError::Hostname(_))
            ));
            // Domain cleared, or replaced by a NetBIOS name.
            for domain in ["", "CORP"] {
                assert!(matches!(
                    resolve(None, Some(domain), Some(&stored), FQDN),
                    Err(RdpAuthSettingsError::Domain(_))
                ));
            }
            // Untouched: still valid.
            assert_eq!(
                resolve(None, None, Some(&stored), FQDN).map(|s| s.mode),
                Ok(mode)
            );
        }
        // Switching an NTLM asset with a NetBIOS domain to Kerberos.
        let stored = json!({"rdp_auth_mode": "ntlm", "domain": "CORP"});
        assert!(matches!(
            resolve(Some("kerberos"), None, Some(&stored), FQDN),
            Err(RdpAuthSettingsError::Domain(_))
        ));
        // Leaving Kerberos for NTLM lifts the constraints.
        let stored = json!({"rdp_auth_mode": "kerberos", "domain": REALM});
        assert_eq!(
            resolve(Some("ntlm"), Some(""), Some(&stored), "192.0.2.10"),
            Ok(RdpAuthSettings {
                mode: RdpAuthMode::Ntlm,
                domain: None
            })
        );
    }

    /// The hostname becomes the SPN: only a DNS name is accepted. Short
    /// IPv4 forms, a port, a trailing dot and malformed labels are not.
    #[test]
    fn attack_kerberos_hostname_that_is_not_a_dns_name_is_rejected() {
        for host in [
            "10.1",
            "192.168.1",
            "0x7f.0.0.1",
            "127.1",
            "192.0.2.10.",
            "srv01.corp.example.com.",
            "srv01.corp.example.com:3389",
            "srv01.corp.example.com:1234",
            "a..b",
            "-.x",
            "srv-.corp.example.com",
            "srv01.corp.example.com/admin",
            "srv01.corp.example.com@evil.test",
            "srv 01.corp.example.com",
            "srv01.corp.example.123",
        ] {
            assert!(
                validate_kerberos_fqdn(host).is_err(),
                "{host:?} must be refused"
            );
            for mode in KERBEROS_MODES {
                assert!(
                    matches!(
                        resolve(Some(mode.as_str()), Some(REALM), None, host),
                        Err(RdpAuthSettingsError::Hostname(_))
                    ),
                    "{mode:?} {host:?}"
                );
            }
            // NTLM keeps accepting what the general hostname rule accepts.
            assert!(resolve(Some("ntlm"), None, None, host).is_ok(), "{host:?}");
        }
        for host in [
            "srv01.corp.example.com",
            "SRV01.Corp.Example.COM",
            "srv-01.corp.example.com",
            "1srv.corp.example.com",
            "srv01.example.co",
            "host_1a2b3c4d.corp.example.com",
        ] {
            assert!(
                validate_kerberos_fqdn(host).is_ok(),
                "{host:?} must be accepted"
            );
        }
    }

    #[test]
    fn test_domain_is_bounded_in_every_mode() {
        let long = "a".repeat(MAX_DOMAIN_LEN + 1);
        for raw in [long.as_str(), "CORP\nX", "CORP\u{0}"] {
            assert!(matches!(
                resolve(Some("ntlm"), Some(raw), None, FQDN),
                Err(RdpAuthSettingsError::Domain(_))
            ));
        }
    }

    #[test]
    fn test_refuse_on_non_rdp() {
        assert_eq!(refuse_on_non_rdp(None, None), Ok(()));
        assert_eq!(
            refuse_on_non_rdp(Some("kerberos"), None),
            Err(RdpAuthSettingsError::NotAnRdpAsset)
        );
        assert_eq!(
            refuse_on_non_rdp(None, Some("")),
            Err(RdpAuthSettingsError::NotAnRdpAsset)
        );
    }

    #[test]
    fn test_apply_writes_only_the_two_keys() {
        let mut config = json!({"username": "jdoe", "password": "v1:abc", "domain": "CORP"});
        let changed = apply(
            &mut config,
            &RdpAuthSettings {
                mode: RdpAuthMode::Kerberos,
                domain: Some(REALM.to_string()),
            },
        );
        assert!(changed);
        assert_eq!(
            config,
            json!({"username": "jdoe", "password": "v1:abc", "domain": REALM, "rdp_auth_mode": "kerberos"})
        );
        // Idempotent.
        let again = apply(
            &mut config,
            &RdpAuthSettings {
                mode: RdpAuthMode::Kerberos,
                domain: Some(REALM.to_string()),
            },
        );
        assert!(!again);
        // Clearing the domain removes the key.
        apply(
            &mut config,
            &RdpAuthSettings {
                mode: RdpAuthMode::Ntlm,
                domain: None,
            },
        );
        assert_eq!(
            config,
            json!({"username": "jdoe", "password": "v1:abc", "rdp_auth_mode": "ntlm"})
        );
        // A non-object config becomes an object.
        let mut config = json!(null);
        apply(
            &mut config,
            &RdpAuthSettings {
                mode: RdpAuthMode::Ntlm,
                domain: None,
            },
        );
        assert_eq!(config, json!({"rdp_auth_mode": "ntlm"}));
    }

    #[test]
    fn test_badge_labels_are_distinct() {
        let labels: std::collections::HashSet<_> =
            RdpAuthMode::ALL.into_iter().map(badge_label).collect();
        assert_eq!(labels.len(), RdpAuthMode::ALL.len());
    }

    mod prop {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            /// Whatever is sent, what `resolve` accepts is storable: the
            /// mode is in the closed set, and a Kerberos result always
            /// has an FQDN target and a DNS-form realm.
            #[test]
            fn proptest_resolved_settings_are_always_valid(
                mode in proptest::option::of("\\PC{0,30}"),
                domain in proptest::option::of("\\PC{0,40}"),
                stored_mode_raw in proptest::option::of("[a-z_]{0,26}"),
                stored_domain_raw in proptest::option::of("[A-Za-z0-9.-]{0,30}"),
                hostname in "[A-Za-z0-9.:\\[\\]-]{0,40}",
            ) {
                let mut stored = serde_json::Map::new();
                if let Some(m) = stored_mode_raw {
                    stored.insert(MODE_KEY.to_string(), json!(m));
                }
                if let Some(d) = stored_domain_raw {
                    stored.insert(DOMAIN_KEY.to_string(), json!(d));
                }
                let stored = serde_json::Value::Object(stored);
                if let Ok(settings) = resolve(mode.as_deref(), domain.as_deref(), Some(&stored), &hostname) {
                    prop_assert!(RdpAuthMode::ALL.contains(&settings.mode));
                    if let Some(d) = &settings.domain {
                        prop_assert!(!d.is_empty() && d.len() <= MAX_DOMAIN_LEN);
                    }
                    if settings.mode.uses_kerberos() {
                        prop_assert!(validate_kerberos_fqdn(&hostname).is_ok());
                        let realm = settings.domain.as_deref().unwrap_or_default();
                        prop_assert!(shared::kerberos::normalize_realm(realm).is_ok());
                    }
                    // What is stored reads back as itself.
                    let mut config = stored.clone();
                    apply(&mut config, &settings);
                    prop_assert_eq!(stored_mode(&config), settings.mode);
                    prop_assert_eq!(stored_domain(&config), settings.domain);
                }
            }

            /// A requested mode is accepted only if it is canonical once
            /// trimmed.
            #[test]
            fn proptest_requested_mode_is_exact(raw in "\\PC{0,40}") {
                let trimmed = raw.trim();
                let expected = if trimmed.is_empty() {
                    Ok(None)
                } else {
                    RdpAuthMode::ALL
                        .into_iter()
                        .find(|m| m.as_str() == trimmed)
                        .map(Some)
                        .ok_or(RdpAuthSettingsError::UnknownMode)
                };
                prop_assert_eq!(parse_requested_mode(Some(&raw)), expected);
            }
        }
    }
}
