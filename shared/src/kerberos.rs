//! Kerberos realm validation and ambient-configuration isolation.
//!
//! Two concerns live here because every process on the Kerberos path
//! needs the same answer:
//!
//! 1. **Realm**. The RDP proxy authenticates through `sspi`, which takes
//!    the realm from the asset's `domain` field by upper-casing it, with
//!    no further check. An empty domain yields an empty realm, and a
//!    NetBIOS short name (`CORP`) is forwarded as-is. [`normalize_realm`]
//!    is the single allowlist every writer (web form, API) and the proxy
//!    apply before a value reaches `sspi`, the SPN or the client
//!    principal.
//! 2. **Ambient configuration**. Before upper-casing the domain, `sspi`
//!    reads `KRB5_CONFIG` (default `/etc/krb5.conf`) and applies its
//!    `[domain_realm]` mappings; for a cross-realm hop it resolves the
//!    KDC from `SSPI_KDC_URL_<REALM>`, `SSPI_KDC_URL`, the same file,
//!    then DNS. On a platform without Capsicum this makes the proxy's
//!    behavior depend on the host. The supervisor therefore strips those
//!    variables from the environment its children inherit and pins
//!    `KRB5_CONFIG` to an empty file; the proxy refuses a Kerberos
//!    session when [`ambient_config_is_isolated`] is false.

/// Maximum length of a realm, in bytes (DNS name limit).
pub const MAX_REALM_LEN: usize = 255;

/// Maximum length of one dot-separated label, in bytes.
pub const MAX_REALM_LABEL_LEN: usize = 63;

/// Environment variable naming the krb5 configuration file(s).
pub const KRB5_CONFIG_ENV: &str = "KRB5_CONFIG";

/// Value [`KRB5_CONFIG_ENV`] is pinned to for the RDP proxy: an always
/// empty file, so no `[domain_realm]` or `[realms]` section is ever read.
pub const KRB5_CONFIG_ISOLATED: &str = "/dev/null";

/// Prefix of the `sspi` KDC override variables (`SSPI_KDC_URL` and
/// `SSPI_KDC_URL_<REALM>`).
pub const SSPI_KDC_URL_ENV_PREFIX: &str = "SSPI_KDC_URL";

/// Suffix of the sentinel host handed to `sspi` as "the KDC" of a realm.
///
/// `sspi` asks its `NetworkClient` to reach a URL; the sandboxed proxy
/// never dials it. The URL only carries WHICH realm the exchange is for,
/// as `tcp://<realm>.kdc.vauban.invalid:88`. `.invalid` is reserved
/// (RFC 2606): the name can never resolve, so a code path that would
/// dial it by mistake fails instead of reaching a real host.
pub const KDC_SENTINEL_HOST_SUFFIX: &str = ".kdc.vauban.invalid";

/// Port of the sentinel URL (Kerberos).
pub const KDC_SENTINEL_PORT: u16 = 88;

/// A validated Kerberos realm: upper-case DNS name, at least two labels.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Realm(String);

impl Realm {
    /// The realm in its canonical upper-case form.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Realm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Why a domain was refused as a Kerberos realm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RealmError {
    /// Absent or blank.
    #[error("A domain is required for Kerberos RDP")]
    Empty,
    /// Longer than [`MAX_REALM_LEN`].
    #[error("The Kerberos domain is too long (255 characters at most)")]
    TooLong,
    /// A single label: a NetBIOS short name, not a DNS domain.
    #[error(
        "Kerberos RDP requires the DNS name of the domain (e.g. corp.example.com), \
         not a NetBIOS short name"
    )]
    NotDnsName,
    /// A character outside `[A-Za-z0-9.-]`.
    #[error("The Kerberos domain may only contain letters, digits, dots and hyphens")]
    InvalidCharacter,
    /// Two consecutive dots, or a leading or trailing dot.
    #[error("The Kerberos domain contains an empty label")]
    EmptyLabel,
    /// A label longer than [`MAX_REALM_LABEL_LEN`].
    #[error("A label of the Kerberos domain is too long (63 characters at most)")]
    LabelTooLong,
    /// A label starting or ending with a hyphen.
    #[error("A label of the Kerberos domain starts or ends with a hyphen")]
    HyphenEdge,
}

/// Validate a domain and return it as a canonical realm.
///
/// The input is trimmed and upper-cased. It must then be a DNS name made
/// of at least two labels, each 1 to 63 bytes of `[A-Z0-9-]` that neither
/// starts nor ends with a hyphen, 255 bytes at most in total. Everything
/// else is refused: the result is the only form allowed to reach a
/// Kerberos principal or SPN.
pub fn normalize_realm(domain: &str) -> Result<Realm, RealmError> {
    let trimmed = domain.trim();
    if trimmed.is_empty() {
        return Err(RealmError::Empty);
    }
    if trimmed.len() > MAX_REALM_LEN {
        return Err(RealmError::TooLong);
    }
    if !trimmed
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    {
        return Err(RealmError::InvalidCharacter);
    }

    let mut labels = 0usize;
    for label in trimmed.split('.') {
        if label.is_empty() {
            return Err(RealmError::EmptyLabel);
        }
        if label.len() > MAX_REALM_LABEL_LEN {
            return Err(RealmError::LabelTooLong);
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(RealmError::HyphenEdge);
        }
        labels += 1;
    }
    if labels < 2 {
        return Err(RealmError::NotDnsName);
    }

    Ok(Realm(trimmed.to_ascii_uppercase()))
}

/// Sentinel host naming `realm` (lower-case realm + reserved suffix).
pub fn kdc_sentinel_host(realm: &Realm) -> String {
    let mut host = realm.as_str().to_ascii_lowercase();
    host.push_str(KDC_SENTINEL_HOST_SUFFIX);
    host
}

/// Recover the realm from a sentinel host. `None` for anything that is
/// not exactly `<valid realm><suffix>`: a real KDC host name produced by
/// `sspi`'s own discovery (krb5.conf, DNS, env) is never a sentinel.
pub fn realm_from_sentinel_host(host: &str) -> Option<Realm> {
    let lowered = host.to_ascii_lowercase();
    let realm = lowered.strip_suffix(KDC_SENTINEL_HOST_SUFFIX)?;
    normalize_realm(realm).ok()
}

/// `sspi` reads this variable for the DNS server it queries when it
/// looks a KDC up by SRV record.
pub const SSPI_DNS_URL_ENV: &str = "SSPI_DNS_URL";

/// Whether `name` is an `sspi` KDC discovery override: `SSPI_KDC_URL`,
/// `SSPI_KDC_URL_<REALM>`, or [`SSPI_DNS_URL_ENV`].
pub fn is_sspi_kdc_override(name: &str) -> bool {
    if name == SSPI_DNS_URL_ENV {
        return true;
    }
    match name.strip_prefix(SSPI_KDC_URL_ENV_PREFIX) {
        Some("") => true,
        Some(rest) => rest.starts_with('_'),
        None => false,
    }
}

/// Names, among `names`, that must be removed from an environment before
/// a child inherits it: [`KRB5_CONFIG_ENV`] and every `sspi` KDC override.
pub fn ambient_config_removals<I, S>(names: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    names
        .into_iter()
        .filter(|name| {
            let name = name.as_ref();
            name == KRB5_CONFIG_ENV || is_sspi_kdc_override(name)
        })
        .map(|name| name.as_ref().to_string())
        .collect()
}

/// Whether an environment carries no ambient Kerberos configuration:
/// [`KRB5_CONFIG_ENV`] is exactly [`KRB5_CONFIG_ISOLATED`] and no `sspi`
/// KDC override is present. An absent `KRB5_CONFIG` is NOT isolated
/// (`sspi` would then fall back to `/etc/krb5.conf`).
pub fn ambient_config_is_isolated<I, K, V>(vars: I) -> bool
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<str>,
    V: AsRef<str>,
{
    let mut krb5_config_pinned = false;
    for (name, value) in vars {
        let name = name.as_ref();
        if is_sspi_kdc_override(name) {
            return false;
        }
        if name == KRB5_CONFIG_ENV {
            if value.as_ref() != KRB5_CONFIG_ISOLATED {
                return false;
            }
            krb5_config_pinned = true;
        }
    }
    krb5_config_pinned
}

/// Why the supervisor refused, or failed, a KDC socket lease.
///
/// The lease answer ([`crate::messages::Message::KerberosKdcResponse`])
/// carries a single error string. The supervisor writes it as
/// `<code>: <text>` with [`KdcLeaseRefusal::error`]; the proxy reads the
/// code back with [`KdcLeaseRefusal::from_error`] to tell an unknown realm
/// from an unreachable KDC. The text after the code is for logs only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdcLeaseRefusal {
    /// Kerberos brokering is disabled or has no realm.
    Disabled,
    /// The realm in the request is not a DNS-form realm.
    InvalidRealm,
    /// The realm is not in the `[auth.kerberos]` table.
    RealmNotConfigured,
    /// A legacy lease named no realm while several are configured.
    AmbiguousRealm,
    /// No KDC host of the realm accepted a connection in time.
    Unreachable,
}

impl KdcLeaseRefusal {
    /// Every refusal.
    pub const ALL: [KdcLeaseRefusal; 5] = [
        KdcLeaseRefusal::Disabled,
        KdcLeaseRefusal::InvalidRealm,
        KdcLeaseRefusal::RealmNotConfigured,
        KdcLeaseRefusal::AmbiguousRealm,
        KdcLeaseRefusal::Unreachable,
    ];

    /// Stable code, `[a-z-]` only: it cannot contain the separator.
    pub const fn code(&self) -> &'static str {
        match self {
            KdcLeaseRefusal::Disabled => "kdc-lease-disabled",
            KdcLeaseRefusal::InvalidRealm => "kdc-lease-invalid-realm",
            KdcLeaseRefusal::RealmNotConfigured => "kdc-lease-realm-not-configured",
            KdcLeaseRefusal::AmbiguousRealm => "kdc-lease-ambiguous-realm",
            KdcLeaseRefusal::Unreachable => "kdc-lease-unreachable",
        }
    }

    /// The lease error string for this refusal: `<code>: <text>`.
    pub fn error(&self, text: &str) -> String {
        format!("{}: {text}", self.code())
    }

    /// Read the refusal back from a lease error string. The code is
    /// everything before the FIRST `": "` and must match exactly; a code
    /// that appears later in the text is not one.
    pub fn from_error(error: &str) -> Option<Self> {
        let (code, _text) = error.split_once(": ")?;
        Self::ALL.into_iter().find(|r| r.code() == code)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------
    // normalize_realm
    // ---------------------------------------------------------------

    #[test]
    fn test_normalize_realm_uppercases_a_dns_domain() {
        let realm = normalize_realm("corp.example.com").unwrap();
        assert_eq!(realm.as_str(), "CORP.EXAMPLE.COM");
        assert_eq!(realm.to_string(), "CORP.EXAMPLE.COM");
    }

    #[test]
    fn test_normalize_realm_trims_surrounding_whitespace() {
        assert_eq!(
            normalize_realm("  Corp.Example.Com\n").unwrap().as_str(),
            "CORP.EXAMPLE.COM"
        );
    }

    #[test]
    fn test_normalize_realm_accepts_digits_and_inner_hyphens() {
        assert_eq!(
            normalize_realm("ad-01.site2.example.net").unwrap().as_str(),
            "AD-01.SITE2.EXAMPLE.NET"
        );
    }

    #[test]
    fn test_normalize_realm_is_idempotent() {
        let once = normalize_realm("corp.example.com").unwrap();
        let twice = normalize_realm(once.as_str()).unwrap();
        assert_eq!(once, twice);
    }

    #[test]
    fn test_normalize_realm_empty_is_rejected() {
        for raw in ["", " ", "\t\n"] {
            assert_eq!(normalize_realm(raw), Err(RealmError::Empty), "{raw:?}");
        }
    }

    #[test]
    fn attack_netbios_short_name_is_rejected() {
        for raw in ["CORP", "corp", "WORKGROUP", "a"] {
            assert_eq!(normalize_realm(raw), Err(RealmError::NotDnsName), "{raw:?}");
        }
    }

    #[test]
    fn attack_realm_with_principal_separators_is_rejected() {
        // '@' and '/' are the Kerberos principal separators; a space, a
        // backslash or a NUL would likewise change what the name means.
        for raw in [
            "corp.example.com@evil.test",
            "corp.example.com/admin",
            "corp example.com",
            "corp\\example.com",
            "corp.example.com\0",
            "corp_x.example.com",
            "corp.example.com:88",
            "corp.exämple.com",
        ] {
            assert_eq!(
                normalize_realm(raw),
                Err(RealmError::InvalidCharacter),
                "{raw:?}"
            );
        }
    }

    #[test]
    fn test_normalize_realm_empty_label_is_rejected() {
        for raw in [".example.com", "example.com.", "corp..example.com", "."] {
            assert_eq!(normalize_realm(raw), Err(RealmError::EmptyLabel), "{raw:?}");
        }
    }

    #[test]
    fn test_normalize_realm_hyphen_edge_is_rejected() {
        for raw in [
            "-corp.example.com",
            "corp-.example.com",
            "corp.-example.com",
        ] {
            assert_eq!(normalize_realm(raw), Err(RealmError::HyphenEdge), "{raw:?}");
        }
    }

    #[test]
    fn test_normalize_realm_label_length_bounds() {
        let ok = format!("{}.example.com", "a".repeat(MAX_REALM_LABEL_LEN));
        assert!(normalize_realm(&ok).is_ok());
        let too_long = format!("{}.example.com", "a".repeat(MAX_REALM_LABEL_LEN + 1));
        assert_eq!(normalize_realm(&too_long), Err(RealmError::LabelTooLong));
    }

    #[test]
    fn test_normalize_realm_total_length_bounds() {
        // 4 labels of 63 bytes + 3 dots = 255 bytes: the limit.
        let label = "a".repeat(63);
        let at_limit = [label.as_str(); 4].join(".");
        assert_eq!(at_limit.len(), MAX_REALM_LEN);
        assert!(normalize_realm(&at_limit).is_ok());
        let over = format!("{at_limit}.b");
        assert_eq!(normalize_realm(&over), Err(RealmError::TooLong));
    }

    #[test]
    fn test_realm_error_messages_are_operator_facing() {
        assert!(RealmError::NotDnsName.to_string().contains("DNS name"));
        assert!(RealmError::Empty.to_string().contains("required"));
    }

    // ---------------------------------------------------------------
    // sentinel host
    // ---------------------------------------------------------------

    #[test]
    fn test_sentinel_host_round_trips_the_realm() {
        let realm = normalize_realm("corp.example.com").unwrap();
        let host = kdc_sentinel_host(&realm);
        assert_eq!(host, "corp.example.com.kdc.vauban.invalid");
        assert_eq!(realm_from_sentinel_host(&host), Some(realm));
    }

    #[test]
    fn test_sentinel_host_is_case_insensitive() {
        assert_eq!(
            realm_from_sentinel_host("CORP.Example.COM.KDC.Vauban.Invalid")
                .unwrap()
                .as_str(),
            "CORP.EXAMPLE.COM"
        );
    }

    #[test]
    fn attack_real_kdc_host_is_not_a_sentinel() {
        for host in [
            "dc1.corp.example.com",
            "kdc-via-supervisor",
            "192.0.2.10",
            "corp.example.com.kdc.vauban.invalid.attacker.test",
            "kdc.vauban.invalid",
            ".kdc.vauban.invalid",
            "corp.kdc.vauban.invalid",
            "corp.example.com@x.kdc.vauban.invalid",
            "",
        ] {
            assert_eq!(realm_from_sentinel_host(host), None, "{host:?}");
        }
    }

    #[test]
    fn test_sentinel_suffix_is_under_the_reserved_invalid_tld() {
        assert!(KDC_SENTINEL_HOST_SUFFIX.ends_with(".invalid"));
        assert!(KDC_SENTINEL_HOST_SUFFIX.starts_with('.'));
    }

    // ---------------------------------------------------------------
    // ambient configuration
    // ---------------------------------------------------------------

    #[test]
    fn test_is_sspi_kdc_override_matches_generic_and_per_realm() {
        assert!(is_sspi_kdc_override("SSPI_KDC_URL"));
        assert!(is_sspi_kdc_override("SSPI_KDC_URL_CORP.EXAMPLE.COM"));
        assert!(is_sspi_kdc_override("SSPI_KDC_URL_"));
    }

    #[test]
    fn test_is_sspi_kdc_override_ignores_lookalikes() {
        for name in [
            "SSPI_KDC_URLS",
            "SSPI_KDC",
            "XSSPI_KDC_URL",
            "sspi_kdc_url",
            "KRB5_CONFIG",
            "",
        ] {
            assert!(!is_sspi_kdc_override(name), "{name:?}");
        }
    }

    #[test]
    fn test_ambient_config_removals_selects_only_kerberos_names() {
        let names = [
            "PATH",
            "KRB5_CONFIG",
            "SSPI_KDC_URL",
            "SSPI_KDC_URL_CORP.EXAMPLE.COM",
            "VAUBAN_IPC_READ",
            "KRB5CCNAME",
        ];
        assert_eq!(
            ambient_config_removals(names),
            vec![
                "KRB5_CONFIG".to_string(),
                "SSPI_KDC_URL".to_string(),
                "SSPI_KDC_URL_CORP.EXAMPLE.COM".to_string(),
            ]
        );
    }

    #[test]
    fn test_ambient_config_is_isolated_when_pinned_and_clean() {
        let env = [("PATH", "/usr/bin"), ("KRB5_CONFIG", KRB5_CONFIG_ISOLATED)];
        assert!(ambient_config_is_isolated(env));
    }

    #[test]
    fn attack_absent_krb5_config_is_rejected() {
        // Absent means `sspi` reads /etc/krb5.conf: not isolated.
        let env = [("PATH", "/usr/bin")];
        assert!(!ambient_config_is_isolated(env));
        assert!(!ambient_config_is_isolated(Vec::<(String, String)>::new()));
    }

    #[test]
    fn attack_hostile_krb5_config_path_is_rejected() {
        for path in [
            "/etc/krb5.conf",
            "/tmp/evil.conf",
            "",
            "/dev/null:/tmp/evil.conf",
        ] {
            let env = [("KRB5_CONFIG", path)];
            assert!(!ambient_config_is_isolated(env), "{path:?}");
        }
    }

    #[test]
    fn attack_sspi_kdc_override_is_rejected() {
        for name in ["SSPI_KDC_URL", "SSPI_KDC_URL_CORP.EXAMPLE.COM"] {
            let env = [
                ("KRB5_CONFIG", KRB5_CONFIG_ISOLATED),
                (name, "tcp://attacker.test:88"),
            ];
            assert!(!ambient_config_is_isolated(env), "{name}");
        }
    }

    // ---------------------------------------------------------------
    // properties
    // ---------------------------------------------------------------

    mod properties {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(512))]

            /// Whatever the input, an accepted realm is canonical: only
            /// `[A-Z0-9.-]`, at least one dot, within the length bound,
            /// and stable under a second normalization.
            #[test]
            fn accepted_realm_is_canonical(raw in "\\PC{0,300}") {
                if let Ok(realm) = normalize_realm(&raw) {
                    let s = realm.as_str();
                    prop_assert!(s.len() <= MAX_REALM_LEN);
                    prop_assert!(s.contains('.'));
                    let canonical_bytes = s.bytes().all(|b| {
                        b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'.' || b == b'-'
                    });
                    prop_assert!(canonical_bytes);
                    prop_assert!(!s.starts_with('.') && !s.ends_with('.'));
                    prop_assert_eq!(normalize_realm(s), Ok(realm.clone()));
                }
            }

            /// A single label is never a realm, however it is spelled.
            #[test]
            fn single_label_is_never_a_realm(label in "[A-Za-z0-9-]{1,63}") {
                prop_assert!(normalize_realm(&label).is_err());
            }

            /// A well-formed DNS domain is accepted and only upper-cased.
            #[test]
            fn well_formed_domain_is_uppercased(
                labels in proptest::collection::vec("[a-z0-9]{1,12}", 2..5)
            ) {
                let domain = labels.join(".");
                let expected = domain.to_ascii_uppercase();
                let realm = normalize_realm(&domain);
                prop_assert_eq!(realm.as_ref().map(Realm::as_str), Ok(expected.as_str()));
            }

            /// The sentinel host of any accepted realm maps back to it,
            /// and nothing else maps to a realm.
            #[test]
            fn sentinel_host_is_a_bijection_on_realms(
                labels in proptest::collection::vec("[a-z0-9]{1,12}", 2..5)
            ) {
                let realm = normalize_realm(&labels.join(".")).unwrap();
                let host = kdc_sentinel_host(&realm);
                prop_assert_eq!(realm_from_sentinel_host(&host), Some(realm));
            }

            /// An arbitrary host is a sentinel only if it carries the
            /// reserved suffix after a valid realm.
            #[test]
            fn arbitrary_host_is_rarely_a_sentinel(host in "[a-zA-Z0-9.@/_:-]{0,80}") {
                if let Some(realm) = realm_from_sentinel_host(&host) {
                    prop_assert!(host.to_ascii_lowercase().ends_with(KDC_SENTINEL_HOST_SUFFIX));
                    prop_assert_eq!(kdc_sentinel_host(&realm), host.to_ascii_lowercase());
                }
            }

            /// Any variable named like an `sspi` KDC override breaks the
            /// isolation, and is always selected for removal.
            #[test]
            fn any_sspi_override_breaks_isolation(suffix in "(_[A-Za-z0-9.-]{0,40})?") {
                let name = format!("{SSPI_KDC_URL_ENV_PREFIX}{suffix}");
                let env = vec![
                    (KRB5_CONFIG_ENV.to_string(), KRB5_CONFIG_ISOLATED.to_string()),
                    (name.clone(), "tcp://attacker.test:88".to_string()),
                ];
                prop_assert!(!ambient_config_is_isolated(env));
                prop_assert_eq!(ambient_config_removals([name.clone()]), vec![name]);
            }

            /// Unrelated variables never affect the verdict.
            #[test]
            fn unrelated_variables_do_not_matter(
                names in proptest::collection::vec("[A-Z_]{1,12}", 0..8)
            ) {
                let mut env: Vec<(String, String)> = names
                    .into_iter()
                    .filter(|n| n != KRB5_CONFIG_ENV && !is_sspi_kdc_override(n))
                    .map(|n| (n, "x".to_string()))
                    .collect();
                prop_assert!(!ambient_config_is_isolated(env.clone()));
                env.push((KRB5_CONFIG_ENV.to_string(), KRB5_CONFIG_ISOLATED.to_string()));
                prop_assert!(ambient_config_is_isolated(env));
            }
        }
    }

    #[test]
    fn kdc_lease_refusal_codes_round_trip() {
        for refusal in KdcLeaseRefusal::ALL {
            let error = refusal.error("some text: with a colon");
            assert_eq!(KdcLeaseRefusal::from_error(&error), Some(refusal));
            assert!(
                refusal
                    .code()
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b == b'-')
            );
        }
    }

    #[test]
    fn kdc_lease_refusal_is_read_from_the_prefix_only() {
        assert_eq!(KdcLeaseRefusal::from_error("send_fd: broken pipe"), None);
        assert_eq!(KdcLeaseRefusal::from_error(""), None);
        assert_eq!(KdcLeaseRefusal::from_error("kdc-lease-unreachable"), None);
        // A code inside the text is not a code.
        assert_eq!(
            KdcLeaseRefusal::from_error("oops: kdc-lease-unreachable: x"),
            None
        );
        // No prefix match: the whole code must match.
        assert_eq!(
            KdcLeaseRefusal::from_error("kdc-lease-unreachable-not: x"),
            None
        );
        // The first separator wins: a realm-shaped text cannot change it.
        assert_eq!(
            KdcLeaseRefusal::from_error("kdc-lease-realm-not-configured: kdc-lease-unreachable: x"),
            Some(KdcLeaseRefusal::RealmNotConfigured)
        );
    }

    /// `sspi` also takes a DNS server for KDC discovery from the
    /// environment: it is scrubbed and breaks isolation like a KDC URL.
    #[test]
    fn attack_ambient_dns_override_for_kdc_discovery_is_rejected() {
        assert!(is_sspi_kdc_override(SSPI_DNS_URL_ENV));
        assert!(!is_sspi_kdc_override("SSPI_DNS_URLS"));
        assert_eq!(
            ambient_config_removals(["PATH", "SSPI_DNS_URL", "HOME"]),
            vec!["SSPI_DNS_URL".to_string()]
        );
        assert!(!ambient_config_is_isolated([
            (KRB5_CONFIG_ENV, KRB5_CONFIG_ISOLATED),
            ("SSPI_DNS_URL", "udp://203.0.113.9:53"),
        ]));
        assert!(ambient_config_is_isolated([(
            KRB5_CONFIG_ENV,
            KRB5_CONFIG_ISOLATED
        )]));
    }
}
