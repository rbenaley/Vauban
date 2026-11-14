//! The production CredSSP leg, end to end, without Active Directory.
//!
//! Each test calls `perform_credssp_step` (the function `connect` runs)
//! with the production Kerberos network client, against the harness of
//! `crate::test_support`: an in-memory KDC and `sspi`'s CredSSP server
//! as the target. See that module for what this does and does not prove.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use crate::auth_failure::{KdcTrace, krb_error};
use crate::test_support::kdc_mock::{KdcFaults, KdcMock};
use crate::test_support::{
    CredsspTarget, DOMAIN, KdcLink, MockKdcTransport, PASSWORD, REALM, TARGET_HOST, TargetOutcome,
    TargetPackages, TargetReport, USERNAME, kdc_with_password, kdc_without_target_spn,
    server_public_key,
};
use shared::kerberos::KdcLeaseRefusal;

impl KdcTransport for MockKdcTransport {
    fn kdc_round_trip<'a>(
        &'a self,
        _session_id: &'a str,
        realm: &'a shared::kerberos::Realm,
        data: Vec<u8>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, String>> + Send + 'a>>
    {
        Box::pin(async move { self.exchange(realm, &data) })
    }
}

/// One session open attempt.
struct Attempt {
    mode: RdpAuthMode,
    kdc: KdcMock,
    link: KdcLink,
    target: TargetPackages,
    /// Hostname of the asset (seeds the `TERMSRV/<host>` SPN).
    host: &'static str,
    username: &'static str,
    password: &'static str,
}

impl Attempt {
    /// A well-configured asset in `mode`, against a healthy domain.
    fn healthy(mode: RdpAuthMode) -> Self {
        Self {
            mode,
            kdc: kdc_with_password(PASSWORD),
            link: KdcLink::Up,
            target: if mode.uses_kerberos() {
                TargetPackages::Kerberos
            } else {
                TargetPackages::RawNtlm
            },
            host: TARGET_HOST,
            username: USERNAME,
            password: PASSWORD,
        }
    }
}

struct Outcome {
    /// What `perform_credssp_step` returned.
    result: ConnectorResult<()>,
    /// The reason production would send for that error.
    reason: Option<RdpAuthFailure>,
    trace: KdcTrace,
    target: TargetReport,
    /// Realms the client asked a KDC socket for.
    realms_asked: Vec<String>,
    /// The password left in the connector configuration after CredSSP:
    /// what IronRDP then sends to the target in the Client Info PDU.
    client_info_password: String,
}

async fn open(attempt: Attempt) -> Outcome {
    let Attempt {
        mode,
        kdc,
        link,
        target,
        host,
        username,
        password,
    } = attempt;
    let transport = MockKdcTransport::new(Arc::new(kdc), link);
    let relay: Arc<dyn KdcTransport> = transport.clone();
    let Opened {
        result,
        reason,
        trace,
        target,
        client_info_password,
    } = open_with(mode, relay, target, host, username, password).await;
    let realms_asked = transport.realms_asked.lock().unwrap().clone();
    Outcome {
        result,
        reason,
        trace,
        target,
        realms_asked,
        client_info_password,
    }
}

/// Run `perform_credssp_step` in `mode` against the in-process target,
/// with `relay` as the path to the KDC.
pub(super) struct Opened {
    pub result: ConnectorResult<()>,
    pub reason: Option<RdpAuthFailure>,
    pub trace: KdcTrace,
    pub target: TargetReport,
    pub client_info_password: String,
}

pub(super) async fn open_with(
    mode: RdpAuthMode,
    relay: Arc<dyn KdcTransport>,
    target: TargetPackages,
    host: &str,
    username: &str,
    password: &str,
) -> Opened {
    let (client_io, target_io) = tokio::io::duplex(256 * 1024);
    let target_task = tokio::spawn(CredsspTarget::serve(target_io, target));

    // The Kerberos client exactly as `for_auth_mode` builds it, with the
    // given KDC path in place of the supervisor relay.
    let mut network_client = if auth_mode_profile(mode).kerberos {
        SessionNetworkClient::KerberosRelay(KerberosRelayNetworkClient {
            relay,
            session_id: "sess".to_string(),
            realm: shared::kerberos::normalize_realm(DOMAIN).unwrap(),
            trace: KdcTrace::default(),
        })
    } else {
        SessionNetworkClient::for_auth_mode(mode, None, "sess", None).unwrap()
    };

    // The domain as the session-open pre-flight hands it over: the
    // canonical realm in a Kerberos mode, absent for a local NTLM account.
    let domain = mode.uses_kerberos().then(|| REALM.to_string());
    let config = build_connector_config(
        username.to_string(),
        password.to_string(),
        domain,
        1024,
        768,
    );
    let mut connector = ClientConnector::new(config, "127.0.0.1:3389".parse().unwrap());
    connector.state = ClientConnectorState::Credssp {
        selected_protocol: nego::SecurityProtocol::HYBRID,
    };
    let mut framed = ironrdp_tokio::TokioFramed::new(client_io);
    let mut buf = WriteBuf::new();

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        perform_credssp_step(
            &mut connector,
            &mut framed,
            &mut network_client,
            &mut buf,
            connector::ServerName::new(host),
            server_public_key(),
            mode,
        ),
    )
    .await
    .expect("the CredSSP leg must terminate");
    drop(framed);

    let reason = result
        .as_ref()
        .err()
        .map(|e| auth_failure_reason(mode, e, &network_client));
    let target = tokio::time::timeout(std::time::Duration::from_secs(30), target_task)
        .await
        .expect("the target must terminate")
        .unwrap();
    let client_info_password = match &connector.config.credentials {
        Credentials::UsernamePassword { password, .. } => password.clone(),
        Credentials::SmartCard { .. } => panic!("the proxy only uses password credentials"),
    };
    Opened {
        result,
        reason,
        trace: network_client.kdc_trace(),
        target,
        client_info_password,
    }
}

const NTLMSSP_SIGNATURE: &[u8] = b"NTLMSSP\0";

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

// ---- success ------------------------------------------------------------

/// `kerberos`: the leg completes and the target receives the identity.
#[tokio::test]
async fn test_kerberos_mode_completes_and_delegates_the_identity() {
    let outcome = open(Attempt::healthy(RdpAuthMode::Kerberos)).await;
    outcome
        .result
        .as_ref()
        .expect("the Kerberos leg must complete");
    match &outcome.target.outcome {
        TargetOutcome::Authenticated { account, password } => {
            assert_eq!(account, USERNAME);
            assert_eq!(
                password, PASSWORD,
                "regular TSCredentials carry the password"
            );
        }
        other => panic!("target did not authenticate the client: {other:?}"),
    }
    assert!(!contains(&outcome.target.client_bytes, NTLMSSP_SIGNATURE));
    // Every KDC exchange was for the session realm, and the KDC answered.
    assert!(
        outcome.realms_asked.len() >= 2,
        "AS then TGS: {:?}",
        outcome.realms_asked
    );
    assert!(outcome.realms_asked.iter().all(|r| r == REALM));
    assert_eq!(outcome.trace.last_krb_error, None);
    assert!(!outcome.trace.relay_failed);
    // This mode delegates the password; the Client Info PDU carries it
    // too, as in NTLM. Stated, not hidden.
    assert_eq!(outcome.client_info_password, PASSWORD);
}

/// `kerberos_restricted_admin`: the leg completes and the target receives
/// EMPTY TSCredentials. The password never reaches it.
#[tokio::test]
async fn test_restricted_admin_mode_completes_without_delegating_the_password() {
    let outcome = open(Attempt::healthy(RdpAuthMode::KerberosRestrictedAdmin)).await;
    outcome
        .result
        .as_ref()
        .expect("the Restricted Admin leg must complete");
    match &outcome.target.outcome {
        TargetOutcome::Authenticated { account, password } => {
            assert_eq!(
                account, "",
                "credential-less TSCredentials carry no account"
            );
            assert_eq!(
                password, "",
                "credential-less TSCredentials carry no password"
            );
        }
        other => panic!("target did not complete CredSSP: {other:?}"),
    }
    // The password is nowhere in what the client sent, in either of the
    // encodings a TSCredentials would use.
    let utf16: Vec<u8> = PASSWORD.encode_utf16().flat_map(u16::to_le_bytes).collect();
    assert!(!contains(&outcome.target.client_bytes, PASSWORD.as_bytes()));
    assert!(!contains(&outcome.target.client_bytes, &utf16));
    assert!(!contains(&outcome.target.client_bytes, NTLMSSP_SIGNATURE));
    assert!(outcome.realms_asked.iter().all(|r| r == REALM));
    // And it is gone from the configuration IronRDP builds the Client
    // Info PDU from, which is sent to the target AFTER CredSSP.
    assert_eq!(
        outcome.client_info_password, "",
        "Restricted Admin must not send the password in the Client Info PDU"
    );
}

/// The password leaves the connector configuration in Restricted Admin
/// even when the leg FAILS after the CredSSP client was built: no later
/// step can send it.
#[tokio::test]
async fn attack_password_in_client_info_after_failed_restricted_admin_is_rejected() {
    for make in [
        (|mode| Attempt {
            target: TargetPackages::NtlmOnly,
            ..Attempt::healthy(mode)
        }) as fn(RdpAuthMode) -> Attempt,
        |mode| Attempt {
            link: KdcLink::Down("down".to_string()),
            ..Attempt::healthy(mode)
        },
    ] {
        let outcome = open(make(RdpAuthMode::KerberosRestrictedAdmin)).await;
        assert!(outcome.result.is_err());
        assert_eq!(outcome.client_info_password, "");
    }
}

/// Non-regression: the NTLM mode still completes, with no KDC exchange.
#[tokio::test]
async fn test_ntlm_mode_completes_without_any_kdc_exchange() {
    let outcome = open(Attempt::healthy(RdpAuthMode::Ntlm)).await;
    outcome.result.as_ref().expect("the NTLM leg must complete");
    assert!(matches!(
        outcome.target.outcome,
        TargetOutcome::Authenticated { .. }
    ));
    assert!(outcome.realms_asked.is_empty());
    assert_eq!(outcome.trace, KdcTrace::default());
    assert!(contains(&outcome.target.client_bytes, NTLMSSP_SIGNATURE));
}

// ---- no NTLM downgrade --------------------------------------------------

/// A target that only does NTLM: both Kerberos modes fail, and the client
/// never emits an NTLM token, whichever way the target offers NTLM.
#[tokio::test]
async fn attack_ntlm_downgrade_by_the_target_is_rejected() {
    for mode in [RdpAuthMode::Kerberos, RdpAuthMode::KerberosRestrictedAdmin] {
        for target in [TargetPackages::NtlmOnly, TargetPackages::RawNtlm] {
            let outcome = open(Attempt {
                target,
                ..Attempt::healthy(mode)
            })
            .await;
            assert!(
                outcome.result.is_err(),
                "{mode:?} against {target:?} must fail"
            );
            assert!(
                !matches!(outcome.target.outcome, TargetOutcome::Authenticated { .. }),
                "{mode:?} against {target:?}: {:?}",
                outcome.target.outcome
            );
            assert!(
                !contains(&outcome.target.client_bytes, NTLMSSP_SIGNATURE),
                "{mode:?} against {target:?}: the client sent an NTLM token"
            );
            assert_eq!(
                outcome.reason,
                Some(RdpAuthFailure::KerberosPackageRefused),
                "{mode:?} against {target:?}"
            );
        }
    }
}

// ---- classified failures ------------------------------------------------

/// Run a failing attempt in both Kerberos modes and check the reason, that
/// the target never authenticated anyone, and that no NTLM token left.
async fn assert_fails_with(make: impl Fn(RdpAuthMode) -> Attempt, expected: RdpAuthFailure) {
    for mode in [RdpAuthMode::Kerberos, RdpAuthMode::KerberosRestrictedAdmin] {
        let outcome = open(make(mode)).await;
        assert!(outcome.result.is_err(), "{mode:?} must fail");
        assert_eq!(
            outcome.reason,
            Some(expected),
            "{mode:?}: {:?}",
            outcome.trace
        );
        assert!(
            !matches!(outcome.target.outcome, TargetOutcome::Authenticated { .. }),
            "{mode:?}"
        );
        assert!(
            !contains(&outcome.target.client_bytes, NTLMSSP_SIGNATURE),
            "{mode:?}"
        );
    }
}

/// The stored password is not the account's: the KDC refuses the
/// pre-authentication.
#[tokio::test]
async fn test_wrong_password_is_pre_auth_failed() {
    assert_fails_with(
        |mode| Attempt {
            password: "not-the-password",
            ..Attempt::healthy(mode)
        },
        RdpAuthFailure::PreAuthFailed,
    )
    .await;
}

/// `TERMSRV/<host>` is not registered in the directory: the KDC refuses
/// the service ticket.
#[tokio::test]
async fn test_unregistered_spn_is_service_principal_unknown() {
    assert_fails_with(
        |mode| Attempt {
            kdc: kdc_without_target_spn(),
            ..Attempt::healthy(mode)
        },
        RdpAuthFailure::ServicePrincipalUnknown,
    )
    .await;
}

/// The asset hostname is a name the target does not answer to (a DNS
/// alias). With user-to-user Kerberos the client first asks the TARGET
/// for its ticket under that name, and this target refuses before any
/// KDC is asked: the failure is reported as a refused Kerberos
/// negotiation, not as an unknown SPN.
#[tokio::test]
async fn test_hostname_the_target_does_not_answer_to_is_refused_by_the_target() {
    for mode in [RdpAuthMode::Kerberos, RdpAuthMode::KerberosRestrictedAdmin] {
        let outcome = open(Attempt {
            host: "alias.corp.example.com",
            ..Attempt::healthy(mode)
        })
        .await;
        assert!(outcome.result.is_err(), "{mode:?}");
        assert_eq!(outcome.reason, Some(RdpAuthFailure::KerberosPackageRefused));
        assert!(
            outcome.realms_asked.is_empty(),
            "no KDC exchange took place"
        );
        assert!(!contains(&outcome.target.client_bytes, NTLMSSP_SIGNATURE));
    }
}

/// The account does not exist in the realm.
#[tokio::test]
async fn test_unknown_account_is_client_principal_unknown() {
    assert_fails_with(
        |mode| Attempt {
            username: "nobody",
            ..Attempt::healthy(mode)
        },
        RdpAuthFailure::ClientPrincipalUnknown,
    )
    .await;
}

/// The KDC refuses the request for clock skew.
#[tokio::test]
async fn test_clock_skew_is_clock_skew() {
    assert_fails_with(
        |mode| {
            let mut kdc = kdc_with_password(PASSWORD);
            kdc.faults = KdcFaults {
                as_error: Some(krb_error::KRB_AP_ERR_SKEW),
                ..KdcFaults::default()
            };
            Attempt {
                kdc,
                ..Attempt::healthy(mode)
            }
        },
        RdpAuthFailure::ClockSkew,
    )
    .await;
}

/// Disabled or locked account, and expired password.
#[tokio::test]
async fn test_account_state_errors_are_classified() {
    for (code, expected) in [
        (
            krb_error::KDC_ERR_CLIENT_REVOKED,
            RdpAuthFailure::AccountDisabledOrLocked,
        ),
        (
            krb_error::KDC_ERR_KEY_EXPIRED,
            RdpAuthFailure::PasswordExpired,
        ),
        (
            krb_error::KDC_ERR_ETYPE_NOSUPP,
            RdpAuthFailure::EncryptionTypeUnsupported,
        ),
    ] {
        assert_fails_with(
            |mode| {
                let mut kdc = kdc_with_password(PASSWORD);
                kdc.faults = KdcFaults {
                    as_error: Some(code),
                    ..KdcFaults::default()
                };
                Attempt {
                    kdc,
                    ..Attempt::healthy(mode)
                }
            },
            expected,
        )
        .await;
    }
}

/// An account exempt from pre-authentication: the KDC answers the first
/// AS-REQ with a TGT, which `sspi` does not accept.
#[tokio::test]
async fn test_account_exempt_from_pre_authentication_is_classified() {
    assert_fails_with(
        |mode| {
            let mut kdc = kdc_with_password(PASSWORD);
            kdc.faults = KdcFaults {
                skip_preauth: true,
                ..KdcFaults::default()
            };
            Attempt {
                kdc,
                ..Attempt::healthy(mode)
            }
        },
        RdpAuthFailure::PreAuthNotRequired,
    )
    .await;
}

/// No KDC socket: a silent KDC, and each refusal of the supervisor.
#[tokio::test]
async fn test_kdc_lease_failures_are_classified() {
    let cases = [
        (
            "KDC FD lease timed out after 15s".to_string(),
            RdpAuthFailure::KdcUnreachable,
        ),
        (
            KdcLeaseRefusal::Unreachable.error("no KDC reachable (tried 2/2 endpoints)"),
            RdpAuthFailure::KdcUnreachable,
        ),
        (
            KdcLeaseRefusal::RealmNotConfigured
                .error("Kerberos realm CORP.EXAMPLE.COM is not configured"),
            RdpAuthFailure::RealmNotConfigured,
        ),
        (
            KdcLeaseRefusal::Disabled.error("Kerberos KDC brokering is disabled"),
            RdpAuthFailure::KerberosBrokerUnavailable,
        ),
    ];
    for (error, expected) in cases {
        assert_fails_with(
            |mode| Attempt {
                link: KdcLink::Down(error.clone()),
                ..Attempt::healthy(mode)
            },
            expected,
        )
        .await;
    }
}

/// Whatever fails, a Kerberos mode never ends in an NTLM session, and
/// only the session realm is ever asked for.
#[tokio::test]
async fn attack_no_failure_path_reaches_ntlm_or_another_realm() {
    let attempts: Vec<Box<dyn Fn(RdpAuthMode) -> Attempt>> = vec![
        Box::new(|mode| Attempt {
            password: "bad",
            ..Attempt::healthy(mode)
        }),
        Box::new(|mode| Attempt {
            host: "alias.corp.example.com",
            ..Attempt::healthy(mode)
        }),
        Box::new(|mode| Attempt {
            link: KdcLink::Down("down".to_string()),
            target: TargetPackages::NtlmOnly,
            ..Attempt::healthy(mode)
        }),
        Box::new(|mode| Attempt {
            password: "bad",
            target: TargetPackages::RawNtlm,
            ..Attempt::healthy(mode)
        }),
    ];
    for make in &attempts {
        for mode in [RdpAuthMode::Kerberos, RdpAuthMode::KerberosRestrictedAdmin] {
            let outcome = open(make(mode)).await;
            assert!(outcome.result.is_err());
            assert!(!contains(&outcome.target.client_bytes, NTLMSSP_SIGNATURE));
            assert!(outcome.realms_asked.iter().all(|r| r == REALM));
            assert_ne!(outcome.reason, None);
        }
    }
}

// ---- X.224 security negotiation ------------------------------------------

/// Run the negotiation steps of `connect` (the local `connect_begin`
/// mirror, then `check_negotiation`) against a target that answers the
/// X.224 Connection Request with `confirm`.
async fn negotiate(mode: RdpAuthMode, confirm: nego::ConnectionConfirm) -> SessionResult<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (client_io, mut target_io) = tokio::io::duplex(8192);
    let target = tokio::spawn(async move {
        let mut request = [0u8; 1024];
        let _ = target_io.read(&mut request).await;
        let pdu = ironrdp::core::encode_vec(&X224(confirm)).unwrap();
        let _ = target_io.write_all(&pdu).await;
        // Keep the stream open until the client is done with it.
        let _ = target_io.read(&mut request).await;
    });

    let config = build_connector_config(
        USERNAME.to_string(),
        PASSWORD.to_string(),
        mode.uses_kerberos().then(|| REALM.to_string()),
        1024,
        768,
    );
    let mut connector = ClientConnector::new(config, "127.0.0.1:3389".parse().unwrap());
    let mut framed = ironrdp_tokio::TokioFramed::new(client_io);
    let extra_flags = if auth_mode_profile(mode).restricted_admin {
        nego::RequestFlags::RESTRICTED_ADMIN_MODE_REQUIRED
    } else {
        nego::RequestFlags::empty()
    };

    let begun = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        connect_begin_with_nego_flags(&mut framed, &mut connector, extra_flags),
    )
    .await
    .expect("the negotiation must terminate");
    drop(framed);
    target.abort();

    let (_, negotiation) = begun.map_err(|e| negotiation_error(&e))?;
    check_negotiation(mode, negotiation).map_err(|detail| SessionError::AuthenticationFailed {
        reason: RdpAuthFailure::NegotiationRefused,
        detail: detail.to_string(),
    })
}

fn response(
    protocol: nego::SecurityProtocol,
    flags: nego::ResponseFlags,
) -> nego::ConnectionConfirm {
    nego::ConnectionConfirm::Response { flags, protocol }
}

const KERBEROS_MODES: [RdpAuthMode; 2] =
    [RdpAuthMode::Kerberos, RdpAuthMode::KerberosRestrictedAdmin];

/// A target (or anyone on the path: the negotiation is cleartext) that
/// answers "TLS only". IronRDP would accept it and skip CredSSP; a
/// Kerberos mode refuses, with a classified reason, before TLS.
#[tokio::test]
async fn attack_tls_only_selection_in_kerberos_mode_is_rejected() {
    for mode in KERBEROS_MODES {
        let refused = negotiate(
            mode,
            response(
                nego::SecurityProtocol::SSL,
                nego::ResponseFlags::RESTRICTED_ADMIN_MODE_SUPPORTED,
            ),
        )
        .await
        .expect_err("a TLS-only selection must be refused");
        assert_eq!(
            refused.auth_failure(),
            Some(RdpAuthFailure::NegotiationRefused),
            "{mode:?}: {refused}"
        );
    }
}

/// Restricted Admin needs the target's agreement: NLA selected but no
/// `RESTRICTED_ADMIN_MODE_SUPPORTED` flag is refused. The plain Kerberos
/// mode does not need the flag.
#[tokio::test]
async fn attack_restricted_admin_without_target_support_is_rejected() {
    for protocol in [
        nego::SecurityProtocol::HYBRID,
        nego::SecurityProtocol::HYBRID_EX,
    ] {
        let refused = negotiate(
            RdpAuthMode::KerberosRestrictedAdmin,
            response(protocol, nego::ResponseFlags::empty()),
        )
        .await
        .expect_err("no Restricted Admin support, no session");
        assert_eq!(
            refused.auth_failure(),
            Some(RdpAuthFailure::NegotiationRefused)
        );

        negotiate(
            RdpAuthMode::Kerberos,
            response(protocol, nego::ResponseFlags::empty()),
        )
        .await
        .expect("plain Kerberos needs NLA only");
        negotiate(
            RdpAuthMode::KerberosRestrictedAdmin,
            response(
                protocol,
                nego::ResponseFlags::RESTRICTED_ADMIN_MODE_SUPPORTED,
            ),
        )
        .await
        .expect("Restricted Admin with NLA and the support flag");
    }
}

/// A negotiation failure sent by the target is a classified reason in a
/// Kerberos mode: its text does not travel as a free-form error.
#[tokio::test]
async fn test_negotiation_failure_is_classified_in_kerberos_modes() {
    for mode in KERBEROS_MODES {
        for code in [
            nego::FailureCode::SSL_REQUIRED_BY_SERVER,
            nego::FailureCode::HYBRID_REQUIRED_BY_SERVER,
        ] {
            let refused = negotiate(mode, nego::ConnectionConfirm::Failure { code })
                .await
                .expect_err("a negotiation failure is a failure");
            assert_eq!(
                refused.auth_failure(),
                Some(RdpAuthFailure::NegotiationRefused)
            );
        }
    }
}

/// The NTLM mode requires NLA too: a TLS-only selection would send the
/// password in the Client Info PDU with no NLA at all. A target that
/// selects NLA passes; a negotiation failure is a classified reason.
#[tokio::test]
async fn attack_tls_only_selection_in_ntlm_mode_is_rejected() {
    let refused = negotiate(
        RdpAuthMode::Ntlm,
        response(nego::SecurityProtocol::SSL, nego::ResponseFlags::empty()),
    )
    .await
    .expect_err("a TLS-only selection must be refused in NTLM mode");
    assert_eq!(
        refused.auth_failure(),
        Some(RdpAuthFailure::NegotiationRefused)
    );

    for protocol in [
        nego::SecurityProtocol::HYBRID,
        nego::SecurityProtocol::HYBRID_EX,
    ] {
        negotiate(
            RdpAuthMode::Ntlm,
            response(protocol, nego::ResponseFlags::empty()),
        )
        .await
        .expect("NTLM mode with NLA selected");
    }

    let failed = negotiate(
        RdpAuthMode::Ntlm,
        nego::ConnectionConfirm::Failure {
            code: nego::FailureCode::SSL_REQUIRED_BY_SERVER,
        },
    )
    .await
    .expect_err("a negotiation failure is a failure");
    assert_eq!(
        failed.auth_failure(),
        Some(RdpAuthFailure::NegotiationRefused)
    );
}

/// `check_negotiation` over every protocol selection and flag set.
#[test]
fn test_check_negotiation_table() {
    let nla = nego::SecurityProtocol::HYBRID | nego::SecurityProtocol::HYBRID_EX;
    for bits in 0u32..16 {
        let selected = nego::SecurityProtocol::from_bits_retain(bits);
        for flag_bits in [0u8, 0x08, 0x01, 0x09] {
            let flags = nego::ResponseFlags::from_bits_retain(flag_bits);
            let outcome = Some(NegotiationOutcome { selected, flags });
            let has_nla = selected.intersects(nla);
            let ra_ok = flags.contains(nego::ResponseFlags::RESTRICTED_ADMIN_MODE_SUPPORTED);
            for mode in [RdpAuthMode::Ntlm, RdpAuthMode::Kerberos] {
                assert_eq!(
                    check_negotiation(mode, outcome).is_ok(),
                    has_nla,
                    "{mode:?} {selected:?} {flags:?}"
                );
            }
            assert_eq!(
                check_negotiation(RdpAuthMode::KerberosRestrictedAdmin, outcome).is_ok(),
                has_nla && ra_ok,
                "{selected:?} {flags:?}"
            );
        }
    }
    for mode in RdpAuthMode::ALL {
        assert!(
            check_negotiation(mode, None).is_err(),
            "{mode:?}: no response, no session"
        );
    }
}

/// Behind the negotiation check: no mode finalizes a handshake that is
/// not about to run CredSSP.
#[tokio::test]
async fn attack_handshake_without_credssp_is_rejected() {
    for mode in RdpAuthMode::ALL {
        let (client_io, _target_io) = tokio::io::duplex(8192);
        let config = build_connector_config(
            USERNAME.to_string(),
            PASSWORD.to_string(),
            Some(REALM.to_string()),
            1024,
            768,
        );
        let mut connector = ClientConnector::new(config, "127.0.0.1:3389".parse().unwrap());
        // What IronRDP does with a TLS-only selection: after the security
        // upgrade it goes straight to the settings exchange, skipping
        // CredSSP.
        connector.state = ClientConnectorState::EnhancedSecurityUpgrade {
            selected_protocol: nego::SecurityProtocol::SSL,
        };
        let should_upgrade = ironrdp_tokio::skip_connect_begin(&mut connector);
        let upgraded = ironrdp_tokio::mark_as_upgraded(should_upgrade, &mut connector);
        assert!(!connector.should_perform_credssp());

        let mut framed = ironrdp_tokio::TokioFramed::new(client_io);
        let mut network_client =
            SessionNetworkClient::for_auth_mode(RdpAuthMode::Ntlm, None, "sess", None).unwrap();
        let result = connect_finalize_with_message_channel_demux(
            upgraded,
            connector,
            &mut framed,
            &mut network_client,
            connector::ServerName::new(TARGET_HOST),
            server_public_key(),
            mode,
        )
        .await;
        assert!(
            result.is_err(),
            "{mode:?} must not finalize without CredSSP"
        );
    }
}

// ---- the proxy's session-open gate ---------------------------------------

/// A compromised vauban-web asks for an NTLM session under `deny`: the
/// proxy's own gate refuses, whatever domain it is given.
#[test]
fn attack_ntlm_session_requested_by_compromised_web_under_deny_is_rejected() {
    use shared::messages::NtlmPolicy;
    for domain in [None, Some("CORP".to_string()), Some(DOMAIN.to_string())] {
        for isolated in [true, false] {
            let refusal = session_open_gate(
                NtlmPolicy::Deny,
                RdpAuthMode::Ntlm,
                domain.clone(),
                isolated,
            )
            .expect_err("NTLM under deny must be refused");
            assert_eq!(refusal, SessionOpenRefusal::NtlmForbidden);
            assert_eq!(refusal.auth_failure(), RdpAuthFailure::NtlmForbidden);
        }
    }
    // Under `allow` the same request passes, with its domain untouched.
    assert_eq!(
        session_open_gate(
            NtlmPolicy::Allow,
            RdpAuthMode::Ntlm,
            Some("CORP".to_string()),
            false
        ),
        Ok(Some("CORP".to_string()))
    );
}

/// The gate applies the Kerberos pre-flight under both policies: a
/// Kerberos session with no realm, a NetBIOS domain or an environment
/// carrying ambient Kerberos configuration is refused.
#[test]
fn attack_kerberos_session_without_realm_or_isolation_is_rejected() {
    use shared::messages::NtlmPolicy;
    for policy in NtlmPolicy::ALL {
        for mode in KERBEROS_MODES {
            for domain in [None, Some(String::new()), Some("CORP".to_string())] {
                let refusal = session_open_gate(policy, mode, domain, true)
                    .expect_err("no DNS-form realm, no session");
                assert_eq!(refusal.auth_failure(), RdpAuthFailure::RealmInvalid);
            }
            let refusal = session_open_gate(policy, mode, Some(DOMAIN.to_string()), false)
                .expect_err("ambient configuration, no session");
            assert!(matches!(
                refusal,
                SessionOpenRefusal::Preflight(KerberosPreflightError::AmbientConfigNotIsolated)
            ));
            // A valid request returns the canonical realm.
            assert_eq!(
                session_open_gate(policy, mode, Some(DOMAIN.to_string()), true),
                Ok(Some(REALM.to_string()))
            );
        }
    }
}
