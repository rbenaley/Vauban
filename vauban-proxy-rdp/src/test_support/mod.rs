//! In-process Kerberos test harness for the CredSSP leg.
//!
//! It lets a test run the PRODUCTION CredSSP function
//! (`session::perform_credssp_step`, with the production network client,
//! realm gate and failure trace) against:
//!
//! * [`kdc_mock::KdcMock`], an in-memory KDC ported from the test suite
//!   of `sspi`, reached through the [`KdcTransport`](crate::session)
//!   seam instead of a socket leased from the supervisor;
//! * [`CredsspTarget`], `sspi`'s own CredSSP server (`CredSspServer` with
//!   a Kerberos acceptor), standing in for the RDP target on an
//!   in-memory stream.
//!
//! Limit: the server is `sspi`'s, not Windows, and the KDC checks little.
//! This validates how Vauban drives `sspi` in each auth mode. It says
//! nothing about interoperability with Active Directory.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only harness"
)]

pub(crate) mod kdc_mock;
pub(crate) mod mit_kdc;

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use ironrdp::connector::sspi;
use ironrdp::connector::sspi::credssp::{
    CredSspServer, CredentialsProxy, ServerMode, ServerState, TsRequest,
};
use ironrdp::connector::sspi::generator::NetworkRequest;
use ironrdp::connector::sspi::kerberos::ServerProperties;
use ironrdp::connector::sspi::network_client::NetworkClient as SyncNetworkClient;
use kdc_mock::{KdcMock, MAX_TIME_SKEW, PasswordCreds, UserName, Validators};
use picky_asn1::restricted_string::IA5String;
use picky_asn1::wrapper::{Asn1SequenceOf, ExplicitContextTag0, ExplicitContextTag1, IntegerAsn1};
use picky_krb::constants::types::{NT_PRINCIPAL, NT_SRV_INST};
use picky_krb::data_types::{KerberosStringAsn1, PrincipalName};
use picky_krb::gss_api::MechTypeList;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

/// Realm of the test domain, and its DNS name as stored on an asset.
pub(crate) const REALM: &str = "CORP.EXAMPLE.COM";
pub(crate) const DOMAIN: &str = "corp.example.com";
/// The account opening the session.
pub(crate) const USERNAME: &str = "jdoe";
pub(crate) const PASSWORD: &str = "Correct-Horse-2026!";
/// The RDP target, registered as `TERMSRV/<TARGET_HOST>` in the KDC.
pub(crate) const TARGET_HOST: &str = "srv01.corp.example.com";

/// Bytes both ends bind CredSSP to (the TLS server public key in
/// production). Any value works as long as both ends agree.
pub(crate) fn server_public_key() -> Vec<u8> {
    (0u8..=255).collect()
}

fn principal(name_type: u8, parts: &[&str]) -> PrincipalName {
    PrincipalName {
        name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![name_type])),
        name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(
            parts
                .iter()
                .map(|p| {
                    KerberosStringAsn1::from(IA5String::from_string((*p).to_string()).unwrap())
                })
                .collect::<Vec<_>>(),
        )),
    }
}

/// A KDC database with the test user, the ticket-granting service and
/// `TERMSRV/<TARGET_HOST>`.
pub(crate) fn kdc_with_password(password: &str) -> KdcMock {
    kdc_database(password, true)
}

/// The same database without `TERMSRV/<TARGET_HOST>`: the target exists
/// but its service principal is not registered in the directory.
pub(crate) fn kdc_without_target_spn() -> KdcMock {
    kdc_database(PASSWORD, false)
}

fn kdc_database(password: &str, with_target_spn: bool) -> KdcMock {
    let tgt_service_key: Vec<u8> = (1u8..=32).collect();
    let target_service_key: Vec<u8> = (101u8..=132).collect();
    let keys: HashMap<UserName, Vec<u8>> = [
        (
            UserName(principal(NT_SRV_INST, &["krbtgt", REALM])),
            tgt_service_key.clone(),
        ),
        (
            UserName(principal(NT_SRV_INST, &["krbtgt", "CORP"])),
            tgt_service_key,
        ),
        (
            UserName(principal(NT_SRV_INST, &["TERMSRV", TARGET_HOST])),
            target_service_key,
        ),
    ]
    .into_iter()
    .filter(|(name, _)| {
        with_target_spn || *name != UserName(principal(NT_SRV_INST, &["TERMSRV", TARGET_HOST]))
    })
    .collect();
    let users: HashMap<UserName, PasswordCreds> = [(
        UserName(principal(NT_PRINCIPAL, &[USERNAME])),
        PasswordCreds {
            password: password.as_bytes().to_vec(),
            salt: format!("{REALM}{USERNAME}"),
        },
    )]
    .into_iter()
    .collect();
    KdcMock::new(REALM.to_string(), keys, users, Validators::default())
}

/// Answer one framed KDC request from the mock, framed.
fn kdc_answer(kdc: &KdcMock, framed_request: &[u8]) -> Result<Vec<u8>, String> {
    let data = framed_request
        .get(4..)
        .ok_or_else(|| "KDC request shorter than its length prefix".to_string())?;
    let response = if let Ok(as_req) = picky_asn1_der::from_bytes(data) {
        match kdc.as_exchange(as_req) {
            Ok(as_rep) => picky_asn1_der::to_vec(&as_rep),
            Err(krb_err) => picky_asn1_der::to_vec(&krb_err),
        }
    } else if let Ok(tgs_req) = picky_asn1_der::from_bytes(data) {
        match kdc.tgs_exchange(tgs_req) {
            Ok(tgs_rep) => picky_asn1_der::to_vec(&tgs_rep),
            Err(krb_err) => picky_asn1_der::to_vec(&krb_err),
        }
    } else {
        return Err("not an AS-REQ or a TGS-REQ".to_string());
    }
    .map_err(|e| format!("KDC reply encoding failed: {e}"))?;
    let mut framed = (response.len() as u32).to_be_bytes().to_vec();
    framed.extend_from_slice(&response);
    Ok(framed)
}

/// What the client-side transport does with a KDC exchange.
pub(crate) enum KdcLink {
    /// Hand it to the in-memory KDC.
    Up,
    /// Fail it with this relay error string (a lease refusal, a timeout).
    Down(String),
}

/// The client's [`KdcTransport`](crate::session): in production, a socket
/// leased from the supervisor; here, the in-memory KDC. Records which
/// realm each exchange was sent for.
pub(crate) struct MockKdcTransport {
    pub kdc: Arc<KdcMock>,
    pub link: KdcLink,
    pub realms_asked: Mutex<Vec<String>>,
}

impl MockKdcTransport {
    pub(crate) fn new(kdc: Arc<KdcMock>, link: KdcLink) -> Arc<Self> {
        Arc::new(Self {
            kdc,
            link,
            realms_asked: Mutex::new(Vec::new()),
        })
    }

    pub(crate) fn exchange(
        &self,
        realm: &shared::kerberos::Realm,
        data: &[u8],
    ) -> Result<Vec<u8>, String> {
        self.realms_asked
            .lock()
            .unwrap()
            .push(realm.as_str().to_string());
        match &self.link {
            KdcLink::Up => kdc_answer(&self.kdc, data),
            KdcLink::Down(error) => Err(error.clone()),
        }
    }
}

/// The target's own KDC access (it needs a TGT for user-to-user).
struct TargetKdcClient(Arc<KdcMock>);

impl SyncNetworkClient for TargetKdcClient {
    fn send(&self, request: &NetworkRequest) -> sspi::Result<Vec<u8>> {
        kdc_answer(&self.0, &request.data)
            .map_err(|e| sspi::Error::new(sspi::ErrorKind::NoAuthenticatingAuthority, e))
    }
}

/// Credentials lookup of the CredSSP server.
struct TargetCredentials(sspi::AuthIdentity);

impl CredentialsProxy for TargetCredentials {
    type AuthenticationData = sspi::AuthIdentity;

    fn auth_data_by_user(
        &mut self,
        _username: &sspi::Username,
    ) -> std::io::Result<Self::AuthenticationData> {
        Ok(self.0.clone())
    }

    fn auth_data(&mut self) -> std::io::Result<Vec<Self::AuthenticationData>> {
        Ok(vec![self.0.clone()])
    }
}

/// Which security packages the target accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TargetPackages {
    /// SPNEGO with Kerberos only: a domain-joined target.
    Kerberos,
    /// SPNEGO with NTLM only: a target outside the domain.
    NtlmOnly,
    /// Bare NTLM, without SPNEGO: what the NTLM mode of the proxy speaks.
    RawNtlm,
}

/// How the target's side of the exchange ended.
#[derive(Debug)]
pub(crate) enum TargetOutcome {
    /// CredSSP completed; these are the TSCredentials the target received.
    Authenticated { account: String, password: String },
    /// The target's CredSSP server refused a message, with this `sspi`
    /// error kind (read through `Debug` in assertion messages).
    Refused(#[allow(dead_code)] String),
    /// The client closed the stream before the exchange completed.
    ClientGone,
}

/// Everything the target observed.
#[derive(Debug)]
pub(crate) struct TargetReport {
    pub outcome: TargetOutcome,
    /// Every byte the client sent, in order.
    pub client_bytes: Vec<u8>,
}

/// `sspi`'s CredSSP server on one end of an in-memory stream.
pub(crate) struct CredsspTarget;

impl CredsspTarget {
    /// Serve one CredSSP exchange on `stream`. The target reaches the
    /// domain through its own healthy KDC instance (same database), so a
    /// fault injected on the client's KDC path does not also fail the
    /// target's own ticket request.
    pub(crate) async fn serve(mut stream: DuplexStream, packages: TargetPackages) -> TargetReport {
        let kdc = Arc::new(kdc_with_password(PASSWORD));
        let identity = sspi::AuthIdentity {
            username: sspi::Username::new(USERNAME, Some(REALM)).unwrap(),
            password: PASSWORD.to_owned().into(),
        };
        let credentials = sspi::Credentials::AuthIdentity(identity.clone());
        let computer_name = TARGET_HOST.to_string();
        // The acceptor names the authenticated client `account@realm`: the
        // identity the target looks it up under is the UPN form.
        let known_user = sspi::AuthIdentity {
            username: sspi::Username::new_upn(USERNAME, DOMAIN).unwrap(),
            password: PASSWORD.to_owned().into(),
        };

        let mode = match packages {
            TargetPackages::Kerberos => {
                let kerberos_config = sspi::KerberosConfig {
                    kdc_url: Some(
                        sspi::kerberos::config::parse_kdc_url("tcp://kdc.test.invalid:88").unwrap(),
                    ),
                    client_computer_name: computer_name.clone(),
                };
                let server_properties = ServerProperties {
                    mech_types: MechTypeList::from(Vec::new()),
                    max_time_skew: MAX_TIME_SKEW,
                    ticket_decryption_key: None,
                    service_name: principal(NT_SRV_INST, &["TERMSRV", TARGET_HOST]),
                    additional_service_keys: Vec::new(),
                    user: Some(sspi::CredentialsBuffers::try_from(credentials).unwrap()),
                    client: None,
                    authenticators_cache: HashSet::new(),
                };
                ServerMode::Negotiate(sspi::NegotiateConfig::new(
                    Box::new(sspi::KerberosServerConfig {
                        kerberos_config,
                        server_properties,
                    }),
                    Some("kerberos,!ntlm".to_owned()),
                    computer_name,
                ))
            }
            TargetPackages::NtlmOnly => ServerMode::Negotiate(sspi::NegotiateConfig::new(
                Box::new(sspi::ntlm::NtlmConfig {
                    client_computer_name: Some(computer_name.clone()),
                }),
                Some("ntlm,!kerberos,!pku2u".to_owned()),
                computer_name,
            )),
            TargetPackages::RawNtlm => ServerMode::Ntlm(sspi::ntlm::NtlmConfig {
                client_computer_name: Some(computer_name),
            }),
        };

        let mut server =
            CredSspServer::new(server_public_key(), TargetCredentials(known_user), mode).unwrap();
        let kdc_client = TargetKdcClient(kdc);

        let mut client_bytes = Vec::new();
        let mut pending: Vec<u8> = Vec::new();
        let outcome = loop {
            // One TsRequest frame from the client.
            let frame = loop {
                if let Ok(len) = TsRequest::read_length(pending.as_slice())
                    && pending.len() >= len
                {
                    break Some(pending.drain(..len).collect::<Vec<u8>>());
                }
                let mut chunk = [0u8; 4096];
                match stream.read(&mut chunk).await {
                    Ok(0) | Err(_) => break None,
                    Ok(n) => {
                        client_bytes.extend_from_slice(&chunk[..n]);
                        pending.extend_from_slice(&chunk[..n]);
                    }
                }
            };
            let Some(frame) = frame else {
                break TargetOutcome::ClientGone;
            };
            let ts_request = match TsRequest::from_buffer(&frame) {
                Ok(ts_request) => ts_request,
                Err(e) => break TargetOutcome::Refused(format!("undecodable TsRequest: {e}")),
            };

            match server.process(ts_request).resolve_with_client(&kdc_client) {
                Ok(ServerState::ReplyNeeded(reply)) => {
                    let mut out = vec![0u8; usize::from(reply.buffer_len())];
                    reply.encode_ts_request(out.as_mut_slice()).unwrap();
                    if stream.write_all(&out).await.is_err() {
                        break TargetOutcome::ClientGone;
                    }
                }
                Ok(ServerState::Finished(received)) => {
                    break TargetOutcome::Authenticated {
                        account: received.username.account_name().to_string(),
                        password: received.password.as_ref().to_string(),
                    };
                }
                Err(error) => {
                    // As a real target does, tell the client when the
                    // protocol has an error TsRequest for it.
                    if let Some(reply) = error.ts_request {
                        let mut out = vec![0u8; usize::from(reply.buffer_len())];
                        if reply.encode_ts_request(out.as_mut_slice()).is_ok() {
                            let _ = stream.write_all(&out).await;
                        }
                    }
                    break TargetOutcome::Refused(format!("{:?}", error.error.error_type));
                }
            }
        };

        // Collect what the client may still have sent, then close.
        drop(stream);
        TargetReport {
            outcome,
            client_bytes,
        }
    }
}
