//! Tests of the Remote Credential Guard policy context.
//!
//! The inner context is scripted: it stands for the `sspi` session, so
//! the policy is exercised through the connector's real `Backend` (NDR
//! decoding, version negotiation, status mapping, response framing)
//! without a live Kerberos exchange. The exchange itself is covered by
//! `session_credssp_loop_tests` and by the smoke runbook.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use ironrdp_connector::remote_guard::{
    Backend, KERBEROS, MAX_MESSAGE_SIZE, NTLM, PROFILE, STATUS_NOT_SUPPORTED, WRAP_OVERHEAD,
    asn1_output,
};
use ironrdp_core::{ReadCursor, encode_vec};
use ironrdp_rdpear::{AuthRedirectionBackend as _, RemoteGuardInnerPacket};
use picky_asn1::date::GeneralizedTime;
use picky_asn1::restricted_string::IA5String;
use picky_asn1::wrapper::{
    Asn1SequenceOf, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2,
    ExplicitContextTag3, ExplicitContextTag4, ExplicitContextTag5, ExplicitContextTag7,
    ExplicitContextTag8, ExplicitContextTag9, ExplicitContextTag10, IntegerAsn1, OctetStringAsn1,
    Optional,
};
use picky_krb::data_types::{
    EncryptionKey, KerberosFlags, KerberosStringAsn1, KerberosTime, LastReq, PrincipalName, Realm,
};
use picky_krb::messages::{EncAsRepPart, EncKdcRepPart, EncTgsRepPart, KdcReqBody};
use proptest::prelude::*;

use super::*;

const SESSION: &str = "sess";
const TOKEN: &[u8] = b"test-token";

/// Counters shared with the scripted context, to observe what reached
/// the `sspi` session.
#[derive(Default, Clone)]
struct Probe {
    executed: Arc<AtomicUsize>,
    ntlm_executed: Arc<AtomicUsize>,
    unwrapped: Arc<AtomicUsize>,
}

impl Probe {
    fn executed(&self) -> usize {
        self.executed.load(Ordering::SeqCst)
    }
    fn ntlm_executed(&self) -> usize {
        self.ntlm_executed.load(Ordering::SeqCst)
    }
    fn unwrapped(&self) -> usize {
        self.unwrapped.load(Ordering::SeqCst)
    }
}

/// Stands for `sspi::rcg::RemoteGuardSession`: hands the next plaintext
/// to the connector, and answers every Kerberos operation it is asked.
struct Scripted {
    plaintext: Vec<u8>,
    fail_execute: bool,
    probe: Probe,
}

impl Context for Scripted {
    fn unwrap(&mut self, token: &[u8]) -> sspi::Result<Secret<Vec<u8>>> {
        assert_eq!(token, TOKEN);
        self.probe.unwrapped.fetch_add(1, Ordering::SeqCst);
        Ok(Secret::new(self.plaintext.clone()))
    }

    fn wrap(&mut self, plaintext: &[u8]) -> sspi::Result<Vec<u8>> {
        let mut out = vec![0xa5; WRAP_OVERHEAD];
        out.extend_from_slice(plaintext);
        Ok(out)
    }

    fn execute(&mut self, request: &KerberosRequest) -> sspi::Result<KerberosResponseCall> {
        self.probe.executed.fetch_add(1, Ordering::SeqCst);
        if self.fail_execute {
            return Err(Error::new(ErrorKind::InvalidParameter, "scripted failure"));
        }
        match request {
            KerberosRequest::ComputeTgsChecksum(_) => Ok(KerberosResponseCall::ComputeTgsChecksum(
                asn1_output(vec![0x30, 0], 8).unwrap(),
            )),
            KerberosRequest::BuildEncryptedAuthData(_) => {
                Ok(KerberosResponseCall::BuildEncryptedAuthData(
                    asn1_output(vec![0x30, 0], 6).unwrap(),
                ))
            }
            KerberosRequest::UnpackKdcReplyBody(_) => Ok(KerberosResponseCall::UnpackKdcReplyBody(
                ndr::UnpackKdcReplyBodyResponse {
                    kerb_protocol_error: 0,
                    reply_body: asn1_output(tgs_reply_part(&["cifs", "dc01.contoso.com"]), 0)
                        .unwrap(),
                },
            )),
            _ => Err(Error::new(ErrorKind::UnsupportedFunction, "not scripted")),
        }
    }

    fn ntlm_available(&self) -> bool {
        // The session below the policy does have an NTLM credential: the
        // refusal must come from the policy context, not from here.
        true
    }

    fn execute_ntlm(&mut self, _request: &ndr::NtlmRequest) -> sspi::Result<ndr::NtlmResponseCall> {
        self.probe.ntlm_executed.fetch_add(1, Ordering::SeqCst);
        Ok(ndr::NtlmResponseCall::NegotiateVersion(
            ndr::NegotiateVersion { version: 0 },
        ))
    }
}

type TestBackend = Backend<PolicyContext<Scripted>>;

fn backend(policy: RemoteGuardOutboundIdentity) -> (TestBackend, Probe) {
    let probe = Probe::default();
    let inner = Scripted {
        plaintext: Vec::new(),
        fail_execute: false,
        probe: probe.clone(),
    };
    let backend = Backend {
        context: Some(PolicyContext::new(inner, policy, SESSION.to_string())),
        negotiated: false,
        ntlm_negotiated: false,
        // As in production: the connector answers the version negotiation.
        kerberos_allowed: true,
    };
    (backend, probe)
}

fn packet(package: &[u8], call: &[u8]) -> Vec<u8> {
    encode_vec(&RemoteGuardInnerPacket {
        package_name: package,
        package_call: call,
    })
    .unwrap()
}

fn set_kerberos(backend: &mut TestBackend, request: &KerberosRequest) {
    let call = request
        .encode_with_profile(ndr::Endianness::Little, ndr::NdrLimits::default(), PROFILE)
        .unwrap();
    backend.context.as_mut().unwrap().inner.plaintext = packet(KERBEROS, &call);
}

fn set_ntlm(backend: &mut TestBackend, request: &ndr::NtlmRequest) {
    let call = request
        .encode_with_profile(ndr::Endianness::Little, ndr::NdrLimits::default(), PROFILE)
        .unwrap();
    backend.context.as_mut().unwrap().inner.plaintext = packet(NTLM, &call);
}

/// Send the request the backend currently holds; decode the status.
fn kerberos_status(backend: &mut TestBackend) -> i32 {
    let token = backend.process(TOKEN, MAX_MESSAGE_SIZE).unwrap();
    let inner = RemoteGuardInnerPacket::decode_with_limit(
        &mut ReadCursor::new(&token[WRAP_OVERHEAD..]),
        MAX_MESSAGE_SIZE,
    )
    .unwrap();
    assert_eq!(inner.package_name, KERBEROS);
    ndr::KerberosResponse::decode_with_profile(
        inner.package_call,
        ndr::NdrLimits::default(),
        PROFILE,
    )
    .unwrap()
    .status
}

fn ntlm_status(backend: &mut TestBackend) -> i32 {
    let token = backend.process(TOKEN, MAX_MESSAGE_SIZE).unwrap();
    let inner = RemoteGuardInnerPacket::decode_with_limit(
        &mut ReadCursor::new(&token[WRAP_OVERHEAD..]),
        MAX_MESSAGE_SIZE,
    )
    .unwrap();
    assert_eq!(inner.package_name, NTLM);
    ndr::NtlmResponse::decode_with_profile(inner.package_call, ndr::NdrLimits::default(), PROFILE)
        .unwrap()
        .status
}

fn negotiate(backend: &mut TestBackend) -> i32 {
    set_kerberos(
        backend,
        &KerberosRequest::NegotiateVersion(ndr::NegotiateVersion { version: 0 }),
    );
    kerberos_status(backend)
}

fn principal(parts: &[&str]) -> PrincipalName {
    PrincipalName {
        name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![2])),
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

fn realm() -> Realm {
    Realm::from(IA5String::from_string("CONTOSO.COM".to_string()).unwrap())
}

fn time() -> KerberosTime {
    KerberosTime::from(GeneralizedTime::new(2030, 1, 1, 0, 0, 0).unwrap())
}

/// DER of a `KDC-REQ-BODY` that asks for a ticket to `sname`.
fn tgs_request_body(sname: Option<&[&str]>) -> Vec<u8> {
    let body = KdcReqBody {
        kdc_options: ExplicitContextTag0::from(KerberosFlags::from(
            picky_asn1::bit_string::BitString::with_bytes(vec![0, 0, 0, 0]),
        )),
        cname: Optional::from(None),
        realm: ExplicitContextTag2::from(realm()),
        sname: Optional::from(sname.map(|parts| ExplicitContextTag3::from(principal(parts)))),
        from: Optional::from(None),
        till: ExplicitContextTag5::from(time()),
        rtime: Optional::from(None),
        nonce: ExplicitContextTag7::from(IntegerAsn1::from(vec![1])),
        etype: ExplicitContextTag8::from(Asn1SequenceOf::from(vec![IntegerAsn1::from(vec![18])])),
        addresses: Optional::from(None),
        enc_authorization_data: Optional::from(None),
        additional_tickets: Optional::from(None),
    };
    picky_asn1_der::to_vec(&body).unwrap()
}

fn reply_part(sname: &[&str]) -> EncKdcRepPart {
    EncKdcRepPart {
        key: ExplicitContextTag0::from(EncryptionKey {
            key_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![18])),
            key_value: ExplicitContextTag1::from(OctetStringAsn1::from(vec![0x5a; 32])),
        }),
        last_req: ExplicitContextTag1::from(LastReq::from(Vec::new())),
        nonce: ExplicitContextTag2::from(IntegerAsn1::from(vec![1])),
        key_expiration: Optional::from(None),
        flags: ExplicitContextTag4::from(KerberosFlags::from(
            picky_asn1::bit_string::BitString::with_bytes(vec![0, 0, 0, 0]),
        )),
        auth_time: ExplicitContextTag5::from(time()),
        start_time: Optional::from(None),
        end_time: ExplicitContextTag7::from(time()),
        renew_till: Optional::from(None),
        srealm: ExplicitContextTag9::from(realm()),
        sname: ExplicitContextTag10::from(principal(sname)),
        caddr: Optional::from(None),
        encrypted_pa_data: Optional::from(None),
    }
}

/// DER of the decrypted part of a TGS-REP for `sname`.
fn tgs_reply_part(sname: &[&str]) -> Vec<u8> {
    picky_asn1_der::to_vec(&EncTgsRepPart::from(reply_part(sname))).unwrap()
}

fn compute_tgs_checksum(sname: Option<&[&str]>) -> KerberosRequest {
    KerberosRequest::ComputeTgsChecksum(ndr::ComputeTgsChecksumRequest {
        request_body: Some(asn1_output(tgs_request_body(sname), 66).unwrap()),
        key: None,
        checksum_type: 16,
    })
}

fn unpack_kdc_reply() -> KerberosRequest {
    KerberosRequest::UnpackKdcReplyBody(ndr::UnpackKdcReplyBodyRequest::default())
}

/// One request of every operation the target sends in a logon.
fn every_operation() -> Vec<KerberosRequest> {
    vec![
        KerberosRequest::BuildEncryptedAuthData(ndr::BuildEncryptedAuthDataRequest::default()),
        compute_tgs_checksum(Some(&["cifs", "dc01.contoso.com"])),
        KerberosRequest::CreateApReqAuthenticator(ndr::CreateApReqAuthenticatorRequest::default()),
        unpack_kdc_reply(),
        KerberosRequest::DecryptApReply(ndr::DecryptApReplyRequest::default()),
        KerberosRequest::PackApReply(ndr::PackApReplyRequest::default()),
    ]
}

// --- policy ---------------------------------------------------------------

/// Under `deny` the version negotiation is answered: without it a
/// Windows target closes the connection instead of opening the session.
#[test]
fn deny_answers_the_version_negotiation() {
    let (mut backend, probe) = backend(RemoteGuardOutboundIdentity::Deny);
    assert_eq!(negotiate(&mut backend), 0);
    assert_eq!(probe.executed(), 0, "the connector answers it, not sspi");
}

/// Under `deny` no operation reaches the `sspi` session, so no key of
/// the user signs or decrypts anything for the target.
#[test]
fn attack_kerberos_operation_under_deny_is_rejected() {
    let (mut backend, probe) = backend(RemoteGuardOutboundIdentity::Deny);
    assert_eq!(negotiate(&mut backend), 0);
    for request in every_operation() {
        set_kerberos(&mut backend, &request);
        assert_eq!(
            kerberos_status(&mut backend),
            STATUS_NOT_SUPPORTED,
            "{:?}",
            Operation::of(&request)
        );
    }
    assert_eq!(probe.executed(), 0, "nothing was performed");
    // The channel stays open: the target keeps asking, and keeps being
    // refused, without the session ending.
    assert!(backend.context.is_some());
}

/// Asking again does not wear the policy down.
#[test]
fn attack_repeated_requests_under_deny_stay_rejected() {
    let (mut backend, probe) = backend(RemoteGuardOutboundIdentity::Deny);
    assert_eq!(negotiate(&mut backend), 0);
    let request = compute_tgs_checksum(Some(&["cifs", "dc01.contoso.com"]));
    for _ in 0..(LOOP_GUARD_MAX_UNANSWERED * 3) {
        set_kerberos(&mut backend, &request);
        assert_eq!(kerberos_status(&mut backend), STATUS_NOT_SUPPORTED);
    }
    assert_eq!(probe.executed(), 0);
    assert!(
        backend.context.is_some(),
        "refusals are not a request loop: the guard watches performed operations only"
    );
}

/// Under `allow` the operations are performed by the `sspi` session.
#[test]
fn allow_performs_the_operations() {
    let (mut backend, probe) = backend(RemoteGuardOutboundIdentity::Allow);
    assert_eq!(negotiate(&mut backend), 0);
    set_kerberos(
        &mut backend,
        &compute_tgs_checksum(Some(&["cifs", "dc01.contoso.com"])),
    );
    assert_eq!(kerberos_status(&mut backend), 0);
    set_kerberos(&mut backend, &unpack_kdc_reply());
    assert_eq!(kerberos_status(&mut backend), 0);
    assert_eq!(probe.executed(), 2);
}

/// Before the version negotiation nothing is performed, in either
/// policy: `allow` does not skip the connector's own sequencing.
#[test]
fn attack_operation_before_negotiation_is_rejected() {
    for policy in RemoteGuardOutboundIdentity::ALL {
        let (mut backend, probe) = backend(policy);
        set_kerberos(
            &mut backend,
            &compute_tgs_checksum(Some(&["cifs", "dc01.contoso.com"])),
        );
        assert_ne!(kerberos_status(&mut backend), 0, "{policy:?}");
        assert_eq!(probe.executed(), 0, "{policy:?}");
    }
}

/// A failure of the `sspi` session is an error status, not a success,
/// and does not count as a KDC reply.
#[test]
fn a_failed_operation_is_reported_as_failed() {
    let (mut backend, probe) = backend(RemoteGuardOutboundIdentity::Allow);
    assert_eq!(negotiate(&mut backend), 0);
    backend.context.as_mut().unwrap().inner.fail_execute = true;
    set_kerberos(&mut backend, &unpack_kdc_reply());
    assert_ne!(kerberos_status(&mut backend), 0);
    assert_eq!(probe.executed(), 1);
}

// --- NTLM -----------------------------------------------------------------

/// Redirected NTLM is refused under both policies, the version
/// negotiation included, although the session below has an NTLM
/// credential: no Kerberos mode reaches NTLM.
#[test]
fn attack_ntlm_operation_in_remote_guard_is_rejected() {
    for policy in RemoteGuardOutboundIdentity::ALL {
        let (mut backend, probe) = backend(policy);
        assert_eq!(negotiate(&mut backend), 0);
        set_ntlm(
            &mut backend,
            &ndr::NtlmRequest::NegotiateVersion(ndr::NegotiateVersion { version: 0 }),
        );
        assert_eq!(
            ntlm_status(&mut backend),
            STATUS_NOT_SUPPORTED,
            "{policy:?}"
        );
        assert!(!backend.ntlm_negotiated, "{policy:?}");
        set_ntlm(
            &mut backend,
            &ndr::NtlmRequest::Lm20GetNtlm3ChallengeResponse(Default::default()),
        );
        assert_eq!(
            ntlm_status(&mut backend),
            STATUS_NOT_SUPPORTED,
            "{policy:?}"
        );
        assert_eq!(probe.ntlm_executed(), 0, "{policy:?}");
    }
}

/// Called directly, the context refuses NTLM too: the answer does not
/// depend on the connector checking `ntlm_available` first.
#[test]
fn attack_ntlm_request_reaching_the_context_is_rejected() {
    for policy in RemoteGuardOutboundIdentity::ALL {
        let probe = Probe::default();
        let mut context = PolicyContext::new(
            Scripted {
                plaintext: Vec::new(),
                fail_execute: false,
                probe: probe.clone(),
            },
            policy,
            SESSION.to_string(),
        );
        assert!(!context.ntlm_available(), "{policy:?}");
        let refused = context
            .execute_ntlm(&ndr::NtlmRequest::NegotiateVersion(ndr::NegotiateVersion {
                version: 0,
            }))
            .expect_err("NTLM is refused");
        assert_eq!(refused.error_type, ErrorKind::UnsupportedFunction);
        assert_eq!(probe.ntlm_executed(), 0, "{policy:?}");
    }
}

// --- request-loop guard ---------------------------------------------------

/// A target that asks for tickets without end and never brings back a
/// KDC reply gets its channel closed: the context is dropped, and the
/// next message is a channel error, which ends the session.
#[test]
fn a_request_loop_closes_the_channel() {
    let (mut backend, probe) = backend(RemoteGuardOutboundIdentity::Allow);
    assert_eq!(negotiate(&mut backend), 0);
    let request = compute_tgs_checksum(Some(&["cifs", "dc01.contoso.com"]));
    for _ in 0..LOOP_GUARD_MAX_UNANSWERED {
        set_kerberos(&mut backend, &request);
        assert_eq!(kerberos_status(&mut backend), 0);
    }
    assert!(
        backend.context.is_some(),
        "the tripping request is answered"
    );
    let unwrapped = probe.unwrapped();
    set_kerberos(&mut backend, &request);
    assert!(
        backend.process(TOKEN, MAX_MESSAGE_SIZE).is_err(),
        "the channel fails on the next message"
    );
    assert!(backend.context.is_none(), "the session keys are dropped");
    assert_eq!(probe.unwrapped(), unwrapped, "nothing more is unwrapped");
    assert!(
        backend.process(TOKEN, MAX_MESSAGE_SIZE).is_err(),
        "and stays closed"
    );
}

/// A logon that works does not trip the guard, however long it lasts:
/// each KDC reply resets the count.
#[test]
fn a_healthy_session_never_trips_the_guard() {
    let (mut backend, _probe) = backend(RemoteGuardOutboundIdentity::Allow);
    assert_eq!(negotiate(&mut backend), 0);
    let request = compute_tgs_checksum(Some(&["cifs", "dc01.contoso.com"]));
    for _ in 0..(LOOP_GUARD_MAX_UNANSWERED * 4) {
        set_kerberos(&mut backend, &request);
        assert_eq!(kerberos_status(&mut backend), 0);
        set_kerberos(&mut backend, &unpack_kdc_reply());
        assert_eq!(kerberos_status(&mut backend), 0);
    }
    assert!(backend.context.is_some());
}

#[test]
fn the_guard_counts_within_its_window_only() {
    let start = Instant::now();
    let mut guard = LoopGuard::new(start);
    for _ in 0..(LOOP_GUARD_MAX_UNANSWERED - 1) {
        assert!(!guard.ticket_requested(start));
    }
    // The window expires: the count starts again.
    let later = start + LOOP_GUARD_WINDOW + Duration::from_secs(1);
    for _ in 0..(LOOP_GUARD_MAX_UNANSWERED - 1) {
        assert!(!guard.ticket_requested(later));
    }
    assert!(!guard.is_tripped());
    assert!(guard.ticket_requested(later), "the bound is reached");
    assert!(guard.is_tripped());
    // Tripped is final: neither a reply nor time clears it.
    guard.kdc_reply_opened(later);
    assert!(guard.is_tripped());
    assert!(!guard.ticket_requested(later + LOOP_GUARD_WINDOW * 2));
    assert!(guard.is_tripped());
}

/// The bound sits between a logon that works (a few tens of operations)
/// and the loop it is meant to catch (several hundred a minute).
#[test]
fn the_guard_bound_is_between_a_logon_and_a_loop() {
    const { assert!(LOOP_GUARD_MAX_UNANSWERED >= 100) };
    const { assert!(LOOP_GUARD_MAX_UNANSWERED <= 400) };
    assert_eq!(LOOP_GUARD_WINDOW, Duration::from_secs(60));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// For any sequence of ticket requests and KDC replies inside one
    /// window, the guard trips exactly when the bound of consecutive
    /// unanswered requests is reached, never before.
    #[test]
    fn proptest_guard_trips_exactly_at_the_bound(events in proptest::collection::vec(any::<bool>(), 0..1200)) {
        let now = Instant::now();
        let mut guard = LoopGuard::new(now);
        let mut unanswered = 0u32;
        let mut expected_tripped = false;
        for is_request in events {
            if is_request {
                let tripped_now = guard.ticket_requested(now);
                if !expected_tripped {
                    unanswered += 1;
                    if unanswered >= LOOP_GUARD_MAX_UNANSWERED {
                        expected_tripped = true;
                        prop_assert!(tripped_now);
                    } else {
                        prop_assert!(!tripped_now);
                    }
                } else {
                    prop_assert!(!tripped_now, "it trips once");
                }
            } else {
                guard.kdc_reply_opened(now);
                if !expected_tripped {
                    unanswered = 0;
                }
            }
            prop_assert_eq!(guard.is_tripped(), expected_tripped);
        }
    }

    /// Under `deny`, whatever the target sends after the negotiation,
    /// nothing reaches the `sspi` session and every answer is a refusal.
    #[test]
    fn proptest_deny_never_performs_an_operation(picks in proptest::collection::vec(0usize..6, 1..80)) {
        let (mut backend, probe) = backend(RemoteGuardOutboundIdentity::Deny);
        prop_assert_eq!(negotiate(&mut backend), 0);
        let operations = every_operation();
        for pick in picks {
            set_kerberos(&mut backend, &operations[pick]);
            prop_assert_eq!(kerberos_status(&mut backend), STATUS_NOT_SUPPORTED);
        }
        prop_assert_eq!(probe.executed(), 0);
    }

    /// A service name is reduced to printable ASCII of bounded length,
    /// whatever it contains: it cannot start a second log line.
    #[test]
    fn proptest_loggable_service_is_bounded_and_printable(raw in "\\PC{0,400}|[\\x00-\\x7f]{0,400}") {
        let out = loggable_service(&raw);
        prop_assert!(out.chars().count() <= MAX_LOGGED_SERVICE_LEN);
        prop_assert!(out.chars().all(|c| c.is_ascii_graphic()));
        prop_assert!(!out.contains('"') && !out.contains('\\') && !out.contains('='));
        prop_assert_eq!(out.chars().count(), raw.chars().count().min(MAX_LOGGED_SERVICE_LEN));
    }
}

// --- flood ----------------------------------------------------------------

/// Battle: many sessions refuse a flood of requests at once. Each keeps
/// its own count, none performs anything, none loses its channel.
#[test]
fn battle_concurrent_floods_under_deny_stay_refused() {
    const SESSIONS: usize = 8;
    const REQUESTS: usize = 2_000;
    let barrier = Arc::new(std::sync::Barrier::new(SESSIONS));
    let handles: Vec<_> = (0..SESSIONS)
        .map(|_| {
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let (mut backend, probe) = backend(RemoteGuardOutboundIdentity::Deny);
                assert_eq!(negotiate(&mut backend), 0);
                let operations = every_operation();
                barrier.wait();
                for i in 0..REQUESTS {
                    set_kerberos(&mut backend, &operations[i % operations.len()]);
                    assert_eq!(kerberos_status(&mut backend), STATUS_NOT_SUPPORTED);
                }
                let context = backend.context.as_ref().expect("the channel is still open");
                assert_eq!(context.refusals.total, REQUESTS as u64);
                probe.executed()
            })
        })
        .collect();
    for handle in handles {
        assert_eq!(handle.join().expect("no panic"), 0);
    }
}

/// A flood of refusals writes a bounded number of lines: the first one,
/// then a summary per interval.
#[test]
fn refusals_are_summarized_not_logged_one_by_one() {
    let start = Instant::now();
    let mut log = RefusalLog::new(start);
    assert_eq!(log.record(start), RefusalLine::First);
    for _ in 0..10_000 {
        assert_eq!(log.record(start), RefusalLine::Nothing);
    }
    let later = start + REFUSAL_SUMMARY_INTERVAL;
    assert_eq!(log.record(later), RefusalLine::Summary(10_001));
    assert_eq!(log.record(later), RefusalLine::Nothing);
    assert_eq!(log.total, 10_003);
}

// --- service names --------------------------------------------------------

#[test]
fn the_requested_service_is_read_from_the_tgs_request_body() {
    assert_eq!(
        requested_service(&compute_tgs_checksum(Some(&["cifs", "dc01.contoso.com"]))).as_deref(),
        Some("cifs/dc01.contoso.com")
    );
    assert_eq!(
        requested_service(&compute_tgs_checksum(Some(&["krbtgt", "CONTOSO.COM"]))).as_deref(),
        Some("krbtgt/CONTOSO.COM")
    );
    assert_eq!(requested_service(&compute_tgs_checksum(None)), None);
    // Only a ticket request names a service.
    for request in every_operation()
        .into_iter()
        .filter(|r| Operation::of(r) != Operation::ComputeTgsChecksum)
    {
        assert_eq!(requested_service(&request), None);
    }
}

#[test]
fn the_granted_service_is_read_from_the_kdc_reply() {
    let reply = |der: Vec<u8>| {
        KerberosResponseCall::UnpackKdcReplyBody(ndr::UnpackKdcReplyBodyResponse {
            kerb_protocol_error: 0,
            reply_body: asn1_output(der, 0).unwrap(),
        })
    };
    assert_eq!(
        granted_service(&reply(tgs_reply_part(&["ldap", "dc01.contoso.com"]))).as_deref(),
        Some("ldap/dc01.contoso.com")
    );
    // A KDC may answer a TGS-REQ with the AS-REP tag.
    let as_tagged = picky_asn1_der::to_vec(&EncAsRepPart::from(reply_part(&[
        "cifs",
        "srv01.contoso.com",
    ])))
    .unwrap();
    assert_eq!(
        granted_service(&reply(as_tagged)).as_deref(),
        Some("cifs/srv01.contoso.com")
    );
    assert_eq!(granted_service(&reply(vec![0x30, 0])), None);
    assert_eq!(
        granted_service(&KerberosResponseCall::ComputeTgsChecksum(
            asn1_output(vec![0x30, 0], 8).unwrap()
        )),
        None
    );
}

/// A request body that is not DER, is truncated or is oversized yields
/// no name and no panic: the operation is still decided by the policy.
#[test]
fn attack_malformed_request_body_yields_no_service_name() {
    let with_body = |der: Vec<u8>| {
        KerberosRequest::ComputeTgsChecksum(ndr::ComputeTgsChecksumRequest {
            request_body: Some(asn1_output(der, 66).unwrap()),
            key: None,
            checksum_type: 16,
        })
    };
    let good = tgs_request_body(Some(&["cifs", "dc01.contoso.com"]));
    for bad in [
        Vec::new(),
        vec![0xff; 64],
        good[..good.len() / 2].to_vec(),
        vec![0x30; MAX_NAME_SOURCE_LEN + 1],
    ] {
        assert_eq!(requested_service(&with_body(bad)), None);
    }
    let missing = KerberosRequest::ComputeTgsChecksum(ndr::ComputeTgsChecksumRequest::default());
    assert_eq!(requested_service(&missing), None);
}

/// A service name is chosen by the target. With a line feed, a quote or
/// a field separator in it, it still occupies one field of one line.
#[test]
fn attack_service_name_with_line_feed_is_escaped_in_log() {
    for (raw, expected) in [
        ("cifs/dc01.contoso.com", "cifs/dc01.contoso.com"),
        ("cifs/x\nERROR forged line", "cifs/x?ERROR?forged?line"),
        ("cifs/x\r\n", "cifs/x??"),
        ("a\"b\\c=d", "a?b?c?d"),
        ("caf\u{e9}/h\u{f4}te", "caf?/h?te"),
        ("tab\there", "tab?here"),
        ("\u{1b}[31mred", "?[31mred"),
    ] {
        assert_eq!(loggable_service(raw), expected, "{raw:?}");
    }
    let long = "a".repeat(MAX_LOGGED_SERVICE_LEN * 3);
    assert_eq!(loggable_service(&long).len(), MAX_LOGGED_SERVICE_LEN);
}

#[test]
fn operation_names_are_stable_and_log_safe() {
    let mut seen = std::collections::HashSet::new();
    for request in every_operation() {
        let name = Operation::of(&request).as_str();
        assert!(seen.insert(name), "duplicate name {name}");
        assert!(name.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'));
    }
    assert_eq!(
        Operation::of(&KerberosRequest::NegotiateVersion(ndr::NegotiateVersion {
            version: 0
        })),
        Operation::NegotiateVersion
    );
    assert_eq!(Operation::Other.as_str(), "other");
}
