//! Classification of a failed NLA leg into a [`RdpAuthFailure`].
//!
//! The reason is the ONLY thing about a failure that leaves this process
//! (in `Message::RdpSessionOpenFailed`). It is a closed set, computed from
//! three kinds of evidence, none of which is text:
//!
//! 1. what the KDC relay saw ([`KdcTrace`]): a refused or failed socket
//!    lease, and the Kerberos error code of the last KDC reply;
//! 2. the error kind `sspi` reports for the CredSSP sequence;
//! 3. the CredSSP status the target returned.
//!
//! `sspi` already classifies most errors. The KDC error code is read here
//! only because `sspi` folds distinct causes into one kind: a wrong
//! password and a missing pre-authentication are both `KdcInvalidRequest`,
//! an unknown account and an unknown SPN are both `UnknownCredentials`.
//!
//! Everything in this module is a total function of its inputs. The KDC
//! reply is untrusted input: the reader below is bounded, allocates
//! nothing and never indexes without a length check.

use ironrdp::connector::sspi::ErrorKind;
use shared::kerberos::KdcLeaseRefusal;
use shared::messages::{RdpAuthFailure, RdpAuthMode};

/// Kerberos error codes (RFC 4120 section 7.5.9) this module acts on.
pub mod krb_error {
    pub const KDC_ERR_C_PRINCIPAL_UNKNOWN: u32 = 6;
    pub const KDC_ERR_S_PRINCIPAL_UNKNOWN: u32 = 7;
    pub const KDC_ERR_ETYPE_NOSUPP: u32 = 14;
    pub const KDC_ERR_CLIENT_REVOKED: u32 = 18;
    pub const KDC_ERR_KEY_EXPIRED: u32 = 23;
    pub const KDC_ERR_PREAUTH_FAILED: u32 = 24;
    /// The normal answer to the first AS-REQ: not a failure.
    pub const KDC_ERR_PREAUTH_REQUIRED: u32 = 25;
    pub const KRB_AP_ERR_SKEW: u32 = 37;
    pub const KDC_ERR_WRONG_REALM: u32 = 68;
}

/// CredSSP `errorCode` values (NTSTATUS) this module acts on.
pub mod nstatus {
    pub const LOGON_FAILURE: u32 = 0xc000_006d;
    pub const ACCOUNT_RESTRICTION: u32 = 0xc000_006e;
}

/// ASN.1 tags of the KDC replies, `[APPLICATION n]` constructed.
const TAG_AS_REP: u8 = 0x6b;
const TAG_KRB_ERROR: u8 = 0x7e;
/// `SEQUENCE`.
const TAG_SEQUENCE: u8 = 0x30;
/// `INTEGER`.
const TAG_INTEGER: u8 = 0x02;
/// `[6]`, the `error-code` field of a KRB-ERROR.
const TAG_ERROR_CODE_FIELD: u8 = 0xa6;
/// A KRB-ERROR has 13 fields; anything longer is not one.
const MAX_KRB_ERROR_FIELDS: usize = 13;

/// What a KDC reply is, as far as classification cares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdcReply {
    /// An AS-REP: the KDC issued a TGT.
    AsRep,
    /// A KRB-ERROR with this error code.
    Error(u32),
    /// Anything else (TGS-REP, or bytes that are not a KDC reply).
    Other,
}

/// Split one DER element off `buf`: `(tag, content, rest)`.
///
/// Definite lengths only, at most four length bytes, single-byte tags
/// only. `None` for anything else, or if the content overruns `buf`.
fn der_element(buf: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, after_tag) = buf.split_first()?;
    if tag & 0x1f == 0x1f {
        return None;
    }
    let (&first, after_len) = after_tag.split_first()?;
    let (len, body) = if first < 0x80 {
        (usize::from(first), after_len)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 || after_len.len() < count {
            return None;
        }
        let (len_bytes, body) = after_len.split_at(count);
        let len = len_bytes
            .iter()
            .fold(0usize, |acc, b| (acc << 8) | usize::from(*b));
        (len, body)
    };
    if body.len() < len {
        return None;
    }
    let (content, rest) = body.split_at(len);
    Some((tag, content, rest))
}

/// The `error-code` of a KRB-ERROR body (the content of its SEQUENCE).
fn krb_error_code(mut fields: &[u8]) -> Option<u32> {
    for _ in 0..MAX_KRB_ERROR_FIELDS {
        let (tag, content, rest) = der_element(fields)?;
        if tag == TAG_ERROR_CODE_FIELD {
            let (int_tag, digits, trailing) = der_element(content)?;
            if int_tag != TAG_INTEGER || !trailing.is_empty() {
                return None;
            }
            // A non-negative INTEGER (error codes are Int32): the first
            // byte carries the sign, one leading zero may pad it.
            if digits.first().is_none_or(|b| b & 0x80 != 0) {
                return None;
            }
            let digits = match digits {
                [0, tail @ ..] if !tail.is_empty() => tail,
                other => other,
            };
            let above_i32 = digits.len() == 4 && digits[0] & 0x80 != 0;
            if digits.len() > 4 || above_i32 {
                return None;
            }
            return Some(
                digits
                    .iter()
                    .fold(0u32, |acc, b| (acc << 8) | u32::from(*b)),
            );
        }
        // Fields are in ascending tag order: past [6], there is no code.
        if tag > TAG_ERROR_CODE_FIELD {
            return None;
        }
        fields = rest;
    }
    None
}

/// Classify a framed KDC reply (4-byte big-endian length, then DER).
pub fn kdc_reply(framed: &[u8]) -> KdcReply {
    let Some(der) = framed.get(4..) else {
        return KdcReply::Other;
    };
    let Some((tag, content, _)) = der_element(der) else {
        return KdcReply::Other;
    };
    match tag {
        TAG_AS_REP => KdcReply::AsRep,
        TAG_KRB_ERROR => der_element(content)
            .filter(|(seq_tag, _, _)| *seq_tag == TAG_SEQUENCE)
            .and_then(|(_, fields, _)| krb_error_code(fields))
            .map_or(KdcReply::Other, KdcReply::Error),
        _ => KdcReply::Other,
    }
}

/// What the KDC relay saw during one session open.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct KdcTrace {
    /// The supervisor refused, or failed, a socket lease.
    pub lease_refusal: Option<KdcLeaseRefusal>,
    /// A KDC exchange failed without a refusal code (lease timeout,
    /// channel closed, socket I/O).
    pub relay_failed: bool,
    /// Number of KDC replies received.
    pub replies: u32,
    /// The first reply was an AS-REP.
    pub first_reply_was_as_rep: bool,
    /// Error code of the LAST reply, when that reply was a KRB-ERROR.
    pub last_krb_error: Option<u32>,
}

impl KdcTrace {
    /// Record a framed KDC reply.
    pub fn record_reply(&mut self, framed: &[u8]) {
        let reply = kdc_reply(framed);
        if self.replies == 0 {
            self.first_reply_was_as_rep = reply == KdcReply::AsRep;
        }
        self.replies = self.replies.saturating_add(1);
        self.last_krb_error = match reply {
            KdcReply::Error(code) => Some(code),
            KdcReply::AsRep | KdcReply::Other => None,
        };
    }

    /// Record a failed KDC exchange, from the relay's error string.
    pub fn record_relay_error(&mut self, error: &str) {
        match KdcLeaseRefusal::from_error(error) {
            Some(refusal) => self.lease_refusal = Some(refusal),
            None => self.relay_failed = true,
        }
    }
}

/// What the CredSSP sequence reported.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NlaFailure {
    /// Error kind of the `sspi` error, if the sequence failed in `sspi`.
    pub sspi_kind: Option<ErrorKind>,
    /// CredSSP `errorCode` the target returned, if any.
    pub nstatus: Option<u32>,
    /// The target answered the early user authorization with a denial.
    pub access_denied: bool,
}

/// The reason for a Kerberos error code, when the code decides it.
const fn reason_for_krb_error(code: u32) -> Option<RdpAuthFailure> {
    match code {
        krb_error::KDC_ERR_C_PRINCIPAL_UNKNOWN => Some(RdpAuthFailure::ClientPrincipalUnknown),
        krb_error::KDC_ERR_S_PRINCIPAL_UNKNOWN => Some(RdpAuthFailure::ServicePrincipalUnknown),
        krb_error::KDC_ERR_ETYPE_NOSUPP => Some(RdpAuthFailure::EncryptionTypeUnsupported),
        krb_error::KDC_ERR_CLIENT_REVOKED => Some(RdpAuthFailure::AccountDisabledOrLocked),
        krb_error::KDC_ERR_KEY_EXPIRED => Some(RdpAuthFailure::PasswordExpired),
        krb_error::KDC_ERR_PREAUTH_FAILED => Some(RdpAuthFailure::PreAuthFailed),
        krb_error::KRB_AP_ERR_SKEW => Some(RdpAuthFailure::ClockSkew),
        krb_error::KDC_ERR_WRONG_REALM => Some(RdpAuthFailure::RealmInvalid),
        // The normal answer to the first AS-REQ: never a cause.
        krb_error::KDC_ERR_PREAUTH_REQUIRED => None,
        _ => None,
    }
}

/// The reason for a refused or failed socket lease.
const fn reason_for_lease_refusal(refusal: KdcLeaseRefusal) -> RdpAuthFailure {
    match refusal {
        KdcLeaseRefusal::Disabled => RdpAuthFailure::KerberosBrokerUnavailable,
        KdcLeaseRefusal::InvalidRealm => RdpAuthFailure::RealmInvalid,
        KdcLeaseRefusal::RealmNotConfigured | KdcLeaseRefusal::AmbiguousRealm => {
            RdpAuthFailure::RealmNotConfigured
        }
        KdcLeaseRefusal::Unreachable => RdpAuthFailure::KdcUnreachable,
    }
}

/// Classify a failed NLA leg.
///
/// Order, most specific evidence first:
/// 1. Kerberos modes: the socket lease (the exchange never reached a KDC),
///    then the KDC's own error code, then an AS-REP to an AS-REQ without
///    pre-authentication.
/// 2. Any mode: the `sspi` kinds that name a cause by themselves.
/// 3. Any mode: a logon refusal by the target. In Restricted Admin it is
///    reported as such, since the target is what refuses that mode.
/// 4. Kerberos modes: a token the client could not use, which is what a
///    target that cannot do Kerberos produces.
///
/// Kerberos evidence is ignored in NTLM mode: an NTLM session has no KDC
/// relay, so a trace there could only be a bug.
pub fn classify(mode: RdpAuthMode, failure: &NlaFailure, trace: &KdcTrace) -> RdpAuthFailure {
    let profile = crate::session::auth_mode_profile(mode);

    if profile.kerberos {
        if let Some(refusal) = trace.lease_refusal {
            return reason_for_lease_refusal(refusal);
        }
        if trace.relay_failed {
            return RdpAuthFailure::KdcUnreachable;
        }
        if let Some(reason) = trace.last_krb_error.and_then(reason_for_krb_error) {
            return reason;
        }
        if trace.first_reply_was_as_rep && trace.replies == 1 {
            return RdpAuthFailure::PreAuthNotRequired;
        }
    }

    match failure.sspi_kind {
        Some(ErrorKind::TimeSkew) => return RdpAuthFailure::ClockSkew,
        Some(ErrorKind::NoAuthenticatingAuthority) if profile.kerberos => {
            return RdpAuthFailure::KdcUnreachable;
        }
        _ => {}
    }

    let logon_refused = failure.access_denied
        || matches!(
            failure.nstatus,
            Some(nstatus::LOGON_FAILURE | nstatus::ACCOUNT_RESTRICTION)
        )
        || failure.sspi_kind == Some(ErrorKind::LogonDenied);
    if logon_refused {
        return if profile.restricted_admin {
            RdpAuthFailure::RestrictedAdminRefused
        } else {
            RdpAuthFailure::CredentialsRejected
        };
    }

    if profile.kerberos
        && matches!(
            failure.sspi_kind,
            Some(
                ErrorKind::InvalidToken
                    | ErrorKind::SecurityPackageNotFound
                    | ErrorKind::BadPackageId
                    | ErrorKind::UnsupportedFunction
            )
        )
    {
        return RdpAuthFailure::KerberosPackageRefused;
    }

    RdpAuthFailure::Other
}

#[cfg(test)]
mod tests {
    use super::*;

    /// DER definite length.
    fn der_len(len: usize) -> Vec<u8> {
        if len < 0x80 {
            vec![len as u8]
        } else if len <= 0xff {
            vec![0x81, len as u8]
        } else {
            vec![0x82, (len >> 8) as u8, len as u8]
        }
    }

    fn der(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        out.extend(der_len(content.len()));
        out.extend_from_slice(content);
        out
    }

    fn framed(der_bytes: &[u8]) -> Vec<u8> {
        let mut out = (der_bytes.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(der_bytes);
        out
    }

    /// A KRB-ERROR with the mandatory leading fields and this error code,
    /// followed by a realm and an e-text the classifier must never read.
    fn krb_error_reply(code: u32) -> Vec<u8> {
        let digits: Vec<u8> = {
            let raw = code.to_be_bytes();
            let first = raw.iter().position(|b| *b != 0).unwrap_or(3);
            let mut d = raw[first..].to_vec();
            if d[0] & 0x80 != 0 {
                d.insert(0, 0);
            }
            d
        };
        let mut fields = Vec::new();
        fields.extend(der(0xa0, &der(TAG_INTEGER, &[5]))); // pvno
        fields.extend(der(0xa1, &der(TAG_INTEGER, &[30]))); // msg-type
        fields.extend(der(0xa4, &der(0x18, b"20261114120000Z"))); // stime
        fields.extend(der(0xa5, &der(TAG_INTEGER, &[1]))); // susec
        fields.extend(der(0xa6, &der(TAG_INTEGER, &digits))); // error-code
        fields.extend(der(0xa9, &der(0x1b, b"CORP.EXAMPLE.COM"))); // realm
        fields.extend(der(0xab, &der(0x1b, b"password=hunter2"))); // e-text
        framed(&der(TAG_KRB_ERROR, &der(TAG_SEQUENCE, &fields)))
    }

    fn as_rep_reply() -> Vec<u8> {
        framed(&der(TAG_AS_REP, &der(TAG_SEQUENCE, &[])))
    }

    fn tgs_rep_reply() -> Vec<u8> {
        framed(&der(0x6d, &der(TAG_SEQUENCE, &[])))
    }

    fn trace_with(replies: &[Vec<u8>]) -> KdcTrace {
        let mut trace = KdcTrace::default();
        for reply in replies {
            trace.record_reply(reply);
        }
        trace
    }

    const NO_FAILURE: NlaFailure = NlaFailure {
        sspi_kind: None,
        nstatus: None,
        access_denied: false,
    };

    fn sspi(kind: ErrorKind) -> NlaFailure {
        NlaFailure {
            sspi_kind: Some(kind),
            ..NO_FAILURE
        }
    }

    const KERBEROS_MODES: [RdpAuthMode; 2] =
        [RdpAuthMode::Kerberos, RdpAuthMode::KerberosRestrictedAdmin];

    // ---- KDC reply reader -------------------------------------------------

    #[test]
    fn test_kdc_reply_reads_the_error_code() {
        for code in [
            0u32, 6, 7, 14, 18, 23, 24, 25, 37, 68, 127, 128, 255, 256, 65_535, 70_000,
        ] {
            assert_eq!(
                kdc_reply(&krb_error_reply(code)),
                KdcReply::Error(code),
                "{code}"
            );
        }
    }

    #[test]
    fn test_kdc_reply_tells_as_rep_from_other_replies() {
        assert_eq!(kdc_reply(&as_rep_reply()), KdcReply::AsRep);
        assert_eq!(kdc_reply(&tgs_rep_reply()), KdcReply::Other);
    }

    #[test]
    fn test_kdc_reply_of_malformed_input_is_other() {
        let good = krb_error_reply(24);
        // Every truncation of a valid reply.
        for cut in 0..good.len() {
            assert_eq!(kdc_reply(&good[..cut]), KdcReply::Other, "cut at {cut}");
        }
        for bad in [
            &[][..],
            &[0, 0, 0, 0],
            // Indefinite length.
            &[0, 0, 0, 2, TAG_KRB_ERROR, 0x80],
            // Five length bytes.
            &[0, 0, 0, 7, TAG_KRB_ERROR, 0x85, 0, 0, 0, 0, 1],
            // Length overruns the buffer.
            &[0, 0, 0, 2, TAG_KRB_ERROR, 0x7f],
            // High tag number form.
            &[0, 0, 0, 3, 0x7f, 0x1e, 0x00],
        ] {
            assert_eq!(kdc_reply(bad), KdcReply::Other, "{bad:?}");
        }
    }

    /// A KRB-ERROR whose error-code is negative, oversized or not an
    /// INTEGER carries no usable code.
    #[test]
    fn attack_forged_krb_error_code_is_rejected() {
        for digits in [
            &[0x80][..],                     // negative
            &[0xff, 0xff, 0xff, 0xff],       // negative, four bytes
            &[0x01, 0x00, 0x00, 0x00, 0x00], // five value bytes
            &[0x00, 0x80, 0x00, 0x00, 0x00], // above i32::MAX
            &[],                             // empty
        ] {
            let mut fields = der(0xa0, &der(TAG_INTEGER, &[5]));
            fields.extend(der(0xa6, &der(TAG_INTEGER, digits)));
            let reply = framed(&der(TAG_KRB_ERROR, &der(TAG_SEQUENCE, &fields)));
            assert_eq!(kdc_reply(&reply), KdcReply::Other, "{digits:?}");
        }
        // error-code holding an OCTET STRING.
        let fields = der(0xa6, &der(0x04, &[24]));
        let reply = framed(&der(TAG_KRB_ERROR, &der(TAG_SEQUENCE, &fields)));
        assert_eq!(kdc_reply(&reply), KdcReply::Other);
        // A [6] nested inside the e-text is not the error-code: fields
        // past [6] are never searched.
        let mut fields = der(0xa0, &der(TAG_INTEGER, &[5]));
        fields.extend(der(0xab, &der(0xa6, &der(TAG_INTEGER, &[24]))));
        let reply = framed(&der(TAG_KRB_ERROR, &der(TAG_SEQUENCE, &fields)));
        assert_eq!(kdc_reply(&reply), KdcReply::Other);
    }

    // ---- trace ------------------------------------------------------------

    #[test]
    fn test_trace_keeps_only_the_last_reply_error() {
        // The normal exchange: pre-auth demanded, then a TGT, then a TGS.
        let ok = trace_with(&[krb_error_reply(25), as_rep_reply(), tgs_rep_reply()]);
        assert_eq!(ok.replies, 3);
        assert_eq!(ok.last_krb_error, None);
        assert!(!ok.first_reply_was_as_rep);

        let wrong_password = trace_with(&[krb_error_reply(25), krb_error_reply(24)]);
        assert_eq!(wrong_password.last_krb_error, Some(24));
    }

    #[test]
    fn test_trace_reads_a_lease_refusal_from_its_code() {
        let mut trace = KdcTrace::default();
        trace.record_relay_error(
            &KdcLeaseRefusal::RealmNotConfigured.error("Kerberos realm LAB.TEST is not configured"),
        );
        assert_eq!(
            trace.lease_refusal,
            Some(KdcLeaseRefusal::RealmNotConfigured)
        );
        assert!(!trace.relay_failed);

        let mut trace = KdcTrace::default();
        trace.record_relay_error("KDC FD lease timed out after 15s");
        assert_eq!(trace.lease_refusal, None);
        assert!(trace.relay_failed);
    }

    // ---- classification ---------------------------------------------------

    #[test]
    fn test_classify_kdc_error_codes() {
        let cases = [
            (6, RdpAuthFailure::ClientPrincipalUnknown),
            (7, RdpAuthFailure::ServicePrincipalUnknown),
            (14, RdpAuthFailure::EncryptionTypeUnsupported),
            (18, RdpAuthFailure::AccountDisabledOrLocked),
            (23, RdpAuthFailure::PasswordExpired),
            (24, RdpAuthFailure::PreAuthFailed),
            (37, RdpAuthFailure::ClockSkew),
            (68, RdpAuthFailure::RealmInvalid),
        ];
        for mode in KERBEROS_MODES {
            for (code, expected) in cases {
                let trace = trace_with(&[krb_error_reply(25), krb_error_reply(code)]);
                // sspi's own kind for these codes is deliberately the
                // ambiguous one.
                for kind in [ErrorKind::KdcInvalidRequest, ErrorKind::UnknownCredentials] {
                    assert_eq!(
                        classify(mode, &sspi(kind), &trace),
                        expected,
                        "{mode:?} {code}"
                    );
                }
            }
        }
    }

    /// `sspi` reports a wrong password and an unknown SPN with kinds that
    /// name neither. Without the KDC code both would be `Other`.
    #[test]
    fn test_classify_needs_the_kdc_code_where_sspi_is_ambiguous() {
        let no_trace = KdcTrace::default();
        for kind in [ErrorKind::KdcInvalidRequest, ErrorKind::UnknownCredentials] {
            assert_eq!(
                classify(RdpAuthMode::Kerberos, &sspi(kind), &no_trace),
                RdpAuthFailure::Other
            );
        }
    }

    #[test]
    fn test_classify_lease_refusals_and_relay_failures() {
        let cases = [
            (
                KdcLeaseRefusal::Disabled,
                RdpAuthFailure::KerberosBrokerUnavailable,
            ),
            (KdcLeaseRefusal::InvalidRealm, RdpAuthFailure::RealmInvalid),
            (
                KdcLeaseRefusal::RealmNotConfigured,
                RdpAuthFailure::RealmNotConfigured,
            ),
            (
                KdcLeaseRefusal::AmbiguousRealm,
                RdpAuthFailure::RealmNotConfigured,
            ),
            (KdcLeaseRefusal::Unreachable, RdpAuthFailure::KdcUnreachable),
        ];
        for mode in KERBEROS_MODES {
            for (refusal, expected) in cases {
                let mut trace = KdcTrace::default();
                trace.record_relay_error(&refusal.error("text"));
                assert_eq!(classify(mode, &NO_FAILURE, &trace), expected);
            }
            let mut trace = KdcTrace::default();
            trace.record_relay_error("KDC write failed: broken pipe");
            assert_eq!(
                classify(mode, &NO_FAILURE, &trace),
                RdpAuthFailure::KdcUnreachable
            );
        }
    }

    #[test]
    fn test_classify_account_exempt_from_pre_authentication() {
        // The KDC answers the first AS-REQ with a TGT; sspi gives up.
        let trace = trace_with(&[as_rep_reply()]);
        for mode in KERBEROS_MODES {
            assert_eq!(
                classify(mode, &sspi(ErrorKind::InvalidToken), &trace),
                RdpAuthFailure::PreAuthNotRequired
            );
        }
        // After a normal exchange, a later failure is not that.
        let normal = trace_with(&[krb_error_reply(25), as_rep_reply(), tgs_rep_reply()]);
        assert_ne!(
            classify(
                RdpAuthMode::Kerberos,
                &sspi(ErrorKind::InvalidToken),
                &normal
            ),
            RdpAuthFailure::PreAuthNotRequired
        );
    }

    #[test]
    fn test_classify_sspi_kinds() {
        let trace = KdcTrace::default();
        for mode in RdpAuthMode::ALL {
            assert_eq!(
                classify(mode, &sspi(ErrorKind::TimeSkew), &trace),
                RdpAuthFailure::ClockSkew
            );
        }
        for mode in KERBEROS_MODES {
            assert_eq!(
                classify(mode, &sspi(ErrorKind::NoAuthenticatingAuthority), &trace),
                RdpAuthFailure::KdcUnreachable
            );
            for kind in [
                ErrorKind::InvalidToken,
                ErrorKind::SecurityPackageNotFound,
                ErrorKind::BadPackageId,
                ErrorKind::UnsupportedFunction,
            ] {
                assert_eq!(
                    classify(mode, &sspi(kind), &trace),
                    RdpAuthFailure::KerberosPackageRefused
                );
            }
        }
        assert_eq!(
            classify(
                RdpAuthMode::Kerberos,
                &sspi(ErrorKind::InternalError),
                &trace
            ),
            RdpAuthFailure::Other
        );
    }

    #[test]
    fn test_classify_logon_refusals_by_mode() {
        let trace = trace_with(&[krb_error_reply(25), as_rep_reply(), tgs_rep_reply()]);
        let refusals = [
            NlaFailure {
                access_denied: true,
                ..NO_FAILURE
            },
            NlaFailure {
                nstatus: Some(nstatus::ACCOUNT_RESTRICTION),
                ..sspi(ErrorKind::InvalidToken)
            },
            NlaFailure {
                nstatus: Some(nstatus::LOGON_FAILURE),
                ..NO_FAILURE
            },
            sspi(ErrorKind::LogonDenied),
        ];
        for refusal in refusals {
            assert_eq!(
                classify(RdpAuthMode::KerberosRestrictedAdmin, &refusal, &trace),
                RdpAuthFailure::RestrictedAdminRefused
            );
            assert_eq!(
                classify(RdpAuthMode::Kerberos, &refusal, &trace),
                RdpAuthFailure::CredentialsRejected
            );
            assert_eq!(
                classify(RdpAuthMode::Ntlm, &refusal, &KdcTrace::default()),
                RdpAuthFailure::CredentialsRejected
            );
        }
    }

    /// NTLM mode never yields a Kerberos reason, whatever the evidence.
    #[test]
    fn test_classify_ntlm_mode_ignores_kerberos_evidence() {
        let kerberos_only = [
            RdpAuthFailure::KdcUnreachable,
            RdpAuthFailure::PreAuthFailed,
            RdpAuthFailure::ClientPrincipalUnknown,
            RdpAuthFailure::ServicePrincipalUnknown,
            RdpAuthFailure::RestrictedAdminRefused,
            RdpAuthFailure::KerberosPackageRefused,
            RdpAuthFailure::RealmNotConfigured,
            RdpAuthFailure::PreAuthNotRequired,
            RdpAuthFailure::RealmInvalid,
            RdpAuthFailure::AccountDisabledOrLocked,
            RdpAuthFailure::PasswordExpired,
            RdpAuthFailure::EncryptionTypeUnsupported,
            RdpAuthFailure::KerberosBrokerUnavailable,
        ];
        let mut traces = vec![
            trace_with(&[as_rep_reply()]),
            trace_with(&[krb_error_reply(24)]),
            trace_with(&[krb_error_reply(7)]),
        ];
        let mut refused = KdcTrace::default();
        refused.record_relay_error(&KdcLeaseRefusal::Unreachable.error("x"));
        traces.push(refused);
        for trace in &traces {
            for kind in [
                ErrorKind::InvalidToken,
                ErrorKind::NoAuthenticatingAuthority,
                ErrorKind::UnknownCredentials,
                ErrorKind::LogonDenied,
            ] {
                let reason = classify(RdpAuthMode::Ntlm, &sspi(kind), trace);
                assert!(!kerberos_only.contains(&reason), "{reason:?} in NTLM mode");
            }
        }
    }

    /// The pre-authentication demand is the normal first reply. Alone, it
    /// must not be read as a failure cause.
    #[test]
    fn test_classify_ignores_the_pre_authentication_demand() {
        let trace = trace_with(&[krb_error_reply(25)]);
        assert_eq!(
            classify(
                RdpAuthMode::Kerberos,
                &sspi(ErrorKind::InternalError),
                &trace
            ),
            RdpAuthFailure::Other
        );
    }

    /// A KDC cannot choose the reason by what it WRITES: only the numeric
    /// code is read. The e-text of `krb_error_reply` says `password=`; the
    /// reason is a closed-set value and the trace holds no text.
    #[test]
    fn attack_kdc_text_never_reaches_the_reason() {
        let trace = trace_with(&[krb_error_reply(24)]);
        let reason = classify(RdpAuthMode::Kerberos, &NO_FAILURE, &trace);
        assert_eq!(reason, RdpAuthFailure::PreAuthFailed);
        assert!(!format!("{trace:?}").contains("hunter2"));
        assert!(!reason.as_str().contains("hunter2"));
    }

    mod prop {
        use super::*;
        use proptest::prelude::*;

        fn any_kind() -> impl Strategy<Value = Option<ErrorKind>> {
            prop_oneof![
                Just(None),
                Just(Some(ErrorKind::InvalidToken)),
                Just(Some(ErrorKind::TimeSkew)),
                Just(Some(ErrorKind::NoAuthenticatingAuthority)),
                Just(Some(ErrorKind::UnknownCredentials)),
                Just(Some(ErrorKind::KdcInvalidRequest)),
                Just(Some(ErrorKind::LogonDenied)),
                Just(Some(ErrorKind::InternalError)),
            ]
        }

        proptest! {
            /// The reader is total: any bytes, no panic, and a code only
            /// from a KRB-ERROR tag.
            #[test]
            fn proptest_kdc_reply_is_total(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
                let reply = kdc_reply(&bytes);
                if let KdcReply::Error(_) = reply {
                    prop_assert_eq!(bytes.get(4), Some(&TAG_KRB_ERROR));
                }
                if reply == KdcReply::AsRep {
                    prop_assert_eq!(bytes.get(4), Some(&TAG_AS_REP));
                }
            }

            /// Any code a KDC can send round-trips through the reader.
            #[test]
            fn proptest_error_code_round_trips(code in 0u32..=0x7fff_ffff) {
                prop_assert_eq!(kdc_reply(&krb_error_reply(code)), KdcReply::Error(code));
            }

            /// Classification is total, and a Kerberos-specific reason
            /// never comes out of NTLM mode.
            #[test]
            fn proptest_classify_is_total(
                mode_idx in 0usize..3,
                kind in any_kind(),
                nstatus in proptest::option::of(any::<u32>()),
                access_denied in any::<bool>(),
                replies in proptest::collection::vec(
                    prop_oneof![
                        (0u32..100).prop_map(krb_error_reply),
                        Just(as_rep_reply()),
                        Just(tgs_rep_reply()),
                        proptest::collection::vec(any::<u8>(), 0..32),
                    ],
                    0..5,
                ),
                relay_error in proptest::option::of("[a-z: -]{0,40}"),
            ) {
                let mode = RdpAuthMode::ALL[mode_idx];
                let mut trace = trace_with(&replies);
                if let Some(error) = relay_error {
                    trace.record_relay_error(&error);
                }
                let failure = NlaFailure { sspi_kind: kind, nstatus, access_denied };
                let reason = classify(mode, &failure, &trace);
                prop_assert!(RdpAuthFailure::ALL.contains(&reason));
                // The policy reason is never produced by classification.
                prop_assert_ne!(reason, RdpAuthFailure::NtlmForbidden);
                if mode == RdpAuthMode::Ntlm {
                    prop_assert!(matches!(
                        reason,
                        RdpAuthFailure::ClockSkew
                            | RdpAuthFailure::CredentialsRejected
                            | RdpAuthFailure::Other
                    ));
                }
                if reason == RdpAuthFailure::RestrictedAdminRefused {
                    prop_assert_eq!(mode, RdpAuthMode::KerberosRestrictedAdmin);
                }
            }
        }
    }
}
