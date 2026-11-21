//! Remote Credential Guard: what the proxy answers to the target.
//!
//! In a Remote Credential Guard session the target holds a forwarded TGT
//! whose key stays here. Over the authentication redirection channel
//! ([MS-RDPEAR]) it asks the proxy for every Kerberos operation that
//! needs a key: the proxy is the one that signs. This module decides what
//! is signed.
//!
//! The channel, its framing, its NDR codecs and the protection of its
//! messages are upstream code (`ironrdp-rdpear`, the connector's
//! `Backend`, `sspi::rcg`). The connector hands every decoded request to
//! a [`Context`]; [`PolicyContext`] is the one the proxy installs, around
//! the `sspi` session:
//!
//! * `deny`: no Kerberos operation is performed. The version negotiation
//!   the logon needs is answered by the connector itself, before the
//!   context is asked anything, so the session opens. The target obtains
//!   no service ticket, and cannot use one it holds: each use needs an
//!   authenticator, which is an operation.
//! * `allow`: the operations are performed by `sspi`.
//! * Redirected NTLM is refused under both: no Kerberos mode reaches NTLM.
//!
//! The target is an untrusted peer and every request is untrusted input.
//! Nothing a request carries is logged except the name of the service a
//! ticket is asked for, bounded and reduced to printable ASCII. The other
//! arguments are keys or are encrypted with one.

use std::time::{Duration, Instant};

use ironrdp_connector::remote_guard::Context;
use ironrdp_connector::sspi::{self, Error, ErrorKind, Secret};
use ironrdp_rdpear::ndr::{self, KerberosRequest, KerberosResponseCall};
use shared::messages::RemoteGuardOutboundIdentity;
use tracing::{error, info, warn};

/// Longest service name written to the log. A principal name is far
/// shorter; the bound is on what a target can make the proxy write.
const MAX_LOGGED_SERVICE_LEN: usize = 160;

/// Largest DER buffer the proxy parses to read a service name. A
/// `KDC-REQ-BODY` or the encrypted part of a KDC reply is a few hundred
/// bytes; anything larger is logged without a name.
const MAX_NAME_SOURCE_LEN: usize = 16 * 1024;

/// How often the refusals of a session are summarized in the log. Under
/// `deny` a Windows target asks again about once per second for as long
/// as the session is open: one line per request would be a log flood the
/// target controls.
const REFUSAL_SUMMARY_INTERVAL: Duration = Duration::from_secs(300);

/// Request-loop guard: a target whose Kerberos module does not accept the
/// responses asks for the same operations without end and never reaches
/// a KDC reply. Observed against an unpatched connector: several hundred
/// ticket requests per minute, none of them completed. A healthy logon
/// is a few tens of operations, each ticket request followed by its
/// reply.
///
/// The guard counts the ticket requests the proxy answers
/// (`ComputeTgsChecksum`, one per TGS-REQ) since the last KDC reply the
/// target brought back. It trips when that count reaches
/// [`LOOP_GUARD_MAX_UNANSWERED`] within [`LOOP_GUARD_WINDOW`]. Requests
/// the KDC refuses (an unknown service) also count; reaching the bound
/// with them alone takes a sustained rate no session produces.
pub const LOOP_GUARD_MAX_UNANSWERED: u32 = 240;
/// See [`LOOP_GUARD_MAX_UNANSWERED`].
pub const LOOP_GUARD_WINDOW: Duration = Duration::from_secs(60);

/// A redirected Kerberos operation, by name. The set the connector
/// performs, and `Other` for the calls it does not implement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Operation {
    NegotiateVersion,
    BuildEncryptedAuthData,
    ComputeTgsChecksum,
    CreateApReqAuthenticator,
    UnpackKdcReplyBody,
    DecryptApReply,
    PackApReply,
    Other,
}

impl Operation {
    /// The operation a request asks for.
    pub const fn of(request: &KerberosRequest) -> Self {
        match request {
            KerberosRequest::NegotiateVersion(_) => Self::NegotiateVersion,
            KerberosRequest::BuildEncryptedAuthData(_) => Self::BuildEncryptedAuthData,
            KerberosRequest::ComputeTgsChecksum(_) => Self::ComputeTgsChecksum,
            KerberosRequest::CreateApReqAuthenticator(_) => Self::CreateApReqAuthenticator,
            KerberosRequest::UnpackKdcReplyBody(_) => Self::UnpackKdcReplyBody,
            KerberosRequest::DecryptApReply(_) => Self::DecryptApReply,
            KerberosRequest::PackApReply(_) => Self::PackApReply,
            _ => Self::Other,
        }
    }

    /// Stable name for the log. `[a-z_]` only.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NegotiateVersion => "negotiate_version",
            Self::BuildEncryptedAuthData => "build_encrypted_auth_data",
            Self::ComputeTgsChecksum => "compute_tgs_checksum",
            Self::CreateApReqAuthenticator => "create_ap_req_authenticator",
            Self::UnpackKdcReplyBody => "unpack_kdc_reply_body",
            Self::DecryptApReply => "decrypt_ap_reply",
            Self::PackApReply => "pack_ap_reply",
            Self::Other => "other",
        }
    }
}

/// Counts ticket requests that never came back with a KDC reply.
#[derive(Debug)]
pub struct LoopGuard {
    window_start: Instant,
    unanswered: u32,
    tripped: bool,
}

impl LoopGuard {
    pub fn new(now: Instant) -> Self {
        Self {
            window_start: now,
            unanswered: 0,
            tripped: false,
        }
    }

    /// Record a ticket request the proxy answered. Returns `true` when
    /// this request trips the guard. Once tripped, it stays tripped.
    pub fn ticket_requested(&mut self, now: Instant) -> bool {
        if self.tripped {
            return false;
        }
        if now.saturating_duration_since(self.window_start) > LOOP_GUARD_WINDOW {
            self.window_start = now;
            self.unanswered = 0;
        }
        self.unanswered = self.unanswered.saturating_add(1);
        if self.unanswered >= LOOP_GUARD_MAX_UNANSWERED {
            self.tripped = true;
            return true;
        }
        false
    }

    /// The target brought back a KDC reply the proxy could open: it
    /// reaches the KDC and accepts the proxy's responses.
    pub fn kdc_reply_opened(&mut self, now: Instant) {
        if !self.tripped {
            self.window_start = now;
            self.unanswered = 0;
        }
    }

    pub const fn is_tripped(&self) -> bool {
        self.tripped
    }
}

/// Aggregates the refusals of a session into one line now and then.
#[derive(Debug)]
struct RefusalLog {
    total: u64,
    since_summary: u64,
    last_summary: Instant,
}

impl RefusalLog {
    fn new(now: Instant) -> Self {
        Self {
            total: 0,
            since_summary: 0,
            last_summary: now,
        }
    }

    /// Returns what to write for this refusal, if anything.
    fn record(&mut self, now: Instant) -> RefusalLine {
        self.total = self.total.saturating_add(1);
        if self.total == 1 {
            self.last_summary = now;
            return RefusalLine::First;
        }
        self.since_summary = self.since_summary.saturating_add(1);
        if now.saturating_duration_since(self.last_summary) >= REFUSAL_SUMMARY_INTERVAL {
            let count = self.since_summary;
            self.since_summary = 0;
            self.last_summary = now;
            return RefusalLine::Summary(count);
        }
        RefusalLine::Nothing
    }
}

#[derive(Debug, PartialEq, Eq)]
enum RefusalLine {
    First,
    Summary(u64),
    Nothing,
}

/// The [`Context`] the proxy installs on the redirection channel of a
/// Remote Credential Guard session: the `sspi` session behind the
/// bastion's policy.
///
/// Generic over the inner context so the policy is tested without a live
/// Kerberos exchange; production uses `sspi::rcg::RemoteGuardSession`.
pub struct PolicyContext<C> {
    inner: C,
    policy: RemoteGuardOutboundIdentity,
    session_id: String,
    guard: LoopGuard,
    refusals: RefusalLog,
    ntlm_refusals: u64,
}

impl<C: Context> PolicyContext<C> {
    pub fn new(inner: C, policy: RemoteGuardOutboundIdentity, session_id: String) -> Self {
        let now = Instant::now();
        info!(
            session_id = %session_id,
            outbound_identity = policy.as_str(),
            "Remote Credential Guard channel ready"
        );
        Self {
            inner,
            policy,
            session_id,
            guard: LoopGuard::new(now),
            refusals: RefusalLog::new(now),
            ntlm_refusals: 0,
        }
    }

    fn refuse(&mut self, operation: Operation, service: Option<&str>) -> Error {
        match self.refusals.record(Instant::now()) {
            RefusalLine::First => info!(
                session_id = %self.session_id,
                operation = operation.as_str(),
                service = service.unwrap_or("-"),
                "Remote Credential Guard: operation refused by policy \
                 (outbound identity is denied); further refusals are summarized"
            ),
            RefusalLine::Summary(count) => info!(
                session_id = %self.session_id,
                refused = count,
                refused_total = self.refusals.total,
                "Remote Credential Guard: operations refused by policy"
            ),
            RefusalLine::Nothing => {}
        }
        Error::new(
            ErrorKind::UnsupportedFunction,
            "outbound identity is denied on this bastion",
        )
    }
}

impl<C: Context> Context for PolicyContext<C> {
    fn unwrap(&mut self, token: &[u8]) -> sspi::Result<Secret<Vec<u8>>> {
        // A tripped guard closes the channel: the connector turns this
        // error into a channel error, drops the context (the keys are
        // erased) and the session ends.
        if self.guard.is_tripped() {
            return Err(Error::new(
                ErrorKind::InternalError,
                "Remote Credential Guard request loop",
            ));
        }
        self.inner.unwrap(token)
    }

    fn wrap(&mut self, plaintext: &[u8]) -> sspi::Result<Vec<u8>> {
        self.inner.wrap(plaintext)
    }

    fn execute(&mut self, request: &KerberosRequest) -> sspi::Result<KerberosResponseCall> {
        let operation = Operation::of(request);
        let requested = requested_service(request);

        if !self.policy.grants_outbound_identity() {
            return Err(self.refuse(operation, requested.as_deref()));
        }

        let result = self.inner.execute(request);
        let now = Instant::now();
        match &result {
            Ok(response) => {
                let granted = granted_service(response);
                if operation == Operation::UnpackKdcReplyBody {
                    self.guard.kdc_reply_opened(now);
                    info!(
                        session_id = %self.session_id,
                        operation = operation.as_str(),
                        service = granted.as_deref().unwrap_or("-"),
                        "Remote Credential Guard: ticket obtained by the target"
                    );
                } else if operation == Operation::ComputeTgsChecksum {
                    info!(
                        session_id = %self.session_id,
                        operation = operation.as_str(),
                        service = requested.as_deref().unwrap_or("-"),
                        "Remote Credential Guard: ticket requested by the target"
                    );
                }
            }
            Err(failure) => warn!(
                session_id = %self.session_id,
                operation = operation.as_str(),
                service = requested.as_deref().unwrap_or("-"),
                kind = ?failure.error_type,
                "Remote Credential Guard: operation failed"
            ),
        }

        if operation == Operation::ComputeTgsChecksum
            && result.is_ok()
            && self.guard.ticket_requested(now)
        {
            error!(
                session_id = %self.session_id,
                unanswered = LOOP_GUARD_MAX_UNANSWERED,
                window_secs = LOOP_GUARD_WINDOW.as_secs(),
                "Remote Credential Guard: the target asks for tickets without end and \
                 never brings back a KDC reply; closing the session. The target does not \
                 accept the responses of the bastion: its Windows version may use a \
                 Kerberos module the bastion does not know"
            );
        }
        result
    }

    fn ntlm_available(&self) -> bool {
        // Never: the connector then refuses every NTLM request, the
        // version negotiation included, before `execute_ntlm` is reached.
        false
    }

    fn execute_ntlm(&mut self, _request: &ndr::NtlmRequest) -> sspi::Result<ndr::NtlmResponseCall> {
        // Unreachable through the connector (`ntlm_available` is false);
        // refused here too, so the answer does not depend on its caller.
        self.ntlm_refusals = self.ntlm_refusals.saturating_add(1);
        if self.ntlm_refusals == 1 {
            warn!(
                session_id = %self.session_id,
                "Remote Credential Guard: redirected NTLM refused"
            );
        }
        Err(Error::new(
            ErrorKind::UnsupportedFunction,
            "redirected NTLM is never granted",
        ))
    }
}

/// The service a ticket request names: `sname` of the `KDC-REQ-BODY` a
/// `ComputeTgsChecksum` carries, as `component/component`. `None` for
/// every other operation, and when the body does not decode.
pub fn requested_service(request: &KerberosRequest) -> Option<String> {
    let KerberosRequest::ComputeTgsChecksum(request) = request else {
        return None;
    };
    let der = request.request_body.as_ref()?.data.value.as_deref()?;
    if der.len() > MAX_NAME_SOURCE_LEN {
        return None;
    }
    let body: picky_krb::messages::KdcReqBody = picky_asn1_der::from_bytes(der).ok()?;
    let sname = body.sname.0.as_ref()?;
    Some(principal_text(&sname.0))
}

/// The service of the ticket a KDC reply carries: `sname` of the
/// decrypted reply part an `UnpackKdcReplyBody` returns.
pub fn granted_service(response: &KerberosResponseCall) -> Option<String> {
    let KerberosResponseCall::UnpackKdcReplyBody(response) = response else {
        return None;
    };
    let der = response.reply_body.data.value.as_deref()?;
    if der.len() > MAX_NAME_SOURCE_LEN {
        return None;
    }
    let part = picky_asn1_der::from_bytes::<picky_krb::messages::EncTgsRepPart>(der)
        .map(|part| part.0)
        .or_else(|_| {
            picky_asn1_der::from_bytes::<picky_krb::messages::EncAsRepPart>(der).map(|part| part.0)
        })
        .ok()?;
    Some(principal_text(&part.sname.0))
}

/// A principal name as `component/component`, made safe to log.
fn principal_text(name: &picky_krb::data_types::PrincipalName) -> String {
    let joined = name
        .name_string
        .0
        .0
        .iter()
        .map(|component| component.to_string())
        .collect::<Vec<_>>()
        .join("/");
    loggable_service(&joined)
}

/// Reduce a name chosen by the target or relayed by the KDC to what the
/// log may hold: printable ASCII without spaces, quotes or backslashes,
/// at most [`MAX_LOGGED_SERVICE_LEN`] characters. Anything else becomes
/// `?`: a name is evidence, not a place to write a second log line.
pub fn loggable_service(raw: &str) -> String {
    raw.chars()
        .take(MAX_LOGGED_SERVICE_LEN)
        .map(|c| {
            if c.is_ascii_graphic() && c != '"' && c != '\\' && c != '=' {
                c
            } else {
                '?'
            }
        })
        .collect()
}

#[cfg(test)]
#[path = "remote_guard_tests.rs"]
mod tests;
