//! Remote Credential Guard: the backend of the authentication redirection
//! channel ([MS-RDPEAR]).
//!
//! It opens each protected message of the target, decodes the request,
//! hands it to a [`Context`], and frames and protects the response. The
//! context the proxy installs is [`crate::remote_guard::PolicyContext`],
//! around the `sspi` session.
//!
//! # Origin
//!
//! Adapted from `crates/ironrdp-connector/src/remote_guard.rs` of IronRDP
//! (Devolutions, MIT OR Apache-2.0), at the commit the workspace manifest
//! pins. Upstream keeps that module private, so the proxy carries its own
//! copy. Compare the two when the pin moves. Three differences are
//! deliberate, and are the reason a plain re-copy would be a regression:
//!
//! * **`KERB_ASN1_DATA.Pdu` is set.** Upstream returns it as 0. A Windows
//!   target does not ignore the field: it is the slot of the ASN.1 type in
//!   its compiled Kerberos module, and the target decodes the returned
//!   buffer with it. With slot 0 it rejects every response locally, sends
//!   nothing to a KDC, and asks for the same operations without end. See
//!   the `PDU_*` constants.
//! * **Redirected NTLM is not implemented.** The session never performs
//!   an NTLM operation here; the framing still answers an NTLM request,
//!   with a refusal.
//! * **No constructor tied to the connector.** The proxy drives CredSSP
//!   itself and attaches the channel in `session.rs`.

use ironrdp_connector::sspi::rcg as rg;
use ironrdp_connector::sspi::{self, Error, ErrorKind, Secret};
use ironrdp_core::{Encode as _, ReadCursor, encode_vec};
use ironrdp_pdu::{PduResult, pdu_other_err};
use ironrdp_rdpear::ndr::{self, KerberosRequest as Request, KerberosResponseCall as Response};
use ironrdp_rdpear::{AuthRedirectionBackend, RemoteGuardInnerPacket};
use tracing::warn;

/// Largest message of the channel, in either direction.
pub const MAX_MESSAGE_SIZE: usize = 1024 * 1024;
/// Bytes the protection of a message adds: header, confounder, encrypted
/// header, checksum.
pub const WRAP_OVERHEAD: usize = 16 + 16 + 16 + 12;
/// Package name of the Kerberos calls, UTF-16LE.
pub const KERBEROS: &[u8] = b"K\0e\0r\0b\0e\0r\0o\0s\0";
/// Package name of the NTLM calls, UTF-16LE.
pub const NTLM: &[u8] = b"N\0T\0L\0M\0";
pub const PROFILE: ndr::NdrProfile = ndr::NdrProfile::WindowsNative;
pub const STATUS_NOT_SUPPORTED: i32 = 0xc000_00bbu32.cast_signed();
pub const STATUS_INVALID_PARAMETER: i32 = 0xc000_000du32.cast_signed();
pub const STATUS_INVALID_HANDLE: i32 = 0xc000_0008u32.cast_signed();
pub const STATUS_ACCESS_DENIED: i32 = 0xc000_0022u32.cast_signed();
pub const STATUS_UNSUCCESSFUL: i32 = 0xc000_0001u32.cast_signed();

// The values below are the ones FreeRDP's rdpear channel uses.
/// Slot of `EncryptedData` in the Kerberos module of targets up to
/// Windows Server 2022.
pub const PDU_ENCRYPTED_DATA: u32 = 6;
/// Slot of `EncryptedData` in the Kerberos module of Windows 11 24H2 and
/// Windows Server 2025.
pub const PDU_ENCRYPTED_DATA_SHIFTED: u32 = 7;
/// Slot of `Checksum`. A target with the older module labels its own
/// checksums with it.
pub const PDU_CHECKSUM: u32 = 8;
/// Slot of `EncAPRepPart`.
pub const PDU_ENC_AP_REP_PART: u32 = 0x31;

/// Slot to return with an encrypted authenticator.
///
/// The target does not announce its module. It labels the checksum it
/// hands over with [`PDU_CHECKSUM`] on the older module and leaves it
/// blank on the newer one, which tells the two apart.
pub fn authenticator_pdu(gss_checksum_pdu: Option<u32>) -> u32 {
    if gss_checksum_pdu == Some(PDU_CHECKSUM) {
        PDU_ENCRYPTED_DATA
    } else {
        PDU_ENCRYPTED_DATA_SHIFTED
    }
}

/// What the backend needs from the authenticated session: the protection
/// of the messages, and the operations. A trait so the framing and the
/// policy are tested without a live Kerberos exchange.
pub trait Context: Send {
    fn unwrap(&mut self, token: &[u8]) -> sspi::Result<Secret<Vec<u8>>>;
    fn wrap(&mut self, plaintext: &[u8]) -> sspi::Result<Vec<u8>>;
    fn execute(&mut self, request: &Request) -> sspi::Result<Response>;
    fn ntlm_available(&self) -> bool;
    fn execute_ntlm(&mut self, request: &ndr::NtlmRequest) -> sspi::Result<ndr::NtlmResponseCall>;
}

pub struct Backend<C> {
    pub context: Option<C>,
    pub negotiated: bool,
    pub ntlm_negotiated: bool,
    pub kerberos_allowed: bool,
}

impl<C: Context> AuthRedirectionBackend for Backend<C> {
    fn process(&mut self, encrypted_payload: &[u8], max_payload_size: usize) -> PduResult<Vec<u8>> {
        let result = self.process_inner(encrypted_payload, max_payload_size);
        if result.is_err() {
            self.close();
        }
        result
    }

    fn close(&mut self) {
        self.context = None;
        self.negotiated = false;
        self.ntlm_negotiated = false;
    }
}

impl<C: Context> Backend<C> {
    fn process_inner(
        &mut self,
        encrypted_payload: &[u8],
        max_payload_size: usize,
    ) -> PduResult<Vec<u8>> {
        let limit = max_payload_size
            .min(MAX_MESSAGE_SIZE - ironrdp_rdpear::AuthRedirectionPdu::HEADER_SIZE);
        if encrypted_payload.len() > limit || limit < WRAP_OVERHEAD {
            return Err(pdu_other_err!("RCG payload exceeds the message limit"));
        }
        let context = self
            .context
            .as_mut()
            .ok_or_else(|| pdu_other_err!("RCG context is closed"))?;
        let plaintext = context
            .unwrap(encrypted_payload)
            .map_err(|_| pdu_other_err!("RCG message authentication failed"))?;
        let inner = RemoteGuardInnerPacket::decode_with_limit(
            &mut ReadCursor::new(plaintext.as_ref()),
            limit,
        )
        .map_err(|_| pdu_other_err!("invalid authenticated RCG inner packet"))?;
        let limits = ndr::NdrLimits {
            max_message_size: limit,
            ..ndr::NdrLimits::default()
        };
        let response = if inner.package_name == KERBEROS {
            let request = Request::decode_with_profile(inner.package_call, limits, PROFILE)
                .map_err(|_| pdu_other_err!("invalid RCG Kerberos request"))?;
            let result = if !self.kerberos_allowed {
                Err(Error::new(
                    ErrorKind::UnsupportedFunction,
                    "RCG Kerberos redirection is disabled",
                ))
            } else {
                match &request {
                    Request::NegotiateVersion(version) => {
                        if version.version != 0 {
                            Err(Error::new(
                                ErrorKind::UnsupportedFunction,
                                "unsupported RCG package version",
                            ))
                        } else {
                            self.negotiated = true;
                            Ok(Response::NegotiateVersion(ndr::NegotiateVersion {
                                version: 0,
                            }))
                        }
                    }
                    _ if !self.negotiated => Err(Error::new(
                        ErrorKind::OutOfSequence,
                        "RCG package version not negotiated",
                    )),
                    _ => context.execute(&request),
                }
            };
            let (status, call) = match result {
                Ok(call) => (0, call),
                Err(error) => {
                    warn!(call_id = request.call_id(), kind = ?error.error_type, "RCG operation rejected");
                    (
                        operation_status(error.error_type),
                        empty_response(&request),
                    )
                }
            };
            ndr::KerberosResponse { status, call }.encode_with_profile(
                ndr::Endianness::Little,
                limits,
                PROFILE,
            )
        } else if inner.package_name == NTLM {
            let request = ndr::NtlmRequest::decode_with_profile(inner.package_call, limits, PROFILE)
                .map_err(|_| pdu_other_err!("invalid RCG NTLM request"))?;
            let result = if !context.ntlm_available() {
                Err(Error::new(
                    ErrorKind::UnsupportedFunction,
                    "RCG NTLM credentials are unavailable",
                ))
            } else {
                match &request {
                    ndr::NtlmRequest::NegotiateVersion(version) => {
                        if version.version != 0 {
                            Err(Error::new(
                                ErrorKind::UnsupportedFunction,
                                "unsupported RCG NTLM package version",
                            ))
                        } else {
                            self.ntlm_negotiated = true;
                            Ok(ndr::NtlmResponseCall::NegotiateVersion(
                                ndr::NegotiateVersion { version: 0 },
                            ))
                        }
                    }
                    _ if !self.ntlm_negotiated => Err(Error::new(
                        ErrorKind::OutOfSequence,
                        "RCG NTLM package version not negotiated",
                    )),
                    ndr::NtlmRequest::CalculateNtResponse(_)
                    | ndr::NtlmRequest::CalculateUserSessionKeyNt(_) => Err(Error::new(
                        ErrorKind::UnsupportedFunction,
                        "RCG NTLMv1 operations are disabled",
                    )),
                    _ => context.execute_ntlm(&request),
                }
            };
            let (status, call) = match result {
                Ok(call) => (0, call),
                Err(error) => {
                    warn!(call_id = request.call_id(), kind = ?error.error_type, "RCG NTLM operation rejected");
                    (
                        operation_status(error.error_type),
                        empty_ntlm_response(&request),
                    )
                }
            };
            ndr::NtlmResponse { status, call }.encode_with_profile(
                ndr::Endianness::Little,
                limits,
                PROFILE,
            )
        } else {
            return Err(pdu_other_err!("unauthorized RCG security package"));
        }
        .map_err(|_| pdu_other_err!("RCG response encoding failed"))?;
        let response = Secret::new(response);
        let inner = RemoteGuardInnerPacket {
            package_name: inner.package_name,
            package_call: response.as_ref(),
        };
        if inner.size() > limit - WRAP_OVERHEAD {
            return Err(pdu_other_err!("RCG response exceeds the message limit"));
        }
        let encoded = Secret::new(
            encode_vec(&inner).map_err(|_| pdu_other_err!("RCG inner encoding failed"))?,
        );
        let sealed = context
            .wrap(encoded.as_ref())
            .map_err(|_| pdu_other_err!("RCG response protection failed"))?;
        if sealed.is_empty() || sealed.len() > limit {
            return Err(pdu_other_err!(
                "RCG protected response exceeds the message limit"
            ));
        }
        Ok(sealed)
    }
}

fn operation_status(kind: ErrorKind) -> i32 {
    match kind {
        ErrorKind::UnsupportedFunction => STATUS_NOT_SUPPORTED,
        ErrorKind::InvalidParameter | ErrorKind::InvalidToken | ErrorKind::OutOfSequence => {
            STATUS_INVALID_PARAMETER
        }
        ErrorKind::InvalidHandle => STATUS_INVALID_HANDLE,
        ErrorKind::NoCredentials | ErrorKind::LogonDenied => STATUS_ACCESS_DENIED,
        _ => STATUS_UNSUCCESSFUL,
    }
}

fn empty_response(request: &Request) -> Response {
    match request {
        Request::NegotiateVersion(_) => Response::NegotiateVersion(Default::default()),
        Request::BuildAsReqAuthenticator(_) => {
            Response::BuildAsReqAuthenticator(Default::default())
        }
        Request::VerifyServiceTicket(_) => Response::VerifyServiceTicket(Default::default()),
        Request::CreateApReqAuthenticator(_) => {
            Response::CreateApReqAuthenticator(Default::default())
        }
        Request::DecryptApReply(_) => Response::DecryptApReply(Default::default()),
        Request::UnpackKdcReplyBody(_) => Response::UnpackKdcReplyBody(Default::default()),
        Request::ComputeTgsChecksum(_) => Response::ComputeTgsChecksum(Default::default()),
        Request::BuildEncryptedAuthData(_) => Response::BuildEncryptedAuthData(Default::default()),
        Request::PackApReply(_) => Response::PackApReply(Default::default()),
        Request::HashS4UPreauth(_) => Response::HashS4UPreauth(Default::default()),
        Request::SignS4UPreauthData(_) => Response::SignS4UPreauthData(Default::default()),
        Request::VerifyChecksum(_) => Response::VerifyChecksum(Default::default()),
        Request::DecryptPacCredentials(_) => Response::DecryptPacCredentials(Default::default()),
        Request::CreateEcdhKeyAgreement(_) => Response::CreateEcdhKeyAgreement(Default::default()),
        Request::CreateDhKeyAgreement(_) => Response::CreateDhKeyAgreement(Default::default()),
        Request::DestroyKeyAgreement(_) => Response::DestroyKeyAgreement(Default::default()),
        Request::KeyAgreementGenerateNonce(_) => {
            Response::KeyAgreementGenerateNonce(Default::default())
        }
        Request::FinalizeKeyAgreement(_) => Response::FinalizeKeyAgreement(Default::default()),
    }
}

fn empty_ntlm_response(request: &ndr::NtlmRequest) -> ndr::NtlmResponseCall {
    match request {
        ndr::NtlmRequest::NegotiateVersion(_) => {
            ndr::NtlmResponseCall::NegotiateVersion(Default::default())
        }
        ndr::NtlmRequest::Lm20GetNtlm3ChallengeResponse(_) => {
            ndr::NtlmResponseCall::Lm20GetNtlm3ChallengeResponse(Default::default())
        }
        ndr::NtlmRequest::CalculateNtResponse(_) => {
            ndr::NtlmResponseCall::CalculateNtResponse(Default::default())
        }
        ndr::NtlmRequest::CalculateUserSessionKeyNt(_) => {
            ndr::NtlmResponseCall::CalculateUserSessionKeyNt(Default::default())
        }
        ndr::NtlmRequest::CompareCredentials(_) => {
            ndr::NtlmResponseCall::CompareCredentials(Default::default())
        }
    }
}

fn invalid_parameter() -> Error {
    Error::new(
        ErrorKind::InvalidParameter,
        "invalid RCG operation argument",
    )
}

fn required<T>(value: &Option<T>) -> sspi::Result<&T> {
    value.as_ref().ok_or_else(invalid_parameter)
}

pub fn bytes(value: &ndr::OctetString) -> sspi::Result<&[u8]> {
    let bytes = required(&value.value)?;
    if usize::try_from(value.length).ok() != Some(bytes.len()) {
        return Err(invalid_parameter());
    }
    Ok(bytes)
}

fn asn1(value: &ndr::Asn1Data) -> sspi::Result<&[u8]> {
    // The slot of an input only matters to the target; the buffer is
    // decoded by its expected type.
    bytes(&value.data)
}

fn key(value: &ndr::EncryptionKey) -> sspi::Result<rg::KeyReference<'_>> {
    Ok(rg::KeyReference {
        encryption_type: value.reserved2,
        value: bytes(&value.reserved3)?,
    })
}

fn unicode(value: &ndr::UnicodeString) -> sspi::Result<String> {
    let buffer = required(&value.buffer)?;
    if usize::from(value.length) != buffer.len() * 2 {
        return Err(invalid_parameter());
    }
    String::from_utf16(buffer).map_err(|_| invalid_parameter())
}

fn output(bytes: Vec<u8>) -> sspi::Result<ndr::OctetString> {
    Ok(ndr::OctetString {
        length: u32::try_from(bytes.len()).map_err(|_| invalid_parameter())?,
        value: Some(bytes),
    })
}

/// An ASN.1 buffer for the target, labelled with the slot of its type.
pub fn asn1_output(bytes: Vec<u8>, pdu: u32) -> sspi::Result<ndr::Asn1Data> {
    Ok(ndr::Asn1Data {
        pdu,
        data: output(bytes)?,
    })
}

impl Context for rg::RemoteGuardSession {
    fn unwrap(&mut self, token: &[u8]) -> sspi::Result<Secret<Vec<u8>>> {
        Self::unwrap(self, token)
    }

    fn wrap(&mut self, plaintext: &[u8]) -> sspi::Result<Vec<u8>> {
        Self::wrap(self, plaintext)
    }

    fn ntlm_available(&self) -> bool {
        // Never, whatever the session holds: the proxy does not perform
        // redirected NTLM (see the module documentation).
        false
    }

    fn execute_ntlm(
        &mut self,
        _request: &ndr::NtlmRequest,
    ) -> sspi::Result<ndr::NtlmResponseCall> {
        Err(Error::new(
            ErrorKind::UnsupportedFunction,
            "RCG NTLM operation is unsupported",
        ))
    }

    fn execute(&mut self, request: &Request) -> sspi::Result<Response> {
        match request {
            Request::ComputeTgsChecksum(request) => {
                let result = self.compute_tgs_checksum(rg::ComputeTgsChecksumRequest {
                    request_body: asn1(required(&request.request_body)?)?,
                    key: key(required(&request.key)?)?,
                    checksum_type: i32::try_from(request.checksum_type)
                        .map_err(|_| invalid_parameter())?,
                })?;
                Ok(Response::ComputeTgsChecksum(asn1_output(
                    result,
                    PDU_CHECKSUM,
                )?))
            }
            Request::BuildEncryptedAuthData(request) => {
                let result = self.build_encrypted_auth_data(rg::BuildEncryptedAuthDataRequest {
                    key_usage: request.key_usage,
                    key: key(required(&request.key)?)?,
                    plain_auth_data: asn1(required(&request.plain_auth_data)?)?,
                })?;
                Ok(Response::BuildEncryptedAuthData(asn1_output(
                    result,
                    PDU_ENCRYPTED_DATA,
                )?))
            }
            Request::CreateApReqAuthenticator(request) => {
                let name = required(&request.client_name)?;
                let names = required(&name.names)?;
                if usize::from(name.name_count) != names.len() {
                    return Err(invalid_parameter());
                }
                let names = names
                    .iter()
                    .map(unicode)
                    .collect::<sspi::Result<Vec<_>>>()?;
                let realm = unicode(required(&request.client_realm)?)?;
                // sspi ignores SkewTime; an adjustment is refused rather
                // than silently dropped.
                if request.skew_time.is_some_and(|skew| skew != 0) {
                    return Err(Error::new(
                        ErrorKind::UnsupportedFunction,
                        "RCG server clock adjustment is unsupported",
                    ));
                }
                let result =
                    self.create_ap_req_authenticator(rg::CreateApReqAuthenticatorRequest {
                        encryption_key: key(required(&request.encryption_key)?)?,
                        sequence_number: request.sequence_number,
                        client_name: &names,
                        client_realm: &realm,
                        skew_time: 0,
                        sub_key: request.sub_key.as_ref().map(key).transpose()?,
                        auth_data: request.auth_data.as_ref().map(asn1).transpose()?,
                        gss_checksum: request.gss_checksum.as_ref().map(asn1).transpose()?,
                        key_usage: request.key_usage,
                    })?;
                let pdu = authenticator_pdu(
                    request.gss_checksum.as_ref().map(|checksum| checksum.pdu),
                );
                Ok(Response::CreateApReqAuthenticator(
                    ndr::CreateApReqAuthenticatorResponse {
                        authenticator_time: result.authenticator_time,
                        authenticator: asn1_output(result.authenticator, pdu)?,
                        kerb_protocol_error: 0,
                    },
                ))
            }
            Request::UnpackKdcReplyBody(request) => {
                let result = self.unpack_kdc_reply_body(rg::UnpackKdcReplyBodyRequest {
                    encrypted_data: asn1(required(&request.encrypted_data)?)?,
                    key: key(required(&request.key)?)?,
                    strengthen_key: request.strengthen_key.as_ref().map(key).transpose()?,
                    key_usage: request.key_usage,
                })?;
                Ok(Response::UnpackKdcReplyBody(
                    ndr::UnpackKdcReplyBodyResponse {
                        kerb_protocol_error: 0,
                        // The target names the type it expects back.
                        reply_body: asn1_output(result, request.pdu)?,
                    },
                ))
            }
            Request::DecryptApReply(request) => {
                let result = self.decrypt_ap_reply(rg::DecryptApReplyRequest {
                    encrypted_reply: asn1(required(&request.encrypted_reply)?)?,
                    key: key(required(&request.key)?)?,
                })?;
                Ok(Response::DecryptApReply(asn1_output(
                    result.as_ref().clone(),
                    PDU_ENC_AP_REP_PART,
                )?))
            }
            Request::PackApReply(request) => {
                let result = self.pack_ap_reply(rg::PackApReplyRequest {
                    reply: asn1(required(&request.reply)?)?,
                    reply_body: asn1(required(&request.reply_body)?)?,
                    session_key: key(required(&request.session_key)?)?,
                })?;
                Ok(Response::PackApReply(output(result)?))
            }
            _ => Err(Error::new(
                ErrorKind::UnsupportedFunction,
                "RCG operation is unsupported",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asn1_output_carries_the_slot_of_the_target_module() {
        let data = asn1_output(vec![0x30, 0], PDU_CHECKSUM).unwrap();
        assert_eq!(data.pdu, PDU_CHECKSUM);
        assert_eq!(bytes(&data.data).unwrap(), [0x30, 0]);
    }

    #[test]
    fn authenticator_slot_follows_the_checksum_label_of_the_target() {
        // Older module: the target labels its checksum, and expects
        // EncryptedData in slot 6.
        assert_eq!(authenticator_pdu(Some(PDU_CHECKSUM)), PDU_ENCRYPTED_DATA);
        // Newer module: the label is blank, EncryptedData moved to slot 7.
        assert_eq!(authenticator_pdu(Some(0)), PDU_ENCRYPTED_DATA_SHIFTED);
        assert_eq!(authenticator_pdu(None), PDU_ENCRYPTED_DATA_SHIFTED);
    }

    /// Slot 0 is what upstream sends and what a Windows target rejects:
    /// no response type of the channel is labelled with it.
    #[test]
    fn attack_no_response_slot_is_zero() {
        for slot in [
            PDU_CHECKSUM,
            PDU_ENCRYPTED_DATA,
            PDU_ENCRYPTED_DATA_SHIFTED,
            PDU_ENC_AP_REP_PART,
            authenticator_pdu(None),
            authenticator_pdu(Some(0)),
            authenticator_pdu(Some(PDU_CHECKSUM)),
        ] {
            assert_ne!(slot, 0);
        }
    }
}
