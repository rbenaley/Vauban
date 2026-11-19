//! A Windows-style acceptor for the SPNEGO `mechListMIC`.
//!
//! `sspi`'s CredSSP server signs its `mechListMIC` with the sequence
//! number its AP-REP announced. A Windows acceptor signs it with sequence
//! number 0, whatever the AP-REP said. `sspi` 0.23.0 refused that token on
//! the initiator side, which failed both Kerberos RDP modes against every
//! Windows target (met on 2026-11-19, fixed by the fork pinned in the
//! workspace manifest).
//!
//! [`WindowsMic`] sits in the target loop of the harness, between `sspi`'s
//! server and the stream: it replaces the server's MIC with one numbered 0
//! and signed with the same key over the same data. Nothing in production
//! changes; the keys it needs are the ones the target itself holds.
//!
//! The exchange is user-to-user (CredSSP asks for `USE_SESSION_KEY`), so
//! the chain of keys is:
//!
//! 1. the target's ticket-granting ticket session key, issued by the
//!    target's own [`KdcMock`], which records it;
//! 2. the service ticket carried by the client's AP-REQ, encrypted under
//!    (1), which holds the ticket session key;
//! 3. the AP-REP of the target, encrypted under (2), which holds the
//!    acceptor sub-key the MIC is signed with.

use picky_asn1::wrapper::{ExplicitContextTag3, OctetStringAsn1, Optional};
use picky_krb::constants::gss_api::AP_REP_TOKEN_ID;
use picky_krb::constants::key_usages::{ACCEPTOR_SIGN, AP_REP_ENC, TICKET_REP};
use picky_krb::crypto::CipherSuite;
use picky_krb::crypto::aes::{AesSize, checksum_sha_aes};
use picky_krb::data_types::{EncApRepPart, EncTicketPart};
use picky_krb::gss_api::{ApplicationTag0, GssApiNegInit, KrbMessage, MicToken, NegTokenTarg1};
use picky_krb::messages::{ApRep, ApReq};

use super::kdc_mock::KdcMock;

/// What the filter does to the acceptor's MIC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MicStyle {
    /// Sequence number 0, correct checksum: a Windows acceptor.
    Windows,
    /// Sequence number 0, checksum altered: an attacker on the path who
    /// counts on the sequence number no longer being checked.
    WindowsForged,
}

/// State of the filter across one CredSSP exchange.
pub(crate) struct WindowsMic {
    style: MicStyle,
    /// DER of the `MechTypeList` the client offered: the data the MIC
    /// signs.
    mech_types: Option<Vec<u8>>,
    /// Session key of the service ticket the client presented.
    ticket_session_key: Option<Vec<u8>>,
    /// Set once a MIC has been replaced: a test asserts the filter ran.
    pub(crate) replaced: bool,
}

impl WindowsMic {
    pub(crate) fn new(style: MicStyle) -> Self {
        Self {
            style,
            mech_types: None,
            ticket_session_key: None,
            replaced: false,
        }
    }

    /// Learn from a client token: the mechanism list of its first token,
    /// then the ticket session key from its AP-REQ.
    pub(crate) fn observe_client(&mut self, nego_token: &[u8], kdc: &KdcMock) {
        // 0x60: the GSS-API initial token ([APPLICATION 0]). The decoder
        // of that framing panics on anything else, so the tag is checked
        // first; later tokens are bare NegTokenTarg ([1], 0xa1).
        if nego_token.first() == Some(&0x60)
            && let Ok(init) =
                picky_asn1_der::from_bytes::<ApplicationTag0<GssApiNegInit>>(nego_token)
            && let Some(mech_types) = init.0.neg_token_init.0.mech_types.0
        {
            self.mech_types = Some(picky_asn1_der::to_vec(&mech_types.0).unwrap());
            return;
        }

        let Ok(targ) = picky_asn1_der::from_bytes::<NegTokenTarg1>(nego_token) else {
            return;
        };
        let Some(response) = targ.0.response_token.0 else {
            return;
        };
        let Ok(ap_req) = KrbMessage::<ApReq>::decode_application_krb_message(&response.0.0) else {
            return;
        };
        let encrypted_ticket = &ap_req.0.krb_msg.0.ticket.0.0.enc_part.0;
        let cipher = CipherSuite::try_from(encrypted_ticket.etype.0.0.as_slice())
            .expect("supported ticket encryption type")
            .cipher();
        // User-to-user: the ticket is encrypted under the session key of
        // the target's own ticket-granting ticket.
        self.ticket_session_key = kdc.issued_session_keys().into_iter().find_map(|tgt_key| {
            let ticket = cipher
                .decrypt(&tgt_key, TICKET_REP, &encrypted_ticket.cipher.0.0)
                .ok()?;
            let ticket: EncTicketPart = picky_asn1_der::from_bytes(&ticket).ok()?;
            Some(ticket.0.key.0.key_value.0.0)
        });
    }

    /// Replace the acceptor's `mechListMIC` in a server token, if it
    /// carries one. Returns the token to send.
    pub(crate) fn rewrite_server(&mut self, nego_token: Vec<u8>) -> Vec<u8> {
        let Ok(mut targ) = picky_asn1_der::from_bytes::<NegTokenTarg1>(&nego_token) else {
            return nego_token;
        };
        let (Some(original_mic), Some(response)) = (
            targ.0.mech_list_mic.0.as_ref(),
            targ.0.response_token.0.as_ref(),
        ) else {
            return nego_token;
        };

        let ap_rep = KrbMessage::<ApRep>::decode_application_krb_message(&response.0.0)
            .expect("the token that carries the MIC carries the AP-REP");
        assert_eq!(ap_rep.0.krb5_token_id, AP_REP_TOKEN_ID);
        let ap_rep = ap_rep.0.krb_msg;
        let ticket_session_key = self
            .ticket_session_key
            .as_ref()
            .expect("the client's AP-REQ was seen before the AP-REP");
        let cipher = CipherSuite::try_from(ap_rep.0.enc_part.0.etype.0.0.as_slice())
            .expect("supported AP-REP encryption type")
            .cipher();
        let enc_part = cipher
            .decrypt(
                ticket_session_key,
                AP_REP_ENC,
                &ap_rep.0.enc_part.0.cipher.0.0,
            )
            .expect("the ticket session key decrypts the AP-REP");
        let enc_part: EncApRepPart = picky_asn1_der::from_bytes(&enc_part).unwrap();
        let sub_key = enc_part
            .0
            .subkey
            .0
            .expect("the acceptor sends a sub-key")
            .0
            .key_value
            .0
            .0;
        let mech_types = self
            .mech_types
            .as_ref()
            .expect("the client's first token was seen");

        // Prove the reconstruction before using it: the same key over the
        // same data must reproduce the MIC `sspi` computed. Without this,
        // a harness that drifted would sign garbage and the attack test
        // would pass for the wrong reason.
        let original = MicToken::decode(original_mic.0.0.as_slice()).unwrap();
        let sign = |token: &MicToken| {
            let payload = [mech_types.as_slice(), token.header().as_slice()].concat();
            checksum_sha_aes(&sub_key, ACCEPTOR_SIGN, &payload, &AesSize::Aes256).unwrap()
        };
        assert_eq!(
            sign(&original),
            original.checksum,
            "the filter does not hold the acceptor's key and data"
        );
        assert_ne!(
            original.seq_num, 0,
            "sspi's acceptor already signs with sequence number 0: the filter is no longer needed"
        );

        let mut windows = MicToken::with_acceptor_flags().with_seq_number(0);
        let mut checksum = sign(&windows);
        if self.style == MicStyle::WindowsForged {
            let last = checksum.len() - 1;
            checksum[last] ^= 0x01;
        }
        windows.set_checksum(checksum);
        let mut encoded = Vec::new();
        windows.encode(&mut encoded).unwrap();

        targ.0.mech_list_mic = Optional::from(Some(ExplicitContextTag3::from(
            OctetStringAsn1::from(encoded),
        )));
        self.replaced = true;
        picky_asn1_der::to_vec(&targ).unwrap()
    }
}
