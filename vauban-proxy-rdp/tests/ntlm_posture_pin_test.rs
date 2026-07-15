//! Behavioral pin tests for the NTLM security posture of the `sspi` crate
//! (the SSPI layer under IronRDP, exercised by the CredSSP/NLA leg of
//! `vauban-proxy-rdp`).
//!
//! Rationale (see `.cursor/audits/rdp_kerberos_evaluation.md` §6.3): NTLMv2
//! remains a supported per-asset authentication mode, so its security floor
//! MUST be pinned against dependency drift. The guarantees below were
//! verified by reading the vendored sspi sources (0.18.7, then re-verified
//! on 0.21.2 after the IronRDP 0.17 migration), but nothing enforced them at
//! runtime until these tests:
//!
//! 1. **v2-only**: the client only ever emits LMv2/NTLMv2 responses. There
//!    is no NTLMv1/DES code path, and a hostile server stripping every
//!    security flag from its CHALLENGE cannot downgrade the client to v1.
//! 2. **MIC always emitted**: the AUTHENTICATE message carries a non-zero
//!    message integrity check plus the `MsvAvFlags` AV pair advertising it,
//!    and the MIC actually covers the message (flag tampering is detected).
//! 3. **Channel bindings capability**: when a channel-binding token is
//!    supplied, the client stamps the `MsvChannelBindings` AV pair into the
//!    NTLMv2 target info and a server enforcing bindings accepts a matching
//!    token / rejects a mismatched one. NOTE: the RDP CredSSP path does NOT
//!    populate this AV pair today -- the anti-MITM binding to the pinned
//!    TLS key (VAU-001) lives in the CredSSP `pubKeyAuth` exchange -- but
//!    the capability is part of the posture we may rely on (strict EPA).
//! 4. **Negotiate flag posture**: extended session security (NTLMv2 session
//!    security), 128-bit keys, always-sign, sign and seal are negotiated.
//!
//! These tests drive a REAL in-process NTLM handshake (client and server
//! roles of the same sspi crate) through its public API and assert on the
//! raw wire bytes, so a future `cargo update` of sspi that regresses any of
//! the invariants fails here instead of silently weakening the CredSSP leg.
//!
//! Wire layout references: [MS-NLMP] 2.2.1.1 (NEGOTIATE), 2.2.1.2
//! (CHALLENGE), 2.2.1.3 (AUTHENTICATE), 2.2.2.1 (AV_PAIR).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ironrdp::connector::sspi::{
    AuthIdentity, BufferType, ClientRequestFlags, CredentialUse, DataRepresentation, ErrorKind,
    Ntlm, SecurityBuffer, SecurityStatus, ServerRequestFlags, Sspi, SspiImpl, Username,
};

// ==================== [MS-NLMP] constants ====================

const NTLM_SIGNATURE: &[u8] = b"NTLMSSP\0";
const MESSAGE_TYPE_CHALLENGE: u32 = 2;
const MESSAGE_TYPE_AUTHENTICATE: u32 = 3;

const FLAG_UNICODE: u32 = 0x0000_0001;
const FLAG_SIGN: u32 = 0x0000_0010;
const FLAG_SEAL: u32 = 0x0000_0020;
const FLAG_ALWAYS_SIGN: u32 = 0x0000_8000;
const FLAG_EXTENDED_SESSION_SECURITY: u32 = 0x0008_0000;
const FLAG_NEGOTIATE_128: u32 = 0x2000_0000;
const FLAG_KEY_EXCH: u32 = 0x4000_0000;
const FLAG_NEGOTIATE_56: u32 = 0x8000_0000;

const AV_PAIR_EOL: u16 = 0;
const AV_PAIR_FLAGS: u16 = 6;
const AV_PAIR_TIMESTAMP: u16 = 7;
const AV_PAIR_CHANNEL_BINDINGS: u16 = 10;
const MSV_AV_FLAG_MESSAGE_INTEGRITY_CHECK: u32 = 0x0000_0002;

/// AUTHENTICATE fixed part: 64-byte header + 8-byte version + 16-byte MIC.
/// sspi always writes both (MIC is unconditional for NTLMv2).
const AUTH_HEADER_SIZE: usize = 64;
const VERSION_SIZE: usize = 8;
const MIC_SIZE: usize = 16;
const AUTH_PAYLOAD_OFFSET: usize = AUTH_HEADER_SIZE + VERSION_SIZE + MIC_SIZE;

/// NTLMv2 response layout: NTProofStr (16) + RespType (1) + HiRespType (1)
/// + Reserved1 (2) + Reserved2 (4) + Timestamp (8) + ClientChallenge (8)
/// + Reserved3 (4) + TargetInfo (variable).
const NT_V2_TARGET_INFO_OFFSET: usize = 44;
/// An NTLMv1 NTResponse is exactly 24 bytes (three DES blocks); anything
/// strictly longer with the v2 blob markers is an NTLMv2 response.
const NTLM_V1_RESPONSE_SIZE: usize = 24;
/// LMv2 = HMAC-MD5 (16) + client challenge (8).
const LM_V2_RESPONSE_SIZE: usize = 24;

// ==================== wire parsing helpers ====================

fn u16_le(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

fn u32_le(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

/// Read an [MS-NLMP] field descriptor (Len u16, MaxLen u16, Offset u32).
fn read_field(msg: &[u8], off: usize) -> (usize, usize) {
    (u16_le(msg, off) as usize, u32_le(msg, off + 4) as usize)
}

struct ParsedAuthenticate<'a> {
    lm_response: &'a [u8],
    nt_response: &'a [u8],
    negotiate_flags: u32,
    mic: &'a [u8],
}

fn parse_authenticate(msg: &[u8]) -> ParsedAuthenticate<'_> {
    assert_eq!(&msg[0..8], NTLM_SIGNATURE, "AUTHENTICATE signature");
    assert_eq!(
        u32_le(msg, 8),
        MESSAGE_TYPE_AUTHENTICATE,
        "AUTHENTICATE message type"
    );

    let (lm_len, lm_off) = read_field(msg, 12);
    let (nt_len, nt_off) = read_field(msg, 20);
    let (_, domain_off) = read_field(msg, 28);
    let negotiate_flags = u32_le(msg, 60);

    // Validate the fixed-part layout assumption before slicing the MIC:
    // the payload (whose first buffer is the domain name) must start right
    // after header + version + MIC, i.e. the MIC is always present.
    assert_eq!(
        domain_off, AUTH_PAYLOAD_OFFSET,
        "AUTHENTICATE payload must start after the 8-byte version and the \
         16-byte MIC (MIC always emitted for NTLMv2)"
    );
    let mic = &msg[AUTH_PAYLOAD_OFFSET - MIC_SIZE..AUTH_PAYLOAD_OFFSET];

    ParsedAuthenticate {
        lm_response: &msg[lm_off..lm_off + lm_len],
        nt_response: &msg[nt_off..nt_off + nt_len],
        negotiate_flags,
        mic,
    }
}

/// Parse the AV pair list of an NTLMv2 target info blob (stop at EOL).
fn parse_av_pairs(target_info: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let mut pairs = Vec::new();
    let mut i = 0;
    while i + 4 <= target_info.len() {
        let id = u16_le(target_info, i);
        let len = u16_le(target_info, i + 2) as usize;
        let value = target_info[i + 4..i + 4 + len].to_vec();
        pairs.push((id, value));
        i += 4 + len;
        if id == AV_PAIR_EOL {
            break;
        }
    }
    pairs
}

/// Assert the structural NTLMv2-ness of an NTResponse buffer.
fn assert_nt_response_is_v2(nt_response: &[u8]) {
    assert!(
        nt_response.len() > NTLM_V1_RESPONSE_SIZE,
        "NTResponse is {} bytes: an NTLMv1 response is exactly 24 bytes, \
         NTLMv2 carries the variable-length blob (v1 regression!)",
        nt_response.len()
    );
    // Blob starts after the 16-byte NTProofStr: RespType and HiRespType
    // MUST both be 1 for NTLMv2 ([MS-NLMP] 2.2.2.8 NTLMv2_CLIENT_CHALLENGE).
    assert_eq!(nt_response[16], 1, "NTLMv2 blob RespType must be 1");
    assert_eq!(nt_response[17], 1, "NTLMv2 blob HiRespType must be 1");
}

// ==================== handshake driver ====================

fn test_identity() -> AuthIdentity {
    AuthIdentity {
        username: Username::new("vauban-op", Some("VAUBAN")).expect("static test username"),
        password: String::from("correct horse battery staple").into(),
    }
}

/// Build a SEC_CHANNEL_BINDINGS buffer (win32 `SecPkgContext_Bindings`
/// layout) carrying `token` as application data, as consumed by the sspi
/// server via a `BufferType::ChannelBindings` input buffer.
fn sec_channel_bindings_buffer(token: &[u8]) -> Vec<u8> {
    let mut buf = vec![0u8; 32];
    buf[24..28].copy_from_slice(&(token.len() as u32).to_le_bytes());
    buf[28..32].copy_from_slice(&32u32.to_le_bytes());
    buf.extend_from_slice(token);
    buf
}

struct NtlmClient {
    ntlm: Ntlm,
    credentials_handle: <Ntlm as SspiImpl>::CredentialsHandle,
}

impl NtlmClient {
    fn new(identity: &AuthIdentity) -> Self {
        let mut ntlm = Ntlm::new();
        let acq = ntlm
            .acquire_credentials_handle()
            .with_credential_use(CredentialUse::Outbound)
            .with_auth_data(identity)
            .execute(&mut ntlm)
            .expect("client acquire_credentials_handle");
        Self {
            ntlm,
            credentials_handle: acq.credentials_handle,
        }
    }

    /// Drive one `InitializeSecurityContext` round; returns the produced
    /// token (NEGOTIATE on the first call, AUTHENTICATE on the second).
    fn step(&mut self, input_token: Option<Vec<u8>>) -> (SecurityStatus, Vec<u8>) {
        let mut output = vec![SecurityBuffer::new(Vec::new(), BufferType::Token)];
        let mut input = input_token
            .map(|token| vec![SecurityBuffer::new(token, BufferType::Token)])
            .unwrap_or_default();

        // Same context requirements as the sspi CredSSP client
        // (`CredSspClient` in sspi/src/credssp/mod.rs), so the pinned flag
        // posture is the one the RDP NLA leg actually negotiates.
        let mut builder = self
            .ntlm
            .initialize_security_context()
            .with_credentials_handle(&mut self.credentials_handle)
            .with_context_requirements(
                ClientRequestFlags::MUTUAL_AUTH
                    | ClientRequestFlags::USE_SESSION_KEY
                    | ClientRequestFlags::INTEGRITY
                    | ClientRequestFlags::CONFIDENTIALITY,
            )
            .with_target_data_representation(DataRepresentation::Native)
            .with_target_name("TERMSRV/target.vauban.example")
            .with_input(&mut input)
            .with_output(&mut output);

        let result = self
            .ntlm
            .initialize_security_context_impl(&mut builder)
            .expect("client initialize_security_context builder")
            .resolve_to_result()
            .expect("NTLM never suspends on the network client");
        (result.status, output.remove(0).buffer)
    }
}

struct NtlmServer {
    ntlm: Ntlm,
    credentials_handle: <Ntlm as SspiImpl>::CredentialsHandle,
}

impl NtlmServer {
    fn new(identity: &AuthIdentity) -> Self {
        let mut ntlm = Ntlm::new();
        let acq = ntlm
            .acquire_credentials_handle()
            .with_credential_use(CredentialUse::Inbound)
            .with_auth_data(identity)
            .execute(&mut ntlm)
            .expect("server acquire_credentials_handle");
        Self {
            ntlm,
            credentials_handle: acq.credentials_handle,
        }
    }

    /// Drive one `AcceptSecurityContext` round. `channel_bindings` is the
    /// optional SEC_CHANNEL_BINDINGS buffer the server enforces.
    fn step(
        &mut self,
        input_token: Vec<u8>,
        channel_bindings: Option<Vec<u8>>,
    ) -> Result<(SecurityStatus, Vec<u8>), ironrdp::connector::sspi::Error> {
        let mut input = vec![SecurityBuffer::new(input_token, BufferType::Token)];
        if let Some(bindings) = channel_bindings {
            input.push(SecurityBuffer::new(bindings, BufferType::ChannelBindings));
        }
        let mut output = vec![SecurityBuffer::new(Vec::new(), BufferType::Token)];

        let builder = self
            .ntlm
            .accept_security_context()
            .with_credentials_handle(&mut self.credentials_handle)
            .with_context_requirements(ServerRequestFlags::ALLOCATE_MEMORY)
            .with_target_data_representation(DataRepresentation::Native)
            .with_input(&mut input)
            .with_output(&mut output);

        let result = self
            .ntlm
            .accept_security_context_impl(builder)?
            .resolve_to_result()?;
        Ok((result.status, output.remove(0).buffer))
    }

    /// Finalize authentication: recompute the NTLMv2 response server-side
    /// and verify the MIC. Errors if no candidate credential matches.
    fn complete(&mut self) -> Result<SecurityStatus, ironrdp::connector::sspi::Error> {
        self.ntlm.complete_auth_token(&mut [])
    }
}

/// Run the full NEGOTIATE -> CHALLENGE -> AUTHENTICATE handshake and return
/// `(negotiate_msg, authenticate_msg, server)` for post-hoc assertions.
fn run_handshake(
    client_channel_binding_token: Option<&[u8]>,
    server_channel_binding_token: Option<&[u8]>,
) -> (Vec<u8>, Vec<u8>, NtlmServer) {
    let identity = test_identity();
    let mut client = NtlmClient::new(&identity);
    let mut server = NtlmServer::new(&identity);

    if let Some(token) = client_channel_binding_token {
        client.ntlm.set_channel_bindings(token);
    }

    let (status, negotiate_msg) = client.step(None);
    assert_eq!(status, SecurityStatus::ContinueNeeded, "client NEGOTIATE");

    let (status, challenge_msg) = server
        .step(negotiate_msg.clone(), None)
        .expect("server CHALLENGE step");
    assert_eq!(status, SecurityStatus::ContinueNeeded, "server CHALLENGE");

    let (status, authenticate_msg) = client.step(Some(challenge_msg));
    assert_eq!(status, SecurityStatus::Ok, "client AUTHENTICATE");

    let bindings = server_channel_binding_token.map(sec_channel_bindings_buffer);
    let (status, _) = server
        .step(authenticate_msg.clone(), bindings)
        .expect("server AUTHENTICATE step");
    assert_eq!(
        status,
        SecurityStatus::CompleteNeeded,
        "server AUTHENTICATE"
    );

    (negotiate_msg, authenticate_msg, server)
}

// ==================== pin tests ====================

/// Invariant 1: the client only computes LMv2/NTLMv2 responses, and the
/// server side (which recomputes the NTLMv2 proof and checks the MIC over
/// the exact wire bytes) accepts the exchange end to end.
#[test]
fn ntlm_client_emits_only_ntlm_v2_and_server_verifies_it() {
    let (_, authenticate_msg, mut server) = run_handshake(None, None);
    let auth = parse_authenticate(&authenticate_msg);

    assert_nt_response_is_v2(auth.nt_response);
    assert_eq!(
        auth.lm_response.len(),
        LM_V2_RESPONSE_SIZE,
        "LmChallengeResponse must be an LMv2 response (HMAC-MD5 + client challenge)"
    );

    // The strongest v2 pin: the server recomputes the NTLMv2 proof from the
    // password and verifies the MIC. Any v1 regression fails right here.
    let status = server
        .complete()
        .expect("server-side NTLMv2 + MIC verification must succeed");
    assert_eq!(status, SecurityStatus::Ok);
}

/// Invariant 2a: the MIC is always emitted (non-zero bytes in the reserved
/// slot) and advertised via the MsvAvFlags AV pair of the target info.
#[test]
fn ntlm_authenticate_always_carries_a_mic() {
    let (_, authenticate_msg, _) = run_handshake(None, None);
    let auth = parse_authenticate(&authenticate_msg);

    assert!(
        auth.mic.iter().any(|&b| b != 0),
        "the 16-byte MIC slot must be populated (all-zero means no MIC)"
    );

    let av_pairs = parse_av_pairs(&auth.nt_response[NT_V2_TARGET_INFO_OFFSET..]);
    let (_, flags_value) = av_pairs
        .iter()
        .find(|(id, _)| *id == AV_PAIR_FLAGS)
        .expect("MsvAvFlags AV pair must be present in the NTLMv2 target info");
    let av_flags = u32_le(flags_value, 0);
    assert_ne!(
        av_flags & MSV_AV_FLAG_MESSAGE_INTEGRITY_CHECK,
        0,
        "MsvAvFlags must advertise MESSAGE_INTEGRITY_CHECK"
    );
}

/// Invariant 2b: the MIC actually covers the message. Tampering with one
/// negotiate-flag bit of the AUTHENTICATE message must be detected by the
/// server-side MIC verification (this is the anti-flag-tampering property
/// the audit relies on).
#[test]
fn ntlm_mic_detects_flag_tampering() {
    let identity = test_identity();
    let mut client = NtlmClient::new(&identity);
    let mut server = NtlmServer::new(&identity);

    let (_, negotiate_msg) = client.step(None);
    let (_, challenge_msg) = server
        .step(negotiate_msg, None)
        .expect("server CHALLENGE step");
    let (_, mut authenticate_msg) = client.step(Some(challenge_msg));

    // Flip the UNICODE bit of the AUTHENTICATE NegotiateFlags (offset 60).
    authenticate_msg[60] ^= (FLAG_UNICODE & 0xFF) as u8;

    let (status, _) = server
        .step(authenticate_msg, None)
        .expect("parsing the tampered message still succeeds");
    assert_eq!(status, SecurityStatus::CompleteNeeded);

    assert!(
        server.complete().is_err(),
        "the MIC check must reject an AUTHENTICATE message whose negotiate \
         flags were tampered with in transit"
    );
}

/// Invariant 4a: NEGOTIATE advertises the strong-security flag set
/// (NTLMv2 session security, 128-bit, sign, seal, key exchange).
#[test]
fn ntlm_negotiate_flags_request_strong_security() {
    let (negotiate_msg, _, _) = run_handshake(None, None);
    assert_eq!(&negotiate_msg[0..8], NTLM_SIGNATURE);
    let flags = u32_le(&negotiate_msg, 12);

    for (bit, name) in [
        (FLAG_EXTENDED_SESSION_SECURITY, "EXTENDED_SESSION_SECURITY"),
        (FLAG_NEGOTIATE_128, "NEGOTIATE128"),
        (FLAG_NEGOTIATE_56, "NEGOTIATE56"),
        (FLAG_KEY_EXCH, "KEY_EXCH"),
        (FLAG_ALWAYS_SIGN, "ALWAYS_SIGN"),
        (FLAG_SIGN, "SIGN"),
        (FLAG_SEAL, "SEAL"),
        (FLAG_UNICODE, "UNICODE"),
    ] {
        assert_ne!(
            flags & bit,
            0,
            "NEGOTIATE must request NTLM_SSP_NEGOTIATE_{name} (flags = {flags:#010x})"
        );
    }
}

/// Invariant 4b: the final AUTHENTICATE keeps the strong-security flags.
#[test]
fn ntlm_authenticate_flags_keep_strong_security() {
    let (_, authenticate_msg, _) = run_handshake(None, None);
    let auth = parse_authenticate(&authenticate_msg);

    for (bit, name) in [
        (FLAG_EXTENDED_SESSION_SECURITY, "EXTENDED_SESSION_SECURITY"),
        (FLAG_NEGOTIATE_128, "NEGOTIATE128"),
        (FLAG_ALWAYS_SIGN, "ALWAYS_SIGN"),
        (FLAG_SIGN, "SIGN"),
        (FLAG_SEAL, "SEAL"),
    ] {
        assert_ne!(
            auth.negotiate_flags & bit,
            0,
            "AUTHENTICATE must keep NTLM_SSP_NEGOTIATE_{name} (flags = {:#010x})",
            auth.negotiate_flags
        );
    }
}

/// Invariant 1 (adversarial): a hostile server that strips EVERY security
/// flag from its CHALLENGE cannot downgrade the client to NTLMv1. The
/// client must still emit an NTLMv2 response with a MIC.
#[test]
fn ntlm_client_refuses_v1_downgrade_against_hostile_server() {
    let identity = test_identity();
    let mut client = NtlmClient::new(&identity);

    let (status, _) = client.step(None);
    assert_eq!(status, SecurityStatus::ContinueNeeded);

    let hostile_challenge = craft_challenge_with_flags(FLAG_UNICODE);
    let (status, authenticate_msg) = client.step(Some(hostile_challenge));
    assert_eq!(status, SecurityStatus::Ok);

    let auth = parse_authenticate(&authenticate_msg);
    assert_nt_response_is_v2(auth.nt_response);
    assert_eq!(auth.lm_response.len(), LM_V2_RESPONSE_SIZE);
    assert!(
        auth.mic.iter().any(|&b| b != 0),
        "MIC must be emitted even against a hostile zero-flag server"
    );
    assert_ne!(
        auth.negotiate_flags & FLAG_EXTENDED_SESSION_SECURITY,
        0,
        "the client must not drop extended session security on server demand"
    );
}

/// Craft a minimal [MS-NLMP] CHALLENGE message with attacker-chosen
/// negotiate flags (no version block: the VERSION flag is not set).
fn craft_challenge_with_flags(flags: u32) -> Vec<u8> {
    const HEADER_SIZE: u32 = 48;

    // Target info: a Timestamp AV pair + EOL.
    let mut target_info = Vec::new();
    target_info.extend_from_slice(&AV_PAIR_TIMESTAMP.to_le_bytes());
    target_info.extend_from_slice(&8u16.to_le_bytes());
    target_info.extend_from_slice(&0u64.to_le_bytes());
    target_info.extend_from_slice(&AV_PAIR_EOL.to_le_bytes());
    target_info.extend_from_slice(&0u16.to_le_bytes());

    let mut msg = Vec::new();
    msg.extend_from_slice(NTLM_SIGNATURE);
    msg.extend_from_slice(&MESSAGE_TYPE_CHALLENGE.to_le_bytes());
    // TargetNameFields: empty, payload starts right after the header.
    msg.extend_from_slice(&0u16.to_le_bytes());
    msg.extend_from_slice(&0u16.to_le_bytes());
    msg.extend_from_slice(&HEADER_SIZE.to_le_bytes());
    msg.extend_from_slice(&flags.to_le_bytes());
    msg.extend_from_slice(&[0x5A; 8]); // server challenge
    msg.extend_from_slice(&0u64.to_le_bytes()); // reserved
    // TargetInfoFields
    msg.extend_from_slice(&(target_info.len() as u16).to_le_bytes());
    msg.extend_from_slice(&(target_info.len() as u16).to_le_bytes());
    msg.extend_from_slice(&HEADER_SIZE.to_le_bytes());
    debug_assert_eq!(msg.len(), HEADER_SIZE as usize);
    msg.extend_from_slice(&target_info);
    msg
}

/// Invariant 3a: a caller-supplied channel-binding token is stamped into
/// the NTLMv2 target info as the MsvChannelBindings AV pair (16-byte MD5),
/// and a server enforcing the SAME token completes the authentication.
#[test]
fn ntlm_channel_bindings_av_pair_is_emitted_and_accepted_on_match() {
    let token = b"tls-server-end-point:vauban-test-token";
    let (_, authenticate_msg, mut server) = run_handshake(Some(token), Some(token));

    let auth = parse_authenticate(&authenticate_msg);
    let av_pairs = parse_av_pairs(&auth.nt_response[NT_V2_TARGET_INFO_OFFSET..]);
    let (_, cbt_value) = av_pairs
        .iter()
        .find(|(id, _)| *id == AV_PAIR_CHANNEL_BINDINGS)
        .expect("MsvChannelBindings AV pair must be present when bindings are set");
    assert_eq!(
        cbt_value.len(),
        16,
        "MsvChannelBindings value must be the 16-byte MD5 of SEC_CHANNEL_BINDINGS"
    );

    let status = server
        .complete()
        .expect("matching channel bindings must authenticate");
    assert_eq!(status, SecurityStatus::Ok);
}

/// Invariant 3b: a server enforcing DIFFERENT channel bindings rejects the
/// exchange with a bindings error (fail closed, relay detection).
#[test]
fn ntlm_channel_bindings_mismatch_is_rejected() {
    let identity = test_identity();
    let mut client = NtlmClient::new(&identity);
    let mut server = NtlmServer::new(&identity);

    client
        .ntlm
        .set_channel_bindings(b"tls-server-end-point:the-real-server");

    let (_, negotiate_msg) = client.step(None);
    let (_, challenge_msg) = server
        .step(negotiate_msg, None)
        .expect("server CHALLENGE step");
    let (_, authenticate_msg) = client.step(Some(challenge_msg));

    let mismatched = sec_channel_bindings_buffer(b"tls-server-end-point:a-relay-target");
    let error = server
        .step(authenticate_msg, Some(mismatched))
        .expect_err("mismatched channel bindings must be rejected");
    assert_eq!(
        error.error_type,
        ErrorKind::BadBindings,
        "the rejection must be a channel-bindings error, got: {error}"
    );
}
