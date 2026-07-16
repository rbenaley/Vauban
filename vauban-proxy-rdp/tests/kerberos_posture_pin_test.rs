//! Behavioral pin tests for the Kerberos / Restricted Admin security
//! posture of the CredSSP leg (phase A).
//!
//! Twin of `ntlm_posture_pin_test.rs`. Where the NTLM tests pin the NTLMv2
//! floor, these pin the two properties Restricted Admin relies on, driven
//! through the `sspi 0.21` PUBLIC API so a `cargo update` that regresses
//! either one fails here instead of silently weakening the proxy:
//!
//! 1. **Credential-less TSCredentials**: in `CredSspMode::CredentialLess`
//!    the `TSCredentials` structure sent AFTER the `pubKeyAuth` exchange
//!    carries an EMPTY identity -- the password bytes never appear on the
//!    wire, for ANY username/password (proptest). This is what makes
//!    "Restricted Admin" restricted: the target never receives delegable
//!    credentials. `WithCredentials` (the NTLM path) is the control and
//!    MUST still embed the password.
//! 2. **Password confined to pre-auth**: the same password, encoded as the
//!    TSCredentials would encode it (UTF-16LE), is present under
//!    `WithCredentials` and absent under `CredentialLess`.
//!
//! Wire references: [MS-CSSP] 2.2.1.2 (TSCredentials), 2.2.1.2.1
//! (TSPasswordCreds).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ironrdp::connector::sspi::credssp::{CredSspMode, write_ts_credentials};
use ironrdp::connector::sspi::{AuthIdentity, AuthIdentityBuffers, CredentialsBuffers, Username};
use proptest::prelude::*;

/// UTF-16LE encoding of `s`, the way TSPasswordCreds encodes its OCTET
/// STRING fields; used to search for password bytes in the DER output.
fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn credentials_for(user: &str, domain: Option<&str>, password: &str) -> CredentialsBuffers {
    let identity = AuthIdentity {
        username: Username::new(user, domain).expect("valid username"),
        password: String::from(password).into(),
    };
    let buffers: AuthIdentityBuffers = identity.into();
    CredentialsBuffers::AuthIdentity(buffers)
}

/// Invariant 1: `CredentialLess` produces TSCredentials whose TSPasswordCreds
/// carry an empty username/domain/password. We assert this structurally by
/// comparing against the encoding of an EMPTY identity: the credential-less
/// output for a populated identity must be byte-identical to the output for
/// an empty identity (the credentials are dropped entirely).
#[test]
fn credentialless_ts_credentials_are_identity_free() {
    let populated = credentials_for("Administrator", Some("CORP"), "S3cr3t-P@ss!");
    let empty = CredentialsBuffers::AuthIdentity(AuthIdentityBuffers::default());

    let cl_populated =
        write_ts_credentials(&populated, CredSspMode::CredentialLess).expect("encode populated");
    let cl_empty = write_ts_credentials(&empty, CredSspMode::CredentialLess).expect("encode empty");

    assert_eq!(
        cl_populated, cl_empty,
        "CredentialLess must drop the identity: a populated credential must \
         encode identically to an empty one"
    );
}

/// Invariant 1 (control): `WithCredentials` embeds the real identity, so the
/// populated and empty encodings MUST differ (otherwise the test above would
/// be vacuous).
#[test]
fn with_credentials_ts_credentials_embed_the_identity() {
    let populated = credentials_for("Administrator", Some("CORP"), "S3cr3t-P@ss!");
    let empty = CredentialsBuffers::AuthIdentity(AuthIdentityBuffers::default());

    let wc_populated =
        write_ts_credentials(&populated, CredSspMode::WithCredentials).expect("encode populated");
    let wc_empty =
        write_ts_credentials(&empty, CredSspMode::WithCredentials).expect("encode empty");

    assert_ne!(
        wc_populated, wc_empty,
        "WithCredentials must embed the identity (control for the \
         CredentialLess invariant)"
    );
}

proptest! {
    /// Invariant 2: for ANY username/password, the CredentialLess encoding
    /// never contains the UTF-16LE password bytes, while the WithCredentials
    /// encoding does. This is the load-bearing Restricted Admin guarantee:
    /// the password stays confined to the in-memory AS-REQ pre-auth and is
    /// never delegated to the target.
    #[test]
    fn password_never_leaks_in_credentialless_encoding(
        user in "[A-Za-z0-9._-]{1,32}",
        password in "[A-Za-z0-9!@#$%^&*()_+=-]{4,48}",
    ) {
        let creds = credentials_for(&user, Some("CORP"), &password);
        let pw_bytes = utf16le(&password);

        let credentialless =
            write_ts_credentials(&creds, CredSspMode::CredentialLess).expect("encode");
        let with_credentials =
            write_ts_credentials(&creds, CredSspMode::WithCredentials).expect("encode");

        prop_assert!(
            !contains_subslice(&credentialless, &pw_bytes),
            "CredentialLess encoding must NOT contain the password bytes"
        );
        prop_assert!(
            contains_subslice(&with_credentials, &pw_bytes),
            "WithCredentials encoding MUST contain the password bytes (control)"
        );
    }
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}
