//! Source invariants for the RDP auth-mode profile table.
//!
//! Behavioral coverage lives in `session.rs` unit tests
//! (`test_auth_mode_profile_table`,
//! `attack_ntlm_downgrade_in_kerberos_mode_is_rejected`; the binary crate
//! has no `lib` target). This file pins that the table is the ONLY place
//! where a mode is turned into a wire posture.

#![allow(clippy::expect_used)]

const SESSION: &str = include_str!("../src/session.rs");

/// Production part of `session.rs` (everything before the test module).
fn production() -> &'static str {
    let end = SESSION
        .find("#[cfg(test)]\nmod tests")
        .expect("session.rs test module");
    &SESSION[..end]
}

/// The body of `auth_mode_profile`.
fn table() -> &'static str {
    let prod = production();
    let start = prod
        .find("pub const fn auth_mode_profile(mode: RdpAuthMode) -> AuthModeProfile {")
        .expect("auth_mode_profile");
    let end = prod[start..].find("\n}\n").expect("end of the table");
    &prod[start..start + end]
}

/// Modes are matched in one place. A second `match` on the mode would be
/// a second definition of what a mode means, free to drift from the table.
#[test]
fn the_profile_table_is_the_only_match_on_the_mode() {
    let prod = production();
    for variant in ["Ntlm", "KerberosRestrictedAdmin", "Kerberos"] {
        let arm = format!("RdpAuthMode::{variant} =>");
        assert_eq!(
            prod.matches(&arm).count(),
            1,
            "`{arm}` must appear once in production code: in the table"
        );
        assert!(table().contains(&arm), "`{arm}` must be a row of the table");
    }
}

/// The table has no wildcard arm: a fourth mode does not compile until
/// it states its posture.
#[test]
fn the_profile_table_has_no_wildcard_arm() {
    let table = table();
    assert!(!table.contains("_ =>"), "no wildcard arm in the table");
    assert_eq!(
        table.matches("AuthModeProfile {").count(),
        // The return type, then one literal per mode.
        4,
        "one profile literal per mode"
    );
}

/// The three mode-dependent sites read the table.
#[test]
fn every_mode_dependent_site_reads_the_table() {
    let prod = production();
    for needle in [
        "if auth_mode_profile(config.auth_mode).restricted_admin {",
        "if !auth_mode_profile(auth_mode).kerberos {",
        "let profile = auth_mode_profile(auth_mode);",
    ] {
        assert_eq!(prod.matches(needle).count(), 1, "missing site: {needle}");
    }
}

/// NTLM is reachable from one production site, and both Kerberos modes
/// share one Kerberos-only package list.
#[test]
fn ntlm_has_a_single_production_site() {
    let prod = production();
    assert_eq!(
        prod.matches("ClientMode::Ntlm(").count(),
        1,
        "one NTLM client mode"
    );
    assert_eq!(
        prod.matches("Self::NtlmOnly(NtlmOnlyNetworkClient)")
            .count(),
        1,
        "one NTLM network client"
    );
    assert!(prod.contains("const KERBEROS_ONLY_PACKAGE_LIST: &str = \"kerberos\";"));
    assert_eq!(
        prod.matches("package_list: Some(").count(),
        1,
        "one package list for every Kerberos mode"
    );
}
