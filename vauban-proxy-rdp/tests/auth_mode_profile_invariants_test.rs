//! Source invariants for the RDP auth-mode profile table.
//!
//! Behavioral coverage lives in `session.rs` unit tests
//! (`test_auth_mode_profile_table`,
//! `attack_ntlm_downgrade_in_kerberos_mode_is_rejected`; the binary crate
//! has no `lib` target). This file pins that the table is the ONLY place
//! where a mode is turned into a wire posture.

#![allow(clippy::expect_used)]

const SESSION: &str = include_str!("../src/session.rs");
const MAIN: &str = include_str!("../src/main.rs");
const REMOTE_GUARD: &str = include_str!("../src/remote_guard.rs");

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
    for variant in [
        "Ntlm",
        "KerberosRestrictedAdmin",
        "Kerberos",
        "KerberosRemoteGuard",
    ] {
        let arm = format!("RdpAuthMode::{variant} =>");
        assert_eq!(
            prod.matches(&arm).count(),
            1,
            "`{arm}` must appear once in production code: in the table"
        );
        assert!(table().contains(&arm), "`{arm}` must be a row of the table");
    }
}

/// The table has no wildcard arm: a new mode does not compile until it
/// states its posture.
#[test]
fn the_profile_table_has_no_wildcard_arm() {
    let table = table();
    assert!(!table.contains("_ =>"), "no wildcard arm in the table");
    assert_eq!(
        table.matches("AuthModeProfile {").count(),
        // The return type, then one literal per mode.
        5,
        "one profile literal per mode"
    );
}

/// The mode-dependent sites read the table.
#[test]
fn every_mode_dependent_site_reads_the_table() {
    let prod = production();
    for needle in [
        "let extra_nego_flags = auth_mode_profile(config.auth_mode).request_flags();",
        "auth_mode_profile(mode).required_response_flag()",
        "if auth_mode_profile(auth_mode).keeps_password_in_proxy() {",
        "if !auth_mode_profile(auth_mode).kerberos {",
        "let profile = auth_mode_profile(auth_mode);",
        "let credssp_mode = profile.credssp_mode();",
        "if auth_mode_profile(config.auth_mode).remote_guard() {",
        "if auth_mode_profile(auth_mode).remote_guard() {",
    ] {
        assert_eq!(prod.matches(needle).count(), 1, "missing site: {needle}");
    }
}

/// What the target receives is one value, and every wire consequence is
/// a `match` on it inside the profile. No production site outside the
/// profile names a negotiation flag or a CredSSP mode.
#[test]
fn wire_postures_are_named_in_the_profile_only() {
    let prod = production();
    let start = prod.find("impl AuthModeProfile {").expect("impl");
    let end = start
        + prod[start..]
            .find("\npub const fn auth_mode_profile(")
            .expect("end of the profile");
    let outside = format!("{}{}", &prod[..start], &prod[end..]);
    for needle in [
        "RequestFlags::RESTRICTED_ADMIN_MODE_REQUIRED",
        "RequestFlags::REDIRECTED_AUTHENTICATION_MODE_REQUIRED",
        "ResponseFlags::RESTRICTED_ADMIN_MODE_SUPPORTED",
        "ResponseFlags::REDIRECTED_AUTHENTICATION_MODE_SUPPORTED",
        "CredSspMode::WithCredentials",
        "CredSspMode::CredentialLess",
        "CredSspMode::RemoteGuard",
    ] {
        assert_eq!(
            prod[start..end].matches(needle).count(),
            1,
            "`{needle}` must appear once, in the profile"
        );
        assert!(
            !outside.contains(needle),
            "`{needle}` must not be chosen outside the profile"
        );
    }
}

/// Remote Credential Guard never reaches NTLM. The CredSSP client is
/// never given an NTLM supplemental credential, the connector is never
/// put in its own Remote Credential Guard mode (which would run CredSSP
/// with its own package list), and the policy context says NTLM is
/// unavailable, whatever the policy.
#[test]
fn remote_guard_never_enables_redirected_ntlm() {
    for (name, source) in [
        ("session.rs", production()),
        ("main.rs", MAIN),
        ("remote_guard.rs", REMOTE_GUARD),
    ] {
        for forbidden in [
            ".enable_remote_guard_ntlm(",
            "with_remote_guard_ntlm",
            ".with_remote_guard(",
            "NtlmRedirectionNames",
        ] {
            assert!(
                !source.contains(forbidden),
                "`{forbidden}` in {name} would give the target a redirected NTLM"
            );
        }
    }
    let start = REMOTE_GUARD
        .find("fn ntlm_available(&self) -> bool {")
        .expect("ntlm_available");
    let body = &REMOTE_GUARD[start..start + REMOTE_GUARD[start..].find("\n    }\n").expect("end")];
    assert!(body.trim_end().ends_with("false"), "ntlm_available: {body}");
    assert!(
        !body.contains("self.policy"),
        "NTLM does not depend on the policy"
    );
}

/// The Remote Credential Guard session leaves the CredSSP exchange at
/// one site, after the target accepted the logon, and goes behind the
/// policy context: no production path hands the raw `sspi` session to
/// the channel.
#[test]
fn the_remote_guard_session_only_exists_behind_the_policy() {
    let prod = production();
    assert_eq!(prod.matches(".take_remote_guard_session()").count(), 1);
    assert_eq!(
        prod.matches("crate::remote_guard::PolicyContext::new(")
            .count(),
        1
    );
    assert_eq!(prod.matches(".attach_dynamic_channel(").count(), 1);
    assert_eq!(prod.matches("remote_guard::Backend {").count(), 1);
    let attach = prod
        .find("fn attach_remote_guard_channel(")
        .expect("attach_remote_guard_channel");
    let body = &prod[attach..attach + prod[attach..].find("\n}\n").expect("end")];
    let take = body.find(".take_remote_guard_session()").expect("take");
    let policy = body
        .find("crate::remote_guard::PolicyContext::new(")
        .expect("policy");
    let backend = body.find("context: Some(context),").expect("backend");
    let attached = body.find(".attach_dynamic_channel(").expect("attach");
    assert!(take < policy && policy < backend && backend < attached);
    // The carrier is bounded before anything is attached to it.
    let bounded = body
        .find("::max_message_size(drdynvc)")
        .expect("bound check");
    assert!(bounded < attached);
    // The call site runs after the CredSSP loop, before the connector
    // is told that CredSSP is done.
    let step = prod.find("async fn perform_credssp_step").expect("step");
    let call = step
        + prod[step..]
            .find("attach_remote_guard_channel(connector, &mut sequence, nla)?;")
            .expect("call");
    let done = step
        + prod[step..]
            .find("connector.mark_credssp_as_done();")
            .expect("done");
    assert!(call < done);
}

/// The outbound-identity policy comes from the supervisor-provided
/// environment, a value that is not canonical stops the proxy, the unset
/// state denies, and the policy context is the only code that reads it.
#[test]
fn the_remote_guard_policy_is_read_once_and_fails_closed() {
    assert!(MAIN.contains("std::env::var_os(RemoteGuardOutboundIdentity::ENV)"));
    assert!(MAIN.contains("RemoteGuardOutboundIdentity::from_env_value("));
    assert!(MAIN.contains(
        ".map_err(|e| anyhow::anyhow!(e))?;\n    let _ = REMOTE_GUARD_OUTBOUND_IDENTITY.set(remote_guard_policy);"
    ));
    assert!(MAIN.contains("std::env::remove_var(RemoteGuardOutboundIdentity::ENV);"));
    assert!(MAIN.contains(".unwrap_or(RemoteGuardOutboundIdentity::Deny)"));
    assert!(!MAIN.contains(".unwrap_or(RemoteGuardOutboundIdentity::Allow)"));
    assert_eq!(
        MAIN.matches("remote_guard_outbound_identity: remote_guard_outbound_identity(),")
            .count(),
        1,
        "one site hands the process policy to a session"
    );
    assert_eq!(
        REMOTE_GUARD.matches(".grants_outbound_identity()").count(),
        1,
        "one decision site in the policy context"
    );
    assert!(
        !production().contains(".grants_outbound_identity()"),
        "session.rs carries the policy, it does not decide"
    );
}

/// Nothing a redirected request carries reaches a log call, except the
/// operation name and the service name, which go through the reducer.
#[test]
fn remote_guard_logs_no_request_argument() {
    let end = REMOTE_GUARD.find("#[cfg(test)]").expect("test module");
    let prod = &REMOTE_GUARD[..end];
    for forbidden in [
        "?request",
        "%request",
        "?response",
        "?token",
        "?plaintext",
        "{request:?}",
    ] {
        assert!(
            !prod.contains(forbidden),
            "`{forbidden}` would log key material"
        );
    }
    // Both name readers return through the reducer.
    assert_eq!(prod.matches("Some(principal_text(").count(), 2);
    assert!(prod.contains("    loggable_service(&joined)\n}"));
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
