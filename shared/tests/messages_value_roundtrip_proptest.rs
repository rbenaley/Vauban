//! Value round-trip proptest for small PartialEq IPC types.
//!
//! Does NOT fuzz frozen bincode discriminant indices (see unit pins in
//! `shared/src/messages.rs`).

#![allow(clippy::expect_used, clippy::unwrap_used)]

use proptest::prelude::*;
use shared::messages::{
    AuditEventType, IpcPageParams, LdapBindAndSearchOutcome, LdapBindOutcome, Service,
};

fn encode<T: serde::Serialize>(value: &T) -> Vec<u8> {
    bincode::serde::encode_to_vec(value, bincode::config::standard()).expect("encode")
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> T {
    bincode::serde::decode_from_slice(bytes, bincode::config::standard())
        .expect("decode")
        .0
}

fn services() -> impl Strategy<Value = Service> {
    prop_oneof![
        Just(Service::Supervisor),
        Just(Service::Web),
        Just(Service::Auth),
        Just(Service::Access),
        Just(Service::Vault),
        Just(Service::Audit),
        Just(Service::ProxySsh),
        Just(Service::ProxyRdp),
        Just(Service::ProxyIacs),
        Just(Service::Mailer),
    ]
}

fn ldap_outcomes() -> impl Strategy<Value = LdapBindOutcome> {
    prop_oneof![
        Just(LdapBindOutcome::Success),
        Just(LdapBindOutcome::InvalidCredentials),
        Just(LdapBindOutcome::Unreachable),
        Just(LdapBindOutcome::TlsError),
    ]
}

fn ldap_bind_and_search_outcomes() -> impl Strategy<Value = LdapBindAndSearchOutcome> {
    prop_oneof![
        Just(LdapBindAndSearchOutcome::BindInvalidCredentials),
        Just(LdapBindAndSearchOutcome::BindUnreachable),
        Just(LdapBindAndSearchOutcome::BindTlsError),
        Just(LdapBindAndSearchOutcome::Complete),
        Just(LdapBindAndSearchOutcome::IncompleteNotFound),
        Just(LdapBindAndSearchOutcome::IncompleteUnreachable),
    ]
}

fn audit_events() -> impl Strategy<Value = AuditEventType> {
    // Representative sample — discriminant pins stay in unit tests.
    prop_oneof![
        Just(AuditEventType::AuthSuccess),
        Just(AuditEventType::AuthFailure),
        Just(AuditEventType::Logout),
        Just(AuditEventType::SessionStart),
        Just(AuditEventType::SessionEnd),
        Just(AuditEventType::AccessDenied),
        Just(AuditEventType::PolicyChange),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn service_value_roundtrip(s in services()) {
        let bytes = encode(&s);
        let back: Service = decode(&bytes);
        prop_assert_eq!(back, s);
    }

    #[test]
    fn ldap_bind_outcome_value_roundtrip(o in ldap_outcomes()) {
        let bytes = encode(&o);
        let back: LdapBindOutcome = decode(&bytes);
        prop_assert_eq!(back, o);
    }

    #[test]
    fn ldap_bind_and_search_outcome_value_roundtrip(o in ldap_bind_and_search_outcomes()) {
        let bytes = encode(&o);
        let back: LdapBindAndSearchOutcome = decode(&bytes);
        prop_assert_eq!(back, o);
    }

    #[test]
    fn ipc_page_params_value_roundtrip(
        limit in any::<u32>(),
        offset in any::<u32>(),
    ) {
        let page = IpcPageParams { limit, offset };
        let bytes = encode(&page);
        let back: IpcPageParams = decode(&bytes);
        prop_assert_eq!(back, page);
    }

    #[test]
    fn audit_event_type_value_roundtrip(e in audit_events()) {
        let bytes = encode(&e);
        let back: AuditEventType = decode(&bytes);
        prop_assert_eq!(back, e);
    }
}
