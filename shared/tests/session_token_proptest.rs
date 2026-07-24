//! Property tests for SessionToken mint / serialize / verify.
//!
//! Does not cover ReplayCache (see `session_token/replay_cache.rs` proptest).

#![allow(clippy::expect_used, clippy::unwrap_used)]

use proptest::prelude::*;
use shared::messages::Service;
use shared::session_token::{
    SessionToken, SessionTokenParams, TokenError, TokenKey, Verifier, token_ttl_for,
};

fn services() -> impl Strategy<Value = Service> {
    prop_oneof![
        Just(Service::ProxySsh),
        Just(Service::ProxyRdp),
        Just(Service::ProxyIacs),
        Just(Service::Mailer),
        Just(Service::Web),
    ]
}

fn params_strategy() -> impl Strategy<Value = SessionTokenParams> {
    (
        "[A-Za-z0-9_-]{8,36}",
        "[A-Za-z0-9_-]{8,36}",
        "[A-Za-z0-9_-]{8,36}",
        prop_oneof![Just("ssh"), Just("rdp"), Just("iacs_tunnel")],
        "[a-z0-9.-]{3,32}",
        1u16..=65535u16,
        services(),
    )
        .prop_map(
            |(session_id, user_uuid, asset_uuid, protocol, host, port, target_service)| {
                SessionTokenParams {
                    session_id,
                    user_uuid,
                    asset_uuid,
                    protocol: protocol.to_string(),
                    host,
                    port,
                    target_service,
                }
            },
        )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Mint → to_bytes → verify_bytes succeeds for a matching Supervisor view.
    #[test]
    fn mint_verify_roundtrip_bytes(
        params in params_strategy(),
        now in 1_700_000_000u64..1_900_000_000u64,
    ) {
        let key = TokenKey::generate();
        let token = SessionToken::mint(&key, now, params.clone());
        let bytes = token.to_bytes().expect("serialize");
        let verifier = Verifier::Supervisor {
            host: params.host.clone(),
            port: params.port,
            target_service: params.target_service.as_token_discriminant(),
            session_id: params.session_id.clone(),
        };
        let back = SessionToken::verify_bytes(&bytes, &key, now, &verifier)
            .expect("verify");
        prop_assert_eq!(back.session_id, params.session_id);
        prop_assert_eq!(back.host, params.host);
        prop_assert_eq!(back.port, params.port);
        prop_assert_eq!(
            back.expires_at,
            now.saturating_add(token_ttl_for(params.target_service))
        );
    }

    /// A different key always yields MacMismatch (after successful deserialize).
    #[test]
    fn wrong_key_always_mac_mismatch(
        params in params_strategy(),
        now in 1_700_000_000u64..1_900_000_000u64,
    ) {
        let key = TokenKey::generate();
        let other = TokenKey::generate();
        let token = SessionToken::mint(&key, now, params.clone());
        let bytes = token.to_bytes().expect("serialize");
        let verifier = Verifier::Proxy {
            user_uuid: params.user_uuid.clone(),
            asset_uuid: params.asset_uuid.clone(),
            protocol: params.protocol.clone(),
            session_id: params.session_id.clone(),
        };
        let err = SessionToken::verify_bytes(&bytes, &other, now, &verifier)
            .expect_err("wrong key");
        prop_assert_eq!(err, TokenError::MacMismatch);
    }

    /// Flipping any single byte in the serialized form fails verify.
    #[test]
    fn any_single_field_tamper_fails_mac_or_version(
        params in params_strategy(),
        now in 1_700_000_000u64..1_900_000_000u64,
        idx_seed in any::<usize>(),
    ) {
        let key = TokenKey::generate();
        let token = SessionToken::mint(&key, now, params.clone());
        let mut bytes = token.to_bytes().expect("serialize");
        prop_assume!(!bytes.is_empty());
        let i = idx_seed % bytes.len();
        bytes[i] ^= 0x01;
        let verifier = Verifier::Supervisor {
            host: params.host.clone(),
            port: params.port,
            target_service: params.target_service.as_token_discriminant(),
            session_id: params.session_id.clone(),
        };
        let err = SessionToken::verify_bytes(&bytes, &key, now, &verifier);
        prop_assert!(
            err.is_err(),
            "tampered byte at {i} must fail verify"
        );
    }

    /// TTL on the minted token matches `token_ttl_for`.
    #[test]
    fn ttl_matches_token_ttl_for(
        service in services(),
        now in 1_700_000_000u64..1_900_000_000u64,
    ) {
        let key = TokenKey::generate();
        let params = SessionTokenParams {
            session_id: "sess".into(),
            user_uuid: "user".into(),
            asset_uuid: "asset".into(),
            protocol: "ssh".into(),
            host: "host.example".into(),
            port: 22,
            target_service: service,
        };
        let token = SessionToken::mint(&key, now, params);
        prop_assert_eq!(
            token.expires_at.saturating_sub(token.issued_at),
            token_ttl_for(service)
        );
    }
}
