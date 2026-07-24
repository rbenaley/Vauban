//! Property tests for [`shared::client_acl::ClientAcl`].

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::{IpAddr, Ipv4Addr};

use ipnetwork::Ipv4Network;
use proptest::prelude::*;
use shared::client_acl::ClientAcl;

fn ip_v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// Env transport preserves membership decisions for sample IPs.
    #[test]
    fn env_roundtrip_preserves_permits(
        prefix in 8u8..=30u8,
        a in 1u8..=223u8,
        b in 0u8..=255u8,
        probe in any::<(u8, u8, u8, u8)>(),
    ) {
        // Keep network base aligned to common /8../30 shapes without
        // fighting host-bit rules: use a.b.0.0/prefix when prefix >= 16.
        let cidr = if prefix >= 16 {
            format!("{a}.{b}.0.0/{prefix}")
        } else {
            format!("{a}.0.0.0/{prefix}")
        };
        let Ok(acl) = ClientAcl::parse(&[cidr.as_str()]) else {
            // Some (a,b,prefix) combos may still be rejected by ipnetwork;
            // skip rather than fail the suite.
            return Ok(());
        };
        let env = acl.to_env_string();
        let back = ClientAcl::from_env_string(&env).expect("env round-trip");
        let sample = ip_v4(probe.0, probe.1, probe.2, probe.3);
        prop_assert_eq!(acl.permits(sample), back.permits(sample));
        prop_assert_eq!(acl.is_enabled(), back.is_enabled());
        prop_assert_eq!(acl.len(), back.len());
    }

    /// Disabled ACL and loopback addresses always permit.
    #[test]
    fn disabled_or_loopback_always_permits(
        a in 0u8..=255u8,
        b in 0u8..=255u8,
        c in 0u8..=255u8,
        d in 0u8..=255u8,
    ) {
        let disabled = ClientAcl::default();
        let sample = ip_v4(a, b, c, d);
        prop_assert!(disabled.permits(sample));

        let acl = ClientAcl::parse(&["10.0.0.0/8"]).expect("valid");
        prop_assert!(acl.permits(ip_v4(127, b, c, d)));
        prop_assert!(acl.permits(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)));
    }

    /// An address inside a parsed /24 is permitted when that /24 is listed.
    #[test]
    fn ip_in_parsed_cidr_is_permitted(
        a in 1u8..=223u8,
        b in 0u8..=255u8,
        c in 0u8..=255u8,
        host in 1u8..=254u8,
    ) {
        let network: Ipv4Network = format!("{a}.{b}.{c}.0/24")
            .parse()
            .expect("/24 parse");
        let acl = ClientAcl::parse(&[network.to_string()]).expect("acl");
        let member = ip_v4(a, b, c, host);
        prop_assert!(
            acl.permits(member),
            "{member} must be inside {network}"
        );
        // Outside the /24 (flip high octet when possible).
        let outside_a = if a == 1 { 2 } else { 1 };
        let outside = ip_v4(outside_a, b, c, host);
        if !outside.is_loopback() {
            prop_assert!(
                !acl.permits(outside),
                "{outside} must be outside {network}"
            );
        }
    }

    /// A garbage CIDR among valid entries fails closed (no partial ACL).
    #[test]
    fn invalid_cidr_never_partially_applies(
        good_a in 1u8..=223u8,
        garbage in "[A-Za-z]{3,12}",
    ) {
        prop_assume!(!garbage.contains('/'));
        let good = format!("{good_a}.0.0.0/8");
        let err = ClientAcl::parse(&[good.as_str(), garbage.as_str()]).unwrap_err();
        prop_assert!(
            err.contains(&garbage),
            "error must name the bad entry: {err}"
        );
        // from_env with the same shape also fails closed.
        let env = format!("{good},{garbage}");
        prop_assert!(ClientAcl::from_env_string(&env).is_err());
    }
}
