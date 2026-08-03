//! Property tests for Apache CLF formatting, handshake coalescing, and
//! trailing-slash canonicalization.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use http::{Method, Version};
use proptest::prelude::*;
use vcp::http_canonical::{should_redirect_trailing_slash, trailing_slash_redirect_location};
use vcp::tls::{HandshakeFailureLog, format_common_log};

fn peer(octets: (u8, u8, u8, u8)) -> SocketAddr {
    SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(octets.0, octets.1, octets.2, octets.3)),
        443,
    )
}

proptest! {
    #![proptest_config(crate::common::prop_config(48))]

    #[test]
    fn prop_clf_contains_status_method_and_host(
        a in 1u8..=254,
        b in 0u8..=255,
        c in 0u8..=255,
        d in 1u8..=254,
        status in 100u16..600,
        path in "/[a-z0-9/_-]{0,48}",
    ) {
        prop_assume!(!path.contains('"'));
        let addr = peer((a, b, c, d));
        let line = format_common_log(
            addr,
            &Method::GET,
            &path,
            Version::HTTP_11,
            status,
            "-",
        );
        let host_prefix = format!("{} - - [", addr.ip());
        let request = format!("\"GET {path} HTTP/1.1\"");
        let status_tail = format!(" {status} -");
        prop_assert!(line.starts_with(&host_prefix));
        prop_assert!(line.contains(&request));
        prop_assert!(line.contains(&status_tail));
        prop_assert!(!line.contains('\n'));
    }
}

proptest! {
    #![proptest_config(crate::common::prop_config(24))]

    #[test]
    fn prop_clf_neutralizes_embedded_quotes(status in 200u16..500) {
        let addr = peer((10, 0, 0, 1));
        let line = format_common_log(
            addr,
            &Method::GET,
            "/q\"x",
            Version::HTTP_11,
            status,
            "12",
        );
        let status_bytes = format!(" {status} 12");
        prop_assert!(!line.contains("/q\"x"));
        prop_assert!(line.contains("%22"));
        prop_assert!(line.contains(&status_bytes));
    }
}

proptest! {
    #![proptest_config(crate::common::prop_config(48))]

    #[test]
    fn prop_trailing_slash_location_is_origin_relative(
        segs in prop::collection::vec("[a-z0-9-]{1,10}", 1..6),
        slashes in 1usize..5,
        q in prop::option::of("[a-z0-9=_-]{1,20}")
    ) {
        let path = format!("/{}{}", segs.join("/"), "/".repeat(slashes));
        let loc = trailing_slash_redirect_location(&path, q.as_deref()).expect("redirect");
        prop_assert!(loc.starts_with('/'));
        prop_assert!(!loc.starts_with("http"));
        prop_assert!(!loc.ends_with('/'));
        let expected = format!("/{}", segs.join("/"));
        match &q {
            Some(query) => prop_assert_eq!(loc, format!("{expected}?{query}")),
            None => prop_assert_eq!(loc, expected),
        }
        prop_assert!(should_redirect_trailing_slash(&Method::GET));
        prop_assert!(!should_redirect_trailing_slash(&Method::POST));
    }
}

proptest! {
    #![proptest_config(crate::common::prop_config(32))]

    #[test]
    fn prop_handshake_coalesce_preserves_total_count(
        labels in prop::collection::vec(prop::sample::select(vec!["A", "B", "C"]), 1..24),
    ) {
        let (log, captured) = HandshakeFailureLog::capturing(Duration::from_secs(60));
        let n = labels.len() as u32;
        for label in &labels {
            log.note((*label).to_owned());
        }
        log.flush();
        let events = captured.lock().unwrap().clone();
        let total: u32 = events.iter().map(|(_, c)| *c).sum();
        prop_assert_eq!(total, n);

        // Consecutive identical labels must form a single batch entry.
        let mut expected_batches = 0u32;
        let mut prev: Option<&str> = None;
        for label in &labels {
            match prev {
                Some(p) if p == *label => {}
                _ => {
                    expected_batches += 1;
                    prev = Some(*label);
                }
            }
        }
        prop_assert_eq!(events.len() as u32, expected_batches);
    }
}
