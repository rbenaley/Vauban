//! Trust-on-first-use store for the leaf's internal SPKI pin.
//!
//! File format, one origin per line: `host:port <space> SHA256:<b64>`.
//! The key is the origin the user typed in `--url`, never a URL the
//! bastion returned. A later pin that differs from the stored one is
//! refused.

use crate::pin::spki_matches;
use std::collections::BTreeMap;

/// `host:port` for an `https://` or `wss://` URL. The host is lowercase
/// without a trailing dot; the port defaults to 443. Any other scheme
/// is refused.
pub fn origin_key(url: &str) -> Result<String, String> {
    let parsed = reqwest::Url::parse(url.trim()).map_err(|e| format!("bad url {url}: {e}"))?;
    match parsed.scheme() {
        "https" | "wss" => {}
        other => return Err(format!("{other}:// is refused; use https://")),
    }
    let host = parsed
        .host_str()
        .map(|h| h.trim_end_matches('.').to_ascii_lowercase())
        .filter(|h| !h.is_empty())
        .ok_or_else(|| format!("no host in {url}"))?;
    let port = parsed.port_or_known_default().unwrap_or(443);
    Ok(format!("{host}:{port}"))
}

/// Host part of an [`origin_key`], usable as a TLS server name.
pub fn origin_host(origin: &str) -> &str {
    let host = origin.rsplit_once(':').map_or(origin, |(host, _)| host);
    host.trim_start_matches('[').trim_end_matches(']')
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TofuDecision {
    Learned,
    Match,
    Mismatch,
    /// A pre-0.9.46 line (bare host, no port) held the same pin; it is
    /// now filed under the origin and the old line is gone.
    Migrated,
}

/// Pre-0.9.46 lines for the host of `origin`: no port, any case, an
/// optional trailing dot. The tunnel identity belongs to the appliance,
/// so such a line stands for every port of that host. IPv6 origins have
/// no legacy form.
pub fn legacy_keys(store: &BTreeMap<String, String>, origin: &str) -> Vec<String> {
    if origin.starts_with('[') {
        return Vec::new();
    }
    let host = origin_host(origin);
    store
        .keys()
        .filter(|key| !key.contains(':'))
        .filter(|key| key.trim_end_matches('.').eq_ignore_ascii_case(host))
        .cloned()
        .collect()
}

pub fn parse_store(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((host, pin)) = line.split_once(' ') else {
            continue;
        };
        if host.is_empty() || !pin.starts_with("SHA256:") {
            continue;
        }
        out.insert(host.to_string(), pin.to_string());
    }
    out
}

pub fn render_store(store: &BTreeMap<String, String>) -> String {
    let mut out = String::new();
    for (host, pin) in store {
        out.push_str(host);
        out.push(' ');
        out.push_str(pin);
        out.push('\n');
    }
    out
}

fn same_pin(known: &str, pin: &str) -> bool {
    spki_matches(known, pin.strip_prefix("SHA256:").unwrap_or(pin))
}

/// First sight of `origin` learns `pin`. A later different pin is
/// [`TofuDecision::Mismatch`]. Without an entry for `origin`, a legacy
/// line for its host decides: same pin migrates, any other pin is a
/// mismatch and the store is left as it was.
pub fn observe(store: &mut BTreeMap<String, String>, origin: &str, pin: &str) -> TofuDecision {
    if let Some(known) = store.get(origin) {
        return if same_pin(known, pin) {
            TofuDecision::Match
        } else {
            TofuDecision::Mismatch
        };
    }
    let legacy = legacy_keys(store, origin);
    if legacy.is_empty() {
        store.insert(origin.to_string(), pin.to_string());
        return TofuDecision::Learned;
    }
    if !legacy
        .iter()
        .all(|key| store.get(key).is_some_and(|known| same_pin(known, pin)))
    {
        return TofuDecision::Mismatch;
    }
    for key in &legacy {
        store.remove(key);
    }
    store.insert(origin.to_string(), pin.to_string());
    TofuDecision::Migrated
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_pin_is_learned_and_a_change_is_refused() {
        let mut store = BTreeMap::new();
        assert_eq!(
            observe(&mut store, "bastion.example", "SHA256:aaaa"),
            TofuDecision::Learned
        );
        assert_eq!(
            observe(&mut store, "bastion.example", "SHA256:aaaa"),
            TofuDecision::Match
        );
        assert_eq!(
            observe(&mut store, "bastion.example", "SHA256:bbbb"),
            TofuDecision::Mismatch
        );
    }

    #[test]
    fn attack_tofu_pin_change_is_rejected() {
        let mut store = parse_store("bastion.example SHA256:aaaa\n");
        assert_eq!(
            observe(&mut store, "bastion.example", "SHA256:evil"),
            TofuDecision::Mismatch
        );
        assert_eq!(
            store.get("bastion.example").map(String::as_str),
            Some("SHA256:aaaa")
        );
    }

    #[test]
    fn origin_key_normalizes_host_and_port() {
        for (url, key) in [
            ("https://bastion.example", "bastion.example:443"),
            ("https://Bastion.EXAMPLE/", "bastion.example:443"),
            ("https://bastion.example./mcp", "bastion.example:443"),
            ("https://bastion.example:443/mcp", "bastion.example:443"),
            ("https://bastion.example:8443", "bastion.example:8443"),
            ("wss://bastion.example/mcp/tunnel", "bastion.example:443"),
            ("https://10.0.0.1/mcp", "10.0.0.1:443"),
            ("https://[::1]:9443/mcp", "[::1]:9443"),
        ] {
            assert_eq!(origin_key(url).unwrap(), key, "{url}");
        }
        assert_eq!(origin_host("[::1]:9443"), "::1");
        assert_eq!(origin_host("bastion.example:443"), "bastion.example");
    }

    #[test]
    fn attack_plain_http_hop1_url_is_rejected() {
        for url in [
            "http://bastion.example/mcp",
            "ws://bastion.example/mcp/tunnel",
            "bastion.example",
            "ftp://bastion.example",
            "https://",
        ] {
            assert!(origin_key(url).is_err(), "{url}");
        }
    }

    #[test]
    fn attack_hop1_case_variant_reuses_stored_pin() {
        let mut store = BTreeMap::new();
        let first = origin_key("https://bastion.example").unwrap();
        assert_eq!(
            observe(&mut store, &first, "SHA256:aaaa"),
            TofuDecision::Learned
        );
        for variant in [
            "https://BASTION.example",
            "https://bastion.example.",
            "https://bastion.example:443/",
        ] {
            let key = origin_key(variant).unwrap();
            assert_eq!(
                observe(&mut store, &key, "SHA256:evil"),
                TofuDecision::Mismatch,
                "{variant} must hit the stored pin, not learn a new one"
            );
        }
        assert_eq!(store.len(), 1);
    }

    proptest::proptest! {
        #[test]
        fn origin_key_is_idempotent_and_case_blind(
            label in "[a-z][a-z0-9]{0,10}",
            upper in proptest::collection::vec(proptest::bool::ANY, 0..12),
            dot in proptest::bool::ANY,
            port in proptest::option::of(1u16..),
        ) {
            let host = format!("{label}.example");
            let mixed: String = host
                .chars()
                .enumerate()
                .map(|(i, c)| if upper.get(i).copied().unwrap_or(false) { c.to_ascii_uppercase() } else { c })
                .collect();
            let suffix = if dot { "." } else { "" };
            let port_part = port.map(|p| format!(":{p}")).unwrap_or_default();
            let canonical = origin_key(&format!("https://{host}{port_part}")).unwrap();
            let variant = origin_key(&format!("https://{mixed}{suffix}{port_part}/mcp")).unwrap();
            proptest::prop_assert_eq!(&variant, &canonical);
            let again = origin_key(&format!("https://{canonical}")).unwrap();
            proptest::prop_assert_eq!(again, canonical);
        }
    }

    #[test]
    fn legacy_lines_migrate_to_the_origin_key() {
        for (legacy, origin) in [
            ("bastion.example", "bastion.example:443"),
            ("Bastion.EXAMPLE", "bastion.example:443"),
            ("bastion.example.", "bastion.example:443"),
            ("bastion.example", "bastion.example:8443"),
            ("10.0.0.1", "10.0.0.1:443"),
        ] {
            let mut store = parse_store(&format!(
                "{legacy} SHA256:aaaa\nother.example SHA256:oooo\n"
            ));
            assert_eq!(
                observe(&mut store, origin, "SHA256:aaaa"),
                TofuDecision::Migrated,
                "{legacy} -> {origin}"
            );
            assert_eq!(store.get(origin).map(String::as_str), Some("SHA256:aaaa"));
            assert!(!store.contains_key(legacy), "{legacy} line must be gone");
            assert_eq!(
                store.get("other.example").map(String::as_str),
                Some("SHA256:oooo")
            );
            assert_eq!(
                observe(&mut store, origin, "SHA256:aaaa"),
                TofuDecision::Match
            );
        }
    }

    #[test]
    fn bracketed_ipv6_origin_is_not_migrated() {
        let mut store = parse_store("::1 SHA256:aaaa\n[::1] SHA256:aaaa\n");
        assert!(legacy_keys(&store, "[::1]:9443").is_empty());
        assert_eq!(
            observe(&mut store, "[::1]:9443", "SHA256:bbbb"),
            TofuDecision::Learned
        );
    }

    #[test]
    fn an_origin_entry_wins_over_a_legacy_line() {
        let mut store = parse_store("b.example SHA256:old\nb.example:443 SHA256:new\n");
        assert_eq!(
            observe(&mut store, "b.example:443", "SHA256:new"),
            TofuDecision::Match
        );
        assert_eq!(store.len(), 2, "a Match never rewrites the store");
    }

    #[test]
    fn attack_legacy_host_pin_still_refuses_a_changed_pin() {
        let text = "Bastion.example SHA256:aaaa\n";
        for origin in ["bastion.example:443", "bastion.example:8443"] {
            let mut store = parse_store(text);
            assert_eq!(
                observe(&mut store, origin, "SHA256:evil"),
                TofuDecision::Mismatch,
                "{origin}"
            );
            assert_eq!(render_store(&store), text, "the store is left as it was");
        }
        let mut split = parse_store("bastion.example SHA256:aaaa\nBASTION.example SHA256:bbbb\n");
        assert_eq!(
            observe(&mut split, "bastion.example:443", "SHA256:aaaa"),
            TofuDecision::Mismatch,
            "two legacy lines that disagree fail closed"
        );
        assert_eq!(split.len(), 2);
    }

    #[test]
    fn attack_legacy_entry_of_another_host_is_not_borrowed() {
        for (legacy, origin) in [
            ("bastion.example", "evil.example:443"),
            ("bastion.example", "bastion.example.evil:443"),
            ("example", "bastion.example:443"),
            ("bastion", "bastion.example:443"),
            ("bastion.example", "xbastion.example:443"),
        ] {
            let mut store = parse_store(&format!("{legacy} SHA256:aaaa\n"));
            assert!(
                legacy_keys(&store, origin).is_empty(),
                "{legacy} for {origin}"
            );
            assert_eq!(
                observe(&mut store, origin, "SHA256:aaaa"),
                TofuDecision::Learned,
                "{legacy} must not vouch for {origin}"
            );
            assert_eq!(store.get(legacy).map(String::as_str), Some("SHA256:aaaa"));
        }
    }

    fn host_of_key(key: &str) -> String {
        let host = if key.contains(':') {
            origin_host(key)
        } else {
            key
        };
        host.trim_end_matches('.').to_ascii_lowercase()
    }

    proptest::proptest! {
        #[test]
        fn observe_keeps_one_entry_per_host_and_never_changes_a_pin(
            hosts in proptest::collection::vec("[a-c]\\.example", 0..4),
            legacy_upper in proptest::bool::ANY,
            target in "[a-d]\\.example",
            port in proptest::sample::select(vec![443u16, 8443]),
            pins in proptest::collection::vec("SHA256:[a-c]{4}", 4),
            pin in "SHA256:[a-c]{4}",
        ) {
            let mut store = BTreeMap::new();
            for (i, host) in hosts.iter().enumerate() {
                let key = if legacy_upper { host.to_ascii_uppercase() } else { host.clone() };
                store.insert(key, pins[i % pins.len()].clone());
            }
            let before = store.clone();
            let origin = format!("{target}:{port}");
            let decision = observe(&mut store, &origin, &pin);
            let mut seen = std::collections::BTreeSet::new();
            for key in store.keys() {
                proptest::prop_assert!(seen.insert(host_of_key(key)), "two entries for one host: {store:?}");
            }
            for (key, value) in &before {
                if host_of_key(key) != target {
                    proptest::prop_assert_eq!(store.get(key), Some(value));
                }
            }
            match decision {
                TofuDecision::Migrated => {
                    let old = before
                        .iter()
                        .find(|(k, _)| host_of_key(k) == target)
                        .map(|(_, v)| v.clone());
                    proptest::prop_assert_eq!(old.as_deref(), Some(pin.as_str()));
                    proptest::prop_assert_eq!(store.get(&origin), Some(&pin));
                }
                TofuDecision::Mismatch | TofuDecision::Match => {
                    proptest::prop_assert_eq!(&store, &before);
                }
                TofuDecision::Learned => {
                    proptest::prop_assert!(before.keys().all(|k| host_of_key(k) != target));
                    proptest::prop_assert_eq!(store.len(), before.len() + 1);
                }
            }
        }
    }

    fn mixed_key(host: &str, kind: u8) -> String {
        match kind {
            0 => host.to_string(),
            1 => host.to_ascii_uppercase(),
            2 => format!("{host}."),
            3 => format!("{host}:443"),
            _ => format!("{host}:8443"),
        }
    }

    proptest::proptest! {
        #[test]
        fn observe_on_mixed_stores_keeps_other_entries_and_never_adds_a_legacy_line(
            entries in proptest::collection::vec(
                ("[a-c]\\.example", 0u8..5, "SHA256:[a-c]{4}"),
                0..8,
            ),
            target in "[a-d]\\.example",
            port in proptest::sample::select(vec![443u16, 8443]),
            pin in "SHA256:[a-c]{4}",
        ) {
            let mut store = BTreeMap::new();
            for (host, kind, entry_pin) in &entries {
                store.insert(mixed_key(host, *kind), entry_pin.clone());
            }
            let before = store.clone();
            let origin = format!("{target}:{port}");
            let is_legacy_of_target =
                |k: &str| !k.contains(':') && host_of_key(k) == target;
            let portless = |s: &BTreeMap<String, String>| {
                s.keys().filter(|k| !k.contains(':')).count()
            };
            let decision = observe(&mut store, &origin, &pin);

            for (key, value) in &before {
                if host_of_key(key) != target {
                    proptest::prop_assert_eq!(store.get(key), Some(value));
                }
            }
            proptest::prop_assert!(portless(&store) <= portless(&before));
            match decision {
                TofuDecision::Match | TofuDecision::Mismatch => {
                    proptest::prop_assert_eq!(&store, &before);
                }
                TofuDecision::Migrated => {
                    proptest::prop_assert!(!before.contains_key(&origin));
                    let removed: Vec<_> =
                        before.iter().filter(|(k, _)| is_legacy_of_target(k)).collect();
                    proptest::prop_assert!(!removed.is_empty());
                    for (_, old) in &removed {
                        proptest::prop_assert!(same_pin(old, &pin));
                    }
                    proptest::prop_assert!(store.keys().all(|k| !is_legacy_of_target(k)));
                    proptest::prop_assert_eq!(store.get(&origin), Some(&pin));
                    for (key, value) in &before {
                        if key.contains(':') && key != &origin {
                            proptest::prop_assert_eq!(store.get(key), Some(value));
                        }
                    }
                }
                TofuDecision::Learned => {
                    proptest::prop_assert!(!before.contains_key(&origin));
                    proptest::prop_assert!(before.keys().all(|k| !is_legacy_of_target(k)));
                    proptest::prop_assert_eq!(store.len(), before.len() + 1);
                    proptest::prop_assert_eq!(store.get(&origin), Some(&pin));
                }
            }
        }
    }

    #[test]
    fn store_round_trips() {
        let mut store = BTreeMap::new();
        observe(&mut store, "a.example", "SHA256:aaaa");
        observe(&mut store, "b.example", "SHA256:bbbb");
        let again = parse_store(&render_store(&store));
        assert_eq!(again, store);
    }
}
