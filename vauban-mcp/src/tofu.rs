//! Trust-on-first-use store for the leaf's internal SPKI pin.
//!
//! File format, one host per line: `host <space> SHA256:<b64>`.
//! A later pin that differs from the stored one is refused.

use crate::pin::spki_matches;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TofuDecision {
    Learned,
    Match,
    Mismatch,
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

/// First sight of `host` learns `pin`. A later different pin is [`TofuDecision::Mismatch`].
pub fn observe(store: &mut BTreeMap<String, String>, host: &str, pin: &str) -> TofuDecision {
    match store.get(host) {
        None => {
            store.insert(host.to_string(), pin.to_string());
            TofuDecision::Learned
        }
        Some(known) if spki_matches(known, pin.strip_prefix("SHA256:").unwrap_or(pin)) => {
            TofuDecision::Match
        }
        Some(_) => TofuDecision::Mismatch,
    }
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
    fn store_round_trips() {
        let mut store = BTreeMap::new();
        observe(&mut store, "a.example", "SHA256:aaaa");
        observe(&mut store, "b.example", "SHA256:bbbb");
        let again = parse_store(&render_store(&store));
        assert_eq!(again, store);
    }
}
