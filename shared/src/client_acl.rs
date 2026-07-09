//! Global client IP allowlist (`[security] allowed_client_networks`).
//!
//! ONE matcher for every client-facing entry point of the bastion:
//!
//! - vauban-web: the `ip_acl` HTTP/WS middleware (all requests, before
//!   auth). The ACME TLS-ALPN-01 challenge is served BELOW the HTTP
//!   layer by the `AcmeResolver`, so certificate renewal is exempt by
//!   construction -- no CA IP list to maintain.
//! - vauban-proxy-iacs: the sshd accept loop (peer gated before any
//!   SSH byte is exchanged).
//! - vauban-supervisor: validates the ranges fail-closed at boot and
//!   transports them to the sandboxed IACS proxy.
//!
//! Semantics:
//!
//! - Empty list = feature disabled (allow all) -- backward compatible.
//! - Loopback (`127.0.0.0/8`, `::1`) is ALWAYS permitted: local rescue
//!   access so an operator cannot lock themselves out of the machine
//!   that runs the bastion.
//! - IPv4-mapped IPv6 addresses (`::ffff:10.0.0.1`) are canonicalised
//!   to their IPv4 form before matching, so a v4 range covers clients
//!   reaching a dual-stack listener.
//! - Parsing is FAIL-CLOSED: any entry that is not a valid CIDR is a
//!   hard error surfaced at boot. A typo must stop the service, never
//!   silently widen or narrow the allowlist.

use std::net::IpAddr;

use ipnetwork::IpNetwork;

/// Parsed, ready-to-match client allowlist.
#[derive(Debug, Clone, Default)]
pub struct ClientAcl {
    networks: Vec<IpNetwork>,
}

impl ClientAcl {
    /// Parse the configured CIDR list. Fail-closed: the first invalid
    /// entry aborts with a descriptive error (unlike the historical
    /// `trusted_proxies` parsing which silently skips bad entries --
    /// an ACL must never boot with a partially-applied policy).
    pub fn parse<S: AsRef<str>>(entries: &[S]) -> Result<Self, String> {
        let mut networks = Vec::with_capacity(entries.len());
        for entry in entries {
            let raw = entry.as_ref().trim();
            if raw.is_empty() {
                return Err("allowed_client_networks contains an empty entry".to_string());
            }
            let network = raw.parse::<IpNetwork>().map_err(|e| {
                format!("allowed_client_networks entry '{raw}' is not a valid CIDR: {e}")
            })?;
            networks.push(network);
        }
        Ok(Self { networks })
    }

    /// `true` when the ACL is active (at least one network configured).
    pub fn is_enabled(&self) -> bool {
        !self.networks.is_empty()
    }

    /// Number of configured networks (boot logging).
    pub fn len(&self) -> usize {
        self.networks.len()
    }

    /// `true` when no network is configured.
    pub fn is_empty(&self) -> bool {
        self.networks.is_empty()
    }

    /// Decide whether a client IP may use the bastion.
    ///
    /// Disabled ACL permits everything; loopback is always permitted
    /// (anti-lockout rescue); IPv4-mapped v6 addresses are matched in
    /// their canonical IPv4 form.
    pub fn permits(&self, ip: IpAddr) -> bool {
        if !self.is_enabled() {
            return true;
        }
        let canonical = canonicalize(ip);
        if canonical.is_loopback() {
            return true;
        }
        self.networks.iter().any(|net| net.contains(canonical))
    }

    /// Canonical serialised form (comma-separated CIDRs) for env-var
    /// transport towards sandboxed children.
    pub fn to_env_string(&self) -> String {
        self.networks
            .iter()
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Parse the env-var transport form produced by [`Self::to_env_string`].
    /// An empty string yields a disabled ACL.
    pub fn from_env_string(raw: &str) -> Result<Self, String> {
        let entries: Vec<&str> = raw
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        Self::parse(&entries)
    }
}

/// Normalise IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) to IPv4 so a
/// v4 CIDR range covers dual-stack listeners.
fn canonicalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn acl(entries: &[&str]) -> ClientAcl {
        ClientAcl::parse(entries).expect("valid test ACL")
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("valid test IP")
    }

    // ==================== parse (fail-closed) ====================

    #[test]
    fn parse_accepts_valid_v4_and_v6_cidrs() {
        let acl = acl(&[
            "10.0.0.0/8",
            "10.20.0.0/28",
            "104.28.30.3/32",
            "2001:db8::/32",
        ]);
        assert!(acl.is_enabled());
        assert_eq!(acl.len(), 4);
    }

    #[test]
    fn parse_rejects_invalid_cidr() {
        for bad in ["not-a-cidr", "10.0.0.0/33", "10.0.0/8", "2001:db8::/129"] {
            let err = ClientAcl::parse(&[bad]).unwrap_err();
            assert!(err.contains(bad), "error must name the bad entry: {err}");
        }
    }

    #[test]
    fn parse_rejects_empty_entry() {
        assert!(ClientAcl::parse(&[""]).is_err());
        assert!(ClientAcl::parse(&["   "]).is_err());
    }

    #[test]
    fn parse_rejects_first_invalid_even_among_valid() {
        let err = ClientAcl::parse(&["10.0.0.0/8", "garbage", "192.168.0.0/16"]).unwrap_err();
        assert!(err.contains("garbage"));
    }

    #[test]
    fn parse_accepts_bare_ip_as_host_route() {
        // ipnetwork parses a bare IP as /32 (v4) or /128 (v6).
        let acl = acl(&["104.28.30.3"]);
        assert!(acl.permits(ip("104.28.30.3")));
        assert!(!acl.permits(ip("104.28.30.4")));
    }

    // ==================== permits: enabled/disabled ====================

    #[test]
    fn empty_acl_is_disabled_and_permits_everything() {
        let acl = ClientAcl::default();
        assert!(!acl.is_enabled());
        assert!(acl.permits(ip("8.8.8.8")));
        assert!(acl.permits(ip("2001:db8::1")));
    }

    #[test]
    fn permits_inside_range_denies_outside() {
        let acl = acl(&["10.0.0.0/8", "10.20.0.0/28", "104.28.30.3/32"]);
        // /8
        assert!(acl.permits(ip("10.0.0.1")));
        assert!(acl.permits(ip("10.255.255.254")));
        assert!(!acl.permits(ip("11.0.0.1")));
        // /28 (also inside /8, but check boundary logic on its own)
        assert!(acl.permits(ip("10.20.0.14")));
        // /32 single-provider case
        assert!(acl.permits(ip("104.28.30.3")));
        assert!(!acl.permits(ip("104.28.30.2")));
        assert!(!acl.permits(ip("104.28.30.4")));
        // unrelated
        assert!(!acl.permits(ip("8.8.8.8")));
    }

    #[test]
    fn v6_range_matches_v6_clients() {
        let acl = acl(&["2001:db8::/32"]);
        assert!(acl.permits(ip("2001:db8::1")));
        assert!(!acl.permits(ip("2001:db9::1")));
    }

    #[test]
    fn v6_client_denied_when_only_v4_ranges_listed() {
        let acl = acl(&["10.0.0.0/8"]);
        assert!(!acl.permits(ip("2001:db8::1")));
    }

    // ==================== v4-mapped canonicalisation ====================

    #[test]
    fn v4_mapped_v6_matches_v4_range() {
        let acl = acl(&["10.0.0.0/8"]);
        assert!(acl.permits(ip("::ffff:10.1.2.3")));
        assert!(!acl.permits(ip("::ffff:11.1.2.3")));
    }

    // ==================== loopback bypass (anti-lockout) ====================

    #[test]
    fn loopback_always_permitted_even_when_not_listed() {
        let acl = acl(&["10.0.0.0/8"]);
        assert!(acl.permits(ip("127.0.0.1")));
        assert!(acl.permits(ip("127.1.2.3"))); // whole 127/8
        assert!(acl.permits(ip("::1")));
        assert!(acl.permits(ip("::ffff:127.0.0.1"))); // mapped loopback
    }

    // ==================== env transport round-trip ====================

    #[test]
    fn env_string_round_trips() {
        let acl = acl(&["10.0.0.0/8", "104.28.30.3/32"]);
        let env = acl.to_env_string();
        assert_eq!(env, "10.0.0.0/8,104.28.30.3/32");
        let back = ClientAcl::from_env_string(&env).unwrap();
        assert!(back.permits(ip("10.1.1.1")));
        assert!(!back.permits(ip("8.8.8.8")));
    }

    #[test]
    fn env_string_empty_is_disabled() {
        let acl = ClientAcl::from_env_string("").unwrap();
        assert!(!acl.is_enabled());
        assert!(acl.permits(ip("8.8.8.8")));
    }

    #[test]
    fn env_string_invalid_fails_closed() {
        assert!(ClientAcl::from_env_string("10.0.0.0/8,garbage").is_err());
    }
}
