//! KDC selection and failover for the Kerberos FD broker.
//!
//! The RDP proxy asks for a connected socket to "the KDC of realm R".
//! This module answers two questions and nothing else:
//!
//! 1. **Which endpoints?** [`select_endpoints`] maps the realm named by
//!    the request to the endpoints configured for it. The realm is a
//!    lookup key into the supervisor-owned `[auth.kerberos]` table: the
//!    request never carries a host, so there is no destination for a
//!    caller to choose.
//! 2. **Which one answers?** [`connect_first_kdc`] tries the endpoints in
//!    order under one overall time budget, so a dead first domain
//!    controller does not consume the whole exchange.
//!
//! No Kerberos byte is read or written here: the caller hands the
//! connected socket to the proxy over SCM_RIGHTS.

use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use shared::kerberos::Realm;

use crate::config::{KdcEndpoints, KerberosConfig};
use crate::tcp_resolve::{AddrDecision, connect_first_reachable, resolve_tcp_targets};

/// Floor of the per-endpoint connect budget. Below this a healthy but
/// distant KDC would be skipped.
const MIN_ATTEMPT: Duration = Duration::from_millis(500);

/// Why no KDC endpoint was selected. No socket has been opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectError {
    /// Kerberos brokering is disabled or has no realm configured.
    Disabled,
    /// The request names a string that is not a DNS-form realm.
    InvalidRealm,
    /// The realm is well-formed but absent from the supervisor's table.
    RealmNotConfigured(Realm),
    /// A lease without a realm while several realms are configured.
    AmbiguousRealm,
}

impl SelectError {
    /// Message returned to the proxy. The requested realm is echoed only
    /// once it has passed `normalize_realm`.
    pub fn broker_message(&self) -> String {
        let text = match self {
            Self::Disabled => "Kerberos KDC brokering is disabled or unconfigured".to_string(),
            Self::InvalidRealm => "Kerberos realm in the lease request is not valid".to_string(),
            Self::RealmNotConfigured(realm) => {
                format!("Kerberos realm {realm} is not configured in [auth.kerberos]")
            }
            Self::AmbiguousRealm => {
                "Kerberos lease names no realm while several realms are configured".to_string()
            }
        };
        self.refusal().error(&text)
    }

    /// The machine-readable refusal the proxy classifies on.
    pub const fn refusal(&self) -> shared::kerberos::KdcLeaseRefusal {
        use shared::kerberos::KdcLeaseRefusal;
        match self {
            Self::Disabled => KdcLeaseRefusal::Disabled,
            Self::InvalidRealm => KdcLeaseRefusal::InvalidRealm,
            Self::RealmNotConfigured(_) => KdcLeaseRefusal::RealmNotConfigured,
            Self::AmbiguousRealm => KdcLeaseRefusal::AmbiguousRealm,
        }
    }
}

/// The only service that may lease a KDC socket.
pub const LEASE_CALLER: &str = "proxy_rdp";

/// Whether `service_key` may lease a KDC socket. Exact match: the key is
/// the supervisor's own name for the channel a request arrived on, never
/// a value taken from the request.
pub fn caller_may_lease(service_key: &str) -> bool {
    service_key == LEASE_CALLER
}

/// Resolve the realm of a lease to its configured endpoints.
///
/// `requested_realm` is `Some` for `KerberosKdcLeaseRequest` and `None`
/// for the legacy `KerberosKdcRequest`, which is honored only when a
/// single realm is configured.
pub fn select_endpoints(
    kerberos: &KerberosConfig,
    requested_realm: Option<&str>,
) -> Result<(Realm, KdcEndpoints), SelectError> {
    if !kerberos.allows() {
        return Err(SelectError::Disabled);
    }
    match requested_realm {
        Some(raw) => {
            let realm =
                shared::kerberos::normalize_realm(raw).map_err(|_| SelectError::InvalidRealm)?;
            match kerberos.endpoints_for(&realm) {
                Some(endpoints) => Ok((realm, endpoints)),
                None => Err(SelectError::RealmNotConfigured(realm)),
            }
        }
        None => kerberos
            .sole_realm_endpoints()
            .ok_or(SelectError::AmbiguousRealm),
    }
}

/// A KDC connection and where it landed.
#[derive(Debug)]
pub struct KdcConnection {
    pub stream: TcpStream,
    pub addr: SocketAddr,
    /// Index, in the configured order, of the endpoint that answered.
    pub endpoint_index: usize,
}

/// Connect to the first reachable endpoint, in order, within `budget`.
///
/// Each endpoint gets an equal share of the budget (never less than
/// [`MIN_ATTEMPT`], never more than what is left), so one unreachable
/// host cannot starve the ones after it. Name resolution failures and
/// refused connections move on to the next endpoint. The error is the
/// last failure, prefixed with how many endpoints were tried.
pub fn connect_first_kdc(
    endpoints: &[(String, u16)],
    budget: Duration,
) -> Result<KdcConnection, String> {
    if endpoints.is_empty() {
        return Err("no KDC endpoint configured".to_string());
    }
    let deadline = Instant::now() + budget;
    let share = (budget / u32::try_from(endpoints.len()).unwrap_or(u32::MAX)).max(MIN_ATTEMPT);
    let mut last_error = String::new();
    let mut tried = 0usize;

    for (endpoint_index, (host, port)) in endpoints.iter().enumerate() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        tried += 1;
        let attempt = share.min(remaining);
        let addrs = match resolve_tcp_targets(host, *port) {
            Ok(addrs) => addrs,
            Err(e) => {
                last_error = format!("{host}:{port}: resolution failed: {e}");
                continue;
            }
        };
        match connect_first_reachable(&addrs, attempt, |_| AddrDecision::Accept) {
            Ok((stream, addr)) => {
                return Ok(KdcConnection {
                    stream,
                    addr,
                    endpoint_index,
                });
            }
            Err(e) => last_error = format!("{host}:{port}: {}", e.broker_message()),
        }
    }

    Err(format!(
        "no KDC reachable (tried {tried}/{} endpoints): {last_error}",
        endpoints.len()
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::config::KerberosRealmConfig;
    use std::net::TcpListener;

    fn config(realms: &[(&str, &[&str])]) -> KerberosConfig {
        KerberosConfig {
            enabled: true,
            realms: realms
                .iter()
                .map(|(realm, hosts)| KerberosRealmConfig {
                    realm: (*realm).to_string(),
                    kdc_hosts: hosts.iter().map(|h| (*h).to_string()).collect(),
                    kdc_port: 88,
                })
                .collect(),
            ..KerberosConfig::default()
        }
    }

    fn realm(s: &str) -> Realm {
        shared::kerberos::normalize_realm(s).unwrap()
    }

    /// A port nothing listens on: bind, read the port, drop the listener.
    fn closed_port() -> u16 {
        TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    // ---------------------------------------------------------------
    // select_endpoints
    // ---------------------------------------------------------------

    #[test]
    fn test_select_endpoints_picks_the_named_realm() {
        let cfg = config(&[
            (
                "corp.example.com",
                &["dc1.corp.example.com", "dc2.corp.example.com"],
            ),
            ("lab.example.net", &["kdc.lab.example.net"]),
        ]);
        let (r, endpoints) = select_endpoints(&cfg, Some("LAB.EXAMPLE.NET")).unwrap();
        assert_eq!(r, realm("lab.example.net"));
        assert_eq!(endpoints, vec![("kdc.lab.example.net".to_string(), 88)]);

        let (_, endpoints) = select_endpoints(&cfg, Some("corp.example.com")).unwrap();
        assert_eq!(
            endpoints,
            vec![
                ("dc1.corp.example.com".to_string(), 88),
                ("dc2.corp.example.com".to_string(), 88),
            ],
            "configured order is the failover order"
        );
    }

    #[test]
    fn test_select_endpoints_reads_the_single_realm_keys() {
        let cfg = KerberosConfig {
            enabled: true,
            realm: "EXAMPLE.COM".to_string(),
            kdc_host: "dc1.example.com".to_string(),
            ..KerberosConfig::default()
        };
        let (r, endpoints) = select_endpoints(&cfg, Some("example.com")).unwrap();
        assert_eq!(r, realm("example.com"));
        assert_eq!(endpoints, vec![("dc1.example.com".to_string(), 88)]);
    }

    #[test]
    fn test_select_endpoints_disabled_is_refused() {
        let mut cfg = config(&[("corp.example.com", &["dc1.corp.example.com"])]);
        cfg.enabled = false;
        assert_eq!(
            select_endpoints(&cfg, Some("corp.example.com")),
            Err(SelectError::Disabled)
        );
        assert_eq!(
            select_endpoints(&KerberosConfig::default(), None),
            Err(SelectError::Disabled)
        );
    }

    #[test]
    fn attack_proxy_supplied_realm_outside_config_is_rejected() {
        let cfg = config(&[("corp.example.com", &["dc1.corp.example.com"])]);
        assert_eq!(
            select_endpoints(&cfg, Some("evil.attacker.test")),
            Err(SelectError::RealmNotConfigured(realm("evil.attacker.test")))
        );
    }

    #[test]
    fn attack_proxy_supplied_host_as_realm_is_rejected() {
        // Anything shaped like a destination rather than a realm.
        let cfg = config(&[("corp.example.com", &["dc1.corp.example.com"])]);
        for raw in [
            "",
            "CORP",
            "203.0.113.9:88",
            "tcp://attacker.test:88",
            "corp.example.com/../x",
            "corp.example.com@attacker.test",
            "attacker.test\0corp.example.com",
        ] {
            let got = select_endpoints(&cfg, Some(raw));
            assert!(
                matches!(
                    got,
                    Err(SelectError::InvalidRealm) | Err(SelectError::RealmNotConfigured(_))
                ),
                "{raw:?} -> {got:?}"
            );
        }
        // A bare IPv4 literal passes the realm grammar; it must still not
        // be in the table.
        assert!(matches!(
            select_endpoints(&cfg, Some("203.0.113.9")),
            Err(SelectError::RealmNotConfigured(_))
        ));
    }

    #[test]
    fn test_legacy_lease_is_honored_only_with_a_single_realm() {
        let one = config(&[("corp.example.com", &["dc1.corp.example.com"])]);
        let (r, _) = select_endpoints(&one, None).unwrap();
        assert_eq!(r, realm("corp.example.com"));

        let two = config(&[
            ("corp.example.com", &["dc1.corp.example.com"]),
            ("lab.example.net", &["kdc.lab.example.net"]),
        ]);
        assert_eq!(
            select_endpoints(&two, None),
            Err(SelectError::AmbiguousRealm)
        );
    }

    #[test]
    fn test_broker_messages_never_echo_an_unvalidated_realm() {
        assert!(
            !SelectError::InvalidRealm
                .broker_message()
                .contains("attacker")
        );
        let msg = SelectError::RealmNotConfigured(realm("lab.example.net")).broker_message();
        assert!(msg.contains("LAB.EXAMPLE.NET"));
    }

    /// The proxy classifies a refused lease on its code: every refusal
    /// the supervisor sends must read back as itself.
    #[test]
    fn test_broker_messages_carry_their_refusal_code() {
        use shared::kerberos::KdcLeaseRefusal;
        for (error, expected) in [
            (SelectError::Disabled, KdcLeaseRefusal::Disabled),
            (SelectError::InvalidRealm, KdcLeaseRefusal::InvalidRealm),
            (
                SelectError::RealmNotConfigured(realm("lab.example.net")),
                KdcLeaseRefusal::RealmNotConfigured,
            ),
            (SelectError::AmbiguousRealm, KdcLeaseRefusal::AmbiguousRealm),
        ] {
            assert_eq!(error.refusal(), expected);
            assert_eq!(
                KdcLeaseRefusal::from_error(&error.broker_message()),
                Some(expected)
            );
        }
    }

    /// Only the RDP proxy leases KDC sockets: every other service of the
    /// bastion, and any near-miss of the name, is refused.
    #[test]
    fn attack_kdc_lease_from_another_service_is_rejected() {
        assert!(caller_may_lease("proxy_rdp"));
        for other in [
            "web",
            "access",
            "auth",
            "audit",
            "vault",
            "proxy_ssh",
            "proxy_iacs",
            "proxy_mcp",
            "mailer",
            "",
            "proxy_rdp ",
            " proxy_rdp",
            "PROXY_RDP",
            "proxy_rdp2",
            "proxy-rdp",
            "proxy_rdp\0",
        ] {
            assert!(!caller_may_lease(other), "{other:?} must not lease");
        }
    }

    // ---------------------------------------------------------------
    // connect_first_kdc
    // ---------------------------------------------------------------

    #[test]
    fn test_connect_first_kdc_uses_the_first_endpoint_when_it_answers() {
        let first = TcpListener::bind("127.0.0.1:0").unwrap();
        let second = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoints = vec![
            ("127.0.0.1".to_string(), first.local_addr().unwrap().port()),
            ("127.0.0.1".to_string(), second.local_addr().unwrap().port()),
        ];
        let conn = connect_first_kdc(&endpoints, Duration::from_secs(5)).unwrap();
        assert_eq!(conn.endpoint_index, 0);
        assert_eq!(conn.addr, first.local_addr().unwrap());
    }

    #[test]
    fn test_connect_first_kdc_fails_over_to_the_next_endpoint() {
        let live = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoints = vec![
            ("127.0.0.1".to_string(), closed_port()),
            ("no-such-host.vauban.invalid".to_string(), 88),
            ("127.0.0.1".to_string(), live.local_addr().unwrap().port()),
        ];
        let conn = connect_first_kdc(&endpoints, Duration::from_secs(5)).unwrap();
        assert_eq!(conn.endpoint_index, 2);
        assert_eq!(conn.addr, live.local_addr().unwrap());
    }

    #[test]
    fn test_connect_first_kdc_reports_every_endpoint_tried() {
        let endpoints = vec![
            ("127.0.0.1".to_string(), closed_port()),
            ("127.0.0.1".to_string(), closed_port()),
        ];
        let err = connect_first_kdc(&endpoints, Duration::from_secs(5)).unwrap_err();
        assert!(err.contains("tried 2/2"), "{err}");
    }

    #[test]
    fn test_connect_first_kdc_without_endpoint_is_an_error() {
        assert!(connect_first_kdc(&[], Duration::from_secs(1)).is_err());
    }

    #[test]
    fn test_connect_first_kdc_stops_when_the_budget_is_spent() {
        let endpoints = vec![("127.0.0.1".to_string(), closed_port())];
        let started = Instant::now();
        let err = connect_first_kdc(&endpoints, Duration::ZERO).unwrap_err();
        assert!(err.contains("tried 0/1"), "{err}");
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    /// Contention: many leases at once, the first endpoint dead. Every
    /// one lands on the live endpoint, none on anything else.
    #[test]
    fn battle_concurrent_leases_all_fail_over_to_the_live_kdc() {
        let live = TcpListener::bind("127.0.0.1:0").unwrap();
        let live_addr = live.local_addr().unwrap();
        let endpoints = std::sync::Arc::new(vec![
            ("127.0.0.1".to_string(), closed_port()),
            ("127.0.0.1".to_string(), live_addr.port()),
        ]);
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(16));
        let handles: Vec<_> = (0..16)
            .map(|_| {
                let endpoints = std::sync::Arc::clone(&endpoints);
                let barrier = std::sync::Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    connect_first_kdc(&endpoints, Duration::from_secs(10))
                })
            })
            .collect();
        for handle in handles {
            let conn = handle.join().unwrap().expect("lease must succeed");
            assert_eq!(conn.endpoint_index, 1);
            assert_eq!(conn.addr, live_addr);
        }
    }

    mod properties {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(256))]

            /// Whatever string the proxy sends as a realm, the selected
            /// endpoints are a configured list or nothing: never a host
            /// derived from the request.
            #[test]
            fn requested_realm_never_becomes_a_destination(raw in "\\PC{0,60}") {
                let cfg = config(&[
                    ("corp.example.com", &["dc1.corp.example.com"]),
                    ("lab.example.net", &["kdc.lab.example.net"]),
                ]);
                match select_endpoints(&cfg, Some(&raw)) {
                    Ok((_, endpoints)) => {
                        let configured = [
                            vec![("dc1.corp.example.com".to_string(), 88u16)],
                            vec![("kdc.lab.example.net".to_string(), 88u16)],
                        ];
                        prop_assert!(configured.contains(&endpoints));
                    }
                    Err(e) => prop_assert!(!e.broker_message().is_empty()),
                }
            }

            /// Realm matching is case-insensitive and nothing else.
            #[test]
            fn realm_lookup_ignores_case_only(upper in any::<bool>(), suffix in "[a-z]{0,6}") {
                let cfg = config(&[("corp.example.com", &["dc1.corp.example.com"])]);
                let base = if upper { "CORP.EXAMPLE.COM" } else { "corp.example.com" };
                let asked = format!("{base}{suffix}");
                let got = select_endpoints(&cfg, Some(&asked));
                if suffix.is_empty() {
                    prop_assert!(got.is_ok());
                } else {
                    prop_assert!(got.is_err());
                }
            }
        }
    }
}
