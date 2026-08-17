//! Dual-stack TCP connect for the supervisor broker.
//!
//! `getaddrinfo("localhost")` commonly returns `[::1, 127.0.0.1]` on
//! macOS (IPv6 first). A sink bound only to `127.0.0.1` then fails if
//! the broker takes `.next()` and stops. Try every resolved address
//! until one connects; skip candidates the caller rejects (IACS
//! anti-SSRF) without treating that skip as a hard deny of later
//! addresses.

use std::io;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

/// Resolve `host:port` to every address `getaddrinfo` returns.
pub fn resolve_tcp_targets(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    let addrs: Vec<SocketAddr> = (host, port).to_socket_addrs()?.collect();
    if addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("DNS resolution failed for {host}: no addresses"),
        ));
    }
    Ok(addrs)
}

/// Per-address gate before `connect_timeout`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddrDecision {
    Accept,
    Skip(String),
}

/// Connect to the first accepted address that accepts a TCP handshake.
pub fn connect_first_reachable(
    addrs: &[SocketAddr],
    timeout: Duration,
    mut decide: impl FnMut(SocketAddr) -> AddrDecision,
) -> Result<(TcpStream, SocketAddr), ConnectAllError> {
    let mut last_io: Option<(SocketAddr, io::Error)> = None;
    let mut last_skip: Option<String> = None;
    let mut attempted = 0usize;
    for &addr in addrs {
        match decide(addr) {
            AddrDecision::Skip(reason) => {
                last_skip = Some(reason);
                continue;
            }
            AddrDecision::Accept => {}
        }
        attempted += 1;
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(stream) => return Ok((stream, addr)),
            Err(e) => last_io = Some((addr, e)),
        }
    }
    if attempted == 0 {
        return Err(ConnectAllError::AllSkipped(
            last_skip.unwrap_or_else(|| "Access denied".into()),
        ));
    }
    let Some((addr, err)) = last_io else {
        return Err(ConnectAllError::AllSkipped(
            last_skip.unwrap_or_else(|| "Access denied".into()),
        ));
    };
    Err(ConnectAllError::AllFailed {
        last_addr: addr,
        last_error: err,
        attempted,
        resolved: addrs.len(),
    })
}

/// Why every candidate failed.
#[derive(Debug)]
pub enum ConnectAllError {
    AllSkipped(String),
    AllFailed {
        last_addr: SocketAddr,
        last_error: io::Error,
        attempted: usize,
        resolved: usize,
    },
}

impl ConnectAllError {
    pub fn broker_message(&self) -> String {
        match self {
            Self::AllSkipped(reason) => reason.clone(),
            Self::AllFailed {
                last_addr,
                last_error,
                attempted,
                resolved,
            } => format!(
                "Connection to {last_addr} failed: {last_error} \
                 (tried {attempted}/{resolved} resolved addresses)"
            ),
        }
    }

    pub fn is_access_denied(&self) -> bool {
        matches!(self, Self::AllSkipped(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, TcpListener};
    use std::sync::{Arc, Barrier};
    use std::thread;

    fn unused_ipv4() -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, 1))
    }

    fn unused_ipv6() -> SocketAddr {
        SocketAddr::from((Ipv6Addr::LOCALHOST, 1))
    }

    fn accept_once(listener: TcpListener) {
        let _ = listener.accept();
    }

    #[test]
    fn resolve_tcp_targets_localhost_is_non_empty() {
        let addrs = resolve_tcp_targets("localhost", 1025).expect("localhost must resolve");
        assert!(!addrs.is_empty());
        assert!(
            addrs.iter().all(|a| a.port() == 1025),
            "port must be applied to every resolved address"
        );
    }

    #[test]
    fn resolve_tcp_targets_does_not_stop_at_first_localhost_record() {
        let src = include_str!("tcp_resolve.rs");
        let fn_start = src
            .find("pub fn resolve_tcp_targets")
            .expect("resolve_tcp_targets must exist");
        let body = &src[fn_start..];
        let fn_end = body.find("\npub fn ").unwrap_or(body.len());
        let body = &body[..fn_end];
        assert!(
            body.contains("to_socket_addrs") && body.contains("collect()"),
            "resolve_tcp_targets MUST collect every getaddrinfo record"
        );
        assert!(
            !body.contains(".next()"),
            "resolve_tcp_targets MUST NOT take only addrs.next() \
             (that is the localhost IPv6-first regression)"
        );
    }

    #[test]
    fn connect_first_reachable_skips_refused_then_uses_ipv4() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind ipv4");
        let good = listener.local_addr().expect("local_addr");
        thread::spawn(move || accept_once(listener));

        let addrs = [unused_ipv6(), unused_ipv4(), good];
        let (stream, used) =
            connect_first_reachable(&addrs, Duration::from_secs(2), |_| AddrDecision::Accept)
                .expect("IPv4 listener must be reached after refused ::1 / 127.0.0.1:1");
        assert_eq!(used, good);
        assert_eq!(stream.peer_addr().expect("peer"), good);
    }

    #[test]
    fn connect_first_reachable_all_refused_is_rejected() {
        let addrs = [unused_ipv6(), unused_ipv4()];
        let err =
            connect_first_reachable(&addrs, Duration::from_millis(200), |_| AddrDecision::Accept)
                .expect_err("closed ports must fail");
        assert!(!err.is_access_denied());
        let msg = err.broker_message();
        assert!(msg.contains("tried 2/2"), "{msg}");
        assert!(msg.contains("Connection to"), "{msg}");
    }

    #[test]
    fn connect_first_reachable_all_skipped_is_access_denied() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        let good = listener.local_addr().expect("local_addr");
        let err = connect_first_reachable(&[good], Duration::from_secs(1), |_| {
            AddrDecision::Skip("Access denied".into())
        })
        .expect_err("skip-all must not connect");
        assert!(err.is_access_denied());
        assert_eq!(err.broker_message(), "Access denied");
    }

    #[test]
    fn connect_first_reachable_skips_then_accepts_later() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        let good = listener.local_addr().expect("local_addr");
        thread::spawn(move || accept_once(listener));

        let forbidden = SocketAddr::from((Ipv4Addr::LOCALHOST, 9));
        let (stream, used) =
            connect_first_reachable(&[forbidden, good], Duration::from_secs(2), |addr| {
                if addr.port() == 9 {
                    AddrDecision::Skip("loopback".into())
                } else {
                    AddrDecision::Accept
                }
            })
            .expect("later accepted address must win");
        assert_eq!(used, good);
        drop(stream);
    }

    #[test]
    fn battle_connect_first_reachable_under_contention() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        let good = listener.local_addr().expect("local_addr");
        let n = 8;
        let barrier = Arc::new(Barrier::new(n + 1));
        let accept_barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            accept_barrier.wait();
            for _ in 0..n {
                let _ = listener.accept();
            }
        });

        let join: Vec<_> = (0..n)
            .map(|_| {
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    connect_first_reachable(&[unused_ipv6(), good], Duration::from_secs(3), |_| {
                        AddrDecision::Accept
                    })
                })
            })
            .collect();

        for h in join {
            let (stream, used) = h.join().expect("thread").expect("connect");
            assert_eq!(used, good);
            drop(stream);
        }
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;
    use std::net::{Ipv4Addr, Ipv6Addr, TcpListener};
    use std::thread;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(24))]

        #[test]
        fn proptest_good_listener_wins_regardless_of_dead_neighbors(
            n_before in 0usize..3,
            n_after in 0usize..3,
        ) {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .expect("bind");
            let good = listener.local_addr().expect("local_addr");
            thread::spawn(move || {
                let _ = listener.accept();
            });
            let mut addrs = vec![SocketAddr::from((Ipv6Addr::LOCALHOST, 1)); n_before];
            addrs.push(good);
            addrs.extend(std::iter::repeat_n(
                SocketAddr::from((Ipv4Addr::LOCALHOST, 1)),
                n_after,
            ));
            let result = connect_first_reachable(
                &addrs,
                Duration::from_secs(2),
                |_| AddrDecision::Accept,
            );
            let (_, used) = result.expect("good listener must be reached");
            prop_assert_eq!(used, good);
        }
    }
}
