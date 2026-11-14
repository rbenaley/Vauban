//! Opt-in: the proxy's Kerberos client against a real MIT KDC, through
//! the real KDC socket path.
//!
//! The in-process harness (`credssp_loop_tests`) answers KDC requests
//! from memory. This one covers what it cannot:
//!
//! * a real Kerberos server checks the AS-REQ the proxy sends (encryption
//!   types, pre-authentication, salt);
//! * the exchange travels the production path: `SupervisorRelay` asks for
//!   a lease, a stand-in supervisor connects to the KDC and passes the
//!   socket over `SCM_RIGHTS`, and `kdc_framed_round_trip` does the
//!   framed I/O on the received descriptor.
//!
//! Scope: the AS exchange (getting a TGT). The service-ticket exchange is
//! user-to-user and needs the target to be a principal of the same KDC,
//! which `sspi`'s test server is not; after the TGT the leg fails and the
//! test stops looking.
//!
//! Run with:
//! `VAUBAN_TEST_MIT_KDC=1 cargo test ... -- --ignored mit_kdc --test-threads=1`

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::credssp_loop_tests::open_with;
use super::*;
use crate::auth_failure::{KdcReply, kdc_reply, krb_error};
use crate::test_support::mit_kdc::{MitKdc, OPT_IN_ENV};
use crate::test_support::{PASSWORD, REALM, TARGET_HOST, TargetPackages, USERNAME};
use std::os::fd::AsRawFd;
use std::sync::Mutex;

/// The production relay, with a note of what the KDC answered.
struct ObservedRelay {
    relay: Arc<SupervisorRelay>,
    replies: Mutex<Vec<KdcReply>>,
}

impl KdcTransport for ObservedRelay {
    fn kdc_round_trip<'a>(
        &'a self,
        session_id: &'a str,
        realm: &'a shared::kerberos::Realm,
        data: Vec<u8>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, String>> + Send + 'a>>
    {
        Box::pin(async move {
            let reply = SupervisorRelay::kdc_round_trip(&self.relay, session_id, realm, data).await;
            if let Ok(framed) = &reply {
                self.replies.lock().unwrap().push(kdc_reply(framed));
            }
            reply
        })
    }
}

struct MitRun {
    replies: Vec<KdcReply>,
    /// Realms of the leases the stand-in supervisor served.
    leases: Vec<String>,
    reason: Option<RdpAuthFailure>,
}

/// Open a Kerberos session whose KDC exchanges go to `kdc` through a
/// stand-in supervisor that passes connected sockets over `SCM_RIGHTS`.
async fn open_through_fd_broker(kdc: &MitKdc, username: &str, password: &str) -> MitRun {
    let (lease_tx, mut lease_rx) = mpsc::unbounded_channel::<Message>();
    let relay = Arc::new(SupervisorRelay::new(lease_tx));
    let leases = Arc::new(Mutex::new(Vec::new()));

    let (supervisor_end, proxy_end) = std::os::unix::net::UnixStream::pair().unwrap();
    let kdc_addr = kdc.addr;
    let supervisor = {
        let relay = Arc::clone(&relay);
        let leases = Arc::clone(&leases);
        tokio::spawn(async move {
            while let Some(message) = lease_rx.recv().await {
                let Message::KerberosKdcLeaseRequest {
                    request_id, realm, ..
                } = message
                else {
                    panic!("the relay sent something other than a KDC lease request");
                };
                leases.lock().unwrap().push(realm);
                // Supervisor side: connect, pass the socket, drop our copy.
                let socket = std::net::TcpStream::connect(kdc_addr).unwrap();
                shared::ipc::send_fd(supervisor_end.as_raw_fd(), socket.as_raw_fd()).unwrap();
                drop(socket);
                // Proxy side: receive the descriptor as `main.rs` does.
                let received = shared::recording_fd::recv_fd_timed(
                    proxy_end.as_raw_fd(),
                    std::time::Instant::now() + std::time::Duration::from_secs(5),
                )
                .map_err(|e| e.to_string());
                relay.complete(request_id, received).await;
            }
        })
    };

    let observed = Arc::new(ObservedRelay {
        relay,
        replies: Mutex::new(Vec::new()),
    });
    let transport: Arc<dyn KdcTransport> = observed.clone();
    let reason = open_with(
        RdpAuthMode::Kerberos,
        transport,
        TargetPackages::Kerberos,
        TARGET_HOST,
        username,
        password,
    )
    .await
    .reason;
    supervisor.abort();

    MitRun {
        replies: observed.replies.lock().unwrap().clone(),
        leases: leases.lock().unwrap().clone(),
        reason,
    }
}

fn require_opt_in() {
    assert!(
        MitKdc::opted_in(),
        "this test starts a local MIT KDC: set {OPT_IN_ENV}=1 to run it"
    );
}

/// The proxy obtains a TGT from a real KDC: the KDC demands
/// pre-authentication, accepts the proxy's AES timestamp and issues the
/// ticket. Each exchange uses a freshly leased socket for the realm.
#[tokio::test]
#[ignore = "starts a local MIT KDC; opt in with VAUBAN_TEST_MIT_KDC=1"]
async fn mit_kdc_issues_a_tgt_through_the_fd_broker() {
    require_opt_in();
    let kdc = MitKdc::start();
    let run = open_through_fd_broker(&kdc, USERNAME, PASSWORD).await;

    assert!(
        run.replies.len() >= 2,
        "pre-authentication demand, then the TGT: {:?}",
        run.replies
    );
    assert_eq!(
        run.replies[0],
        KdcReply::Error(krb_error::KDC_ERR_PREAUTH_REQUIRED)
    );
    assert_eq!(run.replies[1], KdcReply::AsRep, "{:?}", run.replies);
    assert!(
        run.leases.len() >= 2,
        "one lease per exchange: {:?}",
        run.leases
    );
    assert!(run.leases.iter().all(|realm| realm == REALM));
}

/// A wrong password is refused by the real KDC and classified.
#[tokio::test]
#[ignore = "starts a local MIT KDC; opt in with VAUBAN_TEST_MIT_KDC=1"]
async fn mit_kdc_refuses_a_wrong_password() {
    require_opt_in();
    let kdc = MitKdc::start();
    let run = open_through_fd_broker(&kdc, USERNAME, "not-the-password").await;

    assert_eq!(
        run.replies,
        [
            KdcReply::Error(krb_error::KDC_ERR_PREAUTH_REQUIRED),
            KdcReply::Error(krb_error::KDC_ERR_PREAUTH_FAILED),
        ]
    );
    assert_eq!(run.reason, Some(RdpAuthFailure::PreAuthFailed));
}

/// An account the real KDC does not know is classified.
#[tokio::test]
#[ignore = "starts a local MIT KDC; opt in with VAUBAN_TEST_MIT_KDC=1"]
async fn mit_kdc_does_not_know_the_account() {
    require_opt_in();
    let kdc = MitKdc::start();
    let run = open_through_fd_broker(&kdc, "nobody", PASSWORD).await;

    // `sspi` asks twice; the KDC gives the same answer each time.
    assert!(!run.replies.is_empty());
    assert!(
        run.replies
            .iter()
            .all(|r| *r == KdcReply::Error(krb_error::KDC_ERR_C_PRINCIPAL_UNKNOWN)),
        "{:?}",
        run.replies
    );
    assert_eq!(run.reason, Some(RdpAuthFailure::ClientPrincipalUnknown));
}
