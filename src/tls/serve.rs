//! HTTPS accept loop for Topcoat `RouterService` (TLS 1.3 only).

use std::future::Future;
use std::io;
use std::pin::pin;
use std::sync::Arc;
use std::time::Duration;

use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;
use topcoat::router::RouterService;
use tracing::{debug, warn};

const DEFAULT_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);

/// Serve a Topcoat router over TLS until `shutdown` completes.
///
/// When `quiet_self_signed_rejections` is true (development + ACME off),
/// client alerts that reject the local self-signed cert are logged at
/// debug instead of warn.
pub async fn serve_https(
    listener: TcpListener,
    tls_config: Arc<ServerConfig>,
    service: impl Into<RouterService>,
    shutdown: impl Future<Output = ()>,
    quiet_self_signed_rejections: bool,
) -> io::Result<()> {
    let addr = listener.local_addr().ok();
    topcoat::dev::notify_ready(addr).await;

    let service = service.into();
    let acceptor = TlsAcceptor::from(tls_config);

    let (drain_tx, drain_rx) = watch::channel(());
    let (cutoff_tx, cutoff_rx) = watch::channel(());
    let (done_tx, done_rx) = watch::channel(());

    let mut shutdown = pin!(shutdown);

    loop {
        let accepted = tokio::select! {
            accepted = listener.accept() => accepted,
            () = &mut shutdown => break,
        };
        let (stream, _remote) = accepted?;
        let acceptor = acceptor.clone();
        let service = service.clone();

        let mut drain_rx = drain_rx.clone();
        let mut cutoff_rx = cutoff_rx.clone();
        let done_rx = done_rx.clone();

        tokio::spawn(async move {
            let _done_rx = done_rx;

            let tls_stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(error) => {
                    log_handshake_failure(&error, quiet_self_signed_rejections);
                    return;
                }
            };

            let io = TokioIo::new(tls_stream);
            let builder = auto::Builder::new(TokioExecutor::new());
            let mut connection = pin!(builder.serve_connection(io, service));

            let result = tokio::select! {
                result = connection.as_mut() => result,
                _ = drain_rx.changed() => {
                    connection.as_mut().graceful_shutdown();
                    tokio::select! {
                        result = connection.as_mut() => result,
                        _ = cutoff_rx.changed() => return,
                    }
                }
            };

            if let Err(_error) = result {
                // Benign client disconnects are common; keep quiet for now.
            }
        });
    }

    drop(listener);
    drop(drain_rx);
    drop(drain_tx);
    drop(done_rx);
    tokio::select! {
        () = done_tx.closed() => {}
        () = tokio::time::sleep(DEFAULT_SHUTDOWN_TIMEOUT) => {}
    }
    drop(cutoff_rx);
    drop(cutoff_tx);
    Ok(())
}

/// Default process shutdown signal (Ctrl+C / SIGTERM).
pub async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
}

fn log_handshake_failure(error: &impl std::fmt::Display, quiet_self_signed_rejections: bool) {
    if quiet_self_signed_rejections && is_self_signed_rejection(error) {
        debug!(%error, "TLS handshake failed");
        return;
    }
    warn!(%error, "TLS handshake failed");
}

fn is_self_signed_rejection(error: &impl std::fmt::Display) -> bool {
    error.to_string().contains("CertificateUnknown")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_certificate_unknown_alert() {
        assert!(is_self_signed_rejection(
            &"received fatal alert: CertificateUnknown"
        ));
        assert!(!is_self_signed_rejection(
            &"peer is incompatible: SupportedVersionsExtensionRequired"
        ));
    }
}
