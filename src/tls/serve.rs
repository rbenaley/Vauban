//! HTTPS accept loop for Topcoat `RouterService` (TLS 1.3 only).

use std::future::Future;
use std::io;
use std::pin::pin;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;
use topcoat::router::RouterService;
use tracing::debug;

use super::access_log::{AccessLog, AccessLogService};

const DEFAULT_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);

/// Emit a coalesced line after this much quiet time for the same error.
pub const HANDSHAKE_LOG_IDLE: Duration = Duration::from_millis(150);

type EmitFn = Arc<dyn Fn(&str, u32) + Send + Sync>;

/// Captured coalesced emits for tests: `(error, count)`.
pub type HandshakeCapture = Arc<Mutex<Vec<(String, u32)>>>;

struct PendingHandshakeFailures {
    error: String,
    count: u32,
    last_seen: Instant,
    flush_scheduled: bool,
}

/// Coalesces identical TLS handshake failures into one emit with `count=N`.
///
/// Production uses the process-global instance via [`note_handshake_failure`].
/// Tests construct a capturing instance via [`HandshakeFailureLog::capturing`].
pub struct HandshakeFailureLog {
    pending: Mutex<Option<PendingHandshakeFailures>>,
    emit: EmitFn,
    idle: Duration,
    /// When true, schedule a Tokio task to flush after the idle window.
    async_idle: bool,
}

impl HandshakeFailureLog {
    fn new(idle: Duration, async_idle: bool, emit: EmitFn) -> Self {
        Self {
            pending: Mutex::new(None),
            emit,
            idle,
            async_idle,
        }
    }

    /// Production logger: `debug!` emit + async idle flush.
    pub fn production() -> Arc<Self> {
        Arc::new(Self::new(
            HANDSHAKE_LOG_IDLE,
            true,
            Arc::new(|error, count| {
                debug!("TLS handshake failed error={error} count={count}");
            }),
        ))
    }

    /// Capturing logger for tests (no async idle; call [`Self::flush`] / [`Self::tick`]).
    pub fn capturing(idle: Duration) -> (Arc<Self>, HandshakeCapture) {
        let captured: HandshakeCapture = Arc::new(Mutex::new(Vec::new()));
        let sink = captured.clone();
        let log = Arc::new(Self::new(
            idle,
            false,
            Arc::new(move |error, count| {
                sink.lock()
                    .expect("capture poisoned")
                    .push((error.to_owned(), count));
            }),
        ));
        (log, captured)
    }

    /// Record a handshake failure (Arc form — required when `async_idle` is set).
    pub fn note(self: &Arc<Self>, error: String) {
        let mut schedule = false;
        {
            let mut slot = self.pending.lock().expect("handshake coalescer poisoned");
            match slot.as_mut() {
                Some(pending) if pending.error == error => {
                    pending.count = pending.count.saturating_add(1);
                    pending.last_seen = Instant::now();
                    if self.async_idle && !pending.flush_scheduled {
                        pending.flush_scheduled = true;
                        schedule = true;
                    }
                }
                Some(_) => {
                    let prev = slot.take();
                    if let Some(prev) = prev {
                        (self.emit)(&prev.error, prev.count);
                    }
                    *slot = Some(PendingHandshakeFailures {
                        error,
                        count: 1,
                        last_seen: Instant::now(),
                        flush_scheduled: self.async_idle,
                    });
                    schedule = self.async_idle;
                }
                None => {
                    *slot = Some(PendingHandshakeFailures {
                        error,
                        count: 1,
                        last_seen: Instant::now(),
                        flush_scheduled: self.async_idle,
                    });
                    schedule = self.async_idle;
                }
            }
        }
        if schedule {
            let idle = self.idle;
            let this = Arc::clone(self);
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(idle).await;
                    if this.tick() {
                        return;
                    }
                }
            });
        }
    }

    /// Flush any pending batch immediately (shutdown / tests).
    pub fn flush(&self) {
        let pending = self
            .pending
            .lock()
            .expect("handshake coalescer poisoned")
            .take();
        if let Some(pending) = pending {
            (self.emit)(&pending.error, pending.count);
        }
    }

    /// If pending and idle window elapsed, flush and return true.
    /// Returns true when there is nothing left to wait for.
    pub fn tick(&self) -> bool {
        let mut slot = self.pending.lock().expect("handshake coalescer poisoned");
        let Some(pending) = slot.as_mut() else {
            return true;
        };
        if pending.last_seen.elapsed() < self.idle {
            return false;
        }
        let pending = slot.take().expect("pending checked above");
        drop(slot);
        (self.emit)(&pending.error, pending.count);
        true
    }
}

static HANDSHAKE_LOG: OnceLock<Arc<HandshakeFailureLog>> = OnceLock::new();

fn global_handshake_log() -> &'static Arc<HandshakeFailureLog> {
    HANDSHAKE_LOG.get_or_init(HandshakeFailureLog::production)
}

/// Record a handshake failure on the process-global coalescer.
pub fn note_handshake_failure(error: String) {
    global_handshake_log().note(error);
}

fn flush_handshake_failures() {
    global_handshake_log().flush();
}

/// Serve a Topcoat router over TLS until `shutdown` completes.
pub async fn serve_https(
    listener: TcpListener,
    tls_config: Arc<ServerConfig>,
    service: impl Into<RouterService>,
    access_log: AccessLog,
    shutdown: impl Future<Output = ()>,
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
        let (stream, remote) = accepted?;
        let acceptor = acceptor.clone();
        let service = AccessLogService::new(service.clone(), remote, access_log.clone());

        let mut drain_rx = drain_rx.clone();
        let mut cutoff_rx = cutoff_rx.clone();
        let done_rx = done_rx.clone();

        tokio::spawn(async move {
            let _done_rx = done_rx;

            let tls_stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(error) => {
                    note_handshake_failure(error.to_string());
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

    flush_handshake_failures();
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn coalesces_identical_errors_until_flush() {
        let (log, captured) = HandshakeFailureLog::capturing(Duration::from_secs(60));
        for _ in 0..10 {
            log.note("peer is incompatible: NoKxGroupsInCommon".to_owned());
        }
        assert!(captured.lock().unwrap().is_empty());
        log.flush();
        assert_eq!(
            *captured.lock().unwrap(),
            vec![("peer is incompatible: NoKxGroupsInCommon".to_owned(), 10)]
        );
    }

    #[test]
    fn different_error_flushes_previous_batch() {
        let (log, captured) = HandshakeFailureLog::capturing(Duration::from_secs(60));
        log.note("NoKxGroupsInCommon".to_owned());
        log.note("NoKxGroupsInCommon".to_owned());
        log.note("Tls12NotOffered".to_owned());
        assert_eq!(
            *captured.lock().unwrap(),
            vec![("NoKxGroupsInCommon".to_owned(), 2)]
        );
        log.flush();
        assert_eq!(
            *captured.lock().unwrap(),
            vec![
                ("NoKxGroupsInCommon".to_owned(), 2),
                ("Tls12NotOffered".to_owned(), 1),
            ]
        );
    }

    #[test]
    fn flush_empty_is_noop() {
        let (log, captured) = HandshakeFailureLog::capturing(Duration::from_millis(1));
        log.flush();
        assert!(captured.lock().unwrap().is_empty());
    }

    #[test]
    fn tick_flushes_after_idle() {
        let (log, captured) = HandshakeFailureLog::capturing(Duration::from_millis(1));
        log.note("idle-error".to_owned());
        std::thread::sleep(Duration::from_millis(5));
        assert!(log.tick());
        assert_eq!(
            *captured.lock().unwrap(),
            vec![("idle-error".to_owned(), 1)]
        );
    }
}
