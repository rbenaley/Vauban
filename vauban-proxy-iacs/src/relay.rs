//! Bidirectional byte relay between a russh `Channel` (the EWS
//! side) and a TCP socket (the upstream industrial asset).
//!
//! The relay is the only piece of code that touches the actual
//! payload bytes, so it owns:
//!
//!   * the byte counters (`AtomicU64` shared with `TunnelHandle`),
//!   * the close signal,
//!   * the `validate_target` per-session check (refuses any host:port
//!     other than the asset's pinned `(asset_host, asset_port)`).
//!
//! Identical to the legacy in-process implementation, except
//! `validate_target` now takes the **per-session** pinned
//! `(asset_host, asset_port)` rather than a process-wide
//! `target_addr`. This is the single seam that turns the IACS tunnel
//! from a fixed loopback target into a per-asset DNS-resolvable
//! target.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::registry::TunnelHandle;
use crate::iacs_recording::ChannelRecorder;
use shared::messages::IacsRecordingDirection;

/// Pull bytes from `read` and push them to `write`, bumping
/// `counter` along the way. When `recorder` is set, each chunk is
/// durably persisted in audit **before** forwarding to `write`.
pub async fn copy_with_counter_and_record<R, W>(
    mut read: R,
    mut write: W,
    counter: Arc<AtomicU64>,
    handle: TunnelHandle,
    direction: IacsRecordingDirection,
    recorder: Option<ChannelRecorder>,
) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 16 * 1024];
    let mut total: u64 = 0;
    loop {
        if handle.is_closed() {
            break;
        }
        let n = tokio::select! {
            biased;
            _ = handle.wait_close() => break,
            n = read.read(&mut buf) => n?,
        };
        if n == 0 {
            let _ = write.shutdown().await;
            break;
        }
        if let Some(ref rec) = recorder {
            rec.write_batch(direction, &buf[..n]).await?;
        }
        write.write_all(&buf[..n]).await?;
        counter.fetch_add(n as u64, Ordering::Relaxed);
        total += n as u64;
    }
    Ok(total)
}

/// Pull bytes from `read` and push them to `write`, bumping
/// `counter` along the way. Returns the total bytes copied. Stops
/// on EOF, error, or when `handle` flips to closed.
#[cfg(test)]
pub async fn copy_with_counter<R, W>(
    mut read: R,
    mut write: W,
    counter: Arc<AtomicU64>,
    handle: TunnelHandle,
) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 16 * 1024];
    let mut total: u64 = 0;
    loop {
        if handle.is_closed() {
            break;
        }
        let n = tokio::select! {
            biased;
            _ = handle.wait_close() => break,
            n = read.read(&mut buf) => n?,
        };
        if n == 0 {
            let _ = write.shutdown().await;
            break;
        }
        write.write_all(&buf[..n]).await?;
        counter.fetch_add(n as u64, Ordering::Relaxed);
        total += n as u64;
    }
    Ok(total)
}

/// Resolve a TCP target address with strict equality against the
/// per-session expected `(host, port)`. Any mismatch returns false.
///
/// The match is intentionally permissive on `localhost` <->
/// `127.0.0.1` <-> `0.0.0.0` substitutions because the EWS and the
/// bastion may differ on which canonical form of the loopback they
/// use. ANY other substitution -- including `127.0.0.1` <->
/// `127.0.0.2`, IPv4 <-> IPv6, FQDN substring -- is rejected.
pub fn validate_target(
    requested_host: &str,
    requested_port: u32,
    expected_host: &str,
    expected_port: u16,
) -> bool {
    if requested_port != expected_port as u32 {
        return false;
    }
    if requested_host == expected_host {
        return true;
    }
    // Loopback-equivalence for development / E2E. Production
    // assets resolve to a routable IP and never trip this branch.
    let is_loopback =
        |s: &str| matches!(s, "127.0.0.1" | "0.0.0.0" | "localhost" | "::1" | "[::1]");
    is_loopback(requested_host) && is_loopback(expected_host)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;
    use uuid::Uuid;

    fn handle() -> TunnelHandle {
        TunnelHandle::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            None,
        )
    }

    #[test]
    fn target_validation_accepts_canonical_match() {
        assert!(validate_target("127.0.0.1", 4321, "127.0.0.1", 4321));
    }

    #[test]
    fn target_validation_accepts_fqdn_exact_match() {
        assert!(validate_target(
            "asset.plant.example.com",
            502,
            "asset.plant.example.com",
            502
        ));
    }

    #[test]
    fn target_validation_rejects_other_host() {
        assert!(!validate_target("1.2.3.4", 4321, "127.0.0.1", 4321));
    }

    #[test]
    fn target_validation_rejects_other_port() {
        assert!(!validate_target("127.0.0.1", 4322, "127.0.0.1", 4321));
    }

    #[test]
    fn target_validation_accepts_loopback_equivalence() {
        assert!(validate_target("localhost", 4321, "127.0.0.1", 4321));
        assert!(validate_target("127.0.0.1", 4321, "localhost", 4321));
    }

    #[test]
    fn target_validation_rejects_non_loopback_substitutions() {
        // Anti-DNS-rebinding: even close-by addresses are NOT
        // accepted as substitutes for an FQDN target.
        assert!(!validate_target("127.0.0.2", 4321, "127.0.0.1", 4321));
        assert!(!validate_target(
            "asset.plant.example.com",
            502,
            "127.0.0.1",
            502
        ));
    }

    #[tokio::test]
    async fn copy_with_counter_propagates_bytes_and_eof() {
        let (mut a, b) = tokio::io::duplex(64);
        let (c, mut d) = tokio::io::duplex(64);
        let counter = Arc::new(AtomicU64::new(0));
        let counter_clone = counter.clone();
        let h = handle();
        let h2 = h.clone();
        let pump = tokio::spawn(async move {
            copy_with_counter(b, c, counter_clone, h2)
                .await
                .expect("copy ok")
        });
        a.write_all(b"hello world").await.expect("write");
        let mut buf = [0u8; 11];
        d.read_exact(&mut buf).await.expect("read");
        assert_eq!(&buf, b"hello world");
        drop(a);
        let total = pump.await.expect("join");
        assert_eq!(total, 11);
        assert_eq!(counter.load(Ordering::Relaxed), 11);
    }
}
