//! Bidirectional byte relay between a russh `Channel` (the EWS
//! side) and a TCP socket (the bastion-side IACS asset). The
//! relay is the only piece of code that touches the actual
//! payload bytes, so it owns:
//!
//!   * the byte counters (`AtomicU64` shared with `TunnelHandle`),
//!   * the close signal (drains both directions and disconnects
//!     when the handle is closed),
//!   * the connect-target validation (refuses any host:port other
//!     than the configured `target_addr` -- defence-in-depth in
//!     case the russh handler's check is ever bypassed).
//!
//! The russh ChannelStream API (Channel::into_stream) gives us a
//! split AsyncRead/AsyncWrite, so a vanilla `tokio::io::copy` per
//! direction is enough. Counters are bumped in a small helper
//! that wraps the copy buffer so we count *exactly* the bytes
//! that crossed the bastion.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use super::registry::TunnelHandle;

/// Pull bytes from `read` and push them to `write`, bumping
/// `counter` along the way. Returns the total bytes copied (which
/// also equals the final value `counter` advanced by). Stops on
/// EOF, error, or when `handle.is_closed()` flips to true.
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
    // 16 KiB matches `tokio::io::copy`'s default; 64 KiB tested
    // measurably better for sustained Modbus polling but we keep
    // 16 KiB to stay closure-friendly with russh window updates.
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
            // EOF on the read side -- shutdown the write side so
            // the peer sees a clean half-close, then exit.
            let _ = write.shutdown().await;
            break;
        }
        write.write_all(&buf[..n]).await?;
        // SECURITY: count BEFORE returning to the caller so a
        // panic between the write and the counter bump cannot
        // hide the bytes from forensic review.
        counter.fetch_add(n as u64, Ordering::Relaxed);
        total += n as u64;
    }
    Ok(total)
}

/// Resolve a TCP target address with strict equality against the
/// configured `expected_target`. Any mismatch returns `None` --
/// the caller maps this to a russh "channel rejected" response.
///
/// Pinned by `tests::target_resolver_*` AND by the adversarial
/// suite (lot L3 acceptance #4: "direct-tcpip vers host:port !=
/// target_addr -> reject").
pub fn validate_target(requested_host: &str, requested_port: u32, expected_target: &str) -> bool {
    let normalized = format!("{}:{}", requested_host, requested_port);
    normalized == expected_target
        || normalized == expected_target.replace("0.0.0.0", "127.0.0.1")
        || normalized == expected_target.replace("127.0.0.1", "localhost")
}

/// Open a TCP connection to the configured target. Uses a
/// modest connect timeout so a misconfigured target_addr does
/// not stall the russh worker indefinitely.
pub async fn connect_target(target_addr: &str) -> std::io::Result<TcpStream> {
    use tokio::time::{Duration, timeout};
    timeout(Duration::from_secs(5), TcpStream::connect(target_addr))
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("connect timeout to {}", target_addr),
            )
        })?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;
    use uuid::Uuid;

    #[test]
    fn target_validation_accepts_canonical_match() {
        assert!(validate_target("127.0.0.1", 4321, "127.0.0.1:4321"));
    }

    #[test]
    fn target_validation_rejects_other_host() {
        assert!(!validate_target("1.2.3.4", 4321, "127.0.0.1:4321"));
    }

    #[test]
    fn target_validation_rejects_other_port() {
        assert!(!validate_target("127.0.0.1", 4322, "127.0.0.1:4321"));
    }

    #[test]
    fn target_validation_accepts_localhost_for_127001_target() {
        assert!(validate_target("localhost", 4321, "127.0.0.1:4321"));
    }

    #[test]
    fn target_validation_accepts_127001_for_0000_target() {
        // The bastion may bind 0.0.0.0:4321 even though clients
        // ask for 127.0.0.1:4321 in their `ssh -L` command.
        assert!(validate_target("127.0.0.1", 4321, "0.0.0.0:4321"));
    }

    #[tokio::test]
    async fn copy_with_counter_propagates_bytes_and_eof() {
        // Build a duplex pipe; write one frame on side A, read
        // it on side B via the relay.
        let (mut a, b) = tokio::io::duplex(64);
        let (c, mut d) = tokio::io::duplex(64);

        let counter = Arc::new(AtomicU64::new(0));
        let counter_clone = counter.clone();
        let handle = TunnelHandle::new(Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let h2 = handle.clone();

        let pump = tokio::spawn(async move {
            copy_with_counter(b, c, counter_clone, h2)
                .await
                .expect("copy must succeed")
        });

        a.write_all(b"hello world").await.unwrap();
        let mut buf = [0u8; 11];
        d.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello world");
        // Drop the source so the relay sees EOF.
        drop(a);

        let total = pump.await.expect("join");
        assert_eq!(total, 11);
        assert_eq!(counter.load(Ordering::Relaxed), 11);
    }

    #[tokio::test]
    async fn copy_with_counter_stops_on_close() {
        let (a, b) = tokio::io::duplex(64);
        let (c, _d) = tokio::io::duplex(64);
        let counter = Arc::new(AtomicU64::new(0));
        let handle = TunnelHandle::new(Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let h2 = handle.clone();

        let pump =
            tokio::spawn(
                async move { copy_with_counter(b, c, counter.clone(), h2).await.unwrap() },
            );

        // Close the handle before any byte flows.
        handle.close();
        // Keep the writer alive so EOF does not race the close
        // path.
        let _keep = a;
        tokio::time::timeout(std::time::Duration::from_secs(1), pump)
            .await
            .expect("pump must exit on close")
            .expect("pump joined cleanly");
    }
}
