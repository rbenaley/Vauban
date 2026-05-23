//! Protocol recognition gate on the EWS -> asset relay leg.
//!
//! Typed IACS assets MUST speak the expected wire protocol family on
//! the first frames. After confirmation the gate switches to full
//! passthrough (no command filtering).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use shared::iacs_protocol::{
    ConformityDecision, ExpectedProfile, WireProtocol, classify_peek, evaluate_conformity,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::{info, warn};
use uuid::Uuid;

use crate::registry::TunnelHandle;
use crate::relay::copy_with_counter;

/// Maximum bytes buffered while classifying a channel.
pub const CLASSIFY_MAX_BYTES: usize = 4096;

/// Wall-clock budget for protocol confirmation per channel.
pub const CLASSIFY_TIMEOUT: Duration = Duration::from_secs(5);

/// Outcome of a gated copy on the EWS -> asset leg.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolGateOutcome {
    /// Bytes relayed successfully (includes passthrough profiles).
    Relayed,
    /// Detected foreign industrial protocol.
    ForeignProtocol { detected: WireProtocol },
    /// Deadline or buffer limit hit without confirming expected protocol.
    Unconfirmed,
}

/// Copy from EWS to asset with a one-time protocol recognition gate.
pub async fn filtered_copy_with_counter<R, W>(
    read: R,
    mut write: W,
    counter: Arc<AtomicU64>,
    handle: TunnelHandle,
    expected: ExpectedProfile,
    session_uuid: Uuid,
) -> ProtocolGateOutcome
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    if expected == ExpectedProfile::Passthrough {
        let _ = copy_with_counter(read, write, counter, handle).await;
        return ProtocolGateOutcome::Relayed;
    }

    let mut read = read;
    let mut buf = Vec::new();
    let deadline = Instant::now() + CLASSIFY_TIMEOUT;
    let mut scratch = [0u8; 4096];

    loop {
        if handle.is_closed() {
            return ProtocolGateOutcome::Relayed;
        }

        let detected = classify_peek(&buf);
        let still_classifying = Instant::now() < deadline && buf.len() < CLASSIFY_MAX_BYTES;
        match evaluate_conformity(expected, detected, still_classifying) {
            ConformityDecision::AllowPassthrough | ConformityDecision::Confirmed => {
                if !buf.is_empty() {
                    if write.write_all(&buf).await.is_err() {
                        return ProtocolGateOutcome::Relayed;
                    }
                    counter.fetch_add(buf.len() as u64, Ordering::Relaxed);
                }
                info!(
                    session_uuid = %session_uuid,
                    expected = ?expected,
                    detected = detected.as_str(),
                    "iacs_protocol_confirmed"
                );
                let _ = copy_with_counter(read, write, counter, handle).await;
                return ProtocolGateOutcome::Relayed;
            }
            ConformityDecision::ForeignProtocol => {
                warn!(
                    session_uuid = %session_uuid,
                    expected = ?expected,
                    detected = detected.as_str(),
                    "iacs_protocol_mismatch"
                );
                return ProtocolGateOutcome::ForeignProtocol { detected };
            }
            ConformityDecision::Unconfirmed => {
                warn!(
                    session_uuid = %session_uuid,
                    expected = ?expected,
                    buffered = buf.len(),
                    "iacs_protocol_unconfirmed"
                );
                return ProtocolGateOutcome::Unconfirmed;
            }
            ConformityDecision::NeedMoreData => {
                if !still_classifying {
                    warn!(
                        session_uuid = %session_uuid,
                        expected = ?expected,
                        buffered = buf.len(),
                        "iacs_protocol_unconfirmed"
                    );
                    return ProtocolGateOutcome::Unconfirmed;
                }
                let n = tokio::select! {
                    biased;
                    _ = handle.wait_close() => break,
                    n = read.read(&mut scratch) => match n {
                        Ok(n) => n,
                        Err(_) => return ProtocolGateOutcome::Unconfirmed,
                    },
                };
                if n == 0 {
                    return ProtocolGateOutcome::Unconfirmed;
                }
                buf.extend_from_slice(&scratch[..n]);
            }
        }
    }

    ProtocolGateOutcome::Relayed
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    fn handle() -> TunnelHandle {
        TunnelHandle::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            None,
        )
    }

    #[tokio::test]
    async fn passthrough_profile_relays_arbitrary_bytes() {
        let (mut client, server) = duplex(256);
        let (upstream, mut upstream_read) = duplex(256);
        let counter = Arc::new(AtomicU64::new(0));
        let h = handle();
        let pump = tokio::spawn(async move {
            filtered_copy_with_counter(
                server,
                upstream,
                counter,
                h,
                ExpectedProfile::Passthrough,
                Uuid::new_v4(),
            )
            .await
        });
        client.write_all(b"HELLO").await.unwrap();
        drop(client);
        assert_eq!(pump.await.unwrap(), ProtocolGateOutcome::Relayed);
        let mut got = vec![0u8; 5];
        upstream_read.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"HELLO");
    }

    #[tokio::test]
    async fn modbus_profile_rejects_opc_ua_prefix() {
        let (mut client, server) = duplex(64);
        let (upstream, _upstream_read) = duplex(64);
        let counter = Arc::new(AtomicU64::new(0));
        let h = handle();
        let pump = tokio::spawn(async move {
            filtered_copy_with_counter(
                server,
                upstream,
                counter,
                h,
                ExpectedProfile::Modbus,
                Uuid::new_v4(),
            )
            .await
        });
        client.write_all(b"HEL").await.unwrap();
        drop(client);
        assert!(matches!(
            pump.await.unwrap(),
            ProtocolGateOutcome::ForeignProtocol {
                detected: WireProtocol::OpcUa
            }
        ));
    }
}
