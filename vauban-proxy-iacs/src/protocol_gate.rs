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

use crate::iacs_recording::ChannelRecorder;
use crate::registry::TunnelHandle;
use crate::relay::copy_with_counter_and_record;
use shared::messages::IacsRecordingDirection;

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

fn log_protocol_unconfirmed(
    session_uuid: Uuid,
    expected: ExpectedProfile,
    buffered: usize,
    cause: &'static str,
) -> ProtocolGateOutcome {
    warn!(
        session_uuid = %session_uuid,
        expected = ?expected,
        buffered = buffered,
        cause = cause,
        "iacs_protocol_unconfirmed"
    );
    ProtocolGateOutcome::Unconfirmed
}

/// Copy from EWS to asset with a one-time protocol recognition gate.
pub async fn filtered_copy_with_counter<R, W>(
    read: R,
    mut write: W,
    counter: Arc<AtomicU64>,
    handle: TunnelHandle,
    expected: ExpectedProfile,
    session_uuid: Uuid,
    recorder: Option<ChannelRecorder>,
) -> ProtocolGateOutcome
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    if expected == ExpectedProfile::Passthrough {
        let _ = copy_with_counter_and_record(
            read,
            write,
            counter,
            handle,
            IacsRecordingDirection::EwsToAsset,
            recorder,
        )
        .await;
        return ProtocolGateOutcome::Relayed;
    }

    let mut read = read;
    let mut buf = Vec::new();
    let deadline = Instant::now() + CLASSIFY_TIMEOUT;
    let mut scratch = [0u8; 4096];

    loop {
        if handle.is_closed() {
            return log_protocol_unconfirmed(session_uuid, expected, buf.len(), "handle_closed");
        }

        let detected = classify_peek(&buf);
        let still_classifying = Instant::now() < deadline && buf.len() < CLASSIFY_MAX_BYTES;
        match evaluate_conformity(expected, detected, still_classifying) {
            ConformityDecision::AllowPassthrough | ConformityDecision::Confirmed => {
                if !buf.is_empty() {
                    if let Some(ref rec) = recorder {
                        let _ = rec
                            .write_batch(IacsRecordingDirection::EwsToAsset, &buf)
                            .await;
                    }
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
                let _ = copy_with_counter_and_record(
                    read,
                    write,
                    counter,
                    handle,
                    IacsRecordingDirection::EwsToAsset,
                    recorder,
                )
                .await;
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
                return log_protocol_unconfirmed(
                    session_uuid,
                    expected,
                    buf.len(),
                    "classification_failed",
                );
            }
            ConformityDecision::NeedMoreData => {
                if !still_classifying {
                    return log_protocol_unconfirmed(
                        session_uuid,
                        expected,
                        buf.len(),
                        "deadline_or_buffer",
                    );
                }
                let mut classify_sleep = Box::pin(tokio::time::sleep_until(
                    tokio::time::Instant::from_std(deadline),
                ));
                let n = tokio::select! {
                    biased;
                    _ = handle.wait_close() => break,
                    _ = classify_sleep.as_mut() => {
                        return log_protocol_unconfirmed(
                            session_uuid,
                            expected,
                            buf.len(),
                            "deadline_or_buffer",
                        );
                    },
                    n = read.read(&mut scratch) => match n {
                        Ok(n) => n,
                        Err(_) => {
                            return log_protocol_unconfirmed(
                                session_uuid,
                                expected,
                                buf.len(),
                                "read_error",
                            );
                        }
                    },
                };
                if n == 0 {
                    return log_protocol_unconfirmed(session_uuid, expected, buf.len(), "eof");
                }
                buf.extend_from_slice(&scratch[..n]);
            }
        }
    }

    log_protocol_unconfirmed(session_uuid, expected, buf.len(), "peer_closed")
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

    fn sample_modbus_frame() -> Vec<u8> {
        vec![
            0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x0A,
        ]
    }

    async fn assert_upstream_empty(upstream_read: &mut (impl AsyncRead + Unpin)) {
        let mut peek = [0u8; 1];
        assert_eq!(
            upstream_read.read(&mut peek).await.unwrap(),
            0,
            "blocked gate MUST NOT forward bytes to the asset leg"
        );
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
                None,
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
                None,
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

    #[tokio::test]
    async fn modbus_profile_unconfirmed_when_peer_closes_on_unknown_payload() {
        let (mut client, server) = duplex(64);
        let (upstream, mut upstream_read) = duplex(64);
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
                None,
            )
            .await
        });
        client.write_all(b"not-a-modbus-payload!!").await.unwrap();
        drop(client);
        assert_eq!(
            pump.await.unwrap(),
            ProtocolGateOutcome::Unconfirmed,
            "unknown payload + peer close MUST fail closed, not Relayed"
        );
        let mut peek = [0u8; 1];
        assert_eq!(
            upstream_read.read(&mut peek).await.unwrap(),
            0,
            "blocked gate MUST NOT forward bytes to the asset leg"
        );
    }

    #[tokio::test]
    async fn modbus_profile_unconfirmed_on_immediate_eof() {
        let (client, server) = duplex(64);
        let (upstream, mut upstream_read) = duplex(64);
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
                None,
            )
            .await
        });
        drop(client);
        assert_eq!(pump.await.unwrap(), ProtocolGateOutcome::Unconfirmed);
        assert_upstream_empty(&mut upstream_read).await;
    }

    /// Idle EWS client (no bytes sent): the classify deadline MUST fire
    /// even while `read()` would block forever -- mirrors `nc` connected
    /// with zero application payload.
    #[tokio::test(start_paused = true)]
    async fn modbus_profile_unconfirmed_on_idle_classify_timeout() {
        let (_client, server) = duplex(64);
        let (upstream, mut upstream_read) = duplex(64);
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
                None,
            )
            .await
        });

        tokio::task::yield_now().await;
        tokio::time::advance(CLASSIFY_TIMEOUT).await;
        assert_eq!(
            pump.await.unwrap(),
            ProtocolGateOutcome::Unconfirmed,
            "idle client MUST fail closed when CLASSIFY_TIMEOUT elapses"
        );
        assert_upstream_empty(&mut upstream_read).await;
    }

    /// Partial unknown prefix that never completes Modbus MBAP: deadline
    /// MUST win over a blocked `read()` (no peer close required).
    #[tokio::test(start_paused = true)]
    async fn modbus_profile_unconfirmed_on_partial_unknown_then_deadline() {
        let (mut client, server) = duplex(64);
        let (upstream, mut upstream_read) = duplex(64);
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
                None,
            )
            .await
        });

        tokio::task::yield_now().await;
        client.write_all(&[0x00, 0x01, 0x00, 0x00]).await.unwrap();
        tokio::time::advance(CLASSIFY_TIMEOUT).await;
        assert_eq!(pump.await.unwrap(), ProtocolGateOutcome::Unconfirmed);
        assert_upstream_empty(&mut upstream_read).await;
    }

    /// Valid Modbus/TCP MUST confirm and relay before the deadline fires.
    #[tokio::test(start_paused = true)]
    async fn modbus_profile_confirms_and_relays_before_deadline() {
        let (mut client, server) = duplex(256);
        let (upstream, mut upstream_read) = duplex(256);
        let counter = Arc::new(AtomicU64::new(0));
        let h = handle();
        let frame = sample_modbus_frame();
        let pump = tokio::spawn(async move {
            filtered_copy_with_counter(
                server,
                upstream,
                counter,
                h,
                ExpectedProfile::Modbus,
                Uuid::new_v4(),
                None,
            )
            .await
        });

        tokio::task::yield_now().await;
        client.write_all(&frame).await.unwrap();
        drop(client);
        tokio::time::advance(Duration::from_millis(1)).await;
        assert_eq!(
            pump.await.unwrap(),
            ProtocolGateOutcome::Relayed,
            "valid Modbus/TCP MUST pass the gate"
        );

        let mut got = vec![0u8; frame.len()];
        upstream_read.read_exact(&mut got).await.unwrap();
        assert_eq!(got, frame);
    }

    /// Foreign protocol MUST fail closed immediately, without waiting for
    /// the classify deadline.
    #[tokio::test(start_paused = true)]
    async fn modbus_profile_foreign_protocol_does_not_wait_for_deadline() {
        let (mut client, server) = duplex(64);
        let (upstream, mut upstream_read) = duplex(64);
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
                None,
            )
            .await
        });

        tokio::task::yield_now().await;
        client.write_all(b"HEL").await.unwrap();
        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(matches!(
            pump.await.unwrap(),
            ProtocolGateOutcome::ForeignProtocol {
                detected: WireProtocol::OpcUa
            }
        ));
        assert_upstream_empty(&mut upstream_read).await;
    }

    /// EOF MUST beat a not-yet-elapsed deadline (immediate close path).
    #[tokio::test(start_paused = true)]
    async fn modbus_profile_eof_before_classify_timeout() {
        let (client, server) = duplex(64);
        let (upstream, mut upstream_read) = duplex(64);
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
                None,
            )
            .await
        });

        tokio::task::yield_now().await;
        drop(client);
        tokio::time::advance(Duration::from_millis(1)).await;
        assert_eq!(pump.await.unwrap(), ProtocolGateOutcome::Unconfirmed);
        assert_upstream_empty(&mut upstream_read).await;
    }

    #[tokio::test]
    async fn modbus_profile_unconfirmed_when_classify_buffer_exhausted() {
        let (mut client, server) = duplex(8192);
        let (upstream, mut upstream_read) = duplex(8192);
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
                None,
            )
            .await
        });

        let garbage = vec![b'X'; CLASSIFY_MAX_BYTES + 1];
        client.write_all(&garbage).await.unwrap();
        drop(client);
        assert_eq!(
            pump.await.unwrap(),
            ProtocolGateOutcome::Unconfirmed,
            "unknown payload beyond CLASSIFY_MAX_BYTES MUST fail closed"
        );
        assert_upstream_empty(&mut upstream_read).await;
    }
}
