//! Direction inference and per-channel endpoint resolution.
//!
//! The audit-side `iacs_pcap_synth::Endpoints` is rebuilt server
//! side from the channel metadata recorded in `meta.json` -- the
//! client (EWS) and server (asset) tuples are deterministic given
//! the same `(target_host, target_port)` and the synthetic ISN
//! base, but we do not need to recompute the ISN. We just match
//! the captured src/dst IP + port against the client/server tuple.

use std::net::IpAddr;

use super::parser::RawPacket;
use super::types::Direction;

/// Resolved endpoints for one IACS channel. The client side is the
/// EWS application initiating the `direct-tcpip` channel; the
/// server side is the industrial asset.
#[derive(Debug, Clone)]
pub struct ChannelEndpoints {
    pub client_ip: IpAddr,
    pub client_port: u16,
    pub server_ip: IpAddr,
    pub server_port: u16,
}

impl ChannelEndpoints {
    /// Recover the canonical (client, server) tuple from the FIRST
    /// packet of the channel. The audit module always emits the
    /// SYN as the first record, originating from the client; the
    /// server endpoint is therefore the SYN's destination tuple.
    /// If no SYN is seen, we fall back to "first packet src is
    /// client".
    pub fn infer_from_first_packets(packets: &[RawPacket]) -> Option<Self> {
        let first_syn = packets.iter().find(|p| p.tcp_flags.syn && !p.tcp_flags.ack);
        if let Some(p) = first_syn {
            return Some(Self {
                client_ip: p.src_ip,
                client_port: p.src_port,
                server_ip: p.dst_ip,
                server_port: p.dst_port,
            });
        }
        let first = packets.first()?;
        Some(Self {
            client_ip: first.src_ip,
            client_port: first.src_port,
            server_ip: first.dst_ip,
            server_port: first.dst_port,
        })
    }

    /// Direction of `p` relative to this channel's endpoints.
    pub fn direction_of(&self, p: &RawPacket) -> Direction {
        super::parser::infer_direction(
            p,
            self.client_ip,
            self.client_port,
            self.server_ip,
            self.server_port,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::iacs_packet_analyzer::parser::parse_pcap_bytes;
    use vauban_audit::iacs_pcap_synth as synth;

    fn build_handshake_pcap() -> Vec<u8> {
        let flow = synth::TcpFlow::new(
            "s",
            1,
            synth::Endpoints::parse("192.0.2.10", 49_152, "198.51.100.20", 502),
        );
        let mut buf = Vec::new();
        buf.extend_from_slice(&synth::build_global_header());
        for r in synth::build_handshake(&flow, 1_000) {
            buf.extend_from_slice(&r);
        }
        buf
    }

    #[test]
    fn endpoints_inferred_from_first_syn() {
        let buf = build_handshake_pcap();
        let parsed = parse_pcap_bytes(&buf).unwrap();
        let e = ChannelEndpoints::infer_from_first_packets(&parsed).unwrap();
        assert_eq!(e.client_ip.to_string(), "192.0.2.10");
        assert_eq!(e.server_port, 502);
    }

    #[test]
    fn direction_of_matches_canonical_tuple() {
        let buf = build_handshake_pcap();
        let parsed = parse_pcap_bytes(&buf).unwrap();
        let e = ChannelEndpoints::infer_from_first_packets(&parsed).unwrap();
        // SYN goes from client (EWS) to server (asset).
        assert_eq!(e.direction_of(&parsed[0]), Direction::EwsToAsset);
        // SYN-ACK goes the other way.
        assert_eq!(e.direction_of(&parsed[1]), Direction::AssetToEws);
    }

    #[test]
    fn endpoints_returns_none_on_empty_capture() {
        assert!(ChannelEndpoints::infer_from_first_packets(&[]).is_none());
    }
}
