//! Evidence plane extracted from `vauban-web` (architecture §3.2 / §10.13).
//!
//! - [`analyzer`]: IACS Inspect Capture packet analyzer (pure parse /
//!   reassembly / dissection; no DB / IPC / templates).
//! - [`hydrator`]: recording integrity hydration pipeline (trait-parameterized).

#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::todo)
)]

pub mod analyzer;
pub mod hydrator;

pub use analyzer::{
    analyze_channel, analyze_channel_bytes, analyze_packet, analyze_packet_bytes, page_summaries,
    parse_pcap_bytes, parse_pcap_gz,
};
