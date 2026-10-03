#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

//! Local MCP shim.
//!
//! Speaks newline-delimited JSON-RPC on stdio. Hop 1 and the inner TLS
//! tunnel live in the binary; this library owns the pieces that must be
//! tested without a network: framing, the SPKI pin compare, and the
//! trust-on-first-use store.

pub mod cli;
pub mod hop;
pub mod inner;
pub mod pin;
pub mod session;
pub mod tofu;

/// One stdio line. Logs never share this stream.
pub fn parse_line(line: &str) -> Result<serde_json::Value, String> {
    let line = line.trim();
    if line.is_empty() {
        return Err("empty".into());
    }
    if line.len() > 1_048_576 {
        return Err("line too large".into());
    }
    serde_json::from_str(line).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::sync::{Arc, Barrier};

    proptest! {
        #[test]
        fn random_lines_do_not_panic(raw in "\\PC{0,80}") {
            let _ = parse_line(&raw);
        }
    }

    #[test]
    fn empty_line_is_rejected() {
        assert!(parse_line("  ").is_err());
    }

    #[test]
    fn json_line_round_trips() {
        let v = parse_line("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}").unwrap();
        assert_eq!(v["method"], "tools/list");
    }

    #[test]
    fn battle_stdio_lines_keep_ids() {
        let barrier = Arc::new(Barrier::new(32));
        let mut joins = Vec::new();
        for i in 0..32 {
            let barrier = Arc::clone(&barrier);
            joins.push(std::thread::spawn(move || {
                barrier.wait();
                let line = format!("{{\"jsonrpc\":\"2.0\",\"id\":{i},\"method\":\"tools/list\"}}");
                let v = parse_line(&line).expect("parse");
                assert_eq!(v["id"], i);
            }));
        }
        for join in joins {
            join.join().expect("thread");
        }
    }
}
