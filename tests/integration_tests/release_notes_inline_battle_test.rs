//! Contention: parallel parse_inline_code stays consistent under load.

use std::sync::Arc;

use tokio::sync::Barrier;
use vcp::release_notes::{InlineSegment, parse_inline_code};

#[tokio::test]
async fn battle_parallel_parse_inline_code() {
    let samples = Arc::new(vec![
        "Prefer `config/` over workspace".to_owned(),
        "plain text only".to_owned(),
        "use `foo` and `bar`.".to_owned(),
        "unpaired `tick".to_owned(),
        String::new(),
        "`only`".to_owned(),
    ]);
    let n = 12usize;
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::with_capacity(n);
    for i in 0..n {
        let barrier = Arc::clone(&barrier);
        let samples = Arc::clone(&samples);
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let mut ok = 0usize;
            for _ in 0..200 {
                let s = &samples[i % samples.len()];
                let segs = parse_inline_code(s);
                if s.contains('`') && s.chars().filter(|c| *c == '`').count() >= 2 {
                    assert!(
                        segs.iter().any(|seg| matches!(seg, InlineSegment::Code(_))),
                        "expected Code in {s:?} -> {segs:?}"
                    );
                }
                if !s.contains('`') && !s.is_empty() {
                    assert_eq!(segs, vec![InlineSegment::Text(s.clone())]);
                }
                ok += 1;
            }
            ok
        }));
    }
    let mut total = 0usize;
    for h in handles {
        total += h.await.expect("join");
    }
    assert_eq!(total, n * 200);
}
