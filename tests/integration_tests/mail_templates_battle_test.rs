//! Contention: parallel HTML renders stay isolated (no shared mutable template state).

use std::sync::{Arc, Barrier};
use std::thread;

use vcp::mail_templates::{TemplateVars, USER_JOIN_HTML, render_html};

#[test]
fn battle_parallel_render_join_templates() {
    const N: usize = 8;
    let barrier = Arc::new(Barrier::new(N));
    let mut handles = Vec::with_capacity(N);
    for i in 0..N {
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            let org = format!("Org-{i} <x>");
            let url = format!("https://example.test/login/magic?token=tok{i}");
            let html = render_html(
                USER_JOIN_HTML,
                TemplateVars {
                    org_name: Some(&org),
                    magic_url: Some(&url),
                    from_address: "no-reply@vauban.sh",
                    ttl_minutes: Some(5),
                },
            );
            assert!(html.contains(&format!("Org-{i} &lt;x&gt;")), "{html}");
            assert!(html.contains(&format!("tok{i}")), "{html}");
            assert!(!html.contains("__ORG_NAME__"));
            html
        }));
    }
    let bodies: Vec<String> = handles
        .into_iter()
        .map(|h| h.join().expect("thread"))
        .collect();
    assert_eq!(bodies.len(), N);
    for (i, html) in bodies.iter().enumerate() {
        for j in 0..N {
            if i == j {
                continue;
            }
            assert!(
                !html.contains(&format!("tok{j}")),
                "render {i} must not contain sibling token tok{j}"
            );
        }
    }
}
