//! Contention: `equality_filter` is pure and must stay correct under flood.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::{Arc, Barrier};
use std::thread;

use shared::ldap_filter::equality_filter;

#[test]
fn battle_equality_filter_under_barrier() {
    const N: usize = 8;
    let barrier = Arc::new(Barrier::new(N));
    let mut handles = Vec::with_capacity(N);
    for i in 0..N {
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            let dn = format!("uid=user{i},ou=people,dc=example,dc=com");
            let ok = equality_filter("member", &dn).expect("plain DN");
            assert_eq!(ok, format!("(member={dn})"));
            let injected = equality_filter("member", &format!("user{i})(uid=admin")).expect("enc");
            assert!(!injected.contains(")("));
            assert!(injected.contains("\\29\\28"));
        }));
    }
    for h in handles {
        h.join().expect("worker panicked");
    }
}
