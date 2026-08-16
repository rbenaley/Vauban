//! Contention: `substitute_bind_dn` is pure and must stay correct under
//! parallel callers (login flood).

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::{Arc, Barrier};
use std::thread;

use shared::ldap_dn::{BindDnError, substitute_bind_dn};

const DN_TEMPLATE: &str = "uid={username},ou=people,dc=example,dc=com";

#[test]
fn battle_substitute_bind_dn_under_barrier() {
    const N: usize = 8;
    let barrier = Arc::new(Barrier::new(N));
    let mut handles = Vec::with_capacity(N);
    for i in 0..N {
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            let ok = substitute_bind_dn(DN_TEMPLATE, &format!("user{i}")).expect("allowlisted");
            assert_eq!(ok, format!("uid=user{i},ou=people,dc=example,dc=com"));
            let bad = substitute_bind_dn(DN_TEMPLATE, &format!("user{i},ou=admins"));
            assert_eq!(bad, Err(BindDnError::IllegalUsername));
        }));
    }
    for h in handles {
        h.join().expect("worker panicked");
    }
}
