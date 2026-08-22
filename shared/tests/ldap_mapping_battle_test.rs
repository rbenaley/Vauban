//! Contention: `apply` is pure and must stay deterministic under a login flood.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::sync::{Arc, Barrier};
use std::thread;

use shared::ldap_mapping::{self, MappingFile};

#[test]
fn battle_apply_under_barrier() {
    let ast: MappingFile = ldap_mapping::parse(
        b"\
resolve  user-attr  memberOf
static   CN=Domain Admins,CN=Users,DC=x  Administrators
match    CN={name},OU=g,DC=x  {name}
",
    )
    .expect("parse");
    let ast = Arc::new(ast);

    const N: usize = 8;
    let barrier = Arc::new(Barrier::new(N));
    let mut handles = Vec::with_capacity(N);
    for i in 0..N {
        let barrier = Arc::clone(&barrier);
        let ast = Arc::clone(&ast);
        handles.push(thread::spawn(move || {
            barrier.wait();
            let keys = [
                "CN=Domain Admins,CN=Users,DC=x".to_string(),
                format!("CN=user{i},OU=g,DC=x"),
                "CN=Administrators,OU=g,DC=x".to_string(),
            ];
            let names = ldap_mapping::apply(&keys, &ast);
            assert_eq!(
                names,
                BTreeSet::from(["Administrators".into(), format!("user{i}")])
            );
        }));
    }
    for h in handles {
        h.join().expect("worker panicked");
    }
}
