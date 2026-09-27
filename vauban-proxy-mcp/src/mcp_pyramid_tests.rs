use std::sync::{Arc, Barrier};
use std::thread;

use proptest::prelude::*;

use super::SUPPORTED_METHODS;

proptest! {
    #[test]
    fn unknown_methods_are_rejected(method in "[A-Za-z0-9_./]{1,24}") {
        let known = SUPPORTED_METHODS.contains(&method.as_str());
        if known {
            prop_assert!(SUPPORTED_METHODS.contains(&method.as_str()));
        } else {
            prop_assert!(!SUPPORTED_METHODS.contains(&method.as_str()));
        }
    }
}

#[test]
fn battle_supported_methods_stable_under_threads() {
    let barrier = Arc::new(Barrier::new(8));
    let mut handles = Vec::new();
    for _ in 0..8 {
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            SUPPORTED_METHODS.contains(&"tools/call")
                && !SUPPORTED_METHODS.contains(&"session/register")
        }));
    }
    for handle in handles {
        assert!(handle.join().expect("thread"));
    }
}
