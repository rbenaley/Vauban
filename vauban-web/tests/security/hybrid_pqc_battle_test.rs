//! Contention: parallel generate + encapsulate/decapsulate + sign/verify.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::sync::{Arc, Barrier};
use std::thread;

use vauban_web::crypto::{HybridKemSecretKey, HybridSigSecretKey};

#[test]
fn battle_hybrid_pqc_generate_encap_sign_under_barrier() {
    const THREADS: usize = 4;
    const ITERS: usize = 3;
    let barrier = Arc::new(Barrier::new(THREADS));
    let mut handles = Vec::with_capacity(THREADS);

    for t in 0..THREADS {
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for i in 0..ITERS {
                let (pk, sk) = HybridKemSecretKey::generate();
                let (send, ct) = pk.encapsulate().expect("encapsulate");
                let recv = sk.decapsulate(&ct).expect("decapsulate");
                assert_eq!(send, recv, "kem thread {t} iter {i}");

                let (spk, ssk) = HybridSigSecretKey::generate();
                let msg = format!("battle-{t}-{i}").into_bytes();
                let sig = ssk.sign(&msg);
                assert!(spk.verify(&msg, &sig).is_ok(), "sig thread {t} iter {i}");
            }
        }));
    }

    for h in handles {
        h.join().expect("battle thread");
    }
}
