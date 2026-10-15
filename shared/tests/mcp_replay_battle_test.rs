//! Battle: the proxy anti-replay gate (`proxy_gate::verify_proxy`) under
//! simultaneous release. One test only: the key and cache are process-wide.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use shared::messages::Service;
use shared::session_token::{
    SESSION_TOKEN_KEY_ENV, SessionToken, SessionTokenParams, TokenKey, proxy_gate,
};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

const N: usize = 16;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn mint(key: &TokenKey, sid: &str) -> Vec<u8> {
    SessionToken::mint(
        key,
        now(),
        SessionTokenParams {
            session_id: sid.into(),
            user_uuid: "user-1".into(),
            asset_uuid: "asset-1".into(),
            protocol: "mcp".into(),
            host: "mcp.lab".into(),
            port: 443,
            target_service: Service::ProxyMcp,
        },
    )
    .to_bytes()
    .unwrap()
}

/// Release `N` threads at once, each running `f(i)`; return the results.
fn race(f: impl Fn(usize) -> bool + Send + Sync + 'static) -> Vec<bool> {
    let f = Arc::new(f);
    let barrier = Arc::new(Barrier::new(N));
    let handles: Vec<_> = (0..N)
        .map(|i| {
            let (f, barrier) = (Arc::clone(&f), Arc::clone(&barrier));
            thread::spawn(move || {
                barrier.wait();
                f(i)
            })
        })
        .collect();
    handles.into_iter().map(|h| h.join().unwrap()).collect()
}

#[test]
fn battle_replay_gate_under_contention() {
    let key = TokenKey::generate();
    // SAFETY: single-threaded here; no other thread exists yet in this test binary.
    unsafe { std::env::set_var(SESSION_TOKEN_KEY_ENV, key.to_base64()) };
    proxy_gate::init_from_env().unwrap();

    let same = Arc::new(mint(&key, "s-replay"));
    let accepted =
        race(move |_| proxy_gate::verify_proxy(&same, "user-1", "asset-1", "mcp", "s-replay"));
    assert_eq!(
        accepted.iter().filter(|ok| **ok).count(),
        1,
        "one token presented by {N} threads at once must open exactly one session"
    );

    let distinct: Arc<Vec<Vec<u8>>> =
        Arc::new((0..N).map(|i| mint(&key, &format!("s-own-{i}"))).collect());
    let own = race(move |i| {
        proxy_gate::verify_proxy(
            &distinct[i],
            "user-1",
            "asset-1",
            "mcp",
            &format!("s-own-{i}"),
        )
    });
    assert!(
        own.iter().all(|ok| *ok),
        "distinct fresh tokens must never collide"
    );

    let foreign = Arc::new(mint(&key, "s-a"));
    let cross =
        race(move |_| proxy_gate::verify_proxy(&foreign, "user-1", "asset-1", "mcp", "s-b"));
    assert!(
        cross.iter().all(|ok| !*ok),
        "a token bound to another session is refused"
    );
}
