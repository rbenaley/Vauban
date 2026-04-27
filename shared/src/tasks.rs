//! Tiny helper to spawn supervised, fire-and-forget periodic tasks
//! on an explicit tokio runtime handle.
//!
//! ## Why an explicit `Handle` instead of `tokio::spawn`?
//!
//! `tokio::spawn` reads the current runtime from a thread-local that
//! is only set inside `block_on` or `#[tokio::main]`. Crates whose
//! main loop is **synchronous** (e.g. `vauban-access` drives the IPC
//! `select!` directly and only enters its tokio runtime via
//! `rt.block_on(...)` for individual handler calls) would crash at
//! boot with `there is no reactor running` if they used
//! `tokio::spawn`. Threading the `Handle` through removes that
//! footgun by construction; the type system forces every caller to
//! prove they have a runtime to spawn on.
//!
//! Crates that *do* live inside `#[tokio::main]` (e.g. `vauban-web`)
//! pay a one-line cost (`Handle::current()`) for the same uniform
//! API. The benefit is one place where ticker semantics, logging
//! and naming are pinned.
//!
//! ## Semantics
//!
//! * The first immediate tick from `tokio::time::interval` is always
//!   skipped: callers are expected to perform their boot-time check
//!   synchronously, then ask the task to handle subsequent re-checks.
//! * The task runs forever; it is dropped only when the runtime is
//!   dropped. Errors from `tick` must be swallowed inside the closure
//!   (typically by `tracing::warn!`) -- the loop never aborts.
//! * The task is named in `tracing` so operators can correlate the
//!   spawn line with later activity.

use std::time::Duration;
use tracing::info;

/// Spawn a fire-and-forget periodic task on the supplied runtime
/// handle.
///
/// `name` is a stable identifier that appears in the spawn log line
/// and should match the conceptual job (e.g. `"admin_count"`,
/// `"session_cleanup"`, `"dashboard_stats"`).
///
/// Returns the `JoinHandle` so callers that care about lifecycle
/// (tests, supervised shutdown) can keep a reference; the common
/// case is to drop it.
pub fn spawn_periodic<F, Fut>(
    handle: &tokio::runtime::Handle,
    name: &'static str,
    period: Duration,
    mut tick: F,
) -> tokio::task::JoinHandle<()>
where
    F: FnMut() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    info!(
        task = name,
        period_secs = period.as_secs(),
        "background task spawned"
    );
    handle.spawn(async move {
        let mut ticker = tokio::time::interval(period);
        // Skip the first immediate tick: callers do a boot-time check
        // synchronously and only delegate the *re-check* cadence to us.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            tick().await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[tokio::test]
    async fn spawn_periodic_skips_first_tick_then_fires() {
        let counter = Arc::new(AtomicU32::new(0));
        let c = counter.clone();
        let handle = tokio::runtime::Handle::current();
        let _task = spawn_periodic(
            &handle,
            "test_skip_first",
            Duration::from_millis(20),
            move || {
                let c = c.clone();
                async move {
                    c.fetch_add(1, Ordering::SeqCst);
                }
            },
        );
        // Within ~10 ms (less than one period) the counter must still
        // be zero: the first immediate tick is skipped.
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert_eq!(counter.load(Ordering::SeqCst), 0);
        // After ~50 ms (>= 2 periods, with skip + 1 actual tick) the
        // counter must have advanced at least once.
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(
            counter.load(Ordering::SeqCst) >= 1,
            "expected at least one tick to have fired"
        );
    }

    #[test]
    fn spawn_periodic_works_from_handle_clone_outside_block_on() {
        // Mimics vauban-access: build a runtime in synchronous code,
        // call `spawn_periodic` *outside* any `block_on` (so there is
        // no thread-local runtime), and ensure the task still fires.
        // This is the regression test for the boot crash that
        // motivated the explicit-Handle API.
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let counter = Arc::new(AtomicU32::new(0));
        let c = counter.clone();
        // Important: this call site is plain synchronous code, no
        // ambient tokio context. With `tokio::spawn` it would panic
        // with "no reactor running"; with `Handle::spawn` it works.
        let _task = spawn_periodic(
            rt.handle(),
            "test_cross_ctx",
            Duration::from_millis(10),
            move || {
                let c = c.clone();
                async move {
                    c.fetch_add(1, Ordering::SeqCst);
                }
            },
        );
        rt.block_on(async {
            tokio::time::sleep(Duration::from_millis(60)).await;
        });
        assert!(
            counter.load(Ordering::SeqCst) >= 1,
            "task spawned from a synchronous caller must still fire"
        );
    }
}
