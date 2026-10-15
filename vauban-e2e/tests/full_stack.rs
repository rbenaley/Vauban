//! Full-stack scenarios on a real Vauban (supervisor + every service) and a
//! real browser. Boots once, runs every scenario in order, tears down.
//!
//! `just test-full-stack` (rebuilds first). Filters work as usual:
//! `just test-full-stack auth::`.

mod scenarios;
mod support;

use libtest_mimic::{Arguments, Failed, Trial};
use std::process::ExitCode;
use std::sync::{Arc, OnceLock};
use support::Stack;

fn main() -> ExitCode {
    // reqwest brings aws-lc-rs and another dependency brings ring: with two
    // providers compiled in, rustls refuses to pick one implicitly.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut args = Arguments::from_args();
    args.test_threads = Some(1);

    let stack: Arc<OnceLock<Result<Stack, String>>> = Arc::new(OnceLock::new());
    let trials = scenarios::all()
        .into_iter()
        .map(|(name, scenario)| {
            let stack = Arc::clone(&stack);
            Trial::test(name, move || {
                let stack = stack
                    .get_or_init(|| Stack::boot().map_err(|e| format!("boot: {e:#}")))
                    .as_ref()
                    .map_err(|e| Failed::from(e.clone()))?;
                stack
                    .run(name, scenario)
                    .map_err(|e| Failed::from(format!("{e:#}")))
            })
        })
        .collect();

    let full_run = args.filter.is_none() && args.skip.is_empty();
    let conclusion = libtest_mimic::run(&args, trials);
    let mut code = conclusion.exit_code();
    if let Some(Ok(stack)) = stack.get()
        && let Err(e) = stack.shutdown(full_run)
    {
        eprintln!("teardown: {e:#}");
        code = ExitCode::FAILURE;
    }
    code
}
