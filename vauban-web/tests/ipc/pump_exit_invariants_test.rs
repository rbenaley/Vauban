//! Source pins for IPC pump exit / respawn (0.9.43).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

const MAIN: &str = include_str!("../../src/main.rs");

fn prod_main() -> &'static str {
    MAIN.split("#[cfg(test)]").next().unwrap_or(MAIN)
}

#[test]
fn pumps_go_through_spawn_ipc_pump() {
    let src = prod_main();
    assert!(
        src.contains("fn main() -> ExitCode"),
        "binary main must return ExitCode"
    );
    assert!(
        !src.contains("IPC processing task failed"),
        "legacy pump-failed literal must not exist"
    );
    let incoming = src.matches("process_incoming(").count();
    let incoming_state = src.matches("process_incoming_with_state(").count();
    let pumps = src.matches("spawn_ipc_pump(").count();
    assert!(
        pumps >= incoming + incoming_state,
        "every process_incoming* call must be wrapped by spawn_ipc_pump \
         (pumps={pumps} incoming={incoming} with_state={incoming_state})"
    );
}

#[test]
fn pump_module_owns_policy() {
    let pump = include_str!("../../src/ipc/pump.rs");
    assert!(pump.contains("fn pump_exit_policy("));
    assert!(pump.contains("fn spawn_ipc_pump"));
    assert!(pump.contains("EXIT_CODE_RESPAWN"));
}
