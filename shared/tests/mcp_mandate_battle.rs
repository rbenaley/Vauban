#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::sync::{Arc, Barrier, Mutex};
use std::thread;

use serde_json::json;
use shared::mcp_mandate::{
    ApprovalKind, BindingMode, CheckStepOutcome, Contract, ContractStep, check_step, seal_mandate,
};

fn one_step() -> Contract {
    Contract {
        approval: ApprovalKind::Mission,
        edges: vec![],
        steps: vec![ContractStep {
            step_id: "1".into(),
            operation: "echo".into(),
            intent: "Say hello once".into(),
            mode: BindingMode::Literal,
            arguments: json!({"message": "seal-1"}),
            precedes: vec![],
        }],
    }
}

#[test]
fn battle_concurrent_checkstep_allows_one() {
    let mandate = seal_mandate("m1", "sess", "asset", &one_step(), 1_000.0).expect("seal");
    let state = Arc::new(Mutex::new(mandate));
    let barrier = Arc::new(Barrier::new(8));
    let mut handles = Vec::new();
    for _ in 0..8 {
        let state = Arc::clone(&state);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            let args = json!({"message": "seal-1"});
            let mut guard = state.lock().expect("lock");
            check_step(&mut guard, "echo", Some(&args))
        }));
    }
    let mut allows = 0;
    let mut denies = 0;
    for handle in handles {
        match handle.join().expect("thread") {
            CheckStepOutcome::Allow { .. } => allows += 1,
            CheckStepOutcome::Deny { reason } => {
                assert_eq!(reason, "step_inflight");
                denies += 1;
            }
            other => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!(allows, 1);
    assert_eq!(denies, 7);
}

#[test]
fn attack_forged_arguments_are_rejected() {
    let mut mandate = seal_mandate("m1", "sess", "asset", &one_step(), 1_000.0).expect("seal");
    match check_step(&mut mandate, "echo", Some(&json!({"message": "forged"}))) {
        CheckStepOutcome::Deny {
            reason: "args_mismatch_or_precedence",
        } => {}
        other => panic!("forged args must be denied, got {other:?}"),
    }
}
