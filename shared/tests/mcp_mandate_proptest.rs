//! Mission Seal laws over generated contracts (MCP Arch §13.3).
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use proptest::prelude::*;
use serde_json::{Map, Value, json};
use shared::mcp_mandate::{
    ApprovalKind, BindingMode, CheckStepOutcome, Contract, ContractStep, MandateState,
    all_steps_done, check_step, commit_step_result, parse_contract, parse_story, rollback_inflight,
    seal_mandate, strip_vauban_from_rpc_body,
};
use shared::mcp_tool_fingerprint::schema_fingerprint;

const OPS: [&str; 3] = ["echo", "get_time", "read_file"];

/// Steps `s0..sN`, unique arguments per step, edges only from lower to
/// higher index so index order is always a valid execution order.
fn contract() -> impl Strategy<Value = Contract> {
    (1usize..6)
        .prop_flat_map(|n| {
            (
                prop::collection::vec(0usize..OPS.len(), n),
                prop::collection::vec((0..n, 0..n), 0..n * 2),
            )
        })
        .prop_map(|(ops, raw_edges)| {
            let steps = ops
                .iter()
                .enumerate()
                .map(|(i, op)| ContractStep {
                    step_id: format!("s{i}"),
                    operation: OPS[*op].to_string(),
                    intent: format!("Generated step number {i}"),
                    mode: BindingMode::Literal,
                    arguments: json!({ "i": i }),
                    precedes: vec![],
                })
                .collect();
            let edges = raw_edges
                .into_iter()
                .filter(|(a, b)| a < b)
                .map(|(a, b)| [format!("s{a}"), format!("s{b}")])
                .collect();
            Contract {
                approval: ApprovalKind::Mission,
                steps,
                edges,
            }
        })
}

fn seal(c: &Contract) -> MandateState {
    seal_mandate("m1", "sess1", "asset1", c, 1_000.0).expect("seal")
}

fn snapshot(m: &MandateState) -> Value {
    serde_json::to_value(m).expect("mandate serializes")
}

fn call(m: &mut MandateState, step: &ContractStep) -> CheckStepOutcome {
    check_step(m, &step.operation, Some(&step.arguments))
}

/// Run every step in index order, committing a body per step.
fn run_all(m: &mut MandateState, c: &Contract) -> Result<(), TestCaseError> {
    for s in &c.steps {
        match call(m, s) {
            CheckStepOutcome::Allow {
                step_id,
                call_digest,
            } => {
                prop_assert_eq!(&step_id, &s.step_id);
                commit_step_result(m, &step_id, &call_digest, json!({ "ok": step_id }));
            }
            other => prop_assert!(false, "{} refused: {other:?}", s.step_id),
        }
    }
    Ok(())
}

fn chars(n: usize) -> impl Strategy<Value = String> {
    prop::collection::vec(prop::sample::select(vec!['a', 'é', '漢', '🙂']), n)
        .prop_map(|v| v.into_iter().collect())
}

proptest! {
    #[test]
    fn sealed_contract_runs_in_order_then_replays(c in contract()) {
        prop_assert!(parse_contract(&serde_json::to_value(&c).unwrap()).is_ok());
        let mut m = seal(&c);
        run_all(&mut m, &c)?;
        prop_assert!(all_steps_done(&m));
        for s in &c.steps {
            match call(&mut m, s) {
                CheckStepOutcome::Replay { step_id, cached } => {
                    prop_assert_eq!(&cached, &json!({ "ok": step_id }));
                }
                other => prop_assert!(false, "replay of {} gave {other:?}", s.step_id),
            }
        }
    }

    #[test]
    fn off_contract_tool_is_denied_without_state_change(c in contract(), tool in "[a-z_]{1,12}") {
        prop_assume!(!OPS.contains(&tool.as_str()));
        let mut m = seal(&c);
        let before = snapshot(&m);
        prop_assert_eq!(
            check_step(&mut m, &tool, Some(&json!({}))),
            CheckStepOutcome::Deny { reason: "step_not_in_contract" }
        );
        prop_assert_eq!(snapshot(&m), before);
    }

    #[test]
    fn wrong_arguments_are_denied_without_state_change(c in contract(), pick in any::<prop::sample::Index>(), bad in any::<i64>()) {
        let s = pick.get(&c.steps);
        prop_assume!(bad >= c.steps.len() as i64 || bad < 0);
        let mut m = seal(&c);
        let before = snapshot(&m);
        prop_assert_eq!(
            check_step(&mut m, &s.operation, Some(&json!({ "i": bad }))),
            CheckStepOutcome::Deny { reason: "args_mismatch_or_precedence" }
        );
        prop_assert_eq!(snapshot(&m), before);
    }

    #[test]
    fn a_step_never_runs_before_its_predecessor(c in contract()) {
        prop_assume!(!c.edges.is_empty());
        let [_, to] = &c.edges[0];
        let s = c.steps.iter().find(|s| &s.step_id == to).unwrap();
        let mut m = seal(&c);
        let before = snapshot(&m);
        prop_assert_eq!(
            call(&mut m, s),
            CheckStepOutcome::Deny { reason: "args_mismatch_or_precedence" }
        );
        prop_assert_eq!(snapshot(&m), before);
    }

    #[test]
    fn reloaded_mandate_behaves_like_the_live_one(c in contract(), done in 0usize..6) {
        let mut live = seal(&c);
        let done = done.min(c.steps.len());
        for s in &c.steps[..done] {
            if let CheckStepOutcome::Allow { step_id, call_digest } = call(&mut live, s) {
                commit_step_result(&mut live, &step_id, &call_digest, json!(step_id));
            }
        }
        let mut reloaded: MandateState =
            serde_json::from_str(&serde_json::to_string(&live).unwrap()).unwrap();
        prop_assert_eq!(snapshot(&reloaded), snapshot(&live));
        for s in &c.steps {
            prop_assert_eq!(call(&mut reloaded, s), call(&mut live, s));
        }
    }

    #[test]
    fn rollback_restores_the_step(c in contract()) {
        let mut m = seal(&c);
        let first = &c.steps[0];
        let a = call(&mut m, first);
        let allowed = matches!(a, CheckStepOutcome::Allow { .. });
        prop_assert!(allowed);
        prop_assert_eq!(call(&mut m, first), CheckStepOutcome::Deny { reason: "step_inflight" });
        rollback_inflight(&mut m);
        prop_assert_eq!(call(&mut m, first), a);
    }

    #[test]
    fn seal_digest_binds_every_argument(c in contract(), pick in any::<prop::sample::Index>()) {
        let d = seal(&c).sealed_digest;
        prop_assert_eq!(&seal(&c).sealed_digest, &d);
        let mut changed = c.clone();
        let i = pick.index(changed.steps.len());
        changed.steps[i].arguments = json!({ "i": i, "extra": true });
        prop_assert_ne!(seal(&changed).sealed_digest, d);
    }

    #[test]
    fn story_bounds_count_characters(summary in (0usize..260).prop_flat_map(chars)) {
        let n = summary.chars().count();
        let ok = "x".repeat(20);
        let story = json!({ "summary": summary, "context": ok, "objective": ok, "risks": ok });
        prop_assert_eq!(parse_story(&story).is_ok(), (10..=200).contains(&n), "summary of {} chars", n);
    }

    #[test]
    fn contract_intent_bounds_count_characters(intent in (0usize..560).prop_flat_map(chars)) {
        let n = intent.chars().count();
        let raw = json!({
            "approval": "mission",
            "steps": [{ "step_id": "1", "operation": "echo", "intent": intent, "mode": "literal", "arguments": {} }]
        });
        prop_assert_eq!(parse_contract(&raw).is_ok(), (10..=500).contains(&n), "intent of {} chars", n);
    }

    #[test]
    fn fingerprint_ignores_key_order_and_binds_content(
        props in prop::collection::btree_map("[a-z]{1,6}", any::<i32>(), 1..6),
        desc in "\\PC{0,20}",
    ) {
        let forward: Map<String, Value> = props.iter().map(|(k, v)| (k.clone(), json!(v))).collect();
        let backward: Map<String, Value> = props.iter().rev().map(|(k, v)| (k.clone(), json!(v))).collect();
        let a = schema_fingerprint("tool", &desc, Some(&Value::Object(forward.clone())));
        prop_assert_eq!(&a, &schema_fingerprint("tool", &desc, Some(&Value::Object(backward))));
        prop_assert_ne!(&a, &schema_fingerprint("tool", &format!("{desc}!"), Some(&Value::Object(forward.clone()))));
        let mut mutated = forward;
        let k = mutated.keys().next().unwrap().clone();
        mutated.insert(k, json!("changed"));
        prop_assert_ne!(&a, &schema_fingerprint("tool", &desc, Some(&Value::Object(mutated))));
    }

    #[test]
    fn strip_removes_every_vauban_key_and_keeps_the_rest(
        args in prop::collection::btree_map("[a-z]{1,6}", any::<i32>(), 0..4),
        meta in prop::collection::btree_map("[a-z]{1,6}", any::<i32>(), 0..3),
    ) {
        prop_assume!(!args.contains_key("vauban") && !meta.contains_key("vauban"));
        let mut a: Map<String, Value> = args.iter().map(|(k, v)| (k.clone(), json!(v))).collect();
        a.insert("vauban".into(), json!({ "story": {}, "contract": {} }));
        let mut m: Map<String, Value> = meta.iter().map(|(k, v)| (k.clone(), json!(v))).collect();
        m.insert("vauban".into(), json!({ "pending_id": "p1" }));
        let mut body = json!({ "jsonrpc": "2.0", "method": "tools/call", "params": { "name": "echo", "arguments": a, "_meta": m } });
        strip_vauban_from_rpc_body(&mut body);
        prop_assert!(body.pointer("/params/arguments/vauban").is_none());
        prop_assert!(body.pointer("/params/_meta/vauban").is_none());
        for (k, v) in &args {
            prop_assert_eq!(body.pointer(&format!("/params/arguments/{k}")), Some(&json!(v)));
        }
        if meta.is_empty() {
            prop_assert!(body.pointer("/params/_meta").is_none());
        }
        for (k, v) in &meta {
            prop_assert_eq!(body.pointer(&format!("/params/_meta/{k}")), Some(&json!(v)));
        }
    }
}
