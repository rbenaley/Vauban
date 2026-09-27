//! Mission Seal / Mandate — Contract parse, digests, CheckStep (literal + DAG).
//!
//! Pure PDP. `vauban-access` owns live [`MandateState`] (CheckStepAuthorized).
//! `vauban-proxy-mcp` is the PEP (asks access, then relays or denies).

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};

pub const DOMAIN_HITL_ARGS: &[u8] = b"vauban.hitl.args.v1";
pub const DOMAIN_BINDING: &[u8] = b"vauban.mandate.binding.v1";
pub const DOMAIN_SEAL: &[u8] = b"vauban.mandate.seal.v1";
pub const DOMAIN_CALL_BODY: &[u8] = b"vauban.mandate.call_body.v1";

pub const ERR_MANDATE_STEP_DENIED: i32 = -32033;
/// Mission TTL elapsed — mandate dead, session lives, **not** IAM suspend.
pub const ERR_MISSION_EXPIRED: i32 = -32034;

/// CheckStep deny reasons that are Contract-perimeter drift (IAM suspend).
/// `step_inflight` is concurrency, not a mandate violation.
pub fn is_perimeter_drift(reason: &str) -> bool {
    matches!(
        reason,
        "args_mismatch_or_precedence" | "step_not_in_contract" | "mode_not_supported"
    )
}

/// Post-Approve mission TTL (minutes-scale TOCTOU bound — not session TTL).
pub const MISSION_TTL_DEFAULT_SECS: f64 = 900.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BindingMode {
    Literal,
    Constrained,
    Derived,
}

impl BindingMode {
    pub fn as_str(self) -> &'static str {
        match self {
            BindingMode::Literal => "literal",
            BindingMode::Constrained => "constrained",
            BindingMode::Derived => "derived",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalKind {
    Mission,
    Step,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractStep {
    pub step_id: String,
    pub operation: String,
    pub intent: String,
    pub mode: BindingMode,
    /// Exact args for `literal` (object). Ignored for other modes in v1.
    #[serde(default)]
    pub arguments: Value,
    /// Optional predecessors (step_ids that must be consumed first).
    #[serde(default)]
    pub precedes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contract {
    pub approval: ApprovalKind,
    pub steps: Vec<ContractStep>,
    /// Optional edges `[from_step_id, to_step_id]` (to depends on from).
    #[serde(default)]
    pub edges: Vec<[String; 2]>,
}

/// Human-facing explanation of the plan (display + shape only; never CheckStep).
///
/// Field `description`s in docs/schema must tell agents: this is read by a
/// human supervisor who Approves or Denies.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlanStory {
    /// One sentence: what will this mission do?
    pub summary: String,
    /// Why now / which system.
    pub context: String,
    /// Expected outcome for the operator.
    pub objective: String,
    /// What can go wrong if Approved.
    pub risks: String,
}

#[derive(Debug, Clone)]
pub struct SealedStep {
    pub step_id: String,
    pub operation: String,
    #[allow(dead_code)]
    pub intent: String,
    pub mode: BindingMode,
    pub args_digest: String,
    #[allow(dead_code)]
    pub binding_digest: String,
    pub predecessors: Vec<String>,
    pub consumed: bool,
}

#[derive(Debug, Clone)]
pub struct MandateState {
    pub mandate_id: String,
    pub sealed_digest: String,
    #[allow(dead_code)]
    pub approval: ApprovalKind,
    pub contract_json: String,
    pub steps: Vec<SealedStep>,
    /// Memorized JSON-RPC bodies for idempotent replay (no second upstream).
    pub results: HashMap<(String, String), Value>,
    /// Step consumed pending upstream success — rolled back on failure.
    pub inflight: Option<(String, String)>,
    /// Unix seconds; after this the mandate is dead (fail-closed).
    pub expires_at: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CheckStepOutcome {
    Allow {
        step_id: String,
        call_digest: String,
    },
    /// Same body already executed — return cached JSON-RPC body (no upstream).
    Replay {
        step_id: String,
        cached: Value,
    },
    Deny {
        reason: &'static str,
    },
}

/// BLAKE3 over domain || canonical JSON of args (raw Value, no redact).
pub fn digest_args_raw(args: Option<&Value>) -> String {
    let v = args.cloned().unwrap_or(Value::Null);
    let mut hasher = blake3::Hasher::new();
    hasher.update(DOMAIN_HITL_ARGS);
    hasher.update(&serde_json::to_vec(&v).unwrap_or_default());
    hasher.finalize().to_hex().to_string()
}

pub fn digest_call_body(tool: &str, args: Option<&Value>) -> String {
    let body = serde_json::json!({
        "name": tool,
        "arguments": args.cloned().unwrap_or(Value::Null),
    });
    let mut hasher = blake3::Hasher::new();
    hasher.update(DOMAIN_CALL_BODY);
    hasher.update(&serde_json::to_vec(&body).unwrap_or_default());
    hasher.finalize().to_hex().to_string()
}

fn binding_digest(
    mandate_id: &str,
    step_id: &str,
    operation: &str,
    mode: BindingMode,
    payload: &[u8],
) -> String {
    let mode_s = mode.as_str();
    let mut hasher = blake3::Hasher::new();
    hasher.update(DOMAIN_BINDING);
    hasher.update(mandate_id.as_bytes());
    hasher.update(b"|");
    hasher.update(step_id.as_bytes());
    hasher.update(b"|");
    hasher.update(operation.as_bytes());
    hasher.update(b"|");
    hasher.update(mode_s.as_bytes());
    hasher.update(b"|");
    hasher.update(payload);
    hasher.finalize().to_hex().to_string()
}

fn sealed_digest(
    session_id: &str,
    asset_id: &str,
    binding_digests: &[String],
    prec: &str,
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DOMAIN_SEAL);
    hasher.update(session_id.as_bytes());
    hasher.update(b"|");
    hasher.update(asset_id.as_bytes());
    hasher.update(b"|");
    for d in binding_digests {
        hasher.update(d.as_bytes());
        hasher.update(b"|");
    }
    hasher.update(prec.as_bytes());
    hasher.finalize().to_hex().to_string()
}

/// Reserved tools/call arguments key (agent path). Stripped before
/// constraints, CheckStep digest, and upstream relay.
pub const VAUBAN_ARGS_KEY: &str = "vauban";

/// Extract Contract: `arguments.vauban.contract` then `_meta.vauban.contract`.
pub fn extract_contract(params: &Value) -> Option<Value> {
    params
        .pointer("/arguments/vauban/contract")
        .or_else(|| params.pointer("/_meta/vauban/contract"))
        .cloned()
}

/// Extract Story: `arguments.vauban.story` then `_meta.vauban.story`.
pub fn extract_story(params: &Value) -> Option<Value> {
    params
        .pointer("/arguments/vauban/story")
        .or_else(|| params.pointer("/_meta/vauban/story"))
        .cloned()
}

/// Drop `arguments.vauban` so the amont / CheckStep see tool args only.
pub fn strip_vauban_args(args: &Value) -> Value {
    let mut v = args.clone();
    if let Value::Object(ref mut map) = v {
        map.remove(VAUBAN_ARGS_KEY);
    }
    v
}

/// Strip `params.arguments.vauban` on a JSON-RPC body before upstream.
pub fn strip_vauban_from_rpc_body(body: &mut Value) {
    if let Some(Value::Object(map)) = body.pointer_mut("/params/arguments") {
        map.remove(VAUBAN_ARGS_KEY);
    }
}

fn story_field_len(s: &str, min: usize, max: usize, name: &str) -> Result<(), String> {
    let t = s.trim();
    if t.len() < min || t.len() > max {
        return Err(format!(
            "require_plan_story_for_human: {name} must be {min}..{max} (trimmed)"
        ));
    }
    Ok(())
}

/// Validate Story **shape** for human display. Never used for CheckStep.
pub fn parse_story(raw: &Value) -> Result<PlanStory, String> {
    let s: PlanStory = serde_json::from_value(raw.clone()).map_err(|_| {
        "require_plan_story_for_human: story must be an object with summary, context, objective, risks"
            .to_string()
    })?;
    story_field_len(&s.summary, 10, 200, "summary")?;
    story_field_len(&s.context, 10, 500, "context")?;
    story_field_len(&s.objective, 10, 500, "objective")?;
    story_field_len(&s.risks, 10, 500, "risks")?;
    Ok(PlanStory {
        summary: s.summary.trim().to_string(),
        context: s.context.trim().to_string(),
        objective: s.objective.trim().to_string(),
        risks: s.risks.trim().to_string(),
    })
}

pub fn story_to_json(story: &PlanStory) -> String {
    serde_json::to_string(story).unwrap_or_else(|_| "{}".into())
}

pub fn parse_contract(raw: &Value) -> Result<Contract, String> {
    let c: Contract =
        serde_json::from_value(raw.clone()).map_err(|e| format!("invalid_contract: {e}"))?;
    if c.steps.is_empty() {
        return Err("invalid_contract: empty steps".into());
    }
    if c.steps.len() > 64 {
        return Err("invalid_contract: too many steps".into());
    }
    let mut seen = HashSet::new();
    for s in &c.steps {
        let id = s.step_id.trim();
        if id.is_empty() || !seen.insert(id.to_string()) {
            return Err("invalid_contract: bad or duplicate step_id".into());
        }
        if s.operation.trim().is_empty() {
            return Err("invalid_contract: empty operation".into());
        }
        let intent = s.intent.trim();
        if intent.len() < 10 || intent.len() > 500 {
            return Err("invalid_contract: intent must be 10..500".into());
        }
        if !matches!(s.mode, BindingMode::Literal) {
            return Err("invalid_contract: only mode=literal enforced in v1".into());
        }
    }
    if matches!(c.approval, ApprovalKind::Step) {
        return Err("invalid_contract: approval=step not enforced in v1 (use mission)".into());
    }
    Ok(c)
}

/// Seal a validated Contract into runtime MandateState.
pub fn seal_mandate(
    mandate_id: &str,
    session_id: &str,
    asset_id: &str,
    contract: &Contract,
    now: f64,
) -> Result<MandateState, String> {
    if mandate_id.is_empty() || session_id.is_empty() || asset_id.is_empty() {
        return Err("invalid_contract: empty seal identity".into());
    }
    let mut pred_map: HashMap<String, Vec<String>> = HashMap::new();
    for s in &contract.steps {
        pred_map.insert(s.step_id.clone(), s.precedes.clone());
    }
    for edge in &contract.edges {
        pred_map
            .entry(edge[1].clone())
            .or_default()
            .push(edge[0].clone());
    }

    let mut steps = Vec::with_capacity(contract.steps.len());
    let mut binding_digests = Vec::new();
    for s in &contract.steps {
        let args_digest = digest_args_raw(Some(&s.arguments));
        let payload = serde_json::to_vec(&s.arguments).unwrap_or_default();
        let bd = binding_digest(mandate_id, &s.step_id, &s.operation, s.mode, &payload);
        binding_digests.push(bd.clone());
        let predecessors = pred_map.get(&s.step_id).cloned().unwrap_or_default();
        steps.push(SealedStep {
            step_id: s.step_id.clone(),
            operation: s.operation.clone(),
            intent: s.intent.trim().to_string(),
            mode: s.mode,
            args_digest,
            binding_digest: bd,
            predecessors,
            consumed: false,
        });
    }
    let mut prec_canon: Vec<String> = Vec::new();
    for s in &steps {
        for p in &s.predecessors {
            prec_canon.push(format!("{p}->{}", s.step_id));
        }
    }
    prec_canon.sort();
    let prec = prec_canon.join(";");
    let sealed = sealed_digest(session_id, asset_id, &binding_digests, &prec);
    let contract_json = serde_json::to_string(contract).unwrap_or_else(|_| "{}".into());
    Ok(MandateState {
        mandate_id: mandate_id.to_string(),
        sealed_digest: sealed,
        approval: contract.approval,
        contract_json,
        steps,
        results: HashMap::new(),
        inflight: None,
        expires_at: now + MISSION_TTL_DEFAULT_SECS,
    })
}

pub fn is_expired(mandate: &MandateState, now: f64) -> bool {
    now > mandate.expires_at
}

pub fn all_steps_done(mandate: &MandateState) -> bool {
    mandate.steps.iter().all(|s| s.consumed) && mandate.inflight.is_none()
}

/// PEP CheckStep applies only while the mission is in progress.
/// After `all_steps_done` the mandate object stays for replace / display;
/// tools revert to their access-rule modes (Allow / HITL / Require plan).
pub fn pep_mandate_active(mandate: &MandateState) -> bool {
    !all_steps_done(mandate)
}

/// What the PEP does with a live (or finished) mandate on this `tools/call`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MandatePdpPlan {
    NoMandate,
    /// Completed mission + new Story/Contract on a Require plan tool.
    Replace,
    /// Mandate object exists but CheckStep is off (`all_steps_done`).
    Inactive,
    /// Mission in progress — CheckStep every call.
    CheckStep,
}

pub fn plan_mandate_pdp(
    mandate: Option<&MandateState>,
    require_plan: bool,
    params: &Value,
) -> MandatePdpPlan {
    let Some(m) = mandate else {
        return MandatePdpPlan::NoMandate;
    };
    if require_plan
        && all_steps_done(m)
        && extract_story(params).is_some()
        && extract_contract(params).is_some()
    {
        return MandatePdpPlan::Replace;
    }
    if pep_mandate_active(m) {
        MandatePdpPlan::CheckStep
    } else {
        MandatePdpPlan::Inactive
    }
}

/// Enter HITL/CheckStep for this call?
pub fn pep_enter_hitl(needs_hitl: bool, mandate: Option<&MandateState>) -> bool {
    needs_hitl || mandate.is_some_and(pep_mandate_active)
}

/// Treat the call as Require plan (Story/Contract / CheckStep)?
pub fn pep_treat_as_require_plan(require_plan: bool, mandate: Option<&MandateState>) -> bool {
    require_plan || mandate.is_some_and(pep_mandate_active)
}

/// Store memorized result after successful upstream; clear mandate when done.
pub fn commit_step_result(
    mandate: &mut MandateState,
    step_id: &str,
    call_digest: &str,
    body: Value,
) {
    mandate
        .results
        .insert((step_id.to_string(), call_digest.to_string()), body);
    if mandate
        .inflight
        .as_ref()
        .is_some_and(|(s, d)| s == step_id && d == call_digest)
    {
        mandate.inflight = None;
    }
}

/// Upstream failed after Allow — restore step so the agent can retry.
pub fn rollback_inflight(mandate: &mut MandateState) {
    if let Some((step_id, _)) = mandate.inflight.take()
        && let Some(s) = mandate.steps.iter_mut().find(|s| s.step_id == step_id)
    {
        s.consumed = false;
    }
}

/// Multiset + precedence CheckStep (literal only).
pub fn check_step(
    mandate: &mut MandateState,
    tool: &str,
    args: Option<&Value>,
) -> CheckStepOutcome {
    let call_digest = digest_call_body(tool, args);
    let args_d = digest_args_raw(args);

    // Replay: same (step, body) already succeeded — cached body, no upstream.
    for s in &mandate.steps {
        if s.operation == tool
            && s.args_digest == args_d
            && let Some(cached) = mandate
                .results
                .get(&(s.step_id.clone(), call_digest.clone()))
        {
            return CheckStepOutcome::Replay {
                step_id: s.step_id.clone(),
                cached: cached.clone(),
            };
        }
    }

    // Same body reserved but upstream not finished yet.
    if mandate
        .inflight
        .as_ref()
        .is_some_and(|(_, d)| d == &call_digest)
    {
        return CheckStepOutcome::Deny {
            reason: "step_inflight",
        };
    }

    let consumed: HashSet<String> = mandate
        .steps
        .iter()
        .filter(|s| s.consumed)
        .map(|s| s.step_id.clone())
        .collect();

    let mut candidates: Vec<usize> = Vec::new();
    for (i, s) in mandate.steps.iter().enumerate() {
        if s.consumed {
            continue;
        }
        if s.operation != tool {
            continue;
        }
        if s.mode != BindingMode::Literal {
            return CheckStepOutcome::Deny {
                reason: "mode_not_supported",
            };
        }
        if s.args_digest != args_d {
            continue;
        }
        if s.predecessors.iter().all(|p| consumed.contains(p)) {
            candidates.push(i);
        }
    }

    if candidates.is_empty() {
        // Wrong args for a declared operation → explicit drift deny.
        let op_declared = mandate
            .steps
            .iter()
            .any(|s| s.operation == tool && !s.consumed);
        if op_declared {
            return CheckStepOutcome::Deny {
                reason: "args_mismatch_or_precedence",
            };
        }
        return CheckStepOutcome::Deny {
            reason: "step_not_in_contract",
        };
    }

    // Deterministic: lowest step_id among candidates.
    candidates.sort_by_key(|&i| mandate.steps[i].step_id.clone());
    let idx = candidates[0];
    let step_id = mandate.steps[idx].step_id.clone();
    mandate.steps[idx].consumed = true;
    mandate.inflight = Some((step_id.clone(), call_digest.clone()));
    CheckStepOutcome::Allow {
        step_id,
        call_digest,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_contract() -> Contract {
        Contract {
            approval: ApprovalKind::Mission,
            edges: vec![["1".into(), "2".into()]],
            steps: vec![
                ContractStep {
                    step_id: "1".into(),
                    operation: "echo".into(),
                    intent: "Say hello to the lab upstream".into(),
                    mode: BindingMode::Literal,
                    arguments: json!({"message": "seal-1"}),
                    precedes: vec![],
                },
                ContractStep {
                    step_id: "2".into(),
                    operation: "get_time".into(),
                    intent: "Fetch UTC clock after echo".into(),
                    mode: BindingMode::Literal,
                    arguments: json!({}),
                    precedes: vec![],
                },
            ],
        }
    }

    #[test]
    fn raw_digest_differs_from_redacted_bait() {
        // Secret-shaped key still hashed as raw (redact would strip).
        let a = digest_args_raw(Some(&json!({"password": "alpha"})));
        let b = digest_args_raw(Some(&json!({"password": "beta"})));
        assert_ne!(a, b, "P0: raw digest must catch secret bait-and-switch");
    }

    #[test]
    fn check_step_literal_chain_and_drift() {
        let c = sample_contract();
        let mut m = seal_mandate("m1", "sess", "asset", &c, 1_000.0).unwrap();
        assert!((m.expires_at - 1_000.0 - MISSION_TTL_DEFAULT_SECS).abs() < 0.1);

        assert!(matches!(
            check_step(&mut m, "get_time", Some(&json!({}))),
            CheckStepOutcome::Deny { .. }
        ));

        assert!(matches!(
            check_step(&mut m, "echo", Some(&json!({"message": "wrong"}))),
            CheckStepOutcome::Deny {
                reason: "args_mismatch_or_precedence"
            }
        ));

        assert!(matches!(
            check_step(&mut m, "echo", Some(&json!({"message": "seal-1"}))),
            CheckStepOutcome::Allow { .. }
        ));
        // Simulate successful upstream.
        let dig = digest_call_body("echo", Some(&json!({"message": "seal-1"})));
        commit_step_result(&mut m, "1", &dig, json!({"result": {"ok": true}}));

        assert!(matches!(
            check_step(&mut m, "get_time", Some(&json!({}))),
            CheckStepOutcome::Allow { .. }
        ));
    }

    #[test]
    fn idempotent_replay_returns_cached_not_second_allow() {
        let c = sample_contract();
        let mut m = seal_mandate("m1", "sess", "asset", &c, 1_000.0).unwrap();
        let args = json!({"message": "seal-1"});
        let allow = check_step(&mut m, "echo", Some(&args));
        let CheckStepOutcome::Allow {
            step_id,
            call_digest,
        } = allow
        else {
            panic!("expected Allow");
        };
        let body = json!({"jsonrpc":"2.0","id":1,"result":{"content":[{"text":"hi"}]}});
        commit_step_result(&mut m, &step_id, &call_digest, body.clone());

        match check_step(&mut m, "echo", Some(&args)) {
            CheckStepOutcome::Replay { cached, .. } => assert_eq!(cached, body),
            other => panic!("expected Replay, got {other:?}"),
        }
    }

    #[test]
    fn rollback_inflight_allows_retry() {
        let c = sample_contract();
        let mut m = seal_mandate("m1", "sess", "asset", &c, 1_000.0).unwrap();
        let args = json!({"message": "seal-1"});
        assert!(matches!(
            check_step(&mut m, "echo", Some(&args)),
            CheckStepOutcome::Allow { .. }
        ));
        rollback_inflight(&mut m);
        assert!(matches!(
            check_step(&mut m, "echo", Some(&args)),
            CheckStepOutcome::Allow { .. }
        ));
    }

    #[test]
    fn pep_inactive_after_all_steps_done() {
        let c = sample_contract();
        let mut m = seal_mandate("m1", "sess", "asset", &c, 1_000.0).unwrap();
        assert!(pep_mandate_active(&m));
        let args = json!({"message": "seal-1"});
        let CheckStepOutcome::Allow {
            step_id,
            call_digest,
        } = check_step(&mut m, "echo", Some(&args))
        else {
            panic!("expected Allow");
        };
        commit_step_result(&mut m, &step_id, &call_digest, json!({"ok": true}));
        assert!(pep_mandate_active(&m), "second step still open");
        let CheckStepOutcome::Allow {
            step_id,
            call_digest,
        } = check_step(&mut m, "get_time", Some(&json!({})))
        else {
            panic!("expected Allow");
        };
        commit_step_result(&mut m, &step_id, &call_digest, json!({"ok": true}));
        assert!(all_steps_done(&m));
        assert!(!pep_mandate_active(&m));
        assert!(!pep_enter_hitl(false, Some(&m)));
        assert!(pep_enter_hitl(true, Some(&m)));
        assert!(!pep_treat_as_require_plan(false, Some(&m)));
        assert!(pep_treat_as_require_plan(true, Some(&m)));
        assert!(!pep_enter_hitl(false, None));
        assert_eq!(
            plan_mandate_pdp(None, false, &json!({})),
            MandatePdpPlan::NoMandate
        );
        assert_eq!(
            plan_mandate_pdp(Some(&m), false, &json!({})),
            MandatePdpPlan::Inactive
        );
        let replace_params = json!({
            "arguments": {
                "vauban": {
                    "story": { "summary": "ten chars.." },
                    "contract": { "approval": "mission" }
                }
            }
        });
        assert_eq!(
            plan_mandate_pdp(Some(&m), true, &replace_params),
            MandatePdpPlan::Replace
        );
        assert_eq!(
            plan_mandate_pdp(Some(&m), false, &replace_params),
            MandatePdpPlan::Inactive
        );
    }

    #[test]
    fn binding_mode_as_str_covers_v1_and_later() {
        assert_eq!(BindingMode::Literal.as_str(), "literal");
        assert_eq!(BindingMode::Constrained.as_str(), "constrained");
        assert_eq!(BindingMode::Derived.as_str(), "derived");
    }

    #[test]
    fn plan_mandate_pdp_checkstep_while_in_progress() {
        let c = sample_contract();
        let m = seal_mandate("m1", "sess", "asset", &c, 1_000.0).unwrap();
        assert_eq!(
            plan_mandate_pdp(Some(&m), false, &json!({})),
            MandatePdpPlan::CheckStep
        );
        assert!(pep_enter_hitl(false, Some(&m)));
        assert!(pep_treat_as_require_plan(false, Some(&m)));
    }

    fn hello_then_secret_replace_params() -> Value {
        json!({
            "name": "read_demo_file",
            "arguments": {
                "name": "secret.txt",
                "vauban": {
                    "story": {
                        "summary": "Read the lab secret file after hello.",
                        "context": "Local MCP lab after all_steps_done of hello.txt.",
                        "objective": "Queue a new HITL for secret.txt only.",
                        "risks": "Reusing the hello mandate would -32033 this call."
                    },
                    "contract": {
                        "approval": "mission",
                        "steps": [{
                            "step_id": "1",
                            "operation": "read_demo_file",
                            "intent": "Read the sealed lab secret file now",
                            "mode": "literal",
                            "arguments": {"name": "secret.txt"}
                        }]
                    }
                }
            }
        })
    }

    /// Mid-mission: a new Story+Contract is still CheckStep (the PEP
    /// must not Replace until `all_steps_done`). After commit, the
    /// same hello→secret payload is Replace.
    #[test]
    fn plan_mandate_pdp_hello_then_secret_replace_only_when_done() {
        let c = parse_contract(&json!({
            "approval": "mission",
            "edges": [],
            "steps": [{
                "step_id": "1",
                "intent": "Read the sealed lab hello file now",
                "operation": "read_demo_file",
                "mode": "literal",
                "arguments": {"name": "hello.txt"}
            }]
        }))
        .unwrap();
        let mut m = seal_mandate("m-hello", "sess", "asset", &c, 1_000.0).unwrap();
        let params = hello_then_secret_replace_params();
        assert_eq!(
            plan_mandate_pdp(Some(&m), true, &params),
            MandatePdpPlan::CheckStep,
            "unconsumed hello mandate + new secret Seal must stay CheckStep"
        );
        let args = json!({"name": "hello.txt"});
        let CheckStepOutcome::Allow {
            step_id,
            call_digest,
        } = check_step(&mut m, "read_demo_file", Some(&args))
        else {
            panic!("expected Allow");
        };
        commit_step_result(&mut m, &step_id, &call_digest, json!({"ok": true}));
        assert!(all_steps_done(&m));
        assert_eq!(
            plan_mandate_pdp(Some(&m), true, &params),
            MandatePdpPlan::Replace,
            "after hello all_steps_done, secret Story+Contract must Replace"
        );
    }

    #[test]
    fn parse_contract_rejects_shape_and_modes() {
        assert!(parse_contract(&json!("nope")).is_err());
        assert!(parse_contract(&json!({"approval":"mission","steps":[]})).is_err());
        let too_many = (0..65)
            .map(|i| {
                json!({
                    "step_id": format!("{i}"),
                    "operation": "echo",
                    "intent": "ten chars..",
                    "mode": "literal",
                    "arguments": {}
                })
            })
            .collect::<Vec<_>>();
        assert!(parse_contract(&json!({"approval":"mission","steps": too_many})).is_err());
        assert!(
            parse_contract(&json!({
                "approval":"mission",
                "steps":[{
                    "step_id":"",
                    "operation":"echo",
                    "intent":"ten chars..",
                    "mode":"literal",
                    "arguments":{}
                }]
            }))
            .is_err()
        );
        assert!(parse_contract(&json!({
            "approval":"mission",
            "steps":[
                {"step_id":"1","operation":"echo","intent":"ten chars..","mode":"literal","arguments":{}},
                {"step_id":"1","operation":"echo","intent":"ten chars..","mode":"literal","arguments":{}}
            ]
        }))
        .is_err());
        assert!(
            parse_contract(&json!({
                "approval":"mission",
                "steps":[{
                    "step_id":"1",
                    "operation":"",
                    "intent":"ten chars..",
                    "mode":"literal",
                    "arguments":{}
                }]
            }))
            .is_err()
        );
        assert!(
            parse_contract(&json!({
                "approval":"mission",
                "steps":[{
                    "step_id":"1",
                    "operation":"echo",
                    "intent":"short",
                    "mode":"literal",
                    "arguments":{}
                }]
            }))
            .is_err()
        );
        assert!(
            parse_contract(&json!({
                "approval":"mission",
                "steps":[{
                    "step_id":"1",
                    "operation":"echo",
                    "intent":"ten chars..",
                    "mode":"constrained",
                    "arguments":{}
                }]
            }))
            .is_err()
        );
        let ok = parse_contract(&json!({
            "approval":"mission",
            "edges":[["1","2"]],
            "steps":[
                {"step_id":"1","operation":"echo","intent":"ten chars..","mode":"literal","arguments":{"m":"a"}},
                {"step_id":"2","operation":"get_time","intent":"ten chars..","mode":"literal","arguments":{}}
            ]
        }))
        .unwrap();
        let sealed = seal_mandate("m", "s", "a", &ok, 1.0).unwrap();
        assert_eq!(sealed.steps[1].predecessors, vec!["1".to_string()]);
        assert!(
            parse_story(&json!({
                "summary": "0123456789",
                "context": "0123456789",
                "objective": "0123456789",
                "risks": "x".repeat(501)
            }))
            .is_err()
        );
        let story = parse_story(&json!({
            "summary": "  ten chars.  ",
            "context": "  ten chars.  ",
            "objective": "  ten chars.  ",
            "risks": "  ten chars.  "
        }))
        .unwrap();
        assert_eq!(story.summary, "ten chars.");
        let _ = story_to_json(&story);
        strip_vauban_from_rpc_body(&mut json!({"params":{"arguments":"not-obj"}}));
        assert_eq!(strip_vauban_args(&json!("x")), json!("x"));
        let _ = digest_args_raw(None);
        let _ = digest_call_body("echo", None);
        assert!(seal_mandate("", "s", "a", &ok, 1.0).is_err());
        let _ = is_expired(&sealed, 0.0);
        rollback_inflight(&mut seal_mandate("m", "s", "a", &ok, 1.0).unwrap());
        let mut m = seal_mandate("m", "s", "a", &ok, 1.0).unwrap();
        m.steps[0].mode = BindingMode::Constrained;
        assert!(matches!(
            check_step(&mut m, "echo", Some(&json!({"m":"a"}))),
            CheckStepOutcome::Deny {
                reason: "mode_not_supported"
            }
        ));
        let mut ordered = seal_mandate("m", "s", "a", &ok, 1.0).unwrap();
        assert!(matches!(
            check_step(&mut ordered, "get_time", Some(&json!({}))),
            CheckStepOutcome::Deny {
                reason: "args_mismatch_or_precedence"
            }
        ));
        assert!(is_expired(&ordered, 1.0 + MISSION_TTL_DEFAULT_SECS + 1.0));
        commit_step_result(&mut ordered, "nope", "nope", json!({}));
        ordered.inflight = Some(("missing".into(), "x".into()));
        rollback_inflight(&mut ordered);
    }

    #[test]
    fn perimeter_drift_excludes_inflight_and_expiry() {
        assert!(is_perimeter_drift("args_mismatch_or_precedence"));
        assert!(is_perimeter_drift("step_not_in_contract"));
        assert!(is_perimeter_drift("mode_not_supported"));
        assert!(!is_perimeter_drift("step_inflight"));
        assert!(!is_perimeter_drift("mission_expired"));
    }

    #[test]
    fn step_inflight_is_deny_not_allow() {
        let c = sample_contract();
        let mut m = seal_mandate("m1", "sess", "asset-uuid", &c, 1_000.0).unwrap();
        let args = json!({"message": "seal-1"});
        assert!(matches!(
            check_step(&mut m, "echo", Some(&args)),
            CheckStepOutcome::Allow { .. }
        ));
        assert!(matches!(
            check_step(&mut m, "echo", Some(&args)),
            CheckStepOutcome::Deny {
                reason: "step_inflight"
            }
        ));
        assert!(!is_perimeter_drift("step_inflight"));
    }

    #[test]
    fn approval_step_rejected_until_p1() {
        let mut c = sample_contract();
        c.approval = ApprovalKind::Step;
        assert!(parse_contract(&serde_json::to_value(&c).unwrap()).is_err());
    }

    #[test]
    fn sealed_digest_binds_asset_id() {
        let c = sample_contract();
        let a = seal_mandate("m1", "sess", "asset-aaa", &c, 1_000.0).unwrap();
        let b = seal_mandate("m1", "sess", "asset-bbb", &c, 1_000.0).unwrap();
        assert_ne!(
            a.sealed_digest, b.sealed_digest,
            "sealed_digest must bind asset UUID, not a generic label"
        );
    }

    #[test]
    fn story_shape_accepts_and_rejects() {
        let ok = parse_story(&json!({
            "summary": "Run a short lab echo then clock check.",
            "context": "Local MCP lab asset used for Mission Seal demos.",
            "objective": "Prove sealed steps succeed and drift is denied.",
            "risks": "Wrong Approve would allow the declared echo/get_time only."
        }))
        .unwrap();
        assert!(ok.summary.contains("lab echo"));

        assert!(parse_story(&json!({"summary": "too short"})).is_err());
        assert!(parse_story(&json!("just a string")).is_err());
    }

    #[test]
    fn extract_prefers_arguments_vauban_over_meta() {
        let params = json!({
            "name": "read_demo_file",
            "arguments": {
                "name": "hello.txt",
                "vauban": {
                    "story": { "summary": "from arguments vauban story field here" },
                    "contract": { "approval": "mission" }
                }
            },
            "_meta": {
                "vauban": {
                    "story": { "summary": "from meta only should lose" },
                    "contract": { "approval": "ignored" }
                }
            }
        });
        assert_eq!(
            extract_story(&params).unwrap()["summary"],
            "from arguments vauban story field here"
        );
        assert_eq!(extract_contract(&params).unwrap()["approval"], "mission");
    }

    #[test]
    fn extract_falls_back_to_meta_vauban() {
        let params = json!({
            "name": "echo",
            "arguments": { "message": "hi" },
            "_meta": {
                "vauban": {
                    "story": { "summary": "meta story path for curl and demo" },
                    "contract": { "approval": "mission" }
                }
            }
        });
        assert!(
            extract_story(&params).unwrap()["summary"]
                .as_str()
                .unwrap()
                .contains("meta story")
        );
        assert_eq!(extract_contract(&params).unwrap()["approval"], "mission");
    }

    #[test]
    fn strip_vauban_leaves_tool_args() {
        let args = json!({ "name": "hello.txt", "vauban": { "story": {} } });
        let stripped = strip_vauban_args(&args);
        assert_eq!(stripped, json!({ "name": "hello.txt" }));
        let mut body = json!({
            "method": "tools/call",
            "params": { "name": "read_demo_file", "arguments": args }
        });
        strip_vauban_from_rpc_body(&mut body);
        assert_eq!(body["params"]["arguments"], json!({ "name": "hello.txt" }));
    }
}
