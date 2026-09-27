// Relax strict clippy lints in test code where unwrap/expect/panic are idiomatic.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::print_stdout,
        clippy::print_stderr
    )
)]

//! PEP view of MCP tools for an agent session.
//!
//! `tools/list` from upstream is filtered by the frozen allow-list, then
//! Require-plan tools gain `arguments.vauban` (Story + Contract) in
//! `inputSchema`. `initialize.instructions` is identity only (MOTD),
//! not a second tool catalogue — that is `tools/list`.

use crate::tool_constraints::ToolConstraint;
use serde_json::{Value, json};
use std::collections::HashMap;

/// Reserved arguments key. Stripped before constraints / CheckStep / upstream.
pub const VAUBAN_ARGS_KEY: &str = "vauban";

/// JSON Schema for `arguments.vauban` (agent DTO).
pub fn vauban_plan_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["story", "contract"],
        "description": "Vauban Mission Seal. A human Approves the Contract; Vauban verifies the Contract only.",
        "properties": {
            "story": {
                "type": "object",
                "additionalProperties": false,
                "required": ["summary", "context", "objective", "risks"],
                "description": "Why this mission. A human supervisor reads this before Approve.",
                "properties": {
                    "summary": {
                        "type": "string",
                        "minLength": 10,
                        "maxLength": 200,
                        "description": "One sentence: what will this mission do?"
                    },
                    "context": {
                        "type": "string",
                        "minLength": 10,
                        "maxLength": 500,
                        "description": "Why now / which system."
                    },
                    "objective": {
                        "type": "string",
                        "minLength": 10,
                        "maxLength": 500,
                        "description": "Expected outcome for the operator."
                    },
                    "risks": {
                        "type": "string",
                        "minLength": 10,
                        "maxLength": 500,
                        "description": "What Approve does and does not permit."
                    }
                }
            },
            "contract": {
                "type": "object",
                "additionalProperties": false,
                "required": ["approval", "steps"],
                "description": "What will run. After Approve, only these steps pass.",
                "properties": {
                    "approval": {
                        "type": "string",
                        "enum": ["mission"],
                        "description": "One Approve seals the whole Contract."
                    },
                    "edges": {
                        "type": "array",
                        "items": {
                            "type": "array",
                            "minItems": 2,
                            "maxItems": 2,
                            "items": { "type": "string" }
                        },
                        "description": "Optional [from, to] step_id pairs (to depends on from)."
                    },
                    "steps": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": 64,
                        "items": {
                            "type": "object",
                            "additionalProperties": false,
                            "required": ["step_id", "operation", "intent", "mode", "arguments"],
                            "properties": {
                                "step_id": { "type": "string", "minLength": 1 },
                                "operation": {
                                    "type": "string",
                                    "minLength": 1,
                                    "description": "Tool name for this step."
                                },
                                "intent": {
                                    "type": "string",
                                    "minLength": 10,
                                    "maxLength": 500
                                },
                                "mode": {
                                    "type": "string",
                                    "enum": ["literal"],
                                    "description": "Call args must match the sealed arguments bit-for-bit."
                                },
                                "arguments": { "type": "object" }
                            }
                        }
                    }
                }
            }
        }
    })
}

/// Identity MOTD for `initialize.result.instructions`.
///
/// Not a catalogue. Tool names and modes live only on hop-2 `tools/list`
/// (filter + `arguments.vauban` / HITL description). Same idea as SSH:
/// the proxy filters commands; the banner does not invent them.
pub const VISIT_IDENTITY: &str =
    "This MCP endpoint is Vauban PAM. Callable tools are those in tools/list for this visit.";

/// Visit banner for MCP `initialize.result.instructions`.
pub fn visit_instructions(
    _allowed: Option<&[String]>,
    _constraints: &HashMap<String, ToolConstraint>,
) -> String {
    VISIT_IDENTITY.to_string()
}

pub fn attach_visit_instructions(
    result: &mut Value,
    allowed: Option<&[String]>,
    constraints: &HashMap<String, ToolConstraint>,
) {
    let extra = visit_instructions(allowed, constraints);
    let merged = match result.get("instructions").and_then(Value::as_str) {
        Some(existing) if !existing.is_empty() => format!("{extra}\n\n{existing}"),
        _ => extra,
    };
    if let Value::Object(map) = result {
        map.insert("instructions".into(), Value::String(merged));
    }
}

/// Filter allow-list then advertise HITL / Require plan on each tool.
pub fn filter_and_enrich_tools(
    result: Value,
    allowed: Option<&[String]>,
    constraints: &HashMap<String, ToolConstraint>,
    require_vauban_fields: bool,
) -> Value {
    let Some(tools) = result.get("tools").and_then(Value::as_array) else {
        return result;
    };
    let filtered: Vec<Value> = match allowed {
        None => Vec::new(),
        Some(allowed) => tools
            .iter()
            .filter(|t| {
                t.get("name")
                    .and_then(Value::as_str)
                    .is_some_and(|n| allowed.iter().any(|a| a == n))
            })
            .map(|t| enrich_one_tool(t.clone(), constraints, require_vauban_fields))
            .collect(),
    };
    let mut out = result;
    if let Value::Object(ref mut map) = out {
        map.insert("tools".to_string(), Value::Array(filtered));
    }
    out
}

fn enrich_one_tool(
    mut tool: Value,
    constraints: &HashMap<String, ToolConstraint>,
    require_vauban_fields: bool,
) -> Value {
    let Some(name) = tool.get("name").and_then(Value::as_str).map(str::to_string) else {
        return tool;
    };
    let Some(c) = constraints.get(&name) else {
        return tool;
    };
    if c.require_plan {
        append_description(
            &mut tool,
            " Vauban Require plan: first call must include arguments.vauban.story and arguments.vauban.contract. After human Approve, call again with tool args only.",
        );
        merge_vauban_into_input_schema(&mut tool, require_vauban_fields);
    } else if c.hitl {
        append_description(
            &mut tool,
            " Vauban HITL: first call waits for a human Approve on /sessions/mcp.",
        );
    }
    tool
}

fn append_description(tool: &mut Value, suffix: &str) {
    let Value::Object(map) = tool else { return };
    let desc = map
        .get("description")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if desc.contains("Vauban Require plan") || desc.contains("Vauban HITL") {
        return;
    }
    let next = if desc.is_empty() {
        suffix.trim().to_string()
    } else {
        format!("{desc}{suffix}")
    };
    map.insert("description".into(), Value::String(next));
}

fn merge_vauban_into_input_schema(tool: &mut Value, required: bool) {
    let Value::Object(map) = tool else { return };
    let key = if map.contains_key("inputSchema") {
        "inputSchema"
    } else if map.contains_key("input_schema") {
        "input_schema"
    } else {
        map.insert(
            "inputSchema".into(),
            json!({"type": "object", "properties": {}}),
        );
        "inputSchema"
    };
    let Some(schema) = map.get_mut(key) else {
        return;
    };
    let Value::Object(schema) = schema else {
        return;
    };
    if !schema.contains_key("type") {
        schema.insert("type".into(), json!("object"));
    }
    let props = schema.entry("properties").or_insert_with(|| json!({}));
    if let Value::Object(props) = props {
        props.insert(VAUBAN_ARGS_KEY.into(), vauban_plan_schema());
    }
    if required {
        let req = schema.entry("required").or_insert_with(|| json!([]));
        if let Value::Array(req) = req {
            let has = req.iter().any(|v| v.as_str() == Some(VAUBAN_ARGS_KEY));
            if !has {
                req.push(json!(VAUBAN_ARGS_KEY));
            }
        }
    } else if let Some(Value::Array(req)) = schema.get_mut("required") {
        req.retain(|v| v.as_str() != Some(VAUBAN_ARGS_KEY));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan_constraint() -> ToolConstraint {
        ToolConstraint {
            input_schema: json!({}),
            forbidden_keys: vec![],
            hitl: true,
            require_plan: true,
            status: None,
            schema_fingerprint: None,
        }
    }

    fn hitl_constraint() -> ToolConstraint {
        ToolConstraint {
            input_schema: json!({}),
            forbidden_keys: vec![],
            hitl: true,
            require_plan: false,
            status: None,
            schema_fingerprint: None,
        }
    }

    #[test]
    fn plan_schema_requires_story_and_contract() {
        let s = vauban_plan_schema();
        let req = s["required"].as_array().unwrap();
        assert!(req.iter().any(|v| v == "story"));
        assert!(req.iter().any(|v| v == "contract"));
        assert_eq!(s["properties"]["story"]["required"][0], "summary");
        assert_eq!(
            s["properties"]["contract"]["properties"]["approval"]["enum"][0],
            "mission"
        );
    }

    #[test]
    fn filter_drops_tools_outside_allow_list() {
        let result = json!({
            "tools": [
                {"name": "echo", "inputSchema": {"type": "object", "properties": {}}},
                {"name": "write_secret", "inputSchema": {"type": "object"}}
            ]
        });
        let out = filter_and_enrich_tools(result, Some(&["echo".into()]), &HashMap::new(), true);
        let tools = out["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["name"], "echo");
        assert!(
            tools[0]["inputSchema"]["properties"]
                .get("vauban")
                .is_none()
        );
    }

    #[test]
    fn require_plan_tool_gains_vauban_required() {
        let result = json!({
            "tools": [{
                "name": "read_demo_file",
                "description": "Read a lab file",
                "inputSchema": {
                    "type": "object",
                    "required": ["name"],
                    "properties": { "name": { "type": "string" } }
                }
            }]
        });
        let mut c = HashMap::new();
        c.insert("read_demo_file".into(), plan_constraint());
        let out = filter_and_enrich_tools(result, Some(&["read_demo_file".into()]), &c, true);
        let tool = &out["tools"][0];
        assert!(
            tool["description"]
                .as_str()
                .unwrap()
                .contains("Require plan")
        );
        assert!(tool["inputSchema"]["properties"].get("vauban").is_some());
        assert!(tool["inputSchema"]["properties"].get("name").is_some());
        let req = tool["inputSchema"]["required"].as_array().unwrap();
        assert!(req.iter().any(|v| v == "name"));
        assert!(req.iter().any(|v| v == "vauban"));
    }

    #[test]
    fn after_seal_vauban_is_advertised_but_not_required() {
        let result = json!({
            "tools": [{
                "name": "read_demo_file",
                "inputSchema": { "type": "object", "properties": { "name": {} } }
            }]
        });
        let mut c = HashMap::new();
        c.insert("read_demo_file".into(), plan_constraint());
        let out = filter_and_enrich_tools(result, Some(&["read_demo_file".into()]), &c, false);
        assert!(
            out["tools"][0]["inputSchema"]["properties"]
                .get("vauban")
                .is_some()
        );
        let req = out["tools"][0]["inputSchema"]
            .get("required")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        assert!(req.iter().all(|v| v != "vauban"));
    }

    #[test]
    fn hitl_tool_gets_description_only() {
        let result = json!({
            "tools": [{
                "name": "hitl_demo",
                "inputSchema": { "type": "object", "properties": {} }
            }]
        });
        let mut c = HashMap::new();
        c.insert("hitl_demo".into(), hitl_constraint());
        let out = filter_and_enrich_tools(result, Some(&["hitl_demo".into()]), &c, true);
        assert!(
            out["tools"][0]["description"]
                .as_str()
                .unwrap()
                .contains("HITL")
        );
        assert!(
            out["tools"][0]["inputSchema"]["properties"]
                .get("vauban")
                .is_none()
        );
    }

    #[test]
    fn visit_instructions_is_identity_not_a_catalogue() {
        let mut c = HashMap::new();
        c.insert("read_demo_file".into(), plan_constraint());
        c.insert("hitl_demo".into(), hitl_constraint());
        let text = visit_instructions(
            Some(&["echo".into(), "read_demo_file".into(), "hitl_demo".into()]),
            &c,
        );
        assert_eq!(text, VISIT_IDENTITY);
        assert!(text.contains("tools/list"));
        assert!(
            !text.contains("echo")
                && !text.contains("read_demo_file")
                && !text.contains("hitl_demo")
                && !text.contains("HITL")
                && !text.contains("require_plan")
                && !text.contains("Contract")
                && !text.contains("Approve"),
            "MOTD must not list tools or policy verbs"
        );
    }

    #[test]
    fn visit_instructions_never_lists_session_or_pending_tools() {
        let mut c = HashMap::new();
        c.insert("add_ticket_comment".into(), hitl_constraint());
        c.insert("restart_service".into(), hitl_constraint());
        c.insert("deploy_release".into(), plan_constraint());
        let text = visit_instructions(Some(&["add_ticket_comment".into()]), &c);
        assert_eq!(text, VISIT_IDENTITY);
        assert!(
            !text.contains("add_ticket_comment")
                && !text.contains("restart_service")
                && !text.contains("deploy_release"),
            "initialize.instructions is not a tool inventory"
        );
    }

    #[test]
    fn attach_instructions_prepends_vauban_banner() {
        let mut result =
            json!({ "protocolVersion": "2025-03-26", "instructions": "upstream note" });
        attach_visit_instructions(&mut result, Some(&["echo".into()]), &HashMap::new());
        let s = result["instructions"].as_str().unwrap();
        assert!(s.contains("Vauban PAM"));
        assert!(s.contains("upstream note"));
        assert!(s.find("Vauban PAM").unwrap() < s.find("upstream note").unwrap());
    }

    #[test]
    fn enrich_edges_for_full_list_coverage() {
        assert_eq!(
            filter_and_enrich_tools(
                json!({"ok": true}),
                Some(&["echo".into()]),
                &HashMap::new(),
                true
            ),
            json!({"ok": true})
        );
        let empty = filter_and_enrich_tools(
            json!({"tools": [{"name": "echo"}]}),
            None,
            &HashMap::new(),
            true,
        );
        assert_eq!(empty["tools"].as_array().unwrap().len(), 0);
        let none_name = filter_and_enrich_tools(
            json!({"tools": [{"inputSchema": {}}]}),
            Some(&["echo".into()]),
            &HashMap::new(),
            true,
        );
        assert!(none_name["tools"].as_array().unwrap().is_empty());
        let mut c = HashMap::new();
        c.insert("read_demo_file".into(), plan_constraint());
        let snake = filter_and_enrich_tools(
            json!({"tools": [{
                "name": "read_demo_file",
                "description": "Vauban Require plan: already tagged",
                "input_schema": { "properties": { "vauban": {} }, "required": ["vauban"] }
            }]}),
            Some(&["read_demo_file".into()]),
            &c,
            true,
        );
        assert_eq!(
            snake["tools"][0]["description"],
            "Vauban Require plan: already tagged"
        );
        let created = filter_and_enrich_tools(
            json!({"tools": [{"name": "read_demo_file"}]}),
            Some(&["read_demo_file".into()]),
            &c,
            false,
        );
        assert!(
            created["tools"][0]["inputSchema"]["properties"]
                .get("vauban")
                .is_some()
        );
        let drop_req = filter_and_enrich_tools(
            json!({"tools": [{
                "name": "read_demo_file",
                "inputSchema": {
                    "properties": {},
                    "required": ["name", "vauban"]
                }
            }]}),
            Some(&["read_demo_file".into()]),
            &c,
            false,
        );
        let req = drop_req["tools"][0]["inputSchema"]["required"]
            .as_array()
            .unwrap();
        assert!(req.iter().all(|v| v != "vauban"));
        assert!(req.iter().any(|v| v == "name"));
        let hitl = {
            let mut h = HashMap::new();
            h.insert("hitl_demo".into(), hitl_constraint());
            filter_and_enrich_tools(
                json!({"tools": [{
                    "name": "hitl_demo",
                    "description": "Vauban HITL: already"
                }]}),
                Some(&["hitl_demo".into()]),
                &h,
                true,
            )
        };
        assert_eq!(hitl["tools"][0]["description"], "Vauban HITL: already");
        let text = visit_instructions(None, &HashMap::new());
        assert_eq!(text, VISIT_IDENTITY);
        let text = visit_instructions(Some(&[]), &HashMap::new());
        assert_eq!(text, VISIT_IDENTITY);
        let mut result = json!("not-obj");
        attach_visit_instructions(&mut result, None, &HashMap::new());
        let mut blank = json!({ "instructions": "" });
        attach_visit_instructions(&mut blank, Some(&["echo".into()]), &HashMap::new());
        assert!(
            blank["instructions"]
                .as_str()
                .unwrap()
                .contains("Vauban PAM")
        );
    }
}
