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

//! Destructive-tool argument gates (03 §5 / M10).
//!
//! JSON Schema Draft 2020-12 **subset** + `forbidden_keys` (case-insensitive,
//! any depth). Failure → caller maps to JSON-RPC `-32602`.

use serde_json::Value;
use std::collections::HashMap;

const MAX_DEPTH: usize = 6;

#[derive(Debug, Clone, Default)]
pub struct ToolConstraint {
    pub input_schema: Value,
    pub forbidden_keys: Vec<String>,
    /// Catalogue / rule HITL flag (09 §5): `tools/call` needs human approve.
    pub hitl: bool,
    /// Mission Seal: tools/call must carry a Contract (`require_plan`).
    pub require_plan: bool,
    /// TOFU status: `approved` | `pending` | `tombstone` (Phase 3.2).
    pub status: Option<String>,
    /// Frozen BLAKE3 schema fingerprint from catalogue.
    pub schema_fingerprint: Option<String>,
}

/// Parse `tool_constraints_json` from `McpSessionOpen`.
///
/// Accepted per-tool shapes:
/// - plain schema object (`{"type":"object",...}`)
/// - wrapper `{"input_schema":{...},"forbidden_keys":[...],"hitl":true,"require_plan":true,...}`
pub fn parse_constraints_json(raw: &str) -> HashMap<String, ToolConstraint> {
    let Ok(Value::Object(map)) = serde_json::from_str::<Value>(raw) else {
        return HashMap::new();
    };
    let mut out = HashMap::new();
    for (name, val) in map {
        if name.is_empty() {
            continue;
        }
        let constraint = match val {
            Value::Object(ref o)
                if o.contains_key("input_schema")
                    || o.contains_key("schema")
                    || o.contains_key("hitl")
                    || o.contains_key("require_plan")
                    || o.contains_key("status")
                    || o.contains_key("schema_fingerprint") =>
            {
                let schema = o
                    .get("input_schema")
                    .or_else(|| o.get("schema"))
                    .cloned()
                    .unwrap_or(Value::Object(Default::default()));
                let forbidden = o
                    .get("forbidden_keys")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(Value::as_str)
                            .map(|s| s.to_ascii_lowercase())
                            .collect()
                    })
                    .unwrap_or_default();
                let hitl = o.get("hitl").and_then(Value::as_bool).unwrap_or(false);
                let require_plan = o
                    .get("require_plan")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let status = o.get("status").and_then(Value::as_str).map(str::to_string);
                let schema_fingerprint = o
                    .get("schema_fingerprint")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                ToolConstraint {
                    input_schema: schema,
                    forbidden_keys: forbidden,
                    // require_plan implies HITL (Approve Contract).
                    hitl: hitl || require_plan,
                    require_plan,
                    status,
                    schema_fingerprint,
                }
            }
            other => ToolConstraint {
                input_schema: other,
                forbidden_keys: Vec::new(),
                hitl: false,
                require_plan: false,
                status: None,
                schema_fingerprint: None,
            },
        };
        out.insert(name, constraint);
    }
    out
}

/// Mid-session tighten: merge incoming constraints into the live map.
///
/// - Unknown tools in `incoming` are inserted.
/// - `hitl` / `require_plan` may only go **false → true** (never clear mid-flight).
/// - `forbidden_keys` are unioned; schema/status/fingerprint take incoming when set.
/// - Empty `incoming` is a no-op (callers send `"{}"` when only shrinking tools).
pub fn merge_constraints_tighten(
    current: &mut HashMap<String, ToolConstraint>,
    incoming: HashMap<String, ToolConstraint>,
) {
    for (name, new_c) in incoming {
        match current.get_mut(&name) {
            Some(cur) => {
                cur.hitl = cur.hitl || new_c.hitl;
                cur.require_plan = cur.require_plan || new_c.require_plan;
                if cur.require_plan {
                    cur.hitl = true;
                }
                for k in new_c.forbidden_keys {
                    if !cur.forbidden_keys.iter().any(|e| e == &k) {
                        cur.forbidden_keys.push(k);
                    }
                }
                if !new_c.input_schema.is_null() {
                    cur.input_schema = new_c.input_schema;
                }
                if new_c.status.is_some() {
                    cur.status = new_c.status;
                }
                if new_c.schema_fingerprint.is_some() {
                    cur.schema_fingerprint = new_c.schema_fingerprint;
                }
            }
            None => {
                current.insert(name, new_c);
            }
        }
    }
}

/// Validate `arguments` for a tool that has a constraint entry.
/// `Ok(())` = allow; `Err(reason)` = deny with `-32602`.
pub fn validate_tool_args(constraint: &ToolConstraint, args: Option<&Value>) -> Result<(), String> {
    let args = args.unwrap_or(&Value::Null);
    check_forbidden(args, &constraint.forbidden_keys, 0)?;
    validate_schema(&constraint.input_schema, args, 0)
}

fn check_forbidden(value: &Value, forbidden: &[String], depth: usize) -> Result<(), String> {
    if forbidden.is_empty() {
        return Ok(());
    }
    if depth > MAX_DEPTH {
        return Err("arguments exceed max nesting depth".into());
    }
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                if forbidden.iter().any(|f| f.eq_ignore_ascii_case(k)) {
                    return Err(format!("forbidden argument key: {k}"));
                }
                check_forbidden(v, forbidden, depth + 1)?;
            }
            Ok(())
        }
        Value::Array(items) => {
            for item in items {
                check_forbidden(item, forbidden, depth + 1)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

#[allow(clippy::collapsible_if)]
fn validate_schema(schema: &Value, instance: &Value, depth: usize) -> Result<(), String> {
    if depth > MAX_DEPTH {
        return Err("arguments exceed max nesting depth".into());
    }
    let Some(schema_obj) = schema.as_object() else {
        // Empty / non-object schema: accept any JSON value.
        return Ok(());
    };
    if schema_obj.is_empty() {
        return Ok(());
    }

    let ty = schema_obj.get("type").and_then(Value::as_str);
    match ty {
        Some("object") => {
            let Value::Object(map) = instance else {
                return Err("expected object arguments".into());
            };
            if let Some(required) = schema_obj.get("required").and_then(Value::as_array) {
                for req in required {
                    let Some(key) = req.as_str() else { continue };
                    if !map.contains_key(key) {
                        return Err(format!("missing required argument: {key}"));
                    }
                }
            }
            let additional = schema_obj
                .get("additionalProperties")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            let props = schema_obj.get("properties").and_then(Value::as_object);
            for (k, v) in map {
                match props.and_then(|p| p.get(k)) {
                    Some(prop_schema) => validate_schema(prop_schema, v, depth + 1)?,
                    None if !additional => {
                        return Err(format!("unexpected argument: {k}"));
                    }
                    None => {}
                }
            }
            Ok(())
        }
        Some("string") => {
            let Some(s) = instance.as_str() else {
                return Err("expected string".into());
            };
            if let Some(max) = schema_obj.get("maxLength").and_then(Value::as_u64) {
                if s.chars().count() as u64 > max {
                    return Err("string exceeds maxLength".into());
                }
            }
            if let Some(min) = schema_obj.get("minLength").and_then(Value::as_u64) {
                if (s.chars().count() as u64) < min {
                    return Err("string below minLength".into());
                }
            }
            if let Some(enums) = schema_obj.get("enum").and_then(Value::as_array) {
                if !enums.iter().any(|e| e.as_str() == Some(s)) {
                    return Err("string not in enum".into());
                }
            }
            Ok(())
        }
        Some("number") | Some("integer") => {
            let n = match instance {
                Value::Number(n) => n,
                _ => return Err(format!("expected {ty:?}")),
            };
            if ty == Some("integer") && n.as_i64().is_none() && n.as_u64().is_none() {
                return Err("expected integer".into());
            }
            let as_f = n.as_f64().unwrap_or(0.0);
            if let Some(min) = schema_obj.get("minimum").and_then(Value::as_f64) {
                if as_f < min {
                    return Err("number below minimum".into());
                }
            }
            if let Some(max) = schema_obj.get("maximum").and_then(Value::as_f64) {
                if as_f > max {
                    return Err("number above maximum".into());
                }
            }
            if let Some(enums) = schema_obj.get("enum").and_then(Value::as_array) {
                if !enums.iter().any(|e| e.as_f64() == Some(as_f)) {
                    return Err("number not in enum".into());
                }
            }
            Ok(())
        }
        Some("boolean") => {
            if !instance.is_boolean() {
                return Err("expected boolean".into());
            }
            Ok(())
        }
        Some("array") => {
            let Value::Array(items) = instance else {
                return Err("expected array".into());
            };
            if let Some(max) = schema_obj.get("maxItems").and_then(Value::as_u64) {
                if items.len() as u64 > max {
                    return Err("array exceeds maxItems".into());
                }
            }
            if let Some(item_schema) = schema_obj.get("items") {
                for item in items {
                    validate_schema(item_schema, item, depth + 1)?;
                }
            }
            Ok(())
        }
        Some(other) => Err(format!("unsupported schema type: {other}")),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rejects_missing_required() {
        let c = ToolConstraint {
            input_schema: json!({
                "type": "object",
                "required": ["path"],
                "properties": { "path": { "type": "string" } },
                "additionalProperties": false
            }),
            forbidden_keys: vec![],
            hitl: false,
            require_plan: false,
            status: None,
            schema_fingerprint: None,
        };
        assert!(validate_tool_args(&c, Some(&json!({}))).is_err());
        assert!(validate_tool_args(&c, Some(&json!({"path": "/tmp/x"}))).is_ok());
    }

    #[test]
    fn rejects_forbidden_nested_key() {
        let c = ToolConstraint {
            input_schema: json!({"type": "object"}),
            forbidden_keys: vec!["force".into()],
            hitl: false,
            require_plan: false,
            status: None,
            schema_fingerprint: None,
        };
        assert!(validate_tool_args(&c, Some(&json!({"meta": {"Force": true}}))).is_err());
    }

    #[test]
    fn parse_wrapper_and_plain() {
        let map = parse_constraints_json(
            r#"{"a":{"type":"object"},"b":{"input_schema":{"type":"string"},"forbidden_keys":["x"]}}"#,
        );
        assert!(map.contains_key("a"));
        assert_eq!(map["b"].forbidden_keys, vec!["x"]);
    }

    #[test]
    fn merge_constraints_tightens_hitl_only() {
        let mut cur = parse_constraints_json(r#"{"echo":{"hitl":false,"input_schema":{}}}"#);
        let incoming = parse_constraints_json(r#"{"echo":{"hitl":true,"input_schema":{}}}"#);
        merge_constraints_tighten(&mut cur, incoming);
        assert!(cur["echo"].hitl, "HITL must enable mid-session");

        let clear_attempt = parse_constraints_json(r#"{"echo":{"hitl":false,"input_schema":{}}}"#);
        merge_constraints_tighten(&mut cur, clear_attempt);
        assert!(
            cur["echo"].hitl,
            "HITL must not clear mid-session (tighten-only)"
        );
    }
}
