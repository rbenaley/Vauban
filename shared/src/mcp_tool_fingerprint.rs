//! MCP tool and upstream-instructions fingerprints (CIS MCP 4.1.1 / 1.3).
//!
//! vauban-web computes them at discovery and freezes the approved value in
//! the asset catalogue; vauban-proxy-mcp recomputes them on every live
//! `tools/list` / `initialize`. Both sides MUST call this module so the
//! bytes hashed are identical. Changing the algorithm invalidates every
//! approved catalogue on deployed appliances.

use serde_json::Value;

/// Prefix reserved for Vauban keys inside `tool_constraints_json` and the
/// catalogue. Upstream tool names with this prefix are refused.
pub const RESERVED_PREFIX: &str = "__vauban";

/// Reserved `tool_constraints_json` key carrying the approved upstream
/// instructions fingerprint, and the `tool` value of an instructions drift.
pub const INSTRUCTIONS_KEY: &str = "__vauban_upstream_instructions";

/// Text shown to the agent (`-32002` `data.message`) and to the session
/// owner (web sidebar) when an approved tool is quarantined after an
/// upstream definition change.
pub const QUARANTINED_TOOL_MESSAGE: &str = "This tool is temporarily unavailable: its definition changed on the upstream server since it was approved. An administrator must review and re-approve it.";

/// BLAKE3 hex over `name \0 description \0 serde_json(inputSchema)`.
///
/// `serde_json` is built without `preserve_order` in every Vauban crate, so
/// object keys serialize sorted and the schema bytes are canonical.
pub fn schema_fingerprint(name: &str, description: &str, input_schema: Option<&Value>) -> String {
    let schema_bytes = input_schema
        .map(|v| serde_json::to_vec(v).unwrap_or_default())
        .unwrap_or_default();
    let mut hasher = blake3::Hasher::new();
    hasher.update(name.as_bytes());
    hasher.update(&[0]);
    hasher.update(description.as_bytes());
    hasher.update(&[0]);
    hasher.update(&schema_bytes);
    hasher.finalize().to_hex().to_string()
}

/// BLAKE3 hex of upstream `initialize.result.instructions`, domain-separated
/// from tool fingerprints.
pub fn instructions_fingerprint(text: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(INSTRUCTIONS_KEY.as_bytes());
    hasher.update(&[0]);
    hasher.update(text.as_bytes());
    hasher.finalize().to_hex().to_string()
}

/// The fields of one upstream `tools/list` entry that the fingerprint covers.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub input_schema: Option<Value>,
}

impl ToolDefinition {
    /// Extract from a raw `tools/list` entry: trimmed non-empty `name`,
    /// `description` (default empty), non-null `inputSchema`.
    pub fn from_tool(tool: &Value) -> Option<Self> {
        let name = tool
            .get("name")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())?;
        Some(Self {
            name: name.to_string(),
            description: tool
                .get("description")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            input_schema: tool.get("inputSchema").cloned().filter(|v| !v.is_null()),
        })
    }

    pub fn fingerprint(&self) -> String {
        schema_fingerprint(&self.name, &self.description, self.input_schema.as_ref())
    }
}

/// Non-empty `instructions` string of an `initialize` result.
pub fn upstream_instructions(initialize_result: &Value) -> Option<&str> {
    initialize_result
        .get("instructions")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn schema_fingerprint_is_stable_and_field_sensitive() {
        let a = schema_fingerprint("echo", "E", Some(&json!({"type": "object"})));
        assert_eq!(
            a,
            schema_fingerprint("echo", "E", Some(&json!({"type": "object"})))
        );
        assert_ne!(
            a,
            schema_fingerprint("echo", "E2", Some(&json!({"type": "object"})))
        );
        assert_ne!(a, schema_fingerprint("echo", "E", None));
        assert_ne!(
            a,
            schema_fingerprint("echo2", "E", Some(&json!({"type": "object"})))
        );
    }

    #[test]
    fn schema_fingerprint_is_frozen() {
        // Approved catalogues on deployed appliances hold this value.
        assert_eq!(
            schema_fingerprint("echo", "E", Some(&json!({"type": "object"}))),
            {
                let mut h = blake3::Hasher::new();
                h.update(b"echo\0E\0{\"type\":\"object\"}");
                h.finalize().to_hex().to_string()
            }
        );
    }

    #[test]
    fn schema_key_order_does_not_matter() {
        let a: Value =
            serde_json::from_str(r#"{"type":"object","properties":{"b":{},"a":{}}}"#).unwrap();
        let b: Value =
            serde_json::from_str(r#"{"properties":{"a":{},"b":{}},"type":"object"}"#).unwrap();
        assert_eq!(
            schema_fingerprint("t", "", Some(&a)),
            schema_fingerprint("t", "", Some(&b))
        );
    }

    #[test]
    fn definition_from_tool_entry() {
        let d = ToolDefinition::from_tool(&json!({
            "name": "  echo ", "description": "E", "inputSchema": {"type": "object"}
        }))
        .unwrap();
        assert_eq!(d.name, "echo");
        assert_eq!(
            d.fingerprint(),
            schema_fingerprint("echo", "E", Some(&json!({"type": "object"})))
        );
        let bare = ToolDefinition::from_tool(&json!({"name": "x", "inputSchema": null})).unwrap();
        assert_eq!(bare.description, "");
        assert!(bare.input_schema.is_none());
        assert!(ToolDefinition::from_tool(&json!({"name": "  "})).is_none());
        assert!(ToolDefinition::from_tool(&json!({"description": "no name"})).is_none());
    }

    #[test]
    fn instructions_fingerprint_is_domain_separated() {
        let fp = instructions_fingerprint("Use tools carefully.");
        assert_eq!(fp, instructions_fingerprint("Use tools carefully."));
        assert_ne!(fp, instructions_fingerprint("Use tools carefully!"));
        assert_ne!(fp, schema_fingerprint("Use tools carefully.", "", None));
    }

    #[test]
    fn upstream_instructions_reads_non_empty_string() {
        assert_eq!(
            upstream_instructions(&json!({"instructions": "hi"})),
            Some("hi")
        );
        assert_eq!(upstream_instructions(&json!({"instructions": ""})), None);
        assert_eq!(upstream_instructions(&json!({"instructions": 3})), None);
        assert_eq!(upstream_instructions(&json!({})), None);
    }
}
