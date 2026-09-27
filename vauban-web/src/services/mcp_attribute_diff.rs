//! TRUSTED R2.1 — human-readable before→after diffs for MCP attributes.
//!
//! Enriches existing WORM events (`AccessRuleUpdated`, `AssetUpdated`)
//! with a `changes` object; does not invent a parallel history table.

use serde_json::{Value, json};

/// Normalize optional tool lists for stable JSON comparison.
pub fn normalize_tools(tools: Option<&[String]>) -> Vec<String> {
    let mut v: Vec<String> = tools.map(|t| t.to_vec()).unwrap_or_default();
    v.sort();
    v.dedup();
    v
}

/// Build a `changes` object for MCP rule tool attributes (only keys that differ).
pub fn mcp_rule_tool_changes(
    before_allowed: Option<&[String]>,
    after_allowed: Option<&[String]>,
    before_hitl: Option<&[String]>,
    after_hitl: Option<&[String]>,
    before_plan: Option<&[String]>,
    after_plan: Option<&[String]>,
) -> Value {
    let mut changes = serde_json::Map::new();
    let ba = normalize_tools(before_allowed);
    let aa = normalize_tools(after_allowed);
    if ba != aa {
        changes.insert(
            "mcp_allowed_tools".into(),
            json!({ "before": ba, "after": aa }),
        );
    }
    let bh = normalize_tools(before_hitl);
    let ah = normalize_tools(after_hitl);
    if bh != ah {
        changes.insert(
            "mcp_hitl_tools".into(),
            json!({ "before": bh, "after": ah }),
        );
    }
    let bp = normalize_tools(before_plan);
    let ap = normalize_tools(after_plan);
    if bp != ap {
        changes.insert(
            "mcp_require_plan_tools".into(),
            json!({ "before": bp, "after": ap }),
        );
    }
    Value::Object(changes)
}

/// Full AccessRuleUpdated details JSON (rule id, name, optional changes).
pub fn access_rule_updated_details(rule_uuid: &str, name: &str, changes: &Value) -> String {
    let mut obj = serde_json::Map::new();
    obj.insert("rule".into(), json!(rule_uuid));
    obj.insert("name".into(), json!(name));
    if let Value::Object(map) = changes
        && !map.is_empty()
    {
        obj.insert("changes".into(), changes.clone());
    }
    Value::Object(obj).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_diff_only_emits_changed_keys() {
        let changes = mcp_rule_tool_changes(
            Some(&["echo".into(), "delete_row".into()]),
            Some(&["echo".into()]),
            Some(&["echo".into()]),
            Some(&["echo".into()]),
            None,
            None,
        );
        let obj = changes.as_object().unwrap();
        assert!(obj.contains_key("mcp_allowed_tools"));
        assert!(!obj.contains_key("mcp_hitl_tools"));
        let allowed = &obj["mcp_allowed_tools"];
        assert_eq!(allowed["before"], json!(["delete_row", "echo"]));
        assert_eq!(allowed["after"], json!(["echo"]));
    }

    #[test]
    fn details_omit_empty_changes() {
        let changes = mcp_rule_tool_changes(None, None, None, None, None, None);
        let s = access_rule_updated_details("r1", "Rule", &changes);
        assert!(!s.contains("changes"));
        assert!(s.contains("r1"));
    }
}
