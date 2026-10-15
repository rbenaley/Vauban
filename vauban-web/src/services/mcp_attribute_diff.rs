//! TRUSTED R2.1 — human-readable before→after diffs for MCP attributes.
//!
//! Enriches existing WORM events (`AccessRuleUpdated`, `AssetUpdated`)
//! with a `changes` object; does not invent a parallel history table.

use serde_json::{Value, json};

/// Normalize optional tool lists for stable JSON comparison. `None` (NULL)
/// stays distinct from `Some([])` so the WORM diff shows the stored value.
pub fn normalize_tools(tools: Option<&[String]>) -> Option<Vec<String>> {
    tools.map(|t| {
        let mut v = t.to_vec();
        v.sort();
        v.dedup();
        v
    })
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
    for (key, before, after) in [
        ("mcp_allowed_tools", before_allowed, after_allowed),
        ("mcp_hitl_tools", before_hitl, after_hitl),
        ("mcp_require_plan_tools", before_plan, after_plan),
    ] {
        let (b, a) = (normalize_tools(before), normalize_tools(after));
        if b != a {
            changes.insert(key.into(), json!({ "before": b, "after": a }));
        }
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
    fn unrestricted_and_deny_all_are_different_changes() {
        let empty: [String; 0] = [];
        let changes = mcp_rule_tool_changes(None, Some(&empty), None, None, None, None);
        assert_eq!(
            changes["mcp_allowed_tools"],
            json!({ "before": null, "after": [] })
        );
        let back = mcp_rule_tool_changes(Some(&empty), None, None, None, None, None);
        assert_eq!(
            back["mcp_allowed_tools"],
            json!({ "before": [], "after": null })
        );
    }

    #[test]
    fn details_omit_empty_changes() {
        let changes = mcp_rule_tool_changes(None, None, None, None, None, None);
        let s = access_rule_updated_details("r1", "Rule", &changes);
        assert!(!s.contains("changes"));
        assert!(s.contains("r1"));
    }

    fn column() -> impl proptest::strategy::Strategy<Value = Option<Vec<String>>> {
        use proptest::prelude::*;
        prop::option::of(prop::collection::vec("[a-c]", 0..4))
    }

    proptest::proptest! {
        /// A change is logged exactly when the stored meaning changes:
        /// order and duplicates never count, NULL vs empty always does.
        #[test]
        fn diff_tracks_meaning_not_spelling(
            ba in column(), aa in column(), bh in column(), ah in column(), bp in column(), ap in column(),
        ) {
            let changes = mcp_rule_tool_changes(
                ba.as_deref(), aa.as_deref(), bh.as_deref(), ah.as_deref(), bp.as_deref(), ap.as_deref(),
            );
            for (key, b, a) in [("mcp_allowed_tools", &ba, &aa), ("mcp_hitl_tools", &bh, &ah), ("mcp_require_plan_tools", &bp, &ap)] {
                let (nb, na) = (normalize_tools(b.as_deref()), normalize_tools(a.as_deref()));
                proptest::prop_assert_eq!(changes.get(key).is_some(), nb != na, "{}", key);
                if nb != na {
                    proptest::prop_assert_eq!(&changes[key], &json!({ "before": nb, "after": na }));
                }
            }
            let mut shuffled = aa.clone();
            if let Some(v) = shuffled.as_mut() {
                v.reverse();
                v.extend(v.clone());
            }
            let same = mcp_rule_tool_changes(aa.as_deref(), shuffled.as_deref(), None, None, None, None);
            proptest::prop_assert!(same.as_object().unwrap().is_empty());
        }
    }
}
