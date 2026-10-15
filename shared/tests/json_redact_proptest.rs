//! MCP recording / audit redaction laws (spec 07, invariant 13).
#![allow(clippy::expect_used, clippy::unwrap_used)]

use proptest::prelude::*;
use serde_json::{Map, Value, json};
use shared::json_redact::redact_sensitive_json;

const SENSITIVE_KEYS: [&str; 10] = [
    "password",
    "userPassword",
    "client_secret",
    "api_key",
    "apiKey",
    "Authorization",
    "access_token",
    "db_credential",
    "x_auth",
    "private_key",
];

fn leaf() -> impl Strategy<Value = Value> {
    prop_oneof![
        any::<i64>().prop_map(Value::from),
        any::<bool>().prop_map(Value::from),
        "[a-z ]{0,12}".prop_map(Value::from),
        Just(Value::Null),
    ]
}

fn neutral_json() -> impl Strategy<Value = Value> {
    leaf().prop_recursive(4, 32, 4, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..4).prop_map(Value::Array),
            prop::collection::btree_map("[a-m]{1,6}", inner, 0..4)
                .prop_map(|m| Value::Object(m.into_iter().collect::<Map<_, _>>())),
        ]
    })
}

fn credential() -> impl Strategy<Value = String> {
    prop_oneof![
        "sk-[A-Za-z0-9_-]{20,40}",
        "ghp_[A-Za-z0-9]{20,40}",
        "gho_[A-Za-z0-9]{20,40}",
        "xox[abp]-[A-Za-z0-9-]{10,30}",
        "AKIA[A-Z0-9]{16}",
    ]
}

/// Nest `v` under `path` object keys.
fn nest(path: &[String], v: Value) -> Value {
    path.iter()
        .rev()
        .fold(v, |acc, k| json!({ k.as_str(): acc }))
}

proptest! {
    #[test]
    fn sensitive_keys_are_masked_at_any_depth(
        path in prop::collection::vec("[a-m]{1,6}", 0..5),
        key in prop::sample::select(SENSITIVE_KEYS.to_vec()),
        secret in neutral_json(),
    ) {
        let mut full = path.clone();
        full.push(key.to_string());
        let out = redact_sensitive_json(&nest(&full, secret));
        let pointer: String = full.iter().map(|k| format!("/{k}")).collect();
        prop_assert_eq!(out.pointer(&pointer), Some(&json!("***")));
    }

    #[test]
    fn credentials_in_free_text_never_survive(
        before in "[a-z ]{0,10}",
        cred in credential(),
        after in "[ .,;:]{1,3}[a-z ]{0,10}",
        key in "[a-m]{1,6}",
    ) {
        let text = format!("{before} {cred}{after}");
        let out = redact_sensitive_json(&json!({ key.as_str(): text }));
        let s = out[key.as_str()].as_str().unwrap();
        prop_assert!(!s.contains(&cred), "{cred} leaked in {s}");
        prop_assert!(s.contains("***"));
    }

    #[test]
    fn whole_string_jwts_are_masked(h in "[A-Za-z0-9_-]{8,20}", p in "[A-Za-z0-9_-]{4,20}", sig in "[A-Za-z0-9_-]{4,20}") {
        let jwt = format!("eyJ{h}.{p}.{sig}");
        prop_assert_eq!(redact_sensitive_json(&json!([jwt])), json!(["***"]));
    }

    #[test]
    fn redaction_is_idempotent_and_keeps_shape(v in neutral_json(), cred in credential()) {
        let input = json!({ "data": v, "note": format!("x {cred} y"), "token": "t" });
        let once = redact_sensitive_json(&input);
        prop_assert_eq!(&redact_sensitive_json(&once), &once);
        prop_assert_eq!(&once["data"], &input["data"]);
        let keys = |x: &Value| x.as_object().unwrap().keys().cloned().collect::<Vec<_>>();
        prop_assert_eq!(keys(&once), keys(&input));
    }
}
