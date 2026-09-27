//! Recursive JSON redaction for MCP audit / recording (spec 07).
//!
//! Keys whose name *is* or *ends with* (case-insensitive) one of the
//! sensitive suffixes are replaced with `"***"` at any object depth,
//! including array elements. Free-form JWT-looking strings (`eyJ…`)
//! are best-effort redacted.

use serde_json::{Map, Value};

const SENSITIVE_SUFFIXES: &[&str] = &[
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "bearer",
    "set-cookie",
    "cookie",
    "private_key",
    "client_secret",
    "credential",
    "access_token",
    "refresh_token",
];

/// Short keys that must match exactly (or `_auth` / `-auth`) so
/// `author` is not treated as sensitive.
const SENSITIVE_EXACT: &[&str] = &["auth"];

/// Return a deep-cloned Value with sensitive fields redacted.
#[must_use]
pub fn redact_sensitive_json(value: &Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(redact_object(map)),
        Value::Array(arr) => Value::Array(arr.iter().map(redact_sensitive_json).collect()),
        Value::String(s) => Value::String(redact_string(s)),
        other => other.clone(),
    }
}

fn redact_object(map: &Map<String, Value>) -> Map<String, Value> {
    let mut out = Map::new();
    for (k, v) in map {
        if key_is_sensitive(k) {
            out.insert(k.clone(), Value::String("***".to_string()));
        } else {
            out.insert(k.clone(), redact_sensitive_json(v));
        }
    }
    out
}

fn key_is_sensitive(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    if SENSITIVE_EXACT.contains(&lower.as_str())
        || lower.ends_with("_auth")
        || lower.ends_with("-auth")
    {
        return true;
    }
    SENSITIVE_SUFFIXES
        .iter()
        .any(|suf| lower == *suf || lower.ends_with(suf))
}

fn redact_string(s: &str) -> String {
    // Best-effort JWT / compact JWS detection (spec 07 §4).
    if s.starts_with("eyJ") && s.matches('.').count() >= 2 && s.len() > 20 {
        return "***".to_string();
    }
    s.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn redacts_nested_token_and_password() {
        let input = json!({
            "message": "hello",
            "creds": { "token": "abc", "nested": { "api_key": "k" } },
            "items": [ { "password": "p", "ok": 1 } ]
        });
        let out = redact_sensitive_json(&input);
        assert_eq!(out["message"], "hello");
        assert_eq!(out["creds"]["token"], "***");
        assert_eq!(out["creds"]["nested"]["api_key"], "***");
        assert_eq!(out["items"][0]["password"], "***");
        assert_eq!(out["items"][0]["ok"], 1);
    }

    #[test]
    fn redacts_suffix_match_case_insensitive() {
        let input = json!({ "userPassword": "x", "my_SECRET": "y", "Authorization": "Bearer z" });
        let out = redact_sensitive_json(&input);
        assert_eq!(out["userPassword"], "***");
        assert_eq!(out["my_SECRET"], "***");
        assert_eq!(out["Authorization"], "***");
    }

    #[test]
    fn redacts_widened_secret_suffixes() {
        let input = json!({
            "credential": "c",
            "db_credential": "c2",
            "access_token": "at",
            "refresh_token": "rt",
            "apiKey": "k",
            "cookie": "sid",
            "auth": "hdr",
            "x_auth": "x",
            "author": "keep",
        });
        let out = redact_sensitive_json(&input);
        assert_eq!(out["credential"], "***");
        assert_eq!(out["db_credential"], "***");
        assert_eq!(out["access_token"], "***");
        assert_eq!(out["refresh_token"], "***");
        assert_eq!(out["apiKey"], "***");
        assert_eq!(out["cookie"], "***");
        assert_eq!(out["auth"], "***");
        assert_eq!(out["x_auth"], "***");
        assert_eq!(out["author"], "keep");
    }

    #[test]
    fn redacts_jwt_looking_string() {
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature";
        let out = redact_sensitive_json(&Value::String(jwt.into()));
        assert_eq!(out, "***");
    }
}
