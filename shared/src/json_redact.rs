//! Recursive JSON redaction for MCP audit / recording (spec 07).
//!
//! Keys whose name *is* or *ends with* (case-insensitive) one of the
//! sensitive suffixes are replaced with `"***"` at any object depth,
//! including array elements. Free-form JWT-looking strings (`eyJ…`)
//! are best-effort redacted.
//!
//! String values are also scanned for a fixed list of credential
//! shapes, whatever key holds them (invariant 13: not configurable):
//! `sk-…`, `ghp_…`, `gho_…`, `xoxa-`/`xoxb-`/`xoxp-…`, `AKIA` + 16,
//! PEM private-key blocks and `Bearer …`. Only the matched span is
//! replaced with `***`; the rest of the text is kept.

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
            out.insert(k.clone(), Value::String(REDACTED.to_string()));
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

const REDACTED: &str = "***";

fn redact_string(s: &str) -> String {
    // Best-effort JWT / compact JWS detection (spec 07 §4).
    if s.starts_with("eyJ") && s.matches('.').count() >= 2 && s.len() > 20 {
        return REDACTED.to_string();
    }
    let b = s.as_bytes();
    let mut out = String::new();
    let (mut i, mut copied) = (0, 0);
    while i < b.len() {
        // ASCII bytes are always char boundaries, so `&s[i..]` is safe.
        let starts_word = b[i].is_ascii() && (i == 0 || !is_word_byte(b[i - 1]));
        if starts_word && let Some((len, keep)) = secret_at(&s[i..]) {
            out.push_str(&s[copied..i + keep]);
            out.push_str(REDACTED);
            i += len;
            copied = i;
        } else {
            i += 1;
        }
    }
    if copied == 0 {
        return s.to_string();
    }
    out.push_str(&s[copied..]);
    out
}

fn is_word_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

fn run_len(t: &[u8], ok: ByteClass) -> usize {
    t.iter().take_while(|&&c| ok(c)).count()
}

type ByteClass = fn(u8) -> bool;

/// Prefix, minimum body length, body charset.
const PREFIXED: &[(&str, usize, ByteClass)] = &[
    ("sk-", 20, |c| {
        c.is_ascii_alphanumeric() || c == b'-' || c == b'_'
    }),
    ("ghp_", 20, |c| c.is_ascii_alphanumeric()),
    ("gho_", 20, |c| c.is_ascii_alphanumeric()),
    ("xoxa-", 10, |c| c.is_ascii_alphanumeric() || c == b'-'),
    ("xoxb-", 10, |c| c.is_ascii_alphanumeric() || c == b'-'),
    ("xoxp-", 10, |c| c.is_ascii_alphanumeric() || c == b'-'),
];

/// `(matched length, bytes to keep in clear)` for a secret starting at `t`.
fn secret_at(t: &str) -> Option<(usize, usize)> {
    let b = t.as_bytes();
    for (prefix, min, ok) in PREFIXED {
        if t.starts_with(prefix) {
            let n = run_len(&b[prefix.len()..], *ok);
            if n >= *min {
                return Some((prefix.len() + n, 0));
            }
        }
    }
    if t.starts_with("AKIA")
        && run_len(&b[4..], |c| c.is_ascii_uppercase() || c.is_ascii_digit()) == 16
    {
        return Some((20, 0));
    }
    if b.len() > 7 && b[..7].eq_ignore_ascii_case(b"bearer ") {
        let n = run_len(&b[7..], |c| {
            c.is_ascii_alphanumeric() || b"-._~+/=".contains(&c)
        });
        if n >= 8 {
            return Some((7 + n, 7));
        }
    }
    let label = t.strip_prefix("-----BEGIN ")?;
    let label = &label[..label.find("-----")?];
    if !label.ends_with("PRIVATE KEY") {
        return None;
    }
    let end = format!("-----END {label}-----");
    Some((t.find(&end).map_or(t.len(), |e| e + end.len()), 0))
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

    /// One case per fixed pattern, under a neutral key.
    #[test]
    fn redacts_credential_shapes_in_values() {
        let cases = [
            ("sk-proj-abcdefghijklmnopqrstuv", "***"),
            ("ghp_ABCDEFGHIJKLMNOPQRSTuvwx1234", "***"),
            ("gho_ABCDEFGHIJKLMNOPQRSTuvwx1234", "***"),
            ("xoxa-1234567890-abc", "***"),
            ("xoxb-1234567890-abcdef", "***"),
            ("xoxp-1234567890-abcdef", "***"),
            ("AKIAIOSFODNN7EXAMPLE", "***"),
            ("Bearer abc.def-ghi_jkl", "Bearer ***"),
            (
                "authorization: bearer abcdefgh1234=",
                "authorization: bearer ***",
            ),
            (
                "key:\n-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----\nend",
                "key:\n***\nend",
            ),
            ("-----BEGIN OPENSSH PRIVATE KEY-----\ntruncated", "***"),
            (
                "note: ghp_ABCDEFGHIJKLMNOPQRSTuvwx1234 then é sk-abcdefghijklmnopqrstuvwxyz.",
                "note: *** then é ***.",
            ),
        ];
        for (input, want) in cases {
            let out = redact_sensitive_json(&json!({ "note": input }));
            assert_eq!(out["note"], want, "{input}");
        }
    }

    #[test]
    fn leaves_lookalikes_in_clear() {
        for keep in [
            "task-abcdefghijklmnopqrstuvwxyz",
            "sk-short",
            "ghp_short",
            "xoxb-short",
            "xoxz-1234567890-abcdef",
            "AKIAIOSFODNN7EXAMPLE1",
            "AKIA-not-a-key",
            "Bearer",
            "Bearer short",
            "bearer",
            "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
            "-----BEGIN no terminator",
            "skeleton ghost xoxo AKIA",
            "café 日本語",
        ] {
            let out = redact_sensitive_json(&json!({ "note": keep }));
            assert_eq!(out["note"], keep);
        }
    }
}
