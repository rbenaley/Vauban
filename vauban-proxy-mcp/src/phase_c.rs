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

//! Phase C helpers: suspend/resume, HITL pending, clientInfo pin (09).

use serde_json::Value;
use std::collections::HashMap;

pub const HITL_TTL_DEFAULT_SECS: f64 = 900.0;
pub const HITL_MAX_PENDING_PER_SESSION: usize = 5;

/// HITL pending window. Env `HITL_PENDING_TTL_SECONDS` (supervisor
/// `[mcp].hitl_pending_ttl_seconds`); fallback [`HITL_TTL_DEFAULT_SECS`].
pub fn hitl_pending_ttl_secs() -> f64 {
    hitl_pending_ttl_secs_from(std::env::var("HITL_PENDING_TTL_SECONDS").ok().as_deref())
}

pub fn hitl_pending_ttl_secs_from(raw: Option<&str>) -> f64 {
    raw.and_then(|v| v.parse::<f64>().ok())
        .filter(|d| *d > 0.0)
        .map(|d| d.clamp(30.0, 28_800.0))
        .unwrap_or(HITL_TTL_DEFAULT_SECS)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HitlStatus {
    Pending,
    Approved,
    Denied,
}

#[derive(Debug, Clone)]
pub struct HitlPending {
    pub pending_id: String,
    pub tool: String,
    pub args_blake3: String,
    pub expires_at: f64,
    pub status: HitlStatus,
    /// Mission Seal: sealed Contract JSON (empty = classic one-shot HITL).
    pub plan_contract_json: String,
    /// Mission Seal: structured Story JSON for human display (empty = none).
    pub plan_story_json: String,
    pub mandate_id: String,
    pub sealed_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientInfo {
    pub name: String,
    pub version: String,
}

impl ClientInfo {
    pub fn from_params(params: &Value) -> Option<Self> {
        let info = params.get("clientInfo")?;
        let name = info.get("name").and_then(Value::as_str)?.trim().to_string();
        let version = info
            .get("version")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();
        if name.is_empty() {
            return None;
        }
        Some(Self { name, version })
    }

    pub fn label(&self) -> String {
        format!("{}/{}", self.name, self.version)
    }
}

/// HITL / Mission Seal args digest — **raw** Value (domain-separated).
/// Must NOT hash after redact (secret bait-and-switch). See Mission Seal §5.3.
pub fn args_blake3(args: Option<&Value>) -> String {
    crate::mandate::digest_args_raw(args)
}

pub fn extract_pending_id(params: &Value) -> Option<String> {
    // MCP `_meta.vauban.pending_id` or nested `vauban.pending_id`.
    params
        .pointer("/_meta/vauban/pending_id")
        .or_else(|| params.pointer("/vauban/pending_id"))
        .or_else(|| params.pointer("/meta/vauban/pending_id"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

pub fn validate_on_exceed(v: &str) -> Result<(), String> {
    match v {
        "throttle" | "alert" | "suspend" => Ok(()),
        other => Err(format!("invalid envelope_on_exceed: {other}")),
    }
}

/// Fail-closed HITL decide gate (expiry + SoD). `None` = apply.
pub fn hitl_decision_blocked(
    now: f64,
    expires_at: f64,
    status: &HitlStatus,
    requester_user_id: Option<&str>,
    requester_api_key_id: Option<&str>,
    actor_user_id: &str,
) -> Option<&'static str> {
    if actor_user_id.is_empty() {
        return Some("missing_actor");
    }
    if *status != HitlStatus::Pending {
        return Some("not_pending");
    }
    if expires_at < now {
        return Some("expired");
    }
    if requester_user_id.is_some_and(|r| !r.is_empty() && r == actor_user_id) {
        return Some("sod_requester");
    }
    if requester_api_key_id.is_some_and(|k| !k.is_empty() && k == actor_user_id) {
        return Some("sod_opening_key");
    }
    None
}

pub fn purge_expired_hitl(
    pendings: &mut HashMap<String, HitlPending>,
    now: f64,
) -> Vec<HitlPending> {
    let expired: Vec<HitlPending> = pendings
        .iter()
        .filter(|(_, p)| p.expires_at < now && p.status == HitlStatus::Pending)
        .map(|(_, p)| p.clone())
        .collect();
    for p in &expired {
        pendings.remove(&p.pending_id);
    }
    expired
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn args_hash_stable() {
        let a = args_blake3(Some(&json!({"x": 1})));
        let b = args_blake3(Some(&json!({"x": 1})));
        assert_eq!(a, b);
        assert_ne!(a, args_blake3(Some(&json!({"x": 2}))));
    }

    #[test]
    fn args_hash_raw_catches_secret_switch() {
        let a = args_blake3(Some(&json!({"password": "alpha", "ok": true})));
        let b = args_blake3(Some(&json!({"password": "beta", "ok": true})));
        assert_ne!(
            a, b,
            "raw digest must differ when only a secret-shaped field changes"
        );
    }

    #[test]
    fn pending_id_paths() {
        let p = json!({"_meta": {"vauban": {"pending_id": "abc"}}});
        assert_eq!(extract_pending_id(&p).as_deref(), Some("abc"));
    }

    #[test]
    fn hitl_pending_ttl_from_env_and_defaults() {
        assert_eq!(hitl_pending_ttl_secs_from(None), HITL_TTL_DEFAULT_SECS);
        assert_eq!(hitl_pending_ttl_secs_from(Some("120")), 120.0);
        assert_eq!(hitl_pending_ttl_secs_from(Some("10")), 30.0);
        assert_eq!(hitl_pending_ttl_secs_from(Some("999999")), 28_800.0);
        assert_eq!(
            hitl_pending_ttl_secs_from(Some("nope")),
            HITL_TTL_DEFAULT_SECS
        );
    }

    #[test]
    fn on_exceed_accepts_suspend() {
        assert!(validate_on_exceed("suspend").is_ok());
        assert!(validate_on_exceed("nope").is_err());
    }

    #[test]
    fn hitl_decision_blocked_expiry_and_sod() {
        assert_eq!(
            hitl_decision_blocked(100.0, 99.0, &HitlStatus::Pending, Some("u1"), None, "admin"),
            Some("expired")
        );
        assert_eq!(
            hitl_decision_blocked(10.0, 99.0, &HitlStatus::Pending, Some("u1"), None, "u1"),
            Some("sod_requester")
        );
        assert_eq!(
            hitl_decision_blocked(
                10.0,
                99.0,
                &HitlStatus::Pending,
                Some("u1"),
                Some("vbn-key"),
                "vbn-key"
            ),
            Some("sod_opening_key")
        );
        assert_eq!(
            hitl_decision_blocked(10.0, 99.0, &HitlStatus::Approved, Some("u1"), None, "admin"),
            Some("not_pending")
        );
        assert_eq!(
            hitl_decision_blocked(10.0, 99.0, &HitlStatus::Pending, Some("u1"), None, ""),
            Some("missing_actor")
        );
        assert_eq!(
            hitl_decision_blocked(10.0, 99.0, &HitlStatus::Pending, Some("u1"), None, "admin"),
            None
        );
    }
}
