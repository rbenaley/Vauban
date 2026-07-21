//! VAU-012 - Session-creation rate limits and concurrency quotas.
//!
//! Every session-creation handler (`connect_ssh`, `connect_rdp`,
//! `connect_iacs`) MUST call [`enforce_session_creation`] AFTER authorization
//! (Casbin + access-rule + JIT + preflight) and BEFORE allocating any backend
//! resource (the `proxy_sessions` INSERT, session token, TCP brokering, IPC).
//! This guarantees a denied request never leaves a half-created row or leaks
//! resources, and that anti-enumeration is preserved (the controls run after
//! the access decision, so a user without access cannot tell "quota full"
//! apart from "no access").
//!
//! Four controls run in this fixed order (see INV-12-1):
//!   1. global session-creation rate limit (service-wide defense),
//!   2. per-user session-creation rate limit,
//!   3. per-user concurrent live-session quota,
//!   4. per-asset concurrent live-session quota.
//!
//! Each threshold is disabled when set to `0` (INV-12-3).

use std::net::IpAddr;

use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use diesel::prelude::*;
use diesel_async::{AsyncPgConnection, RunQueryDsl};

use crate::AppState;
use crate::error::{AppError, AppResult};
use crate::models::session::SessionStatus;

/// Session statuses that count as "live" (holding resources). Kept in lock-step
/// with [`SessionStatus::is_live`]; the drift test `live_statuses_match_is_live`
/// pins the alignment.
pub const LIVE_STATUSES: [&str; 5] = SessionStatus::LIVE_AS_STR;

/// A session-creation control denied the request.
///
/// `message` is safe to surface to the end user (no internal detail). Handlers
/// map this to a 429 (non-HTMX) or an error toast (HTMX).
#[derive(Debug, Clone)]
pub struct LimitDenied {
    pub message: String,
}

impl LimitDenied {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// Build the response for a denied session-creation request (INV-12-2).
///
/// HTMX requests (the asset list `Connect` buttons post via `hx-post`, so a
/// 4xx body would be invisible) receive a 200 with an error-toast `HX-Trigger`;
/// every other client receives a real `429 Too Many Requests` with the message.
pub fn connect_limit_response(headers: &HeaderMap, message: &str) -> Response {
    let is_htmx = headers.get("HX-Request").is_some();
    if is_htmx {
        let escaped = message.replace('\\', r"\\").replace('"', r#"\""#);
        let trigger = format!(
            r#"{{"showToast": {{"message": "{}", "type": "error"}}}}"#,
            escaped
        );
        return (
            StatusCode::OK,
            [
                ("HX-Trigger", trigger),
                ("Content-Type", "text/html".to_string()),
            ],
            "",
        )
            .into_response();
    }
    (StatusCode::TOO_MANY_REQUESTS, message.to_string()).into_response()
}

/// Count the caller's currently-live sessions across all assets.
pub async fn count_live_for_user(conn: &mut AsyncPgConnection, user_id: i32) -> AppResult<i64> {
    use crate::schema::proxy_sessions as ps;
    ps::table
        .filter(ps::user_id.eq(user_id))
        .filter(ps::status.eq_any(LIVE_STATUSES))
        .count()
        .get_result(conn)
        .await
        .map_err(AppError::Database)
}

/// Count currently-live sessions targeting a given asset, across all users.
pub async fn count_live_for_asset(conn: &mut AsyncPgConnection, asset_id: i32) -> AppResult<i64> {
    use crate::schema::proxy_sessions as ps;
    ps::table
        .filter(ps::asset_id.eq(asset_id))
        .filter(ps::status.eq_any(LIVE_STATUSES))
        .count()
        .get_result(conn)
        .await
        .map_err(AppError::Database)
}

/// Run the four VAU-012 controls in order. Returns `Ok(())` when the request
/// may proceed, `Err(LimitDenied)` when any control trips.
///
/// A threshold of `0` disables the corresponding control.
pub async fn enforce_session_creation(
    state: &AppState,
    conn: &mut AsyncPgConnection,
    user_id: i32,
    asset_id: i32,
    ip: IpAddr,
) -> AppResult<Result<(), LimitDenied>> {
    let sec = &state.config.security;

    // 1. Global session-creation rate limit (service-wide defense).
    if sec.session_create_rate_global_per_minute > 0 {
        let res = state
            .rate_limiter
            .check("session:global", sec.session_create_rate_global_per_minute)
            .await?;
        if !res.allowed {
            tracing::warn!(
                limit = sec.session_create_rate_global_per_minute,
                "VAU-012: global session-creation rate limit exceeded"
            );
            return Ok(Err(LimitDenied::new(
                "The bastion is handling too many new sessions right now. \
                 Please retry in a moment.",
            )));
        }
    }

    // 2. Per-user session-creation rate limit.
    if sec.session_create_rate_per_minute > 0 {
        let key = format!("session:user:{}", user_id);
        let res = state
            .rate_limiter
            .check(&key, sec.session_create_rate_per_minute)
            .await?;
        if !res.allowed {
            tracing::warn!(
                user_id,
                %ip,
                limit = sec.session_create_rate_per_minute,
                "VAU-012: per-user session-creation rate limit exceeded"
            );
            return Ok(Err(LimitDenied::new(
                "You are opening sessions too quickly. Please wait a moment \
                 before trying again.",
            )));
        }
    }

    // 3. Per-user concurrent live-session quota.
    if sec.max_concurrent_sessions_per_user > 0 {
        let live = count_live_for_user(conn, user_id).await?;
        if live >= sec.max_concurrent_sessions_per_user {
            tracing::warn!(
                user_id,
                live,
                cap = sec.max_concurrent_sessions_per_user,
                "VAU-012: per-user concurrent session quota exceeded"
            );
            return Ok(Err(LimitDenied::new(
                "You have reached the maximum number of concurrent sessions. \
                 Disconnect an existing session to open a new one.",
            )));
        }
    }

    // 4. Per-asset concurrent live-session quota.
    if sec.max_concurrent_sessions_per_asset > 0 {
        let live = count_live_for_asset(conn, asset_id).await?;
        if live >= sec.max_concurrent_sessions_per_asset {
            tracing::warn!(
                asset_id,
                live,
                cap = sec.max_concurrent_sessions_per_asset,
                "VAU-012: per-asset concurrent session quota exceeded"
            );
            return Ok(Err(LimitDenied::new(
                "This asset has reached its maximum number of concurrent \
                 sessions. Please try again later.",
            )));
        }
    }

    Ok(Ok(()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::session::SessionStatus;

    #[test]
    fn live_statuses_match_is_live() {
        // LIVE_STATUSES must be exactly the set of SessionStatus variants for
        // which is_live() is true.
        for status in SessionStatus::ALL {
            let s = status.as_str();
            let in_const = LIVE_STATUSES.contains(&s);
            assert_eq!(
                status.is_live(),
                in_const,
                "LIVE_STATUSES disagrees with SessionStatus::is_live for '{}'",
                s
            );
        }
    }

    #[test]
    fn live_statuses_has_five_entries() {
        assert_eq!(LIVE_STATUSES.len(), 5);
    }

    #[test]
    fn connect_limit_response_non_htmx_is_429() {
        // INV-12-2: a non-HTMX client gets a real 429 Too Many Requests.
        let headers = HeaderMap::new();
        let resp = connect_limit_response(&headers, "slow down");
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(
            resp.headers().get("HX-Trigger").is_none(),
            "non-HTMX denial must not carry an HX-Trigger"
        );
    }

    #[test]
    fn connect_limit_response_htmx_is_toast_200() {
        // INV-12-2: an HTMX client gets a 200 with an error-toast HX-Trigger
        // (a 4xx body would be invisible to hx-post).
        let mut headers = HeaderMap::new();
        headers.insert("HX-Request", "true".parse().unwrap());
        let resp = connect_limit_response(&headers, "slow down");
        assert_eq!(resp.status(), StatusCode::OK);
        let trigger = resp
            .headers()
            .get("HX-Trigger")
            .expect("HTMX denial must carry an HX-Trigger toast");
        let trigger = trigger.to_str().unwrap();
        assert!(trigger.contains("showToast"));
        assert!(trigger.contains("\"type\": \"error\""));
    }

    #[test]
    fn connect_limit_response_escapes_quotes() {
        // The message is embedded in JSON; quotes/backslashes must be escaped
        // so the HX-Trigger stays valid JSON.
        let mut headers = HeaderMap::new();
        headers.insert("HX-Request", "true".parse().unwrap());
        let resp = connect_limit_response(&headers, r#"a "quoted" \ message"#);
        let trigger = resp
            .headers()
            .get("HX-Trigger")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(trigger.contains(r#"\""#), "double quotes must be escaped");
        assert!(serde_json::from_str::<serde_json::Value>(&trigger).is_ok());
    }
}
