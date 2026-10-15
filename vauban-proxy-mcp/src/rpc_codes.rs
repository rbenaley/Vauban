//! JSON-RPC error codes returned to MCP agents (MCP Arch §9).
//!
//! Agents and supervising tools key on these numbers: they are wire, like
//! the IPC discriminants. Never renumber; `mcp_wire_tests` pins the values
//! and `check_mcp_error_codes_single_source.sh` refuses a raw literal
//! anywhere else in the proxy. Mission Seal codes live with their engine in
//! `shared::mcp_mandate` (`ERR_MANDATE_STEP_DENIED`, `ERR_MISSION_EXPIRED`).

/// Tool outside the visit allow-list.
pub const TOOL_NOT_ALLOWED: i32 = -32001;
/// Tool pending first approval, tombstoned, or quarantined after drift.
pub const TOOL_PENDING_OR_DRIFT: i32 = -32002;
/// Unknown or expired `vbw_` bearer.
pub const SESSION_UNKNOWN: i32 = -32003;
/// Session terminated (IAM, expiry, admin).
pub const SESSION_TERMINATED: i32 = -32004;
/// Upstream, recording sync, in-flight step, or PDP unavailable.
pub const UPSTREAM_OR_RECORDING: i32 = -32010;
/// Envelope rate limit.
pub const RATE_LIMITED: i32 = -32029;
/// HITL or Mission Seal approval pending.
pub const APPROVAL_REQUIRED: i32 = -32030;
/// Session suspended (envelope or ops).
pub const SESSION_SUSPENDED: i32 = -32031;
/// HITL denied, expired, or pending exhausted.
pub const HITL_DENIED: i32 = -32032;
/// JSON-RPC invalid request (protocol version, clientInfo).
pub const INVALID_REQUEST: i32 = -32600;
/// JSON-RPC method not found (outside the four supported methods).
pub const METHOD_NOT_FOUND: i32 = -32601;
/// JSON-RPC invalid params (constraints, Story / Contract shape).
pub const INVALID_PARAMS: i32 = -32602;
