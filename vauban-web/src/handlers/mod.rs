//! VAUBAN Web - Request handlers module.
//!
//! Organized into:
//! - `api/`: JSON API handlers for M2M communication (can be disabled)
//!   Contains: accounts, assets, groups, sessions
//! - `web`: HTML page handlers with Askama templates (human users)
//! - `auth`: Authentication handlers (shared between web and API)
//! - `websocket`: WebSocket handlers for real-time updates

pub mod api;
pub mod auth;
pub mod web;
pub mod websocket;

// Re-export web and websocket handlers for convenient access
pub use auth::*;
pub use web::*;
pub use websocket::*;
