pub mod accounts;
/// VAUBAN Web - Request handlers module.
///
/// Organized into:
/// - `web`: HTML page handlers with Askama templates (human users)
/// - `api`: JSON API handlers for M2M communication (can be disabled)
/// - `auth`: Authentication handlers (shared between web and API)
/// - `websocket`: WebSocket handlers for real-time updates
pub mod api;
pub mod assets;
pub mod auth;
pub mod sessions;
pub mod web;
pub mod websocket;

pub use accounts::*;
pub use assets::*;
pub use auth::*;
pub use sessions::*;
pub use web::*;
pub use websocket::*;
