/// VAUBAN Web - Data models.
///
/// All models use Diesel for compile-time verified queries.
pub mod api_key;
pub mod asset;
pub mod auth_session;
pub mod session;
pub mod user;

pub use api_key::*;
pub use asset::*;
pub use auth_session::*;
pub use session::*;
pub use user::*;
