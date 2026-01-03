/// VAUBAN Web - Data models.
///
/// All models use Diesel for compile-time verified queries.

pub mod user;
pub mod asset;
pub mod session;

pub use user::*;
pub use asset::*;
pub use session::*;

