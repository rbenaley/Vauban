//! Industrial protocol peek classification for IACS tunnel gates.
//!
//! This module identifies the **wire protocol family** from the first
//! bytes of a TCP stream. It does NOT filter individual commands
//! (Modbus function codes, IEC 104 type IDs, etc.) -- only whether
//! the payload belongs to the expected industrial protocol profile.

mod classify;
mod conform;
mod expected;

pub use classify::{WireProtocol, classify_peek};
pub use conform::{ConformityDecision, evaluate_conformity};
pub use expected::ExpectedProfile;
