/// VAUBAN Web - IPC clients module.
///
/// Note: This module was previously named "grpc" but now uses Unix pipes IPC.
/// The name is kept for backward compatibility with existing imports.
pub mod clients;

pub use clients::*;
