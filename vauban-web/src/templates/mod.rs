/// VAUBAN Web - Askama templates module.
///
/// This module contains all template structs and shared types for Askama templates.

pub mod base;
pub mod partials;
pub mod dashboard;
pub mod accounts;
pub mod assets;
pub mod sessions;

// Re-export commonly used templates
pub use base::BaseTemplate;

