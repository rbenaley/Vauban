pub mod accounts;
pub mod assets;
/// VAUBAN Web - Askama templates module.
///
/// This module contains all template structs and shared types for Askama templates.
pub mod base;
pub mod dashboard;
pub mod partials;
pub mod sessions;

// Re-export commonly used templates
pub use base::BaseTemplate;
