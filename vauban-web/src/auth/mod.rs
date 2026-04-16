//! VAUBAN Web - Authorization primitives shared between handlers and templates.
//!
//! This module centralizes the canonical RBAC types so that:
//!
//! - There is exactly **one** definition of `check_rbac` (the legacy duplicate
//!   in `handlers::web` is now a thin re-export).
//! - There is exactly **one** definition of the per-request `PermissionContext`
//!   that holds the pre-computed booleans templates and handlers consume.
//!
//! Templates MUST gate UI elements through `PermissionContext` (and not via
//! `is_staff` / `is_superuser`, which are display-only attributes of the
//! current user). See the doc-comment on
//! [`crate::templates::base::UserContext`] for details.

pub mod permissions;

pub use permissions::{PermissionContext, check_rbac};
