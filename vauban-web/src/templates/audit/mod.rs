//! Admin-only audit pages.
//!
//! Surfaces the append-only `approval_audit_log` rows (separation-of-
//! duties record) with pagination and basic filters. Fully read-only;
//! every mutation path is guarded by the database trigger
//! `block_approval_audit_log_mutation`.

pub mod approval_audit_list;

pub use approval_audit_list::{ApprovalAuditListTemplate, ApprovalAuditRow};
