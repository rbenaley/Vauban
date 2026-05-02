//! Bastion Watch dashboard services.
//!
//! This module owns the read-only data layer behind the dashboard:
//!
//! * [`widgets`] -- pure-Rust SVG geometry helpers (sparkline, gauge,
//!   donut, heatmap, bar). They produce strings ready for inline SVG
//!   interpolation in the Askama tile partials.
//! * [`snapshot`] -- the role-aware `DashboardSnapshot::load` loader
//!   that aggregates every metric the dashboard renders for a single
//!   request (added in step 5 of the bastion-watch plan).

pub mod snapshot;
pub mod widgets;

pub use snapshot::{
    AccessPosture, DashboardScope, DashboardSnapshot, EvidenceChain, HeroBand, LiveSession,
    UserLens,
};
