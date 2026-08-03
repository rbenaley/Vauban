//! Shared Proptest config for library `#[cfg(test)]` modules.
//!
//! Default proptest persistence writes a sibling `proptest-regressions/` next to
//! `src/`. Point seeds at `target/proptest-regressions/` instead (already
//! gitignored via `/target`).

use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;

/// Persist failure seeds under `target/proptest-regressions/` (crate-root sibling
/// of `src/` + `target/…`).
pub fn cases(n: u32) -> ProptestConfig {
    ProptestConfig {
        failure_persistence: Some(Box::new(FileFailurePersistence::SourceParallel(
            "target/proptest-regressions",
        ))),
        ..ProptestConfig::with_cases(n)
    }
}

/// Same persistence path with proptest's default case count.
pub fn default_config() -> ProptestConfig {
    ProptestConfig {
        failure_persistence: Some(Box::new(FileFailurePersistence::SourceParallel(
            "target/proptest-regressions",
        ))),
        ..ProptestConfig::default()
    }
}
