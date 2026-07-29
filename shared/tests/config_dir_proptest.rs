//! Property tests for [`shared::config_dir::resolve_config_dir`].
//!
//! Pins the release contract from issue #38: a leftover workspace `config/`
//! must never win over a missing/present system path when the profile is
//! Release.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use proptest::prelude::*;
use shared::config_dir::{ConfigDirError, ConfigDirProfile, SYSTEM_CONFIG_DIR, resolve_config_dir};
use std::path::Path;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// Release never returns the workspace path, even when it "exists".
    #[test]
    fn release_never_selects_workspace(
        system_exists in any::<bool>(),
        workspace_exists in any::<bool>(),
    ) {
        let system = Path::new(SYSTEM_CONFIG_DIR);
        let workspace = Path::new("/home/builder/Vauban/config");
        let result = resolve_config_dir(
            None,
            (system, system_exists),
            Some((workspace, workspace_exists)),
            ConfigDirProfile::Release,
        );
        match result {
            Ok(path) => {
                prop_assert!(system_exists);
                prop_assert_eq!(&path, system);
                prop_assert_ne!(&path, workspace);
            }
            Err(ConfigDirError::NotFound { profile }) => {
                prop_assert!(!system_exists);
                prop_assert_eq!(profile, ConfigDirProfile::Release);
            }
            Err(other) => {
                return Err(TestCaseError::fail(format!("unexpected error: {other:?}")));
            }
        }
    }

    /// When env is set and exists, it always wins for both profiles.
    #[test]
    fn env_always_wins_when_present(
        profile in prop_oneof![
            Just(ConfigDirProfile::Release),
            Just(ConfigDirProfile::Debug),
        ],
        system_exists in any::<bool>(),
        workspace_exists in any::<bool>(),
    ) {
        let env = Path::new("/override/config");
        let system = Path::new(SYSTEM_CONFIG_DIR);
        let workspace = Path::new("/workspace/config");
        let got = resolve_config_dir(
            Some((env, true)),
            (system, system_exists),
            Some((workspace, workspace_exists)),
            profile,
        )
        .expect("env exists");
        prop_assert_eq!(got, env);
    }

    /// Debug falls back to workspace only when system is absent.
    #[test]
    fn debug_workspace_only_after_system_miss(
        workspace_exists in any::<bool>(),
    ) {
        let system = Path::new(SYSTEM_CONFIG_DIR);
        let workspace = Path::new("/workspace/config");
        let result = resolve_config_dir(
            None,
            (system, false),
            Some((workspace, workspace_exists)),
            ConfigDirProfile::Debug,
        );
        if workspace_exists {
            let path = result.expect("workspace");
            prop_assert_eq!(&path, workspace);
        } else {
            match result {
                Err(ConfigDirError::NotFound { profile }) => {
                    prop_assert_eq!(profile, ConfigDirProfile::Debug);
                }
                other => {
                    return Err(TestCaseError::fail(format!("unexpected result: {other:?}")));
                }
            }
        }
    }
}
