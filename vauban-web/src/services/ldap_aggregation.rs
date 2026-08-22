//! LDAPS group aggregation (Phase 1): mapping AST and A/B/C replace-set.
//!
//! Web derives `aggregation_enabled` from [`LdapMappingRuntime`], never from
//! its own `[auth.ldaps]` TOML. Membership changes go only through the
//! existing access IPC (`add_group_member` / `remove_group_member`). Local
//! accounts are never touched. Search incompleteness never deactivates.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use shared::ldap_mapping::MappingFile;
use shared::messages::AuditEventType;

use crate::AppState;
use crate::error::AppResult;
use crate::ipc::AuditEvent;
use crate::models::user::{AuthSource, User};
use crate::services::emit_audit;

/// Directory search result after a successful bind (aggregation on).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LdapSearchForSync {
    /// Case A: keys fully collected.
    Complete(Vec<String>),
    /// Case B: entry missing or unreadable. Hold; increment streak.
    IncompleteNotFound,
    /// Case C: range / overflow / timeout. Hold; increment streak.
    IncompleteUnreachable,
}

/// Pure A/B/C classification used by tests and the state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AggregationCase {
    /// Complete keys (case A).
    Complete,
    /// Incomplete not-found (case B).
    IncompleteNotFound,
    /// Incomplete unreachable (case C).
    IncompleteUnreachable,
}

/// What the login path must do after classifying the search.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AggregationAction {
    /// Apply mapping and replace `user_groups` (LDAP shadows only).
    ReplaceSet,
    /// Leave memberships unchanged.
    Hold,
    /// Purge LDAP group memberships; do not deactivate.
    PurgeFailsafe,
}

/// Decide the membership action from case + post-increment streak.
#[must_use]
pub fn decide_action(case: AggregationCase, new_streak: u32, threshold: u32) -> AggregationAction {
    match case {
        AggregationCase::Complete => AggregationAction::ReplaceSet,
        AggregationCase::IncompleteNotFound | AggregationCase::IncompleteUnreachable => {
            if threshold > 0 && new_streak >= threshold {
                AggregationAction::PurgeFailsafe
            } else {
                AggregationAction::Hold
            }
        }
    }
}

/// In-memory mapping compiled from `WebLdapMappingProvision`.
#[derive(Debug)]
pub struct LdapMappingRuntime {
    /// Authoritative flag from the supervisor provision (not web TOML).
    pub aggregation_enabled: bool,
    /// Parsed `static` / `match` (and resolve, unused here).
    pub ast: MappingFile,
    /// Consecutive incomplete resolutions before purge (`0` = never).
    pub fail_closed_threshold: u32,
    /// Per-source incomplete counter (Phase 1 has one directory).
    pub incomplete_streak: AtomicU32,
    /// Whether the fail-closed alert has already been latched.
    pub purge_alert_latched: AtomicBool,
}

impl LdapMappingRuntime {
    /// Compile provision bytes. Aggregation-off is an empty AST.
    pub fn from_provision(
        aggregation_enabled: bool,
        file_bytes: &[u8],
        fail_closed_threshold: u32,
    ) -> Result<Self, String> {
        let ast = if aggregation_enabled {
            let ast = shared::ldap_mapping::parse(file_bytes)
                .map_err(|e| format!("LDAP mapping provision refused parse: {e}"))?;
            if !ast.has_resolve() {
                return Err(
                    "LDAP mapping provision has no resolve line (aggregation on)".to_string(),
                );
            }
            ast
        } else {
            shared::ldap_mapping::parse(b"").map_err(|e| e.to_string())?
        };
        Ok(Self {
            aggregation_enabled,
            ast,
            fail_closed_threshold,
            incomplete_streak: AtomicU32::new(0),
            purge_alert_latched: AtomicBool::new(false),
        })
    }

    /// Reset the incomplete streak and unlatch the purge alert (case A heal).
    pub fn record_complete(&self) {
        self.incomplete_streak.store(0, Ordering::SeqCst);
        self.purge_alert_latched.store(false, Ordering::SeqCst);
    }

    /// Increment the incomplete streak; return the new value.
    pub fn record_incomplete(&self) -> u32 {
        self.incomplete_streak.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// Latch the fail-closed alert. Returns `true` on the first crossing.
    pub fn latch_purge_alert(&self) -> bool {
        !self.purge_alert_latched.swap(true, Ordering::SeqCst)
    }

    /// Test helper: clear counters between serial E2E cases on a singleton app.
    pub fn reset_counters(&self) {
        self.incomplete_streak.store(0, Ordering::SeqCst);
        self.purge_alert_latched.store(false, Ordering::SeqCst);
    }
}

/// Sync `user_groups` after a successful LDAP bind. Local accounts are a no-op.
pub async fn sync_after_login(
    state: &AppState,
    user: &User,
    search: LdapSearchForSync,
) -> AppResult<()> {
    if user.auth_source != AuthSource::Ldap {
        return Ok(());
    }
    let Some(runtime) = state.ldap_mapping.as_ref() else {
        return Ok(());
    };
    if !runtime.aggregation_enabled {
        return Ok(());
    }

    match search {
        LdapSearchForSync::Complete(keys) => {
            runtime.record_complete();
            replace_set(state, user, &runtime.ast, &keys).await
        }
        LdapSearchForSync::IncompleteNotFound => {
            apply_incomplete(state, user, runtime, AggregationCase::IncompleteNotFound).await
        }
        LdapSearchForSync::IncompleteUnreachable => {
            apply_incomplete(state, user, runtime, AggregationCase::IncompleteUnreachable).await
        }
    }
}

async fn apply_incomplete(
    state: &AppState,
    user: &User,
    runtime: &LdapMappingRuntime,
    case: AggregationCase,
) -> AppResult<()> {
    let new_streak = runtime.record_incomplete();
    match decide_action(case, new_streak, runtime.fail_closed_threshold) {
        AggregationAction::Hold | AggregationAction::ReplaceSet => Ok(()),
        AggregationAction::PurgeFailsafe => {
            purge_ldap_groups(state, user).await?;
            if runtime.latch_purge_alert() {
                emit_audit(
                    state,
                    AuditEvent::new(
                        AuditEventType::LdapAggregationPurgedFailsafe,
                        format!(r#"{{"streak":{new_streak}}}"#),
                    )
                    .user(&user.username),
                );
            }
            Ok(())
        }
    }
}

async fn replace_set(
    state: &AppState,
    user: &User,
    ast: &MappingFile,
    keys: &[String],
) -> AppResult<()> {
    let desired_names = shared::ldap_mapping::apply(keys, ast);
    let catalogue = state.access_client.list_vauban_groups().await?;
    let mut desired_ids = BTreeSet::new();
    for name in &desired_names {
        if let Some(group) = catalogue
            .iter()
            .find(|g| g.name.eq_ignore_ascii_case(name.as_str()))
        {
            desired_ids.insert(group.id);
        }
    }

    let current = state.access_client.list_user_groups(user.id).await?;
    let current_ids: BTreeSet<i32> = current.iter().map(|g| g.id).collect();

    for id in desired_ids.difference(&current_ids) {
        state.access_client.add_group_member(*id, user.id).await?;
    }
    for id in current_ids.difference(&desired_ids) {
        state
            .access_client
            .remove_group_member(*id, user.id)
            .await?;
    }

    if desired_ids.is_empty() {
        emit_audit(
            state,
            AuditEvent::new(AuditEventType::LdapAggregationEmptied, "{}").user(&user.username),
        );
        if !current_ids.is_empty() {
            tracing::warn!(
                username = %user.username,
                previous = current_ids.len(),
                "ldap_aggregation_emptied_from_nonempty"
            );
        }
    }
    emit_audit(
        state,
        AuditEvent::new(
            AuditEventType::LdapAggregationReplaced,
            format!(
                r#"{{"desired":{},"previous":{}}}"#,
                desired_ids.len(),
                current_ids.len()
            ),
        )
        .user(&user.username),
    );
    Ok(())
}

async fn purge_ldap_groups(state: &AppState, user: &User) -> AppResult<()> {
    let current = state.access_client.list_user_groups(user.id).await?;
    for group in current {
        state
            .access_client
            .remove_group_member(group.id, user.id)
            .await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;
    use std::thread;

    #[test]
    fn comments_only_refuses_when_aggregation_on() {
        let shipped = include_str!("../../../config/access/ldaps_mapping.conf");
        let err = LdapMappingRuntime::from_provision(true, shipped.as_bytes(), 3)
            .expect_err("comments-only");
        assert!(err.contains("resolve"), "{err}");
    }

    #[test]
    fn aggregation_off_accepts_empty_bytes() {
        let rt = LdapMappingRuntime::from_provision(false, b"", 3).expect("off");
        assert!(!rt.aggregation_enabled);
    }

    #[test]
    fn aggregation_on_accepts_resolve() {
        let rt = LdapMappingRuntime::from_provision(true, b"resolve user-attr memberOf\n", 3)
            .expect("ok");
        assert!(rt.aggregation_enabled);
        assert!(rt.ast.has_resolve());
    }

    #[test]
    fn web_boot_compiles_aggregation_from_provision_not_toml() {
        let main = include_str!("../main.rs");
        assert!(
            main.contains("data.aggregation_enabled"),
            "boot must compile aggregation from the provision payload"
        );
        assert!(
            !main.contains("config.auth.ldaps.aggregation_enabled"),
            "web TOML aggregation_enabled is not the authority"
        );
    }

    #[test]
    fn login_does_not_read_toml_aggregation_flag() {
        let auth = include_str!("../handlers/auth.rs");
        assert!(
            !auth.contains("config.auth.ldaps.aggregation_enabled"),
            "login must derive aggregation from ldap_mapping provision, not TOML"
        );
        assert!(
            auth.contains("ldap_bind_and_search") || auth.contains("ldap_authenticate"),
            "login must call the bind-and-search path when aggregation is on"
        );
    }

    #[test]
    fn aggregation_uses_access_ipc_not_diesel() {
        let src = include_str!("ldap_aggregation.rs");
        assert!(src.contains("add_group_member"));
        assert!(src.contains("remove_group_member"));
        assert!(!src.contains(concat!("user_groups", "::")));
        assert!(!src.contains(concat!("diesel", "::")));
        assert!(!src.contains(concat!("is_", "superuser")));
        assert!(!src.contains(concat!("is_", "staff")));
        assert!(!src.contains(concat!("is_", "active")));
    }

    #[test]
    fn decide_complete_is_replace_set() {
        assert_eq!(
            decide_action(AggregationCase::Complete, 99, 3),
            AggregationAction::ReplaceSet
        );
    }

    #[test]
    fn decide_incomplete_below_threshold_holds() {
        assert_eq!(
            decide_action(AggregationCase::IncompleteNotFound, 2, 3),
            AggregationAction::Hold
        );
        assert_eq!(
            decide_action(AggregationCase::IncompleteUnreachable, 1, 3),
            AggregationAction::Hold
        );
    }

    #[test]
    fn decide_incomplete_at_threshold_purges() {
        assert_eq!(
            decide_action(AggregationCase::IncompleteNotFound, 3, 3),
            AggregationAction::PurgeFailsafe
        );
        assert_eq!(
            decide_action(AggregationCase::IncompleteUnreachable, 3, 3),
            AggregationAction::PurgeFailsafe
        );
    }

    #[test]
    fn decide_threshold_zero_never_purges() {
        assert_eq!(
            decide_action(AggregationCase::IncompleteUnreachable, 100, 0),
            AggregationAction::Hold
        );
    }

    #[test]
    fn search_entry_not_found_does_not_deactivate_action() {
        // Case B is hold (or purge memberships) -- never a deactivate action.
        assert_ne!(
            decide_action(AggregationCase::IncompleteNotFound, 1, 3),
            AggregationAction::ReplaceSet
        );
    }

    #[test]
    fn case_a_resets_streak_and_unlatches() {
        let rt = LdapMappingRuntime::from_provision(true, b"resolve user-attr memberOf\n", 3)
            .expect("ok");
        rt.record_incomplete();
        rt.record_incomplete();
        assert_eq!(rt.incomplete_streak.load(Ordering::SeqCst), 2);
        rt.latch_purge_alert();
        rt.record_complete();
        assert_eq!(rt.incomplete_streak.load(Ordering::SeqCst), 0);
        assert!(!rt.purge_alert_latched.load(Ordering::SeqCst));
    }

    #[test]
    fn battle_incomplete_counter_is_deterministic() {
        let rt = std::sync::Arc::new(
            LdapMappingRuntime::from_provision(true, b"resolve user-attr memberOf\n", 0)
                .expect("ok"),
        );
        let n = 8;
        let barrier = std::sync::Arc::new(Barrier::new(n));
        let mut handles = Vec::new();
        for _ in 0..n {
            let rt = std::sync::Arc::clone(&rt);
            let barrier = std::sync::Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                rt.record_incomplete();
            }));
        }
        for h in handles {
            h.join().expect("thread");
        }
        assert_eq!(rt.incomplete_streak.load(Ordering::SeqCst), n as u32);
    }
}
