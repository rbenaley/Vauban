//! LDAPS group aggregation (Phase 1): mapping AST and A/B/C replace-set.
//!
//! Web derives `aggregation_enabled` from [`LdapMappingRuntime`], never from
//! its own `[auth.ldaps]` TOML. Membership changes go only through the
//! existing access IPC (`add_group_member` / `remove_group_member`). Local
//! accounts are never touched. Search incompleteness never deactivates.

use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use serde::Serialize;
use shared::ldap_mapping::MappingFile;
use shared::messages::AuditEventType;
use tracing::info;

use crate::AppState;
use crate::error::AppResult;
use crate::ipc::AuditEvent;
use crate::models::user::{AuthSource, User};
use crate::services::emit_audit;

/// Max names per `added` / `removed` / `unmapped` list in the WORM payload.
pub const AUDIT_NAME_CAP: usize = 64;

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

/// WORM / journal payload for an aggregation replace-set or purge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AggregationAuditPayload {
    /// Count of catalogue groups in the desired set (not `unmapped`).
    pub desired: usize,
    /// Count of the user's groups before the write.
    pub previous: usize,
    /// Catalogue names added, sorted, capped at [`AUDIT_NAME_CAP`].
    pub added: Vec<String>,
    /// Catalogue names removed, sorted, capped.
    pub removed: Vec<String>,
    /// `apply` names with no existing User Group, sorted, capped.
    pub unmapped: Vec<String>,
    /// At least one list exceeded [`AUDIT_NAME_CAP`].
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
    /// Fail-closed streak when this payload is a purge.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub streak: Option<u32>,
}

/// Ids plus audit payload produced by [`build_aggregation_delta`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregationDelta {
    /// Catalogue ids that should remain after replace-set.
    pub desired_ids: BTreeSet<i32>,
    /// Catalogue ids the user currently holds.
    pub current_ids: BTreeSet<i32>,
    /// Operator-visible / WORM body.
    pub payload: AggregationAuditPayload,
}

/// Build the replace-set delta and audit lists. Pure: no I/O.
///
/// `applied` is the name set from [`shared::ldap_mapping::apply`]. Catalogue
/// and current rows are `(id, name)` as returned by access IPC.
#[must_use]
pub fn build_aggregation_delta(
    applied: &BTreeSet<String>,
    catalogue: &[(i32, String)],
    current: &[(i32, String)],
    streak: Option<u32>,
) -> AggregationDelta {
    let mut by_lower: HashMap<String, (i32, String)> = HashMap::new();
    for (id, name) in catalogue {
        by_lower
            .entry(name.to_ascii_lowercase())
            .or_insert_with(|| (*id, name.clone()));
    }

    let mut desired_ids = BTreeSet::new();
    let mut unmapped = BTreeSet::new();
    for name in applied {
        match by_lower.get(&name.to_ascii_lowercase()) {
            Some((id, _)) => {
                desired_ids.insert(*id);
            }
            None => {
                unmapped.insert(name.clone());
            }
        }
    }

    let current_ids: BTreeSet<i32> = current.iter().map(|(id, _)| *id).collect();
    let mut id_to_name: HashMap<i32, String> = HashMap::new();
    for (id, name) in catalogue.iter().chain(current.iter()) {
        id_to_name.entry(*id).or_insert_with(|| name.clone());
    }

    let added_ids: BTreeSet<i32> = desired_ids.difference(&current_ids).copied().collect();
    let removed_ids: BTreeSet<i32> = current_ids.difference(&desired_ids).copied().collect();

    let added_all: BTreeSet<String> = added_ids
        .iter()
        .filter_map(|id| id_to_name.get(id).cloned())
        .collect();
    let removed_all: BTreeSet<String> = removed_ids
        .iter()
        .filter_map(|id| id_to_name.get(id).cloned())
        .collect();

    let (added, added_cut) = cap_names(added_all);
    let (removed, removed_cut) = cap_names(removed_all);
    let (unmapped, unmapped_cut) = cap_names(unmapped);
    let desired = desired_ids.len();
    let previous = current_ids.len();

    AggregationDelta {
        desired_ids,
        current_ids,
        payload: AggregationAuditPayload {
            desired,
            previous,
            added,
            removed,
            unmapped,
            truncated: added_cut || removed_cut || unmapped_cut,
            streak,
        },
    }
}

fn cap_names(names: BTreeSet<String>) -> (Vec<String>, bool) {
    let truncated = names.len() > AUDIT_NAME_CAP;
    (names.into_iter().take(AUDIT_NAME_CAP).collect(), truncated)
}

fn emit_aggregation_audit(
    state: &AppState,
    username: &str,
    event_type: AuditEventType,
    payload: &AggregationAuditPayload,
) {
    let details = serde_json::to_string(payload).unwrap_or_else(|_| "{}".to_string());
    match event_type {
        AuditEventType::LdapAggregationReplaced => {
            info!(
                username,
                desired = payload.desired,
                previous = payload.previous,
                added = ?payload.added,
                removed = ?payload.removed,
                unmapped = ?payload.unmapped,
                "ldap_aggregation_replaced"
            );
        }
        AuditEventType::LdapAggregationEmptied => {
            info!(
                username,
                desired = payload.desired,
                previous = payload.previous,
                added = ?payload.added,
                removed = ?payload.removed,
                unmapped = ?payload.unmapped,
                "ldap_aggregation_emptied"
            );
        }
        AuditEventType::LdapAggregationPurgedFailsafe => {
            info!(
                username,
                desired = payload.desired,
                previous = payload.previous,
                added = ?payload.added,
                removed = ?payload.removed,
                unmapped = ?payload.unmapped,
                streak = payload.streak,
                "ldap_aggregation_purged_failsafe"
            );
        }
        _ => {}
    }
    emit_audit(state, AuditEvent::new(event_type, details).user(username));
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
            let current = state.access_client.list_user_groups(user.id).await?;
            let current_pairs: Vec<(i32, String)> =
                current.iter().map(|g| (g.id, g.name.clone())).collect();
            let delta =
                build_aggregation_delta(&BTreeSet::new(), &[], &current_pairs, Some(new_streak));
            for group in &current {
                state
                    .access_client
                    .remove_group_member(group.id, user.id)
                    .await?;
            }
            if runtime.latch_purge_alert() {
                emit_aggregation_audit(
                    state,
                    &user.username,
                    AuditEventType::LdapAggregationPurgedFailsafe,
                    &delta.payload,
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
    let applied = shared::ldap_mapping::apply(keys, ast);
    let catalogue = state.access_client.list_vauban_groups().await?;
    let current = state.access_client.list_user_groups(user.id).await?;
    let catalogue_pairs: Vec<(i32, String)> =
        catalogue.iter().map(|g| (g.id, g.name.clone())).collect();
    let current_pairs: Vec<(i32, String)> =
        current.iter().map(|g| (g.id, g.name.clone())).collect();
    let delta = build_aggregation_delta(&applied, &catalogue_pairs, &current_pairs, None);

    for id in delta.desired_ids.difference(&delta.current_ids) {
        state.access_client.add_group_member(*id, user.id).await?;
    }
    for id in delta.current_ids.difference(&delta.desired_ids) {
        state
            .access_client
            .remove_group_member(*id, user.id)
            .await?;
    }

    if delta.desired_ids.is_empty() {
        emit_aggregation_audit(
            state,
            &user.username,
            AuditEventType::LdapAggregationEmptied,
            &delta.payload,
        );
        if !delta.current_ids.is_empty() {
            tracing::warn!(
                username = %user.username,
                previous = delta.payload.previous,
                "ldap_aggregation_emptied_from_nonempty"
            );
        }
    }
    emit_aggregation_audit(
        state,
        &user.username,
        AuditEventType::LdapAggregationReplaced,
        &delta.payload,
    );
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
    fn aggregation_audit_uses_serde_and_info_literals() {
        let src = include_str!("ldap_aggregation.rs");
        assert!(src.contains("serde_json::to_string"));
        assert!(src.contains("\"ldap_aggregation_replaced\""));
        assert!(src.contains("\"ldap_aggregation_emptied\""));
        assert!(src.contains("\"ldap_aggregation_purged_failsafe\""));
        assert!(src.contains("build_aggregation_delta"));
        assert!(
            !src.contains(concat!("{{\"desired\":", "{")),
            "audit details must not format! desired/previous counts"
        );
    }

    fn names(pairs: &[(i32, &str)]) -> Vec<(i32, String)> {
        pairs
            .iter()
            .map(|(id, n)| (*id, (*n).to_string()))
            .collect()
    }

    fn applied(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn delta_adds_mapped_group() {
        let d = build_aggregation_delta(
            &applied(&["Administrators"]),
            &names(&[(1, "Administrators")]),
            &[],
            None,
        );
        assert_eq!(d.desired_ids, BTreeSet::from([1]));
        assert_eq!(d.payload.added, vec!["Administrators".to_string()]);
        assert!(d.payload.removed.is_empty());
        assert!(d.payload.unmapped.is_empty());
        assert!(!d.payload.truncated);
    }

    #[test]
    fn delta_removes_extra_membership() {
        let d = build_aggregation_delta(
            &applied(&["ops"]),
            &names(&[(1, "ops"), (2, "old")]),
            &names(&[(1, "ops"), (2, "old")]),
            None,
        );
        assert_eq!(d.payload.added, Vec::<String>::new());
        assert_eq!(d.payload.removed, vec!["old".to_string()]);
        assert_eq!(d.payload.desired, 1);
        assert_eq!(d.payload.previous, 2);
    }

    #[test]
    fn delta_noop_identical_set() {
        let d = build_aggregation_delta(
            &applied(&["ops"]),
            &names(&[(1, "ops")]),
            &names(&[(1, "ops")]),
            None,
        );
        assert!(d.payload.added.is_empty());
        assert!(d.payload.removed.is_empty());
        assert_eq!(d.payload.desired, 1);
        assert_eq!(d.payload.previous, 1);
    }

    #[test]
    fn delta_empty_applied_is_empty_desired() {
        let d = build_aggregation_delta(&BTreeSet::new(), &names(&[(1, "ops")]), &[], None);
        assert!(d.desired_ids.is_empty());
        assert!(d.payload.added.is_empty());
        assert_eq!(d.payload.desired, 0);
    }

    #[test]
    fn delta_unmapped_name_is_not_desired() {
        let d = build_aggregation_delta(&applied(&["Administrators"]), &[], &[], None);
        assert!(d.desired_ids.is_empty());
        assert_eq!(d.payload.unmapped, vec!["Administrators".to_string()]);
        assert_eq!(d.payload.desired, 0);
    }

    #[test]
    fn delta_matches_catalogue_case_insensitively() {
        let d = build_aggregation_delta(
            &applied(&["administrators"]),
            &names(&[(1, "Administrators")]),
            &[],
            None,
        );
        assert_eq!(d.payload.added, vec!["Administrators".to_string()]);
    }

    #[test]
    fn delta_caps_lists_and_sets_truncated() {
        let applied_set: BTreeSet<String> = (0..AUDIT_NAME_CAP + 5)
            .map(|i| format!("g{i:03}"))
            .collect();
        let catalogue: Vec<(i32, String)> = (0..AUDIT_NAME_CAP + 5)
            .map(|i| (i as i32, format!("g{i:03}")))
            .collect();
        let d = build_aggregation_delta(&applied_set, &catalogue, &[], None);
        assert_eq!(d.payload.added.len(), AUDIT_NAME_CAP);
        assert!(d.payload.truncated);
        assert_eq!(d.payload.desired, AUDIT_NAME_CAP + 5);
    }

    #[test]
    fn delta_name_order_is_sorted() {
        let d = build_aggregation_delta(
            &applied(&["zeta", "alpha"]),
            &names(&[(2, "zeta"), (1, "alpha")]),
            &[],
            None,
        );
        assert_eq!(
            d.payload.added,
            vec!["alpha".to_string(), "zeta".to_string()]
        );
    }

    #[test]
    fn delta_purge_lists_removed_and_streak() {
        let d = build_aggregation_delta(
            &BTreeSet::new(),
            &[],
            &names(&[(1, "ops"), (2, "lab")]),
            Some(3),
        );
        assert_eq!(
            d.payload.removed,
            vec!["lab".to_string(), "ops".to_string()]
        );
        assert_eq!(d.payload.streak, Some(3));
        assert_eq!(d.payload.desired, 0);
        assert_eq!(d.payload.previous, 2);
    }

    #[test]
    fn payload_serializes_without_format_interpolation() {
        let d = build_aggregation_delta(&applied(&["ops"]), &names(&[(1, "ops")]), &[], None);
        let json = serde_json::to_string(&d.payload).expect("json");
        assert!(json.contains("\"added\":[\"ops\"]"));
        assert!(!json.contains("truncated"));
        assert!(!json.contains("streak"));
    }

    #[test]
    fn battle_delta_builder_is_deterministic() {
        let applied_set = applied(&["ops", "lab"]);
        let catalogue = names(&[(1, "ops"), (2, "lab")]);
        let current = names(&[(2, "lab")]);
        let n = 8;
        let barrier = std::sync::Arc::new(Barrier::new(n));
        let mut handles = Vec::new();
        for _ in 0..n {
            let applied_set = applied_set.clone();
            let catalogue = catalogue.clone();
            let current = current.clone();
            let barrier = std::sync::Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                build_aggregation_delta(&applied_set, &catalogue, &current, None)
            }));
        }
        let first = handles.pop().expect("one").join().expect("thread");
        for h in handles {
            assert_eq!(h.join().expect("thread"), first);
        }
        assert_eq!(first.payload.added, vec!["ops".to_string()]);
        assert!(first.payload.removed.is_empty());
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
