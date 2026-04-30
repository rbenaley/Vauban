//! Issue #27 — pin the `assets:write` -> `assets:manage` rename in the
//! shipped Casbin policy file.
//!
//! The handler-side rename is enforced by
//! `web::manage_assets_invariants_test::no_legacy_assets_write_in_production_code`.
//! This test pins the *policy* side: no `(assets, write)` grant may
//! survive in `config/access/default_policy.csv`, otherwise a fresh
//! installation would still seed the deprecated permission and a
//! customised CSV could quietly drift. Conversely the test asserts
//! that `(assets, manage)` is granted to at least one non-superuser
//! role so the admin sub-tree is reachable without relying on the
//! `*` wildcard.

/// The shipped policy MUST NOT contain a `p, ..., assets, write` line.
///
/// Allowed survival: a comment line that mentions the historical name
/// for documentation purposes (we strip lines starting with `#` before
/// scanning so this is not a problem in practice).
#[test]
fn default_policy_csv_does_not_grant_assets_write() {
    let csv = include_str!("../../../config/access/default_policy.csv");

    let legacy_resource = "assets";
    let legacy_action = "write";

    for (line_no, raw) in csv.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split(',').map(str::trim).collect();
        if fields.len() < 4 || fields[0] != "p" {
            continue;
        }
        let (subject, obj, act) = (fields[1], fields[2], fields[3]);

        let is_legacy_grant = obj == legacy_resource && act == legacy_action;
        assert!(
            !is_legacy_grant,
            "config/access/default_policy.csv line {}: `{subject}` is granted \
             the legacy `({legacy_resource}, {legacy_action})` permission. \
             It was renamed to `(assets, manage)` in issue #27; a fresh \
             install seeded with this CSV would silently fail to authorise \
             handlers under `/assets/manage/*`. Update the line to use \
             `manage` instead.",
            line_no + 1
        );
    }
}

/// At least one non-superuser role MUST be granted `(assets, manage)`.
///
/// Without this grant, the `/assets/manage/*` admin sub-tree is only
/// reachable for users that satisfy the `p, role:superuser, *, *`
/// wildcard. Staff (without the superuser flag) would lose admin CRUD
/// access on assets, breaking the published RBAC contract.
#[test]
fn default_policy_csv_grants_assets_manage_to_a_named_role() {
    let csv = include_str!("../../../config/access/default_policy.csv");

    let mut named_grants = Vec::new();
    for raw in csv.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split(',').map(str::trim).collect();
        if fields.len() < 4 || fields[0] != "p" {
            continue;
        }
        let (subject, obj, act) = (fields[1], fields[2], fields[3]);
        if obj == "assets" && act == "manage" && subject != "*" {
            named_grants.push(subject.to_string());
        }
    }

    assert!(
        !named_grants.is_empty(),
        "config/access/default_policy.csv MUST grant `(assets, manage)` \
         to at least one named role (e.g. `role:staff`). The `/assets/manage/*` \
         admin sub-tree would otherwise only be reachable for users that \
         match the `p, role:superuser, *, *` wildcard, which removes the \
         intentional split between staff and superuser introduced by \
         the fine-grained migration."
    );

    assert!(
        named_grants.iter().any(|s| s == "role:staff"),
        "config/access/default_policy.csv MUST grant `(assets, manage)` to \
         `role:staff` (current named grants: {named_grants:?}). The \
         documented RBAC contract pinned by `permissions_test.rs::\
         check_rbac_staff_granted_assets_manage` depends on it."
    );
}
