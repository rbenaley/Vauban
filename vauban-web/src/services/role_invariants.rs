/// VAUBAN Web - Role invariants (non-Casbin, count-based).
///
/// Casbin authorises *who* can perform a role mutation; this module
/// enforces the *minimum/maximum* constraints those mutations must
/// always preserve, regardless of the caller's permissions:
///
/// 1. **No self-demotion** -- an operator cannot remove their own
///    `is_superuser` / `is_staff` flag, deactivate themselves, or delete
///    their own account through the admin UI. Lock-out prevention.
/// 2. **At least one active superuser** -- the system must always have
///    one usable superuser. Demoting, deactivating, or soft-deleting the
///    last one is refused.
///
/// These invariants are enforced server-side **and** must run inside a
/// SERIALIZABLE transaction (see [`run_serializable`]) for the count-
/// based ones, so two concurrent demotions of two different superusers
/// cannot both succeed and leave the system with zero superusers (TOCTOU
/// window). The pure self-check ([`check_self_change`]) can run before
/// the transaction since `operator_uuid == target_uuid` does not depend
/// on database state.
use diesel::prelude::*;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use uuid::Uuid;

/// Snapshot of the role-bearing flags of a single user row.
///
/// `before` is read inside the transaction; `after` is the desired
/// state after the mutation (form-derived for web, payload-derived for
/// API). Soft-delete (`is_deleted`) lives on the snapshot so the same
/// type can express demote / deactivate / delete uniformly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoleSnapshot {
    pub is_superuser: bool,
    pub is_staff: bool,
    pub is_active: bool,
    pub is_deleted: bool,
}

/// What the caller is trying to do to the target's superuser eligibility.
///
/// Drives [`check_last_active_superuser`]: only mutations that would
/// reduce the active-superuser count must be guarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeIntent {
    /// `is_superuser` flips from `true` to `false` (with target staying
    /// active). May or may not also flip `is_staff`.
    Demote,
    /// `is_active` flips from `true` to `false` on a superuser row.
    Deactivate,
    /// `is_deleted` flips from `false` to `true` on an active superuser.
    Delete,
}

/// Why a role mutation was refused.
///
/// Each variant maps to a stable, user-facing flash message via
/// [`Self::flash_message`]; tests assert on those constants so the
/// wording cannot drift silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleViolation {
    /// Operator tried to clear their own `is_superuser`.
    SelfDemoteSuperuser,
    /// Operator tried to clear their own `is_staff`.
    SelfDemoteStaff,
    /// Operator tried to clear their own `is_active`.
    SelfDeactivate,
    /// Operator tried to delete their own account.
    SelfDelete,
    /// Demoting `target` would leave zero active superusers.
    LastActiveSuperuserDemote,
    /// Deactivating `target` would leave zero active superusers.
    LastActiveSuperuserDeactivate,
    /// Soft-deleting `target` would leave zero active superusers.
    LastActiveSuperuserDelete,
}

impl RoleViolation {
    /// Stable, user-facing flash message. Test-asserted; do not change
    /// without updating [`crate::handlers::web::users`] tests AND the
    /// `role_invariants_test` integration suite.
    pub const fn flash_message(&self) -> &'static str {
        match self {
            Self::SelfDemoteSuperuser => "You cannot remove your own superuser privileges",
            Self::SelfDemoteStaff => "You cannot remove your own staff privileges",
            Self::SelfDeactivate => "You cannot deactivate your own account",
            Self::SelfDelete => "You cannot delete your own account",
            Self::LastActiveSuperuserDemote => "Cannot demote the last active superuser",
            Self::LastActiveSuperuserDeactivate => "Cannot deactivate the last active superuser",
            Self::LastActiveSuperuserDelete => "Cannot delete the last active superuser",
        }
    }
}

/// Pure check (no DB): refuse self-demotion / self-deactivation /
/// self-delete.
///
/// Returns `Ok(())` if the operator is not the target, OR if the
/// mutation does not reduce the operator's own privileges (example: the
/// operator updates their own e-mail without touching the role flags).
///
/// `intent_delete` carries whether the calling site is a delete handler
/// (vs an edit handler). For delete the `before`/`after` snapshots are
/// otherwise identical, so we need this side channel to detect the
/// `SelfDelete` case without ambiguity.
pub fn check_self_change(
    operator_uuid: Uuid,
    target_uuid: Uuid,
    before: &RoleSnapshot,
    after: &RoleSnapshot,
    intent_delete: bool,
) -> Result<(), RoleViolation> {
    if operator_uuid != target_uuid {
        return Ok(());
    }

    if intent_delete {
        return Err(RoleViolation::SelfDelete);
    }

    // Self-demote: was a superuser, no longer one.
    if before.is_superuser && !after.is_superuser {
        return Err(RoleViolation::SelfDemoteSuperuser);
    }
    // Self-demote: was staff, no longer staff.
    if before.is_staff && !after.is_staff {
        return Err(RoleViolation::SelfDemoteStaff);
    }
    // Self-deactivate.
    if before.is_active && !after.is_active {
        return Err(RoleViolation::SelfDeactivate);
    }

    Ok(())
}

/// Async check, MUST run inside the SERIALIZABLE transaction that owns
/// the subsequent UPDATE/DELETE. Counts the **other** active, non-
/// soft-deleted superusers. If the mutation would leave zero, returns
/// the corresponding violation.
///
/// Excludes the target by `id` so we count only "other" rows; otherwise
/// a self-demote would always count its own row and never trigger.
///
/// `before` is the **current DB** state of the target (read in the same
/// transaction, before this call). `intent` selects which flavor of
/// violation to return; the count query is identical.
pub async fn check_last_active_superuser(
    conn: &mut AsyncPgConnection,
    target_id: i32,
    before: &RoleSnapshot,
    intent: ChangeIntent,
) -> Result<(), CheckError> {
    use crate::schema::users;

    // Only relevant if target is currently a usable superuser. A
    // demote of a non-superuser, deactivation of an inactive row, or
    // delete of a soft-deleted row cannot reduce the active-superuser
    // count below the current value, so the invariant is unaffected.
    if !(before.is_superuser && before.is_active && !before.is_deleted) {
        return Ok(());
    }

    let other_active_supers: i64 = users::table
        .filter(users::id.ne(target_id))
        .filter(users::is_superuser.eq(true))
        .filter(users::is_active.eq(true))
        .filter(users::is_deleted.eq(false))
        .count()
        .get_result(conn)
        .await
        .map_err(CheckError::Db)?;

    if other_active_supers >= 1 {
        return Ok(());
    }

    Err(CheckError::Violation(match intent {
        ChangeIntent::Demote => RoleViolation::LastActiveSuperuserDemote,
        ChangeIntent::Deactivate => RoleViolation::LastActiveSuperuserDeactivate,
        ChangeIntent::Delete => RoleViolation::LastActiveSuperuserDelete,
    }))
}

/// Result of an in-transaction invariant check: either a database error
/// to bubble up or a business-rule violation to translate to a flash /
/// HTTP response.
#[derive(Debug)]
pub enum CheckError {
    Violation(RoleViolation),
    Db(diesel::result::Error),
}

impl From<diesel::result::Error> for CheckError {
    fn from(e: diesel::result::Error) -> Self {
        Self::Db(e)
    }
}

/// Run an operation inside a SERIALIZABLE Postgres transaction, retrying
/// up to 3 times on `40001` (`SerializationFailure`) errors.
///
/// SERIALIZABLE is the strongest isolation level Postgres offers: it
/// detects read-write conflicts at commit time and aborts the offending
/// transaction with `40001`. This is the only way to make a `count()`
/// then `update()` pair atomic across concurrent writers (e.g. two
/// operators racing to demote the last superuser).
///
/// Retries are bounded (3 total attempts, exponential backoff 10/20/40
/// ms) so the handler cannot livelock under sustained contention; after
/// the cap the last error is bubbled up. Any non-serialization error is
/// surfaced immediately. The transaction is rolled back automatically by
/// `diesel-async` on `Err`.
///
/// `SET TRANSACTION ISOLATION LEVEL SERIALIZABLE` is issued as the first
/// statement inside the transaction; setting it on the connection-level
/// GUC would leak across pool checkouts.
///
/// The `op` closure is `Fn` (not `FnOnce`/`FnMut`) so it can be invoked
/// fresh on each retry. Captured state must therefore be `Sync` and any
/// per-attempt mutable state must live inside the closure body.
pub async fn run_serializable<T, F>(pool: &crate::db::DbPool, op: F) -> Result<T, CheckError>
where
    F: for<'c> Fn(
            &'c mut AsyncPgConnection,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<T, CheckError>> + Send + 'c>,
        > + Send
        + Sync,
    T: Send + 'static,
{
    use diesel::result::{DatabaseErrorKind, Error as DieselError};
    use diesel::sql_query;
    use diesel_async::AsyncConnection;

    const MAX_ATTEMPTS: u8 = 3;

    let op_ref = &op;

    let mut last_err: Option<CheckError> = None;
    for attempt in 0..MAX_ATTEMPTS {
        let mut conn = match pool.get().await {
            Ok(c) => c,
            Err(e) => {
                return Err(CheckError::Db(DieselError::DatabaseError(
                    DatabaseErrorKind::ClosedConnection,
                    Box::new(format!("pool error: {e}")),
                )));
            }
        };

        let result = conn
            .transaction::<T, CheckError, _>(|c| {
                Box::pin(async move {
                    sql_query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
                        .execute(c)
                        .await
                        .map_err(CheckError::Db)?;
                    op_ref(c).await
                })
            })
            .await;

        match result {
            Ok(v) => return Ok(v),
            Err(CheckError::Db(DieselError::DatabaseError(
                DatabaseErrorKind::SerializationFailure,
                _,
            ))) if attempt + 1 < MAX_ATTEMPTS => {
                let backoff = std::time::Duration::from_millis(10u64 << attempt);
                tokio::time::sleep(backoff).await;
                continue;
            }
            Err(e) => {
                last_err = Some(e);
                break;
            }
        }
    }
    // Invariant: the loop only `break`s after pushing into `last_err`,
    // and otherwise either `return Ok(_)` or `continue`. `unwrap_or_else`
    // documents that fact and avoids the clippy lint against `expect`
    // on Option values.
    Err(last_err.unwrap_or_else(|| {
        CheckError::Db(diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::SerializationFailure,
            Box::new("run_serializable: retries exhausted with no recorded error".to_string()),
        ))
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(s: bool, st: bool, a: bool, d: bool) -> RoleSnapshot {
        RoleSnapshot {
            is_superuser: s,
            is_staff: st,
            is_active: a,
            is_deleted: d,
        }
    }

    fn op() -> Uuid {
        Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap()
    }

    fn other() -> Uuid {
        Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap()
    }

    // -----------------------------------------------------------------
    // check_self_change -- different-target paths always allowed
    // -----------------------------------------------------------------

    #[test]
    fn different_target_demote_super_allowed() {
        let before = snap(true, true, true, false);
        let after = snap(false, true, true, false);
        assert!(check_self_change(op(), other(), &before, &after, false).is_ok());
    }

    #[test]
    fn different_target_delete_allowed() {
        let before = snap(true, true, true, false);
        let after = snap(true, true, true, true);
        assert!(check_self_change(op(), other(), &before, &after, true).is_ok());
    }

    // -----------------------------------------------------------------
    // check_self_change -- same-target diminutions refused
    // -----------------------------------------------------------------

    #[test]
    fn self_demote_superuser_refused() {
        let before = snap(true, true, true, false);
        let after = snap(false, true, true, false);
        assert_eq!(
            check_self_change(op(), op(), &before, &after, false),
            Err(RoleViolation::SelfDemoteSuperuser)
        );
    }

    #[test]
    fn self_demote_staff_refused() {
        let before = snap(false, true, true, false);
        let after = snap(false, false, true, false);
        assert_eq!(
            check_self_change(op(), op(), &before, &after, false),
            Err(RoleViolation::SelfDemoteStaff)
        );
    }

    #[test]
    fn self_deactivate_refused() {
        let before = snap(true, true, true, false);
        let after = snap(true, true, false, false);
        assert_eq!(
            check_self_change(op(), op(), &before, &after, false),
            Err(RoleViolation::SelfDeactivate)
        );
    }

    #[test]
    fn self_delete_refused_regardless_of_flags() {
        let before = snap(true, true, true, false);
        let after = snap(true, true, true, false);
        assert_eq!(
            check_self_change(op(), op(), &before, &after, true),
            Err(RoleViolation::SelfDelete)
        );
    }

    // -----------------------------------------------------------------
    // check_self_change -- same-target NON diminutions allowed
    // -----------------------------------------------------------------

    #[test]
    fn self_promote_super_allowed() {
        let before = snap(false, true, true, false);
        let after = snap(true, true, true, false);
        assert!(check_self_change(op(), op(), &before, &after, false).is_ok());
    }

    #[test]
    fn self_promote_staff_allowed() {
        let before = snap(true, false, true, false);
        let after = snap(true, true, true, false);
        assert!(check_self_change(op(), op(), &before, &after, false).is_ok());
    }

    #[test]
    fn self_no_change_allowed() {
        let before = snap(true, true, true, false);
        let after = snap(true, true, true, false);
        assert!(check_self_change(op(), op(), &before, &after, false).is_ok());
    }

    // The first violation matched wins. We assert order-of-matching is
    // (super, staff, active) so callers know which message they get
    // when multiple diminutions are stacked into the same form post.
    #[test]
    fn self_demote_super_takes_precedence_over_staff() {
        let before = snap(true, true, true, false);
        let after = snap(false, false, true, false);
        assert_eq!(
            check_self_change(op(), op(), &before, &after, false),
            Err(RoleViolation::SelfDemoteSuperuser)
        );
    }

    // -----------------------------------------------------------------
    // RoleViolation::flash_message -- stable wording (regression guard)
    // -----------------------------------------------------------------

    #[test]
    fn flash_messages_are_stable() {
        assert_eq!(
            RoleViolation::SelfDemoteSuperuser.flash_message(),
            "You cannot remove your own superuser privileges"
        );
        assert_eq!(
            RoleViolation::SelfDemoteStaff.flash_message(),
            "You cannot remove your own staff privileges"
        );
        assert_eq!(
            RoleViolation::SelfDeactivate.flash_message(),
            "You cannot deactivate your own account"
        );
        assert_eq!(
            RoleViolation::SelfDelete.flash_message(),
            "You cannot delete your own account"
        );
        assert_eq!(
            RoleViolation::LastActiveSuperuserDemote.flash_message(),
            "Cannot demote the last active superuser"
        );
        assert_eq!(
            RoleViolation::LastActiveSuperuserDeactivate.flash_message(),
            "Cannot deactivate the last active superuser"
        );
        assert_eq!(
            RoleViolation::LastActiveSuperuserDelete.flash_message(),
            "Cannot delete the last active superuser"
        );
    }
}
