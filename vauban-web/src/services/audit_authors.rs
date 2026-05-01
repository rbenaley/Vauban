//! Audit author resolution for detail pages.
//!
//! Issue #22 (UX-24) — surface `created_by` / `updated_by` on the
//! Metadata sections of the admin detail pages: assets, asset groups,
//! access rules. The data model already carries `created_by_id` and
//! `updated_by_id` (Nullable<Int4> -> users.id) on every audited
//! table; this module turns those raw foreign-key ids into a
//! presentation-ready [`AuthorRef`] without leaking implementation
//! details (e.g. user UUIDs, emails) that the Metadata UI does not
//! need.
//!
//! Resolution lives in vauban-web (not vauban-access) because the
//! audit metadata is purely a presentation concern of the admin
//! detail pages — keeping it out of the IPC contract avoids
//! unrelated services having to learn about audit actor display
//! names. The web layer already has direct DB access via
//! `state.db_pool`; the helper below is the only place where the
//! `users` table is joined for audit-display purposes, so any future
//! change to the display rule (e.g. honor a privacy preference)
//! lands in one spot.
//!
//! ## Display contract
//!
//! For each audited row, the Metadata section renders one of three
//! states:
//!
//! 1. **Active author**: `<username>`. Aligned with the
//!    approval-decision UI (`approver_username`, `approved_by`)
//!    so a single identity is surfaced everywhere on the audit
//!    surface. We never compose `First Last` here: the auditor
//!    needs the stable login name, not the cosmetic display name
//!    that an operator can rename in their profile.
//! 2. **Inactive author**: `<username>` followed by a muted
//!    `(inactive)` suffix. Triggered when `users.is_active = false`,
//!    matching the AC of issue #22.
//! 3. **Unknown / system**: `—` (em dash, muted). Returned both
//!    when the foreign key is `NULL` (e.g. row created by a system
//!    bootstrap script before the audit columns were back-filled)
//!    and when the user row was hard-deleted (referential integrity
//!    is `ON DELETE SET NULL`, see migration
//!    `20260102000000_initial_schema/up.sql`).
//!
//! State (3) is chosen instead of "Unknown user #42" both for
//! security (we never expose internal numeric ids) and for honesty
//! (we genuinely no longer have any way to render that author).

use std::collections::HashMap;

use diesel::prelude::*;
use diesel_async::AsyncPgConnection;
use diesel_async::RunQueryDsl;

/// Display-ready audit author.
///
/// Carries only what the Metadata UI needs to render — never the
/// numeric id, UUID, email or any other field that the admin
/// detail surface should not leak. `is_active` drives the
/// `(inactive)` suffix.
///
/// `username` is the stable login handle (`users.username`),
/// chosen over `first_name + last_name` so the audit-trail label
/// matches the approval-decision UI on
/// `/sessions/approvals/{uuid}` and `/sessions/recordings/{uuid}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorRef {
    pub username: String,
    pub is_active: bool,
}

impl AuthorRef {
    /// Plain-text label for the author. Used by tests and by
    /// Askama templates that prefer a single string over a
    /// branching block. The HTML view (templates) renders the
    /// `(inactive)` suffix as a styled `<span>` instead, so the
    /// muted formatting is preserved across themes.
    pub fn label(&self) -> String {
        if self.is_active {
            self.username.clone()
        } else {
            format!("{} (inactive)", self.username)
        }
    }
}

/// Bulk-resolve a slice of optional user ids into display-ready
/// [`AuthorRef`]s.
///
/// Returns a `HashMap<i32, AuthorRef>` keyed by `users.id` so the
/// caller can look up each row's `created_by_id` / `updated_by_id`
/// independently while issuing only one DB round-trip per detail
/// page (instead of two — see the dedup at the top of this
/// function).
///
/// `None` slots in `ids` are filtered out before issuing the
/// query, and ids that point to a user row that has since been
/// hard-deleted simply do not appear in the returned map; callers
/// are expected to treat both cases identically (rendering the
/// "unknown / system" state).
pub async fn resolve_authors(
    conn: &mut AsyncPgConnection,
    ids: &[Option<i32>],
) -> HashMap<i32, AuthorRef> {
    use crate::schema::users::dsl as u;

    let mut wanted: Vec<i32> = ids.iter().filter_map(|id| *id).collect();
    wanted.sort_unstable();
    wanted.dedup();

    if wanted.is_empty() {
        return HashMap::new();
    }

    type UserRow = (i32, String, bool);
    let rows: Vec<UserRow> = match u::users
        .filter(u::id.eq_any(&wanted))
        .select((u::id, u::username, u::is_active))
        .load(conn)
        .await
    {
        Ok(rows) => rows,
        Err(_) => {
            // The Metadata section is non-critical: a transient DB
            // failure on the author lookup must not break the
            // detail page. Return an empty map and let the caller
            // fall back to the "unknown / system" rendering.
            return HashMap::new();
        }
    };

    rows.into_iter()
        .map(|(id, username, is_active)| {
            (
                id,
                AuthorRef {
                    username,
                    is_active,
                },
            )
        })
        .collect()
}

/// Convenience: bulk-resolve and return `(created_by, updated_by)`
/// in the order matching the standard audit-column pair on every
/// audited table.
pub async fn resolve_audit_pair(
    conn: &mut AsyncPgConnection,
    created_by_id: Option<i32>,
    updated_by_id: Option<i32>,
) -> (Option<AuthorRef>, Option<AuthorRef>) {
    let map = resolve_authors(conn, &[created_by_id, updated_by_id]).await;
    let created = created_by_id.and_then(|id| map.get(&id).cloned());
    let updated = updated_by_id.and_then(|id| map.get(&id).cloned());
    (created, updated)
}

/// Resolve the *write-side* audit actor: turn a JWT-side UUID
/// (the `sub` claim, exposed as `AuthUser.uuid`) into a numeric
/// `users.id` suitable for stamping `created_by_id` /
/// `updated_by_id` on a write.
///
/// Returns `None` when the UUID does not parse, when the lookup
/// fails, or when no matching user row exists. Callers MUST be
/// safe with a `None` actor: the audit columns are
/// `Nullable<Int4>` precisely so a transient lookup miss never
/// blocks a legitimate write. The Metadata UI then falls back to
/// the muted em-dash, exactly like a row created before the
/// audit columns were back-filled.
///
/// Issue #22 — UX-24. Companion to [`resolve_audit_pair`] which
/// powers the *read-side* presentation.
pub async fn resolve_actor_id(conn: &mut AsyncPgConnection, actor_uuid: &str) -> Option<i32> {
    use crate::schema::users::dsl as u;

    let parsed = ::uuid::Uuid::parse_str(actor_uuid).ok()?;
    u::users
        .filter(u::uuid.eq(parsed))
        .select(u::id)
        .first::<i32>(conn)
        .await
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn active(name: &str) -> AuthorRef {
        AuthorRef {
            username: name.to_string(),
            is_active: true,
        }
    }

    fn inactive(name: &str) -> AuthorRef {
        AuthorRef {
            username: name.to_string(),
            is_active: false,
        }
    }

    #[test]
    fn label_active_returns_username_unchanged() {
        assert_eq!(active("alice").label(), "alice");
    }

    #[test]
    fn label_inactive_appends_muted_suffix() {
        assert_eq!(inactive("bob").label(), "bob (inactive)");
    }

    #[test]
    fn author_ref_equality_holds_on_clone() {
        let a = active("Alice");
        assert_eq!(a, a.clone());
        let b = inactive("Bob");
        assert_eq!(b, b.clone());
        assert_ne!(active("X"), inactive("X"));
    }
}
