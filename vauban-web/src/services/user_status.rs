//! Usable-account contract and the approval-mail recipient pool.
//!
//! A row may act iff `is_active && !is_deleted`. Soft-delete is the
//! tombstone; deactivation is the "still listed, cannot log in" flag.
//! Delete now sets both (and a DB CHECK forbids `is_deleted && is_active`).
//!
//! Every Diesel filter that uses `users::is_active.eq(true)` MUST also
//! carry `users::is_deleted.eq(false)` (enforced by
//! `scripts/check_users_usable_filters.sh`).

use diesel::prelude::*;
use diesel_async::{AsyncPgConnection, RunQueryDsl};

use crate::schema::users;

/// Account may act: enabled and not a tombstone.
pub fn is_usable(is_active: bool, is_deleted: bool) -> bool {
    is_active && !is_deleted
}

/// CHECK `users_tombstone_is_inactive`: a tombstone cannot stay active.
pub fn tombstone_flags_legal(is_deleted: bool, is_active: bool) -> bool {
    !is_deleted || !is_active
}

/// Staff or superuser who may receive an approval-request email.
pub fn is_approver_candidate(
    is_active: bool,
    is_deleted: bool,
    is_staff: bool,
    is_superuser: bool,
    email: &str,
) -> bool {
    is_usable(is_active, is_deleted) && (is_staff || is_superuser) && !email.is_empty()
}

/// Requester may receive a decision / offboard courtesy email.
pub fn requester_may_receive_mail(is_active: bool, is_deleted: bool, email: &str) -> bool {
    is_usable(is_active, is_deleted) && !email.is_empty()
}

/// Live staff ∪ superuser contacts with a non-empty mailbox.
///
/// Used by JIT `access_request.submitted` and IACS `onboard_submitted`.
pub async fn load_approver_contacts(
    conn: &mut AsyncPgConnection,
) -> Result<Vec<(String, String)>, diesel::result::Error> {
    users::table
        .filter(users::is_active.eq(true))
        .filter(users::is_deleted.eq(false))
        .filter(users::is_staff.eq(true).or(users::is_superuser.eq(true)))
        .filter(users::email.ne(""))
        .select((users::email, users::username))
        .load(conn)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_usable_requires_active_and_not_deleted() {
        let cases = [
            (true, false, true),
            (false, false, false),
            (true, true, false),
            (false, true, false),
        ];
        for (active, deleted, expected) in cases {
            assert_eq!(
                is_usable(active, deleted),
                expected,
                "active={active} deleted={deleted}"
            );
        }
    }

    #[test]
    fn tombstone_cannot_stay_active() {
        assert!(tombstone_flags_legal(false, true));
        assert!(tombstone_flags_legal(false, false));
        assert!(tombstone_flags_legal(true, false));
        assert!(!tombstone_flags_legal(true, true));
    }

    #[test]
    fn approver_is_staff_or_superuser_usable_with_email() {
        assert!(is_approver_candidate(true, false, true, false, "a@x"));
        assert!(is_approver_candidate(true, false, false, true, "a@x"));
        assert!(is_approver_candidate(true, false, true, true, "a@x"));
        assert!(!is_approver_candidate(true, false, false, false, "a@x"));
        assert!(!is_approver_candidate(false, false, true, true, "a@x"));
        assert!(!is_approver_candidate(true, true, true, true, "a@x"));
        assert!(!is_approver_candidate(true, false, true, true, ""));
    }

    #[test]
    fn requester_mail_skips_tombstone_and_empty() {
        assert!(requester_may_receive_mail(true, false, "a@x"));
        assert!(!requester_may_receive_mail(true, true, "a@x"));
        assert!(!requester_may_receive_mail(false, false, "a@x"));
        assert!(!requester_may_receive_mail(true, false, ""));
    }

    proptest::proptest! {
        #![proptest_config(proptest::test_runner::Config::with_cases(64))]

        #[test]
        fn approver_candidate_matches_contract(
            active in proptest::bool::ANY,
            deleted in proptest::bool::ANY,
            staff in proptest::bool::ANY,
            superuser in proptest::bool::ANY,
            email in ".*",
        ) {
            let got = is_approver_candidate(active, deleted, staff, superuser, &email);
            let expected =
                active && !deleted && (staff || superuser) && !email.is_empty();
            proptest::prop_assert_eq!(got, expected);
            if deleted {
                proptest::prop_assert!(!is_usable(active, deleted));
            }
        }

        #[test]
        fn tombstone_flags_mirror_check(deleted in proptest::bool::ANY, active in proptest::bool::ANY) {
            proptest::prop_assert_eq!(
                tombstone_flags_legal(deleted, active),
                !deleted || !active
            );
        }
    }

    #[test]
    fn battle_approver_predicate_under_contention() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let barrier = Arc::new(Barrier::new(8));
        let mut handles = Vec::new();
        for t in 0..8 {
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                for i in 0..64 {
                    let active = i % 2 == 0;
                    let deleted = i % 3 == 0;
                    let staff = t % 2 == 0;
                    let email = if i % 5 == 0 {
                        String::new()
                    } else {
                        format!("u{t}-{i}@x.test")
                    };
                    let got = is_approver_candidate(active, deleted, staff, true, &email);
                    let expected = active && !deleted && !email.is_empty();
                    assert_eq!(got, expected);
                }
            }));
        }
        for h in handles {
            h.join().expect("battle thread");
        }
    }
}
