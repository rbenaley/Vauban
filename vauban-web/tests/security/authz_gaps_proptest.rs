//! Property-based invariants for the three authorization fences closed
//! by `docs/remediation/authz_shadowing_and_api_gaps.md`:
//!
//! 1. the interactive WebSocket audience never honors
//!    `sessions:supervise`;
//! 2. a superuser row is editable only with `users:manage_admins`;
//! 3. a request justification is either refused or a trimmed, tag-free
//!    text of the minimum length.

use proptest::prelude::*;
use vauban_web::handlers::websocket::WsSessionAudience;
use vauban_web::services::access_request::{MIN_JUSTIFICATION_LEN, normalize_justification};
use vauban_web::services::role_invariants::{
    RoleSnapshot, RoleViolation, check_superuser_target_edit,
};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Owner-only audience: whatever the caller holds, the supervise
    /// override is off. The supervisor audience mirrors the flag.
    #[test]
    fn owner_only_audience_never_honors_supervise(holds_supervise in any::<bool>()) {
        prop_assert!(!WsSessionAudience::OwnerOnly.honors_supervise(holds_supervise));
        prop_assert_eq!(
            WsSessionAudience::OwnerOrSupervisor.honors_supervise(holds_supervise),
            holds_supervise
        );
    }

    /// The superuser-target fence refuses exactly when the target is a
    /// superuser and the caller lacks `users:manage_admins`. The other
    /// flags of the row never change the verdict.
    #[test]
    fn superuser_target_fence_refuses_iff_super_and_no_manage_admins(
        is_superuser in any::<bool>(),
        is_staff in any::<bool>(),
        is_active in any::<bool>(),
        is_deleted in any::<bool>(),
        can_manage_admins in any::<bool>(),
    ) {
        let before = RoleSnapshot { is_superuser, is_staff, is_active, is_deleted };
        let verdict = check_superuser_target_edit(&before, can_manage_admins);
        if is_superuser && !can_manage_admins {
            prop_assert_eq!(
                verdict,
                Err(RoleViolation::SuperuserEditRequiresManageAdmins)
            );
        } else {
            prop_assert_eq!(verdict, Ok(()));
        }
    }

    /// Anything shorter than the minimum once trimmed is refused.
    #[test]
    fn short_justification_is_refused(
        body in "[ -~]{0,9}",
        pad_left in "[ \\t\\n]{0,4}",
        pad_right in "[ \\t\\n]{0,4}",
    ) {
        let raw = format!("{pad_left}{body}{pad_right}");
        prop_assert_eq!(normalize_justification(Some(&raw)), None);
    }

    /// An accepted justification is trimmed, at least the minimum
    /// length, and carries no raw angle bracket (every tag is stripped,
    /// stray brackets are entity-encoded).
    #[test]
    fn accepted_justification_is_trimmed_and_tag_free(raw in "\\PC{0,200}") {
        if let Some(out) = normalize_justification(Some(&raw)) {
            prop_assert!(out.len() >= MIN_JUSTIFICATION_LEN);
            prop_assert_eq!(out.trim(), out.as_str());
            prop_assert!(!out.contains('<'), "raw '<' survived: {out:?}");
            prop_assert!(!out.contains('>'), "raw '>' survived: {out:?}");
        }
    }

    /// Plain alphanumeric text of sufficient length is accepted
    /// verbatim (modulo trimming): the fence does not eat honest input.
    #[test]
    fn plain_justification_is_accepted_verbatim(body in "[a-zA-Z0-9]{10,80}") {
        let raw = format!("  {body}\n");
        prop_assert_eq!(normalize_justification(Some(&raw)), Some(body));
    }
}
