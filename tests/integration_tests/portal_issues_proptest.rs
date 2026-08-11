//! Property tests for issue details bounds / key shaping / comment roles.

use proptest::prelude::*;
use vcp::app::lightbox_step_index;
use vcp::issue_anchor::{ISSUE_REPLY_ANCHOR, with_reply_anchor};
use vcp::issue_attachments::{
    AttachmentToken, attachment_cap_hint, gallery_src, parse_attachment_token,
};
use vcp::issue_component::{ISSUE_COMPONENTS, normalize_issue_component};
use vcp::issue_fsm::{ALL_EVENTS, IssueEvent, IssueState};
use vcp::issue_key::{next_issue_key_from_keys, parse_vbn_suffix};
use vcp::issue_status::issue_is_closed;
use vcp::models::{
    ISSUE_ATTACHMENT_OPENER_COMMENT_ID, ISSUE_COMMENT_KIND_COMMENT, ISSUE_COMMENT_KIND_STATUS,
    ISSUE_ROLE_REPORTER, ISSUE_ROLE_SUPPORT, ISSUE_ROLE_SYSTEM, ISSUE_STATUS_CLOSED,
    ISSUE_STATUS_IN_ANALYSIS, ISSUE_STATUS_OPEN, ISSUE_STATUS_RESOLVED, IssueAttachment,
    MAX_ISSUE_ATTACHMENTS,
};

fn reference_model(state: IssueState, event: IssueEvent) -> Option<IssueState> {
    use IssueEvent::*;
    use IssueState::*;
    match (state, event) {
        (Open, StartAnalysis) => Some(InAnalysis),
        (InAnalysis, Resolve) => Some(Resolved),
        (Resolved, Close) => Some(Closed),
        (Resolved, Reopen) => Some(InAnalysis),
        (Closed, Reopen) => Some(Open),
        _ => None,
    }
}

fn any_state() -> impl Strategy<Value = IssueState> {
    prop_oneof![
        Just(IssueState::Open),
        Just(IssueState::InAnalysis),
        Just(IssueState::Resolved),
        Just(IssueState::Closed),
    ]
}

fn any_event() -> impl Strategy<Value = IssueEvent> {
    prop_oneof![
        Just(IssueEvent::StartAnalysis),
        Just(IssueEvent::Resolve),
        Just(IssueEvent::Close),
        Just(IssueEvent::Reopen),
    ]
}

proptest! {
    #![proptest_config(crate::common::prop_config(64))]

    #[test]
    fn prop_fsm_matches_reference_model(state in any_state(), event in any_event()) {
        prop_assert_eq!(state.transition(event).ok(), reference_model(state, event));
    }

    #[test]
    fn prop_fsm_sequences_never_panic(
        events in prop::collection::vec(any_event(), 0..40)
    ) {
        let mut state = IssueState::Open;
        for event in events {
            if let Ok(next) = state.transition(event) {
                state = next;
            }
        }
        prop_assert!(matches!(
            state,
            IssueState::Open
                | IssueState::InAnalysis
                | IssueState::Resolved
                | IssueState::Closed
        ));
        let _ = ALL_EVENTS;
    }
}

proptest! {
    #![proptest_config(crate::common::prop_config(32))]

    #[test]
    fn prop_details_trim_preserves_nonempty(raw in "[a-zA-Z0-9 .]{1,200}") {
        let details = raw.trim().to_owned();
        prop_assume!(!details.is_empty());
        prop_assert_eq!(details.len(), details.trim().len());
        prop_assert!(details.len() <= 200);
    }

    #[test]
    fn prop_normalize_issue_component_round_trips_catalogue(
        idx in 0usize..ISSUE_COMPONENTS.len()
    ) {
        let label = ISSUE_COMPONENTS[idx];
        prop_assert_eq!(normalize_issue_component(label), Some(label));
        prop_assert_eq!(
            normalize_issue_component(&format!("  {label}  ")),
            Some(label)
        );
        prop_assert_eq!(
            normalize_issue_component(&label.to_ascii_lowercase()),
            Some(label)
        );
    }

    #[test]
    fn prop_normalize_rejects_unknown_component(s in "[A-Za-z]{3,20}") {
        prop_assume!(!ISSUE_COMPONENTS.iter().any(|c| c.eq_ignore_ascii_case(&s)));
        prop_assume!(!s.eq_ignore_ascii_case("SSH Proxy"));
        prop_assume!(!s.eq_ignore_ascii_case("RDP Gateway"));
        prop_assume!(!s.eq_ignore_ascii_case("Control plane"));
        prop_assert_eq!(normalize_issue_component(&s), None);
    }
}

proptest! {
    #![proptest_config(crate::common::prop_config(24))]

    #[test]
    fn prop_issue_key_shape(n in 200u32..500) {
        let key = format!("VBN-{n}");
        prop_assert!(key.starts_with("VBN-"));
        prop_assert!(key.len() >= 5);
        prop_assert_eq!(parse_vbn_suffix(&key), Some(n));
    }
}

proptest! {
    #![proptest_config(crate::common::prop_config(32))]

    #[test]
    fn prop_next_issue_key_strictly_above_max_vbn(
        suffixes in prop::collection::vec(0u32..10_000, 0..40),
        noise in prop::collection::vec("[A-Z]{2,6}-[0-9]{1,5}", 0..10)
    ) {
        let mut keys: Vec<String> = suffixes.iter().map(|n| format!("VBN-{n}")).collect();
        keys.extend(noise);
        let key_refs: Vec<&str> = keys.iter().map(String::as_str).collect();
        let next = next_issue_key_from_keys(key_refs.iter().copied());
        let next_n = parse_vbn_suffix(&next).expect("allocator returns VBN-n");
        if let Some(max) = suffixes.iter().copied().max() {
            prop_assert!(next_n > max);
        } else {
            prop_assert_eq!(next_n, 200);
        }
    }
}

proptest! {
    #![proptest_config(crate::common::prop_config(24))]

    #[test]
    fn prop_comment_role_and_kind_are_catalogued(
        role in prop_oneof![
            Just(ISSUE_ROLE_REPORTER),
            Just(ISSUE_ROLE_SUPPORT),
            Just(ISSUE_ROLE_SYSTEM)
        ],
        kind in prop_oneof![
            Just(ISSUE_COMMENT_KIND_COMMENT),
            Just(ISSUE_COMMENT_KIND_STATUS)
        ]
    ) {
        prop_assert!(matches!(
            role,
            "reporter" | "support" | "system"
        ));
        prop_assert!(matches!(kind, "comment" | "status_change"));
    }
}

proptest! {
    #![proptest_config(crate::common::prop_config(24))]

    #[test]
    fn prop_issue_closed_catalogue(
        status in prop_oneof![
            Just(ISSUE_STATUS_OPEN),
            Just(ISSUE_STATUS_IN_ANALYSIS),
            Just(ISSUE_STATUS_RESOLVED),
            Just(ISSUE_STATUS_CLOSED),
            Just("closed"),
            Just("RESOLVED"),
            Just("open")
        ]
    ) {
        let closed = issue_is_closed(status);
        let expect = status.eq_ignore_ascii_case(ISSUE_STATUS_CLOSED)
            || status.eq_ignore_ascii_case(ISSUE_STATUS_RESOLVED);
        prop_assert_eq!(closed, expect);
        if status.eq_ignore_ascii_case(ISSUE_STATUS_CLOSED) {
            prop_assert_eq!(
                IssueState::Closed.transition(IssueEvent::Reopen).ok(),
                Some(IssueState::Open)
            );
        }
        if status.eq_ignore_ascii_case(ISSUE_STATUS_RESOLVED) {
            prop_assert_eq!(
                IssueState::Resolved.transition(IssueEvent::Reopen).ok(),
                Some(IssueState::InAnalysis)
            );
        }
    }
}

fn uuid_v4_hyphenated() -> impl Strategy<Value = String> {
    "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
}

proptest! {
    #![proptest_config(crate::common::prop_config(48))]

    #[test]
    fn prop_attachment_token_round_trip(
        id in uuid_v4_hyphenated(),
        ext in prop_oneof![Just("png"), Just("jpg"), Just("jpeg"), Just("webp"), Just("PNG"), Just("JPG")]
    ) {
        let raw = format!("{id}.{ext}");
        let parsed = parse_attachment_token(&raw).expect("canonical token");
        let expect_ext = match ext.to_ascii_lowercase().as_str() {
            "jpg" | "jpeg" => "jpeg",
            "png" => "png",
            "webp" => "webp",
            _ => unreachable!(),
        };
        prop_assert_eq!(&parsed.image_id, &id);
        prop_assert_eq!(parsed.ext, expect_ext);
        let again = parse_attachment_token(&parsed.as_filename());
        prop_assert_eq!(again.as_ref().map(|t| t.ext), Some(expect_ext));
        prop_assert_eq!(again.map(|t| t.image_id), Some(id));
    }
}

proptest! {
    #![proptest_config(crate::common::prop_config(48))]

    #[test]
    fn prop_attachment_garbage_rejected(
        junk in prop::collection::vec(prop::char::any(), 0..64)
    ) {
        let raw: String = junk.into_iter().collect();
        // Almost all random strings fail; accept only if they happen to match.
        if let Some(tok) = parse_attachment_token(&raw) {
            prop_assert!(vcp::storage::is_uuid_key(&tok.image_id));
            prop_assert!(matches!(tok.ext, "png" | "jpeg" | "webp"));
        }
    }
}

proptest! {
    #![proptest_config(crate::common::prop_config(48))]

    /// Multi-image lightbox nav wraps at both ends for every strip length ≥ 2.
    #[test]
    fn prop_lightbox_step_wraps(
        len in 2usize..12,
        index in 0usize..12,
        step in prop::sample::select(vec![-1i32, 1, -2, 2, 5, -5]),
    ) {
        let index = index % len;
        let next = lightbox_step_index(index, len, step).expect("nav enabled");
        prop_assert!(next < len);
        let expected = {
            let n = len as i64;
            let i = index as i64 + i64::from(step);
            (((i % n) + n) % n) as usize
        };
        prop_assert_eq!(next, expected);
        // One full lap of +1 (resp. −1) returns to the start.
        if step == 1 {
            let mut i = index;
            for _ in 0..len {
                i = lightbox_step_index(i, len, 1).unwrap();
            }
            prop_assert_eq!(i, index);
        }
        if step == -1 {
            let mut i = index;
            for _ in 0..len {
                i = lightbox_step_index(i, len, -1).unwrap();
            }
            prop_assert_eq!(i, index);
        }
    }

    #[test]
    fn prop_lightbox_step_noop_when_not_multi(len in 0usize..2, index in 0usize..4, step in -3i32..4) {
        prop_assert_eq!(lightbox_step_index(index, len, step), None);
    }
}

proptest! {
    #![proptest_config(crate::common::prop_config(48))]

    /// The lightbox copies this path into `data-src` and then into `img.src`,
    /// so it must stay a same-origin portal path for every org / image pair.
    #[test]
    fn prop_gallery_src_is_first_party(
        slug in "[a-z0-9][a-z0-9-]{0,24}",
        id in "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        ext in prop::sample::select(vec!["png", "jpeg", "webp"]),
    ) {
        let att = IssueAttachment {
            id: 1,
            issue_id: 2,
            organization_id: 3,
            issue_comment_id: ISSUE_ATTACHMENT_OPENER_COMMENT_ID,
            image_id: id.clone(),
            ext: ext.to_owned(),
            uploaded_by_user_id: 4,
            created_at: 0,
            sort_order: 0,
        };
        let src = gallery_src(&slug, &att);
        prop_assert_eq!(&src, &format!("/{slug}/images/{id}.{ext}"));
        prop_assert!(src.starts_with('/'));
        prop_assert!(!src.starts_with("//"), "must not become protocol-relative");
        prop_assert!(!src.contains("://"), "must stay same-origin");
        prop_assert!(!src.contains(".."), "must not traverse");
    }
}

proptest! {
    #![proptest_config(crate::common::prop_config(24))]

    #[test]
    fn prop_attachment_cap_is_five(_n in 0u8..10) {
        prop_assert_eq!(MAX_ISSUE_ATTACHMENTS, 5);
        prop_assert_eq!(
            MAX_ISSUE_ATTACHMENTS,
            vcp::models::DEFAULT_MAX_ATTACHMENTS_PER_COMMENT
        );
        let _ = AttachmentToken {
            image_id: "550e8400-e29b-41d4-a716-446655440000".into(),
            ext: "png",
        };
    }
}

proptest! {
    #![proptest_config(crate::common::prop_config(64))]

    /// A `Location` header only scrolls the browser when the fragment comes
    /// last: `?err=` codes and `?org=` hints must never end up behind the `#`.
    #[test]
    fn prop_reply_anchor_stays_last(
        slug in "[a-z0-9][a-z0-9-]{0,24}",
        key in "VBN-[0-9]{1,5}",
        err in prop::option::of(prop::sample::select(vec!["attach", "reply", "create"])),
        org_hint in prop::option::of("[a-z0-9-]{1,24}"),
    ) {
        let mut href = format!("/{slug}/issues/{key}");
        if let Some(hint) = &org_hint {
            href.push_str(&format!("?org={hint}"));
        }
        if let Some(code) = &err {
            let sep = if href.contains('?') { '&' } else { '?' };
            href.push(sep);
            href.push_str(&format!("err={code}"));
        }
        let target = with_reply_anchor(&href);

        prop_assert_eq!(target.matches('#').count(), 1, "exactly one fragment: {}", &target);
        prop_assert!(target.ends_with(&format!("#{ISSUE_REPLY_ANCHOR}")), "{}", &target);
        let (path, fragment) = target.split_once('#').expect("fragment");
        prop_assert_eq!(path, &href, "path must survive untouched");
        prop_assert_eq!(fragment, ISSUE_REPLY_ANCHOR);
        if let Some(q) = path.find('?') {
            prop_assert!(q < target.find('#').expect("fragment"), "query before fragment");
        }
        // Re-anchoring a target is a no-op, so nested helpers cannot stack `#`.
        prop_assert_eq!(with_reply_anchor(&target), target.clone());
    }
}

proptest! {
    #![proptest_config(crate::common::prop_config(48))]

    /// The picker hint is the only place a reporter learns how many
    /// screenshots fit, so it must state the effective cap for any config
    /// value — including a misconfigured 0, which the server clamps to 1.
    #[test]
    fn prop_cap_hint_states_the_effective_cap(max in 0usize..64) {
        let hint = attachment_cap_hint(max);
        let effective = max.max(1);
        prop_assert!(hint.contains(&effective.to_string()), "hint: {hint}");
        prop_assert!(hint.contains("PNG") && hint.contains("JPEG") && hint.contains("WebP"));
        prop_assert!(
            hint.contains("drag") && hint.contains("browse"),
            "hint must invite drag & drop: {hint}"
        );
        prop_assert!(!hint.contains("up to 0"), "never advertise a zero cap: {hint}");
        if effective == 1 {
            prop_assert!(hint.contains("1 screenshot per"), "singular: {hint}");
        } else {
            prop_assert!(hint.contains("screenshots"), "plural: {hint}");
        }
    }
}
