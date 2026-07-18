//! Property-based invariants for the shared list filtering /
//! pagination seam (`services::list_filters`), which every list page
//! of vauban-web now goes through.
//!
//! The pagination properties pin the *canonical* arithmetic that the
//! 13 hand-rolled copies used to implement (float `ceil().max(1.0)` +
//! `page.min(total_pages)`), so the integer rewrite can never drift
//! from the historical behavior. The predicate properties pin the
//! in-memory filters (search / select / protocol) used by the
//! IPC-backed lists, and the LIKE-escaping property pins the fix of
//! the `/audit/approvals` wildcard-injection drift.

use std::collections::HashMap;

use proptest::prelude::*;
use vauban_web::services::list_filters::{
    distinct_sorted, matches_bool, matches_search, matches_select, opt_filter, paginate,
    parse_active_inactive, parse_page, parse_page_param, parse_yes_no, protocol_matches,
    slice_page,
};

fn params_from(pairs: Vec<(String, String)>) -> HashMap<String, String> {
    pairs.into_iter().collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    // -----------------------------------------------------------------
    // Query-param parsing
    // -----------------------------------------------------------------

    /// `opt_filter` is total and returns Some iff the key maps to a
    /// non-empty value.
    #[test]
    fn opt_filter_some_iff_non_empty(
        pairs in proptest::collection::vec(("[a-z]{1,8}", ".{0,12}"), 0..6),
        key in "[a-z]{1,8}",
    ) {
        let params = params_from(pairs);
        let got = opt_filter(&params, &key);
        match params.get(&key) {
            Some(v) if !v.is_empty() => prop_assert_eq!(got, Some(v.clone())),
            _ => prop_assert_eq!(got, None),
        }
    }

    /// `parse_page` is total and always >= 1, for arbitrary raw input.
    #[test]
    fn parse_page_is_total_and_at_least_one(raw in ".{0,16}") {
        let params = params_from(vec![("page".to_string(), raw.clone())]);
        let page = parse_page(&params);
        prop_assert!(page >= 1);
        // A valid positive integer must round-trip untouched.
        if let Ok(n) = raw.parse::<i32>()
            && n >= 1 {
                prop_assert_eq!(page, n);
        }
        // Keyed variant is the same function under a different key.
        let params2 = params_from(vec![("ews_page".to_string(), raw)]);
        prop_assert_eq!(parse_page_param(&params2, "ews_page"), page);
    }

    // -----------------------------------------------------------------
    // Pagination
    // -----------------------------------------------------------------

    /// The integer arithmetic is exactly equivalent to the historical
    /// float formula used by every hand-rolled copy:
    /// `((total as f64) / (per as f64)).ceil().max(1.0)` then
    /// `page.min(total_pages)` / `offset = (page-1)*per`.
    #[test]
    fn paginate_matches_canonical_float_arithmetic(
        total in 0usize..100_000,
        page in 1i32..5_000,
        per in 1usize..500,
    ) {
        let w = paginate(total, page, per);
        let float_pages = ((total as f64) / (per as f64)).ceil().max(1.0) as i32;
        let clamped = page.min(float_pages);
        let offset = ((clamped - 1) as usize) * per;
        prop_assert_eq!(w.total_pages, float_pages);
        prop_assert_eq!(w.page, clamped);
        prop_assert_eq!(w.offset, offset);
        prop_assert_eq!(w.start_index, if total > 0 { offset + 1 } else { 0 });
        prop_assert_eq!(w.end_index, (offset + per).min(total));
        prop_assert_eq!(w.has_previous, clamped > 1);
        prop_assert_eq!(w.has_next, clamped < float_pages);
    }

    /// Structural invariants: page clamped in `1..=total_pages`,
    /// `total_pages >= 1`, indices coherent, never panics — including
    /// hostile inputs (page <= 0, per_page == 0).
    #[test]
    fn paginate_is_total_and_clamped(
        total in 0usize..1_000_000,
        page in proptest::num::i32::ANY,
        per in 0usize..1_000,
    ) {
        let w = paginate(total, page, per);
        prop_assert!(w.total_pages >= 1);
        prop_assert!(w.page >= 1 && w.page <= w.total_pages);
        prop_assert!(w.per_page >= 1);
        prop_assert!(w.end_index <= total);
        if total == 0 {
            prop_assert_eq!(w.start_index, 0);
            prop_assert_eq!(w.end_index, 0);
        } else {
            prop_assert_eq!(w.start_index, w.offset + 1);
            prop_assert!(w.start_index <= w.end_index);
        }
    }

    /// Walking every page with `slice_page` reconstructs the whole
    /// list, in order, with no duplicates and no losses.
    #[test]
    fn slice_page_union_over_all_pages_is_identity(
        len in 0usize..400,
        per in 1usize..40,
    ) {
        let items: Vec<usize> = (0..len).collect();
        let first = paginate(len, 1, per);
        let mut rebuilt: Vec<usize> = Vec::new();
        for p in 1..=first.total_pages {
            let w = paginate(len, p, per);
            rebuilt.extend(slice_page(items.clone(), &w));
        }
        prop_assert_eq!(rebuilt, items);
    }

    /// The three converters carry the window fields faithfully.
    #[test]
    fn pagination_converters_are_faithful(
        total in 0usize..100_000,
        page in 1i32..5_000,
        per in 1usize..500,
    ) {
        let w = paginate(total, page, per);
        let p = w.to_pagination();
        prop_assert_eq!(p.current_page, w.page);
        prop_assert_eq!(p.total_pages, w.total_pages);
        prop_assert_eq!(p.total_items as usize, w.total_items);
        prop_assert_eq!(p.items_per_page as usize, w.per_page);
        prop_assert_eq!(p.start_index as usize, w.start_index);
        prop_assert_eq!(p.end_index as usize, w.end_index);
        prop_assert_eq!(p.has_previous, w.has_previous);
        prop_assert_eq!(p.has_next, w.has_next);
        let a = w.to_approval_pagination();
        prop_assert_eq!(a.current_page, w.page);
        prop_assert_eq!(a.total_pages, w.total_pages);
        prop_assert_eq!(a.total_items as usize, w.total_items);
        let d = w.to_audit_pagination();
        prop_assert_eq!(d.current_page, w.page);
        prop_assert_eq!(d.total_items as usize, w.total_items);
        prop_assert_eq!(w.offset_i64() as usize, w.offset);
        prop_assert_eq!(w.limit_i64() as usize, w.per_page);
    }

    // -----------------------------------------------------------------
    // In-memory predicates
    // -----------------------------------------------------------------

    /// Identity: no filter (None or blank) matches everything.
    #[test]
    fn matches_search_none_or_blank_is_identity(
        hay in proptest::collection::vec(".{0,20}", 0..4),
        blanks in "[ \t]{0,6}",
    ) {
        let refs: Vec<&str> = hay.iter().map(String::as_str).collect();
        prop_assert!(matches_search(&refs, None));
        prop_assert!(matches_search(&refs, Some(&blanks)));
    }

    /// Case-insensitivity: changing the case of the needle never
    /// changes the outcome, and a needle taken from a haystack always
    /// matches.
    #[test]
    fn matches_search_is_case_insensitive_and_reflexive(
        hay in proptest::collection::vec("[a-zA-Z0-9 ]{1,20}", 1..4),
        idx in 0usize..4,
    ) {
        let refs: Vec<&str> = hay.iter().map(String::as_str).collect();
        let needle = &hay[idx % hay.len()];
        prop_assert!(matches_search(&refs, Some(needle)));
        prop_assert!(matches_search(&refs, Some(&needle.to_uppercase())));
        prop_assert!(matches_search(&refs, Some(&needle.to_lowercase())));
    }

    /// `matches_select` is exact equality under Some, identity under
    /// None; `matches_bool` likewise.
    #[test]
    fn select_and_bool_filters_are_exact(
        value in ".{0,16}",
        filter in proptest::option::of(".{0,16}"),
        b in proptest::bool::ANY,
        fb in proptest::option::of(proptest::bool::ANY),
    ) {
        let expected = filter.as_ref().is_none_or(|f| f == &value);
        prop_assert_eq!(matches_select(&value, filter.as_deref()), expected);
        let expected_b = fb.is_none_or(|f| f == b);
        prop_assert_eq!(matches_bool(b, fb), expected_b);
    }

    /// Protocol semantics: `ssh`/`rdp` exact membership, `iacs`
    /// matches iff any protocol has the `iacs_` prefix, unknown
    /// filter values match nothing (fail-closed), None matches all.
    #[test]
    fn protocol_matches_semantics_hold(
        protos in proptest::collection::vec(
            prop_oneof!["ssh".prop_map(String::from), "rdp".prop_map(String::from), "iacs_[a-z]{1,8}"],
            0..5,
        ),
        junk in "[a-z]{1,10}",
    ) {
        prop_assert!(protocol_matches(&protos, None));
        prop_assert_eq!(
            protocol_matches(&protos, Some("ssh")),
            protos.iter().any(|p| p == "ssh")
        );
        prop_assert_eq!(
            protocol_matches(&protos, Some("rdp")),
            protos.iter().any(|p| p == "rdp")
        );
        prop_assert_eq!(
            protocol_matches(&protos, Some("iacs")),
            protos.iter().any(|p| p.starts_with("iacs_"))
        );
        if junk != "ssh" && junk != "rdp" && junk != "iacs" {
            prop_assert!(!protocol_matches(&protos, Some(&junk)));
        }
    }

    /// `distinct_sorted` output is deduplicated, case-insensitively
    /// ordered, preserves the value set, and is idempotent.
    #[test]
    fn distinct_sorted_dedups_and_orders(
        values in proptest::collection::vec("[a-zA-Z]{1,10}", 0..12),
    ) {
        let out = distinct_sorted(values.iter().map(String::as_str));
        // Every input value survives, no invented values.
        for v in &values {
            prop_assert!(out.contains(v));
        }
        for v in &out {
            prop_assert!(values.contains(v));
        }
        // Case-insensitive order.
        for pair in out.windows(2) {
            prop_assert!(pair[0].to_lowercase() <= pair[1].to_lowercase());
        }
        // Idempotence.
        let again = distinct_sorted(out.iter().map(String::as_str));
        prop_assert_eq!(again, out);
    }

    /// Yes/no and active/inactive parsers are closed vocabularies:
    /// anything outside them degrades to "no filter".
    #[test]
    fn boolean_select_parsers_are_closed(raw in ".{0,12}") {
        let yn = parse_yes_no(Some(&raw));
        match raw.as_str() {
            "yes" => prop_assert_eq!(yn, Some(true)),
            "no" => prop_assert_eq!(yn, Some(false)),
            _ => prop_assert_eq!(yn, None),
        }
        let ai = parse_active_inactive(Some(&raw));
        match raw.as_str() {
            "active" => prop_assert_eq!(ai, Some(true)),
            "inactive" => prop_assert_eq!(ai, Some(false)),
            _ => prop_assert_eq!(ai, None),
        }
    }

    // -----------------------------------------------------------------
    // LIKE escaping (audit drift fix)
    // -----------------------------------------------------------------

    /// `like_contains` wraps the input in `%...%` and escapes every
    /// LIKE metacharacter, so user input is always matched literally
    /// (the pre-fix `/audit/approvals` built `format!("%{}%", input)`
    /// and let a searched `%` act as a wildcard).
    #[test]
    fn like_contains_escapes_all_wildcards(input in ".{0,24}") {
        let pattern = vauban_web::db::like_contains(&input);
        prop_assert!(pattern.starts_with('%'));
        prop_assert!(pattern.ends_with('%'));
        let inner = &pattern[1..pattern.len() - 1];
        // Decode: every %, _ and \ must be preceded by the escape
        // char; decoding must reproduce the input exactly.
        let mut decoded = String::new();
        let mut chars = inner.chars();
        while let Some(c) = chars.next() {
            if c == '\\' {
                let escaped = chars.next();
                prop_assert!(matches!(escaped, Some('%') | Some('_') | Some('\\')));
                if let Some(e) = escaped {
                    decoded.push(e);
                }
            } else {
                prop_assert!(c != '%' && c != '_');
                decoded.push(c);
            }
        }
        prop_assert_eq!(decoded, input);
    }
}
