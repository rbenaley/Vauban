//! Property tests for filter combination subset semantics.

use proptest::prelude::*;

#[derive(Clone, Debug)]
struct FakeDoc {
    title: String,
    category: String,
    status: String,
}

fn apply_filters(docs: &[FakeDoc], q: &str, cat: &str) -> Vec<FakeDoc> {
    docs.iter()
        .filter(|d| d.status == "PUBLISHED")
        .filter(|d| cat.is_empty() || d.category.eq_ignore_ascii_case(cat))
        .filter(|d| q.is_empty() || d.title.to_lowercase().contains(&q.to_lowercase()))
        .cloned()
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn prop_filters_return_subset(
        q in "[a-z]{0,6}",
        cat in prop_oneof!["", "API", "Security"],
    ) {
        let catalog = vec![
            FakeDoc { title: "api guide".into(), category: "API".into(), status: "PUBLISHED".into() },
            FakeDoc { title: "draft only".into(), category: "API".into(), status: "DRAFT".into() },
            FakeDoc { title: "security hard".into(), category: "Security".into(), status: "PUBLISHED".into() },
        ];
        let filtered = apply_filters(&catalog, &q, &cat);
        prop_assert!(filtered.len() <= catalog.iter().filter(|d| d.status == "PUBLISHED").count());
        for d in &filtered {
            prop_assert_eq!(&d.status, "PUBLISHED");
            if !cat.is_empty() {
                prop_assert!(d.category.eq_ignore_ascii_case(&cat));
            }
            if !q.is_empty() {
                prop_assert!(d.title.to_lowercase().contains(&q.to_lowercase()));
            }
        }
    }
}
