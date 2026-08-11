//! Property tests for docs Markdown frontmatter round-trip.

use proptest::prelude::*;
use vcp::docs_bundle::{
    BundledArticle, parse_markdown, serialize_markdown, validate_article, yaml_escape,
};
use vcp::models::{DOC_CATEGORIES, DOC_STATUS_DRAFT, DOC_STATUS_PUBLISHED};

fn status_strategy() -> impl Strategy<Value = &'static str> {
    prop_oneof![Just(DOC_STATUS_DRAFT), Just(DOC_STATUS_PUBLISHED)]
}

fn category_strategy() -> impl Strategy<Value = &'static str> {
    prop::sample::select(DOC_CATEGORIES)
}

proptest! {
    #[test]
    fn prop_serialize_parse_round_trip(
        title in "[A-Za-z0-9 :\"'-]{1,48}",
        slug in "[a-z][a-z0-9-]{1,24}",
        summary in "([A-Za-z0-9 :\"'-]{0,40})",
        body in "([A-Za-z0-9 `\n#.:/-]{0,120})",
        version_n in 1u32..20,
        status in status_strategy(),
        category in category_strategy(),
    ) {
        let article = BundledArticle {
            title: title.clone(),
            slug: slug.clone(),
            summary: summary.clone(),
            category: category.to_owned(),
            status: status.to_owned(),
            version: format!("v{version_n}"),
            body: body.trim_end().to_owned(),
        };
        prop_assume!(validate_article(&article).is_ok());
        let md = serialize_markdown(&article);
        let parsed = parse_markdown(&md).expect("parse");
        prop_assert_eq!(&parsed.title, &article.title);
        prop_assert_eq!(&parsed.slug, &article.slug);
        prop_assert_eq!(&parsed.summary, &article.summary);
        prop_assert_eq!(&parsed.category, &article.category);
        prop_assert_eq!(&parsed.status, &article.status);
        prop_assert_eq!(&parsed.version, &article.version);
        prop_assert_eq!(&parsed.body, &article.body);
        let _ = yaml_escape(&title);
    }
}
