//! Pure helpers for admin companies list + live search shard.

/// Org fields considered by admin companies search.
pub struct CompanyMatchFields<'a> {
    pub name: &'a str,
    pub slug: &'a str,
    pub contact_name: &'a str,
    pub contact_email: &'a str,
    pub vat: &'a str,
    pub address: &'a str,
    pub emails: &'a [String],
}

/// Trim + lowercase search query.
pub fn normalize_query(q: &str) -> String {
    q.trim().to_lowercase()
}

/// Case-insensitive match against an already-normalized query.
///
/// Empty `q` matches everything. Fields: name, slug, technical contact name /
/// email, VAT, address, and membership account emails.
pub fn company_matches_query(q: &str, fields: &CompanyMatchFields<'_>) -> bool {
    if q.is_empty() {
        return true;
    }
    fields.name.to_lowercase().contains(q)
        || fields.slug.to_lowercase().contains(q)
        || fields.contact_name.to_lowercase().contains(q)
        || fields.contact_email.to_lowercase().contains(q)
        || fields.vat.to_lowercase().contains(q)
        || fields.address.to_lowercase().contains(q)
        || fields.emails.iter().any(|e| e.to_lowercase().contains(q))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn fields<'a>(
        name: &'a str,
        slug: &'a str,
        contact_name: &'a str,
        contact_email: &'a str,
        vat: &'a str,
        address: &'a str,
        emails: &'a [String],
    ) -> CompanyMatchFields<'a> {
        CompanyMatchFields {
            name,
            slug,
            contact_name,
            contact_email,
            vat,
            address,
            emails,
        }
    }

    #[test]
    fn companies_search_normalize_query_trims_and_lowercases() {
        assert_eq!(normalize_query("  Acme Corp  "), "acme corp");
        assert_eq!(normalize_query("   "), "");
    }

    #[test]
    fn companies_search_company_matches_query_fields() {
        let emails = vec!["ops@acme.example".to_owned()];
        let q = normalize_query("Acme");
        assert!(company_matches_query(
            &q,
            &fields("Acme Infrastructure", "other", "", "", "", "", &[])
        ));
        assert!(company_matches_query(
            &q,
            &fields("X", "acme-infra", "", "", "", "", &[])
        ));
        assert!(company_matches_query(
            &q,
            &fields("X", "y", "Acme Person", "", "", "", &[])
        ));
        assert!(company_matches_query(
            &q,
            &fields("X", "y", "", "acme@x.test", "", "", &[])
        ));
        assert!(company_matches_query(
            &q,
            &fields("X", "y", "", "", "FR ACME", "", &[])
        ));
        assert!(company_matches_query(
            &q,
            &fields("X", "y", "", "", "", "1 Acme St", &[])
        ));
        assert!(company_matches_query(
            &q,
            &fields("X", "y", "", "", "", "", &emails)
        ));
        assert!(!company_matches_query(
            &q,
            &fields("Beta", "beta", "", "", "", "", &[])
        ));
        assert!(company_matches_query(
            "",
            &fields("any", "thing", "", "", "", "", &[])
        ));
    }

    proptest! {
        #![proptest_config(crate::proptest_util::cases(48))]

        #[test]
        fn companies_search_prop_query_normalization_idempotent(
            raw in " *[A-Za-z0-9 -]{0,40} *"
        ) {
            let once = normalize_query(&raw);
            let twice = normalize_query(&once);
            prop_assert_eq!(&once, &twice);
            prop_assert!(!once.chars().any(|c| c.is_ascii_uppercase()));
            prop_assert_eq!(once.as_str(), once.trim());
        }

        #[test]
        fn companies_search_prop_match_case_insensitive(needle in "[A-Za-z]{3,10}") {
            let q = normalize_query(&needle);
            let name = needle.to_uppercase();
            prop_assert!(company_matches_query(
                &q,
                &fields(&name, "z", "", "", "", "", &[])
            ));
            prop_assert!(company_matches_query(
                &q,
                &fields("z", &name, "", "", "", "", &[])
            ));
            let email = format!("{needle}@example.com");
            prop_assert!(company_matches_query(
                &q,
                &fields("z", "z", "", "", "", "", &[email])
            ));
        }
    }
}
