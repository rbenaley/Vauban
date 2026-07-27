//! Doc article version bumping and publish exclusivity helpers.

use toasty::Db;

use crate::models::{DOC_STATUS_DRAFT, DOC_STATUS_PUBLISHED, DocArticle};

/// Concept type-delete confirm: user must type exactly `delete` (trimmed).
pub fn is_delete_confirm(text: &str) -> bool {
    text.trim() == "delete"
}

/// Bump `v1` -> `v2`, `v12` -> `v13`. Non-matching input becomes `v2`.
pub fn bump_version(current: &str) -> String {
    let trimmed = current.trim();
    let digits = trimmed
        .strip_prefix('v')
        .or_else(|| trimmed.strip_prefix('V'))
        .unwrap_or(trimmed);
    match digits.parse::<u32>() {
        Ok(n) => format!("v{}", n.saturating_add(1)),
        Err(_) => "v2".to_owned(),
    }
}

/// Set every PUBLISHED article with `slug` to DRAFT, except `except_id`.
pub async fn unpublish_other_published(
    db: &mut Db,
    slug: &str,
    except_id: u64,
) -> anyhow::Result<()> {
    let rows = DocArticle::all()
        .filter(DocArticle::fields().slug().eq(slug))
        .exec(db)
        .await?;
    let now = crate::db::now_unix();
    for mut article in rows {
        if article.id == except_id || article.status != DOC_STATUS_PUBLISHED {
            continue;
        }
        article
            .update()
            .status(DOC_STATUS_DRAFT.to_owned())
            .updated_at(now)
            .exec(db)
            .await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bump_version_increments() {
        assert_eq!(bump_version("v1"), "v2");
        assert_eq!(bump_version("v9"), "v10");
        assert_eq!(bump_version("V3"), "v4");
        assert_eq!(bump_version("1"), "v2");
        assert_eq!(bump_version("weird"), "v2");
        assert_eq!(bump_version(""), "v2");
    }

    #[test]
    fn delete_confirm_accepts_exact_delete() {
        assert!(is_delete_confirm("delete"));
        assert!(is_delete_confirm("  delete  "));
        assert!(!is_delete_confirm("Delete"));
        assert!(!is_delete_confirm(""));
        assert!(!is_delete_confirm("remove"));
    }
}
