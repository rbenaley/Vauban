//! Markdown + YAML-frontmatter bundle for DocArticle export/import (ops CLI).

use std::fs;
use std::path::{Path, PathBuf};

use toasty::Db;

use crate::db::now_unix;
use crate::docs_version::unpublish_other_published;
use crate::models::{DOC_CATEGORIES, DOC_STATUS_DRAFT, DOC_STATUS_PUBLISHED, DocArticle};

/// One article ready to write or loaded from a bundle file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundledArticle {
    pub title: String,
    pub slug: String,
    pub summary: String,
    pub category: String,
    pub status: String,
    pub version: String,
    /// Body after the closing frontmatter fence (trailing whitespace stripped).
    pub body: String,
}

/// Counts from a successful export.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExportReport {
    pub exported: usize,
}

/// Counts from a successful import.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ImportReport {
    pub created: usize,
    pub updated: usize,
}

/// Bundle file name: `{slug}__{version}.md`.
pub fn bundle_filename(slug: &str, version: &str) -> String {
    format!("{slug}__{version}.md")
}

/// Escape a scalar for a single-line YAML value (double-quoted when needed).
pub fn yaml_escape(value: &str) -> String {
    if value.is_empty() {
        return "\"\"".to_owned();
    }
    let needs_quote = value.chars().any(|c| {
        matches!(
            c,
            ':' | '#'
                | '{'
                | '}'
                | '['
                | ']'
                | ','
                | '&'
                | '*'
                | '!'
                | '|'
                | '>'
                | '\''
                | '"'
                | '%'
                | '@'
                | '`'
                | '\n'
                | '\r'
                | '\t'
        ) || c.is_whitespace()
            && (value.starts_with(char::is_whitespace) || value.ends_with(char::is_whitespace))
    }) || value.starts_with(['-', '?', ':', '@', '`'])
        || value.contains(": ")
        || value.contains('#');

    if !needs_quote && !value.contains('"') && !value.contains('\\') {
        // Also quote if leading/trailing space or looks like bool/null.
        let lower = value.to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "true" | "false" | "null" | "yes" | "no" | "on" | "off"
        ) {
            return format!("\"{value}\"");
        }
        return value.to_owned();
    }

    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

fn yaml_unescape(raw: &str) -> Result<String, String> {
    let s = raw.trim();
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        let inner = &s[1..s.len() - 1];
        let mut out = String::with_capacity(inner.len());
        let mut chars = inner.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\\' {
                match chars.next() {
                    Some('\\') => out.push('\\'),
                    Some('"') => out.push('"'),
                    Some('n') => out.push('\n'),
                    Some('r') => out.push('\r'),
                    Some('t') => out.push('\t'),
                    Some(other) => {
                        out.push('\\');
                        out.push(other);
                    }
                    None => return Err("unterminated escape in YAML string".to_owned()),
                }
            } else {
                out.push(c);
            }
        }
        Ok(out)
    } else if s.len() >= 2 && s.starts_with('\'') && s.ends_with('\'') {
        Ok(s[1..s.len() - 1].replace("''", "'"))
    } else {
        Ok(s.to_owned())
    }
}

/// Serialize a bundled article to Markdown + frontmatter.
pub fn serialize_markdown(article: &BundledArticle) -> String {
    let mut out = String::new();
    out.push_str("---\n");
    out.push_str(&format!("title: {}\n", yaml_escape(&article.title)));
    out.push_str(&format!("slug: {}\n", yaml_escape(&article.slug)));
    out.push_str(&format!("summary: {}\n", yaml_escape(&article.summary)));
    out.push_str(&format!("category: {}\n", yaml_escape(&article.category)));
    out.push_str(&format!("status: {}\n", yaml_escape(&article.status)));
    out.push_str(&format!("version: {}\n", yaml_escape(&article.version)));
    out.push_str("---\n");
    if !article.body.is_empty() {
        out.push('\n');
        out.push_str(article.body.trim_end());
        out.push('\n');
    }
    out
}

/// Parse Markdown + frontmatter into a [`BundledArticle`].
pub fn parse_markdown(src: &str) -> Result<BundledArticle, String> {
    let text = src.replace("\r\n", "\n");
    let rest = text
        .strip_prefix("---\n")
        .or_else(|| text.strip_prefix("---\r\n"))
        .ok_or_else(|| "missing opening --- frontmatter fence".to_owned())?;
    let close = rest
        .find("\n---\n")
        .ok_or_else(|| "missing closing --- frontmatter fence".to_owned())?;
    let yaml = &rest[..close];
    // Drop at most one conventional blank line after the closing fence;
    // preserve any further leading newlines in the body. Trailing whitespace
    // is stripped on both serialize and parse.
    let after = &rest[close + "\n---\n".len()..];
    let after = after.strip_prefix('\n').unwrap_or(after);
    let body = after.trim_end().to_owned();

    let mut title = None;
    let mut slug = None;
    let mut summary = None;
    let mut category = None;
    let mut status = None;
    let mut version = None;

    for (lineno, line) in yaml.lines().enumerate() {
        let line = line.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            return Err(format!(
                "frontmatter line {}: expected key: value",
                lineno + 1
            ));
        };
        let key = key.trim();
        let value = yaml_unescape(value.trim())?;
        match key {
            "title" => title = Some(value),
            "slug" => slug = Some(value),
            "summary" => summary = Some(value),
            "category" => category = Some(value),
            "status" => status = Some(value),
            "version" => version = Some(value),
            other => return Err(format!("unknown frontmatter key `{other}`")),
        }
    }

    let article = BundledArticle {
        title: title.ok_or_else(|| "missing frontmatter key `title`".to_owned())?,
        slug: slug.ok_or_else(|| "missing frontmatter key `slug`".to_owned())?,
        summary: summary.unwrap_or_default(),
        category: category.ok_or_else(|| "missing frontmatter key `category`".to_owned())?,
        status: status.ok_or_else(|| "missing frontmatter key `status`".to_owned())?,
        version: version.ok_or_else(|| "missing frontmatter key `version`".to_owned())?,
        body,
    };
    validate_article(&article)?;
    Ok(article)
}

/// Validate category, status, and required non-empty fields.
pub fn validate_article(article: &BundledArticle) -> Result<(), String> {
    if article.title.trim().is_empty() {
        return Err("title must not be empty".to_owned());
    }
    if article.slug.trim().is_empty() {
        return Err("slug must not be empty".to_owned());
    }
    if article.version.trim().is_empty() {
        return Err("version must not be empty".to_owned());
    }
    if article.slug.contains('/') || article.slug.contains('\\') || article.slug.contains("..") {
        return Err("slug must not contain path separators".to_owned());
    }
    if article.version.contains('/') || article.version.contains('\\') {
        return Err("version must not contain path separators".to_owned());
    }
    if !DOC_CATEGORIES
        .iter()
        .any(|c| c.eq_ignore_ascii_case(article.category.trim()))
    {
        return Err(format!(
            "unknown category `{}` (expected one of {})",
            article.category,
            DOC_CATEGORIES.join(", ")
        ));
    }
    // Normalize category to canonical catalogue spelling.
    let _ = canonical_category(&article.category)?;
    if !article.status.eq_ignore_ascii_case(DOC_STATUS_DRAFT)
        && !article.status.eq_ignore_ascii_case(DOC_STATUS_PUBLISHED)
    {
        return Err(format!(
            "status must be {DOC_STATUS_DRAFT} or {DOC_STATUS_PUBLISHED}"
        ));
    }
    Ok(())
}

fn canonical_category(raw: &str) -> Result<&'static str, String> {
    DOC_CATEGORIES
        .iter()
        .find(|c| c.eq_ignore_ascii_case(raw.trim()))
        .copied()
        .ok_or_else(|| format!("unknown category `{raw}`"))
}

fn canonical_status(raw: &str) -> Result<&'static str, String> {
    if raw.eq_ignore_ascii_case(DOC_STATUS_PUBLISHED) {
        Ok(DOC_STATUS_PUBLISHED)
    } else if raw.eq_ignore_ascii_case(DOC_STATUS_DRAFT) {
        Ok(DOC_STATUS_DRAFT)
    } else {
        Err(format!("invalid status `{raw}`"))
    }
}

fn ensure_export_dir(dir: &Path) -> anyhow::Result<()> {
    if dir.exists() {
        if !dir.is_dir() {
            anyhow::bail!(
                "export path exists and is not a directory: {}",
                dir.display()
            );
        }
        let mut entries = fs::read_dir(dir)?;
        if entries.next().is_some() {
            anyhow::bail!(
                "export directory is not empty (refusing to mix bundles): {}",
                dir.display()
            );
        }
    } else {
        fs::create_dir_all(dir)?;
    }
    Ok(())
}

/// Load all articles (with body) and write one Markdown file each.
pub async fn export_articles_to_dir(db: &Db, dir: &Path) -> anyhow::Result<ExportReport> {
    ensure_export_dir(dir)?;
    let mut conn = db.clone();
    let rows = DocArticle::all()
        .include(DocArticle::fields().body())
        .exec(&mut conn)
        .await?;

    let mut exported = 0usize;
    for row in rows {
        let category = canonical_category(&row.category).unwrap_or(row.category.as_str());
        let status = canonical_status(&row.status).unwrap_or(row.status.as_str());
        let article = BundledArticle {
            title: row.title.clone(),
            slug: row.slug.clone(),
            summary: row.summary.clone(),
            category: category.to_owned(),
            status: status.to_owned(),
            version: row.version.clone(),
            body: row.body.get().clone(),
        };
        validate_article(&article).map_err(|e| {
            anyhow::anyhow!(
                "cannot export slug={} version={}: {e}",
                article.slug,
                article.version
            )
        })?;
        let name = bundle_filename(&article.slug, &article.version);
        let path = dir.join(&name);
        if path
            .file_name()
            .and_then(|s| s.to_str())
            .is_none_or(|s| s != name)
        {
            anyhow::bail!("refusing unsafe bundle filename for {}", name);
        }
        fs::write(&path, serialize_markdown(&article))?;
        exported += 1;
    }
    Ok(ExportReport { exported })
}

/// Import all `*.md` files from `dir` (fail-fast on first error).
pub async fn import_articles_from_dir(db: &Db, dir: &Path) -> anyhow::Result<ImportReport> {
    if !dir.is_dir() {
        anyhow::bail!("import path is not a directory: {}", dir.display());
    }
    let mut paths: Vec<PathBuf> = fs::read_dir(dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("md"))
        .collect();
    paths.sort();

    if paths.is_empty() {
        anyhow::bail!("no .md files found in {}", dir.display());
    }

    let mut report = ImportReport::default();
    let mut conn = db.clone();
    for path in paths {
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("(unknown)")
            .to_owned();
        let text = fs::read_to_string(&path).map_err(|e| anyhow::anyhow!("read {name}: {e}"))?;
        let mut article =
            parse_markdown(&text).map_err(|e| anyhow::anyhow!("parse {name}: {e}"))?;
        let category = canonical_category(&article.category)
            .map_err(|e| anyhow::anyhow!("parse {name}: {e}"))?;
        let status =
            canonical_status(&article.status).map_err(|e| anyhow::anyhow!("parse {name}: {e}"))?;
        article.category = category.to_owned();
        article.status = status.to_owned();

        let existing = DocArticle::all()
            .filter(DocArticle::fields().slug().eq(&article.slug))
            .filter(DocArticle::fields().version().eq(&article.version))
            .limit(1)
            .include(DocArticle::fields().body())
            .exec(&mut conn)
            .await?;

        let now = now_unix();
        if let Some(mut row) = existing.into_iter().next() {
            let row_id = row.id;
            row.update()
                .title(article.title.clone())
                .summary(article.summary.clone())
                .category(article.category.clone())
                .status(article.status.clone())
                .body(article.body.clone())
                .updated_at(now)
                .exec(&mut conn)
                .await?;
            if article.status == DOC_STATUS_PUBLISHED {
                unpublish_other_published(&mut conn, &article.slug, row_id).await?;
            }
            report.updated += 1;
        } else {
            let created = toasty::create!(DocArticle {
                title: article.title.clone(),
                summary: article.summary.clone(),
                category: article.category.clone(),
                slug: article.slug.clone(),
                version: article.version.clone(),
                status: article.status.clone(),
                body: article.body.clone(),
                updated_at: now,
            })
            .exec(&mut conn)
            .await?;
            if article.status == DOC_STATUS_PUBLISHED {
                unpublish_other_published(&mut conn, &article.slug, created.id).await?;
            }
            report.created += 1;
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> BundledArticle {
        BundledArticle {
            title: "Prefer config".to_owned(),
            slug: "prefer-config".to_owned(),
            summary: "One line".to_owned(),
            category: "API".to_owned(),
            status: DOC_STATUS_PUBLISHED.to_owned(),
            version: "v1".to_owned(),
            body: "Prefer `config/` over workspace.\n\n## Details".to_owned(),
        }
    }

    #[test]
    fn bundle_filename_shape() {
        assert_eq!(
            bundle_filename("prefer-config", "v2"),
            "prefer-config__v2.md"
        );
    }

    #[test]
    fn serialize_parse_round_trip() {
        let a = sample();
        let md = serialize_markdown(&a);
        let b = parse_markdown(&md).expect("parse");
        assert_eq!(b, a);
    }

    #[test]
    fn serialize_parse_preserves_leading_body_newline() {
        let mut a = sample();
        a.body = "\n0".to_owned();
        let md = serialize_markdown(&a);
        let b = parse_markdown(&md).expect("parse");
        assert_eq!(b.body, "\n0");
    }

    #[test]
    fn parse_rejects_unknown_category() {
        let mut a = sample();
        a.category = "NotACat".to_owned();
        let md = serialize_markdown(&a);
        let err = parse_markdown(&md).unwrap_err();
        assert!(err.contains("unknown category"), "{err}");
    }

    #[test]
    fn parse_rejects_bad_status() {
        let md = "---\ntitle: T\nslug: s\nsummary: \ncategory: API\nstatus: LIVE\nversion: v1\n---\n\nbody\n";
        let err = parse_markdown(md).unwrap_err();
        assert!(err.contains("status"), "{err}");
    }

    #[test]
    fn yaml_escape_handles_colon_and_quotes() {
        let a = BundledArticle {
            title: r#"Say: "hi""#.to_owned(),
            slug: "say-hi".to_owned(),
            summary: String::new(),
            category: "Security".to_owned(),
            status: DOC_STATUS_DRAFT.to_owned(),
            version: "v1".to_owned(),
            body: "x".to_owned(),
        };
        let md = serialize_markdown(&a);
        let b = parse_markdown(&md).expect("parse");
        assert_eq!(b.title, a.title);
        assert_eq!(b.summary, "");
    }

    #[test]
    fn validate_rejects_pathful_slug() {
        let mut a = sample();
        a.slug = "../evil".to_owned();
        assert!(validate_article(&a).is_err());
    }
}
