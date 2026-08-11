//! Issue ↔ tenant image liaisons (`issue_attachments`).
//!
//! Blobs live in the storage helper; this module only manages Postgres join
//! rows. Attach caps are **per comment** (config
//! `[issues].max_attachments_per_comment`). Published attachments are not
//! unlinked from the portal UI.

use toasty::Db;

use crate::{
    db::now_unix,
    models::IssueAttachment,
    storage::{
        StorageClient, find_image_object, is_uuid_key, normalize_image_ext, put_tenant_image,
        sniff_image,
    },
};

/// Soft ceiling when loading all attachments for one issue page.
pub fn issue_attachment_list_limit(max_per_comment: usize) -> usize {
    max_per_comment.saturating_mul(64).clamp(16, 256)
}

/// Picker copy for the per-message cap (compose + reply share one wording).
pub fn attachment_cap_hint(max_per_comment: usize) -> String {
    let max = max_per_comment.max(1);
    if max == 1 {
        "PNG, JPEG or WebP · drag & drop or browse · 1 screenshot per message".to_owned()
    } else {
        format!("PNG, JPEG or WebP · drag & drop or browse · up to {max} screenshots per message")
    }
}

/// One screenshot taken from a multipart form field.
#[derive(Debug, Clone)]
pub struct ScreenshotUpload {
    pub bytes: Vec<u8>,
    pub ext: &'static str,
}

/// Build a screenshot upload from a multipart part (None if empty / unsupported).
///
/// Ext resolution order: filename → `Content-Type` → magic-byte sniff.
pub fn screenshot_from_part(
    file_name: &str,
    content_type: Option<&str>,
    bytes: Vec<u8>,
) -> Option<ScreenshotUpload> {
    if bytes.is_empty() {
        return None;
    }
    let ext = file_name
        .rsplit_once('.')
        .and_then(|(_, e)| normalize_image_ext(e))
        .or_else(|| {
            content_type.and_then(|ct| match ct.split(';').next().unwrap_or("").trim() {
                "image/png" => Some("png"),
                "image/jpeg" | "image/jpg" => Some("jpeg"),
                "image/webp" => Some("webp"),
                _ => None,
            })
        })
        .or_else(|| sniff_image(&bytes).map(|k| k.ext()))?;
    Some(ScreenshotUpload { bytes, ext })
}

/// Parsed attachment token: `{uuid}.{ext}` (normalized ext).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentToken {
    pub image_id: String,
    pub ext: &'static str,
}

impl AttachmentToken {
    pub fn as_filename(&self) -> String {
        format!("{}.{}", self.image_id, self.ext)
    }
}

/// Why attach / validate failed (fail-closed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttachError {
    /// Token shape invalid (non-uuid, bad ext, empty).
    BadToken,
    /// Image not in `storage_objects` for this org (unknown / cross-tenant).
    UnknownImage,
    /// Existing + new would exceed the per-comment cap.
    CapExceeded,
    /// Database write / read failure.
    Db(String),
}

impl std::fmt::Display for AttachError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadToken => write!(f, "bad attachment token"),
            Self::UnknownImage => write!(f, "unknown image"),
            Self::CapExceeded => write!(f, "attachment cap exceeded"),
            Self::Db(msg) => write!(f, "db: {msg}"),
        }
    }
}

/// Parse `uuid.ext` into a normalized token (`jpg` → `jpeg`).
pub fn parse_attachment_token(raw: &str) -> Option<AttachmentToken> {
    let raw = raw.trim();
    if raw.is_empty() || raw.contains('/') || raw.contains('\\') || raw.contains('\0') {
        return None;
    }
    let (id, ext) = raw.rsplit_once('.')?;
    if !is_uuid_key(id) {
        return None;
    }
    let ext = normalize_image_ext(ext)?;
    Some(AttachmentToken {
        image_id: id.to_ascii_lowercase(),
        ext,
    })
}

/// List attachments for an issue in this org — indexed `issue_id` + limit.
pub async fn list_for_issue(
    db: &mut Db,
    org_id: u64,
    issue_id: u64,
    list_limit: usize,
) -> Result<Vec<IssueAttachment>, AttachError> {
    let limit = list_limit.max(1);
    let mut rows = IssueAttachment::all()
        .filter(IssueAttachment::fields().issue_id().eq(issue_id))
        .filter(IssueAttachment::fields().organization_id().eq(org_id))
        .order_by(IssueAttachment::fields().sort_order().asc())
        .limit(limit)
        .exec(db)
        .await
        .map_err(|e| AttachError::Db(e.to_string()))?;
    rows.truncate(limit);
    Ok(rows)
}

/// Count attachments for one comment on an issue (O(k) with k ≤ cap).
pub async fn count_for_comment(
    db: &mut Db,
    org_id: u64,
    issue_id: u64,
    comment_id: u64,
    max_per_comment: usize,
) -> Result<usize, AttachError> {
    let cap = max_per_comment.max(1);
    let rows = IssueAttachment::all()
        .filter(IssueAttachment::fields().issue_id().eq(issue_id))
        .filter(IssueAttachment::fields().organization_id().eq(org_id))
        .filter(IssueAttachment::fields().issue_comment_id().eq(comment_id))
        .limit(cap.saturating_add(1))
        .exec(db)
        .await
        .map_err(|e| AttachError::Db(e.to_string()))?;
    Ok(rows.len())
}

/// Attachments belonging to one comment (or opener).
pub fn for_comment(attachments: &[IssueAttachment], comment_id: u64) -> Vec<&IssueAttachment> {
    attachments
        .iter()
        .filter(|a| a.issue_comment_id == comment_id)
        .collect()
}

/// Store multipart screenshots via the helper (cap `max_per_comment`).
/// Returns `{uuid}.{ext}` tokens for [`attach_many`].
pub async fn store_screenshot_uploads(
    db: &mut Db,
    client: &StorageClient,
    org_id: u64,
    files: &[ScreenshotUpload],
    max_per_comment: usize,
) -> Result<Vec<String>, AttachError> {
    if files.len() > max_per_comment.max(1) {
        return Err(AttachError::CapExceeded);
    }
    let mut tokens = Vec::with_capacity(files.len());
    for file in files {
        let token = put_tenant_image(db, client, org_id, &file.bytes, file.ext)
            .await
            .map_err(|e| AttachError::Db(e.to_string()))?;
        tokens.push(token);
    }
    Ok(tokens)
}

/// Validate tokens against `storage_objects` for **this** org (O(k) point lookups).
pub async fn validate_tokens(
    db: &mut Db,
    org_id: u64,
    raw_tokens: &[String],
    max_per_comment: usize,
) -> Result<Vec<AttachmentToken>, AttachError> {
    if raw_tokens.is_empty() {
        return Ok(Vec::new());
    }
    let cap = max_per_comment.max(1);
    if raw_tokens.len() > cap {
        return Err(AttachError::CapExceeded);
    }
    let mut out = Vec::with_capacity(raw_tokens.len());
    let mut seen = Vec::with_capacity(raw_tokens.len());
    for raw in raw_tokens {
        let Some(token) = parse_attachment_token(raw) else {
            return Err(AttachError::BadToken);
        };
        if seen.iter().any(|id: &String| id == &token.image_id) {
            continue;
        }
        let Some(obj) = find_image_object(db, org_id, &token.image_id, token.ext).await else {
            return Err(AttachError::UnknownImage);
        };
        if obj.organization_id != org_id {
            return Err(AttachError::UnknownImage);
        }
        seen.push(token.image_id.clone());
        out.push(token);
    }
    if out.len() > cap {
        return Err(AttachError::CapExceeded);
    }
    Ok(out)
}

/// Attach validated tokens to an issue comment (or opener). Counts **existing
/// rows for that comment** toward `max_per_comment`.
pub async fn attach_many(
    db: &mut Db,
    org_id: u64,
    issue_id: u64,
    comment_id: u64,
    user_id: u64,
    raw_tokens: &[String],
    max_per_comment: usize,
) -> Result<usize, AttachError> {
    if raw_tokens.is_empty() {
        return Ok(0);
    }
    let cap = max_per_comment.max(1);
    let tokens = validate_tokens(db, org_id, raw_tokens, cap).await?;
    let now = now_unix();
    let mut inserted = 0usize;
    for token in tokens {
        let on_comment = count_for_comment(db, org_id, issue_id, comment_id, cap).await?;
        let issue_rows =
            list_for_issue(db, org_id, issue_id, issue_attachment_list_limit(cap)).await?;
        if issue_rows.iter().any(|e| e.image_id == token.image_id) {
            continue;
        }
        if on_comment >= cap {
            return Err(AttachError::CapExceeded);
        }
        let sort_order = issue_rows
            .iter()
            .map(|r| r.sort_order)
            .max()
            .map(|m| m + 1)
            .unwrap_or(0);
        toasty::create!(IssueAttachment {
            issue_id,
            organization_id: org_id,
            issue_comment_id: comment_id,
            image_id: token.image_id.clone(),
            ext: token.ext.to_owned(),
            uploaded_by_user_id: user_id,
            created_at: now,
            sort_order,
        })
        .exec(db)
        .await
        .map_err(|e| AttachError::Db(e.to_string()))?;
        inserted += 1;
    }
    Ok(inserted)
}

/// First-party gallery `src` path for an attachment.
pub fn gallery_src(org_slug: &str, att: &IssueAttachment) -> String {
    format!("/{}/images/{}.{}", org_slug, att.image_id, att.ext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ISSUE_ATTACHMENT_OPENER_COMMENT_ID;

    #[test]
    fn parse_accepts_canonical_tokens() {
        let t = parse_attachment_token("550e8400-e29b-41d4-a716-446655440000.png").unwrap();
        assert_eq!(t.image_id, "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(t.ext, "png");
        assert_eq!(t.as_filename(), "550e8400-e29b-41d4-a716-446655440000.png");
    }

    #[test]
    fn parse_normalizes_jpg() {
        let t = parse_attachment_token("550e8400-e29b-41d4-a716-446655440000.JPG").unwrap();
        assert_eq!(t.ext, "jpeg");
    }

    #[test]
    fn parse_rejects_bad_tokens() {
        assert!(parse_attachment_token("").is_none());
        assert!(parse_attachment_token("not-a-uuid.png").is_none());
        assert!(parse_attachment_token("550e8400-e29b-41d4-a716-446655440000.svg").is_none());
        assert!(parse_attachment_token("../550e8400-e29b-41d4-a716-446655440000.png").is_none());
        assert!(parse_attachment_token("550e8400-e29b-41d4-a716-446655440000").is_none());
        assert!(parse_attachment_token("550e8400e29b41d4a716446655440000.png").is_none());
    }

    #[test]
    fn screenshot_from_part_uses_filename_ctype_and_sniff() {
        let png = [
            0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n', 0, 0, 0, 0,
        ];
        let by_name = screenshot_from_part("shot.PNG", None, png.to_vec()).unwrap();
        assert_eq!(by_name.ext, "png");
        let by_ct =
            screenshot_from_part("", Some("image/jpeg"), vec![0xff, 0xd8, 0xff, 0x01]).unwrap();
        assert_eq!(by_ct.ext, "jpeg");
        let by_sniff = screenshot_from_part("", None, png.to_vec()).unwrap();
        assert_eq!(by_sniff.ext, "png");
        assert!(screenshot_from_part("", None, b"not-an-image".to_vec()).is_none());
        assert!(screenshot_from_part("x.png", None, vec![]).is_none());
    }

    #[test]
    fn default_cap_is_five() {
        assert_eq!(crate::models::DEFAULT_MAX_ATTACHMENTS_PER_COMMENT, 5);
        assert_eq!(issue_attachment_list_limit(5), 256);
    }

    #[test]
    fn cap_hint_states_the_cap_and_formats() {
        let five = attachment_cap_hint(5);
        assert!(five.contains('5'), "hint must state the cap: {five}");
        assert!(five.contains("PNG") && five.contains("WebP"));
        assert!(five.contains("screenshots"), "plural above one: {five}");
        assert!(
            five.contains("drag") && five.contains("browse"),
            "hint must mention drag & drop: {five}"
        );
        let one = attachment_cap_hint(1);
        assert!(one.contains("1 screenshot per"), "singular at one: {one}");
        // A misconfigured 0 must never advertise "up to 0".
        assert_eq!(attachment_cap_hint(0), one);
    }

    #[test]
    fn for_comment_filters_opener_and_reply() {
        let a = IssueAttachment {
            id: 1,
            issue_id: 2,
            organization_id: 3,
            issue_comment_id: ISSUE_ATTACHMENT_OPENER_COMMENT_ID,
            image_id: "550e8400-e29b-41d4-a716-446655440000".into(),
            ext: "png".into(),
            uploaded_by_user_id: 4,
            created_at: 0,
            sort_order: 0,
        };
        let b = IssueAttachment {
            id: 2,
            issue_comment_id: 99,
            image_id: "550e8400-e29b-41d4-a716-446655440001".into(),
            sort_order: 1,
            ..a.clone()
        };
        let rows = [a, b];
        assert_eq!(
            for_comment(&rows, ISSUE_ATTACHMENT_OPENER_COMMENT_ID).len(),
            1
        );
        assert_eq!(for_comment(&rows, 99).len(), 1);
        assert!(for_comment(&rows, 7).is_empty());
    }

    #[test]
    fn gallery_src_is_first_party() {
        let att = IssueAttachment {
            id: 1,
            issue_id: 2,
            organization_id: 3,
            issue_comment_id: ISSUE_ATTACHMENT_OPENER_COMMENT_ID,
            image_id: "550e8400-e29b-41d4-a716-446655440000".into(),
            ext: "png".into(),
            uploaded_by_user_id: 4,
            created_at: 0,
            sort_order: 0,
        };
        assert_eq!(
            gallery_src("acme", &att),
            "/acme/images/550e8400-e29b-41d4-a716-446655440000.png"
        );
    }
}
