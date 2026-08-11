//! Entitlement-gated release artifact download via the storage helper.

use std::io::Read;

use serde::Deserialize;
use topcoat::{
    Result,
    context::Cx,
    router::{
        Body, Response, StatusCode,
        content::Form,
        error::{forbidden, not_found},
        header, path_param, route,
    },
};

use super::find_visible_release_by_version;
use super::release_ver::ReleaseVer;
use crate::{
    app::org::Org,
    auth::{db, require_org, storage},
    list_page::href_with_query,
    perms::perms_for_user,
    release_pkg::{org_builds_entitled, package_file_name},
    storage::find_release_object,
};

/// Artifact routes return this when the helper is unavailable.
pub const DOWNLOAD_UNAVAILABLE: &str = "download unavailable";
/// Stable body when mirror/SoT/disk digests disagree.
pub const INTEGRITY_MISMATCH: &str = "integrity mismatch";

/// Query key carrying a [`DlError`] code back to the Builds page.
pub const DL_ERROR_PARAM: &str = "dl_error";

/// Why the session download could not be served.
///
/// The POST redirects back to Builds with [`DlError::as_code`]; the page maps
/// the code to modal copy. Raw query text is never echoed into HTML.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DlError {
    /// Release is visible but carries no artifact yet.
    Missing,
    /// Helper unreachable or the blob could not be read.
    Unavailable,
    /// Mirror / SoT / disk digests disagree.
    Integrity,
}

impl DlError {
    pub fn as_code(self) -> &'static str {
        match self {
            DlError::Missing => "missing",
            DlError::Unavailable => "unavailable",
            DlError::Integrity => "integrity",
        }
    }

    pub fn from_code(code: &str) -> Option<Self> {
        match code {
            "missing" => Some(DlError::Missing),
            "unavailable" => Some(DlError::Unavailable),
            "integrity" => Some(DlError::Integrity),
            _ => None,
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            DlError::Missing => "Package not available",
            DlError::Unavailable => "Download unavailable",
            DlError::Integrity => "Signature check failed",
        }
    }

    /// Modal copy, one line per paragraph: what happened, then what to do.
    pub fn message_lines(self) -> [&'static str; 2] {
        match self {
            DlError::Missing => [
                "No signed package is attached to this build yet.",
                "Contact Vauban Support if you expected one.",
            ],
            DlError::Unavailable => [
                "The artifact service is temporarily unavailable.",
                "Your entitlement is unchanged - try again later.",
            ],
            DlError::Integrity => [
                "This package failed its signature check and was not served.",
                "Vauban Support has been alerted.",
            ],
        }
    }
}

#[derive(Debug, Deserialize)]
struct DlRedirectForm {
    channel: Option<String>,
}

/// Builds URL that reopens the release row and asks the page for a modal.
pub fn download_error_href(org: &str, ver: &str, channel: &str, err: DlError) -> String {
    let mut parts = Vec::with_capacity(2);
    let channel = channel.trim();
    if !channel.is_empty() {
        parts.push(format!("channel={channel}"));
    }
    parts.push(format!("{DL_ERROR_PARAM}={}", err.as_code()));
    href_with_query(&format!("/{org}/builds/{ver}"), &parts)
}

/// Stay on Builds: PRG back to the open row so the page can raise the modal.
fn redirect_with_error(org: &str, ver: &str, channel: &str, err: DlError) -> Result<Response> {
    Ok(Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(
            header::LOCATION,
            download_error_href(org, ver, channel, err),
        )
        .body(Body::from(""))?)
}

#[route(POST "/{org}/builds/{release_ver}/download")]
async fn builds_download(cx: &Cx, Form(form): Form<DlRedirectForm>) -> Result<Response> {
    let org_slug = path_param::<Org>(cx);
    let ver = path_param::<ReleaseVer>(cx);
    let ctx = require_org(cx, org_slug).await.map_err(|_| not_found())?;
    let perms = perms_for_user(cx, &ctx.user).await;
    if !perms.builds_download {
        return Err(forbidden().into());
    }
    let lts = ctx.org.lts_subscriptions;
    let industrial = ctx.org.industrial_lts_subscriptions;
    if !org_builds_entitled(org_slug, lts, industrial) {
        return Err(not_found().into());
    }

    let channel = form.channel.as_deref().map(str::trim).unwrap_or_default();
    let ver_key = ver.to_string();
    let mut database = db(cx);
    let Some(rel) = find_visible_release_by_version(
        &mut database,
        &ver_key,
        ctx.org.id,
        org_slug,
        lts,
        industrial,
    )
    .await
    else {
        return Err(not_found().into());
    };

    let Some(obj) = find_release_object(&mut database, rel.id).await else {
        return redirect_with_error(org_slug, ver, channel, DlError::Missing);
    };

    let client = storage(cx);
    let (size, _sha, mut file) = match client.get_release(rel.id, &obj.sha256) {
        Ok(v) => v,
        Err(e) => {
            let err = if e.code == crate::storage::StorageErrorCode::IntegrityMismatch {
                DlError::Integrity
            } else {
                DlError::Unavailable
            };
            return redirect_with_error(org_slug, ver, channel, err);
        }
    };

    let mut bytes = Vec::with_capacity(size.min(64 * 1024 * 1024) as usize);
    if file.read_to_end(&mut bytes).is_err() {
        return redirect_with_error(org_slug, ver, channel, DlError::Unavailable);
    }

    let filename = package_file_name(&rel.version, &rel.channel);
    let disposition = format!("attachment; filename=\"{filename}\"");
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_DISPOSITION, disposition)
        .header(header::CONTENT_LENGTH, bytes.len().to_string())
        .header("X-Content-Type-Options", "nosniff")
        .body(Body::from(bytes))?)
}

#[cfg(test)]
mod tests {
    use super::{DL_ERROR_PARAM, DOWNLOAD_UNAVAILABLE, DlError, download_error_href};

    const ALL: [DlError; 3] = [DlError::Missing, DlError::Unavailable, DlError::Integrity];

    #[test]
    fn error_href_omits_empty_channel() {
        assert_eq!(
            download_error_href("acme", "v1.0.0", "", DlError::Unavailable),
            "/acme/builds/v1.0.0?dl_error=unavailable"
        );
        assert_eq!(
            download_error_href("acme", "v1.0.0", "  ", DlError::Missing),
            "/acme/builds/v1.0.0?dl_error=missing"
        );
    }

    #[test]
    fn error_href_keeps_channel_filter() {
        let href = download_error_href("acme", "v0.8.6-acme1", "Stable", DlError::Integrity);
        assert_eq!(
            href,
            "/acme/builds/v0.8.6-acme1?channel=Stable&dl_error=integrity"
        );
        assert_eq!(href.matches('?').count(), 1);
        assert_eq!(href.matches(DL_ERROR_PARAM).count(), 1);
    }

    #[test]
    fn code_round_trips_and_rejects_unknown() {
        for err in ALL {
            assert_eq!(DlError::from_code(err.as_code()), Some(err));
        }
        assert_eq!(DlError::from_code("boom"), None);
        assert_eq!(DlError::from_code(""), None);
        assert_eq!(DlError::from_code("<script>"), None);
    }

    #[test]
    fn copy_is_ascii_and_non_empty() {
        for err in ALL {
            assert!(!err.title().is_empty());
            assert!(err.title().is_ascii(), "title must stay ASCII");
            for line in err.message_lines() {
                assert!(!line.trim().is_empty());
                assert!(line.is_ascii(), "message must stay ASCII");
                assert!(
                    !line.contains('\n'),
                    "each line is its own paragraph; no raw newline"
                );
            }
        }
        // Helper text stays lowercase for the machine-facing ephemeral route.
        assert_eq!(DOWNLOAD_UNAVAILABLE, "download unavailable");
    }
}
