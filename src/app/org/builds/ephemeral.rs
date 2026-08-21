//! Server-issued ephemeral download links (POST/PRG; no client JS).

use serde::Deserialize;
use topcoat::{
    Result,
    context::Cx,
    router::{
        content::Form,
        error::{SeeOther, forbidden, not_found, see_other},
        href, path_param, route,
    },
};
use uuid::Uuid;

use super::find_visible_release_by_version;
use super::release_ver::ReleaseVer;
use crate::{
    app::org::Org,
    auth::{db, require_org},
    db::now_unix,
    models::{EPH_DOWNLOAD_TTL_SECS, EphemeralDownload, Release},
    perms::perms_for_user,
    release_pkg::org_builds_entitled,
    storage::find_release_object,
};

#[derive(Debug, Deserialize)]
struct EphRedirectForm {
    channel: Option<String>,
}

/// SSR view model for the open release's ephemeral panel.
#[derive(Debug, Clone)]
pub(super) struct EphPanel {
    pub url: String,
    /// Remaining seconds at render time (SSR label seed).
    pub remaining_secs: f64,
    /// Absolute unix expiry — client countdown syncs from `Date.now()` against this.
    pub expires_at: i64,
}

pub(crate) use crate::release_pkg::package_file_name;

pub(super) fn eph_public_url(
    public_origin: &str,
    token: &str,
    version: &str,
    channel: &str,
) -> String {
    format!(
        "{public_origin}/releases/{token}/{}",
        package_file_name(version, channel)
    )
}

pub(super) fn format_countdown(expires_at: i64, now: i64) -> (String, bool, bool) {
    let remaining = expires_at - now;
    if remaining <= 0 {
        return ("expired".to_owned(), false, true);
    }
    let mins = remaining / 60;
    let secs = remaining % 60;
    (
        format!("expires in {mins}:{secs:02}"),
        remaining < 60,
        false,
    )
}

pub(super) async fn load_eph_for(
    cx: &Cx,
    user_id: u64,
    organization_id: u64,
    version: &str,
) -> Option<EphemeralDownload> {
    let mut database = db(cx);
    let rows = EphemeralDownload::all()
        .filter(EphemeralDownload::fields().user_id().eq(user_id))
        .filter(
            EphemeralDownload::fields()
                .organization_id()
                .eq(organization_id),
        )
        .filter(EphemeralDownload::fields().release_version().eq(version))
        .order_by(EphemeralDownload::fields().created_at().desc())
        .limit(1)
        .exec(&mut database)
        .await
        .unwrap_or_default();
    rows.into_iter().next()
}

pub(super) fn panel_from_row(
    public_origin: &str,
    row: &EphemeralDownload,
    version: &str,
    channel: &str,
    now: i64,
) -> EphPanel {
    let url = eph_public_url(public_origin, &row.token, version, channel);
    let (_countdown, _warn, expired) = format_countdown(row.expires_at, now);
    let remaining_secs = if expired {
        0.0
    } else {
        (row.expires_at - now) as f64
    };
    EphPanel {
        url,
        remaining_secs,
        expires_at: row.expires_at,
    }
}

fn redirect_detail(cx: &Cx, org: &str, ver: &str, form: &EphRedirectForm) -> SeeOther {
    let channel = form
        .channel
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("");
    see_other(
        href!(
            super::release_ver::build_detail_page,
            Org(org),
            ReleaseVer(ver)
        )
        .query(crate::app::hrefs::ChannelQ { channel })
        .resolve(cx),
    )
}

async fn require_downloadable_release(
    cx: &Cx,
    org_slug: &str,
    ver: &str,
) -> Result<(crate::auth::OrgContext, Release)> {
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

    let ver_key = ver.to_owned();
    let mut database = db(cx);
    let Some(release) = find_visible_release_by_version(
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
    if find_release_object(&mut database, release.id)
        .await
        .is_none()
    {
        return Err(not_found().into());
    }
    Ok((ctx, release))
}

async fn delete_existing_for(
    database: &mut toasty::Db,
    user_id: u64,
    organization_id: u64,
    version: &str,
) {
    let rows = EphemeralDownload::all()
        .filter(EphemeralDownload::fields().user_id().eq(user_id))
        .filter(
            EphemeralDownload::fields()
                .organization_id()
                .eq(organization_id),
        )
        .filter(EphemeralDownload::fields().release_version().eq(version))
        .exec(database)
        .await
        .unwrap_or_default();
    for row in rows {
        let _ = row.delete().exec(database).await;
    }
}

#[route(POST "/{org}/builds/{release_ver}/ephemeral")]
pub(crate) async fn builds_eph_generate(
    cx: &Cx,
    Form(form): Form<EphRedirectForm>,
) -> Result<SeeOther> {
    let org_slug = path_param::<Org>(cx);
    let ver = path_param::<ReleaseVer>(cx);
    let (ctx, _release) = require_downloadable_release(cx, org_slug, ver).await?;

    let now = now_unix();
    let token = Uuid::new_v4().to_string();
    let mut database = db(cx);
    delete_existing_for(&mut database, ctx.user.id, ctx.org.id, ver).await;
    let _ = toasty::create!(EphemeralDownload {
        token,
        user_id: ctx.user.id,
        organization_id: ctx.org.id,
        release_version: ver.to_owned(),
        expires_at: now + EPH_DOWNLOAD_TTL_SECS,
        created_at: now,
    })
    .exec(&mut database)
    .await;

    Ok(redirect_detail(cx, org_slug, ver, &form))
}

#[route(POST "/{org}/builds/{release_ver}/ephemeral/revoke")]
pub(crate) async fn builds_eph_revoke(
    cx: &Cx,
    Form(form): Form<EphRedirectForm>,
) -> Result<SeeOther> {
    let org_slug = path_param::<Org>(cx);
    let ver = path_param::<ReleaseVer>(cx);
    let (ctx, _release) = require_downloadable_release(cx, org_slug, ver).await?;

    let mut database = db(cx);
    delete_existing_for(&mut database, ctx.user.id, ctx.org.id, ver).await;

    Ok(redirect_detail(cx, org_slug, ver, &form))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_url_shape_strips_v() {
        let url = eph_public_url("https://access.vauban.sh", "tok-1", "v1.0.0", "LTS");
        assert_eq!(
            url,
            "https://access.vauban.sh/releases/tok-1/vauban-1.0.0+LTS.pkg"
        );
    }

    #[test]
    fn countdown_live_warn_and_expired() {
        let (label, warn, expired) = format_countdown(100, 40);
        assert_eq!(label, "expires in 1:00");
        assert!(!warn);
        assert!(!expired);

        let (label, warn, expired) = format_countdown(100, 50);
        assert_eq!(label, "expires in 0:50");
        assert!(warn);
        assert!(!expired);

        let (label, warn, expired) = format_countdown(100, 100);
        assert_eq!(label, "expired");
        assert!(!warn);
        assert!(expired);
    }
}
