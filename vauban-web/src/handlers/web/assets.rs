//! User-zone "Assets" handlers — issue #27 asset zone split.
//!
//! These handlers serve the user-facing `/assets` catalogue. Every row
//! is filtered by the caller's access rules and exposes ONLY two
//! actions: `Connect` (SSH/RDP, via `handlers::web::ssh::connect_ssh`
//! and `handlers::web::rdp::connect_rdp`) or `Request access` (via
//! `handlers::web::sessions::submit_access_request`).
//!
//! There is no detail page, no create / edit / delete affordance and no
//! View link in the user zone. All CRUD lives in
//! [`crate::handlers::web::manage_assets`] under the gated
//! `/assets/manage/*` sub-tree (`assets:manage` Casbin permission).
//!
//! Source-level invariants are enforced by
//! `vauban-web/tests/web/asset_user_zone_no_crud_test.rs`, which scans
//! both this module and `templates/assets/asset_list.html` for any
//! `assets/new`, `assets/manage`, `/edit`, `/delete`, `assets_manage`,
//! `New asset`, `Edit`, `Delete`, `View` action labels and any
//! `diesel::insert_into(assets::table)` / `diesel::update(assets::table)`
//! / `diesel::delete(assets::table)` mutation. Mutation in this file is
//! a regression by definition.
use super::*;
use crate::models::asset::AssetType;

const ASSETS_PER_PAGE: i64 = 30;

/// User-facing asset catalogue (filtered by access rules).
///
/// Renders the `templates/assets/asset_list.html` template with
/// per-row Connect / Request affordances. The gated admin list
/// (`/assets/manage`) lives in
/// [`crate::handlers::web::manage_assets::manage_asset_list`].
pub async fn asset_list(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    browser_tz: BrowserTz,
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse, AppError> {
    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new("Assets".to_string(), user.clone(), browser_tz.0)
        .with_current_path("/assets");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;

    let search_filter = params.get("search").filter(|s| !s.is_empty()).cloned();
    let type_filter = params.get("type").filter(|s| !s.is_empty()).cloned();
    let status_filter = params.get("status").filter(|s| !s.is_empty()).cloned();
    let page: i32 = params
        .get("page")
        .and_then(|s| s.parse::<i32>().ok())
        .unwrap_or(1)
        .max(1);

    // Resolve user internal ID for ALL users (incl. superuser/staff) so that
    // the listing, the per-row "Request Access" badge, and the connect
    // handler all consult the same access policy. The historical
    // privileged-user bypass produced a UI that pretended access rules
    // didn't apply to admins, while the connect handler (since febd388)
    // and `submit_access_request` enforced them anyway.
    let user_internal_id: i32 = crate::schema::users::table
        .filter(
            crate::schema::users::uuid
                .eq(::uuid::Uuid::parse_str(&auth_user.uuid).unwrap_or_default()),
        )
        .select(crate::schema::users::id)
        .first(&mut conn)
        .await
        .map_err(|_| AppError::Authorization("User not found".to_string()))?;

    // Resolve accessible asset IDs once for everyone, including superusers.
    // The bootstrap superuser MUST own at least one access_rule for itself
    // (the Vauban admin runbook covers this); otherwise its asset list will
    // legitimately be empty, mirroring what the proxy would enforce.
    let accessible_ids: Vec<i32> = crate::services::access::list_accessible_asset_ids(
        &state.access_client,
        &mut conn,
        user_internal_id,
    )
    .await?;

    let mut count_query = schema_assets::table
        .filter(schema_assets::is_deleted.eq(false))
        .into_boxed();

    count_query = count_query.filter(schema_assets::id.eq_any(accessible_ids.clone()));
    // Industrial kill-switch (layer 2 of 4): when `industrial.enabled
    // = false`, every `iacs_*` row is filtered out at the DB level so
    // the user-zone /assets list does not leak the existence of the
    // industrial surface. The Connect button + sidebar entry are
    // already hidden by the PermissionContext collapse (layer 1); the
    // form options + handler POST guards are layers 3-4. See the
    // `industrial gate hide iacs surface` plan.
    if !state.config.industrial.enabled {
        count_query =
            count_query.filter(schema_assets::asset_type.ne_all(AssetType::iacs_variants()));
    }
    if let Some(ref search) = search_filter
        && !search.is_empty()
    {
        let pattern = crate::db::like_contains(search);
        count_query = count_query.filter(
            schema_assets::name
                .ilike(pattern.clone())
                .or(schema_assets::hostname.ilike(pattern)),
        );
    }
    if let Some(ref asset_type) = type_filter
        && !asset_type.is_empty()
    {
        match AssetType::parse_filter(asset_type) {
            crate::models::asset::AssetTypeFilter::One(parsed) => {
                count_query = count_query.filter(schema_assets::asset_type.eq(parsed));
            }
            crate::models::asset::AssetTypeFilter::IacsAll => {
                count_query = count_query
                    .filter(schema_assets::asset_type.eq_any(AssetType::iacs_variants()));
            }
            crate::models::asset::AssetTypeFilter::Unknown => {
                count_query = count_query.filter(schema_assets::id.eq(-1));
            }
        }
    }
    if let Some(ref status_val) = status_filter
        && !status_val.is_empty()
    {
        count_query = count_query.filter(schema_assets::status.eq(status_val));
    }

    let total_items: i64 = count_query.count().get_result(&mut conn).await.unwrap_or(0);
    let total_pages = ((total_items as f64) / (ASSETS_PER_PAGE as f64))
        .ceil()
        .max(1.0) as i32;
    let page = page.min(total_pages);
    let offset = ((page - 1) as i64) * ASSETS_PER_PAGE;

    let mut query = schema_assets::table
        .filter(schema_assets::is_deleted.eq(false))
        .into_boxed();

    query = query.filter(schema_assets::id.eq_any(accessible_ids.clone()));
    // Industrial kill-switch (layer 2 of 4): same DB-level filter as
    // applied to `count_query` above. Both queries MUST stay in
    // lock-step or pagination would surface "0 rows" on a count of
    // N IACS rows that the user cannot actually see.
    if !state.config.industrial.enabled {
        query = query.filter(schema_assets::asset_type.ne_all(AssetType::iacs_variants()));
    }
    if let Some(ref search) = search_filter
        && !search.is_empty()
    {
        let pattern = crate::db::like_contains(search);
        query = query.filter(
            schema_assets::name
                .ilike(pattern.clone())
                .or(schema_assets::hostname.ilike(pattern)),
        );
    }
    if let Some(ref asset_type) = type_filter
        && !asset_type.is_empty()
    {
        match AssetType::parse_filter(asset_type) {
            crate::models::asset::AssetTypeFilter::One(parsed) => {
                query = query.filter(schema_assets::asset_type.eq(parsed));
            }
            crate::models::asset::AssetTypeFilter::IacsAll => {
                query = query.filter(schema_assets::asset_type.eq_any(AssetType::iacs_variants()));
            }
            crate::models::asset::AssetTypeFilter::Unknown => {
                query = query.filter(schema_assets::id.eq(-1));
            }
        }
    }
    if let Some(ref status_val) = status_filter
        && !status_val.is_empty()
    {
        query = query.filter(schema_assets::status.eq(status_val));
    }

    let db_assets: Vec<(i32, ::uuid::Uuid, String, String, i32, AssetType, String)> = query
        .select((
            schema_assets::id,
            schema_assets::uuid,
            schema_assets::name,
            schema_assets::hostname,
            schema_assets::port,
            schema_assets::asset_type,
            schema_assets::status,
        ))
        .order(schema_assets::name.asc())
        .limit(ASSETS_PER_PAGE)
        .offset(offset)
        .load(&mut conn)
        .await?;

    let displayed_asset_ids: Vec<i32> = db_assets.iter().map(|(id, ..)| *id).collect();

    // Compute the approval / approved sets for ALL users (incl. superusers).
    // Skipping this step for admins is what made the row render the blue
    // "Connect" button on assets that actually require approval — see the
    // top-of-handler comment in the legacy revision.
    //
    // NOTE: the virtual "All assets" group has no rows in `asset_asset_groups`
    // (enforced by a DB trigger). An INNER JOIN through that table silently
    // misses any access rule whose `asset_group_id` is the virtual id, causing
    // `requires_request` to be false even though approval is required. We
    // handle this with a separate query that detects such rules and, when
    // found, marks every asset on the current page as requiring approval.
    let (approval_set, approved_set, mfa_set) = {
        use crate::schema::{access_rules, asset_asset_groups, user_groups};

        let mut approval_ids: Vec<i32> = access_rules::table
            .inner_join(
                asset_asset_groups::table
                    .on(asset_asset_groups::asset_group_id.eq(access_rules::asset_group_id)),
            )
            .inner_join(
                user_groups::table.on(user_groups::group_id.eq(access_rules::user_group_id)),
            )
            .filter(user_groups::user_id.eq(user_internal_id))
            .filter(access_rules::is_active.eq(true))
            .filter(access_rules::require_approval.eq(true))
            .filter(asset_asset_groups::asset_id.eq_any(&displayed_asset_ids))
            .select(asset_asset_groups::asset_id)
            .distinct()
            .load(&mut conn)
            .await
            .unwrap_or_default();

        let virtual_id = crate::services::virtual_group::virtual_asset_group_id();
        let virtual_approval_count: i64 = access_rules::table
            .inner_join(
                user_groups::table.on(user_groups::group_id.eq(access_rules::user_group_id)),
            )
            .filter(user_groups::user_id.eq(user_internal_id))
            .filter(access_rules::is_active.eq(true))
            .filter(access_rules::require_approval.eq(true))
            .filter(access_rules::asset_group_id.eq(virtual_id))
            .select(diesel::dsl::count_star())
            .first(&mut conn)
            .await
            .unwrap_or(0);
        if virtual_approval_count > 0 {
            approval_ids.extend_from_slice(&displayed_asset_ids);
            approval_ids.sort_unstable();
            approval_ids.dedup();
        }

        let approved_ids: Vec<i32> = proxy_sessions::table
            .filter(proxy_sessions::user_id.eq(user_internal_id))
            .filter(proxy_sessions::status.eq("approved"))
            .filter(
                proxy_sessions::expires_at
                    .is_null()
                    .or(proxy_sessions::expires_at.gt(diesel::dsl::now)),
            )
            .filter(proxy_sessions::asset_id.eq_any(&displayed_asset_ids))
            .select(proxy_sessions::asset_id)
            .distinct()
            .load(&mut conn)
            .await
            .unwrap_or_default();

        // Issue #34: per-row MFA flag so the inlined Request-Access
        // modal on /assets knows whether to render the TOTP field
        // without a detour through a detail page. Same predicate as
        // the legacy `asset_user_view`: we union the per-group rules
        // with the virtual all-assets group, then collapse to a
        // HashSet for O(1) lookup. Single query for the group-level
        // rules; one extra `count` for the virtual group (cardinality
        // 0 or 1 access_rule entry against ~100s of rows on the page).
        let mut mfa_ids: Vec<i32> = access_rules::table
            .inner_join(
                asset_asset_groups::table
                    .on(asset_asset_groups::asset_group_id.eq(access_rules::asset_group_id)),
            )
            .inner_join(
                user_groups::table.on(user_groups::group_id.eq(access_rules::user_group_id)),
            )
            .filter(user_groups::user_id.eq(user_internal_id))
            .filter(access_rules::is_active.eq(true))
            .filter(access_rules::require_mfa.eq(true))
            .filter(asset_asset_groups::asset_id.eq_any(&displayed_asset_ids))
            .select(asset_asset_groups::asset_id)
            .distinct()
            .load(&mut conn)
            .await
            .unwrap_or_default();

        let virtual_mfa_count: i64 = access_rules::table
            .inner_join(
                user_groups::table.on(user_groups::group_id.eq(access_rules::user_group_id)),
            )
            .filter(user_groups::user_id.eq(user_internal_id))
            .filter(access_rules::is_active.eq(true))
            .filter(access_rules::require_mfa.eq(true))
            .filter(access_rules::asset_group_id.eq(virtual_id))
            .select(diesel::dsl::count_star())
            .first(&mut conn)
            .await
            .unwrap_or(0);
        if virtual_mfa_count > 0 {
            mfa_ids.extend_from_slice(&displayed_asset_ids);
            mfa_ids.sort_unstable();
            mfa_ids.dedup();
        }

        let a_set: std::collections::HashSet<i32> = approval_ids.into_iter().collect();
        let p_set: std::collections::HashSet<i32> = approved_ids.into_iter().collect();
        let m_set: std::collections::HashSet<i32> = mfa_ids.into_iter().collect();
        (a_set, p_set, m_set)
    };

    let asset_items: Vec<AssetListItem> = db_assets
        .into_iter()
        .map(|(id, uuid, name, hostname, port, asset_type, status)| {
            // The `asset_type` column is decoded into the strict
            // `AssetType` enum at the Diesel layer (see
            // `models::asset::AssetType::FromSql`), so we already
            // hold the typed value here. The DB CHECK constraint
            // (`assets_asset_type_chk`) ensures no unknown
            // variant can ever reach this path.
            let is_iacs = asset_type.is_iacs();
            let iacs_protocol_label = asset_type
                .iacs_protocol()
                .map(|p| p.as_str().to_string())
                .unwrap_or_default();
            AssetListItem {
                requires_request: approval_set.contains(&id) && !approved_set.contains(&id),
                require_mfa: mfa_set.contains(&id),
                id,
                uuid,
                name,
                hostname,
                port,
                asset_type: asset_type.to_string(),
                status,
                group_name: None,
                is_iacs,
                iacs_protocol_label,
            }
        })
        .collect();

    use crate::templates::accounts::user_list::Pagination;

    let start_index = if total_items > 0 { offset + 1 } else { 0 };
    let end_index = (offset + ASSETS_PER_PAGE).min(total_items);

    let pagination = if total_items > 0 {
        Some(Pagination {
            current_page: page,
            total_pages,
            total_items: total_items as i32,
            items_per_page: ASSETS_PER_PAGE as i32,
            has_previous: page > 1,
            has_next: page < total_pages,
            start_index: start_index as i32,
            end_index: end_index as i32,
        })
    } else {
        None
    };

    // Pre-resolve `user_has_active_ews` once for the entire page so
    // the template branch on the IACS Connect button stays a pure
    // boolean read (no Askama-side DB call). "Active" = neither
    // disabled (`disabled_at IS NULL`) nor offboarded (`offboarded_at
    // IS NULL`); the partial unique index `ews_active_fingerprint_uniq`
    // already enforces the exclusivity at the DB layer.
    let user_has_active_ews: bool = {
        use crate::schema::ews;
        let count: i64 = ews::table
            .filter(ews::user_id.eq(user_internal_id))
            .filter(ews::disabled_at.is_null())
            .filter(ews::offboarded_at.is_null())
            .select(diesel::dsl::count_star())
            .first(&mut conn)
            .await
            .unwrap_or(0);
        count > 0
    };

    let template = AssetListTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        assets: asset_items,
        pagination,
        search: search_filter,
        type_filter,
        status_filter,
        asset_types: AssetType::filter_options(state.config.industrial.enabled),
        statuses: vec![
            ("online".to_string(), "Online".to_string()),
            ("offline".to_string(), "Offline".to_string()),
            ("maintenance".to_string(), "Maintenance".to_string()),
        ],
        require_justification: state.config.security.require_justification,
        iacs_request_allowed: perms.iacs_request,
        iacs_connect_allowed: perms.assets_connect_iacs,
        user_has_active_ews,
    };

    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;
    Ok(Html(html))
}

/// User-facing asset connect page -- REMOVED.
///
/// Was `GET /assets/{uuid}` and rendered a per-asset detail page.
/// The page was an information-disclosure surface: every caller with
/// `assets:read` (i.e. EVERY user) loaded `description`,
/// `ssh_host_key_fingerprint`, `created_at`, `updated_at`, the asset
/// `uuid` in plain HTML, and the `group_name` -- including users who
/// had NOT yet been granted access (i.e. for whom the modal "Request
/// Access" was about to be opened).  All these fields except hostname
/// and port are gone from the user zone now: hostname/port stays in
/// `/assets` (catalogue browsing is permitted by the `assets:read`
/// contract), the rest moves to `/assets/manage/{uuid}` behind the
/// `assets:manage` Casbin gate.
///
/// The two modaux (Request Access / Justification) are inlined on the
/// `/assets` list so the user never has to load a detail page just to
/// open a modal.  See `gone_asset_user_view` below.
///
/// # Why 410 (and not 308 to /assets)
///
/// 410 Gone is a deliberate dead-end:
///
/// - It is NOT cached aggressively by browsers / proxies.
/// - It is auditable: a single grep on access logs reveals every
///   client still hitting the legacy URL (bookmarks, vendor
///   integrations, scripts) so we can reach out instead of silently
///   redirecting and hiding the migration.
/// - It is anti-enumeration: a 410 is returned to ANY UUID (existing
///   or not, accessible or not) so the route is not an oracle for
///   asset existence.  The body NEVER echoes the UUID, the asset
///   name, or any DB-derived field.
/// - It does NOT bounce back to `/assets`: a redirect would carry the
///   referer fragment (`#request-access`, `#justify`) which used to
///   auto-open a modal client-side, but the new modaux are now driven
///   by per-row buttons -- the hash navigation has no consumer left.
///
/// The handler intentionally takes no DB connection, no permission
/// extractor, and no UUID parse: it is a pure constant-time response
/// that cannot leak a 200 vs 410 timing difference between known and
/// unknown UUIDs (the upstream Casbin middleware still applies, so an
/// unauthenticated caller is bounced to /login first).
pub async fn gone_asset_user_view(
    axum::extract::Path(_asset_uuid_str): axum::extract::Path<String>,
) -> Response {
    use axum::http::StatusCode;
    // Constant body: no UUID, no asset name, no DB field.  Audit-grep
    // friendly.  Browsers render this as plain text under the
    // axum default error response; HTMX swallows it as an error.
    (
        StatusCode::GONE,
        [(axum::http::header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        "Asset detail page has moved to /assets (modaux inlined). Admin asset details live at /assets/manage/{uuid}.\n",
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_assets_per_page_is_30() {
        assert_eq!(super::ASSETS_PER_PAGE, 30);
    }

    #[test]
    fn test_asset_list_handler_uses_pagination() {
        let source = include_str!("assets.rs");
        let fn_start = source
            .find("fn asset_list")
            .expect("asset_list handler must exist");
        let fn_end = source[fn_start..]
            .find("\npub async fn ")
            .map(|p| fn_start + p)
            .unwrap_or(source.len());
        let body = &source[fn_start..fn_end];

        assert!(
            body.contains("ASSETS_PER_PAGE"),
            "asset_list must use ASSETS_PER_PAGE constant"
        );
        assert!(
            body.contains(".count()"),
            "asset_list must execute a COUNT query"
        );
        assert!(
            body.contains(".offset("),
            "asset_list must use .offset() for pagination"
        );
        assert!(
            body.contains("Pagination {"),
            "asset_list must construct a Pagination struct"
        );
        assert!(
            !body.contains(".limit(50)"),
            "asset_list must not hardcode .limit(50)"
        );
    }

    #[test]
    fn test_asset_list_handler_parses_page_param() {
        let source = include_str!("assets.rs");
        let fn_start = source
            .find("fn asset_list")
            .expect("asset_list handler must exist");
        let fn_end = source[fn_start..]
            .find("\npub async fn ")
            .map(|p| fn_start + p)
            .unwrap_or(source.len());
        let body = &source[fn_start..fn_end];

        assert!(
            body.contains("\"page\""),
            "asset_list must read the 'page' query parameter"
        );
        assert!(
            body.contains(".max(1)"),
            "asset_list must clamp page to minimum 1"
        );
    }

    #[test]
    fn test_asset_list_handler_clamps_page_to_total() {
        let source = include_str!("assets.rs");
        let fn_start = source
            .find("fn asset_list")
            .expect("asset_list handler must exist");
        let fn_end = source[fn_start..]
            .find("\npub async fn ")
            .map(|p| fn_start + p)
            .unwrap_or(source.len());
        let body = &source[fn_start..fn_end];

        assert!(
            body.contains(".min(total_pages)"),
            "asset_list must clamp page to total_pages so ?page=999 stays valid"
        );
    }

    #[test]
    fn test_asset_list_queries_approval_rules() {
        let source = include_str!("assets.rs");
        let fn_start = source
            .find("fn asset_list")
            .expect("asset_list handler must exist");
        let fn_end = source[fn_start..]
            .find("\npub async fn ")
            .map(|p| fn_start + p)
            .unwrap_or(source.len());
        let body = &source[fn_start..fn_end];

        assert!(
            body.contains("require_approval"),
            "asset_list must query access_rules.require_approval"
        );
        assert!(
            body.contains("asset_asset_groups"),
            "asset_list must join asset_asset_groups for approval check"
        );
    }

    #[test]
    fn test_asset_list_queries_approved_sessions() {
        let source = include_str!("assets.rs");
        let fn_start = source
            .find("fn asset_list")
            .expect("asset_list handler must exist");
        let fn_end = source[fn_start..]
            .find("\npub async fn ")
            .map(|p| fn_start + p)
            .unwrap_or(source.len());
        let body = &source[fn_start..fn_end];

        assert!(
            body.contains("status.eq(\"approved\")"),
            "asset_list must query approved sessions"
        );
        assert!(
            body.contains("expires_at"),
            "asset_list must check expires_at for approved sessions"
        );
    }

    #[test]
    fn test_asset_list_uses_hashset_for_lookup() {
        let source = include_str!("assets.rs");
        let fn_start = source
            .find("fn asset_list")
            .expect("asset_list handler must exist");
        let fn_end = source[fn_start..]
            .find("\npub async fn ")
            .map(|p| fn_start + p)
            .unwrap_or(source.len());
        let body = &source[fn_start..fn_end];

        assert!(
            body.contains("HashSet"),
            "asset_list must use HashSet for O(1) lookup"
        );
        assert!(
            body.contains("approval_set.contains"),
            "asset_list must use approval_set.contains for lookup"
        );
    }
}
