//! Read-only admin handlers for audit pages.
//!
//! Backed by `approval_audit_log`, an append-only PostgreSQL table whose
//! `UPDATE` and `DELETE` are blocked by trigger
//! `block_approval_audit_log_mutation`. The handler therefore only ever
//! `SELECT`s; no mutation path exists from the web layer at all.

use super::*;
use crate::schema::approval_audit_log;
use crate::templates::audit::approval_audit_list::{ApprovalAuditFilters, AuditPagination};
use crate::templates::audit::{ApprovalAuditListTemplate, ApprovalAuditRow};

/// Hard ceiling on `LIMIT` so a malicious or accidental
/// `?per_page=999999` cannot pin a worker on a giant scan.
const MAX_PER_PAGE: i64 = 100;

/// Default page size; small enough to render cheaply, large enough to
/// keep most investigations one-page.
const DEFAULT_PER_PAGE: i64 = 30;

/// `GET /audit/approvals` — admin-only, paginated, filterable view of
/// the append-only approval audit log.
///
/// Filters are AND-combined; an empty filter is treated as absent so
/// that "All" really means all. The `from_date`/`to_date` filters
/// match `created_at` against `YYYY-MM-DD` (UTC start- and end-of-day
/// respectively).
pub async fn approval_audit_list(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    browser_tz: BrowserTz,
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse, AppError> {
    if !perms.admin_view {
        return Err(AppError::Authorization(
            "Only administrators can view the approval audit log".to_string(),
        ));
    }

    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new("Approval Audit Log".to_string(), user, browser_tz.0)
        .with_current_path("/audit/approvals");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

    let filters = ApprovalAuditFilters {
        actor: params.get("actor").filter(|s| !s.is_empty()).cloned(),
        requester: params.get("requester").filter(|s| !s.is_empty()).cloned(),
        asset: params.get("asset").filter(|s| !s.is_empty()).cloned(),
        decision: params
            .get("decision")
            .filter(|s| matches!(s.as_str(), "approve" | "reject"))
            .cloned(),
        from_date: params.get("from_date").filter(|s| !s.is_empty()).cloned(),
        to_date: params.get("to_date").filter(|s| !s.is_empty()).cloned(),
    };

    let page = params
        .get("page")
        .and_then(|s| s.parse::<i32>().ok())
        .filter(|p| *p >= 1)
        .unwrap_or(1);
    let per_page = params
        .get("per_page")
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|p| *p > 0)
        .unwrap_or(DEFAULT_PER_PAGE)
        .min(MAX_PER_PAGE);
    let offset = ((page as i64) - 1) * per_page;

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;

    let from_dt = parse_from_date(filters.from_date.as_deref())?;
    let to_dt = parse_to_date(filters.to_date.as_deref())?;

    let total_items: i64 = build_filtered_query(&filters, from_dt, to_dt)
        .count()
        .get_result(&mut conn)
        .await
        .map_err(AppError::Database)?;

    #[allow(clippy::type_complexity)]
    let rows_data: Vec<(
        i64,
        uuid::Uuid,
        String,
        String,
        String,
        uuid::Uuid,
        String,
        Option<String>,
        Option<i32>,
        Option<String>,
        Option<ipnetwork::IpNetwork>,
        Option<String>,
        Option<String>,
        chrono::DateTime<chrono::Utc>,
    )> = build_filtered_query(&filters, from_dt, to_dt)
        .select((
            approval_audit_log::id,
            approval_audit_log::session_uuid,
            approval_audit_log::decision,
            approval_audit_log::actor_username,
            approval_audit_log::requester_username,
            approval_audit_log::asset_uuid,
            approval_audit_log::asset_name,
            approval_audit_log::protocol,
            approval_audit_log::duration_override_seconds,
            approval_audit_log::decision_reason,
            approval_audit_log::decision_ip,
            approval_audit_log::decision_user_agent,
            approval_audit_log::request_id,
            approval_audit_log::created_at,
        ))
        .order(approval_audit_log::created_at.desc())
        .limit(per_page)
        .offset(offset)
        .load(&mut conn)
        .await
        .map_err(AppError::Database)?;

    let rows: Vec<ApprovalAuditRow> = rows_data
        .into_iter()
        .map(
            |(
                id,
                session_uuid,
                decision,
                actor_username,
                requester_username,
                asset_uuid,
                asset_name,
                protocol,
                duration_override_seconds,
                decision_reason,
                decision_ip,
                decision_user_agent,
                request_id,
                created_at,
            )| ApprovalAuditRow {
                id,
                session_uuid: session_uuid.to_string(),
                decision,
                actor_username,
                requester_username,
                asset_uuid: asset_uuid.to_string(),
                asset_name,
                protocol,
                duration_override_seconds,
                decision_reason,
                decision_ip: decision_ip.map(|ip| ip.ip().to_string()),
                decision_user_agent,
                request_id,
                created_at: crate::utils::format_local_with_seconds(created_at, browser_tz.0),
            },
        )
        .collect();

    let total_pages = if total_items == 0 {
        1
    } else {
        ((total_items as f64) / (per_page as f64)).ceil() as i32
    };

    let pagination = AuditPagination {
        current_page: page,
        total_pages,
        total_items,
        has_previous: page > 1,
        has_next: page < total_pages,
    };

    let template = ApprovalAuditListTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        rows,
        pagination,
        filters,
    };

    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;
    Ok(Html(html))
}

/// Parse `YYYY-MM-DD` as the start of the day in UTC.
fn parse_from_date(s: Option<&str>) -> AppResult<Option<chrono::DateTime<chrono::Utc>>> {
    let Some(s) = s else { return Ok(None) };
    let date = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").map_err(|_| {
        AppError::Validation("Invalid 'from_date' (expected YYYY-MM-DD)".to_string())
    })?;
    Ok(Some(
        date.and_hms_opt(0, 0, 0).unwrap_or_default().and_utc(),
    ))
}

/// Parse `YYYY-MM-DD` as the *end* of the day in UTC (inclusive day).
fn parse_to_date(s: Option<&str>) -> AppResult<Option<chrono::DateTime<chrono::Utc>>> {
    let Some(s) = s else { return Ok(None) };
    let date = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d")
        .map_err(|_| AppError::Validation("Invalid 'to_date' (expected YYYY-MM-DD)".to_string()))?;
    Ok(Some(
        date.and_hms_opt(23, 59, 59).unwrap_or_default().and_utc(),
    ))
}

type BoxedAuditQuery<'a> = approval_audit_log::BoxedQuery<'a, diesel::pg::Pg>;

/// Build a `WHERE`-only query (no select/order/limit) that the
/// `count` and `select` paths share so a filter never gets applied
/// to one and not the other.
fn build_filtered_query<'a>(
    filters: &ApprovalAuditFilters,
    from_dt: Option<chrono::DateTime<chrono::Utc>>,
    to_dt: Option<chrono::DateTime<chrono::Utc>>,
) -> BoxedAuditQuery<'a> {
    let mut q = approval_audit_log::table.into_boxed();

    if let Some(actor) = filters.actor.as_ref() {
        let pat = format!("%{}%", actor);
        q = q.filter(approval_audit_log::actor_username.ilike(pat));
    }
    if let Some(requester) = filters.requester.as_ref() {
        let pat = format!("%{}%", requester);
        q = q.filter(approval_audit_log::requester_username.ilike(pat));
    }
    if let Some(asset) = filters.asset.as_ref() {
        let pat = format!("%{}%", asset);
        q = q.filter(approval_audit_log::asset_name.ilike(pat));
    }
    if let Some(decision) = filters.decision.as_ref() {
        q = q.filter(approval_audit_log::decision.eq(decision.clone()));
    }
    if let Some(from_dt) = from_dt {
        q = q.filter(approval_audit_log::created_at.ge(from_dt));
    }
    if let Some(to_dt) = to_dt {
        q = q.filter(approval_audit_log::created_at.le(to_dt));
    }
    q
}
