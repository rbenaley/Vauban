//! Read-only admin handlers for audit pages.
//!
//! Backed by `approval_audit_log`, an append-only PostgreSQL table whose
//! `UPDATE` and `DELETE` are blocked by trigger
//! `block_approval_audit_log_mutation`. The handler therefore only ever
//! `SELECT`s; no mutation path exists from the web layer at all.

use super::*;
use crate::schema::approval_audit_log;
use crate::templates::audit::approval_audit_list::ApprovalAuditFilters;
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

    use crate::services::list_filters::{opt_filter, paginate, parse_page};

    let filters = ApprovalAuditFilters {
        actor: opt_filter(&params, "actor"),
        requester: opt_filter(&params, "requester"),
        asset: opt_filter(&params, "asset"),
        // Closed vocabulary (`status_vocab::AUDIT_DECISIONS`, kept in
        // lock-step with the `approval_audit_log.decision` CHECK):
        // unknown values degrade to "no filter".
        decision: crate::services::status_vocab::AUDIT_DECISIONS
            .sanitize(opt_filter(&params, "decision")),
        from_date: opt_filter(&params, "from_date"),
        to_date: opt_filter(&params, "to_date"),
    };

    let page = parse_page(&params);
    let per_page = params
        .get("per_page")
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|p| *p > 0)
        .unwrap_or(DEFAULT_PER_PAGE)
        .min(MAX_PER_PAGE);

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

    let window = paginate(
        usize::try_from(total_items).unwrap_or(0),
        page,
        usize::try_from(per_page).unwrap_or(30),
    );

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
        .limit(window.limit_i64())
        .offset(window.offset_i64())
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

    let pagination = window.to_audit_pagination();

    let template = ApprovalAuditListTemplate {
        decisions: crate::services::status_vocab::AUDIT_DECISIONS.options(),
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

    // `like_contains` escapes `%`/`_`/`\` so user input is matched
    // literally (the pre-fix `format!("%{}%", ..)` let a searched `%`
    // act as a wildcard).
    if let Some(actor) = filters.actor.as_ref() {
        q = q.filter(approval_audit_log::actor_username.ilike(crate::db::like_contains(actor)));
    }
    if let Some(requester) = filters.requester.as_ref() {
        q = q.filter(
            approval_audit_log::requester_username.ilike(crate::db::like_contains(requester)),
        );
    }
    if let Some(asset) = filters.asset.as_ref() {
        q = q.filter(approval_audit_log::asset_name.ilike(crate::db::like_contains(asset)));
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
