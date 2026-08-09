//! Parse and sync portal accounts for admin company compose (email-only).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use toasty::Db;
use topcoat::{
    context::{Cx, app_context},
    mail::Mailbox,
};

use crate::{
    auth::invalidate_sessions_for_user,
    config::Config,
    magic_link::{invalidate_tokens_for_user, issue_token},
    mailer::{send_invitation_mail, send_revocation_mail},
    models::{
        MEMBERSHIP_ROLE_ORG, Membership, PORTAL_ROLE_ORG, USER_NOT_DELETED, User, is_portal_org,
    },
};

/// Max compose rows we accept from the form (hard ceiling above config cap).
pub const MAX_EMAIL_FORM_SLOTS: usize = 32;

/// Clamp a subscription count into `0..=max`.
pub fn clamp_lts_count(value: i32, max: usize) -> i32 {
    let max_i = i32::try_from(max).unwrap_or(i32::MAX).max(0);
    value.clamp(0, max_i)
}

/// Parse a form field as an LTS count (empty -> 0). `None` if not an integer.
pub fn parse_lts_field(raw: &str) -> Option<i32> {
    let t = raw.trim();
    if t.is_empty() {
        return Some(0);
    }
    t.parse().ok()
}

/// Parse and reject out-of-range values (tampered POST defense).
pub fn parse_lts_subscriptions(raw: &str, max: usize, label: &str) -> Result<i32, String> {
    let Some(v) = parse_lts_field(raw) else {
        return Err(format!("Invalid {label} count."));
    };
    let max_i = i32::try_from(max).unwrap_or(i32::MAX);
    if v < 0 || v > max_i {
        return Err(format!("{label} must be between 0 and {max}."));
    }
    Ok(v)
}

/// Pure LTS stepper step (inc/dec + clamp). UI steppers are client signals;
/// this helper stays the shared math model for unit / proptest / battle.
pub fn apply_lts_compose_action(
    lts: i32,
    industrial: i32,
    action: &str,
    max: usize,
) -> Option<(i32, i32)> {
    match action {
        "lts_inc" => Some((clamp_lts_count(lts.saturating_add(1), max), industrial)),
        "lts_dec" => Some((clamp_lts_count(lts.saturating_sub(1), max), industrial)),
        "ind_inc" => Some((lts, clamp_lts_count(industrial.saturating_add(1), max))),
        "ind_dec" => Some((lts, clamp_lts_count(industrial.saturating_sub(1), max))),
        _ => None,
    }
}

/// Read `email_0` … `email_{n-1}` style fields from a key/value map.
pub fn emails_from_indexed_map(map: &HashMap<String, String>, rows: usize) -> Vec<String> {
    let n = rows.min(MAX_EMAIL_FORM_SLOTS);
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let key = format!("email_{i}");
        out.push(map.get(&key).cloned().unwrap_or_default());
    }
    out
}

/// Trim, lowercase, and validate a single portal email via Topcoat `Mailbox`.
///
/// Empty / whitespace-only input returns `Ok(None)` so compose slots can be blank.
pub fn parse_portal_email(raw: &str) -> Result<Option<String>, String> {
    let email = raw.trim().to_ascii_lowercase();
    if email.is_empty() {
        return Ok(None);
    }
    Mailbox::new(&email)
        .map(|m| Some(m.address().to_owned()))
        .map_err(|_| format!("Invalid email address: {email}"))
}

/// Normalize optional technical-contact email (same Mailbox rules as accounts).
///
/// Empty input → `Ok("")`. Non-empty invalid → `Err`.
pub fn normalize_contact_email(raw: &str) -> Result<String, String> {
    Ok(parse_portal_email(raw)?.unwrap_or_default())
}

/// Display line for company technical contact (name and/or email).
/// True when `email` is the session user (case-insensitive). Used to mark the
/// current account pill on `/{org}/account`.
pub fn is_signed_in_member(email: &str, signed_in_email: &str) -> bool {
    !signed_in_email.is_empty() && email.eq_ignore_ascii_case(signed_in_email.trim())
}

/// Pill class for USER ACCOUNTS: highlight the session member.
pub fn account_member_pill_class(email: &str, signed_in_email: &str) -> &'static str {
    if is_signed_in_member(email, signed_in_email) {
        "vb-account-pill is-you"
    } else {
        "vb-account-pill"
    }
}

/// Shared display separator (technical contact name/email, multi-line address).
pub const COMPANY_DISPLAY_SEP: &str = " · ";

pub fn format_technical_contact(name: &str, email: &str) -> String {
    let name = name.trim();
    let email = email.trim();
    match (name.is_empty(), email.is_empty()) {
        (true, true) => "—".to_owned(),
        (false, true) => name.to_owned(),
        (true, false) => email.to_owned(),
        (false, false) => format!("{name}{COMPANY_DISPLAY_SEP}{email}"),
    }
}

/// Single-line display for a stored company address (textarea may contain
/// newlines). Non-empty lines are trimmed and joined with
/// [`COMPANY_DISPLAY_SEP`] (same glyph as technical contact).
pub fn format_company_address(address: &str) -> String {
    let lines: Vec<&str> = address
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    if lines.is_empty() {
        "—".to_owned()
    } else {
        lines.join(COMPANY_DISPLAY_SEP)
    }
}

/// Trim, lowercase, drop empties, validate via `Mailbox`, dedupe (first wins).
///
/// Fail-closed: the first non-empty invalid address returns `Err` (never dropped).
pub fn normalize_emails(raw: &[String]) -> Result<Vec<String>, String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for e in raw {
        let Some(email) = parse_portal_email(e)? else {
            continue;
        };
        if !seen.insert(email.clone()) {
            continue;
        }
        out.push(email);
    }
    Ok(out)
}

/// Ensure row count for the compose form (at least one empty slot when empty).
pub fn ensure_email_rows(emails: &[String], max: usize) -> Vec<String> {
    let mut rows = emails.to_vec();
    if rows.is_empty() {
        rows.push(String::new());
    }
    if rows.len() > max {
        rows.truncate(max);
    }
    rows
}

fn display_name_from_email(email: &str) -> String {
    email
        .split('@')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or(email)
        .to_owned()
}

/// Notify a client account that access to `org_name` was removed.
///
/// Sent for every org membership removal (including multi-org users who remain
/// active elsewhere). Soft-delete is a separate step for orphans only.
async fn notify_org_access_revoked(cx: &Cx, cfg: &Config, user: &User, org_name: &str) {
    if !is_portal_org(&user.portal_role) {
        return;
    }
    if let Err(err) = send_revocation_mail(cx, &cfg.magiclinks, &user.email, org_name).await {
        tracing::warn!(
            email = %user.email,
            error = %err,
            "failed to send account revocation mail"
        );
    }
}

async fn soft_delete_org_user(db: &mut Db, user: &User) -> anyhow::Result<()> {
    if !is_portal_org(&user.portal_role) {
        return Ok(());
    }
    let now = crate::db::now_unix();
    user.clone().update().deleted_at(now).exec(db).await?;
    invalidate_sessions_for_user(db, user.id).await?;
    invalidate_tokens_for_user(db, user.id).await?;
    Ok(())
}

async fn invite_user(
    cx: &Cx,
    db: &mut Db,
    user: &User,
    org_name: &str,
    cfg: &Config,
) -> anyhow::Result<()> {
    let raw = issue_token(db, user.id, cfg.magiclinks.token_ttl_secs).await?;
    if let Err(err) = send_invitation_mail(
        cx,
        &cfg.magiclinks,
        cfg.primary_public_origin(),
        &user.email,
        org_name,
        &raw,
    )
    .await
    {
        tracing::warn!(
            email = %user.email,
            error = %err,
            "failed to send account invitation mail"
        );
    }
    Ok(())
}

/// Sync org memberships to exactly `emails` (already normalized), capped at `max`.
///
/// Removed client memberships always receive a per-org revocation mail.
/// Orphan client users (no remaining memberships) are soft-deleted (issues
/// history preserved). New memberships and revived accounts receive an
/// invitation magic-link email.
pub async fn sync_org_accounts(
    cx: &Cx,
    db: &mut Db,
    organization_id: u64,
    emails: &[String],
    max: usize,
    org_name: &str,
) -> anyhow::Result<()> {
    if emails.len() > max {
        anyhow::bail!("too many accounts for seat cap");
    }

    let cfg = app_context::<Arc<Config>>(cx);

    let memberships = Membership::all()
        .filter(Membership::fields().organization_id().eq(organization_id))
        .exec(db)
        .await?;
    let member_ids: Vec<u64> = memberships.iter().map(|m| m.user_id).collect();
    let member_users = crate::id_lookups::users_by_ids(db, &member_ids).await?;
    let email_users = if emails.is_empty() {
        Vec::new()
    } else {
        User::all()
            .filter(User::fields().email().in_list(emails.to_vec()))
            .exec(db)
            .await?
    };
    let mut user_by_id: HashMap<u64, User> = HashMap::new();
    let mut user_by_email: HashMap<String, User> = HashMap::new();
    for u in member_users.into_iter().chain(email_users) {
        user_by_email.insert(u.email.to_ascii_lowercase(), u.clone());
        user_by_id.insert(u.id, u);
    }

    let desired: HashSet<String> = emails.iter().cloned().collect();

    for m in &memberships {
        let Some(user) = user_by_id.get(&m.user_id) else {
            let _ = m.clone().delete().exec(db).await;
            continue;
        };
        let email = user.email.to_ascii_lowercase();
        if desired.contains(&email) {
            continue;
        }
        let _ = m.clone().delete().exec(db).await;
        notify_org_access_revoked(cx, cfg.as_ref(), user, org_name).await;
        let remaining = Membership::all()
            .filter(Membership::fields().user_id().eq(user.id))
            .exec(db)
            .await?;
        if remaining.is_empty() && is_portal_org(&user.portal_role) {
            soft_delete_org_user(db, user).await?;
        }
    }

    for email in emails {
        let mut should_invite = false;
        let user = if let Some(existing) = user_by_email.get(email) {
            let mut existing = existing.clone();
            if !is_portal_org(&existing.portal_role) {
                // Staff must not be rewritten or re-invited via company sync.
                existing
            } else if !existing.is_active() {
                existing
                    .update()
                    .deleted_at(USER_NOT_DELETED)
                    .exec(db)
                    .await?;
                existing.deleted_at = USER_NOT_DELETED;
                should_invite = true;
                existing
            } else {
                existing
            }
        } else {
            let created = toasty::create!(User {
                email: email.clone(),
                display_name: display_name_from_email(email),
                portal_role: PORTAL_ROLE_ORG.to_owned(),
                deleted_at: USER_NOT_DELETED,
            })
            .exec(db)
            .await?;
            user_by_email.insert(email.clone(), created.clone());
            should_invite = true;
            created
        };

        let already = Membership::all()
            .filter(Membership::fields().user_id().eq(user.id))
            .filter(Membership::fields().organization_id().eq(organization_id))
            .exec(db)
            .await?;
        if already.is_empty() {
            let _ = toasty::create!(Membership {
                user_id: user.id,
                organization_id,
                role: MEMBERSHIP_ROLE_ORG.to_owned(),
            })
            .exec(db)
            .await?;
            if is_portal_org(&user.portal_role) {
                should_invite = true;
            }
        }

        if should_invite {
            invite_user(cx, db, &user, org_name, cfg.as_ref()).await?;
        }
    }

    Ok(())
}

/// Delete all memberships for an org; revoke-mail each client; soft-delete orphans; delete the org.
pub async fn delete_org_with_accounts(
    cx: &Cx,
    db: &mut Db,
    org_id: u64,
    org_name: &str,
) -> anyhow::Result<()> {
    use crate::models::Organization;
    use crate::storage::delete_org_objects;

    // Best-effort blob purge before catalog delete (authz already passed).
    let store = crate::auth::storage(cx);
    let _ = store.delete_org(org_id);
    let _ = delete_org_objects(db, org_id).await;

    let cfg = app_context::<Arc<Config>>(cx);
    let memberships = Membership::all()
        .filter(Membership::fields().organization_id().eq(org_id))
        .exec(db)
        .await?;
    for m in memberships {
        let user_id = m.user_id;
        let _ = m.delete().exec(db).await;
        let users = User::all()
            .filter(User::fields().id().eq(user_id))
            .exec(db)
            .await?;
        if let Some(user) = users.into_iter().next() {
            notify_org_access_revoked(cx, cfg.as_ref(), &user, org_name).await;
            let remaining = Membership::all()
                .filter(Membership::fields().user_id().eq(user.id))
                .exec(db)
                .await?;
            if remaining.is_empty() && is_portal_org(&user.portal_role) {
                soft_delete_org_user(db, &user).await?;
            }
        }
    }

    let orgs = Organization::all()
        .filter(Organization::fields().id().eq(org_id))
        .exec(db)
        .await?;
    if let Some(org) = orgs.into_iter().next() {
        let _ = org.delete().exec(db).await;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_portal_email_happy_and_empty() {
        assert_eq!(
            parse_portal_email("  A@Example.COM ").unwrap().as_deref(),
            Some("a@example.com")
        );
        assert_eq!(parse_portal_email("   ").unwrap(), None);
        assert_eq!(parse_portal_email("").unwrap(), None);
    }

    #[test]
    fn parse_portal_email_rejects_invalid() {
        let err = parse_portal_email("not-an-email").unwrap_err();
        assert!(err.contains("Invalid email address"));
        assert!(err.contains("not-an-email"));
        assert!(parse_portal_email("a@").is_err());
    }

    #[test]
    fn normalize_emails_trims_lowercases_dedupes() {
        let raw = vec![
            "  A@Example.COM ".to_owned(),
            "a@example.com".to_owned(),
            "".to_owned(),
            "b@x.test".to_owned(),
        ];
        assert_eq!(
            normalize_emails(&raw).unwrap(),
            vec!["a@example.com".to_owned(), "b@x.test".to_owned()]
        );
    }

    #[test]
    fn normalize_emails_fail_closed_on_invalid() {
        let raw = vec!["ok@example.com".to_owned(), "not-an-email".to_owned()];
        let err = normalize_emails(&raw).unwrap_err();
        assert!(err.contains("not-an-email"));
    }

    #[test]
    fn normalize_contact_email_empty_and_valid() {
        assert_eq!(normalize_contact_email("").unwrap(), "");
        assert_eq!(normalize_contact_email("   ").unwrap(), "");
        assert_eq!(
            normalize_contact_email("  Ops@Example.COM ").unwrap(),
            "ops@example.com"
        );
    }

    #[test]
    fn normalize_contact_email_rejects_invalid() {
        let err = normalize_contact_email("not-an-email").unwrap_err();
        assert!(err.contains("Invalid email address"));
        assert!(err.contains("not-an-email"));
    }

    #[test]
    fn format_technical_contact_variants() {
        assert_eq!(format_technical_contact("", ""), "—");
        assert_eq!(format_technical_contact("  Ada  ", ""), "Ada");
        assert_eq!(format_technical_contact("", " a@x.test "), "a@x.test");
        assert_eq!(
            format_technical_contact("Ada Lovelace", "ada@x.test"),
            format!("Ada Lovelace{COMPANY_DISPLAY_SEP}ada@x.test")
        );
    }

    #[test]
    fn format_company_address_joins_lines_with_display_sep() {
        assert_eq!(format_company_address(""), "—");
        assert_eq!(format_company_address("  \n  "), "—");
        assert_eq!(format_company_address("1 Rue Alone"), "1 Rue Alone");
        assert_eq!(
            format_company_address(
                "Scalable Solutions\nChaussée de Mons 1229\n1070 Bruxelles\nBelgique"
            ),
            format!(
                "Scalable Solutions{COMPANY_DISPLAY_SEP}Chaussée de Mons 1229{COMPANY_DISPLAY_SEP}1070 Bruxelles{COMPANY_DISPLAY_SEP}Belgique"
            )
        );
        assert_eq!(
            format_company_address("  Line A  \r\n\r\n  Line B  \n"),
            format!("Line A{COMPANY_DISPLAY_SEP}Line B")
        );
        assert!(
            format_company_address("A\nB").contains(COMPANY_DISPLAY_SEP),
            "address sep must match technical contact glyph"
        );
    }

    #[test]
    fn signed_in_member_pill_marks_session_user() {
        assert!(is_signed_in_member("Ada@X.test", " ada@x.test "));
        assert!(!is_signed_in_member("other@x.test", "ada@x.test"));
        assert!(!is_signed_in_member("ada@x.test", ""));
        assert_eq!(
            account_member_pill_class("ada@x.test", "ada@x.test"),
            "vb-account-pill is-you"
        );
        assert_eq!(
            account_member_pill_class("other@x.test", "ada@x.test"),
            "vb-account-pill"
        );
    }

    #[test]
    fn ensure_email_rows_pads_and_caps() {
        assert_eq!(ensure_email_rows(&[], 5), vec![String::new()]);
        let many = vec!["a@x".into(), "b@x".into(), "c@x".into()];
        assert_eq!(ensure_email_rows(&many, 2).len(), 2);
    }

    #[test]
    fn emails_from_indexed_map_reads_slots() {
        let mut map = HashMap::new();
        map.insert("email_0".to_owned(), "a@x.test".to_owned());
        map.insert("email_1".to_owned(), "b@x.test".to_owned());
        assert_eq!(
            emails_from_indexed_map(&map, 2),
            vec!["a@x.test".to_owned(), "b@x.test".to_owned()]
        );
    }

    #[test]
    fn clamp_lts_count_bounds() {
        assert_eq!(clamp_lts_count(-3, 99), 0);
        assert_eq!(clamp_lts_count(0, 99), 0);
        assert_eq!(clamp_lts_count(50, 99), 50);
        assert_eq!(clamp_lts_count(99, 99), 99);
        assert_eq!(clamp_lts_count(100, 99), 99);
        assert_eq!(clamp_lts_count(5, 0), 0);
    }

    #[test]
    fn parse_lts_subscriptions_accepts_range() {
        assert_eq!(
            parse_lts_subscriptions("2", 99, "Vauban LTS subscriptions").unwrap(),
            2
        );
        assert_eq!(
            parse_lts_subscriptions("", 99, "Vauban LTS subscriptions").unwrap(),
            0
        );
        assert!(parse_lts_subscriptions("100", 99, "Vauban LTS subscriptions").is_err());
        assert!(parse_lts_subscriptions("-1", 99, "Vauban LTS subscriptions").is_err());
        assert!(parse_lts_subscriptions("x", 99, "Vauban LTS subscriptions").is_err());
    }

    #[test]
    fn apply_lts_compose_action_steps() {
        assert_eq!(apply_lts_compose_action(0, 0, "lts_inc", 99), Some((1, 0)));
        assert_eq!(apply_lts_compose_action(1, 0, "lts_dec", 99), Some((0, 0)));
        assert_eq!(apply_lts_compose_action(0, 0, "lts_dec", 99), Some((0, 0)));
        assert_eq!(
            apply_lts_compose_action(99, 0, "lts_inc", 99),
            Some((99, 0))
        );
        assert_eq!(apply_lts_compose_action(0, 1, "ind_inc", 99), Some((0, 2)));
        assert_eq!(apply_lts_compose_action(0, 0, "save", 99), None);
    }
}
