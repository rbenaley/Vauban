//! Parse and sync portal accounts for admin company compose (email-only).

use std::collections::{HashMap, HashSet};

use toasty::Db;
use topcoat::mail::Mailbox;

use crate::{
    db::hash_password,
    models::{MEMBERSHIP_ROLE_ORG, Membership, User},
};

/// Max compose rows we accept from the form (hard ceiling above config cap).
pub const MAX_EMAIL_FORM_SLOTS: usize = 32;

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
pub fn format_technical_contact(name: &str, email: &str) -> String {
    let name = name.trim();
    let email = email.trim();
    match (name.is_empty(), email.is_empty()) {
        (true, true) => "—".to_owned(),
        (false, true) => name.to_owned(),
        (true, false) => email.to_owned(),
        (false, false) => format!("{name} · {email}"),
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

fn unusable_password_hash() -> anyhow::Result<String> {
    use argon2::password_hash::rand_core::{OsRng, RngCore};
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);
    let secret = format!("vcp-unusable-{}", hex::encode(buf));
    hash_password(&secret)
}

/// Sync org memberships to exactly `emails` (already normalized), capped at `max`.
pub async fn sync_org_accounts(
    db: &mut Db,
    organization_id: u64,
    emails: &[String],
    max: usize,
) -> anyhow::Result<()> {
    if emails.len() > max {
        anyhow::bail!("too many accounts for seat cap");
    }

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
        let remaining = Membership::all()
            .filter(Membership::fields().user_id().eq(user.id))
            .exec(db)
            .await?;
        if remaining.is_empty() && user.portal_role.is_empty() {
            let _ = user.clone().delete().exec(db).await;
        }
    }

    for email in emails {
        let user = if let Some(existing) = user_by_email.get(email) {
            existing.clone()
        } else {
            let password_hash = unusable_password_hash()?;
            toasty::create!(User {
                email: email.clone(),
                display_name: display_name_from_email(email),
                password_hash,
                portal_role: String::new(),
            })
            .exec(db)
            .await?
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
        }
    }

    Ok(())
}

/// Delete all memberships for an org; remove orphan client users; delete the org.
pub async fn delete_org_with_accounts(db: &mut Db, org_id: u64) -> anyhow::Result<()> {
    use crate::models::Organization;

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
            let remaining = Membership::all()
                .filter(Membership::fields().user_id().eq(user.id))
                .exec(db)
                .await?;
            if remaining.is_empty() && user.portal_role.is_empty() {
                let _ = user.delete().exec(db).await;
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
            "Ada Lovelace · ada@x.test"
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
}
