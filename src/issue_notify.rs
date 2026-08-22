//! Issue notification policy, outbox enqueue, and drain.
//!
//! Policy helpers are pure (no Topcoat / SMTP). Loaders use SQL-side filters.

use toasty::Db;
use topcoat::context::Cx;

use crate::{
    auth::{config, db as cx_db},
    config::{ISSUE_NOTIFY_EVENT_TOKENS, IssuesNotifyConfig},
    db::now_unix,
    mail_circuit::MailCircuitBreaker,
    mail_templates::IssueMailVars,
    mailer::send_issue_event_mail,
    models::{
        ISSUE_MAIL_SOURCE_CREATE, Issue, IssueComment, IssueMailOutbox, Membership, Organization,
        PORTAL_ROLE_ADMIN, PORTAL_ROLE_ORG, USER_NOT_DELETED, User, is_portal_admin,
    },
};

/// Max characters of issue details / comment copied into mail.
pub const EXCERPT_MAX_CHARS: usize = 500;

/// Bounded pending rows claimed per drain pass.
const DRAIN_BATCH: usize = 50;

/// Closed event catalogue (`[issues.notify]` tokens).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NotifyEvent {
    Create,
    Comment,
    SupportComment,
    Status,
}

impl NotifyEvent {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Comment => "comment",
            Self::SupportComment => "support_comment",
            Self::Status => "status",
        }
    }

    pub fn parse(token: &str) -> Option<Self> {
        match token.trim() {
            "create" => Some(Self::Create),
            "comment" => Some(Self::Comment),
            "support_comment" => Some(Self::SupportComment),
            "status" => Some(Self::Status),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Create => "New issue",
            Self::Comment => "New comment",
            Self::SupportComment => "Support replied",
            Self::Status => "Status changed",
        }
    }
}

/// Which audiences a configured event should fan out to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotifyAudiences {
    pub support: bool,
    pub company: bool,
}

/// Audiences for `event` under `cfg` (empty when notify is disabled).
pub fn notify_audiences(event: NotifyEvent, cfg: &IssuesNotifyConfig) -> NotifyAudiences {
    if !cfg.enabled {
        return NotifyAudiences {
            support: false,
            company: false,
        };
    }
    let token = event.as_str();
    NotifyAudiences {
        support: cfg.support_events.iter().any(|e| e == token),
        company: cfg.company_events.iter().any(|e| e == token),
    }
}

/// Drop the actor (when requested) and dedupe ids. Soft-delete is a SQL concern.
pub fn filter_recipient_ids(ids: &[u64], actor_id: u64, exclude_actor: bool) -> Vec<u64> {
    let mut out: Vec<u64> = ids
        .iter()
        .copied()
        .filter(|id| !exclude_actor || *id != actor_id)
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// Truncate `raw` to [`EXCERPT_MAX_CHARS`] (Unicode scalar values).
pub fn excerpt_text(raw: &str) -> String {
    let t = raw.trim();
    let mut out = String::new();
    for (i, c) in t.chars().enumerate() {
        if i >= EXCERPT_MAX_CHARS {
            out.push('…');
            break;
        }
        out.push(c);
    }
    out
}

/// Stable unique-key tuple for an outbox row.
pub fn outbox_unique_key(
    issue_id: u64,
    event: NotifyEvent,
    source_id: u64,
    recipient_user_id: u64,
) -> (u64, &'static str, u64, u64) {
    (issue_id, event.as_str(), source_id, recipient_user_id)
}

/// Classify a comment author: Support staff vs company user account.
pub fn comment_event_for_actor(portal_role: &str) -> NotifyEvent {
    if is_portal_admin(portal_role) {
        NotifyEvent::SupportComment
    } else {
        NotifyEvent::Comment
    }
}

/// Event tokens accepted by config (kept in sync with [`NotifyEvent`]).
pub fn known_event_tokens() -> &'static [&'static str] {
    ISSUE_NOTIFY_EVENT_TOKENS
}

async fn load_support_ids(
    db: &mut Db,
    actor_id: u64,
    exclude_actor: bool,
) -> anyhow::Result<Vec<u64>> {
    let users = if exclude_actor {
        User::all()
            .filter(
                User::fields()
                    .portal_role()
                    .eq(PORTAL_ROLE_ADMIN.to_owned()),
            )
            .filter(User::fields().deleted_at().eq(USER_NOT_DELETED))
            .filter(User::fields().id().ne(actor_id))
            .exec(db)
            .await?
    } else {
        User::all()
            .filter(
                User::fields()
                    .portal_role()
                    .eq(PORTAL_ROLE_ADMIN.to_owned()),
            )
            .filter(User::fields().deleted_at().eq(USER_NOT_DELETED))
            .exec(db)
            .await?
    };
    Ok(users.into_iter().map(|u| u.id).collect())
}

async fn load_company_ids(
    db: &mut Db,
    org_id: u64,
    actor_id: u64,
    exclude_actor: bool,
) -> anyhow::Result<Vec<u64>> {
    let memberships = Membership::all()
        .filter(Membership::fields().organization_id().eq(org_id))
        .exec(db)
        .await?;
    let member_ids: Vec<u64> = memberships.into_iter().map(|m| m.user_id).collect();
    if member_ids.is_empty() {
        return Ok(Vec::new());
    }
    let users = User::all()
        .filter(User::fields().id().in_list(member_ids))
        .filter(User::fields().portal_role().eq(PORTAL_ROLE_ORG.to_owned()))
        .filter(User::fields().deleted_at().eq(USER_NOT_DELETED))
        .exec(db)
        .await?;
    let ids: Vec<u64> = users.into_iter().map(|u| u.id).collect();
    Ok(filter_recipient_ids(&ids, actor_id, exclude_actor))
}

/// Insert pending outbox rows for this event inside the caller's transaction.
pub async fn enqueue_issue_notify(
    db: &mut Db,
    cfg: &IssuesNotifyConfig,
    issue: &Issue,
    event: NotifyEvent,
    source_id: u64,
    actor_user_id: u64,
) -> anyhow::Result<usize> {
    let audiences = notify_audiences(event, cfg);
    if !audiences.support && !audiences.company {
        return Ok(0);
    }
    let mut recipient_ids = Vec::new();
    if audiences.support {
        recipient_ids.extend(load_support_ids(db, actor_user_id, cfg.exclude_actor).await?);
    }
    if audiences.company {
        recipient_ids.extend(
            load_company_ids(db, issue.organization_id, actor_user_id, cfg.exclude_actor).await?,
        );
    }
    let recipient_ids = filter_recipient_ids(&recipient_ids, actor_user_id, cfg.exclude_actor);
    let now = now_unix();
    let mut inserted = 0usize;
    for recipient_user_id in recipient_ids {
        let result =
            IssueMailOutbox::upsert_by_issue_id_and_event_and_source_id_and_recipient_user_id(
                issue.id,
                event.as_str(),
                source_id,
                recipient_user_id,
            )
            .actor_user_id(actor_user_id)
            .created_at(now)
            .sent_at(0)
            .attempts(0)
            .last_error(String::new())
            .version(1)
            .or_ignore()
            .exec(db)
            .await?;
        if result.is_some() {
            inserted += 1;
        }
    }
    Ok(inserted)
}

/// Drain pending outbox rows after a successful issue write (uses request mail).
pub async fn drain_pending(cx: &Cx) {
    let cfg = config(cx);
    if !cfg.issues.notify.enabled {
        return;
    }
    let mut database = cx_db(cx);
    if let Err(err) = drain_pending_rows(cx, &mut database, &cfg.issues.notify).await {
        tracing::error!(
            target: "vcp::issue_notify",
            error = %err,
            "issue notify drain failed"
        );
    }
}

/// Claim and send a bounded batch of pending rows.
pub async fn drain_pending_rows(
    cx: &Cx,
    db: &mut Db,
    notify: &IssuesNotifyConfig,
) -> anyhow::Result<u32> {
    let breaker = topcoat::context::try_app_context::<std::sync::Arc<MailCircuitBreaker>>(cx);
    if breaker.as_ref().is_some_and(|b| !b.allow_attempt()) {
        return Ok(0);
    }
    let pending = IssueMailOutbox::all()
        .filter(IssueMailOutbox::fields().sent_at().eq(0_i64))
        .filter(
            IssueMailOutbox::fields()
                .attempts()
                .lt(u64::from(notify.max_attempts)),
        )
        .limit(DRAIN_BATCH)
        .exec(db)
        .await?;
    let mut sent = 0u32;
    for mut row in pending {
        match deliver_one(cx, db, notify, &mut row).await {
            Ok(true) => sent += 1,
            Ok(false) => {}
            Err(err) => {
                tracing::warn!(
                    target: "vcp::issue_notify",
                    error = %err,
                    "issue notify deliver failed"
                );
            }
        }
    }
    Ok(sent)
}

async fn deliver_one(
    cx: &Cx,
    db: &mut Db,
    notify: &IssuesNotifyConfig,
    row: &mut IssueMailOutbox,
) -> anyhow::Result<bool> {
    let next_attempts = row.attempts.saturating_add(1);
    if let Err(err) = row.update().attempts(next_attempts).exec(db).await {
        if err.is_condition_failed() {
            return Ok(false);
        }
        return Err(err.into());
    }
    row.attempts = next_attempts;

    let Some(recipient) = load_active_user(db, row.recipient_user_id).await? else {
        mark_sent(db, row).await?;
        return Ok(false);
    };
    let Some(issue) = load_issue(db, row.issue_id).await? else {
        mark_sent(db, row).await?;
        return Ok(false);
    };
    let Some(org) = load_org(db, issue.organization_id).await? else {
        mark_sent(db, row).await?;
        return Ok(false);
    };
    let event = NotifyEvent::parse(&row.event).unwrap_or(NotifyEvent::Comment);
    let excerpt = load_excerpt(db, event, &issue, row.source_id).await;
    let cfg = config(cx);
    let origin = cfg.primary_public_origin().trim_end_matches('/');
    let url = issue_url(origin, event, &issue, &org, &recipient);
    let subject = issue_subject(event, &issue);
    let text = issue_text(&org, &issue, event, &excerpt, &url);
    let vars = IssueMailVars {
        org_name: &org.name,
        issue_key: &issue.key,
        issue_title: &issue.title,
        event_label: event.label(),
        excerpt: &excerpt,
        issue_url: &url,
        from_address: cfg.magiclinks.from_address.trim(),
    };
    match send_issue_event_mail(cx, &cfg.magiclinks, &recipient.email, &subject, &text, vars).await
    {
        Ok(()) => {
            mark_sent(db, row).await?;
            Ok(true)
        }
        Err(err) => {
            let msg = truncate_error(&err.to_string());
            if row.attempts >= u64::from(notify.max_attempts) {
                tracing::error!(
                    target: "vcp::issue_notify",
                    issue_id = row.issue_id,
                    event = %row.event,
                    attempts = row.attempts,
                    "issue notify exhausted attempts"
                );
            }
            let _ = row.update().last_error(msg).exec(db).await;
            Ok(false)
        }
    }
}

async fn mark_sent(db: &mut Db, row: &mut IssueMailOutbox) -> anyhow::Result<()> {
    let now = now_unix();
    row.update()
        .sent_at(now)
        .last_error(String::new())
        .exec(db)
        .await?;
    row.sent_at = now;
    Ok(())
}

async fn load_active_user(db: &mut Db, id: u64) -> anyhow::Result<Option<User>> {
    let rows = User::all()
        .filter(User::fields().id().eq(id))
        .filter(User::fields().deleted_at().eq(USER_NOT_DELETED))
        .limit(1)
        .exec(db)
        .await?;
    Ok(rows.into_iter().next())
}

async fn load_issue(db: &mut Db, id: u64) -> anyhow::Result<Option<Issue>> {
    let rows = Issue::all()
        .filter(Issue::fields().id().eq(id))
        .limit(1)
        .exec(db)
        .await?;
    Ok(rows.into_iter().next())
}

async fn load_org(db: &mut Db, id: u64) -> anyhow::Result<Option<Organization>> {
    let rows = Organization::all()
        .filter(Organization::fields().id().eq(id))
        .limit(1)
        .exec(db)
        .await?;
    Ok(rows.into_iter().next())
}

async fn load_excerpt(db: &mut Db, event: NotifyEvent, issue: &Issue, source_id: u64) -> String {
    match event {
        NotifyEvent::Create => excerpt_text(&issue.details),
        NotifyEvent::Comment | NotifyEvent::SupportComment | NotifyEvent::Status => {
            if source_id == ISSUE_MAIL_SOURCE_CREATE {
                return excerpt_text(&issue.details);
            }
            let rows = IssueComment::all()
                .filter(IssueComment::fields().id().eq(source_id))
                .limit(1)
                .exec(db)
                .await
                .unwrap_or_default();
            rows.into_iter()
                .next()
                .map(|c| excerpt_text(&c.body))
                .unwrap_or_else(|| excerpt_text(&issue.details))
        }
    }
}

fn issue_url(
    origin: &str,
    _event: NotifyEvent,
    issue: &Issue,
    org: &Organization,
    recipient: &User,
) -> String {
    if is_portal_admin(&recipient.portal_role) {
        format!(
            "{origin}/admin/issues/{}?org={}",
            urlencoding_path(&issue.key),
            urlencoding_path(&org.slug)
        )
    } else {
        format!(
            "{origin}/{}/issues/{}",
            urlencoding_path(&org.slug),
            urlencoding_path(&issue.key)
        )
    }
}

fn issue_subject(event: NotifyEvent, issue: &Issue) -> String {
    match event {
        NotifyEvent::Create => format!("[{}] New issue", issue.key),
        NotifyEvent::Comment => format!("[{}] New comment", issue.key),
        NotifyEvent::SupportComment => format!("[{}] Support replied", issue.key),
        NotifyEvent::Status => format!("[{}] Status: {}", issue.key, issue.status),
    }
}

fn issue_text(
    org: &Organization,
    issue: &Issue,
    event: NotifyEvent,
    excerpt: &str,
    url: &str,
) -> String {
    format!(
        "{label} on {key} ({org})\n\n{title}\n\n{excerpt}\n\n{url}\n",
        label = event.label(),
        key = issue.key,
        org = org.name,
        title = issue.title,
        excerpt = excerpt,
        url = url,
    )
}

fn urlencoding_path(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn truncate_error(err: &str) -> String {
    let t = err.trim();
    t.chars().take(200).collect()
}

/// Background leftover drain (SMTP via the next HTTP drain if TEM is down).
pub fn start_issue_notify_drain(db: Db, notify: IssuesNotifyConfig) {
    if !notify.enabled {
        return;
    }
    let interval = notify.drain_interval_duration();
    tracing::info!(
        target: "vcp::issue_notify",
        drain_interval_secs = notify.drain_interval_secs,
        "issue notify drain scheduler started"
    );
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let mut conn = db.clone();
            let pending = IssueMailOutbox::all()
                .filter(IssueMailOutbox::fields().sent_at().eq(0_i64))
                .filter(
                    IssueMailOutbox::fields()
                        .attempts()
                        .lt(u64::from(notify.max_attempts)),
                )
                .count()
                .exec(&mut conn)
                .await;
            match pending {
                Ok(0) => {}
                Ok(n) => {
                    tracing::info!(
                        target: "vcp::issue_notify",
                        pending = n,
                        "issue notify outbox still pending (next request drain will send)"
                    );
                }
                Err(err) => {
                    tracing::error!(
                        target: "vcp::issue_notify",
                        error = %err,
                        "issue notify pending count failed"
                    );
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mail_templates::html_escape;
    use std::sync::{Arc, Barrier};
    use std::thread;

    fn cfg_default() -> IssuesNotifyConfig {
        IssuesNotifyConfig::default()
    }

    #[test]
    fn audiences_locked_matrix() {
        let cfg = cfg_default();
        let create = notify_audiences(NotifyEvent::Create, &cfg);
        assert!(create.support && !create.company);
        let comment = notify_audiences(NotifyEvent::Comment, &cfg);
        assert!(comment.support && !comment.company);
        let support = notify_audiences(NotifyEvent::SupportComment, &cfg);
        assert!(support.support && support.company);
        let status = notify_audiences(NotifyEvent::Status, &cfg);
        assert!(status.support && !status.company);
    }

    #[test]
    fn disabled_notifies_nobody() {
        let cfg = IssuesNotifyConfig::silent();
        for ev in [
            NotifyEvent::Create,
            NotifyEvent::Comment,
            NotifyEvent::SupportComment,
            NotifyEvent::Status,
        ] {
            let a = notify_audiences(ev, &cfg);
            assert!(!a.support && !a.company);
        }
    }

    #[test]
    fn exclude_actor_filters_self() {
        let ids = [1, 2, 3, 2];
        assert_eq!(filter_recipient_ids(&ids, 2, true), vec![1, 3]);
        assert_eq!(filter_recipient_ids(&ids, 2, false), vec![1, 2, 3]);
        assert_eq!(filter_recipient_ids(&[], 1, true), Vec::<u64>::new());
    }

    #[test]
    fn excerpt_caps_and_trims() {
        assert_eq!(excerpt_text("  hi  "), "hi");
        let fenced = "See:\n\n```\nssh allow\n```\n";
        let raw = excerpt_text(fenced);
        assert!(
            raw.contains("```"),
            "mail excerpt must stay raw dialect source: {raw}"
        );
        assert!(raw.contains("ssh allow"));
        let long = "x".repeat(EXCERPT_MAX_CHARS + 20);
        let out = excerpt_text(&long);
        assert_eq!(out.chars().count(), EXCERPT_MAX_CHARS + 1);
        assert!(out.ends_with('…'));
        assert_eq!(html_escape("<b>"), "&lt;b&gt;");
    }

    #[test]
    fn comment_event_uses_portal_role() {
        assert_eq!(
            comment_event_for_actor(PORTAL_ROLE_ADMIN),
            NotifyEvent::SupportComment
        );
        assert_eq!(
            comment_event_for_actor(PORTAL_ROLE_ORG),
            NotifyEvent::Comment
        );
    }

    #[test]
    fn parse_event_catalogue() {
        for tok in ISSUE_NOTIFY_EVENT_TOKENS {
            assert!(NotifyEvent::parse(tok).is_some(), "{tok}");
        }
        assert!(NotifyEvent::parse("nightly").is_none());
        assert_eq!(known_event_tokens(), ISSUE_NOTIFY_EVENT_TOKENS);
    }

    #[test]
    fn outbox_key_is_stable() {
        let a = outbox_unique_key(9, NotifyEvent::Status, 3, 4);
        let b = outbox_unique_key(9, NotifyEvent::Status, 3, 4);
        assert_eq!(a, b);
        assert_ne!(a, outbox_unique_key(9, NotifyEvent::Comment, 3, 4));
    }

    #[test]
    fn event_labels_are_stable() {
        assert_eq!(NotifyEvent::Status.label(), "Status changed");
        assert_eq!(NotifyEvent::SupportComment.label(), "Support replied");
        assert_eq!(NotifyEvent::Create.as_str(), "create");
    }

    use proptest::prelude::*;

    proptest! {
        #![proptest_config(crate::proptest_util::cases(32))]
        fn excerpt_never_exceeds_cap(s in ".*") {
            let out = excerpt_text(&s);
            let max = EXCERPT_MAX_CHARS + usize::from(s.trim().chars().count() > EXCERPT_MAX_CHARS);
            prop_assert!(out.chars().count() <= max);
        }

        fn actor_never_in_filtered_ids(
            ids in prop::collection::vec(1u64..200, 0..12),
            actor in 1u64..200,
        ) {
            let out = filter_recipient_ids(&ids, actor, true);
            prop_assert!(!out.contains(&actor));
        }

        fn audiences_respect_event_lists(
            include_support in any::<bool>(),
            include_company in any::<bool>(),
            kind in 0u8..4,
        ) {
            let event = match kind {
                0 => NotifyEvent::Create,
                1 => NotifyEvent::Comment,
                2 => NotifyEvent::SupportComment,
                _ => NotifyEvent::Status,
            };
            let token = event.as_str().to_owned();
            let cfg = IssuesNotifyConfig {
                support_events: if include_support {
                    vec![token.clone()]
                } else {
                    vec![]
                },
                company_events: if include_company {
                    vec![token]
                } else {
                    vec![]
                },
                ..IssuesNotifyConfig::default()
            };
            let a = notify_audiences(event, &cfg);
            prop_assert_eq!(a.support, include_support);
            prop_assert_eq!(a.company, include_company);
        }
    }

    #[test]
    fn battle_filter_recipients_under_contention() {
        let barrier = Arc::new(Barrier::new(8));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                for _ in 0..200 {
                    let out = filter_recipient_ids(&[1, 2, 3, 1], 2, true);
                    assert_eq!(out, vec![1, 3]);
                    assert!(
                        !notify_audiences(NotifyEvent::Status, &IssuesNotifyConfig::silent())
                            .support
                    );
                }
            }));
        }
        for h in handles {
            h.join().expect("battle thread");
        }
    }
}
