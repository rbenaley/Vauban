//! Queue MCP HITL / contestation emails through the existing outbox.
//!
//! Web INSERTs `email_outbox` only. SMTP stays in sealed `vauban-mailer`.
//! Reviewers = `load_approver_contacts` minus the author (SoD). Decision
//! mails go to the requester / opener when `requester_may_receive_mail`.
//! Best-effort: callers log and never fail the business action.

use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use uuid::Uuid;

use crate::AppState;
use crate::models::access_contestation::AccessContestation;
use crate::schema::{assets, proxy_sessions, users};
use crate::services::mailer::{
    EmailEvent, EmailRecipient, McpContestationOpenedEvent, McpContestationResolvedEvent,
    McpHitlDecidedEvent, McpHitlPendingEvent, McpMandateDriftEvent, deterministic_event_id,
};
use crate::services::user_status::{load_approver_contacts, requester_may_receive_mail};
use shared::mcp_drift_iam::McpDriftIam;

/// Drop the author from the reviewer pool (SoD: no self-notify).
pub(crate) fn exclude_author(
    contacts: Vec<(String, String)>,
    exclude_username: Option<&str>,
    exclude_email: Option<&str>,
) -> Vec<(String, String)> {
    contacts
        .into_iter()
        .filter(|(email, username)| {
            if let Some(u) = exclude_username
                && username == u
            {
                return false;
            }
            if let Some(e) = exclude_email
                && email.eq_ignore_ascii_case(e)
            {
                return false;
            }
            true
        })
        .collect()
}

pub async fn queue_hitl_pending(
    state: &AppState,
    session_id: &str,
    pending_id: &str,
    tool: &str,
    requester_user_id: &str,
    has_mission_seal: bool,
) -> Result<(), String> {
    if !state.mailer.is_enabled() {
        return Ok(());
    }

    let mut conn = state.db_pool.get().await.map_err(|e| e.to_string())?;
    let (requester_username, requester_email) =
        lookup_user_by_uuid(&mut conn, requester_user_id).await;
    let asset_name = lookup_asset_name(&mut conn, session_id).await;
    let approvers = load_approver_contacts(&mut conn)
        .await
        .map_err(|e| format!("approver lookup: {e}"))?;
    drop(conn);

    let approvers = exclude_author(
        approvers,
        Some(requester_username.as_str()),
        Some(requester_email.as_str()),
    );
    if approvers.is_empty() {
        return Ok(());
    }

    let review_url = format!("{}/sessions/mcp", state.config.mailer.base_url);
    let business_key = format!("hitl_pending:{pending_id}");
    let mut queued = 0usize;
    let mut duplicates = 0usize;
    let mut errors: Vec<String> = Vec::new();
    let mut recipients: Vec<EmailRecipient> = Vec::new();
    for (email, username) in approvers {
        let recipient = EmailRecipient::new(email.clone(), username);
        recipients.push(recipient.clone());
        let event_id = deterministic_event_id("mcp.hitl_pending", &business_key, &email);
        let event = EmailEvent::McpHitlPending(McpHitlPendingEvent {
            event_id,
            recipient,
            requester_username: requester_username.clone(),
            asset_name: asset_name.clone(),
            tool: tool.to_string(),
            has_mission_seal,
            review_url: review_url.clone(),
            base_url: state.config.mailer.base_url.clone(),
            from_brand: state.config.mailer.from_name.clone(),
        });
        let mut conn = state.db_pool.get().await.map_err(|e| e.to_string())?;
        match state.mailer.queue(&mut conn, &event).await {
            Ok(()) => queued += 1,
            Err(crate::services::mailer::MailerError::Duplicate) => duplicates += 1,
            Err(e) => errors.push(format!("{email}: {e}")),
        }
    }
    crate::services::mailer::log_emails_queued(
        "mcp.hitl_pending",
        &recipients,
        queued,
        duplicates,
        &errors,
    );
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

pub async fn queue_hitl_decided(
    state: &AppState,
    session_id: &str,
    pending_id: &str,
    tool: &str,
    requester_user_id: &str,
    decision: &str,
    decider_username: &str,
) -> Result<(), String> {
    if !state.mailer.is_enabled() {
        return Ok(());
    }

    let decision_label = match decision {
        "approve" => "approved",
        "deny" => "denied",
        other => other,
    };

    let mut conn = state.db_pool.get().await.map_err(|e| e.to_string())?;
    let Some((email, _username, active, deleted)) =
        load_user_mail_by_uuid(&mut conn, requester_user_id).await
    else {
        return Ok(());
    };
    if !requester_may_receive_mail(active, deleted, &email) {
        return Ok(());
    }
    let asset_name = lookup_asset_name(&mut conn, session_id).await;
    drop(conn);

    let recipient = EmailRecipient::bare(&email);
    let business_key = format!("hitl_decided:{pending_id}:{decision_label}");
    let event_id = deterministic_event_id("mcp.hitl_decided", &business_key, &email);
    let event = EmailEvent::McpHitlDecided(McpHitlDecidedEvent {
        event_id,
        recipient,
        asset_name,
        tool: tool.to_string(),
        decision: decision_label.to_string(),
        decider_username: decider_username.to_string(),
        review_url: format!("{}/sessions/mcp", state.config.mailer.base_url),
        base_url: state.config.mailer.base_url.clone(),
        from_brand: state.config.mailer.from_name.clone(),
    });
    queue_one(state, event).await
}

pub async fn queue_contestation_opened(
    state: &AppState,
    row: &AccessContestation,
    opener_username: &str,
) -> Result<(), String> {
    if !state.mailer.is_enabled() {
        return Ok(());
    }

    let mut conn = state.db_pool.get().await.map_err(|e| e.to_string())?;
    let opener_email = load_user_mail_by_id(&mut conn, row.opened_by_id)
        .await
        .map(|(email, _, _, _)| email)
        .unwrap_or_default();
    let approvers = load_approver_contacts(&mut conn)
        .await
        .map_err(|e| format!("approver lookup: {e}"))?;
    drop(conn);

    let approvers = exclude_author(
        approvers,
        Some(opener_username),
        Some(opener_email.as_str()),
    );
    if approvers.is_empty() {
        return Ok(());
    }

    let review_url = format!(
        "{}/sessions/mcp/contestations/{}",
        state.config.mailer.base_url, row.uuid
    );
    let business_key = format!("contestation_opened:{}", row.uuid);
    let mut queued = 0usize;
    let mut duplicates = 0usize;
    let mut errors: Vec<String> = Vec::new();
    let mut recipients: Vec<EmailRecipient> = Vec::new();
    for (email, username) in approvers {
        let recipient = EmailRecipient::new(email.clone(), username);
        recipients.push(recipient.clone());
        let event_id = deterministic_event_id("mcp.contestation_opened", &business_key, &email);
        let event = EmailEvent::McpContestationOpened(McpContestationOpenedEvent {
            event_id,
            recipient,
            opener_username: opener_username.to_string(),
            decision_id: row.decision_id.clone(),
            session_uuid: row.session_uuid.to_string(),
            review_url: review_url.clone(),
            base_url: state.config.mailer.base_url.clone(),
            from_brand: state.config.mailer.from_name.clone(),
        });
        let mut conn = state.db_pool.get().await.map_err(|e| e.to_string())?;
        match state.mailer.queue(&mut conn, &event).await {
            Ok(()) => queued += 1,
            Err(crate::services::mailer::MailerError::Duplicate) => duplicates += 1,
            Err(e) => errors.push(format!("{email}: {e}")),
        }
    }
    crate::services::mailer::log_emails_queued(
        "mcp.contestation_opened",
        &recipients,
        queued,
        duplicates,
        &errors,
    );
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

pub async fn queue_contestation_resolved(
    state: &AppState,
    row: &AccessContestation,
    reviewer_username: &str,
    outcome: &str,
) -> Result<(), String> {
    if !state.mailer.is_enabled() {
        return Ok(());
    }

    let mut conn = state.db_pool.get().await.map_err(|e| e.to_string())?;
    let opener = load_user_mail_by_id(&mut conn, row.opened_by_id).await;
    let subject = if row.subject_user_id != row.opened_by_id {
        load_user_mail_by_id(&mut conn, row.subject_user_id).await
    } else {
        None
    };
    drop(conn);

    let review_url = format!(
        "{}/sessions/contestations/{}",
        state.config.mailer.base_url, row.uuid
    );
    let mut targets: Vec<(String, String)> = Vec::new();
    if let Some((email, _, active, deleted)) = opener
        && requester_may_receive_mail(active, deleted, &email)
    {
        targets.push((
            email,
            format!("contestation_resolved:{}:{outcome}", row.uuid),
        ));
    }
    if let Some((email, _, active, deleted)) = subject
        && requester_may_receive_mail(active, deleted, &email)
    {
        targets.push((
            email,
            format!("contestation_resolved:{}:{outcome}:subject", row.uuid),
        ));
    }
    if targets.is_empty() {
        return Ok(());
    }

    let mut errors: Vec<String> = Vec::new();
    for (email, business_key) in targets {
        let recipient = EmailRecipient::bare(&email);
        let event_id = deterministic_event_id("mcp.contestation_resolved", &business_key, &email);
        let event = EmailEvent::McpContestationResolved(McpContestationResolvedEvent {
            event_id,
            recipient,
            outcome: outcome.to_string(),
            reviewer_username: reviewer_username.to_string(),
            decision_id: row.decision_id.clone(),
            review_url: review_url.clone(),
            base_url: state.config.mailer.base_url.clone(),
            from_brand: state.config.mailer.from_name.clone(),
        });
        if let Err(e) = queue_one(state, event).await {
            errors.push(format!("{email}: {e}"));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

pub async fn queue_mandate_drift(
    state: &AppState,
    session_id: &str,
    tool: &str,
    reason: &str,
    mandate_id: &str,
    requester_user_id: &str,
    iam: McpDriftIam,
) -> Result<(), String> {
    if !state.mailer.is_enabled() {
        return Ok(());
    }

    let mut conn = state.db_pool.get().await.map_err(|e| e.to_string())?;
    let (requester_username, requester_email, req_active, req_deleted) =
        match load_user_mail_by_uuid(&mut conn, requester_user_id).await {
            Some((email, username, active, deleted)) => (username, email, active, deleted),
            None => (requester_user_id.to_string(), String::new(), false, true),
        };
    let approvers = load_approver_contacts(&mut conn)
        .await
        .map_err(|e| format!("approver lookup: {e}"))?;
    drop(conn);

    let session_url = format!("{}/sessions/{session_id}", state.config.mailer.base_url);
    let key = if mandate_id.trim().is_empty() {
        session_id.to_string()
    } else {
        mandate_id.to_string()
    };
    let business_key = format!("mandate_drift:{key}");

    let mut contacts = exclude_author(
        approvers,
        Some(requester_username.as_str()),
        Some(requester_email.as_str()),
    );
    if requester_may_receive_mail(req_active, req_deleted, &requester_email) {
        contacts.push((requester_email.clone(), requester_username.clone()));
    }
    if contacts.is_empty() {
        return Ok(());
    }

    let mut queued = 0usize;
    let mut duplicates = 0usize;
    let mut errors: Vec<String> = Vec::new();
    let mut recipients: Vec<EmailRecipient> = Vec::new();
    for (email, username) in contacts {
        let recipient = EmailRecipient::new(email.clone(), username);
        recipients.push(recipient.clone());
        let event_id = deterministic_event_id("mcp.mandate_drift", &business_key, &email);
        let event = EmailEvent::McpMandateDrift(McpMandateDriftEvent {
            event_id,
            recipient,
            requester_username: requester_username.clone(),
            tool: tool.to_string(),
            reason: reason.to_string(),
            iam_consequence: iam.mail_consequence().to_string(),
            session_url: session_url.clone(),
            base_url: state.config.mailer.base_url.clone(),
            from_brand: state.config.mailer.from_name.clone(),
        });
        let mut conn = state.db_pool.get().await.map_err(|e| e.to_string())?;
        match state.mailer.queue(&mut conn, &event).await {
            Ok(()) => queued += 1,
            Err(crate::services::mailer::MailerError::Duplicate) => duplicates += 1,
            Err(e) => errors.push(format!("{email}: {e}")),
        }
    }
    crate::services::mailer::log_emails_queued(
        "mcp.mandate_drift",
        &recipients,
        queued,
        duplicates,
        &errors,
    );
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

async fn queue_one(state: &AppState, event: EmailEvent) -> Result<(), String> {
    let kind = event.kind();
    let recipient = event.recipient().clone();
    let mut conn = state.db_pool.get().await.map_err(|e| e.to_string())?;
    let (queued, duplicates, errors) = match state.mailer.queue(&mut conn, &event).await {
        Ok(()) => (1, 0, Vec::new()),
        Err(crate::services::mailer::MailerError::Duplicate) => (0, 1, Vec::new()),
        Err(e) => (0, 0, vec![e.to_string()]),
    };
    crate::services::mailer::log_emails_queued(
        kind,
        std::slice::from_ref(&recipient),
        queued,
        duplicates,
        &errors,
    );
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

async fn lookup_asset_name(conn: &mut diesel_async::AsyncPgConnection, session_id: &str) -> String {
    let Ok(su) = Uuid::parse_str(session_id) else {
        return "MCP session".into();
    };
    proxy_sessions::table
        .inner_join(assets::table.on(assets::id.eq(proxy_sessions::asset_id)))
        .filter(proxy_sessions::uuid.eq(su))
        .select(assets::name)
        .first::<String>(conn)
        .await
        .unwrap_or_else(|_| "MCP session".into())
}

async fn lookup_user_by_uuid(
    conn: &mut diesel_async::AsyncPgConnection,
    user_uuid: &str,
) -> (String, String) {
    match load_user_mail_by_uuid(conn, user_uuid).await {
        Some((email, username, _, _)) => (username, email),
        None => (user_uuid.to_string(), String::new()),
    }
}

async fn load_user_mail_by_uuid(
    conn: &mut diesel_async::AsyncPgConnection,
    user_uuid: &str,
) -> Option<(String, String, bool, bool)> {
    let uid = Uuid::parse_str(user_uuid).ok()?;
    users::table
        .filter(users::uuid.eq(uid))
        .select((
            users::email,
            users::username,
            users::is_active,
            users::is_deleted,
        ))
        .first(conn)
        .await
        .ok()
}

async fn load_user_mail_by_id(
    conn: &mut diesel_async::AsyncPgConnection,
    user_id: i32,
) -> Option<(String, String, bool, bool)> {
    users::table
        .filter(users::id.eq(user_id))
        .select((
            users::email,
            users::username,
            users::is_active,
            users::is_deleted,
        ))
        .first(conn)
        .await
        .ok()
}

#[cfg(test)]
mod tests {
    use super::exclude_author;

    #[test]
    fn exclude_author_drops_matching_username_and_email() {
        let contacts = vec![
            ("alice@x.test".into(), "alice".into()),
            ("bob@x.test".into(), "bob".into()),
            ("carol@x.test".into(), "carol".into()),
        ];
        let by_name = exclude_author(contacts.clone(), Some("bob"), None);
        assert_eq!(by_name.len(), 2);
        assert!(by_name.iter().all(|(_, u)| u != "bob"));

        let by_email = exclude_author(contacts, None, Some("ALICE@x.test"));
        assert_eq!(by_email.len(), 2);
        assert!(
            by_email
                .iter()
                .all(|(e, _)| !e.eq_ignore_ascii_case("alice@x.test"))
        );
    }

    #[test]
    fn helper_uses_approver_pool_and_requester_mail_gate() {
        let src = include_str!("mcp_mail.rs");
        let prod = src.split("#[cfg(test)]").next().unwrap_or(src);
        assert!(
            prod.contains("load_approver_contacts"),
            "MCP reviewer mail must use load_approver_contacts"
        );
        assert!(
            prod.contains("requester_may_receive_mail"),
            "MCP decision mail must skip empty / unusable mailboxes"
        );
        assert!(
            prod.contains("exclude_author"),
            "MCP reviewer mail must exclude the author (SoD)"
        );
        assert!(
            !prod.contains("lettre::") && !prod.contains("connect("),
            "web must not speak SMTP"
        );
    }
}
