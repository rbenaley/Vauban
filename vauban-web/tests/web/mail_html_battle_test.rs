//! Concurrent render of the 14 catalogue events.

use std::sync::{Arc, Barrier};
use std::thread;

use chrono::DateTime;
use uuid::Uuid;
use vauban_web::services::mailer::{
    AccessRequestApprovedEvent, AccessRequestExpiredEvent, AccessRequestRejectedEvent,
    AccessRequestRevokedEvent, AccessRequestSubmittedEvent, EmailEvent, EmailRecipient,
    IacsOffboardedEvent, IacsOnboardApprovedEvent, IacsOnboardRejectedEvent,
    IacsOnboardSubmittedEvent, SecurityMonoAdminDetectedEvent, UserCreatedEvent,
    UserLockedAfterFailedAttemptsEvent, UserMfaResetByAdminEvent, UserPasswordResetRequestedEvent,
};

fn recipient() -> EmailRecipient {
    EmailRecipient::new("alice@example.test", "Alice")
}

fn catalogue() -> Vec<EmailEvent> {
    vec![
        EmailEvent::AccessRequestSubmitted(AccessRequestSubmittedEvent {
            event_id: Uuid::nil(),
            recipient: recipient(),
            requester_username: "bob".into(),
            asset_name: "prod-db-01".into(),
            protocol: "ssh".into(),
            justification: Some("why".into()),
            approval_url: "https://vauban.test/a".into(),
            base_url: "https://vauban.test".into(),
            from_brand: "Vauban PAM".into(),
        }),
        EmailEvent::AccessRequestApproved(AccessRequestApprovedEvent {
            event_id: Uuid::nil(),
            recipient: recipient(),
            asset_name: "prod-db-01".into(),
            protocol: "ssh".into(),
            approver_username: "admin".into(),
            session_url: "https://vauban.test/s".into(),
            valid_until: None,
            base_url: "https://vauban.test".into(),
            from_brand: "Vauban PAM".into(),
        }),
        EmailEvent::AccessRequestRejected(AccessRequestRejectedEvent {
            event_id: Uuid::nil(),
            recipient: recipient(),
            asset_name: "prod-db-01".into(),
            protocol: "ssh".into(),
            approver_username: "admin".into(),
            reason: Some("no".into()),
            base_url: "https://vauban.test".into(),
            from_brand: "Vauban PAM".into(),
        }),
        EmailEvent::AccessRequestRevoked(AccessRequestRevokedEvent {
            event_id: Uuid::nil(),
            recipient: recipient(),
            asset_name: "prod-db-01".into(),
            protocol: "ssh".into(),
            approver_username: "admin".into(),
            reason: None,
            base_url: "https://vauban.test".into(),
            from_brand: "Vauban PAM".into(),
        }),
        EmailEvent::AccessRequestExpired(AccessRequestExpiredEvent {
            event_id: Uuid::nil(),
            recipient: recipient(),
            requester_username: "bob".into(),
            asset_name: "prod-db-01".into(),
            protocol: "ssh".into(),
            base_url: "https://vauban.test".into(),
            from_brand: "Vauban PAM".into(),
        }),
        EmailEvent::UserCreated(UserCreatedEvent {
            event_id: Uuid::nil(),
            recipient: recipient(),
            username: "alice".into(),
            created_by: "admin".into(),
            login_url: "https://vauban.test/login".into(),
            base_url: "https://vauban.test".into(),
            from_brand: "Vauban PAM".into(),
        }),
        EmailEvent::UserPasswordResetRequested(UserPasswordResetRequestedEvent {
            event_id: Uuid::nil(),
            recipient: recipient(),
            username: "alice".into(),
            reset_url: "https://vauban.test/reset".into(),
            valid_until: DateTime::from_timestamp(1_700_000_000, 0).expect("fixed ts"),
            base_url: "https://vauban.test".into(),
            from_brand: "Vauban PAM".into(),
        }),
        EmailEvent::UserLockedAfterFailedAttempts(UserLockedAfterFailedAttemptsEvent {
            event_id: Uuid::nil(),
            recipient: recipient(),
            username: "alice".into(),
            failed_attempts: 5,
            locked_until: None,
            base_url: "https://vauban.test".into(),
            from_brand: "Vauban PAM".into(),
        }),
        EmailEvent::UserMfaResetByAdmin(UserMfaResetByAdminEvent {
            event_id: Uuid::nil(),
            recipient: recipient(),
            username: "alice".into(),
            admin_username: "admin".into(),
            base_url: "https://vauban.test".into(),
            from_brand: "Vauban PAM".into(),
        }),
        EmailEvent::SecurityMonoAdminDetected(SecurityMonoAdminDetectedEvent {
            event_id: Uuid::nil(),
            recipient: recipient(),
            remaining_admin_username: "carol".into(),
            base_url: "https://vauban.test".into(),
            from_brand: "Vauban PAM".into(),
        }),
        EmailEvent::IacsOnboardSubmitted(IacsOnboardSubmittedEvent {
            event_id: Uuid::nil(),
            recipient: recipient(),
            requester_username: "bob".into(),
            ews_name: "ews".into(),
            fingerprint: "ab".into(),
            justification: None,
            admin_url: "https://vauban.test/i".into(),
            base_url: "https://vauban.test".into(),
            from_brand: "Vauban PAM".into(),
        }),
        EmailEvent::IacsOnboardApproved(IacsOnboardApprovedEvent {
            event_id: Uuid::nil(),
            recipient: recipient(),
            ews_name: "ews".into(),
            fingerprint: "ab".into(),
            approver_username: "carol".into(),
            my_requests_url: "https://vauban.test/my".into(),
            base_url: "https://vauban.test".into(),
            from_brand: "Vauban PAM".into(),
        }),
        EmailEvent::IacsOnboardRejected(IacsOnboardRejectedEvent {
            event_id: Uuid::nil(),
            recipient: recipient(),
            ews_name: "ews".into(),
            approver_username: "carol".into(),
            reason: "no".into(),
            my_requests_url: "https://vauban.test/my".into(),
            base_url: "https://vauban.test".into(),
            from_brand: "Vauban PAM".into(),
        }),
        EmailEvent::IacsOffboarded(IacsOffboardedEvent {
            event_id: Uuid::nil(),
            recipient: recipient(),
            ews_name: "ews".into(),
            fingerprint: "ab".into(),
            admin_username: "carol".into(),
            base_url: "https://vauban.test".into(),
            from_brand: "Vauban PAM".into(),
        }),
    ]
}

#[test]
fn battle_render_catalogue_under_contention() {
    let sequential: Vec<(String, String)> = catalogue()
        .into_iter()
        .map(|e| {
            let r = e.render().expect("render");
            (e.kind().to_string(), r.body_html.expect("html"))
        })
        .collect();
    assert_eq!(sequential.len(), 14);

    let barrier = Arc::new(Barrier::new(8));
    let mut handles = Vec::new();
    for _ in 0..8 {
        let barrier = Arc::clone(&barrier);
        let expected = sequential.clone();
        handles.push(thread::spawn(move || {
            barrier.wait();
            for _ in 0..16 {
                let got: Vec<(String, String)> = catalogue()
                    .into_iter()
                    .map(|e| {
                        let r = e.render().expect("render");
                        (e.kind().to_string(), r.body_html.expect("html"))
                    })
                    .collect();
                assert_eq!(got, expected);
            }
        }));
    }
    for h in handles {
        h.join().expect("battle thread");
    }
}
