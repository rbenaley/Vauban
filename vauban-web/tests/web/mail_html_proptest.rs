//! Property tests: user-controlled mail fields cannot inject markup.

use proptest::prelude::*;
use vauban_web::services::mail_templates::{
    ACCESS_REQUEST_REJECTED_HTML, ACCESS_REQUEST_SUBMITTED_HTML, IACS_ONBOARD_SUBMITTED_HTML,
    RenderSpec, field, render_event,
};

fn no_injection(html: &str) {
    assert!(!html.contains("<script"));
    assert!(!html.contains("onerror="));
    assert!(!html.contains("javascript:"));
    assert!(!html.contains("__BRAND__"));
    assert!(!html.contains("__ASSET__"));
    assert!(!html.contains("__REASON__"));
    assert!(!html.contains("__FACTS_BLOCK__"));
    assert!(!html.contains("__DANGER_BLOCK__"));
    assert!(!html.contains("__NOTICE_BLOCK__"));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn rejected_html_escapes_hostile_fields(
        asset in "\\PC{0,80}",
        protocol in "\\PC{0,20}",
        approver in "\\PC{0,40}",
        reason in "\\PC{0,120}",
        brand in "\\PC{1,24}",
    ) {
        let fields = [
            field("__ASSET__", &asset),
            field("__PROTOCOL__", &protocol),
            field("__APPROVER__", &approver),
        ];
        let html = render_event(
            ACCESS_REQUEST_REJECTED_HTML,
            RenderSpec {
                brand: &brand,
                base_url: "https://vauban.test",
                fields: &fields,
                facts: &[("Asset", asset.as_str()), ("Protocol", protocol.as_str())],
                notice: None,
                info: None,
                danger: Some(reason.as_str()),
                cta: None,
            },
        );
        no_injection(&html);
    }

    #[test]
    fn submitted_html_escapes_justification(
        requester in "\\PC{0,40}",
        asset in "\\PC{0,80}",
        justification in "\\PC{0,160}",
    ) {
        let fields = [
            field("__REQUESTER__", &requester),
            field("__ASSET__", &asset),
            field("__PROTOCOL__", "ssh"),
        ];
        let html = render_event(
            ACCESS_REQUEST_SUBMITTED_HTML,
            RenderSpec {
                brand: "Brand",
                base_url: "https://vauban.test",
                fields: &fields,
                facts: &[("Requester", requester.as_str()), ("Asset", asset.as_str())],
                notice: Some(justification.as_str()),
                info: None,
                danger: None,
                cta: Some(("https://vauban.test/a", "Review")),
            },
        );
        no_injection(&html);
    }

    #[test]
    fn iacs_html_escapes_fingerprint_and_ews(
        ews in "\\PC{0,60}",
        fingerprint in "\\PC{0,80}",
        requester in "\\PC{0,40}",
    ) {
        let fields = [
            field("__REQUESTER__", &requester),
            field("__EWS__", &ews),
            field("__FINGERPRINT__", &fingerprint),
        ];
        let html = render_event(
            IACS_ONBOARD_SUBMITTED_HTML,
            RenderSpec {
                brand: "Brand",
                base_url: "https://vauban.test",
                fields: &fields,
                facts: &[
                    ("EWS", ews.as_str()),
                    ("Fingerprint", fingerprint.as_str()),
                ],
                notice: None,
                info: None,
                danger: None,
                cta: Some(("https://vauban.test/i", "Review")),
            },
        );
        no_injection(&html);
    }
}
