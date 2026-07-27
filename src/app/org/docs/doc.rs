//! Article modal at `/{org}/docs/{doc}` — Concept overlay over the docs list.

use topcoat::{
    Result,
    context::Cx,
    router::{forbidden, not_found, page, path_param},
    view::view,
};

use super::{DocsFilter, docs_list_view};
use crate::{
    app::_components::article_modal_shell,
    app::org::Org,
    auth::require_org,
    models::{DOC_STATUS_PUBLISHED, DocArticle},
    perms::perms_for_user,
    tz::{browser_tz, format_unix_local, unix_rfc3339},
};

#[path_param]
struct Doc(str);

#[page]
async fn doc_article_page(cx: &Cx) -> Result {
    let org_slug = path_param::<Org>(cx);
    let doc_slug = path_param::<Doc>(cx);
    let ctx = require_org(cx, org_slug).await?;
    let perms = perms_for_user(cx, &ctx.user).await;
    if !perms.docs_read {
        return Err(forbidden().into());
    }

    let mut database = crate::auth::db(cx);
    let slug_key = doc_slug.to_string();
    let Some(article) = DocArticle::all()
        .filter(DocArticle::fields().slug().eq(&slug_key))
        .include(DocArticle::fields().body())
        .exec(&mut database)
        .await
        .ok()
        .and_then(|mut rows| rows.pop())
    else {
        return Err(not_found().into());
    };
    if article.status != DOC_STATUS_PUBLISHED {
        return Err(not_found().into());
    }

    let filter = DocsFilter::from_cx(cx);
    let list = docs_list_view(cx, org_slug, &filter.q, &filter.cat).await;
    let close_href = format!("/{org_slug}/docs");
    let title = article.title.clone();
    let category = article.category.clone();
    let version = article.version.clone();
    let body_text = article.body.get().clone();
    let summary = article.summary.clone();
    let slug = article.slug.clone();
    let tz = browser_tz(cx);
    let updated = format_unix_local(article.updated_at, tz);
    let updated_rfc = unix_rfc3339(article.updated_at);
    let blocks = article_body_view(cx, &slug, &summary, &body_text, org_slug).await;

    view! {
        cx =>
        (list?)
        article_modal_shell(
            title: &title,
            category: &category,
            version: &version,
            close_href: &close_href,
            body: view! {
                cx =>
                <p class="vb-muted" style="font-size: 12px; margin-bottom: 4px;">
                    "Updated "
                    <time datetime=(updated_rfc)>(updated)</time>
                </p>
                (blocks?)
            }
        )
    }
}

/// Prefer Concept-rich HTML for the demo quick-start; otherwise render the
/// persisted plain-text body (admin CRUD). Thin seed placeholders keep the
/// previous Overview / Example scaffold so catalog rows still look intentional.
async fn article_body_view(
    cx: &Cx,
    slug: &str,
    summary: &str,
    body: &str,
    org_slug: &str,
) -> Result {
    if slug == "quick-start" && is_seed_placeholder_or_outline(body, summary) {
        return quick_start_blocks(cx).await;
    }
    if is_seed_placeholder_or_outline(body, summary) {
        return placeholder_blocks(cx, summary, org_slug).await;
    }
    plain_body_blocks(cx, body).await
}

fn is_seed_placeholder_or_outline(body: &str, summary: &str) -> bool {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return true;
    }
    if trimmed == summary.trim() {
        return true;
    }
    if trimmed.starts_with(summary.trim())
        && trimmed.contains("Full article body will expand as the knowledge base grows.")
    {
        return true;
    }
    // Sparse outline seed used for quick-start before Concept HTML was restored.
    trimmed.starts_with("Vauban ships as a single signed binary.")
        && trimmed.contains("1. Install the binary")
        && !trimmed.contains("vauban server init")
}

async fn quick_start_blocks(cx: &Cx) -> Result {
    view! {
        cx =>
        <p>
            "Vauban ships as a single signed binary. This guide takes you from a fresh host to your first end-to-end recorded SSH session in about fifteen minutes. No agent is installed on the protected machines — every connection is brokered by the bastion."
        </p>
        <div class="vb-callout">
            <span>"⚑"</span>
            <span>
                "You will need: a Linux or FreeBSD host with 2 vCPU / 2 GB RAM, outbound access to your target hosts, and a DNS record pointing at the bastion."
            </span>
        </div>
        <h3>"1. Install the binary"</h3>
        <p>
            "Download the latest LTS build for your platform and verify its signature before running it. The checksum is published alongside each release in the customer portal."
        </p>
        <pre class="vb-pre">
            "$ curl -fsSLO https://vauban.sh/releases/freebsd/15/x86_64/vauban-0.8.6\n$ vauban verify ./vauban-0.8.6\n  signature: OK (key 0xA3F9C1E…)\n$ install -m 0755 vauban-0.8.6 /usr/local/bin/vauban"
        </pre>
        <p>
            "Initialize the server. This generates the host keys, the local policy store, and an admin enrollment token printed once to stdout."
        </p>
        <pre class="vb-pre">
            "$ vauban server init --domain bastion.acme.internal\n  ✓ host keys generated\n  ✓ policy store created at /var/db/vauban\n  admin token: vbn_enroll_8f3a…  (valid 30 min)"
        </pre>
        <h3>"2. Enroll your first target host"</h3>
        <p>
            "A target is any machine your users will reach through the bastion. Register it by address and assign it to a group — groups are what RBAC policies bind to."
        </p>
        <pre class="vb-pre">
            "$ vauban host add db-01.acme.internal \\\n    --group production \\\n    --protocol ssh"
        </pre>
        <ul>
            <li>
                "Use stable DNS names rather than IP addresses so policies survive re-addressing."
            </li>
            <li>
                "Group by blast radius (production, staging, pci) — not by team."
            </li>
            <li>
                "A host can belong to several groups; the most restrictive policy wins."
            </li>
        </ul>
        <h3>"3. Define an access policy"</h3>
        <p>
            "Policies map subjects to the targets and actions they may use. Keep them narrow and compose by inheritance."
        </p>
        <pre class="vb-pre">
            "policy \"oncall-prod\" {\n  subjects = [\"group:on-call\"]\n  targets  = [\"group:production\"]\n  actions  = [\"ssh:shell\"]\n  record   = true\n  mfa      = \"required\"\n}"
        </pre>
        <div class="vb-callout">
            <span>"⚑"</span>
            <span>
                "With record = true, every keystroke and the full TTY stream are captured and signed for audit. Recordings are searchable from the portal."
            </span>
        </div>
        <h3>"4. Open your first session"</h3>
        <p>
            "Point your SSH client at the bastion. Vauban authenticates you, enforces MFA, applies the policy, then transparently proxies you to the target while recording the session."
        </p>
        <pre class="vb-pre">
            "$ ssh db-01.acme.internal@bastion.acme.internal\n  ▸ MFA: approve push on your device… ✓\n  ▸ policy oncall-prod matched · recording on\n  Last login: Fri Jun 20 14:02 2026\n  db-01 $"
        </pre>
        <h3>"Next steps"</h3>
        <ul>
            <li>"Enable WebAuthn hardware keys for privileged sessions."</li>
            <li>"Wire audit events to your SIEM via native export or webhooks."</li>
            <li>
                "Deploy a second node behind a TCP load balancer for high availability."
            </li>
        </ul>
    }
}

async fn placeholder_blocks(cx: &Cx, summary: &str, org_slug: &str) -> Result {
    let summary = summary.to_owned();
    let org = org_slug.to_owned();
    view! {
        cx =>
        <h3>"Overview"</h3>
        <p>(summary.clone())</p>
        <h3>"Example"</h3>
        <pre class="vb-pre">
            "# Install and enroll\nvaubanctl bootstrap --org "
            (org)
            "\nvaubanctl host enroll --token <TOKEN>"
        </pre>
        <div class="vb-callout">
            <span>"⚑"</span>
            <span>
                "Initial analysis and support follow your subscription SLA (2–5 business days)."
            </span>
        </div>
        <p>(summary)</p>
    }
}

async fn plain_body_blocks(cx: &Cx, body: &str) -> Result {
    let paragraphs: Vec<String> = body
        .split("\n\n")
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(str::to_owned)
        .collect();
    view! {
        cx =>
        for p in paragraphs {
            <p style="white-space: pre-wrap;">(p)</p>
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_thin_quick_start_seed_outline() {
        let outline = concat!(
            "Vauban ships as a single signed binary. This guide takes you from a fresh host ",
            "to your first end-to-end recorded SSH session in about fifteen minutes.\n\n",
            "1. Install the binary\n",
            "Download the latest LTS build and verify its signature before running it.\n\n",
            "2. Enroll your first target host\n",
            "Register machines by DNS name and assign them to groups.\n\n",
            "3. Define an access policy\n",
            "Map subjects to targets and actions; keep policies narrow.\n\n",
            "4. Open your first session\n",
            "Point SSH at the bastion. Vauban authenticates, enforces MFA, and records the session."
        );
        assert!(is_seed_placeholder_or_outline(
            outline,
            "Install the bastion, enroll a host, and open a supervised SSH session."
        ));
        assert!(!is_seed_placeholder_or_outline(
            "Custom admin rewrite with vauban server init steps.",
            "summary"
        ));
    }
}
