//! Article modal at `/{org}/docs/{doc}` — Concept overlay over the docs list.

use topcoat::{
    Result,
    context::Cx,
    router::{forbidden, page, path_param},
    view::view,
};

use super::{DocsFilter, docs_list_view, load_filtered_docs};
use crate::{
    app::org::Org,
    auth::require_org,
    layout::{self, NavSection},
    models::DocArticle,
    perms::perms_for_user,
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
    let articles = DocArticle::all()
        .exec(&mut database)
        .await
        .unwrap_or_default();
    let Some(article) = articles.into_iter().find(|a| a.slug == *doc_slug) else {
        return Err(topcoat::router::not_found().into());
    };

    let (q, cat, filtered) = load_filtered_docs(cx, &DocsFilter::from_cx(cx)).await;
    let body = docs_list_view(cx, org_slug, &q, &cat, &filtered).await;
    let close_href = format!("/{org_slug}/docs");
    let modal = article_modal(cx, &article, org_slug, &close_href).await;

    layout::shell_with_modal(
        cx,
        &ctx,
        &perms,
        NavSection::Docs,
        "documentation",
        body,
        modal,
    )
    .await
}

async fn article_modal(cx: &Cx, article: &DocArticle, org_slug: &str, close_href: &str) -> Result {
    let close = close_href.to_owned();
    let close2 = close.clone();
    let cat = article.category.clone();
    let version = article.version.clone();
    let title = article.title.clone();
    let summary = article.summary.clone();
    let slug = article.slug.clone();
    let org = org_slug.to_owned();
    let blocks = article_blocks(cx, &slug, &summary, &org).await;

    view! { cx =>
        <div class="vb-modal-root" role="dialog" aria-modal="true" aria-label=(title.clone())>
            <a class="vb-modal-backdrop" href=(close.clone()) aria-label="Close article"></a>
            <div class="vb-modal">
                <div class="vb-modal-head">
                    <div>
                        <div class="vb-mono" style="font-size: 10px; color: var(--accent); letter-spacing: 0.06em; margin-bottom: 8px;">
                            (cat)
                            " · Updated "
                            (version)
                        </div>
                        <h2 style="font-size: 23px; font-weight: 800; margin: 0; line-height: 1.25;">
                            (title)
                        </h2>
                    </div>
                    <a class="vb-modal-close" href=(close2) aria-label="Close">"✕"</a>
                </div>
                <div class="vb-modal-body">
                    (blocks?)
                </div>
            </div>
        </div>
    }
}

async fn article_blocks(cx: &Cx, slug: &str, summary: &str, org_slug: &str) -> Result {
    if slug == "quick-start" {
        return view! { cx =>
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
                <li>"Use stable DNS names rather than IP addresses so policies survive re-addressing."</li>
                <li>"Group by blast radius (production, staging, pci) — not by team."</li>
                <li>"A host can belong to several groups; the most restrictive policy wins."</li>
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
                <li>"Deploy a second node behind a TCP load balancer for high availability."</li>
            </ul>
        };
    }

    let summary = summary.to_owned();
    let org = org_slug.to_owned();
    view! { cx =>
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
