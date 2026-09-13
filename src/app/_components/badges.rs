use topcoat::{
    Result,
    context::Cx,
    view::{View, component, view},
};

#[component]
pub async fn severity_badge(cx: &Cx, severity: &str) -> Result<impl View> {
    let class = match severity.to_ascii_lowercase().as_str() {
        "critical" => "vb-sev critical",
        "major" => "vb-sev major",
        _ => "vb-sev minor",
    };
    let label = severity.to_owned();
    Ok(view! { cx => <span class=(class)>(label)</span> })
}

#[component]
pub async fn status_badge(cx: &Cx, status: &str) -> Result<impl View> {
    let class = match status {
        "In analysis" => "vb-status analysis",
        "Resolved" | "Closed" => "vb-status resolved",
        _ => "vb-status open",
    };
    let label = status.to_owned();
    Ok(view! { cx => <span class=(class)>(label)</span> })
}
