use topcoat::{
    Result,
    view::{View, component, view},
};

/// Inner 404 copy (layouts set [`topcoat::router::StatusCode::NOT_FOUND`]).
#[component]
pub async fn branded_404_body() -> Result<impl View> {
    Ok(view! {
        <div class="vb-panel" data-vcp-404="1" style="padding: 24px;">
            <h1>"Page not found"</h1>
            <p class="vb-muted">"This URL is not a Vauban Portal page."</p>
        </div>
    })
}
