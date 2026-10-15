use crate::support::Ctx;
use anyhow::{Result, ensure};

/// Boot noise is judged by the sentinel after this (empty) scenario; the
/// health page must also render for an anonymous browser.
pub async fn boot_is_clean(cx: &Ctx<'_>) -> Result<()> {
    cx.browser.goto("/health").await?;
    let body = cx.browser.driver.source().await?;
    ensure!(body.contains(">OK<"), "health: {body}");
    Ok(())
}
