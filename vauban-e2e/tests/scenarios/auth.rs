use crate::support::{Ctx, SEED_PASSWORD};
use anyhow::{Result, ensure};

const SEEDED: &[&str] = &["admin", "operator1", "operator2", "user1", "user2"];
const LOGOUT: &str = "form[action='/auth/logout'] button[type='submit']";

pub async fn login_page_renders(cx: &Ctx<'_>) -> Result<()> {
    let b = cx.browser;
    b.goto("/").await?;
    ensure!(
        b.path().await? == "/login",
        "anonymous / must land on /login"
    );
    b.el("#username").await?;
    b.el("#password").await?;
    b.el("#login-form button[type='submit']").await?;
    Ok(())
}

pub async fn wrong_password_stays_on_login(cx: &Ctx<'_>) -> Result<()> {
    let b = cx.browser;
    b.goto("/login").await?;
    b.fill("#username", "admin").await?;
    b.fill("#password", "definitely-not-the-password").await?;
    b.click("#login-form button[type='submit']").await?;
    let text = b
        .el("#login-result .bg-red-50, #login-result.bg-red-50")
        .await?
        .text()
        .await?;
    ensure!(
        text.contains("Incorrect username or password"),
        "generic failure message expected, got: {text:?}"
    );
    ensure!(b.path().await? == "/login");
    Ok(())
}

/// First login of every seeded account goes through TOTP enrolment.
pub async fn every_seeded_account_enrols_mfa_and_logs_in(cx: &Ctx<'_>) -> Result<()> {
    let b = cx.browser;
    for user in SEEDED {
        b.reset().await?;
        b.login(user, SEED_PASSWORD).await?;
        ensure!(b.has_mfa(user), "{user} was never asked to enrol TOTP");
        let path = b.path().await?;
        ensure!(
            path == "/" || path == "/dashboard",
            "{user} landed on {path}"
        );
    }
    Ok(())
}

pub async fn second_login_asks_for_the_totp_code(cx: &Ctx<'_>) -> Result<()> {
    let b = cx.browser;
    b.as_user("operator1").await?;
    b.reset().await?;
    b.goto("/login").await?;
    b.fill("#username", "operator1").await?;
    b.fill("#password", SEED_PASSWORD).await?;
    b.click("#login-form button[type='submit']").await?;
    b.wait_path_is("/mfa/verify").await?;
    b.reset().await?;
    b.login("operator1", SEED_PASSWORD).await?;
    ensure!(
        !b.path().await?.starts_with("/mfa"),
        "TOTP verify did not finish"
    );
    Ok(())
}

pub async fn wrong_totp_code_is_rejected(cx: &Ctx<'_>) -> Result<()> {
    let b = cx.browser;
    b.as_user("user1").await?;
    b.reset().await?;
    b.goto("/login").await?;
    b.fill("#username", "user1").await?;
    b.fill("#password", SEED_PASSWORD).await?;
    b.click("#login-form button[type='submit']").await?;
    b.wait_path_is("/mfa/verify").await?;
    b.fill("#totp_code", "000000").await?;
    b.click("form[action='/mfa/verify'] button[type='submit']")
        .await?;
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    ensure!(
        b.path().await? == "/mfa/verify",
        "a wrong code must not sign in"
    );
    b.goto("/dashboard").await?;
    ensure!(
        b.path().await?.starts_with("/login") || b.path().await? == "/mfa/verify",
        "half-authenticated session reached the dashboard"
    );
    Ok(())
}

pub async fn logout_returns_to_login(cx: &Ctx<'_>) -> Result<()> {
    let b = cx.browser;
    b.as_user("admin").await?;
    if !b
        .driver
        .find(thirtyfour::By::Css(LOGOUT))
        .await?
        .is_displayed()
        .await?
    {
        b.click_xpath(
            "//form[@action='/auth/logout']/ancestor::div[@x-data][1]/button[@type='button']",
        )
        .await?;
    }
    b.click(LOGOUT).await?;
    b.wait_path_is("/login").await?;
    b.goto("/dashboard").await?;
    ensure!(
        b.path().await? == "/login",
        "session must be gone after logout"
    );
    Ok(())
}
