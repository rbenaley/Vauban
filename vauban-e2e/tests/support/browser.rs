//! Headless Chrome driven over W3C WebDriver (`thirtyfour`), with a probe
//! injected into every document that records JS errors, unhandled
//! rejections, `console.error` and any 5xx seen by fetch / XHR (htmx).

use anyhow::{Context, Result, bail, ensure};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;
use thirtyfour::prelude::*;

use super::SEED_PASSWORD;
use super::totp::Authenticator;

const PROBE: &str = r#"
(() => {
  if (window.__vaubanE2e) return;
  const state = (window.__vaubanE2e = { errors: [] });
  const describe = (v) => {
    if (v instanceof Event) {
      const t = v.target || {};
      return "Event(" + v.type + ") on " + (t.url || t.src || t.tagName || t.constructor?.name || "?");
    }
    if (v instanceof Error) return v.name + ": " + v.message;
    return String(v);
  };
  const push = (kind, msg) =>
    state.errors.push(kind + ": " + describe(msg).slice(0, 500) + " @ " + location.pathname);
  addEventListener("error", (ev) => {
    if (ev.target && ev.target !== window) {
      push("resource", (ev.target.src || ev.target.href || ev.target.tagName) + " failed to load");
    } else {
      push("js", ev.message || ev.type);
    }
  }, true);
  addEventListener("unhandledrejection", (ev) => push("promise", ev.reason));
  const consoleError = console.error;
  console.error = (...args) => { push("console", args.map(describe).join(" ")); consoleError.apply(console, args); };
  const fetch0 = window.fetch;
  if (fetch0) {
    window.fetch = async (...args) => {
      const r = await fetch0(...args);
      if (r.status >= 500) push("http", r.status + " " + r.url);
      return r;
    };
  }
  state.trace = [];
  const trace = (msg) => state.trace.push(Math.round(performance.now()) + "ms " + msg);
  const WS0 = window.WebSocket;
  window.WebSocket = function (url, protocols) {
    const ws = protocols === undefined ? new WS0(url) : new WS0(url, protocols);
    const path = new URL(url, location.href).pathname;
    trace("ws new " + path);
    ws.addEventListener("open", () => trace("ws open " + path));
    ws.addEventListener("error", () => trace("ws error " + path + " readyState=" + ws.readyState));
    ws.addEventListener("close", (e) => trace("ws close " + path + " code=" + e.code + " clean=" + e.wasClean));
    const close0 = ws.close.bind(ws);
    ws.close = (...a) => { trace("ws close() called " + path + " readyState=" + ws.readyState); return close0(...a); };
    return ws;
  };
  window.WebSocket.prototype = WS0.prototype;
  Object.assign(window.WebSocket, { CONNECTING: 0, OPEN: 1, CLOSING: 2, CLOSED: 3 });
  addEventListener("load", () => {
    const nav = performance.getEntriesByType("navigation")[0];
    if (nav && nav.responseStatus >= 500) push("http", nav.responseStatus + " document");
  });
  const open0 = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function (method, url, ...rest) {
    this.addEventListener("loadend", () => {
      if (this.status >= 500) push("http", this.status + " " + method + " " + url);
    });
    return open0.call(this, method, url, ...rest);
  };
})();
"#;

pub struct Browser {
    pub driver: WebDriver,
    origin: String,
    authenticator: Authenticator,
    sessions: Mutex<HashMap<String, Vec<Cookie>>>,
    /// Probe lines of documents already navigated away from.
    pending: Mutex<Vec<String>>,
}

impl Browser {
    pub async fn launch(origin: String) -> Result<Self> {
        let mut caps = DesiredCapabilities::chrome();
        if std::env::var_os("VAUBAN_E2E_HEADED").is_none() {
            caps.set_headless()?;
        }
        caps.accept_insecure_certs(true)?;
        caps.set_ignore_certificate_errors()?;
        caps.set_disable_gpu()?;
        caps.add_arg("--window-size=1440,1000")?;
        let mut manager = WebDriver::managed(caps);
        if let Some(path) = std::env::var_os("VAUBAN_E2E_CHROMEDRIVER") {
            manager = manager
                .driver_binary(thirtyfour::manager::BrowserKind::Chrome, path)
                .offline();
        }
        let driver = manager
            .await
            .context("launch chromedriver + Chrome (thirtyfour manager)")?;
        driver
            .cdp()
            .page()
            .add_script_to_evaluate_on_new_document(PROBE)
            .await?;
        driver.set_implicit_wait_timeout(Duration::ZERO).await?;
        Ok(Self {
            driver,
            origin,
            authenticator: Authenticator::default(),
            sessions: Mutex::new(HashMap::new()),
            pending: Mutex::new(Vec::new()),
        })
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{path}", self.origin)
    }

    pub async fn goto(&self, path: &str) -> Result<()> {
        self.drain_page().await?;
        self.driver.goto(self.url(path)).await?;
        Ok(())
    }

    /// HTTP status of the current document.
    pub async fn status(&self) -> Result<u16> {
        let ret = self
            .driver
            .execute(
                "const n = performance.getEntriesByType('navigation')[0]; return n ? n.responseStatus : 0;",
                Vec::new(),
            )
            .await?;
        Ok(ret.convert()?)
    }

    pub async fn path(&self) -> Result<String> {
        Ok(self.driver.current_url().await?.path().to_string())
    }

    /// Anonymous browser state (probe lines seen so far are kept).
    pub async fn reset(&self) -> Result<()> {
        self.goto("/login").await?;
        self.driver.delete_all_cookies().await?;
        Ok(())
    }

    /// Drop probe lines left by a previous scenario.
    pub async fn forget_errors(&self) -> Result<()> {
        self.take_errors().await?;
        Ok(())
    }

    /// Signed-in browser for `user`: reuses that account's cookies when its
    /// session is still valid, otherwise performs the full login.
    pub async fn as_user(&self, user: &str) -> Result<()> {
        if self.resume(user).await? {
            return Ok(());
        }
        self.reset().await?;
        self.login(user, SEED_PASSWORD).await
    }

    /// Restores `user`'s cached cookies; true when they still sign in.
    pub async fn resume(&self, user: &str) -> Result<bool> {
        self.reset().await?;
        let cached = self
            .sessions
            .lock()
            .expect("sessions lock")
            .get(user)
            .cloned();
        let Some(cookies) = cached else {
            return Ok(false);
        };
        for cookie in cookies {
            self.driver.add_cookie(cookie).await?;
        }
        self.goto("/").await?;
        Ok(!self.path().await?.starts_with("/login"))
    }

    /// Password, then MFA enrolment (first login) or verification.
    pub async fn login(&self, username: &str, password: &str) -> Result<()> {
        self.goto("/login").await?;
        self.fill("#username", username).await?;
        self.fill("#password", password).await?;
        self.click("#login-form button[type='submit']").await?;
        self.wait_path_not("/login").await?;
        match self.path().await?.as_str() {
            "/mfa/setup" => self.enrol_mfa(username).await?,
            "/mfa/verify" => {
                let code = self.authenticator.code(username).await?;
                self.fill("#totp_code", &code).await?;
                self.click("form[action='/mfa/verify'] button[type='submit']")
                    .await?;
                self.wait_path_not("/mfa/verify").await?;
            }
            _ => {}
        }
        let cookies = self.driver.get_all_cookies().await?;
        self.sessions
            .lock()
            .expect("sessions lock")
            .insert(username.to_string(), cookies);
        Ok(())
    }

    async fn enrol_mfa(&self, username: &str) -> Result<()> {
        self.click("form[action='/mfa/setup/init'] button[type='submit']")
            .await?;
        let secret = self.el("code.font-mono").await?.text().await?;
        ensure!(!secret.trim().is_empty(), "no TOTP secret on /mfa/setup");
        self.authenticator.enrol(username, &secret);
        let code = self.authenticator.code(username).await?;
        self.fill("#totp_code", &code).await?;
        self.click("form[action='/mfa/setup'] button[type='submit']")
            .await?;
        self.wait_path_not("/mfa/setup").await
    }

    pub fn has_mfa(&self, user: &str) -> bool {
        self.authenticator.knows(user)
    }

    /// A fresh TOTP code of `user` (step-up confirmations).
    pub async fn totp(&self, user: &str) -> Result<String> {
        self.authenticator.code(user).await
    }

    /// HTML and screenshot of the current page under
    /// `target/e2e-failures/` (where a failed scenario stopped).
    pub async fn save_page(&self, name: &str) -> Result<String> {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../target/e2e-failures");
        std::fs::create_dir_all(&dir)?;
        let stem = dir.join(name.replace("::", "__"));
        let url = self.driver.current_url().await?;
        std::fs::write(stem.with_extension("html"), self.driver.source().await?)?;
        std::fs::write(
            stem.with_extension("png"),
            self.driver.screenshot_as_png().await?,
        )?;
        Ok(format!(
            "stopped on {url}, page saved to {}.{{html,png}}",
            stem.display()
        ))
    }

    /// Flash messages rendered on the current page.
    pub async fn flash(&self) -> Result<Vec<String>> {
        let mut out = Vec::new();
        for el in self
            .driver
            .find_all(By::Css(r#"main [x-data="{ show: true }"] .flex-1"#))
            .await?
        {
            out.push(el.text().await?);
        }
        Ok(out)
    }

    /// Fails unless a flash message contains `needle`.
    pub async fn expect_flash(&self, needle: &str) -> Result<()> {
        let flash = self.flash().await?;
        ensure!(
            flash.iter().any(|m| m.contains(needle)),
            "expected a flash containing {needle:?} on {}, got {flash:?}",
            self.path().await?
        );
        Ok(())
    }

    /// Lets the server see what the browser would refuse (pattern,
    /// required, minlength): server-side validation is what is tested.
    pub async fn no_validate(&self, form_css: &str) -> Result<()> {
        self.driver
            .execute(
                "const f = document.querySelector(arguments[0]); f.noValidate = true;",
                vec![serde_json::Value::String(form_css.into())],
            )
            .await?;
        Ok(())
    }

    /// Accepts the confirmation an `hx-confirm` form raises: the styled
    /// modal when the form handles `htmx:confirm`, else the native dialog.
    pub async fn confirm(&self) -> Result<()> {
        for _ in 0..50 {
            if self.driver.accept_alert().await.is_ok() {
                return Ok(());
            }
            for button in self
                .driver
                .find_all(By::Css(r"button[\@click*='deleteConfirm.confirm']"))
                .await?
            {
                if button.is_displayed().await? {
                    button.click().await?;
                    return Ok(());
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        bail!("no confirmation dialog on {}", self.path().await?)
    }

    /// A form POST forged from the current page (session cookie and CSRF
    /// token of this browser): what a user can do without the UI.
    /// Returns the final status, path and body text after redirects.
    pub async fn post(&self, path: &str, fields: &[(&str, &str)]) -> Result<(u16, String, String)> {
        let fields: serde_json::Map<String, serde_json::Value> = fields
            .iter()
            .map(|(k, v)| (k.to_string(), serde_json::Value::String(v.to_string())))
            .collect();
        let ret = self
            .driver
            .execute_async(
                r#"const [path, fields, done] = arguments;
                   const m = document.cookie.match(/(?:^|;\s*)__vauban_csrf=([^;]*)/);
                   const body = new URLSearchParams({ csrf_token: m ? m[1] : "", ...fields });
                   fetch(path, { method: "POST", body, credentials: "same-origin" })
                     .then(async (r) => {
                       const doc = new DOMParser().parseFromString(await r.text(), "text/html");
                       done([r.status, new URL(r.url).pathname, doc.body ? doc.body.innerText : ""]);
                     })
                     .catch((e) => done([0, "", String(e)]));"#,
                vec![
                    serde_json::Value::String(path.into()),
                    serde_json::Value::Object(fields),
                ],
            )
            .await?;
        Ok(ret.convert()?)
    }

    /// UUID in the last segment-like position of the current path.
    pub async fn uuid_in_path(&self) -> Result<String> {
        let path = self.path().await?;
        path.split('/')
            .find(|s| s.len() == 36 && s.matches('-').count() == 4)
            .map(str::to_string)
            .with_context(|| format!("no UUID in {path}"))
    }

    pub async fn fill(&self, css: &str, text: &str) -> Result<()> {
        let el = self.el(css).await?;
        el.clear().await?;
        el.send_keys(text).await?;
        Ok(())
    }

    /// Picks the option of `css` whose value is `label` or whose label
    /// starts with it, then fires the events Alpine `x-model` listens to.
    pub async fn select(&self, css: &str, label: &str) -> Result<()> {
        let el = self.el(css).await?;
        let picked = self
            .driver
            .execute(
                r#"const [s, label] = arguments;
                   const o = [...s.options].find((o) => o.value === label)
                     || [...s.options].find((o) => o.textContent.trim().startsWith(label));
                   if (!o) return false;
                   s.value = o.value;
                   s.dispatchEvent(new Event("input", { bubbles: true }));
                   s.dispatchEvent(new Event("change", { bubbles: true }));
                   return true;"#,
                vec![el.to_json()?, serde_json::Value::String(label.into())],
            )
            .await?
            .convert::<bool>()?;
        ensure!(picked, "{css} has no option {label:?}");
        Ok(())
    }

    pub async fn set_checked(&self, css: &str, on: bool) -> Result<()> {
        let el = self.el(css).await?;
        if el.is_selected().await? != on {
            el.click().await?;
        }
        Ok(())
    }

    /// Visible text of `<main>`.
    pub async fn main_text(&self) -> Result<String> {
        Ok(self.driver.find(By::Tag("main")).await?.text().await?)
    }

    pub async fn click(&self, css: &str) -> Result<()> {
        self.drain_page().await?;
        let el = self
            .driver
            .query(By::Css(css))
            .desc(css)
            .and_clickable()
            .first()
            .await?;
        el.click().await?;
        Ok(())
    }

    /// Clicks a control that loads a new document (form submit, link) and
    /// waits until that document has loaded, even when the URL is the same.
    pub async fn submit(&self, css: &str) -> Result<()> {
        self.driver
            .execute("window.__vaubanE2eOld = true;", Vec::new())
            .await?;
        self.click(css).await?;
        for _ in 0..150 {
            let loaded = self
                .driver
                .execute(
                    "return !window.__vaubanE2eOld && document.readyState === 'complete';",
                    Vec::new(),
                )
                .await
                .ok()
                .and_then(|r| r.convert::<bool>().ok())
                .unwrap_or(false);
            if loaded {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        bail!("{css} did not load a new page in 15s")
    }

    pub async fn click_xpath(&self, xpath: &str) -> Result<()> {
        self.drain_page().await?;
        let el = self
            .driver
            .query(By::XPath(xpath))
            .desc(xpath)
            .and_clickable()
            .first()
            .await?;
        el.click().await?;
        Ok(())
    }

    pub async fn el(&self, css: &str) -> Result<WebElement> {
        Ok(self
            .driver
            .query(By::Css(css))
            .desc(css)
            .and_displayed()
            .first()
            .await?)
    }

    pub async fn wait_path_not(&self, path: &str) -> Result<()> {
        for _ in 0..100 {
            if self.path().await? != path {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        bail!("still on {path} after 10s");
    }

    pub async fn wait_path_is(&self, path: &str) -> Result<()> {
        for _ in 0..100 {
            if self.path().await? == path {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        bail!("expected {path}, still on {} after 10s", self.path().await?);
    }

    /// Moves the current document's probe lines (with its WebSocket trace
    /// when there are errors) into `pending` before a possible navigation.
    async fn drain_page(&self) -> Result<()> {
        let ret = self
            .driver
            .execute(
                "const s = window.__vaubanE2e; if (!s) return [];
                 const e = s.errors.splice(0); const t = s.trace.splice(0);
                 return e.length ? e.concat(t.slice(-20).map((l) => 'trace: ' + l)) : [];",
                Vec::new(),
            )
            .await;
        // A document mid-navigation cannot run scripts; nothing to collect.
        if let Ok(ret) = ret {
            let lines: Vec<String> = ret.convert()?;
            self.pending.lock().expect("pending lock").extend(lines);
        }
        Ok(())
    }

    /// Every probe line since the last call, across navigations.
    pub async fn take_errors(&self) -> Result<Vec<String>> {
        self.drain_page().await?;
        Ok(std::mem::take(
            &mut *self.pending.lock().expect("pending lock"),
        ))
    }

    pub async fn quit(self) -> Result<()> {
        self.driver.quit().await?;
        Ok(())
    }
}
