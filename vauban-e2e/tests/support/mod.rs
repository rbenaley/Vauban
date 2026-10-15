pub mod bench;
pub mod browser;
pub mod known;
pub mod sentinel;
pub mod totp;
pub mod upstream;

use anyhow::{Result, bail};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Mutex;
use tokio::runtime::Runtime;

pub use bench::{Bench, SEED_PASSWORD};
pub use browser::Browser;
use upstream::{Agent, FakeUpstream};

/// One booted stack + one browser, shared by every scenario of a run.
pub struct Stack {
    pub rt: Runtime,
    bench: Mutex<Bench>,
    browser: Mutex<Option<Browser>>,
    upstream: FakeUpstream,
    agent: Agent,
    data: PathBuf,
}

pub type ScenarioFuture<'a> = Pin<Box<dyn Future<Output = Result<()>> + 'a>>;
pub type ScenarioFn = for<'a> fn(&'a Ctx<'a>) -> ScenarioFuture<'a>;

/// What a scenario sees.
pub struct Ctx<'a> {
    pub browser: &'a Browser,
    /// MCP server behind the bastion (pinned TLS on loopback).
    pub upstream: &'a FakeUpstream,
    /// MCP agent: hop 1 and hop 2 over HTTPS, outside the browser.
    pub agent: &'a Agent,
    /// The bench tree: `recordings/`, `audit/`.
    pub data: &'a Path,
}

impl Stack {
    pub fn boot() -> Result<Self> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        let bench = Bench::start()?;
        let browser = rt.block_on(Browser::launch(bench.origin()))?;
        let upstream = rt.block_on(FakeUpstream::start())?;
        let agent = Agent::new(&bench.origin())?;
        let data = bench.data().to_path_buf();
        Ok(Self {
            rt,
            bench: Mutex::new(bench),
            browser: Mutex::new(Some(browser)),
            upstream,
            agent,
            data,
        })
    }

    /// Runs one scenario from a clean browser, then fails it on any JS
    /// error, 5xx, or degraded-stack line it produced.
    pub fn run(&self, name: &str, scenario: ScenarioFn) -> Result<()> {
        let guard = self.browser.lock().expect("browser lock");
        let browser = guard.as_ref().expect("browser running");
        let outcome = self.rt.block_on(async {
            browser.reset().await?;
            browser.forget_errors().await?;
            let ctx = Ctx {
                browser,
                upstream: &self.upstream,
                agent: &self.agent,
                data: &self.data,
            };
            if let Err(e) = scenario(&ctx).await {
                let saved = browser.save_page(name).await;
                return Err(e.context(saved.unwrap_or_else(|e| format!("page not saved: {e:#}"))));
            }
            let (unknown, known) = known::triage(browser.take_errors().await?);
            for defect in known {
                eprintln!("    known defect {}: {}", defect.id, defect.summary);
            }
            if !unknown.is_empty() {
                bail!("browser:\n  {}", unknown.join("\n  "));
            }
            Ok(())
        });
        let mut bench = self.bench.lock().expect("bench lock");
        let stack = bench.ensure_alive().and_then(|()| bench.sentinel.check());
        match (outcome, stack) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(e), Ok(())) | (Ok(()), Err(e)) => Err(e),
            (Err(a), Err(b)) => bail!("{a:#}\n{b:#}"),
        }
    }

    /// `full_run`: no filter was given, so every known defect had its chance.
    pub fn shutdown(&self, full_run: bool) -> Result<()> {
        if let Some(browser) = self.browser.lock().expect("browser lock").take() {
            let _ = self.rt.block_on(browser.quit());
        }
        let mut bench = self.bench.lock().expect("bench lock");
        bench.sentinel.check()?;
        bench.stop()?;
        let fixed = known::unseen();
        if full_run && !fixed.is_empty() {
            bail!(
                "known defects no longer observed (fixed? remove them from known.rs): {}",
                fixed.join(", ")
            );
        }
        Ok(())
    }
}

/// `scenario!(name)` registers `async fn name(cx: &Ctx<'_>) -> Result<()>`.
#[macro_export]
macro_rules! scenario {
    ($module:ident :: $name:ident) => {
        (
            concat!(stringify!($module), "::", stringify!($name)),
            (|cx| Box::pin($module::$name(cx))) as $crate::support::ScenarioFn,
        )
    };
}
