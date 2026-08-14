//! Vauban sealed mailer -- drains email_outbox via supervisor-brokered SMTP.

use anyhow::{Context, Result};
use diesel_async::pooled_connection::{AsyncDieselConnectionManager, deadpool};
use shared::ipc::IpcChannel;
use shared::sandbox as capsicum;
use std::os::unix::io::RawFd;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use tracing::{error, info};
use vauban_mailer::outbox::{DrainCtx, dispatcher_loop};
use vauban_mailer::provision::wait_for_mailer_provision;

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    info!("vauban-mailer starting");

    match run_service() {
        Ok(()) => {
            info!("vauban-mailer exiting normally");
            ExitCode::SUCCESS
        }
        Err(e) => {
            error!("vauban-mailer error: {:#}", e);
            ExitCode::FAILURE
        }
    }
}

fn run_service() -> Result<()> {
    let ipc_read_fd: RawFd = std::env::var("VAUBAN_IPC_READ")
        .unwrap_or_else(|_| "0".to_string())
        .parse()
        .context("Invalid VAUBAN_IPC_READ")?;
    let ipc_write_fd: RawFd = std::env::var("VAUBAN_IPC_WRITE")
        .unwrap_or_else(|_| "1".to_string())
        .parse()
        .context("Invalid VAUBAN_IPC_WRITE")?;
    let database_url = std::env::var("VAUBAN_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .context("VAUBAN_DATABASE_URL or DATABASE_URL required")?;
    let fd_passing_socket: Option<RawFd> = std::env::var("VAUBAN_FD_PASSING_SOCKET")
        .ok()
        .and_then(|v| v.parse().ok());

    unsafe {
        std::env::remove_var("VAUBAN_IPC_READ");
        std::env::remove_var("VAUBAN_IPC_WRITE");
        std::env::remove_var("VAUBAN_DATABASE_URL");
        std::env::remove_var("DATABASE_URL");
        std::env::remove_var("VAUBAN_FD_PASSING_SOCKET");
    }

    let supervisor_channel = unsafe { IpcChannel::from_raw_fds(ipc_read_fd, ipc_write_fd) };
    let fd_passing_socket =
        fd_passing_socket.context("VAUBAN_FD_PASSING_SOCKET required for SMTP broker")?;

    let runtime = wait_for_mailer_provision(&supervisor_channel)
        .context("Failed to receive MailerSmtpProvision")?;
    info!(
        host = %runtime.smtp_host,
        port = runtime.smtp_port,
        "Mailer SMTP runtime provisioned"
    );

    // The fd_passing socket only ever receives fds via SCM_RIGHTS (recvmsg):
    // declare it as a dedicated fd-receiver so Capsicum narrows it to
    // fd_receiver_socket rights (no write). It MUST NOT also appear in
    // `ipc_fds` (one fd, one kind) -- the historic bug of listing it in both
    // crash-looped vauban-mailer on FreeBSD with ConflictingFdRights.
    let ipc_fds = vec![ipc_read_fd, ipc_write_fd];
    let fd_receiver_fds: Option<Vec<RawFd>> = Some(vec![fd_passing_socket]);
    let _sealed =
        capsicum::setup_service_sandbox_extended(&ipc_fds, None, fd_receiver_fds.as_deref())
            .context("Failed to setup sandbox")?;

    let manager =
        AsyncDieselConnectionManager::<diesel_async::AsyncPgConnection>::new(database_url);
    let pool = deadpool::Pool::builder(manager)
        .max_size(2)
        .build()
        .context("Failed to build DB pool")?;

    let shutdown = Arc::new(AtomicBool::new(false));
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("Failed to build Tokio runtime")?;

    rt.block_on(async {
        let ctx = DrainCtx {
            pool,
            supervisor: supervisor_channel,
            fd_passing_socket,
            runtime,
            shutdown: Arc::clone(&shutdown),
        };
        dispatcher_loop(ctx).await;
        Ok(())
    })
}
