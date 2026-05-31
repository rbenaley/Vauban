//! Helpers for IACS tunnel integration tests.
//!
//! Each test used to `tokio::spawn` echo targets and sshd listeners then
//! drop the [`JoinHandle`], which detaches the tasks and leaks sockets for
//! the remainder of the 1500+ test binary. Guards here [`abort`] on drop.

use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use vauban_web::config::IacsTunnelConfig;
use vauban_web::db::DbPool;
use vauban_web::services::broadcast::BroadcastService;
use vauban_web::services::iacs_tunnel::{
    TunnelRegistry, spawn_iacs_tunnel_server, spawn_iacs_tunnel_server_with_broadcast,
};

/// Aborts a background task when dropped.
pub struct AbortOnDrop(pub JoinHandle<std::io::Result<()>>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// TCP echo server bound on `127.0.0.1:0`.
pub struct EchoTarget {
    pub addr: SocketAddr,
    _guard: AbortOnDrop,
}

fn spawn_listener_task(
    listener: TcpListener,
    on_accept: impl Fn(tokio::net::TcpStream) + Send + Sync + 'static,
) -> AbortOnDrop {
    AbortOnDrop(tokio::spawn(async move {
        loop {
            let (sock, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            on_accept(sock);
        }
        Ok(())
    }))
}

/// Minimal accept loop that echoes bytes (upstream target for sshd tests).
pub async fn spawn_echo_target() -> EchoTarget {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind echo target");
    let addr = listener.local_addr().expect("local_addr");
    let guard = spawn_listener_task(listener, |mut sock| {
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if sock.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });
    });
    EchoTarget { addr, _guard: guard }
}

/// Accept-and-drop target for auth stress tests.
pub async fn spawn_dummy_target() -> EchoTarget {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let guard = spawn_listener_task(listener, |_| {});
    EchoTarget { addr, _guard: guard }
}

/// In-process IACS sshd for integration tests; aborted when dropped.
pub struct SpawnedIacsTunnel {
    pub addr: SocketAddr,
    pub registry: TunnelRegistry,
    _server: AbortOnDrop,
}

pub async fn spawn_iacs_tunnel(
    registry: TunnelRegistry,
    db_pool: DbPool,
    config: IacsTunnelConfig,
) -> std::io::Result<SpawnedIacsTunnel> {
    let (addr, join) = spawn_iacs_tunnel_server(registry.clone(), db_pool, config).await?;
    Ok(SpawnedIacsTunnel {
        addr,
        registry,
        _server: AbortOnDrop(join),
    })
}

pub async fn spawn_iacs_tunnel_with_broadcast(
    registry: TunnelRegistry,
    db_pool: DbPool,
    config: IacsTunnelConfig,
    broadcast: BroadcastService,
) -> std::io::Result<SpawnedIacsTunnel> {
    let (addr, join) = spawn_iacs_tunnel_server_with_broadcast(
        registry.clone(),
        db_pool,
        config,
        Some(broadcast),
    )
    .await?;
    Ok(SpawnedIacsTunnel {
        addr,
        registry,
        _server: AbortOnDrop(join),
    })
}
