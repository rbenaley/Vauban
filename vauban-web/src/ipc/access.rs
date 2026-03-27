//! IPC client for communication with vauban-access.
//!
//! Provides async methods to check access permissions via IPC pipes
//! to the Access service (Casbin enforcer).
//!
//! Follows the same pattern as `VaultCryptoClient`.

use crate::error::{AppError, AppResult};
use shared::ipc::IpcChannel;
use shared::messages::{
    AccessCheckResult, AccessCheckResultEntry, AccessRequest as AccessReq,
    AccessResponse as AccessResp, AccessRuleData, AccessRuleInfo, AccessibleGroupEntry,
    AssetGroupInfo, GroupOption, IpcPage, IpcPageParams, Message, RbacResult, VaubanGroupInfo,
};
use std::collections::HashMap;
use std::io;
use std::os::unix::io::RawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::sync::{Mutex, oneshot};
use tracing::{debug, error, info, warn};

/// Async IPC client for vauban-access authorization checks.
pub struct AccessIpcClient {
    channel: IpcChannel,
    read_async_fd: AsyncFd<RawFd>,
    next_request_id: AtomicU64,
    pending_requests: Mutex<HashMap<u64, oneshot::Sender<RbacResult>>>,
    pending_access_requests: Mutex<HashMap<u64, oneshot::Sender<AccessResp>>>,
}

impl AccessIpcClient {
    /// Create a new Access IPC client.
    ///
    /// The file descriptors are passed by the supervisor via topology pipes.
    pub fn new(read_fd: RawFd, write_fd: RawFd) -> io::Result<Arc<Self>> {
        let channel = unsafe { IpcChannel::from_raw_fds(read_fd, write_fd) };

        set_nonblocking(read_fd)?;

        let read_async_fd = AsyncFd::new(read_fd)?;

        Ok(Arc::new(Self {
            channel,
            read_async_fd,
            next_request_id: AtomicU64::new(1),
            pending_requests: Mutex::new(HashMap::new()),
            pending_access_requests: Mutex::new(HashMap::new()),
        }))
    }

    /// Check if a subject has permission to perform an action on a resource.
    ///
    /// Fail-closed: returns false on IPC errors.
    pub async fn check_permission(
        &self,
        subject: &str,
        resource: &str,
        action: &str,
    ) -> AppResult<bool> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = oneshot::channel();

        self.pending_requests.lock().await.insert(request_id, tx);

        let msg = Message::RbacCheck {
            request_id,
            subject: subject.to_string(),
            object: resource.to_string(),
            action: action.to_string(),
        };
        self.channel
            .send(&msg)
            .map_err(|e| AppError::Ipc(format!("rbac send error: {}", e)))?;

        debug!(
            request_id,
            subject, resource, action, "RbacCheck request sent"
        );

        let result = rx
            .await
            .map_err(|_| AppError::Ipc("rbac response channel dropped".to_string()))?;

        Ok(result.allowed)
    }

    async fn send_access_request(&self, request: AccessReq) -> AppResult<AccessResp> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = oneshot::channel();

        self.pending_access_requests
            .lock()
            .await
            .insert(request_id, tx);

        let msg = Message::AccessRequest {
            request_id,
            request,
        };
        self.channel
            .send(&msg)
            .map_err(|e| AppError::Ipc(format!("access send error: {}", e)))?;

        rx.await
            .map_err(|_| AppError::Ipc("access response channel dropped".to_string()))
    }

    /// Drain all pages from a paginated IPC list endpoint into a single Vec.
    async fn drain_pages<T>(
        &self,
        mut make_request: impl FnMut(u32) -> AccessReq,
        extract_page: impl Fn(AccessResp) -> Result<IpcPage<T>, AppError>,
    ) -> AppResult<Vec<T>> {
        const MAX_DRAIN_ITEMS: usize = 50_000;
        let mut all = Vec::new();
        let mut offset = 0u32;
        loop {
            let resp = self.send_access_request(make_request(offset)).await?;
            let page = extract_page(resp)?;
            let n = page.items.len() as u32;
            all.extend(page.items);
            if !page.has_more || n == 0 {
                break;
            }
            if all.len() > MAX_DRAIN_ITEMS {
                return Err(AppError::Ipc(format!(
                    "IPC pagination drained {} items, exceeding safety limit {MAX_DRAIN_ITEMS}",
                    all.len()
                )));
            }
            offset = offset.saturating_add(n);
        }
        Ok(all)
    }

    // === Evaluation ===

    pub async fn check_access(
        &self,
        user_id: i32,
        asset_group_id: i32,
        protocol: &str,
    ) -> AppResult<AccessCheckResult> {
        let resp = self
            .send_access_request(AccessReq::CheckAccess {
                user_id,
                asset_group_id,
                protocol: protocol.to_string(),
            })
            .await?;
        match resp {
            AccessResp::AccessChecked(result) => Ok(result),
            AccessResp::Error(e) => Err(AppError::Ipc(e)),
            _ => Err(AppError::Ipc(
                "unexpected response for CheckAccess".to_string(),
            )),
        }
    }

    pub async fn check_access_multi(
        &self,
        user_id: i32,
        asset_group_ids: &[i32],
        protocol: &str,
    ) -> AppResult<Vec<AccessCheckResultEntry>> {
        let resp = self
            .send_access_request(AccessReq::CheckAccessMulti {
                user_id,
                asset_group_ids: asset_group_ids.to_vec(),
                protocol: protocol.to_string(),
            })
            .await?;
        match resp {
            AccessResp::AccessCheckedMulti(entries) => Ok(entries),
            AccessResp::Error(e) => Err(AppError::Ipc(e)),
            _ => Err(AppError::Ipc(
                "unexpected response for CheckAccessMulti".into(),
            )),
        }
    }

    pub async fn list_accessible_groups(
        &self,
        user_id: i32,
    ) -> AppResult<Vec<AccessibleGroupEntry>> {
        self.drain_pages(
            |offset| AccessReq::ListAccessibleGroups {
                user_id,
                page: ipc_page(offset),
            },
            |resp| match resp {
                AccessResp::AccessibleGroupsPage(p) => Ok(p),
                AccessResp::Error(e) => Err(AppError::Ipc(e)),
                _ => Err(AppError::Ipc("unexpected response".into())),
            },
        )
        .await
    }

    // === Access Rules CRUD ===

    pub async fn create_access_rule(&self, data: AccessRuleData) -> AppResult<AccessRuleInfo> {
        let resp = self
            .send_access_request(AccessReq::CreateAccessRule { data })
            .await?;
        match resp {
            AccessResp::AccessRule(Ok(info)) => Ok(info),
            AccessResp::AccessRule(Err(e)) => Err(AppError::Ipc(e)),
            AccessResp::Error(e) => Err(AppError::Ipc(e)),
            _ => Err(AppError::Ipc("unexpected response".to_string())),
        }
    }

    pub async fn get_access_rule(&self, uuid: &str) -> AppResult<AccessRuleInfo> {
        let resp = self
            .send_access_request(AccessReq::GetAccessRule {
                uuid: uuid.to_string(),
            })
            .await?;
        match resp {
            AccessResp::AccessRule(Ok(info)) => Ok(info),
            AccessResp::AccessRule(Err(e)) => Err(AppError::Ipc(e)),
            AccessResp::Error(e) => Err(AppError::Ipc(e)),
            _ => Err(AppError::Ipc("unexpected response".to_string())),
        }
    }

    pub async fn list_access_rules(&self) -> AppResult<Vec<AccessRuleInfo>> {
        self.drain_pages(
            |offset| AccessReq::ListAccessRules {
                page: ipc_page(offset),
            },
            |resp| match resp {
                AccessResp::AccessRulePage(p) => Ok(p),
                AccessResp::Error(e) => Err(AppError::Ipc(e)),
                _ => Err(AppError::Ipc("unexpected response".into())),
            },
        )
        .await
    }

    pub async fn update_access_rule(
        &self,
        uuid: &str,
        data: AccessRuleData,
    ) -> AppResult<AccessRuleInfo> {
        let resp = self
            .send_access_request(AccessReq::UpdateAccessRule {
                uuid: uuid.to_string(),
                data,
            })
            .await?;
        match resp {
            AccessResp::AccessRule(Ok(info)) => Ok(info),
            AccessResp::AccessRule(Err(e)) => Err(AppError::Ipc(e)),
            AccessResp::Error(e) => Err(AppError::Ipc(e)),
            _ => Err(AppError::Ipc("unexpected response".to_string())),
        }
    }

    pub async fn delete_access_rule(&self, uuid: &str) -> AppResult<()> {
        let resp = self
            .send_access_request(AccessReq::DeleteAccessRule {
                uuid: uuid.to_string(),
            })
            .await?;
        match resp {
            AccessResp::Deleted(Ok(())) => Ok(()),
            AccessResp::Deleted(Err(e)) => Err(AppError::Ipc(e)),
            AccessResp::Error(e) => Err(AppError::Ipc(e)),
            _ => Err(AppError::Ipc("unexpected response".to_string())),
        }
    }

    // === Vauban Groups CRUD ===

    pub async fn create_vauban_group(
        &self,
        name: &str,
        description: Option<String>,
    ) -> AppResult<VaubanGroupInfo> {
        let resp = self
            .send_access_request(AccessReq::CreateVaubanGroup {
                name: name.to_string(),
                description,
            })
            .await?;
        match resp {
            AccessResp::VaubanGroup(Ok(info)) => Ok(info),
            AccessResp::VaubanGroup(Err(e)) => Err(AppError::Ipc(e)),
            AccessResp::Error(e) => Err(AppError::Ipc(e)),
            _ => Err(AppError::Ipc("unexpected response".to_string())),
        }
    }

    pub async fn get_vauban_group(&self, uuid: &str) -> AppResult<VaubanGroupInfo> {
        let resp = self
            .send_access_request(AccessReq::GetVaubanGroup {
                uuid: uuid.to_string(),
            })
            .await?;
        match resp {
            AccessResp::VaubanGroup(Ok(info)) => Ok(info),
            AccessResp::VaubanGroup(Err(e)) => Err(AppError::Ipc(e)),
            AccessResp::Error(e) => Err(AppError::Ipc(e)),
            _ => Err(AppError::Ipc("unexpected response".to_string())),
        }
    }

    pub async fn get_vauban_group_by_id(&self, id: i32) -> AppResult<VaubanGroupInfo> {
        let resp = self
            .send_access_request(AccessReq::GetVaubanGroupById { id })
            .await?;
        match resp {
            AccessResp::VaubanGroup(Ok(info)) => Ok(info),
            AccessResp::VaubanGroup(Err(e)) => Err(AppError::Ipc(e)),
            AccessResp::Error(e) => Err(AppError::Ipc(e)),
            _ => Err(AppError::Ipc("unexpected response".to_string())),
        }
    }

    pub async fn list_vauban_groups(&self) -> AppResult<Vec<VaubanGroupInfo>> {
        self.drain_pages(
            |offset| AccessReq::ListVaubanGroups {
                page: ipc_page(offset),
            },
            |resp| match resp {
                AccessResp::VaubanGroupPage(p) => Ok(p),
                AccessResp::Error(e) => Err(AppError::Ipc(e)),
                _ => Err(AppError::Ipc("unexpected response".into())),
            },
        )
        .await
    }

    pub async fn update_vauban_group(
        &self,
        uuid: &str,
        name: &str,
        description: Option<String>,
    ) -> AppResult<VaubanGroupInfo> {
        let resp = self
            .send_access_request(AccessReq::UpdateVaubanGroup {
                uuid: uuid.to_string(),
                name: name.to_string(),
                description,
            })
            .await?;
        match resp {
            AccessResp::VaubanGroup(Ok(info)) => Ok(info),
            AccessResp::VaubanGroup(Err(e)) => Err(AppError::Ipc(e)),
            AccessResp::Error(e) => Err(AppError::Ipc(e)),
            _ => Err(AppError::Ipc("unexpected response".to_string())),
        }
    }

    pub async fn delete_vauban_group(&self, uuid: &str) -> AppResult<()> {
        let resp = self
            .send_access_request(AccessReq::DeleteVaubanGroup {
                uuid: uuid.to_string(),
            })
            .await?;
        match resp {
            AccessResp::Deleted(Ok(())) => Ok(()),
            AccessResp::Deleted(Err(e)) => Err(AppError::Ipc(e)),
            AccessResp::Error(e) => Err(AppError::Ipc(e)),
            _ => Err(AppError::Ipc("unexpected response".to_string())),
        }
    }

    // === Group Membership ===

    pub async fn add_group_member(&self, group_id: i32, user_id: i32) -> AppResult<()> {
        let resp = self
            .send_access_request(AccessReq::AddGroupMember { group_id, user_id })
            .await?;
        match resp {
            AccessResp::Ok => Ok(()),
            AccessResp::Error(e) => Err(AppError::Ipc(e)),
            _ => Err(AppError::Ipc("unexpected response".to_string())),
        }
    }

    pub async fn remove_group_member(&self, group_id: i32, user_id: i32) -> AppResult<()> {
        let resp = self
            .send_access_request(AccessReq::RemoveGroupMember { group_id, user_id })
            .await?;
        match resp {
            AccessResp::Ok => Ok(()),
            AccessResp::Error(e) => Err(AppError::Ipc(e)),
            _ => Err(AppError::Ipc("unexpected response".to_string())),
        }
    }

    pub async fn list_group_members(&self, group_id: i32) -> AppResult<Vec<i32>> {
        self.drain_pages(
            |offset| AccessReq::ListGroupMembers {
                group_id,
                page: ipc_page(offset),
            },
            |resp| match resp {
                AccessResp::MemberListPage(p) => Ok(p),
                AccessResp::Error(e) => Err(AppError::Ipc(e)),
                _ => Err(AppError::Ipc("unexpected response".into())),
            },
        )
        .await
    }

    pub async fn list_user_groups(&self, user_id: i32) -> AppResult<Vec<VaubanGroupInfo>> {
        self.drain_pages(
            |offset| AccessReq::ListUserGroups {
                user_id,
                page: ipc_page(offset),
            },
            |resp| match resp {
                AccessResp::UserGroupPage(p) => Ok(p),
                AccessResp::Error(e) => Err(AppError::Ipc(e)),
                _ => Err(AppError::Ipc("unexpected response".into())),
            },
        )
        .await
    }

    // === Asset Groups CRUD ===

    pub async fn create_asset_group(
        &self,
        name: &str,
        slug: &str,
        description: Option<String>,
        color: &str,
        icon: &str,
    ) -> AppResult<AssetGroupInfo> {
        let resp = self
            .send_access_request(AccessReq::CreateAssetGroup {
                name: name.to_string(),
                slug: slug.to_string(),
                description,
                color: color.to_string(),
                icon: icon.to_string(),
            })
            .await?;
        match resp {
            AccessResp::AssetGroup(Ok(info)) => Ok(info),
            AccessResp::AssetGroup(Err(e)) => Err(AppError::Ipc(e)),
            AccessResp::Error(e) => Err(AppError::Ipc(e)),
            _ => Err(AppError::Ipc("unexpected response".to_string())),
        }
    }

    pub async fn get_asset_group(&self, uuid: &str) -> AppResult<AssetGroupInfo> {
        let resp = self
            .send_access_request(AccessReq::GetAssetGroup {
                uuid: uuid.to_string(),
            })
            .await?;
        match resp {
            AccessResp::AssetGroup(Ok(info)) => Ok(info),
            AccessResp::AssetGroup(Err(e)) => Err(AppError::Ipc(e)),
            AccessResp::Error(e) => Err(AppError::Ipc(e)),
            _ => Err(AppError::Ipc("unexpected response".to_string())),
        }
    }

    pub async fn list_asset_groups(&self) -> AppResult<Vec<AssetGroupInfo>> {
        self.drain_pages(
            |offset| AccessReq::ListAssetGroups {
                page: ipc_page(offset),
            },
            |resp| match resp {
                AccessResp::AssetGroupPage(p) => Ok(p),
                AccessResp::Error(e) => Err(AppError::Ipc(e)),
                _ => Err(AppError::Ipc("unexpected response".into())),
            },
        )
        .await
    }

    pub async fn update_asset_group(
        &self,
        uuid: &str,
        name: &str,
        slug: &str,
        description: Option<String>,
        color: &str,
        icon: &str,
    ) -> AppResult<AssetGroupInfo> {
        let resp = self
            .send_access_request(AccessReq::UpdateAssetGroup {
                uuid: uuid.to_string(),
                name: name.to_string(),
                slug: slug.to_string(),
                description,
                color: color.to_string(),
                icon: icon.to_string(),
            })
            .await?;
        match resp {
            AccessResp::AssetGroup(Ok(info)) => Ok(info),
            AccessResp::AssetGroup(Err(e)) => Err(AppError::Ipc(e)),
            AccessResp::Error(e) => Err(AppError::Ipc(e)),
            _ => Err(AppError::Ipc("unexpected response".to_string())),
        }
    }

    pub async fn delete_asset_group(&self, uuid: &str) -> AppResult<()> {
        let resp = self
            .send_access_request(AccessReq::DeleteAssetGroup {
                uuid: uuid.to_string(),
            })
            .await?;
        match resp {
            AccessResp::Deleted(Ok(())) => Ok(()),
            AccessResp::Deleted(Err(e)) => Err(AppError::Ipc(e)),
            AccessResp::Error(e) => Err(AppError::Ipc(e)),
            _ => Err(AppError::Ipc("unexpected response".to_string())),
        }
    }

    // === Support ===

    pub async fn get_group_options(&self) -> AppResult<(Vec<GroupOption>, Vec<GroupOption>)> {
        let user_groups = self
            .drain_pages(
                |offset| AccessReq::ListUserGroupOptions {
                    page: ipc_page(offset),
                },
                |resp| match resp {
                    AccessResp::UserGroupOptionsPage(p) => Ok(p),
                    AccessResp::Error(e) => Err(AppError::Ipc(e)),
                    _ => Err(AppError::Ipc("unexpected response".into())),
                },
            )
            .await?;
        let asset_groups = self
            .drain_pages(
                |offset| AccessReq::ListAssetGroupOptions {
                    page: ipc_page(offset),
                },
                |resp| match resp {
                    AccessResp::AssetGroupOptionsPage(p) => Ok(p),
                    AccessResp::Error(e) => Err(AppError::Ipc(e)),
                    _ => Err(AppError::Ipc("unexpected response".into())),
                },
            )
            .await?;
        Ok((user_groups, asset_groups))
    }

    /// Process incoming messages from the Access service.
    ///
    /// Should be spawned as a background task via `tokio::spawn`.
    pub async fn process_incoming(&self) -> AppResult<()> {
        loop {
            let mut guard = self
                .read_async_fd
                .ready(Interest::READABLE)
                .await
                .map_err(|e| AppError::Ipc(format!("AsyncFd ready failed: {}", e)))?;

            loop {
                match self.channel.try_recv() {
                    Ok(msg) => {
                        self.handle_message(msg).await;
                    }
                    Err(shared::ipc::IpcError::Io(ref e))
                        if e.kind() == io::ErrorKind::WouldBlock =>
                    {
                        guard.clear_ready();
                        break;
                    }
                    Err(shared::ipc::IpcError::ConnectionClosed) => {
                        info!("Access IPC connection closed");
                        return Err(AppError::Ipc("Access IPC connection closed".to_string()));
                    }
                    Err(e) => {
                        error!(error = %e, "Access IPC receive error");
                        guard.clear_ready();
                        break;
                    }
                }
            }
        }
    }

    async fn handle_message(&self, msg: Message) {
        match msg {
            Message::RbacResponse { request_id, result } => {
                let mut pending = self.pending_requests.lock().await;
                if let Some(tx) = pending.remove(&request_id) {
                    let _ = tx.send(result);
                } else {
                    warn!(request_id, "No pending request for RBAC response");
                }
            }
            Message::AccessResponse {
                request_id,
                response,
            } => {
                let mut pending = self.pending_access_requests.lock().await;
                if let Some(tx) = pending.remove(&request_id) {
                    let _ = tx.send(response);
                } else {
                    warn!(request_id, "No pending request for Access response");
                }
            }
            other => {
                warn!("Unexpected message from Access service: {:?}", other);
            }
        }
    }
}

/// `limit == 0` lets vauban-access apply [`shared::messages::DEFAULT_IPC_PAGE_LIMIT`].
fn ipc_page(offset: u32) -> IpcPageParams {
    IpcPageParams {
        limit: 0,
        offset,
    }
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    use libc::{F_GETFL, F_SETFL, O_NONBLOCK, fcntl};

    unsafe {
        let flags = fcntl(fd, F_GETFL);
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;
    use std::sync::atomic::Ordering;

    #[test]
    fn test_set_nonblocking() {
        let (read_fd, _write_fd) = nix::unistd::pipe().unwrap();
        let result = set_nonblocking(read_fd.as_raw_fd());
        assert!(result.is_ok());

        use libc::{F_GETFL, O_NONBLOCK, fcntl};
        let flags = unsafe { fcntl(read_fd.as_raw_fd(), F_GETFL) };
        assert!(flags & O_NONBLOCK != 0);
    }

    #[test]
    fn test_request_id_counter_increments() {
        let counter = AtomicU64::new(1);
        let id1 = counter.fetch_add(1, Ordering::SeqCst);
        let id2 = counter.fetch_add(1, Ordering::SeqCst);
        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
    }
}
