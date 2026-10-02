//! Owner-only Unix socket, bounded framing, concurrent clients and request lifetime.
use crate::config::Config;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    os::unix::fs::{FileTypeExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::{Semaphore, mpsc, oneshot},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Status,
    Peers,
    Members,
    Member { action: MemberAction },
    Routes,
    Exit { action: ExitAction },
    Route { action: RouteAction },
    Trace { target: String },
    Ping { target: String, size: usize },
    Shutdown,
}
pub struct Call {
    pub request: Request,
    pub reply: oneshot::Sender<Value>,
}
pub struct Server {
    path: PathBuf,
    task: tokio::task::JoinHandle<()>,
}
impl Server {
    /// The instance identity lock must already be held before stale socket removal.
    pub fn start(path: PathBuf) -> Result<(Self, mpsc::Receiver<Call>)> {
        if let Ok(meta) = std::fs::symlink_metadata(&path) {
            ensure!(
                meta.file_type().is_socket(),
                "control socket path is occupied by a non-socket"
            );
            std::fs::remove_file(&path)?;
        }
        let listener = UnixListener::bind(&path).context("bind control socket")?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        let (tx, rx) = mpsc::channel(32);
        let slots = Arc::new(Semaphore::new(16));
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let Ok(permit) = slots.clone().try_acquire_owned() else {
                    continue;
                };
                let tx = tx.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let _ = tokio::time::timeout(Duration::from_secs(8), serve(stream, tx)).await;
                });
            }
        });
        Ok((Self { path, task }, rx))
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_file(&self.path);
    }
}
async fn serve(mut stream: UnixStream, tx: mpsc::Sender<Call>) -> Result<()> {
    let mut length = [0; 4];
    stream.read_exact(&mut length).await?;
    let length = u32::from_be_bytes(length) as usize;
    ensure!(length <= 16_384, "admin request too large");
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).await?;
    let request: Request = serde_json::from_slice(&bytes)?;
    let (reply, response) = oneshot::channel();
    tx.send(Call { request, reply }).await?;
    let response = response.await?;
    let bytes = serde_json::to_vec(&response)?;
    stream
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .await?;
    stream.write_all(&bytes).await?;
    Ok(())
}
pub fn socket_path(config_path: &Path) -> PathBuf {
    config_path.with_extension("sock")
}
pub async fn request(config_path: &Path, request: Request) -> Result<Value> {
    let _ = Config::load(config_path)?;
    tokio::time::timeout(Duration::from_secs(8), async {
        let mut stream = UnixStream::connect(socket_path(config_path))
            .await
            .context("connect daemon control socket")?;
        let bytes = serde_json::to_vec(&request)?;
        stream
            .write_all(&(bytes.len() as u32).to_be_bytes())
            .await?;
        stream.write_all(&bytes).await?;
        let mut size = [0; 4];
        stream.read_exact(&mut size).await?;
        let size = u32::from_be_bytes(size) as usize;
        ensure!(size <= 16 * 1024 * 1024, "admin response too large");
        let mut bytes = vec![0; size];
        stream.read_exact(&mut bytes).await?;
        let value: Value = serde_json::from_slice(&bytes)?;
        if let Some(error) = value.get("error").and_then(Value::as_str) {
            anyhow::bail!("{error}");
        }
        Ok(value)
    })
    .await
    .context("daemon request timed out")?
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum RouteAction {
    Advertise {
        prefix: ipnet::IpNet,
    },
    Withdraw {
        prefix: ipnet::IpNet,
    },
    Accept {
        prefix: ipnet::IpNet,
        via: String,
        #[serde(default)]
        replace: bool,
    },
    Reject {
        prefix: ipnet::IpNet,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExitAction {
    Use { target: String },
    Off,
    Serve { enabled: bool },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum MemberAction {
    Deny { node: crate::identity::NodeId },
    Allow { node: crate::identity::NodeId },
}
