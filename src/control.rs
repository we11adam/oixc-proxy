//! Local service control. No administrative endpoint is exposed over HTTP.
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot};

const REQUEST_LIMIT: usize = 4096;
const RESPONSE_LIMIT: usize = 8 << 20;
const CONTROL_TIMEOUT: Duration = Duration::from_secs(180);

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    RefreshNodes,
    ReloadConfig,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Response {
    pub ok: bool,
    pub message: String,
    pub error: Option<crate::diagnostics::ErrorKind>,
    pub payload: serde_json::Value,
}

impl Response {
    pub fn success(message: &str, payload: serde_json::Value) -> Self {
        Self {
            ok: true,
            message: message.to_owned(),
            error: None,
            payload,
        }
    }
    pub fn failure(message: &str, error: crate::diagnostics::ErrorKind) -> Self {
        Self {
            ok: false,
            message: message.to_owned(),
            error: Some(error),
            payload: serde_json::Value::Null,
        }
    }
}

pub struct Request {
    pub command: Command,
    pub reply: oneshot::Sender<Response>,
}

pub fn socket_path(config: &Path) -> Result<PathBuf> {
    let parent = config
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = parent
        .canonicalize()
        .context("locate service configuration directory")?;
    let name = config
        .file_name()
        .context("config path requires a filename")?;
    let digest = hex::encode(Sha256::digest(name.as_bytes()));
    Ok(parent.join(format!(".oixc-{}.sock", &digest[..8])))
}

struct SocketFile {
    path: PathBuf,
    inode: u64,
    device: u64,
}
impl Drop for SocketFile {
    fn drop(&mut self) {
        if let Ok(metadata) = std::fs::symlink_metadata(&self.path) {
            if metadata.ino() == self.inode && metadata.dev() == self.device {
                let _ = std::fs::remove_file(&self.path);
            }
        }
    }
}

pub struct Server {
    listener: UnixListener,
    _file: SocketFile,
}
impl Server {
    pub async fn bind(config: &Path) -> Result<Self> {
        let path = socket_path(config)?;
        if let Ok(metadata) = std::fs::symlink_metadata(&path) {
            if !metadata.file_type().is_socket() {
                bail!("control socket path is occupied by a non-socket file");
            }
            let uid = unsafe { libc::geteuid() };
            if uid != 0 && metadata.uid() != uid {
                bail!("control socket belongs to another user");
            }
            match tokio::time::timeout(Duration::from_secs(1), UnixStream::connect(&path)).await {
                Ok(Ok(_)) => bail!("another service already uses this configuration"),
                Ok(Err(error)) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                    let current = std::fs::symlink_metadata(&path)?;
                    if current.ino() != metadata.ino() || current.dev() != metadata.dev() {
                        bail!("control socket changed during startup");
                    }
                    std::fs::remove_file(&path).context("remove stale service control socket")?;
                }
                _ => bail!("existing control socket is not safely replaceable"),
            }
        }
        let listener = UnixListener::bind(&path).context("bind private service control socket")?;
        let metadata = std::fs::symlink_metadata(&path)?;
        let file = SocketFile {
            path: path.clone(),
            inode: metadata.ino(),
            device: metadata.dev(),
        };
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        Ok(Self {
            listener,
            _file: file,
        })
    }

    pub async fn serve(self, sender: mpsc::Sender<Request>) -> Result<()> {
        let mut clients = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                connection = self.listener.accept() => {
                    let (stream, _) = connection?;
                    if clients.len() >= 16 { drop(stream); continue; }
                    let sender = sender.clone();
                    clients.spawn(async move { let _ = handle(stream, sender).await; });
                }
                _ = clients.join_next(), if !clients.is_empty() => {}
            }
        }
    }
}

async fn handle(stream: UnixStream, sender: mpsc::Sender<Request>) -> Result<()> {
    let (read, mut write) = stream.into_split();
    let mut bytes = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(5),
        BufReader::new(read)
            .take((REQUEST_LIMIT + 1) as u64)
            .read_until(b'\n', &mut bytes),
    )
    .await??;
    if bytes.len() > REQUEST_LIMIT || !bytes.ends_with(b"\n") {
        bail!("invalid control request length");
    }
    let command = serde_json::from_slice::<Command>(&bytes);
    let response = match command {
        Ok(command) => {
            let (reply, receive) = oneshot::channel();
            if sender.try_send(Request { command, reply }).is_err() {
                Response::failure(
                    "service control queue is busy",
                    crate::diagnostics::ErrorKind::Other,
                )
            } else {
                tokio::time::timeout(CONTROL_TIMEOUT, receive)
                    .await
                    .ok()
                    .and_then(Result::ok)
                    .unwrap_or_else(|| {
                        Response::failure(
                            "service control operation unavailable or timed out",
                            crate::diagnostics::ErrorKind::Timeout,
                        )
                    })
            }
        }
        Err(_) => Response::failure(
            "invalid control command",
            crate::diagnostics::ErrorKind::InvalidResponse,
        ),
    };
    let mut bytes = serde_json::to_vec(&response)?;
    bytes.push(b'\n');
    tokio::time::timeout(Duration::from_secs(5), write.write_all(&bytes)).await??;
    Ok(())
}

pub async fn send(config: &Path, command: Command) -> Result<Response> {
    tokio::time::timeout(CONTROL_TIMEOUT, async {
        let mut stream = UnixStream::connect(socket_path(config)?)
            .await
            .context("connect service control socket; run the command as the service user")?;
        let mut bytes = serde_json::to_vec(&command)?;
        bytes.push(b'\n');
        stream.write_all(&bytes).await?;
        let mut response = Vec::new();
        BufReader::new(stream)
            .take((RESPONSE_LIMIT + 1) as u64)
            .read_until(b'\n', &mut response)
            .await?;
        if response.len() > RESPONSE_LIMIT || !response.ends_with(b"\n") {
            bail!("invalid service control response");
        }
        serde_json::from_slice(&response).context("decode service control result")
    })
    .await
    .context("service control request timed out")?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn control_is_private_reports_results_and_preserves_occupied_paths() {
        let directory = tempfile::tempdir().unwrap();
        let config = directory.path().join("test.conf");
        let path = socket_path(&config).unwrap();
        std::fs::write(&path, b"user file").unwrap();
        assert!(Server::bind(&config).await.is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"user file");
        std::fs::remove_file(&path).unwrap();
        let server = Server::bind(&config).await.unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(Server::bind(&config).await.is_err());
        let (sender, mut receive) = mpsc::channel(1);
        let task = tokio::spawn(server.serve(sender));
        let client = tokio::spawn({
            let config = config.clone();
            async move { send(&config, Command::RefreshNodes).await.unwrap() }
        });
        let request = receive.recv().await.unwrap();
        assert!(matches!(request.command, Command::RefreshNodes));
        request
            .reply
            .send(Response::success(
                "refreshed",
                serde_json::json!({"nodes":3}),
            ))
            .unwrap();
        assert_eq!(client.await.unwrap().payload["nodes"], 3);
        task.abort();
        let _ = task.await;
        assert!(!path.exists());
        let stale = UnixListener::bind(&path).unwrap();
        drop(stale);
        let server = Server::bind(&config).await.unwrap();
        drop(server);
        assert!(!path.exists());
    }
}
