//! Virtual-mount filesystem operations (`docs/PROTOCOL.md` §4).
//!
//! A filesystem session is a persistent peer session serving many request/response
//! pairs: metadata ops (`ListDir`/`Stat`) and mutations answer inline on the control
//! stream; `ReadRange` payloads travel on unidirectional streams tagged with the
//! request id, so bulk data never stalls metadata traffic. Sessions are classified
//! by their first control message after `Hello` — see `transfer::serve_session`.
//!
//! [`serve_fs`] is the responding side: it exposes one **share root** directory and
//! answers requests until the peer disconnects. Every inbound path is validated
//! share-relative (no `..`, no absolute paths, no drive letters) before it touches
//! the filesystem.
//!
//! [`FsClient`] is the mounting side: a cloneable handle whose async methods the
//! platform mount backends (`conduit-fs`) call from their filesystem callbacks.
//! Writes are deliberately absent here: a write into the mount spools locally and
//! re-uses the ordinary chunked transfer engine on close (`docs/PROTOCOL.md` §4).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{oneshot, Mutex, Semaphore};
use tokio::task::JoinSet;

use crate::transport::PeerSession;
use crate::wire::{
    self, ControlMessage, FsAttr, FsDataHeader, FsDirEntry, FsEntryKind, FsOp, FsResult,
    MAX_FS_READ_BYTES,
};
use crate::{Error, Result};

/// Concurrent requests a serving peer works on; further requests queue.
const SERVE_CONCURRENCY: usize = 8;

/// How long the mounting side waits for one response before failing the FS op —
/// a hung mount freezes the OS file manager, so time out rather than wedge.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// Serving side
// ---------------------------------------------------------------------------

/// Serve filesystem requests against `share_root` until the peer disconnects.
/// `first` is the request that classified this session (already read from the
/// control stream by the dispatcher).
pub(crate) async fn serve_fs(
    session: &PeerSession,
    mut control_recv: quinn::RecvStream,
    first: (u64, FsOp),
    share_root: PathBuf,
) -> Result<()> {
    let conn = session.conn.clone();
    let control_send = Arc::clone(&session.control_send);
    let share_root = Arc::new(share_root);
    let limiter = Arc::new(Semaphore::new(SERVE_CONCURRENCY));
    let mut workers: JoinSet<()> = JoinSet::new();

    let mut next = Some(first);
    loop {
        let (request_id, op) = match next.take() {
            Some(req) => req,
            None => match wire::read_frame::<ControlMessage>(&mut control_recv).await {
                Ok(Some(ControlMessage::FsRequest { request_id, op })) => (request_id, op),
                Ok(Some(ControlMessage::Bye { .. })) | Ok(None) => break,
                Ok(Some(other)) => {
                    return Err(Error::Protocol(format!(
                        "unexpected {other:?} on a filesystem session"
                    )))
                }
                // Peer vanished: normal end of a mount session.
                Err(Error::Connection(_)) => break,
                Err(e) => return Err(e),
            },
        };

        let permit = limiter.clone().acquire_owned().await.expect("semaphore open");
        let conn = conn.clone();
        let control_send = Arc::clone(&control_send);
        let share_root = Arc::clone(&share_root);
        workers.spawn(async move {
            let result = handle_op(&conn, &share_root, request_id, op).await;
            let mut send = control_send.lock().await;
            let _ = wire::write_frame(
                &mut send,
                &ControlMessage::FsResponse {
                    request_id,
                    result: result.unwrap_or_else(|e| FsResult::Error {
                        message: e.to_string(),
                    }),
                },
            )
            .await;
            drop(permit);
        });

        // Reap finished workers without blocking the request loop.
        while workers.try_join_next().is_some() {}
    }

    while workers.join_next().await.is_some() {}
    Ok(())
}

async fn handle_op(
    conn: &quinn::Connection,
    share_root: &Path,
    request_id: u64,
    op: FsOp,
) -> Result<FsResult> {
    match op {
        FsOp::ListDir { path } => {
            let dir = resolve(share_root, &path)?;
            tokio::task::spawn_blocking(move || list_dir_sync(&dir))
                .await
                .map_err(|e| Error::Protocol(format!("list task panicked: {e}")))?
        }
        FsOp::Stat { path } => {
            let target = resolve(share_root, &path)?;
            tokio::task::spawn_blocking(move || {
                let meta = std::fs::metadata(&target)?;
                Ok(FsResult::Attr(attr_of(&meta)))
            })
            .await
            .map_err(|e| Error::Protocol(format!("stat task panicked: {e}")))?
        }
        FsOp::ReadRange { path, offset, len } => {
            if len > MAX_FS_READ_BYTES {
                return Ok(FsResult::Error {
                    message: format!("read of {len} bytes exceeds the {MAX_FS_READ_BYTES} cap"),
                });
            }
            let target = resolve(share_root, &path)?;
            let payload = tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
                use std::io::{Read, Seek};
                let mut file = std::fs::File::open(&target)?;
                file.seek(std::io::SeekFrom::Start(offset))?;
                let mut buf = vec![0u8; len as usize];
                // Short reads at EOF are expected and legal.
                let mut filled = 0;
                loop {
                    let n = file.read(&mut buf[filled..])?;
                    if n == 0 {
                        break;
                    }
                    filled += n;
                }
                buf.truncate(filled);
                Ok(buf)
            })
            .await
            .map_err(|e| Error::Protocol(format!("read task panicked: {e}")))??;

            // Payload on its own stream so a big read never blocks metadata ops.
            let mut stream = conn.open_uni().await?;
            let header = FsDataHeader {
                request_id,
                len: payload.len() as u32,
            };
            wire::write_frame(&mut stream, &header).await?;
            stream.write_all(&payload).await.map_err(Error::from)?;
            let _ = stream.finish();
            Ok(FsResult::ReadStarted {
                len: payload.len() as u32,
            })
        }
        FsOp::Mkdir { path } => {
            let target = resolve_new(share_root, &path)?;
            tokio::task::spawn_blocking(move || {
                std::fs::create_dir(&target)?;
                Ok(FsResult::Done)
            })
            .await
            .map_err(|e| Error::Protocol(format!("mkdir task panicked: {e}")))?
        }
        FsOp::Unlink { path } => {
            let target = resolve(share_root, &path)?;
            tokio::task::spawn_blocking(move || {
                std::fs::remove_file(&target)?;
                Ok(FsResult::Done)
            })
            .await
            .map_err(|e| Error::Protocol(format!("unlink task panicked: {e}")))?
        }
        FsOp::Rename { from, to } => {
            let from = resolve(share_root, &from)?;
            let to = resolve_new(share_root, &to)?;
            tokio::task::spawn_blocking(move || {
                if to.exists() {
                    return Err(Error::Io(std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        "destination already exists",
                    )));
                }
                std::fs::rename(&from, &to)?;
                Ok(FsResult::Done)
            })
            .await
            .map_err(|e| Error::Protocol(format!("rename task panicked: {e}")))?
        }
    }
}

fn list_dir_sync(dir: &Path) -> Result<FsResult> {
    let mut entries = Vec::new();
    for item in std::fs::read_dir(dir)? {
        let item = item?;
        let Ok(name) = item.file_name().into_string() else {
            continue; // non-UTF-8 names cannot travel the wire; skip
        };
        // In-flight staging dirs are plumbing, not content.
        if name.starts_with(".conduit-") {
            continue;
        }
        let Ok(meta) = item.metadata() else { continue };
        if !meta.is_file() && !meta.is_dir() {
            continue;
        }
        let attr = attr_of(&meta);
        entries.push(FsDirEntry {
            name,
            kind: attr.kind,
            size: attr.size,
            modified_unix: attr.modified_unix,
        });
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(FsResult::DirListing { entries })
}

fn attr_of(meta: &std::fs::Metadata) -> FsAttr {
    FsAttr {
        kind: if meta.is_dir() {
            FsEntryKind::Dir
        } else {
            FsEntryKind::File
        },
        size: meta.len(),
        modified_unix: meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0),
    }
}

/// Resolve a share-relative path that must already exist conceptually (its shape is
/// checked; existence is the operation's concern). `""` is the share root.
fn resolve(share_root: &Path, rel: &str) -> Result<PathBuf> {
    if rel.is_empty() {
        return Ok(share_root.to_path_buf());
    }
    let mut out = share_root.to_path_buf();
    for component in rel.split('/') {
        if component.is_empty()
            || component == "."
            || component == ".."
            || component.contains(['\\', ':'])
        {
            return Err(Error::Protocol(format!(
                "unsafe share-relative path {rel:?}"
            )));
        }
        out.push(component);
    }
    Ok(out)
}

/// Like [`resolve`], but the path names something to *create* — the root itself is
/// not a valid target.
fn resolve_new(share_root: &Path, rel: &str) -> Result<PathBuf> {
    if rel.is_empty() {
        return Err(Error::Protocol("the share root cannot be a target".into()));
    }
    resolve(share_root, rel)
}

// ---------------------------------------------------------------------------
// Mounting side
// ---------------------------------------------------------------------------

struct FsClientInner {
    conn: quinn::Connection,
    control_send: Arc<Mutex<quinn::SendStream>>,
    next_id: AtomicU64,
    pending: std::sync::Mutex<HashMap<u64, oneshot::Sender<FsResult>>>,
    reads: std::sync::Mutex<HashMap<u64, oneshot::Sender<Vec<u8>>>>,
}

/// Cloneable handle to a filesystem session. The platform mount backends call these
/// methods from their (threaded) filesystem callbacks via a runtime handle.
#[derive(Clone)]
pub struct FsClient {
    inner: Arc<FsClientInner>,
}

impl FsClient {
    /// Turn an established (and trusted!) session into a filesystem session. Spawns
    /// the response router and data-stream acceptor; the session classifies itself
    /// on the serving side when the first `FsRequest` arrives.
    pub fn start(session: PeerSession) -> Result<Self> {
        let mut control_recv = session.control_recv_take()?;
        let inner = Arc::new(FsClientInner {
            conn: session.conn.clone(),
            control_send: Arc::clone(&session.control_send),
            next_id: AtomicU64::new(1),
            pending: std::sync::Mutex::new(HashMap::new()),
            reads: std::sync::Mutex::new(HashMap::new()),
        });

        // Control responses → pending waiters.
        let router = Arc::clone(&inner);
        tokio::spawn(async move {
            while let Ok(Some(ControlMessage::FsResponse { request_id, result })) =
                wire::read_frame::<ControlMessage>(&mut control_recv).await
            {
                if let Some(tx) = router.pending.lock().expect("lock").remove(&request_id) {
                    let _ = tx.send(result);
                }
            }
            // Session over: wake every waiter with a failure (drop = RecvError).
            router.pending.lock().expect("lock").clear();
            router.reads.lock().expect("lock").clear();
        });

        // Read payloads → read waiters.
        let acceptor = Arc::clone(&inner);
        tokio::spawn(async move {
            while let Ok(mut stream) = acceptor.conn.accept_uni().await {
                let acceptor = Arc::clone(&acceptor);
                tokio::spawn(async move {
                    let Ok(Some(header)) =
                        wire::read_frame::<FsDataHeader>(&mut stream).await
                    else {
                        return;
                    };
                    if header.len > MAX_FS_READ_BYTES {
                        return;
                    }
                    let mut payload = vec![0u8; header.len as usize];
                    if stream.read_exact(&mut payload).await.is_err() {
                        return;
                    }
                    if let Some(tx) = acceptor
                        .reads
                        .lock()
                        .expect("lock")
                        .remove(&header.request_id)
                    {
                        let _ = tx.send(payload);
                    }
                });
            }
        });

        Ok(Self { inner })
    }

    pub async fn list_dir(&self, path: &str) -> Result<Vec<FsDirEntry>> {
        match self.request(FsOp::ListDir { path: path.into() }).await? {
            FsResult::DirListing { entries } => Ok(entries),
            other => Err(unexpected(other)),
        }
    }

    pub async fn stat(&self, path: &str) -> Result<FsAttr> {
        match self.request(FsOp::Stat { path: path.into() }).await? {
            FsResult::Attr(attr) => Ok(attr),
            other => Err(unexpected(other)),
        }
    }

    /// Read up to `len` bytes at `offset`; short at EOF like an ordinary read.
    pub async fn read_range(&self, path: &str, offset: u64, len: u32) -> Result<Vec<u8>> {
        let request_id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        // Register the payload waiter before the request goes out: the data stream
        // can land before the control response does.
        let (data_tx, data_rx) = oneshot::channel();
        self.inner
            .reads
            .lock()
            .expect("lock")
            .insert(request_id, data_tx);

        let result = self
            .request_with_id(
                request_id,
                FsOp::ReadRange {
                    path: path.into(),
                    offset,
                    len,
                },
            )
            .await;
        let expected = match result {
            Ok(FsResult::ReadStarted { len }) => len,
            Ok(other) => {
                self.inner.reads.lock().expect("lock").remove(&request_id);
                return Err(unexpected(other));
            }
            Err(e) => {
                self.inner.reads.lock().expect("lock").remove(&request_id);
                return Err(e);
            }
        };

        let payload = tokio::time::timeout(REQUEST_TIMEOUT, data_rx)
            .await
            .map_err(|_| Error::Connection("timed out waiting for read payload".into()))?
            .map_err(|_| Error::Connection("filesystem session ended mid-read".into()))?;
        if payload.len() as u32 != expected {
            return Err(Error::Protocol(format!(
                "read payload was {} bytes, response promised {expected}",
                payload.len()
            )));
        }
        Ok(payload)
    }

    pub async fn mkdir(&self, path: &str) -> Result<()> {
        self.expect_done(FsOp::Mkdir { path: path.into() }).await
    }

    pub async fn unlink(&self, path: &str) -> Result<()> {
        self.expect_done(FsOp::Unlink { path: path.into() }).await
    }

    pub async fn rename(&self, from: &str, to: &str) -> Result<()> {
        self.expect_done(FsOp::Rename {
            from: from.into(),
            to: to.into(),
        })
        .await
    }

    /// End the session (unmount).
    pub fn close(&self) {
        self.inner.conn.close(0u32.into(), b"unmount");
    }

    async fn expect_done(&self, op: FsOp) -> Result<()> {
        match self.request(op).await? {
            FsResult::Done => Ok(()),
            other => Err(unexpected(other)),
        }
    }

    async fn request(&self, op: FsOp) -> Result<FsResult> {
        let request_id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        self.request_with_id(request_id, op).await
    }

    async fn request_with_id(&self, request_id: u64, op: FsOp) -> Result<FsResult> {
        let (tx, rx) = oneshot::channel();
        self.inner
            .pending
            .lock()
            .expect("lock")
            .insert(request_id, tx);

        {
            let mut send = self.inner.control_send.lock().await;
            wire::write_frame(&mut send, &ControlMessage::FsRequest { request_id, op })
                .await?;
        }

        let result = tokio::time::timeout(REQUEST_TIMEOUT, rx)
            .await
            .map_err(|_| {
                self.inner.pending.lock().expect("lock").remove(&request_id);
                Error::Connection("filesystem request timed out".into())
            })?
            .map_err(|_| Error::Connection("filesystem session ended".into()))?;
        match result {
            FsResult::Error { message } => Err(Error::Fs(message)),
            ok => Ok(ok),
        }
    }
}

fn unexpected(result: FsResult) -> Error {
    Error::Protocol(format!("unexpected filesystem response {result:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn share_relative_paths_resolve_safely() {
        let root = Path::new("share");
        assert_eq!(resolve(root, "").unwrap(), root);
        assert_eq!(resolve(root, "a/b.txt").unwrap(), root.join("a").join("b.txt"));
        for bad in ["../x", "a/../b", "a//b", "/abs", "a\\b", "c:evil", "."] {
            assert!(resolve(root, bad).is_err(), "{bad:?} must be rejected");
        }
        assert!(resolve_new(root, "").is_err(), "root is not a create target");
    }
}
