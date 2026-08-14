//! The chunked transfer engine (`docs/PROTOCOL.md` §3).
//!
//! Sender: build manifest → `Offer` → wait `Accept` → push chunks over N parallel
//! unidirectional streams → `Complete` → wait `Ack`. A control-stream reader services
//! `Progress` (forwarded as events) and `ResendChunk` (the chunk goes back into the
//! work queue) until the `Ack` lands.
//!
//! Receiver: `Offer` → validate → `Accept` → write verified chunks into a temp file at
//! their offsets as data streams arrive → after `Complete` and a full bitmap, verify
//! the whole-file BLAKE3 → atomic rename → `Ack`. A corrupt chunk is never written;
//! it is re-requested via `ResendChunk`.
//!
//! Nothing here buffers a whole file: senders read chunk-sized windows, receivers
//! write chunk-sized windows, and hashing is streaming throughout.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex, Notify};
use tokio::task::JoinSet;

use crate::chunk::{chunk_range, hash_chunk};
use crate::manifest::{manifest_for_file, EntryKind, Manifest, TransferId};
use crate::transport::PeerSession;
use crate::wire::{self, AckResult, ChunkFrameHeader, ControlMessage};
use crate::{Error, Result};

/// Parallel data streams per transfer. A single stream cannot saturate a fast link;
/// tuned properly in Phase 2 against real Thunderbolt hardware.
pub const DEFAULT_STREAM_COUNT: usize = 4;

/// How often receivers publish progress (locally and to the peer).
const PROGRESS_INTERVAL: Duration = Duration::from_millis(150);

/// Everything the app layers (CLI, Tauri UI) need to render a transfer. `Serialize`
/// so the Tauri glue can emit these to the frontend as-is.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TransferEvent {
    /// Receiver saw an `Offer` (before accepting).
    Offered {
        transfer_id: TransferId,
        name: String,
        total_bytes: u64,
    },
    /// Both sides: the transfer is underway.
    Started {
        transfer_id: TransferId,
        name: String,
        total_bytes: u64,
    },
    /// Bytes verified-and-written so far (receiver-authoritative on both sides).
    Progress {
        transfer_id: TransferId,
        bytes_done: u64,
        total_bytes: u64,
    },
    /// A chunk failed its hash on arrival and was re-requested. Recoverable.
    ChunkResent {
        transfer_id: TransferId,
        entry_index: u32,
        chunk_index: u32,
    },
    /// Receiver is running the whole-file hash before the atomic rename.
    Verifying { transfer_id: TransferId },
    /// Done. `path` is the final on-disk location on the receiving side.
    Completed {
        transfer_id: TransferId,
        path: Option<String>,
    },
    Failed {
        transfer_id: TransferId,
        reason: String,
    },
}

/// Fire-and-forget event emission: a UI that stopped listening must never stall or
/// fail a transfer.
async fn emit(events: &mpsc::Sender<TransferEvent>, event: TransferEvent) {
    let _ = events.send(event).await;
}

fn bitmap_has(bitmap: &[u8], index: u64) -> bool {
    bitmap
        .get((index / 8) as usize)
        .is_some_and(|b| b & (1 << (index % 8)) != 0)
}

// ---------------------------------------------------------------------------
// Sender
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SendOptions {
    pub chunk_size: u32,
    pub streams: usize,
    /// Fault injection for tests: flip a byte in this `(entry_index, chunk_index)`
    /// payload the first time it is sent, exercising the detect-and-resend path.
    pub corrupt_chunk_once: Option<(u32, u32)>,
}

impl Default for SendOptions {
    fn default() -> Self {
        Self {
            chunk_size: crate::chunk::DEFAULT_CHUNK_SIZE,
            streams: DEFAULT_STREAM_COUNT,
            corrupt_chunk_once: None,
        }
    }
}

/// A queued unit of work for the data-stream workers.
#[derive(Debug, Clone, Copy)]
struct ChunkJob {
    entry_index: u32,
    chunk_index: u32,
    /// Resends satisfy a `ResendChunk` request and do not count toward the initial
    /// queue that gates the `Complete` message.
    is_resend: bool,
}

/// Send one file over an established session. Consumes the session: the QUIC
/// connection is closed when the transfer ends either way.
pub async fn send_file(
    session: PeerSession,
    path: &Path,
    opts: SendOptions,
    events: mpsc::Sender<TransferEvent>,
) -> Result<()> {
    let manifest = Arc::new(manifest_for_file(path, opts.chunk_size).await?);
    let transfer_id = manifest.transfer_id;

    let result = send_inner(&session, Arc::clone(&manifest), path, &opts, &events).await;

    match &result {
        Ok(()) => {
            session.conn.close(0u32.into(), b"done");
            emit(
                &events,
                TransferEvent::Completed {
                    transfer_id,
                    path: None,
                },
            )
            .await;
        }
        Err(e) => {
            session.conn.close(2u32.into(), b"transfer failed");
            emit(
                &events,
                TransferEvent::Failed {
                    transfer_id,
                    reason: e.to_string(),
                },
            )
            .await;
        }
    }
    result
}

async fn send_inner(
    session: &PeerSession,
    manifest: Arc<Manifest>,
    path: &Path,
    opts: &SendOptions,
    events: &mpsc::Sender<TransferEvent>,
) -> Result<()> {
    let transfer_id = manifest.transfer_id;
    let control_send = Arc::clone(&session.control_send);

    {
        let mut send = control_send.lock().await;
        wire::write_frame(
            &mut send,
            &ControlMessage::Offer {
                manifest: (*manifest).clone(),
            },
        )
        .await?;
    }

    // The control stream is ours to read here (no other reader yet): wait for the
    // receiver's verdict directly.
    let mut control_recv = session.control_recv_take()?;
    let have_chunks = match wire::read_frame::<ControlMessage>(&mut control_recv).await? {
        Some(ControlMessage::Accept {
            transfer_id: tid,
            have_chunks,
        }) if tid == transfer_id => have_chunks,
        Some(ControlMessage::Reject { reason, .. }) => return Err(Error::Rejected { reason }),
        Some(ControlMessage::Bye { reason }) => {
            return Err(Error::Connection(format!("peer said goodbye: {reason:?}")))
        }
        Some(other) => {
            return Err(Error::Protocol(format!(
                "expected Accept or Reject, got {other:?}"
            )))
        }
        None => {
            return Err(Error::Connection(
                "control stream closed while awaiting Accept".into(),
            ))
        }
    };

    emit(
        events,
        TransferEvent::Started {
            transfer_id,
            name: manifest.root_name.clone(),
            total_bytes: manifest.total_bytes,
        },
    )
    .await;

    // Enumerate the chunks the receiver is missing (global chunk index across
    // entries orders the resume bitmap).
    let mut jobs = Vec::new();
    let mut global = 0u64;
    for (entry_index, entry) in manifest.entries.iter().enumerate() {
        for chunk_index in 0..entry.chunk_hashes.len() {
            if !bitmap_has(&have_chunks, global) {
                jobs.push(ChunkJob {
                    entry_index: entry_index as u32,
                    chunk_index: chunk_index as u32,
                    is_resend: false,
                });
            }
            global += 1;
        }
    }
    let initial_total = jobs.len();

    let (job_tx, job_rx) = mpsc::unbounded_channel::<ChunkJob>();
    let job_rx = Arc::new(Mutex::new(job_rx));
    for job in jobs {
        let _ = job_tx.send(job);
    }

    let sent_initial = Arc::new(AtomicUsize::new(0));
    let all_queued_sent = Arc::new(Notify::new());
    let corruption_pending = Arc::new(AtomicBool::new(opts.corrupt_chunk_once.is_some()));

    let mut workers: JoinSet<Result<()>> = JoinSet::new();
    for _ in 0..opts.streams.max(1) {
        let conn = session.conn.clone();
        let manifest = Arc::clone(&manifest);
        let job_rx = Arc::clone(&job_rx);
        let sent_initial = Arc::clone(&sent_initial);
        let all_queued_sent = Arc::clone(&all_queued_sent);
        let corruption_pending = Arc::clone(&corruption_pending);
        let corrupt_target = opts.corrupt_chunk_once;
        let path = path.to_owned();
        let chunk_size = manifest.chunk_size;

        workers.spawn(async move {
            let mut stream = conn.open_uni().await?;
            let mut file = tokio::fs::File::open(&path).await?;
            let mut buf = vec![0u8; chunk_size as usize];

            loop {
                let job = { job_rx.lock().await.recv().await };
                let Some(job) = job else { break };

                let entry = &manifest.entries[job.entry_index as usize];
                let range =
                    chunk_range(job.chunk_index as u64, chunk_size, entry.size)?;
                let len = (range.end - range.start) as usize;

                file.seek(std::io::SeekFrom::Start(range.start)).await?;
                file.read_exact(&mut buf[..len]).await?;

                if corrupt_target == Some((job.entry_index, job.chunk_index))
                    && corruption_pending.swap(false, Ordering::AcqRel)
                {
                    buf[0] ^= 0xFF;
                }

                let header = ChunkFrameHeader {
                    transfer_id,
                    entry_index: job.entry_index,
                    chunk_index: job.chunk_index,
                    len: len as u32,
                };
                wire::write_frame(&mut stream, &header).await?;
                stream.write_all(&buf[..len]).await?;

                if !job.is_resend
                    && sent_initial.fetch_add(1, Ordering::AcqRel) + 1 == initial_total
                {
                    all_queued_sent.notify_one();
                }
            }

            let _ = stream.finish();
            Ok(())
        });
    }

    // Control-stream reader: forwarded through a channel so the main select below
    // stays cancellation-safe (a frame is never half-read and abandoned).
    let (ctrl_tx, mut ctrl_rx) = mpsc::channel::<Result<ControlMessage>>(16);
    let ctrl_reader = tokio::spawn(async move {
        loop {
            match wire::read_frame::<ControlMessage>(&mut control_recv).await {
                Ok(Some(msg)) => {
                    if ctrl_tx.send(Ok(msg)).await.is_err() {
                        break;
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    let _ = ctrl_tx.send(Err(e)).await;
                    break;
                }
            }
        }
    });

    let mut complete_sent = false;
    if initial_total == 0 {
        // Zero-chunk payload (empty file): nothing will trigger the notify.
        let mut send = control_send.lock().await;
        wire::write_frame(&mut send, &ControlMessage::Complete { transfer_id }).await?;
        complete_sent = true;
    }

    let result = loop {
        tokio::select! {
            _ = all_queued_sent.notified(), if !complete_sent => {
                let mut send = control_send.lock().await;
                wire::write_frame(&mut send, &ControlMessage::Complete { transfer_id }).await?;
                complete_sent = true;
            }

            msg = ctrl_rx.recv() => match msg {
                Some(Ok(ControlMessage::Progress { bytes_done, .. })) => {
                    emit(events, TransferEvent::Progress {
                        transfer_id,
                        bytes_done,
                        total_bytes: manifest.total_bytes,
                    }).await;
                }
                Some(Ok(ControlMessage::ResendChunk { entry_index, chunk_index, .. })) => {
                    emit(events, TransferEvent::ChunkResent {
                        transfer_id, entry_index, chunk_index,
                    }).await;
                    let _ = job_tx.send(ChunkJob { entry_index, chunk_index, is_resend: true });
                }
                Some(Ok(ControlMessage::Ack { result: AckResult::Ok, .. })) => break Ok(()),
                Some(Ok(ControlMessage::Ack { result: AckResult::Failed { reason }, .. })) => {
                    break Err(Error::TransferFailed { reason });
                }
                Some(Ok(ControlMessage::Cancel { reason, .. })) => {
                    break Err(Error::TransferFailed { reason: format!("cancelled by peer: {reason}") });
                }
                Some(Ok(ControlMessage::Bye { reason })) => {
                    break Err(Error::Connection(format!("peer said goodbye: {reason:?}")));
                }
                Some(Ok(other)) => {
                    break Err(Error::Protocol(format!("unexpected control message {other:?}")));
                }
                Some(Err(e)) => break Err(e),
                None => break Err(Error::Connection(
                    "connection lost before the receiver acknowledged".into(),
                )),
            },

            Some(joined) = workers.join_next() => {
                match joined {
                    Ok(Ok(())) => {} // a worker drained the queue and finished cleanly
                    Ok(Err(e)) => break Err(e),
                    Err(e) => break Err(Error::Protocol(format!("worker panicked: {e}"))),
                }
            }
        }
    };

    drop(job_tx);
    workers.abort_all();
    ctrl_reader.abort();
    result
}

// ---------------------------------------------------------------------------
// Receiver
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ReceiveOptions {
    /// Directory the finished file lands in. The in-flight temp file lives here too,
    /// so the final rename never crosses filesystems.
    pub dest_dir: PathBuf,
}

/// Shared state between the data-stream reader tasks and the main receive loop.
struct RecvShared {
    transfer_id: TransferId,
    manifest: Arc<Manifest>,
    tmp_path: PathBuf,
    /// One flag per global chunk; guarded so duplicate frames count once.
    bitmap: Mutex<Vec<bool>>,
    remaining: AtomicU64,
    bytes_done: AtomicU64,
    /// Pinged when `remaining` hits zero so the main loop re-checks completion.
    made_progress: Notify,
    control_send: Arc<Mutex<quinn::SendStream>>,
    events: mpsc::Sender<TransferEvent>,
}

/// Receive one offered file into `opts.dest_dir`. Consumes the session; auto-accepts
/// the offer (Phase 1 policy — the caller gated trust during pairing).
/// Returns the final path of the verified file.
pub async fn receive_one(
    session: PeerSession,
    opts: ReceiveOptions,
    events: mpsc::Sender<TransferEvent>,
) -> Result<PathBuf> {
    // Read the Offer directly — nothing else can arrive first.
    let mut control_recv = session.control_recv_take()?;
    let manifest = match wire::read_frame::<ControlMessage>(&mut control_recv).await? {
        Some(ControlMessage::Offer { manifest }) => Arc::new(manifest),
        Some(ControlMessage::Bye { reason }) => {
            return Err(Error::Connection(format!("peer said goodbye: {reason:?}")))
        }
        Some(other) => return Err(Error::Protocol(format!("expected Offer, got {other:?}"))),
        None => {
            return Err(Error::Connection(
                "control stream closed before an Offer arrived".into(),
            ))
        }
    };

    let transfer_id = manifest.transfer_id;
    emit(
        &events,
        TransferEvent::Offered {
            transfer_id,
            name: manifest.root_name.clone(),
            total_bytes: manifest.total_bytes,
        },
    )
    .await;

    // Validate before touching disk; reject anything Phase 1 cannot honor.
    let validation = manifest.validate().and_then(|()| {
        let single_file = manifest.entries.len() == 1
            && manifest.entries[0].kind == EntryKind::File;
        if single_file {
            Ok(())
        } else {
            Err(Error::Protocol(
                "only single-file transfers are supported in this version".into(),
            ))
        }
    });
    if let Err(e) = validation {
        let mut send = session.control_send.lock().await;
        let _ = wire::write_frame(
            &mut send,
            &ControlMessage::Reject {
                transfer_id,
                reason: e.to_string(),
            },
        )
        .await;
        return Err(e);
    }

    // Phase 1 policy: accept with an empty bitmap (no resume state yet — the
    // sidecar that fills `have_chunks` lands in Phase 3).
    {
        let mut send = session.control_send.lock().await;
        wire::write_frame(
            &mut send,
            &ControlMessage::Accept {
                transfer_id,
                have_chunks: Vec::new(),
            },
        )
        .await?;
    }
    emit(
        &events,
        TransferEvent::Started {
            transfer_id,
            name: manifest.root_name.clone(),
            total_bytes: manifest.total_bytes,
        },
    )
    .await;

    let result = receive_inner(&session, control_recv, Arc::clone(&manifest), &opts, &events).await;

    match &result {
        Ok(path) => {
            emit(
                &events,
                TransferEvent::Completed {
                    transfer_id,
                    path: Some(path.display().to_string()),
                },
            )
            .await;
            // Give the peer a moment to read the Ack and close first; then close.
            let _ = tokio::time::timeout(Duration::from_secs(10), session.conn.closed()).await;
            session.conn.close(0u32.into(), b"done");
        }
        Err(e) => {
            emit(
                &events,
                TransferEvent::Failed {
                    transfer_id,
                    reason: e.to_string(),
                },
            )
            .await;
            session.conn.close(2u32.into(), b"transfer failed");
        }
    }
    result
}

async fn receive_inner(
    session: &PeerSession,
    control_recv: quinn::RecvStream,
    manifest: Arc<Manifest>,
    opts: &ReceiveOptions,
    events: &mpsc::Sender<TransferEvent>,
) -> Result<PathBuf> {
    let transfer_id = manifest.transfer_id;
    let total_chunks = manifest.total_chunks();

    tokio::fs::create_dir_all(&opts.dest_dir).await?;
    let tmp_path = opts.dest_dir.join(format!(
        ".conduit-{}.part",
        &transfer_id.simple().to_string()[..12]
    ));
    {
        let file = tokio::fs::File::create(&tmp_path).await?;
        file.set_len(manifest.total_bytes).await?;
    }

    let shared = Arc::new(RecvShared {
        transfer_id,
        manifest: Arc::clone(&manifest),
        tmp_path: tmp_path.clone(),
        bitmap: Mutex::new(vec![false; total_chunks as usize]),
        remaining: AtomicU64::new(total_chunks),
        bytes_done: AtomicU64::new(0),
        made_progress: Notify::new(),
        control_send: Arc::clone(&session.control_send),
        events: events.clone(),
    });

    let result = drive_receive(session, control_recv, &shared, events).await;

    match result {
        Ok(()) => {
            // Every chunk verified; now the whole-file check before the rename.
            emit(events, TransferEvent::Verifying { transfer_id }).await;
            let final_path = finalize(&shared, &opts.dest_dir).await;

            let mut send = shared.control_send.lock().await;
            match final_path {
                Ok(path) => {
                    wire::write_frame(
                        &mut send,
                        &ControlMessage::Ack {
                            transfer_id,
                            result: AckResult::Ok,
                        },
                    )
                    .await?;
                    emit(
                        events,
                        TransferEvent::Progress {
                            transfer_id,
                            bytes_done: manifest.total_bytes,
                            total_bytes: manifest.total_bytes,
                        },
                    )
                    .await;
                    Ok(path)
                }
                Err(e) => {
                    let _ = wire::write_frame(
                        &mut send,
                        &ControlMessage::Ack {
                            transfer_id,
                            result: AckResult::Failed {
                                reason: e.to_string(),
                            },
                        },
                    )
                    .await;
                    Err(e)
                }
            }
        }
        Err(e) => {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            Err(e)
        }
    }
}

/// Accept data streams and control messages until every chunk is present and the
/// sender has said `Complete`.
async fn drive_receive(
    session: &PeerSession,
    mut control_recv: quinn::RecvStream,
    shared: &Arc<RecvShared>,
    events: &mpsc::Sender<TransferEvent>,
) -> Result<()> {
    let transfer_id = shared.transfer_id;

    // Cancellation-safe control reads via a dedicated reader task (see send_inner).
    let (ctrl_tx, mut ctrl_rx) = mpsc::channel::<Result<ControlMessage>>(16);
    let ctrl_reader = tokio::spawn(async move {
        loop {
            match wire::read_frame::<ControlMessage>(&mut control_recv).await {
                Ok(Some(msg)) => {
                    if ctrl_tx.send(Ok(msg)).await.is_err() {
                        break;
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    let _ = ctrl_tx.send(Err(e)).await;
                    break;
                }
            }
        }
    });

    // Periodic progress: local event + Progress message to the sender.
    let ticker = tokio::spawn({
        let shared = Arc::clone(shared);
        async move {
            let mut last = u64::MAX;
            loop {
                tokio::time::sleep(PROGRESS_INTERVAL).await;
                let done = shared.bytes_done.load(Ordering::Acquire);
                if done != last {
                    last = done;
                    emit(
                        &shared.events,
                        TransferEvent::Progress {
                            transfer_id: shared.transfer_id,
                            bytes_done: done,
                            total_bytes: shared.manifest.total_bytes,
                        },
                    )
                    .await;
                    let mut send = shared.control_send.lock().await;
                    let _ = wire::write_frame(
                        &mut send,
                        &ControlMessage::Progress {
                            transfer_id: shared.transfer_id,
                            bytes_done: done,
                        },
                    )
                    .await;
                }
            }
        }
    });

    let mut readers: JoinSet<Result<()>> = JoinSet::new();
    let mut complete_received = false;

    let result = loop {
        if complete_received && shared.remaining.load(Ordering::Acquire) == 0 {
            break Ok(());
        }

        tokio::select! {
            stream = session.conn.accept_uni() => {
                let stream = stream?;
                readers.spawn(read_data_stream(stream, Arc::clone(shared)));
            }

            msg = ctrl_rx.recv() => match msg {
                Some(Ok(ControlMessage::Complete { transfer_id: tid })) if tid == transfer_id => {
                    complete_received = true;
                }
                Some(Ok(ControlMessage::Cancel { reason, .. })) => {
                    break Err(Error::TransferFailed {
                        reason: format!("cancelled by sender: {reason}"),
                    });
                }
                Some(Ok(ControlMessage::Bye { reason })) => {
                    break Err(Error::Connection(format!("peer said goodbye: {reason:?}")));
                }
                Some(Ok(other)) => {
                    break Err(Error::Protocol(format!("unexpected control message {other:?}")));
                }
                Some(Err(e)) => break Err(e),
                None => break Err(Error::Connection(
                    "connection lost mid-transfer — transfer will restart on reconnect (resume lands in Phase 3)".into(),
                )),
            },

            _ = shared.made_progress.notified() => {}

            Some(joined) = readers.join_next() => {
                match joined {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => break Err(e),
                    Err(e) => break Err(Error::Protocol(format!("data reader panicked: {e}"))),
                }
            }
        }
    };

    ticker.abort();
    ctrl_reader.abort();
    readers.abort_all();

    // One final authoritative progress line so UIs never end short of 100%.
    if result.is_ok() {
        let done = shared.bytes_done.load(Ordering::Acquire);
        emit(
            events,
            TransferEvent::Progress {
                transfer_id,
                bytes_done: done,
                total_bytes: shared.manifest.total_bytes,
            },
        )
        .await;
    }
    result
}

/// Read chunk frames off one unidirectional stream until the sender finishes it.
async fn read_data_stream(mut stream: quinn::RecvStream, shared: Arc<RecvShared>) -> Result<()> {
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .open(&shared.tmp_path)
        .await?;
    let chunk_size = shared.manifest.chunk_size;
    let mut payload = vec![0u8; chunk_size as usize];

    while let Some(header) = wire::read_frame::<ChunkFrameHeader>(&mut stream).await? {
        if header.transfer_id != shared.transfer_id {
            return Err(Error::Protocol("chunk frame for an unknown transfer".into()));
        }
        let entry = shared
            .manifest
            .entries
            .get(header.entry_index as usize)
            .ok_or_else(|| Error::Protocol("chunk frame entry_index out of range".into()))?;
        let range = chunk_range(header.chunk_index as u64, chunk_size, entry.size)?;
        let expected_len = (range.end - range.start) as usize;
        if header.len as usize != expected_len {
            return Err(Error::Protocol(format!(
                "chunk {} of entry {} declared {} bytes, manifest says {}",
                header.chunk_index, header.entry_index, header.len, expected_len
            )));
        }

        stream.read_exact(&mut payload[..expected_len]).await?;

        // Verify before anything touches the file.
        let expected_hash = entry.chunk_hashes[header.chunk_index as usize];
        if hash_chunk(&payload[..expected_len]) != expected_hash {
            let err = Error::ChunkHashMismatch {
                entry_index: header.entry_index,
                chunk_index: header.chunk_index,
            };
            tracing::warn!("{err} — requesting resend");
            emit(
                &shared.events,
                TransferEvent::ChunkResent {
                    transfer_id: shared.transfer_id,
                    entry_index: header.entry_index,
                    chunk_index: header.chunk_index,
                },
            )
            .await;
            let mut send = shared.control_send.lock().await;
            wire::write_frame(
                &mut send,
                &ControlMessage::ResendChunk {
                    transfer_id: shared.transfer_id,
                    entry_index: header.entry_index,
                    chunk_index: header.chunk_index,
                },
            )
            .await?;
            continue;
        }

        // Phase 1 receives single-file manifests, so the global chunk index and the
        // in-file offset are both direct functions of chunk_index.
        let global_index = header.chunk_index as usize;
        {
            let mut bitmap = shared.bitmap.lock().await;
            if bitmap[global_index] {
                continue; // duplicate (e.g. a resend raced the original) — count once
            }
            file.seek(std::io::SeekFrom::Start(range.start)).await?;
            file.write_all(&payload[..expected_len]).await?;
            bitmap[global_index] = true;
        }
        shared
            .bytes_done
            .fetch_add(expected_len as u64, Ordering::AcqRel);
        if shared.remaining.fetch_sub(1, Ordering::AcqRel) == 1 {
            shared.made_progress.notify_one();
        }
    }
    Ok(())
}

/// Whole-file verification + atomic rename into a collision-free final name.
async fn finalize(shared: &Arc<RecvShared>, dest_dir: &Path) -> Result<PathBuf> {
    let tmp = shared.tmp_path.clone();
    let expected = shared.manifest.entries[0].file_hash;
    let root_name = shared.manifest.root_name.clone();
    let dest_dir = dest_dir.to_owned();

    tokio::task::spawn_blocking(move || -> Result<PathBuf> {
        use std::io::Read;

        // Stream the temp file through BLAKE3; catches any reassembly/offset bug.
        let mut file = std::fs::File::open(&tmp)?;
        let mut hasher = crate::chunk::FileHasher::new();
        let mut buf = vec![0u8; 1024 * 1024];
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        drop(file);

        if hasher.finalize() != expected {
            let _ = std::fs::remove_file(&tmp);
            return Err(Error::FileHashMismatch {
                path: root_name.clone(),
            });
        }

        // Never clobber an existing file: "name.ext", "name (1).ext", ...
        let final_path = unique_destination(&dest_dir, &root_name);
        std::fs::rename(&tmp, &final_path)?;
        Ok(final_path)
    })
    .await
    .map_err(|e| Error::Protocol(format!("finalize task panicked: {e}")))?
}

fn unique_destination(dir: &Path, name: &str) -> PathBuf {
    let candidate = dir.join(name);
    if !candidate.exists() {
        return candidate;
    }
    let (stem, ext) = match name.rsplit_once('.') {
        Some((s, e)) if !s.is_empty() => (s.to_string(), format!(".{e}")),
        _ => (name.to_string(), String::new()),
    };
    for i in 1.. {
        let candidate = dir.join(format!("{stem} ({i}){ext}"));
        if !candidate.exists() {
            return candidate;
        }
    }
    unreachable!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitmap_bits_are_lsb_first_within_each_byte() {
        let bitmap = [0b0000_0101u8, 0b1000_0000];
        assert!(bitmap_has(&bitmap, 0));
        assert!(!bitmap_has(&bitmap, 1));
        assert!(bitmap_has(&bitmap, 2));
        assert!(bitmap_has(&bitmap, 15));
        assert!(!bitmap_has(&bitmap, 16), "past the end reads as absent");
    }

    #[test]
    fn unique_destination_appends_counters_instead_of_clobbering() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            unique_destination(dir.path(), "a.bin"),
            dir.path().join("a.bin")
        );
        std::fs::write(dir.path().join("a.bin"), b"x").unwrap();
        assert_eq!(
            unique_destination(dir.path(), "a.bin"),
            dir.path().join("a (1).bin")
        );
        std::fs::write(dir.path().join("a (1).bin"), b"x").unwrap();
        assert_eq!(
            unique_destination(dir.path(), "a.bin"),
            dir.path().join("a (2).bin")
        );
        // Extensionless names get plain counters.
        std::fs::write(dir.path().join("noext"), b"x").unwrap();
        assert_eq!(
            unique_destination(dir.path(), "noext"),
            dir.path().join("noext (1)")
        );
    }
}
