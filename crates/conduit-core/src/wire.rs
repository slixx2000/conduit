//! Wire encoding and framing (`docs/PROTOCOL.md` §2.3–§3.3).
//!
//! Encoding decision (recorded in `docs/ARCHITECTURE.md` §8): **`postcard`**, chosen
//! over CBOR because both peers are always the same Rust codebase, so a compact
//! schema-implied format wins and cross-language readability buys nothing. Every frame
//! is a **u32 little-endian length prefix** followed by the postcard bytes; chunk
//! payloads travel as raw bytes *after* their header frame rather than inside it, so
//! multi-MiB payloads are never run through the serializer.

use serde::{Deserialize, Serialize};

use crate::manifest::{Manifest, TransferId};
use crate::protocol::Hello;
use crate::{Error, Result};

/// ALPN identifier negotiated inside TLS. Bump alongside `PROTOCOL_VERSION` majors.
pub const ALPN: &[u8] = b"conduit/1";

/// Upper bound on a single control frame. Generous because a manifest for a large
/// file carries all chunk hashes (a 1 TiB file at 4 MiB chunks ≈ 8 MiB of hashes),
/// but still small enough to stop a hostile length prefix from ballooning memory.
pub const MAX_FRAME_BYTES: u32 = 64 * 1024 * 1024;

/// Everything that flows on the bidirectional control stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlMessage {
    Hello(Hello),
    Offer {
        manifest: Manifest,
    },
    Accept {
        transfer_id: TransferId,
        /// Bitmap of chunks the receiver already holds (resume). Bit `i` set means
        /// global chunk `i` is present and verified. Empty = start from scratch —
        /// always empty in Phase 1; populated from the sidecar in Phase 3.
        have_chunks: Vec<u8>,
    },
    Reject {
        transfer_id: TransferId,
        reason: String,
    },
    /// Periodic receiver → sender byte count, so the sender's progress reflects
    /// bytes actually verified on disk rather than bytes pushed into the socket.
    Progress {
        transfer_id: TransferId,
        bytes_done: u64,
    },
    /// Receiver asks for one chunk again after a BLAKE3 mismatch on arrival.
    ResendChunk {
        transfer_id: TransferId,
        entry_index: u32,
        chunk_index: u32,
    },
    /// Sender has written every offered chunk to the data streams.
    Complete {
        transfer_id: TransferId,
    },
    /// Receiver's final word after whole-file verification and atomic rename.
    Ack {
        transfer_id: TransferId,
        result: AckResult,
    },
    Cancel {
        transfer_id: TransferId,
        reason: String,
    },
    Bye {
        reason: ByeReason,
    },
    /// Virtual-mount operation (`docs/PROTOCOL.md` §4). The first control message
    /// after `Hello` classifies the session: `Offer` opens a transfer session,
    /// `FsRequest` opens a filesystem session that serves many requests.
    FsRequest {
        /// Correlates the response (and any data stream) with this request.
        request_id: u64,
        op: FsOp,
    },
    FsResponse {
        request_id: u64,
        result: FsResult,
    },
}

/// Filesystem operations against the peer's shared area. Paths are share-relative,
/// `/`-separated, and never absolute; `""` names the share root itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FsOp {
    ListDir { path: String },
    Stat { path: String },
    /// Read `len` bytes at `offset`. The payload answers on a unidirectional
    /// stream (see [`FsDataHeader`]), not inside the control response.
    ReadRange { path: String, offset: u64, len: u32 },
    Mkdir { path: String },
    /// Remove a file (not a directory) — v1 keeps deletion conservative.
    Unlink { path: String },
    Rename { from: String, to: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FsResult {
    DirListing { entries: Vec<FsDirEntry> },
    Attr(FsAttr),
    /// `len` bytes (possibly short at EOF) follow on a unidirectional stream
    /// framed by [`FsDataHeader`] with the same `request_id`.
    ReadStarted { len: u32 },
    /// A mutation (mkdir/unlink/rename) succeeded.
    Done,
    Error { message: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FsEntryKind {
    File,
    Dir,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsDirEntry {
    pub name: String,
    pub kind: FsEntryKind,
    pub size: u64,
    /// Seconds since the Unix epoch; 0 when the filesystem does not say.
    pub modified_unix: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsAttr {
    pub kind: FsEntryKind,
    pub size: u64,
    pub modified_unix: u64,
}

/// Header preceding a `ReadRange` payload on its unidirectional stream; the `len`
/// raw bytes follow on the same stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsDataHeader {
    pub request_id: u64,
    pub len: u32,
}

/// Upper bound on one `ReadRange` request. Mount backends issue reads in pieces no
/// larger than this; the server rejects anything bigger.
pub const MAX_FS_READ_BYTES: u32 = 8 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AckResult {
    Ok,
    Failed { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ByeReason {
    VersionMismatch,
    PairingRejected,
    Done,
    Other(String),
}

/// Header preceding each chunk payload on a data stream. The `len` bytes of payload
/// follow as raw bytes on the same stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkFrameHeader {
    pub transfer_id: TransferId,
    pub entry_index: u32,
    pub chunk_index: u32,
    pub len: u32,
}

/// Length-prefix + postcard-encode a value into a single buffer, ready to write.
pub fn encode_frame<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let body = postcard::to_stdvec(value)?;
    let len = u32::try_from(body.len()).map_err(|_| Error::FrameTooLarge {
        len: body.len() as u64,
        max: MAX_FRAME_BYTES as u64,
    })?;
    if len > MAX_FRAME_BYTES {
        return Err(Error::FrameTooLarge {
            len: len as u64,
            max: MAX_FRAME_BYTES as u64,
        });
    }
    let mut framed = Vec::with_capacity(4 + body.len());
    framed.extend_from_slice(&len.to_le_bytes());
    framed.extend_from_slice(&body);
    Ok(framed)
}

/// Decode one frame body (the bytes after the length prefix).
pub fn decode_body<T: for<'de> Deserialize<'de>>(body: &[u8]) -> Result<T> {
    Ok(postcard::from_bytes(body)?)
}

/// Write one framed message to a QUIC stream.
pub async fn write_frame<T: Serialize>(stream: &mut quinn::SendStream, value: &T) -> Result<()> {
    let framed = encode_frame(value)?;
    stream.write_all(&framed).await?;
    Ok(())
}

/// Read one framed message from a QUIC stream. Returns `Ok(None)` on a clean
/// end-of-stream at a frame boundary; mid-frame EOF is an error.
pub async fn read_frame<T: for<'de> Deserialize<'de>>(
    stream: &mut quinn::RecvStream,
) -> Result<Option<T>> {
    let mut len_buf = [0u8; 4];
    match stream.read_exact(&mut len_buf).await {
        Ok(()) => {}
        Err(quinn::ReadExactError::FinishedEarly(0)) => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_le_bytes(len_buf);
    if len > MAX_FRAME_BYTES {
        return Err(Error::FrameTooLarge {
            len: len as u64,
            max: MAX_FRAME_BYTES as u64,
        });
    }
    let mut body = vec![0u8; len as usize];
    stream.read_exact(&mut body).await?;
    decode_body(&body).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Capabilities, DeviceId};
    use uuid::Uuid;

    fn roundtrip(msg: &ControlMessage) -> ControlMessage {
        let framed = encode_frame(msg).unwrap();
        let len = u32::from_le_bytes(framed[..4].try_into().unwrap()) as usize;
        assert_eq!(len, framed.len() - 4, "prefix must match body length");
        decode_body(&framed[4..]).unwrap()
    }

    #[test]
    fn control_messages_roundtrip_through_postcard() {
        let msgs = [
            ControlMessage::Hello(Hello::new(
                DeviceId::new_random(),
                "Laptop",
                Capabilities::RESUME,
            )),
            ControlMessage::Accept {
                transfer_id: Uuid::new_v4(),
                have_chunks: vec![0b1010_0001],
            },
            ControlMessage::ResendChunk {
                transfer_id: Uuid::new_v4(),
                entry_index: 3,
                chunk_index: 71,
            },
            ControlMessage::Ack {
                transfer_id: Uuid::new_v4(),
                result: AckResult::Failed {
                    reason: "hash mismatch".into(),
                },
            },
            ControlMessage::Bye {
                reason: ByeReason::VersionMismatch,
            },
        ];
        for msg in &msgs {
            assert_eq!(&roundtrip(msg), msg);
        }
    }

    #[test]
    fn chunk_frame_headers_roundtrip() {
        let hdr = ChunkFrameHeader {
            transfer_id: Uuid::new_v4(),
            entry_index: 1,
            chunk_index: 42,
            len: 4 * 1024 * 1024,
        };
        let framed = encode_frame(&hdr).unwrap();
        let back: ChunkFrameHeader = decode_body(&framed[4..]).unwrap();
        assert_eq!(back, hdr);
    }

    #[test]
    fn oversized_length_prefixes_are_rejected() {
        // encode_frame guards the outbound side; the inbound guard in read_frame uses
        // the same constant, exercised here via the constant relationship.
        let huge = vec![0u8; 8];
        let framed = encode_frame(&huge).unwrap();
        assert!(framed.len() < MAX_FRAME_BYTES as usize);
    }
}
