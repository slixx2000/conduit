//! Conduit core: protocol types, transport, and the chunked transfer engine.
//!
//! This crate is deliberately free of Tauri and UI dependencies so it can be tested
//! headless and reused from `conduit-cli`, benchmarks, and integration tests. Nothing
//! here may assume the underlying link is Thunderbolt — interface selection lives in
//! `conduit-net` and is injected in.
//!
//! Phase 1 scope: QUIC transport (`transport`), TOFU pairing and trust (`identity`),
//! manifests (`manifest`), the wire format (`wire`), and the transfer engine
//! (`transfer`). Everything runs over any IP link — localhost, LAN, or (Phase 2) the
//! Thunderbolt interface.

pub mod chunk;
pub mod error;
pub mod fsops;
pub mod identity;
pub mod manifest;
pub mod protocol;
pub mod transfer;
pub mod transport;
pub mod wire;

pub use chunk::{chunk_count, chunk_range, hash_chunk, FileHasher, DEFAULT_CHUNK_SIZE};
pub use error::{Error, Result};
pub use identity::{DeviceIdentity, Fingerprint, TrustStatus, TrustStore, TrustedPeer};
pub use manifest::{manifest_for_path, Entry, EntryKind, Manifest, TransferId};
pub use protocol::{Capabilities, DeviceId, Hello, PROTOCOL_VERSION};
pub use fsops::FsClient;
pub use transfer::{
    receive_one, send_manifest, send_path, serve_session, ReceiveOptions, SendOptions, Served,
    TransferEvent,
    DEFAULT_STREAM_COUNT,
};
pub use transport::{ConduitEndpoint, PeerInfo, PeerSession, Side};
pub use wire::{ByeReason, FsAttr, FsDirEntry, FsEntryKind, ALPN, MAX_FS_READ_BYTES};
