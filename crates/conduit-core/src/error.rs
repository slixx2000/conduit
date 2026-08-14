//! Typed errors.
//!
//! Every variant carries enough context to render actionable UI text — see
//! `docs/PROTOCOL.md` §5. Never fail silently, and never leave a partial file at its
//! final path.

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Protocol majors differ; the session must abort with `Bye{VersionMismatch}`.
    #[error("protocol version mismatch: this device speaks v{local}, peer speaks v{peer}")]
    VersionMismatch { local: u16, peer: u16 },

    /// A chunk failed its BLAKE3 check on arrival. Recoverable: request a resend.
    #[error("integrity check failed for chunk {chunk_index} of entry {entry_index}")]
    ChunkHashMismatch {
        entry_index: u32,
        chunk_index: u32,
    },

    /// Whole-file hash disagreed after reassembly — indicates an offset/ordering bug,
    /// not line noise. The temp file must be discarded, never renamed into place.
    #[error("integrity check failed for completed file {path}")]
    FileHashMismatch { path: String },

    /// A chunk index was requested that the manifest does not describe.
    #[error("chunk index {index} out of range: entry has {count} chunk(s)")]
    ChunkOutOfRange { index: u64, count: u64 },

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Postcard encode/decode failure — a malformed or truncated control frame.
    #[error("wire encoding error: {0}")]
    Wire(#[from] postcard::Error),

    /// A length prefix larger than the protocol allows. Defends against a hostile or
    /// corrupted peer making us allocate unbounded memory.
    #[error("control frame of {len} bytes exceeds the {max}-byte limit")]
    FrameTooLarge { len: u64, max: u64 },

    /// QUIC connection or stream failure (peer went away, cable pulled, timeout).
    #[error("connection error: {0}")]
    Connection(String),

    /// TLS / certificate machinery failed to set up. A local configuration problem,
    /// not a peer problem.
    #[error("crypto setup error: {0}")]
    Crypto(String),

    /// The peer's certificate no longer matches the fingerprint pinned at pairing.
    /// Possible impersonation: surface loudly and require an explicit re-pair.
    #[error(
        "peer identity changed: pinned fingerprint {pinned} but the connection presented \
         {presented} — possible impersonation; remove the trusted device and re-pair to accept \
         the new identity"
    )]
    FingerprintMismatch { pinned: String, presented: String },

    /// The user (either side) declined the pairing code. No trust stored.
    #[error("pairing was rejected — codes did not match or the user cancelled")]
    PairingRejected,

    /// The peer declined our `Offer`.
    #[error("peer rejected the transfer: {reason}")]
    Rejected { reason: String },

    /// The transfer failed after acceptance (peer reported an error in `Ack`, or the
    /// session died mid-flight).
    #[error("transfer failed: {reason}")]
    TransferFailed { reason: String },

    /// The peer sent something the protocol does not allow at this point.
    #[error("protocol violation: {0}")]
    Protocol(String),

    /// Placeholder for surface that is scaffolded but not yet built. Carries the
    /// roadmap phase so the message is actionable rather than mysterious.
    #[error("{what} is not implemented yet (planned for {phase})")]
    NotImplemented {
        what: &'static str,
        phase: &'static str,
    },
}

impl Error {
    /// Whether the transfer can continue after this error (e.g. by resending a chunk).
    pub fn is_recoverable(&self) -> bool {
        matches!(self, Error::ChunkHashMismatch { .. })
    }
}

// quinn's error types are many and fine-grained; collapse them into `Connection` while
// keeping the original message, which quinn renders well (e.g. "closed by peer: ...").
macro_rules! connection_error_from {
    ($($ty:ty),+ $(,)?) => {$(
        impl From<$ty> for Error {
            fn from(e: $ty) -> Self {
                Error::Connection(e.to_string())
            }
        }
    )+};
}

connection_error_from!(
    quinn::ConnectionError,
    quinn::ConnectError,
    quinn::WriteError,
    quinn::ReadError,
    quinn::ReadExactError,
    quinn::ClosedStream,
);

impl From<rustls::Error> for Error {
    fn from(e: rustls::Error) -> Self {
        Error::Crypto(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_mismatch_is_recoverable_but_file_mismatch_is_not() {
        let chunk = Error::ChunkHashMismatch {
            entry_index: 0,
            chunk_index: 7,
        };
        let file = Error::FileHashMismatch {
            path: "a.bin".into(),
        };
        assert!(chunk.is_recoverable());
        assert!(!file.is_recoverable());
    }

    #[test]
    fn messages_name_the_offending_item() {
        let e = Error::VersionMismatch { local: 1, peer: 2 };
        let rendered = e.to_string();
        assert!(rendered.contains("v1"), "{rendered}");
        assert!(rendered.contains("v2"), "{rendered}");
    }
}
