//! Transfer manifests (`docs/PROTOCOL.md` §3.1).
//!
//! A manifest fully describes a payload before any data moves: sizes, chunking, and
//! BLAKE3 hashes per chunk and per file. The hashes power integrity *and* resume, so
//! building the manifest is a full read of the source — that pass is unavoidable and
//! is done with a streaming hasher, never by loading the file into memory.
//!
//! Phase 1 builds single-file manifests; the `entries` vector and `Entry.path` exist
//! so folder trees (Phase 3) extend the format without a wire change.

use std::path::Path;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::chunk::{chunk_count, hash_chunk, FileHasher};
use crate::{Error, Result};

/// Identifies one transfer across control messages, data frames, and resume state.
pub type TransferId = Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntryKind {
    File,
    Dir,
    Symlink,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// Path relative to the transfer root, always `/`-separated on the wire.
    pub path: String,
    pub kind: EntryKind,
    /// Bytes; 0 for dirs.
    pub size: u64,
    /// Unix permission bits, best-effort on Windows.
    pub mode: u32,
    /// BLAKE3 per chunk, in order. Empty for dirs and zero-byte files.
    pub chunk_hashes: Vec<[u8; 32]>,
    /// BLAKE3 of the whole file contents.
    pub file_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub transfer_id: TransferId,
    /// File or folder name shown to the receiver; also the final on-disk name.
    pub root_name: String,
    pub total_bytes: u64,
    pub chunk_size: u32,
    pub entries: Vec<Entry>,
}

impl Manifest {
    /// Total number of chunks across all entries.
    pub fn total_chunks(&self) -> u64 {
        self.entries
            .iter()
            .map(|e| e.chunk_hashes.len() as u64)
            .sum()
    }

    /// Sanity-check an inbound manifest before acting on it. Guards the receiver
    /// against a peer whose framing decoded but whose contents are inconsistent —
    /// everything downstream (chunk math, temp-file sizing) assumes these hold.
    pub fn validate(&self) -> Result<()> {
        if self.chunk_size == 0 {
            return Err(Error::Protocol("manifest chunk_size is zero".into()));
        }
        if self.entries.is_empty() {
            return Err(Error::Protocol("manifest has no entries".into()));
        }
        if self.root_name.is_empty()
            || self.root_name.contains(['/', '\\'])
            || self.root_name == "."
            || self.root_name == ".."
        {
            return Err(Error::Protocol(format!(
                "manifest root_name {:?} is not a plain file name",
                self.root_name
            )));
        }
        let mut sum = 0u64;
        for (i, e) in self.entries.iter().enumerate() {
            let expected = chunk_count(e.size, self.chunk_size);
            if e.kind == EntryKind::File && e.chunk_hashes.len() as u64 != expected {
                return Err(Error::Protocol(format!(
                    "entry {i} declares {} chunk hashes but its size needs {expected}",
                    e.chunk_hashes.len()
                )));
            }
            sum += e.size;
        }
        if sum != self.total_bytes {
            return Err(Error::Protocol(format!(
                "manifest total_bytes {} disagrees with entry sizes {sum}",
                self.total_bytes
            )));
        }
        Ok(())
    }
}

/// Build a manifest for a single file, streaming it once to compute per-chunk and
/// whole-file hashes. Runs the read+hash loop on the blocking pool: it is a CPU/disk
/// bound pass over potentially many gigabytes.
pub async fn manifest_for_file(path: &Path, chunk_size: u32) -> Result<Manifest> {
    assert!(chunk_size > 0, "chunk size must be non-zero");
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || manifest_for_file_sync(&path, chunk_size))
        .await
        .map_err(|e| Error::Protocol(format!("manifest task panicked: {e}")))?
}

fn manifest_for_file_sync(path: &Path, chunk_size: u32) -> Result<Manifest> {
    use std::io::Read;

    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| {
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{} has no usable file name", path.display()),
            ))
        })?
        .to_owned();

    let mut file = std::fs::File::open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} is not a regular file", path.display()),
        )));
    }

    let mut chunk_hashes = Vec::with_capacity(chunk_count(meta.len(), chunk_size) as usize);
    let mut file_hasher = FileHasher::new();
    let mut buf = vec![0u8; chunk_size as usize];
    let mut total: u64 = 0;

    loop {
        // Fill up to a whole chunk; short reads happen on pipes and at EOF.
        let mut filled = 0;
        while filled < buf.len() {
            let n = file.read(&mut buf[filled..])?;
            if n == 0 {
                break;
            }
            filled += n;
        }
        if filled == 0 {
            break;
        }
        chunk_hashes.push(hash_chunk(&buf[..filled]));
        file_hasher.update(&buf[..filled]);
        total += filled as u64;
        if filled < buf.len() {
            break;
        }
    }

    let entry = Entry {
        path: file_name.clone(),
        kind: EntryKind::File,
        size: total,
        mode: unix_mode(&meta),
        chunk_hashes,
        file_hash: file_hasher.finalize(),
    };

    Ok(Manifest {
        transfer_id: Uuid::new_v4(),
        root_name: file_name,
        total_bytes: total,
        chunk_size,
        entries: vec![entry],
    })
}

#[cfg(unix)]
fn unix_mode(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode()
}

#[cfg(not(unix))]
fn unix_mode(_meta: &std::fs::Metadata) -> u32 {
    0o644
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_temp(bytes: &[u8]) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("payload.bin");
        std::fs::write(&path, bytes).unwrap();
        (dir, path)
    }

    #[tokio::test]
    async fn manifest_covers_the_file_and_hashes_each_chunk() {
        let data: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        let (_dir, path) = write_temp(&data);

        let m = manifest_for_file(&path, 4096).await.unwrap();
        m.validate().unwrap();
        assert_eq!(m.total_bytes, 10_000);
        assert_eq!(m.root_name, "payload.bin");
        assert_eq!(m.entries.len(), 1);

        let e = &m.entries[0];
        assert_eq!(e.chunk_hashes.len(), 3);
        assert_eq!(e.chunk_hashes[0], hash_chunk(&data[..4096]));
        assert_eq!(e.chunk_hashes[2], hash_chunk(&data[8192..]));
        assert_eq!(e.file_hash, *blake3::hash(&data).as_bytes());
    }

    #[tokio::test]
    async fn zero_byte_file_has_no_chunks_but_a_valid_hash() {
        let (_dir, path) = write_temp(b"");
        let m = manifest_for_file(&path, 4096).await.unwrap();
        m.validate().unwrap();
        assert_eq!(m.total_bytes, 0);
        assert!(m.entries[0].chunk_hashes.is_empty());
        assert_eq!(m.entries[0].file_hash, *blake3::hash(b"").as_bytes());
    }

    #[test]
    fn validate_rejects_inconsistent_manifests() {
        let good = Manifest {
            transfer_id: Uuid::new_v4(),
            root_name: "a.bin".into(),
            total_bytes: 4,
            chunk_size: 4096,
            entries: vec![Entry {
                path: "a.bin".into(),
                kind: EntryKind::File,
                size: 4,
                mode: 0o644,
                chunk_hashes: vec![[0u8; 32]],
                file_hash: [0u8; 32],
            }],
        };
        good.validate().unwrap();

        let mut bad = good.clone();
        bad.total_bytes = 5;
        assert!(bad.validate().is_err(), "size mismatch must fail");

        let mut bad = good.clone();
        bad.entries[0].chunk_hashes.clear();
        assert!(bad.validate().is_err(), "missing chunk hashes must fail");

        let mut bad = good.clone();
        bad.root_name = "../evil".into();
        assert!(bad.validate().is_err(), "path traversal in root_name must fail");

        let mut bad = good;
        bad.chunk_size = 0;
        assert!(bad.validate().is_err(), "zero chunk size must fail");
    }
}
