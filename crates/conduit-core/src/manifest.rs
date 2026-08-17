//! Transfer manifests (`docs/PROTOCOL.md` §3.1).
//!
//! A manifest fully describes a payload before any data moves: the entry tree, sizes,
//! chunking, and BLAKE3 hashes per chunk and per file. The hashes power integrity
//! *and* resume, so building the manifest is a full read of the source — that pass is
//! unavoidable and is done with a streaming hasher, never by loading files into
//! memory.
//!
//! Path convention: `Entry.path` is `/`-separated and **root-prefixed** — the first
//! segment is always `root_name` (`"photos"`, `"photos/2024/a.jpg"`). A single-file
//! transfer is one `File` entry whose path equals `root_name`.
//!
//! The transfer id is **deterministic**: the first 16 bytes of
//! [`Manifest::content_digest`]. Re-offering the same unchanged source yields the
//! same id, which is what lets a receiver recognize an interrupted transfer and
//! resume it (`docs/PROTOCOL.md` §3.5) without any sender-side session state.

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
    /// Root-prefixed, `/`-separated path — see the module docs.
    pub path: String,
    pub kind: EntryKind,
    /// Bytes; 0 for dirs.
    pub size: u64,
    /// Unix permission bits, best-effort on Windows.
    pub mode: u32,
    /// BLAKE3 per chunk, in order. Empty for dirs and zero-byte files.
    pub chunk_hashes: Vec<[u8; 32]>,
    /// BLAKE3 of the whole file contents. All-zero for dirs.
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

    /// Start of each entry's slice in the **global chunk index space**: entries in
    /// manifest order, chunks in order within each entry. This ordering is shared
    /// with the peer — it defines the bits of `Accept.have_chunks`.
    pub fn chunk_index_offsets(&self) -> Vec<u64> {
        let mut offsets = Vec::with_capacity(self.entries.len());
        let mut acc = 0u64;
        for e in &self.entries {
            offsets.push(acc);
            acc += e.chunk_hashes.len() as u64;
        }
        offsets
    }

    /// Digest over everything except the transfer id itself. Drives the
    /// deterministic transfer id and the receiver's resume marker: matching digests
    /// mean "the same content, chunked the same way".
    pub fn content_digest(&self) -> [u8; 32] {
        let encoded = postcard::to_stdvec(&(
            &self.root_name,
            self.total_bytes,
            self.chunk_size,
            &self.entries,
        ))
        .expect("manifest encodes");
        *blake3::hash(&encoded).as_bytes()
    }

    fn derived_transfer_id(&self) -> TransferId {
        let digest = self.content_digest();
        Uuid::from_slice(&digest[..16]).expect("16 bytes make a uuid")
    }

    /// Sanity-check an inbound manifest before acting on it. Guards the receiver
    /// against a peer whose framing decoded but whose contents are inconsistent —
    /// everything downstream (chunk math, staging layout, resume scan) assumes these
    /// hold. Path checks stop traversal attacks (`../`, absolute paths, drive
    /// letters) before any filesystem operation is derived from a path.
    pub fn validate(&self) -> Result<()> {
        if self.chunk_size == 0 {
            return Err(Error::Protocol("manifest chunk_size is zero".into()));
        }
        // Bound the attacker-controlled chunk size: the receiver allocates a buffer
        // this large per data stream, so an unbounded value is a memory-exhaustion
        // vector from a paired-but-hostile peer.
        if self.chunk_size > crate::chunk::MAX_CHUNK_SIZE {
            return Err(Error::Protocol(format!(
                "manifest chunk_size {} exceeds the {}-byte limit",
                self.chunk_size,
                crate::chunk::MAX_CHUNK_SIZE
            )));
        }
        if self.entries.is_empty() {
            return Err(Error::Protocol("manifest has no entries".into()));
        }
        if !valid_path_component(&self.root_name) {
            return Err(Error::Protocol(format!(
                "manifest root_name {:?} is not a plain file name",
                self.root_name
            )));
        }
        let mut sum = 0u64;
        for (i, e) in self.entries.iter().enumerate() {
            if !valid_entry_path(&self.root_name, &e.path) {
                return Err(Error::Protocol(format!(
                    "entry {i} path {:?} is not a safe root-prefixed relative path",
                    e.path
                )));
            }
            match e.kind {
                EntryKind::File => {
                    let expected = chunk_count(e.size, self.chunk_size);
                    if e.chunk_hashes.len() as u64 != expected {
                        return Err(Error::Protocol(format!(
                            "entry {i} declares {} chunk hashes but its size needs {expected}",
                            e.chunk_hashes.len()
                        )));
                    }
                }
                EntryKind::Dir => {
                    if e.size != 0 || !e.chunk_hashes.is_empty() {
                        return Err(Error::Protocol(format!(
                            "dir entry {i} must carry no bytes or chunk hashes"
                        )));
                    }
                }
                EntryKind::Symlink => {
                    return Err(Error::Protocol(
                        "symlink entries are not supported in this version".into(),
                    ));
                }
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

fn valid_path_component(c: &str) -> bool {
    !c.is_empty()
        && c != "."
        && c != ".."
        && !c.contains(['/', '\\', ':'])
}

fn valid_entry_path(root: &str, path: &str) -> bool {
    if path == root {
        return true;
    }
    match path.strip_prefix(root) {
        Some(rest) => {
            rest.starts_with('/') && rest[1..].split('/').all(valid_path_component)
        }
        None => false,
    }
}

/// Build a manifest for a file **or a directory tree**, streaming every file once to
/// compute per-chunk and whole-file hashes. Directory walks are sorted so the same
/// tree always produces the same manifest (and thus the same transfer id). Symlinks
/// are skipped with a warning — carrying them is future work.
///
/// Runs on the blocking pool: it is a CPU/disk bound pass over potentially many
/// gigabytes.
/// A source file left out of a manifest because it could not be read (locked,
/// permissions, vanished mid-walk). Reported alongside the manifest so callers can
/// surface it; the transfer proceeds without these files.
#[derive(Debug, Clone)]
pub struct SkippedSource {
    /// Root-prefixed `/`-separated path, like manifest entry paths.
    pub path: String,
    pub reason: String,
}

pub async fn manifest_for_path(
    path: &Path,
    chunk_size: u32,
) -> Result<(Manifest, Vec<SkippedSource>)> {
    assert!(chunk_size > 0, "chunk size must be non-zero");
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || manifest_for_path_sync(&path, chunk_size))
        .await
        .map_err(|e| Error::Protocol(format!("manifest task panicked: {e}")))?
}

fn manifest_for_path_sync(path: &Path, chunk_size: u32) -> Result<(Manifest, Vec<SkippedSource>)> {
    let root_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| {
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{} has no usable file name", path.display()),
            ))
        })?
        .to_owned();

    let meta = std::fs::metadata(path)?;
    let mut entries = Vec::new();
    let mut skipped = Vec::new();
    let mut total = 0u64;

    if meta.is_dir() {
        entries.push(dir_entry(root_name.clone()));
        walk_dir(
            path,
            &root_name,
            chunk_size,
            &mut entries,
            &mut skipped,
            &mut total,
        );
        // Real folders always contain the root dir entry; if not one file survived
        // the walk and something was skipped, there is nothing worth offering.
        if !skipped.is_empty() && !entries.iter().any(|e| e.kind == EntryKind::File) {
            return Err(Error::TransferFailed {
                reason: format!(
                    "no readable files in {root_name} — {} unreadable (first: {})",
                    skipped.len(),
                    skipped[0].reason
                ),
            });
        }
    } else if meta.is_file() {
        // A single-file send with an unreadable file has nothing to offer: hard error.
        entries.push(file_entry(path, root_name.clone(), chunk_size, &mut total)?);
    } else {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} is neither a regular file nor a directory", path.display()),
        )));
    }

    let mut manifest = Manifest {
        transfer_id: Uuid::nil(),
        root_name,
        total_bytes: total,
        chunk_size,
        entries,
    };
    manifest.transfer_id = manifest.derived_transfer_id();
    Ok((manifest, skipped))
}

/// Walk one directory level. Unreadable files and subdirectories are recorded in
/// `skipped` rather than aborting the walk — one locked file must not veto a whole
/// tree (game folders and AV locks make this routine, not exceptional).
fn walk_dir(
    dir: &Path,
    rel_prefix: &str,
    chunk_size: u32,
    entries: &mut Vec<Entry>,
    skipped: &mut Vec<SkippedSource>,
    total: &mut u64,
) {
    let items = match std::fs::read_dir(dir)
        .and_then(|it| it.collect::<std::io::Result<Vec<_>>>())
    {
        Ok(mut items) => {
            // Sort by name for a deterministic manifest (and therefore transfer id).
            items.sort_by_key(|e| e.file_name());
            items
        }
        Err(e) => {
            skipped.push(SkippedSource {
                path: rel_prefix.to_owned(),
                reason: e.to_string(),
            });
            return;
        }
    };

    for item in items {
        let name = match item.file_name().into_string() {
            Ok(n) => n,
            Err(raw) => {
                tracing::warn!("skipping {raw:?}: not valid UTF-8");
                continue;
            }
        };
        let rel = format!("{rel_prefix}/{name}");
        let file_type = match item.file_type() {
            Ok(t) => t,
            Err(e) => {
                skipped.push(SkippedSource {
                    path: rel,
                    reason: e.to_string(),
                });
                continue;
            }
        };
        if file_type.is_symlink() {
            tracing::warn!("skipping symlink {rel}: not supported yet");
            continue;
        }
        if file_type.is_dir() {
            entries.push(dir_entry(rel.clone()));
            walk_dir(&item.path(), &rel, chunk_size, entries, skipped, total);
        } else if file_type.is_file() {
            match file_entry(&item.path(), rel.clone(), chunk_size, total) {
                Ok(entry) => entries.push(entry),
                Err(e) => skipped.push(SkippedSource {
                    path: rel,
                    reason: e.to_string(),
                }),
            }
        }
    }
}

fn dir_entry(path: String) -> Entry {
    Entry {
        path,
        kind: EntryKind::Dir,
        size: 0,
        mode: 0o755,
        chunk_hashes: Vec::new(),
        file_hash: [0u8; 32],
    }
}

fn file_entry(abs: &Path, rel_path: String, chunk_size: u32, total: &mut u64) -> Result<Entry> {
    use std::io::Read;

    let mut file = std::fs::File::open(abs)?;
    let meta = file.metadata()?;
    let mut chunk_hashes = Vec::with_capacity(chunk_count(meta.len(), chunk_size) as usize);
    let mut file_hasher = FileHasher::new();
    let mut buf = vec![0u8; chunk_size as usize];
    let mut size = 0u64;

    loop {
        // Fill up to a whole chunk; short reads happen at EOF.
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
        size += filled as u64;
        if filled < buf.len() {
            break;
        }
    }

    *total += size;
    Ok(Entry {
        path: rel_path,
        kind: EntryKind::File,
        size,
        mode: unix_mode(&meta),
        chunk_hashes,
        file_hash: file_hasher.finalize(),
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
    async fn single_file_manifest_covers_the_file_and_hashes_each_chunk() {
        let data: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        let (_dir, path) = write_temp(&data);

        let m = manifest_for_path(&path, 4096).await.unwrap().0;
        m.validate().unwrap();
        assert_eq!(m.total_bytes, 10_000);
        assert_eq!(m.root_name, "payload.bin");
        assert_eq!(m.entries.len(), 1);

        let e = &m.entries[0];
        assert_eq!(e.path, "payload.bin");
        assert_eq!(e.chunk_hashes.len(), 3);
        assert_eq!(e.chunk_hashes[0], hash_chunk(&data[..4096]));
        assert_eq!(e.chunk_hashes[2], hash_chunk(&data[8192..]));
        assert_eq!(e.file_hash, *blake3::hash(&data).as_bytes());
    }

    #[tokio::test]
    async fn folder_manifest_walks_the_tree_in_stable_order() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("photos");
        std::fs::create_dir_all(root.join("2024")).unwrap();
        std::fs::create_dir_all(root.join("empty")).unwrap();
        std::fs::write(root.join("a.jpg"), b"aaaa").unwrap();
        std::fs::write(root.join("2024/b.jpg"), b"bbbbbb").unwrap();
        std::fs::write(root.join("2024/c.jpg"), b"").unwrap();

        let m = manifest_for_path(&root, 4096).await.unwrap().0;
        m.validate().unwrap();
        assert_eq!(m.root_name, "photos");
        assert_eq!(m.total_bytes, 10);

        let paths: Vec<(&str, EntryKind)> = m
            .entries
            .iter()
            .map(|e| (e.path.as_str(), e.kind))
            .collect();
        assert_eq!(
            paths,
            vec![
                ("photos", EntryKind::Dir),
                ("photos/2024", EntryKind::Dir),
                ("photos/2024/b.jpg", EntryKind::File),
                ("photos/2024/c.jpg", EntryKind::File),
                ("photos/a.jpg", EntryKind::File),
                ("photos/empty", EntryKind::Dir),
            ]
        );

        // Zero-byte file: no chunks, but a real (empty-input) hash.
        let c = &m.entries[3];
        assert!(c.chunk_hashes.is_empty());
        assert_eq!(c.file_hash, *blake3::hash(b"").as_bytes());

        // Rebuilding the same tree gives the same transfer id (deterministic resume key).
        let again = manifest_for_path(&root, 4096).await.unwrap().0;
        assert_eq!(m.transfer_id, again.transfer_id);
        // A content change gives a different id.
        std::fs::write(root.join("a.jpg"), b"AAAA").unwrap();
        let changed = manifest_for_path(&root, 4096).await.unwrap().0;
        assert_ne!(m.transfer_id, changed.transfer_id);
    }

    #[tokio::test]
    async fn global_chunk_offsets_are_cumulative() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("data");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("one.bin"), vec![1u8; 5000]).unwrap();
        std::fs::write(root.join("two.bin"), vec![2u8; 9000]).unwrap();

        let m = manifest_for_path(&root, 4096).await.unwrap().0;
        // Entries: dir(data)=0 chunks, one.bin=2 chunks, two.bin=3 chunks.
        assert_eq!(m.chunk_index_offsets(), vec![0, 0, 2]);
        assert_eq!(m.total_chunks(), 5);
    }

    #[test]
    fn validate_rejects_inconsistent_and_unsafe_manifests() {
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
        assert!(bad.validate().is_err(), "traversal in root_name must fail");

        let mut bad = good.clone();
        bad.entries[0].path = "b.bin".into();
        assert!(bad.validate().is_err(), "path outside the root must fail");

        let mut bad = good.clone();
        bad.entries[0].path = "a.bin/../../x".into();
        assert!(bad.validate().is_err(), "dot-dot segments must fail");

        let mut bad = good.clone();
        bad.entries[0].path = "a.bin/c:\\x".into();
        assert!(bad.validate().is_err(), "backslash/drive segments must fail");

        let mut bad = good.clone();
        bad.chunk_size = 0;
        assert!(bad.validate().is_err(), "zero chunk size must fail");

        // An oversized chunk_size is rejected even when internally consistent.
        let mut bad = good;
        bad.chunk_size = crate::chunk::MAX_CHUNK_SIZE + 1;
        bad.total_bytes = 4;
        bad.entries[0].size = 4;
        bad.entries[0].chunk_hashes = vec![[0u8; 32]];
        assert!(bad.validate().is_err(), "oversized chunk size must fail");
    }
}
