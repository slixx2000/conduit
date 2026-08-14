//! Chunk math and hashing.
//!
//! Files are split into fixed-size chunks; each chunk is hashed with BLAKE3 so that
//! integrity failures are caught on arrival and only the failing chunk is resent. The
//! same per-chunk hashes drive resume (see `docs/PROTOCOL.md` §3.5).
//!
//! BLAKE3 is mandatory here rather than SHA-2: at a 10–40 Gbps link speed SHA-256 is
//! itself the bottleneck (`docs/ARCHITECTURE.md` §4).

use std::ops::Range;

use crate::{Error, Result};

/// Default chunk size (4 MiB).
///
/// Larger chunks amortize per-chunk overhead; smaller chunks improve resume
/// granularity and shrink the manifest's hash list. Tuned empirically in Phase 2.
pub const DEFAULT_CHUNK_SIZE: u32 = 4 * 1024 * 1024;

/// Number of chunks a file of `total_bytes` occupies.
///
/// A zero-byte file has zero chunks — it is still transferred (the entry and its
/// whole-file hash are in the manifest), there is simply no payload to move.
pub fn chunk_count(total_bytes: u64, chunk_size: u32) -> u64 {
    debug_assert!(chunk_size > 0, "chunk size must be non-zero");
    let chunk_size = chunk_size as u64;
    total_bytes.div_ceil(chunk_size)
}

/// Byte range covered by `index`. The final chunk is short unless the file divides
/// evenly.
pub fn chunk_range(index: u64, chunk_size: u32, total_bytes: u64) -> Result<Range<u64>> {
    let count = chunk_count(total_bytes, chunk_size);
    if index >= count {
        return Err(Error::ChunkOutOfRange { index, count });
    }
    let start = index * chunk_size as u64;
    let end = (start + chunk_size as u64).min(total_bytes);
    Ok(start..end)
}

/// BLAKE3-256 over a chunk payload, as carried in `Manifest.Entry.chunk_hashes`.
pub fn hash_chunk(payload: &[u8]) -> [u8; 32] {
    *blake3::hash(payload).as_bytes()
}

/// Streaming hasher for whole-file digests.
///
/// Whole files are hashed incrementally as bytes stream past — never by loading the
/// file into memory. Lives here rather than at each call site so the hash algorithm
/// stays a single decision for the whole project.
#[derive(Debug, Clone, Default)]
pub struct FileHasher(blake3::Hasher);

impl FileHasher {
    pub fn new() -> Self {
        Self(blake3::Hasher::new())
    }

    pub fn update(&mut self, bytes: &[u8]) -> &mut Self {
        self.0.update(bytes);
        self
    }

    pub fn finalize(&self) -> [u8; 32] {
        *self.0.finalize().as_bytes()
    }

    /// Lowercase hex digest, for CLI output and log lines.
    pub fn finalize_hex(&self) -> String {
        self.0.finalize().to_hex().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_multiples_do_not_produce_a_trailing_empty_chunk() {
        assert_eq!(chunk_count(4096, 1024), 4);
    }

    #[test]
    fn partial_final_chunk_is_counted() {
        assert_eq!(chunk_count(4097, 1024), 5);
        assert_eq!(chunk_count(1, 1024), 1);
    }

    #[test]
    fn empty_file_has_no_chunks() {
        assert_eq!(chunk_count(0, 1024), 0);
        assert!(chunk_range(0, 1024, 0).is_err());
    }

    #[test]
    fn ranges_tile_the_file_without_gaps_or_overlap() {
        let (total, size) = (10_000u64, 4096u32);
        let count = chunk_count(total, size);

        let mut cursor = 0u64;
        for i in 0..count {
            let r = chunk_range(i, size, total).expect("index within count");
            assert_eq!(r.start, cursor, "gap or overlap at chunk {i}");
            cursor = r.end;
        }
        assert_eq!(cursor, total, "ranges must cover the whole file");
    }

    #[test]
    fn final_chunk_is_truncated_to_the_file_end() {
        let r = chunk_range(2, 4096, 10_000).unwrap();
        assert_eq!(r, 8192..10_000);
        assert_eq!(r.end - r.start, 1808);
    }

    #[test]
    fn out_of_range_index_reports_the_real_count() {
        match chunk_range(4, 1024, 4096) {
            Err(Error::ChunkOutOfRange { index, count }) => {
                assert_eq!((index, count), (4, 4));
            }
            other => panic!("expected ChunkOutOfRange, got {other:?}"),
        }
    }

    #[test]
    fn hashing_matches_the_blake3_reference_vector() {
        // Official BLAKE3 test vector for the input "abc".
        let got = hash_chunk(b"abc");
        assert_eq!(
            hex(&got),
            "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
        );
    }

    #[test]
    fn different_payloads_hash_differently() {
        assert_ne!(hash_chunk(b"chunk-a"), hash_chunk(b"chunk-b"));
    }

    #[test]
    fn streaming_in_pieces_matches_hashing_in_one_go() {
        let mut streamed = FileHasher::new();
        streamed.update(b"ab").update(b"c");
        assert_eq!(streamed.finalize(), hash_chunk(b"abc"));
        assert_eq!(
            streamed.finalize_hex(),
            "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
        );
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
