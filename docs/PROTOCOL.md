# PROTOCOL.md — Conduit wire protocol (v1)

Defines discovery, pairing, and the transfer protocol between two Conduit peers. Peers are
**symmetric** — the same software runs on both ends; "initiator" and "responder" are per-session
roles, not fixed identities. All framing is versioned so the protocol can evolve.

Transport baseline: **QUIC (via `quinn`) with TLS 1.3**. One QUIC connection per peer session, using:
- one bidirectional **control stream** (metadata, offers, acks), and
- N unidirectional **data streams** (chunk payloads).

Message encoding (**resolved**, see `conduit-core::wire`): **`postcard`**, framed as a **u32
little-endian length prefix** followed by the postcard bytes. Chunk payloads travel as raw bytes
*after* their header frame, never through the serializer. A single control frame is capped at
64 MiB (`MAX_FRAME_BYTES`). The TLS ALPN identifier is **`conduit/1`**; bump it together with
`PROTOCOL_VERSION` majors. All multi-byte integers little-endian. Hashes are **BLAKE3-256**
(32 bytes) unless noted — including certificate fingerprints, which are the BLAKE3-256 of the
peer's DER certificate (lowercase hex when rendered).

---

## 1. Discovery (mDNS / DNS-SD)

Service type: `_conduit._tcp`.

TXT record keys:

| Key | Meaning |
|---|---|
| `v` | protocol major version (e.g. `1`) |
| `id` | stable device UUID (persisted locally) |
| `name` | human-friendly device name (e.g. "Shaun's OMEN") |
| `port` | QUIC/control port |
| `fp` | short fingerprint of this device's long-term cert (for reconnection trust) |

Behavior:
- On startup and whenever the preferred interface changes, (re)advertise on that interface.
- Browse continuously; emit `PeerFound{id, name, addr, port, fp}` / `PeerLost{id}` to the app.
- Prefer the Thunderbolt interface (from `conduit-net`) for both advertise and connect so the cable
  peer ranks first. Never require manual IP entry.

---

## 2. Connection + pairing

### 2.1 First contact (trust-on-first-use)

1. Initiator opens a QUIC connection to the responder's advertised `addr:port`. Both sides use a
   **persistent self-signed certificate** (generated once, stored locally, keyed to the device UUID).
2. Because certs are self-signed, the TLS session is encrypted but not yet *trusted*. Both sides
   derive a **6-digit pairing code** from the TLS exporter/keying material
   (`TLS-Exporter("conduit-pair", "", 4 bytes)` → `u32` (LE) `mod 1_000_000`, zero-padded to six
   digits), so the code is bound to *this* channel and cannot be replayed onto another.
3. Each app displays the same 6-digit code. The user confirms it matches on both machines.
4. On confirmation, each side **pins the peer's certificate fingerprint** under its device UUID as a
   *trusted device*. Future connections verify the pinned fingerprint and skip the code entirely.

> Rejection: if codes don't match (potential MITM, unlikely on a cable but cheap to defend), either
> user cancels and the connection is dropped; no trust is stored.

### 2.2 Optional hardening (upgrade path)

Replace the exporter-derived code with a **PAKE (SPAKE2)** keyed on the code: the user types/reads a
short code that actively authenticates the channel, closing even a theoretical MITM before any file
metadata is exchanged. Keep TOFU as the default for v1; expose SPAKE2 behind a flag.

### 2.3 `Hello` handshake (control stream, every session)

After the QUIC connection is up (and trust verified for known peers):

```
Hello {
  version: u16,          // PROTOCOL_VERSION
  device_id: Uuid,
  device_name: String,
  capabilities: u32,     // bitflags: RESUME, MOUNT, COMPRESSION, ...
}
```

Both sides exchange `Hello`; if `version` majors differ, abort with `Bye{reason: VersionMismatch}`.

---

## 3. Transfer protocol

### 3.1 Manifest

Before sending, the initiator builds a manifest describing the payload:

```
Manifest {
  transfer_id: Uuid,
  root_name: String,             // file or folder name shown to receiver
  total_bytes: u64,
  chunk_size: u32,               // bytes, e.g. 4 MiB
  entries: Vec<Entry>,
}

Entry {
  path: String,                  // relative path within the transfer
  kind: File | Dir | Symlink,
  size: u64,                     // 0 for dirs
  mode: u32,                     // unix perms (best-effort on Windows)
  chunk_hashes: Vec<[u8; 32]>,   // BLAKE3 per chunk, in order (files only)
  file_hash: [u8; 32],          // BLAKE3 of whole file
}
```

`chunk_hashes` powers both integrity and resume. For huge trees, the manifest may itself be streamed
in framed pages rather than sent as one blob.

### 3.2 Control message flow

```
Initiator                         Responder
   │  Offer{manifest}  ───────────►│   (UI: accept? choose dest / auto-inbox)
   │◄──────────  Accept{transfer_id, have_chunks: BitmapOrEmpty}
   │                               │   have_chunks non-empty ⇒ resuming
   │  (open N data streams; send only missing chunks)
   │  DataStream × N  ────────────►│   (write to temp, verify each chunk hash)
   │◄──────────  Progress{transfer_id, bytes_done}   (periodic, either direction)
   │  Complete{transfer_id}  ─────►│   (verify file_hash; atomic rename into place)
   │◄──────────  Ack{transfer_id, ok | Err{...}}
```

Also defined: `Reject{transfer_id, reason}`, `Cancel{transfer_id, reason}`, `Bye{reason}`, and
`ResendChunk{transfer_id, entry_index, chunk_index}` (§3.3). `Ack.result` is
`Ok | Failed{reason}`. In Phase 1 `Accept.have_chunks` is always empty (the resume sidecar that
populates it lands in Phase 3); the bitmap orders chunks by **global index** — entries in manifest
order, chunks in order within each entry, bit `i` of byte `i/8` at position `i%8` (LSB-first).

### 3.3 Data stream framing

Each unidirectional data stream carries a sequence of chunk frames:

```
ChunkFrame {
  transfer_id: Uuid,
  entry_index: u32,     // index into Manifest.entries
  chunk_index: u32,     // which chunk of that entry
  len: u32,             // payload length (== chunk_size except final chunk)
  // followed by `len` bytes of payload
}
```

Receiver computes BLAKE3 over the payload and checks it against
`entries[entry_index].chunk_hashes[chunk_index]`. Mismatch ⇒ request re-send of that (entry, chunk)
via a `ResendChunk` control message; repeated failure ⇒ fail the transfer with a clear error.

Chunk-to-stream assignment is arbitrary (round-robin or work-stealing across the N streams); ordering
is recovered from `(entry_index, chunk_index)`, so streams need not be ordered relative to each other.

### 3.4 Integrity

- Per-chunk BLAKE3 verified on arrival (fast fail, enables targeted resend).
- Whole-file BLAKE3 verified before the atomic rename (defends against reassembly/offset bugs).
- Only after whole-file verification is the temp file renamed into its final path.

### 3.5 Resume

Receiver persists a small sidecar per in-flight transfer: `{transfer_id, manifest_ref, received_chunk_bitmap}`.
On reconnect for the same `transfer_id`, the receiver sends its bitmap in `Accept.have_chunks`; the
sender transmits only the zero bits. Completed-and-verified files are skipped entirely (their whole-file
hash already matches).

---

## 4. Virtual mount operations (Phase 4)

When a peer is mounted (`conduit-fs`), filesystem callbacks map onto the same session:

| FS op | Protocol action |
|---|---|
| `readdir` | `ListDir{path}` → `DirListing{entries}` (cached briefly) |
| `getattr` | `Stat{path}` → `Attr{...}` |
| `read(off,len)` | `ReadRange{path, off, len}` → streamed chunk(s) |
| `write(off,buf)` | buffer locally; on flush/close, emit `Offer`+transfer for the file |
| `rename`/`unlink`/`mkdir` | corresponding `FsMutate{op}` control messages |

Reads are lazy/streamed; large writes reuse the chunked transfer engine. Metadata ops are cheap
control-stream round-trips with short client-side caching to keep the file manager responsive.

---

## 5. Versioning & errors

- `PROTOCOL_VERSION: u16` bumped on any wire-incompatible change; majors must match or the session
  aborts with `Bye{VersionMismatch}`.
- All errors are typed and surfaced to the UI with actionable text (e.g. "device not authorized —
  approve the Thunderbolt connection", "hash mismatch — retrying chunk", "peer disconnected — transfer
  will resume on reconnect").
- Never fail silently; never leave a partial file at its final path (temp + atomic rename only).
