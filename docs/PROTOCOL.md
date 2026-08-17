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
- Browse continuously; emit `PeerFound{id, name, addrs, port, fp}` / `PeerLost{id}` to the app. A
  peer advertises one address per interface; connect logic tries candidates best-first
  (cable-friendly IPv4 — APIPA included — before IPv6).
- Prefer the Thunderbolt interface (from `conduit-net`) for both advertise and connect so the cable
  peer ranks first. Never require manual IP entry.
- Current scope: mDNS runs IPv4-only, because the QUIC endpoint binds an IPv4 socket and IPv6
  link-local targets need zone indices to dial. Revisit when the transport goes dual-stack.

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

Conventions (implemented in `conduit-core::manifest`):

- **Paths are root-prefixed**: `Entry.path` is `/`-separated and its first segment is always
  `root_name` (`"photos"`, `"photos/2024/a.jpg"`). A single file is one `File` entry whose path
  equals `root_name`. Receivers must reject `..`, absolute paths, backslashes, and drive letters
  before deriving any filesystem path.
- **`transfer_id` is deterministic**: the first 16 bytes of the BLAKE3 of the postcard encoding of
  `(root_name, total_bytes, chunk_size, entries)`. Re-offering the same unchanged source yields the
  same id — that identity is what lets the receiver recognize and resume an interrupted transfer
  with no sender-side session state.
- **Global chunk index**: entries in manifest order, chunks in order within each entry. This is the
  bit order of `Accept.have_chunks` and the sort key for resume bookkeeping.
- Symlink entries are defined but not yet carried; current receivers reject them.

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

Also defined: `Reject{transfer_id, reason}`, `Cancel{transfer_id, reason}`, `Bye{reason}`,
`ResendChunk{transfer_id, entry_index, chunk_index}` (§3.3), and
`SkipEntry{transfer_id, entry_index, reason}`: the sender could not read that entry
(locked, deleted, permission) and will send none of its remaining chunks. The receiver stops
expecting them, excludes the entry from verification, removes any partial from the delivered
tree, and the transfer otherwise completes — both sides surface the skip as an event. If the
entry is already fully staged (resume), the data wins and the skip is ignored; if *every* file
entry is skipped, the receiver fails the transfer instead of delivering an empty success.
`Ack.result` is `Ok | Failed{reason}`. In Phase 1 `Accept.have_chunks` is always empty (the resume sidecar that
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

An in-flight transfer lives in a staging directory named by the (deterministic) transfer id —
`dest/.conduit-<id>.part/` — holding the partial tree plus a sidecar marker with the manifest's
content digest. On a new `Offer` whose digest matches an existing staging dir, the receiver
**rescans the staged bytes against the manifest's chunk hashes** to rebuild the have-bitmap, sends
it in `Accept.have_chunks`, and the sender transmits only the zero bits.

No bitmap is persisted: hashing the staged data *is* the record of what arrived, so a crash at any
moment (half-written chunks included) resumes correctly — invalid bytes fail their hash and are
fetched again, and a zero-filled region that matches a chunk hash is correct content by definition.
The receiver keeps the staging dir on connection loss and deletes it on protocol violations or
failed verification (that state is suspect) and after a successful finalize.

---

## 4. Virtual mount operations (Phase 4)

A filesystem session is a persistent peer session serving many request/response pairs. **Session
classification**: the first control message after `Hello` decides the session kind — `Offer` opens
a transfer session, `FsRequest` opens a filesystem session that lives until the mounting peer
disconnects (unmount). The serving side exposes one **share root** (the inbox directory in v1) and
validates every inbound path share-relative (`""` = the root; no `..`, absolute paths, or drive
letters).

```
FsRequest  { request_id: u64, op: FsOp }
FsOp       = ListDir{path} | Stat{path} | ReadRange{path, offset: u64, len: u32}
           | Mkdir{path} | Unlink{path} | Rename{from, to}
FsResponse { request_id: u64, result: FsResult }
FsResult   = DirListing{entries: Vec<FsDirEntry>} | Attr(FsAttr) | ReadStarted{len}
           | Done | Error{message}
FsDirEntry = { name, kind: File|Dir, size: u64, modified_unix: u64 }
```

`ReadRange` payloads answer on a **unidirectional stream** — `FsDataHeader{request_id, len}`
followed by `len` raw bytes — so bulk reads never stall metadata traffic; one request is capped at
`MAX_FS_READ_BYTES` (8 MiB) and reads short at EOF like an ordinary file. Op failures travel as
`FsResult::Error` and fail only that op, never the session.

**Writes re-use the transfer engine**: a file written into the mount spools locally on the mounting
side; when its handle closes, the spool is offered to the peer as an ordinary chunked transfer
(v1: it lands in the share root under its file name; in-place overwrite of an existing remote file
is refused; `Unlink` refuses directories).

Reads are lazy/streamed; metadata ops are cheap control-stream round-trips with short client-side
caching (plus the platform FS driver's own cache) to keep the file manager responsive.

---

## 5. Versioning & errors

- `PROTOCOL_VERSION: u16` bumped on any wire-incompatible change; majors must match or the session
  aborts with `Bye{VersionMismatch}`.
- All errors are typed and surfaced to the UI with actionable text (e.g. "device not authorized —
  approve the Thunderbolt connection", "hash mismatch — retrying chunk", "peer disconnected — transfer
  will resume on reconnect").
- Never fail silently; never leave a partial file at its final path (temp + atomic rename only).
