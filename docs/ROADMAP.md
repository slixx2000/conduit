# ROADMAP.md — Conduit build plan

Phased, each phase independently demoable with concrete acceptance criteria. **Do not advance until
the current phase's criteria pass.** Critically, the whole transport is proven over LAN/localhost
before any Thunderbolt-specific code, so most of the app can be built with zero special hardware.

---

## Phase 0 — Scaffold

**Goal:** an empty but running cross-platform app and a Rust workspace with CI.

- Cargo workspace with `conduit-core`, `conduit-discovery`, `conduit-net`, `conduit-fs` (stub).
- Tauri v2 app in `src-tauri` + React/TS/Tailwind frontend in `ui`, launching to a placeholder window.
- CI: `cargo build/test/clippy` + `npm run build` on **Linux and Windows** as a matrix. Linux is the
  required gate; Windows runs alongside it and must stay green (it's the primary dev machine, and the
  Windows-specific paths — USB4/TB networking, WinFsp, `.msi` — are the least exercised). Add macOS to
  the matrix when a runner is available; don't block Phase 0 on it.
- `conduit-cli` stub binary for headless testing.

**Acceptance:** `npm run tauri dev` opens a window; `cargo test --workspace` passes (even if trivial);
CI green on both Linux and Windows.

---

## Phase 1 — Transport MVP over IP (no Thunderbolt)

**Goal:** send one real file end-to-end between two app instances over localhost/LAN, encrypted, with
progress and integrity. This proves the entire core pipeline.

- `conduit-core`: QUIC connection via `quinn`+`rustls`; persistent self-signed cert per device.
- Pairing: TLS-exporter-derived 6-digit code, user confirms, cert fingerprint pinned (TOFU).
- `Hello` handshake with version check.
- Manifest build (single file): chunking + per-chunk & whole-file BLAKE3.
- `Offer`/`Accept`/data streams/`Complete`/`Ack` flow over N parallel streams.
- Receiver: streamed write to temp, per-chunk verify, whole-file verify, atomic rename.
- `Progress` events surfaced to a minimal UI (pick file → send → progress bar → done) and via
  `conduit-cli`.

**Acceptance:** run two instances on one machine (or two on a LAN); send a multi-GB file; it arrives
byte-identical (verify hash); progress updates live; a corrupted chunk (fault-injection test) is
detected and re-sent. All over TLS.

---

## Phase 2 — Thunderbolt / USB4 link integration

**Goal:** run the Phase 1 pipeline over a real direct cable at high speed.

- `conduit-net`: detect the Thunderbolt/USB4 interface (Linux `/sys/bus/thunderbolt` + netdev match;
  macOS/Windows equivalents), select its link-local/assigned address as the preferred bind address.
- Handle authorization state on Linux/Windows: detect "device present but not authorized" and prompt
  the user to approve (`boltctl authorize` guidance / OS dialog).
- Bind data path to the TB interface; keep LAN/WiFi as automatic fallback.
- Tune chunk size and parallel-stream count; add a throughput benchmark to `conduit-cli`.

**Acceptance:** two laptops joined by a TB/USB4 cable transfer a large file with the data path
confirmed to be on the Thunderbolt interface; measured throughput is meaningfully above the same
machines' WiFi/Ethernet; if unauthorized, the app shows a clear "approve the connection" prompt.

> If test hardware lacks Thunderbolt, keep everything on the IP fallback — the code path is identical;
> only the measured speed differs.

---

## Phase 3 — Discovery + drop-folder & browse UX ("Tier A")

**Goal:** zero-config peer discovery and the drag-and-drop "place to drop files on the other machine"
experience.

- `conduit-discovery`: advertise/browse `_conduit._tcp`; peers appear automatically in the UI with no
  IP entry. Reconnect to trusted peers silently via pinned fingerprint.
- Shared folder + inbox per peer; browse the peer's shared folder in-app.
- Drag-and-drop send; folder (recursive) transfers via the manifest tree.
- Resume-on-reconnect wired end-to-end (bitmap sidecar).
- Transfer queue UI: multiple/queued transfers, per-item progress, cancel.

**Acceptance:** with two paired laptops on a cable, dropping a folder onto a peer transfers the whole
tree; pulling the cable mid-transfer and reconnecting resumes without re-sending completed chunks;
peers appear/disappear in the list as the cable is connected/removed.

---

## Phase 4 — Virtual mounted volume ("Tier B", the true USB-drive feel)

**Goal:** the peer appears as a mounted drive in the OS file manager.

- `conduit-fs`: FUSE via `fuser` (Linux; macOS via macFUSE), WinFsp (or Dokan) on Windows.
- Map FS ops to protocol ops (`ListDir`/`Stat`/`ReadRange`/streamed writes/`FsMutate`) per
  `PROTOCOL.md §4`.
- Lazy streamed reads; large writes reuse the chunked engine; brief metadata caching for
  responsiveness.
- Installer flow to bootstrap macFUSE/WinFsp (detect, guide install, handle system-extension approval).

**Acceptance:** mounting a paired peer shows a drive in Finder/Explorer/Files; opening/copying a file
from it streams on demand and matches the source hash; copying a file *onto* it transfers to the peer;
unmount is clean.

---

## Phase 5 — Polish & release

**Goal:** shippable installers and a trustworthy everyday tool.

- Trusted-device management UI (list, rename, revoke pinned certs).
- Pause/resume, transfer history, notifications, settings (default inbox, auto-accept from trusted
  peers, chunk/stream tuning).
- Robust error surfacing (authorization, driver-missing, disconnect, hash-mismatch).
- Optional SPAKE2 pairing behind a flag.
- Signed/notarized bundles: `.deb`/AppImage (Linux), notarized `.dmg` (macOS), signed `.msi`
  (Windows).
- Docs: user-facing setup guide including Thunderbolt authorization and macFUSE/WinFsp install.

**Acceptance:** clean install on all three OSes from the produced bundles; a non-technical user can
connect a cable, pair once, and transfer both directions; v1 "definition of done" in `../CLAUDE.md`
met.

---

## Cross-cutting requirements (all phases)

- **Symmetric peers**, bidirectional by design.
- **conduit-core stays UI/Tauri-free** and testable headless.
- **Encryption always on** (QUIC/TLS 1.3); never a plaintext mode.
- **Stream to disk, never buffer whole files**; BLAKE3 for all hashing.
- **Typed errors with actionable UI text**; temp-file + atomic-rename only (no partials at final path).
- Keep `PROTOCOL_VERSION` and message formats in sync with `PROTOCOL.md` on every change.

## Suggested first prompt to Claude Code

> "Read CLAUDE.md and docs/. Execute Phase 0, then Phase 1. Build `conduit-core` first with an
> in-process loopback QUIC integration test that sends a multi-MB file and verifies the BLAKE3 hash
> end-to-end, before wiring the Tauri UI. Stop at the Phase 1 acceptance criteria and show me the test
> output."
