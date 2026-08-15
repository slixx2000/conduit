# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

---

## Conduit

> **Conduit** is a peer-to-peer, high-speed file transfer app for laptops connected over a direct
> Thunderbolt / USB4 cable. To the user it feels like plugging in a USB drive: the other machine
> shows up in the app (and, later, as a mounted volume) and you drag files across at 10–40 Gbps.
>
> `Conduit` is a working codename — rename freely (e.g. a ChainReaction-branded name) before release.

This file is the entry point for anyone (human or agent) working in this repo. Read it first, then
`docs/ARCHITECTURE.md` (system design + performance model), `docs/PROTOCOL.md` (wire format,
normative), and `docs/ROADMAP.md` (phase order + acceptance criteria).

---

## Current state of the repo

**Phases 0–5 are done on Windows** (pending items are hardware/credential-bound, listed below), and
the Phase 4 mount now has a **Linux FUSE backend** verified on this machine. The workspace builds,
tests, and lints clean.

Phase 5: trusted-device management (list/rename/revoke — app section + `conduit trusted`
subcommand + `TrustStore::rename`), persisted transfer **history** (`history.json`, capped, with
*Send again / Resume* for outgoing entries — resume rides the scan-based staging), desktop
**notifications** on finished/failed transfers (`tauri-plugin-notification`, toggleable),
**settings** (`settings.json`: inbox/shared dir with folder picker, chunk MiB, stream count,
notifications) applied live to sends/receives/mounts, a user-facing guide in `docs/SETUP.md`, and
an unsigned Windows `.msi` produced by `npm run tauri build`. **Still pending, deliberately**:
code-signing the `.msi` and notarizing a `.dmg` (needs certificates/Apple account), the macFUSE
mount port (needs a Mac), the Thunderbolt-cable acceptance runs (need
two cable-linked machines), and SPAKE2 pairing (roadmap-optional; TOFU + exporter-bound codes
remain the default — revisit if the threat model grows).

Phase 4: `PROTOCOL.md` §4 is implemented — sessions classify on their first control message
(`Offer` = transfer, `FsRequest` = filesystem), `conduit-core::fsops` provides the serving side
(share root = the inbox) and the `FsClient` used by mounts, with `ReadRange` payloads on uni
streams. `conduit-fs` mounts a peer via **WinFsp** (winfsp-rs): streamed reads, spool-on-write
shipping via the ordinary transfer engine on handle close (cleanup, not close — the kernel defers
close), brief stat caching, wildcard-filtered directory queries. Verified live on this machine:
`conduit mount X: --peer <name>` shows the peer's share in Explorer, a 100 MB read off the drive is
hash-identical (~180 MB/s loopback), a file copied onto the drive lands on the peer intact, mkdir/
rename/delete work through the drive, and killing/unmounting removes it cleanly. **Windows build
prerequisites**: WinFsp installed with its *Developer* feature (`winget install WinFsp.WinFsp
--override "/qn ADDLOCAL=ALL"`) and LLVM for libclang (`LIBCLANG_PATH`) — winfsp-sys generates
bindings against the installed SDK. Every crate that produces a Windows *binary* linking
`conduit-fs` needs the delayload build script (see `crates/conduit-cli/build.rs`).

**Linux mount (`fuse_mount.rs`, `fuser` 0.18 with `default-features = false`)** is implemented and
verified live over loopback on this machine: `conduit mount /mnt/point --to 127.0.0.1:<port>` shows
the peer's share, a 100 MB read off the drive is hash-identical (~325 MB/s), a `cp` onto the drive
lands on the peer intact, mkdir/rename/unlink work, and SIGINT unmounts cleanly. No build-time
system dependency (`default-features = false` skips libfuse; mounting goes through `fusermount3`),
so **only `/dev/fuse` + the `fuse3` package are needed at runtime** — `mount()` returns
`DriverMissing` when `/dev/fuse` is absent. FUSE speaks inodes and the protocol speaks
share-relative paths, so `Inodes` interns the mapping; inodes are never recycled. Deliberate parity
with the WinFsp backend: `rmdir` is refused (there is no recursive-delete op on the wire), in-place
overwrite of a remote file is refused (`EPERM`), and a file created inside a *subdirectory* of the
mount still lands in the peer's share root — `WriteHandler` ships one file into the inbox and
carries only the leaf name.

The pipeline: QUIC/TLS 1.3 (`quinn` + `rustls`/ring) with persistent self-signed device certs,
TLS-exporter-derived 6-digit pairing with TOFU fingerprint pinning, manifests for files **and
folder trees** (root-prefixed `/`-separated entry paths; deterministic transfer id = BLAKE3 of the
manifest content) with per-chunk + whole-file BLAKE3,
`Offer`/`Accept`/N-parallel-data-streams/`Complete`/`Ack` per `docs/PROTOCOL.md`, staging-dir
writes with per-chunk verify → per-file verify → atomic rename, detect-and-resend on chunk
corruption, and **scan-based resume**: interrupted transfers stay staged
(`dest/.conduit-<id>.part/`), and a re-offer of the same content rehashes staged bytes to rebuild
`Accept.have_chunks` — no bitmap persistence, crash-safe at any byte. All integration-tested over
loopback (incl. an abort-mid-transfer resume test) and verified 2 GiB byte-identical between two
CLI processes.

Phase 2 + `docs/TRANSPORTS.md`: `conduit-net` is a **pluggable link layer** — a `Transport` trait
with Thunderbolt/USB4, Ethernet (direct-cable vs LAN via the no-gateway + link-local rule), WiFi,
and USB-bridge (CDC-NCM/RNDIS; tethers with a gateway are classified as shared "USB network
device") implementations, aggregated and ranked `(direct, speed_tier, base_priority)` by
`TransportManager` (Linux probing is sysfs/fixture-unit-tested on all platforms; Windows uses
adapter metadata). The app's Connection panel shows all links with the active one and a manual
override (`link_status`/`set_link_override`); `doctor` prints the ranked list. The QUIC endpoint
deliberately stays wildcard-bound (see ARCHITECTURE §8) so a dying link falls back + resumes via
the send retry loop. Authorization banner, `conduit bench`, tuned QUIC windows as before.
Hardware-dependent acceptance (TB cable, two-laptop direct Ethernet, real bridge cable) pending
hardware.

Phase 3: `conduit-discovery` advertises/browses `_conduit._tcp` via `mdns-sd` (IPv4-scoped for now
— the endpoint binds a v4 socket; peers carry *all* advertised addresses and `connect_any` tries
candidates best-first). The app announces on startup, peers appear/disappear live in the UI,
drag-and-drop onto a peer card sends files/folders, transfers are cancellable (abort keeps the
peer's staged partial → later resume), and outgoing sends auto-retry on disconnect, resuming via
the staged state. CLI: `peers [--watch]`, `send --peer <name>`. **Deferred from Phase 3**: per-peer
shared-folder browsing + inbox-per-peer (not in the phase's acceptance criteria; shares its
machinery with Phase 4's `ListDir`/`ReadRange`, so build it there).

CI runs on a Linux + Windows matrix (currently disabled on GitHub: private repo without Actions
billing). `.github/workflows/release.yml` builds unsigned installers for all three platforms into a
draft GitHub release, triggered by pushing a `v*` tag.

Two things that will bite you if you don't know them:

- **Build the frontend before any cargo command.** `tauri-build` resolves `frontendDist`
  (`ui/dist`) at compile time and fails if it is missing. `npm run build` once after a clean
  checkout, then cargo works normally.
- **Everything runs from the repo root** — both `cargo` and `npm`. The Tauri CLI discovers
  `src-tauri/tauri.conf.json` by searching subfolders of the working directory, so it cannot be run
  from `ui/`. That is why `package.json`, `vite.config.ts`, and `tsconfig.json` sit at the root while
  the frontend *source* lives in `ui/` (Vite is configured with `root: "ui"`).

Development happens on Windows, so keep Windows green rather than treating it as a port later.
`docs/ROADMAP.md` ends with the project owner's intended opening prompt; treat it as the default plan
absent other instructions.

---

## The one constraint that shapes everything

USB is a **host-to-device** bus. Two laptops are both *hosts*. The USB controller (xHCI) in a normal
x86 laptop is **host-only silicon with no USB Device Controller**, so a laptop physically cannot
present itself as a real USB mass-storage device to another laptop. No driver can add hardware that
isn't there.

**Therefore we do NOT emulate a USB gadget.** We deliver the *experience* of "a drive appeared" one
layer up:

1. A **direct Thunderbolt/USB4 cable** gives us a point-to-point **IP network interface** for free
   (Linux `thunderbolt-net`, macOS Thunderbolt Bridge, Windows USB4/Thunderbolt networking).
2. Conduit runs an **encrypted peer-to-peer protocol over that IP link**.
3. The "USB drive" UX is a **virtual mounted volume** (FUSE / WinFsp) whose reads and writes stream
   over the link — not a literal USB device.

Everything in this codebase assumes: *"a fast IP link appears when the cable is connected; build on
top of IP."* This also means we can develop and test the entire stack over LAN/localhost with no
Thunderbolt hardware — the transport does not care what the underlying link is.

---

## Tech stack

| Layer | Choice | Notes |
|---|---|---|
| Core / transport | **Rust** + `tokio` | Performance-critical, testable as a pure lib |
| Wire transport | **QUIC** via `quinn` + `rustls` (TLS 1.3) | Built-in encryption + stream multiplexing |
| Discovery | **mDNS / DNS-SD** via `mdns-sd` | Advertises `_conduit._tcp` on the link |
| Hashing / integrity | **BLAKE3** (`blake3` crate) | SIMD/multithreaded; SHA-256 is too slow at 40 Gbps |
| Virtual filesystem | `fuser` (Linux/macOS), `winfsp`/`dokan` (Windows) | Phase 4 only |
| TB interface detection | custom (`conduit-net`) | sysfs on Linux, system APIs elsewhere |
| Desktop shell + UI | **Tauri v2** + **React + TypeScript + Tailwind** | Rust core, web frontend |
| Packaging | Tauri bundler | Linux (.deb/AppImage), macOS (.dmg), Windows (.msi) |

Rationale for Tauri: keeps the performance-critical core in Rust while letting the UI be built in the
TypeScript/React/Tailwind stack the project owner already works in. Electron was rejected (heavier, no
native transport story).

---

## Repository layout

```
conduit/
├── Cargo.toml                # Rust workspace root
├── package.json              # frontend + Tauri CLI; lives at the root, see "Current state"
├── vite.config.ts            # Vite is rooted at ui/, outputs to ui/dist
├── tsconfig.json
├── CLAUDE.md                 # this file
├── crates/
│   ├── conduit-core/         # protocol, transport (QUIC), transfer engine, manifests. Pure lib, heavily unit-tested.
│   ├── conduit-discovery/    # mDNS peer discovery / advertisement
│   ├── conduit-net/          # Thunderbolt/USB4 interface detection + address selection
│   ├── conduit-fs/           # virtual filesystem mount (fuser / winfsp) — Phase 4
│   └── conduit-cli/          # `conduit` binary: headless E2E driver + benchmarks
├── src-tauri/                # Tauri app: wires crates together, exposes commands to the UI
│   ├── Cargo.toml
│   ├── tauri.conf.json
│   ├── icons/
│   └── src/
├── ui/                       # React + TypeScript + Tailwind frontend *source only*
│   └── src/
├── .github/workflows/ci.yml  # Linux + Windows matrix
└── docs/
    ├── ARCHITECTURE.md   # system design + performance model
    ├── PROTOCOL.md       # wire format, normative
    ├── ROADMAP.md        # phase order + acceptance criteria
    ├── TRANSPORTS.md     # link classification/ranking rules
    └── SETUP.md          # end-user guide
```

`conduit-core` module map (read in this order — each layer only uses the ones above it):

| Module | Owns |
|---|---|
| `protocol` | `Hello`, `DeviceId`, `Capabilities`, `PROTOCOL_VERSION`. Handshake vocabulary only. |
| `wire` | Framing (u32-LE length + `postcard`) and every control message, incl. `FsOp`/`FsResult`. Chunk payloads travel as raw bytes *after* their header frame, never inside it. |
| `identity` | Persistent self-signed device cert, `Fingerprint`, `TrustStore` (TOFU pins). |
| `transport` | QUIC endpoint/`PeerSession`. The rustls verifiers accept *any* cert on purpose — trust is decided one layer up by fingerprint, not by the TLS chain. |
| `chunk` | Chunk arithmetic + streaming BLAKE3 (`FileHasher`). |
| `manifest` | File/folder-tree manifests; `TransferId` = BLAKE3 of the manifest content, so it is deterministic and drives resume. |
| `transfer` | The engine: `send_path` / `receive_one` / `serve_session` (which also classifies a session as transfer-vs-filesystem on its first control message), staging, verify, resume. |
| `fsops` | Phase 4: `serve_fs` (share-root side, validates every inbound path) and `FsClient` (mount side). Writes are deliberately absent — a mount write spools locally and re-uses `transfer`. |
| `error` | `Error`/`Result` for the whole crate. |

Per-device state lives in one directory (`--identity-dir` on the CLI, the Tauri app config dir in
the app): `device.key`/`device.crt` (persistent self-signed identity), `trusted.json` (pinned peer
fingerprints), plus the app's `settings.json` and `history.json`.

Keep `conduit-core` free of Tauri and UI dependencies so it can be tested headless and reused (CLI,
tests, benchmarks). Tauri commands in `src-tauri` are thin wrappers over the crates.

---

## How to work in this repo

- **Build in the order set by `docs/ROADMAP.md`.** Do not start Phase N+1 until Phase N's acceptance
  criteria pass. Each phase is independently demoable.
- **Prove the pipeline over LAN before touching Thunderbolt.** Phase 1 must send a real file
  end-to-end over localhost/LAN with progress + integrity before any TB-specific code is written.
- **The core is transport-agnostic.** Never hard-code Thunderbolt assumptions into `conduit-core`;
  interface selection lives in `conduit-net` and is injected in.
- **Symmetric peers.** Both machines run the identical app; either can send or receive. There is no
  dedicated "server". Design every feature bidirectionally.
- **Security is not optional even on a cable.** All data flows over TLS 1.3 (QUIC). First contact
  uses a pairing code + trust-on-first-use cert pinning (see `docs/PROTOCOL.md`).
- **`docs/PROTOCOL.md` is normative.** Message shapes, `PROTOCOL_VERSION` (defined in
  `conduit-core::protocol`), and the encoding choice (`postcard` vs CBOR — still open, pick once) must
  stay in lockstep with the code. Changing the wire format means editing that doc in the same change.
- **Record resolved design decisions** in `docs/ARCHITECTURE.md §8 "Open decisions"` rather than
  leaving them implicit in code (encoding, chunk size, stream count, QUIC-vs-TCP fast path).
- **Favor streaming and zero-copy.** At these speeds the disk (SATA SSD ≈ 4 Gbps, NVMe ≈ 25–56 Gbps)
  is often the real bottleneck. Stream to disk; avoid buffering whole files in memory.

## Commands

All of these run from the repo root.

```bash
# First time / after a clean checkout. The frontend build must precede any cargo
# command: tauri-build resolves frontendDist (ui/dist) and fails if it is missing.
npm install
npm run build

# Linux only — src-tauri's system deps (the other crates need none):
sudo apt install libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev \
                 libxdo-dev libssl-dev libdbus-1-dev pkg-config patchelf
# ...and `fuse3` at runtime for `conduit mount` (/dev/fuse + fusermount3).

# Rust
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings   # CI treats warnings as errors

# Single crate / single test (the usual inner loop while building conduit-core)
cargo test -p conduit-core
cargo test -p conduit-core <test_name> -- --nocapture

# App
npm run tauri dev        # Tauri v2 + React frontend, hot-reloading
npm run tauri build      # release bundles

# Headless — the scripted E2E and benchmark path
cargo run -p conduit-cli -- doctor          # ranked links + identity fingerprint
cargo run -p conduit-cli -- hash <file>     # verify a transfer byte-for-byte

# Two instances on one machine: --identity-dir gives each its own device identity +
# trust store; --trust skips the interactive pairing prompt so scripts don't block.
cargo run --release -p conduit-cli -- receive --dest recv --identity-dir idA [--forever]
cargo run --release -p conduit-cli -- send <file-or-dir> --peer <name> --identity-dir idB
cargo run --release -p conduit-cli -- peers [--watch]
cargo run --release -p conduit-cli -- mount X: --peer <name> --identity-dir idB   # Windows
cargo run --release -p conduit-cli -- trusted list|rename|revoke
cargo run --release -p conduit-cli -- bench --to <addr> --size-gib 1 --streams 8
```

## Testing strategy

- `conduit-core`: unit + integration tests over an in-process loopback QUIC connection. No hardware.
- End-to-end: two app instances on one machine over `127.0.0.1` / link-local, then two machines over
  LAN, then finally over a real Thunderbolt cable for throughput validation.
- `conduit-cli` (the `conduit` binary) is the scripted E2E and benchmark path, so the pipeline can be
  driven without the GUI. `hash` exists to verify a transferred file byte-for-byte against its source.

## Definition of done for the whole project (v1)

Two laptops joined by a Thunderbolt/USB4 cable can, with no manual network setup: discover each other
in the app, pair with a confirmation code, and transfer files in both directions with live progress,
resume-on-reconnect, and end-to-end integrity — and (Phase 4) mount the peer as a drive that behaves
like external storage in the OS file manager.
