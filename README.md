# Conduit

Peer-to-peer, high-speed file transfer between two laptops joined by a direct
Thunderbolt/USB4 cable. The other machine shows up in the app — and eventually as a
mounted volume — and you drag files across at 10–40 Gbps.

Two laptops are both USB *hosts*, so neither can present itself as a USB drive to the
other. Conduit instead uses the point-to-point **IP link** a Thunderbolt/USB4 cable
provides, runs an encrypted QUIC protocol over it, and delivers the "a drive appeared"
experience as a virtual filesystem. The full reasoning is in
[`CLAUDE.md`](CLAUDE.md) and [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

Because the transport only assumes IP, the entire stack develops and tests over
localhost or LAN with no Thunderbolt hardware.

## Status

**Phase 5 (polish & release) — complete on Windows.** Trusted-device management
(rename/revoke pinned devices), persisted transfer history with one-click
*Send again / Resume*, desktop notifications, and settings (inbox location, chunk
size, stream count) — plus an unsigned `.msi` installer from `npm run tauri build`.
See [`docs/SETUP.md`](docs/SETUP.md) for the user guide. Remaining for a public v1:
code-signing/notarization, Linux/macOS packages and their FUSE mount ports, and
on-cable validation — all blocked on credentials or hardware, not code.

**Phase 4 (virtual mounted volume) — complete on Windows.** A paired peer mounts as a
real drive (`conduit mount X: --peer <name>`, or "Mount as drive" in the app): its
shared folder appears in Explorer, reads stream over the link on demand, and files
copied onto the drive transfer to the peer through the ordinary verified pipeline.
FUSE (Linux) and macFUSE ports are pending hardware to validate on. Requires the
[WinFsp](https://winfsp.dev) driver at runtime.

**Phase 3 (discovery + drop-folder UX) — complete.** Peers find each other over mDNS —
no IP entry — and pair once with a 6-digit code (TOFU cert pinning). Files **and folder
trees** transfer over QUIC/TLS 1.3 with parallel streams, live progress, per-chunk +
whole-file BLAKE3 verification, and automatic resend of corrupted chunks. Interrupted
transfers stay staged and **resume on reconnect** without re-sending verified chunks.
In the app: drag files onto a peer card to send; transfers are cancellable.
`conduit-net` is a pluggable link layer: it enumerates and ranks every usable link —
Thunderbolt/USB4, direct or LAN Ethernet, WiFi, USB bridge cables — auto-selects the
fastest (a direct cable beats a shared network), and the app's Connection panel shows
alternatives with a manual override. A plain Ethernet cable between two laptops works
with zero configuration via link-local addressing. On-cable throughput validation
awaits two cable-linked machines — every code path is identical over LAN. Try
it headless: `conduit receive` on one side, `conduit send <path> --peer <name>` on the
other. See [`docs/ROADMAP.md`](docs/ROADMAP.md) for the phase plan and acceptance
criteria.

## Layout

| Path | Purpose |
|---|---|
| `crates/conduit-core` | Protocol types, transport, transfer engine. No UI/Tauri deps. |
| `crates/conduit-discovery` | mDNS/DNS-SD peer advertisement and browsing. |
| `crates/conduit-net` | Thunderbolt/USB4 interface detection, address selection. |
| `crates/conduit-fs` | Virtual mounted volume (Phase 4). |
| `crates/conduit-cli` | Headless driver (`conduit`) for scripted E2E tests and benchmarks. |
| `src-tauri` | Desktop shell; thin glue exposing the crates to the UI. |
| `ui` | React + TypeScript + Tailwind frontend source (Vite is rooted here). |

## Development

Prerequisites: Rust (stable, MSVC toolchain on Windows), Node 20+, and the platform
webview dependencies — WebView2 (ships with Windows 11 and current Edge), or
`libwebkit2gtk-4.1-dev` and friends on Linux (see `.github/workflows/ci.yml`).
Building on Windows additionally needs **WinFsp with its Developer feature**
(`winget install WinFsp.WinFsp --override "/qn ADDLOCAL=ALL"`) and **LLVM** for
libclang (`winget install LLVM.LLVM`, then set `LIBCLANG_PATH` to
`C:\Program Files\LLVM\bin`) — the WinFsp bindings are generated against the
installed SDK.

Everything runs from the repo root — the Tauri CLI locates `src-tauri/tauri.conf.json`
by searching subfolders of the working directory, so `package.json` lives at the root
while the frontend *source* lives in `ui/`.

```bash
npm install

# Build the frontend once before any cargo command: tauri-build resolves
# `frontendDist` (ui/dist) and fails if it is missing.
npm run build

# Rust
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings

# Single crate / single test
cargo test -p conduit-core
cargo test -p conduit-core chunk -- --nocapture

# Desktop app
npm run tauri dev

# Headless
cargo run -p conduit-cli -- doctor
cargo run -p conduit-cli -- hash <file>

# Headless end-to-end transfer (two terminals; --identity-dir lets two instances
# share one machine, --trust skips the interactive pairing prompt for scripting).
# The receiver announces itself over mDNS; the sender finds it by name.
cargo run --release -p conduit-cli -- receive --dest recv --identity-dir idA
cargo run --release -p conduit-cli -- send <file-or-folder> --peer <name> --identity-dir idB
cargo run --release -p conduit-cli -- peers            # who is visible right now?

# Mount a peer's shared folder as a drive (peer runs `receive --forever`;
# its --dest directory is the share). Ctrl+C unmounts.
cargo run --release -p conduit-cli -- mount X: --peer <name> --identity-dir idB

# Throughput benchmark (receiver side, then sender side; sweep with repeated flags)
cargo run --release -p conduit-cli -- receive --forever --trust --dest recv --identity-dir idA
cargo run --release -p conduit-cli -- bench --to <addr> --size-gib 1 --streams 2 --streams 8 --identity-dir idB --trust
```

## License

MIT OR Apache-2.0.
