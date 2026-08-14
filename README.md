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

**Phase 2 (Thunderbolt/USB4 link integration) — code-complete.** Two instances pair with
a 6-digit code (TOFU cert pinning), then transfer files over QUIC/TLS 1.3 with parallel
streams, live progress, per-chunk + whole-file BLAKE3 verification, and automatic resend
of corrupted chunks. `conduit-net` detects the Thunderbolt/USB4 interface (and
unauthorized peers awaiting approval) on Linux and Windows; transfers prefer it and fall
back to LAN/WiFi. `conduit bench` measures throughput per streams×chunk configuration.
The on-cable acceptance run awaits two TB-linked machines — every code path is identical
over LAN. Try it headless: `conduit receive` on one side,
`conduit send <file> --to <addr>` on the other. See [`docs/ROADMAP.md`](docs/ROADMAP.md)
for the phase plan and acceptance criteria.

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
# share one machine, --trust skips the interactive pairing prompt for scripting)
cargo run --release -p conduit-cli -- receive --listen 127.0.0.1:44553 --dest recv --identity-dir idA
cargo run --release -p conduit-cli -- send <file> --to 127.0.0.1:44553 --identity-dir idB

# Throughput benchmark (receiver side, then sender side; sweep with repeated flags)
cargo run --release -p conduit-cli -- receive --forever --trust --dest recv --identity-dir idA
cargo run --release -p conduit-cli -- bench --to <addr> --size-gib 1 --streams 2 --streams 8 --identity-dir idB --trust
```

## License

MIT OR Apache-2.0.
