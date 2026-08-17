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
code-signing/notarization, the macOS package and its macFUSE mount port, and
on-cable validation — all blocked on credentials or hardware, not code.

**Phase 4 (virtual mounted volume) — complete on Windows and Linux.** A paired peer
mounts as a real drive (`conduit mount X: --peer <name>` on Windows,
`conduit mount ~/peer --peer <name>` on Linux, or "Mount as drive" in the app): its
shared folder appears in the file manager, reads stream over the link on demand, and
files copied onto the drive transfer to the peer through the ordinary verified
pipeline. The macFUSE port is pending a Mac to validate on. Needs the
[WinFsp](https://winfsp.dev) driver on Windows, or `fuse3` on Linux.

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

## Install

Grab the installer for your OS from the [Releases](https://github.com/slixx2000/conduit/releases)
page. While the repo is private, download them signed-in or with the GitHub CLI:

```bash
gh release download <tag> -R slixx2000/conduit                # every asset
gh release download <tag> -R slixx2000/conduit -p '*.msi'      # just one
```

Every build is **unsigned**, so each desktop OS shows a one-time warning the first
time you launch it — the bypass is noted per platform below. The installers ship the
desktop app (`conduit-app`) only; the headless `conduit` CLI comes from
`cargo build -p conduit-cli`.

### Windows — `.msi` or `-setup.exe`

Double-click either one (the `.msi` is the plain installer, the `-setup.exe` is the
NSIS one — pick whichever your tooling prefers). SmartScreen will warn: **More info →
Run anyway**. Silent installs:

```powershell
msiexec /i Conduit_1.1.0_x64_en-US.msi /qn      # .msi
.\Conduit_1.1.0_x64-setup.exe /S                # NSIS
```

*Mount as drive* additionally needs [WinFsp](https://winfsp.dev):
`winget install WinFsp.WinFsp`. Uninstall from Add or remove programs.

### Linux — `.deb` (Debian, Ubuntu, Mint)

```bash
sudo apt install ./Conduit_1.1.0_amd64.deb     # resolves dependencies; dpkg -i does not
conduit-app                                     # or launch it from your app menu
```

`fuse3` is a recommended dependency and normally comes along; install it explicitly
(`sudo apt install fuse3`) if *Mount as drive* reports FUSE missing. Remove with
`sudo apt remove conduit`.

### Linux — AppImage (any distro)

```bash
chmod +x Conduit_1.1.0_amd64.AppImage
./Conduit_1.1.0_amd64.AppImage
```

No installation and nothing to uninstall — delete the file. Two FUSE caveats, and
they are different things:

- The AppImage *format* needs libfuse2 to self-mount. Ubuntu 22.04+/Mint 21+ ship
  only libfuse3, so if it fails with `dlopen(): error loading libfuse.so.2`, either
  `sudo apt install libfuse2t64` (older releases: `libfuse2`) or skip it entirely
  with `./Conduit_1.1.0_amd64.AppImage --appimage-extract-and-run`.
- Conduit's own *Mount as drive* needs `fuse3`, which the AppImage cannot install
  for you: `sudo apt install fuse3`.

### macOS — `.dmg`

Open the `.dmg` and drag Conduit to Applications. Gatekeeper blocks unsigned apps on
first launch: **right-click the app → Open**, then confirm. From a terminal instead:

```bash
xattr -dr com.apple.quarantine /Applications/Conduit.app
```

*Mount as drive* is not available on macOS yet. Uninstall by dragging the app to the
Trash. (`Conduit_universal.app.tar.gz` is the same app bundle without the disk image —
use it only if you prefer extracting the `.app` by hand.)

For what to do once it is running — pairing, sending, mounting, troubleshooting — see
[`docs/SETUP.md`](docs/SETUP.md).

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
webview dependencies — WebView2 (ships with Windows 11 and current Edge), or on Linux:

```bash
sudo apt install libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev \
                 libxdo-dev libssl-dev libdbus-1-dev pkg-config patchelf
sudo apt install fuse3   # runtime only, for `conduit mount`
```

Only `src-tauri` needs those; `cargo build -p conduit-cli` works without them.
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
# its --dest directory is the share). Ctrl+C unmounts. On Linux the mount point is
# a directory (created if missing) instead of a drive letter.
cargo run --release -p conduit-cli -- mount X: --peer <name> --identity-dir idB
cargo run --release -p conduit-cli -- mount ~/peer --peer <name> --identity-dir idB

# Throughput benchmark (receiver side, then sender side; sweep with repeated flags)
cargo run --release -p conduit-cli -- receive --forever --trust --dest recv --identity-dir idA
cargo run --release -p conduit-cli -- bench --to <addr> --size-gib 1 --streams 2 --streams 8 --identity-dir idB --trust
```

## Releases

`.github/workflows/release.yml` builds installers for all three platforms
(Windows `.msi` + NSIS `.exe`, Linux `.deb` + AppImage, a universal macOS `.dmg`)
and uploads them to a **draft** GitHub release. Cut one by pushing a version tag:

```bash
git tag v1.1.0
git push origin v1.1.0
```

Then review the draft release on GitHub and publish it. (The Actions tab also has a
manual "Run workflow" button for a test build.) Building the bundles *locally* on
Linux works too (`npm run tauri build`), with one gotcha: the AppImage step
downloads `linuxdeploy-plugin-{gtk,gstreamer}.sh`, and the bundler's HTTP client
tries IPv6 first — on a network without working IPv6 it stalls until its global
timeout instead of falling back. Fetch them into `~/.cache/tauri/` with `curl` and
re-run; the `.deb` and `.rpm` are unaffected. Builds are currently **unsigned** —
users get a one-time OS prompt on first launch (see `docs/SETUP.md`); Linux needs
none. To sign later, add the secrets noted in the workflow's `env:` block; no other
change is required.

## License

Dual-licensed under either [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at
your option.
