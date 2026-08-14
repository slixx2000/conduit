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

**Phases 0 (scaffold), 1 (transport MVP over IP), and 2 (TB/USB4 link integration, code-complete)
are done. Phase 3 (discovery + drop-folder UX) is the next work.** The workspace builds, tests, and
lints clean. The full transfer pipeline works over any IP link: QUIC/TLS 1.3 (`quinn` +
`rustls`/ring) with persistent self-signed device certs, TLS-exporter-derived 6-digit pairing with
TOFU fingerprint pinning, single-file manifests with per-chunk + whole-file BLAKE3,
`Offer`/`Accept`/N-parallel-data-streams/`Complete`/`Ack` per `docs/PROTOCOL.md`, streamed temp-file
writes with per-chunk verify → whole-file verify → atomic rename, and detect-and-resend on chunk
corruption (fault-injection tested). Verified end-to-end: a 2 GiB file between two `conduit` CLI
processes over localhost arrived byte-identical.

Phase 2 status: `conduit-net` does real link detection — Linux sysfs (`/sys/bus/thunderbolt` netdev
match + `authorized == 0` scan, unit-tested against fixture trees), Windows adapter
description/friendly-name matching ("Thunderbolt"/"USB4", virtual adapters filtered), macOS
bridge-interface heuristic. Unauthorized TB peers surface as `ThunderboltUnauthorized`; the app
shows an "approve the connection" banner (UI polls `link_status`) and `doctor` prints all links +
the preferred one. `conduit bench` (against `conduit receive --forever --trust`) measures the full
pipeline per streams×chunk combination; QUIC windows are tuned for high BDP (see
`docs/ARCHITECTURE.md` §8 for the loopback matrix). **The cable acceptance run (two TB-linked
laptops, throughput above WiFi) is pending hardware** — per the roadmap the IP-fallback code path is
identical, so nothing else blocks on it.

What exists: `conduit-core` (identity/trust, wire format — postcard, length-prefixed — transport,
transfer engine, loopback integration tests), `conduit-net` (link detection as above), the `conduit`
CLI (`send`/`receive [--forever]`/`bench`/`version`/`doctor`/`hash`), and the Tauri app:
always-listening endpoint, pairing dialog, pick file → send → live progress → done, inbox at
`Downloads/Conduit`, link/authorization banner. `conduit-discovery` (mDNS, Phase 3) and
`conduit-fs` (mount, Phase 4) are still typed stubs. CI runs on a Linux + Windows matrix (currently
disabled on GitHub: private repo without Actions billing).

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
    ├── ARCHITECTURE.md
    ├── PROTOCOL.md
    └── ROADMAP.md
```

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
cargo run -p conduit-cli -- doctor
cargo run -p conduit-cli -- hash <file>
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
