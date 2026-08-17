# ARCHITECTURE.md — Conduit

System design for a direct-cable, peer-to-peer, high-speed file transfer app. Read `../CLAUDE.md` first
for the core constraint and stack.

---

## 1. Why the design looks like this

The naive mental model — "make my laptop appear as a USB stick on yours" — is impossible between two
x86 laptops, because presenting as a USB mass-storage device requires the USB controller to run in
**device (gadget) mode**, which needs a USB Device Controller (UDC) in silicon. Laptops ship
**host-only xHCI** controllers with no UDC. (Phones and Raspberry Pis can do gadget mode because their
SoCs have dual-role controllers; laptops can't.)

What a Thunderbolt/USB4 cable *does* give us is a **point-to-point IP link** exposed by the OS as a
network interface:

- **Linux:** the `thunderbolt-net` kernel module creates a `thunderbolt0`-style interface once the
  peer is authorized (`boltctl`). IPv6 link-local (`fe80::…`) comes up automatically.
- **macOS:** "Thunderbolt Bridge" appears as a network service/interface automatically.
- **Windows 11:** USB4 / Thunderbolt networking (and Intel's *Thunderbolt Share*) expose an
  equivalent IP link.

So Conduit is, at its heart, **a LAN file-transfer app whose "LAN" happens to be a 10–40 Gbps direct
cable.** That framing gives us three wins: it's testable over ordinary localhost/LAN with no special
hardware, it degrades gracefully to WiFi/Ethernet when there's no cable, and it reuses mature IP-based
tooling (QUIC, TLS, mDNS).

---

## 2. Layered architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│  UI  (Tauri v2 · React · TypeScript · Tailwind)                        │
│  peer list · pairing dialog · transfer queue · progress · mount toggle │
└───────────────▲───────────────────────────────────┬────────────────────┘
                │ Tauri commands / events            │
┌───────────────┴───────────────────────────────────▼────────────────────┐
│  src-tauri  (thin glue: exposes core to UI, owns app state)             │
└───┬───────────────┬───────────────┬───────────────┬────────────────────┘
    │               │               │               │
┌───▼─────┐   ┌─────▼──────┐  ┌─────▼───────┐  ┌────▼────────┐
│ conduit-│   │  conduit-  │  │  conduit-   │  │  conduit-fs │
│  net    │   │ discovery  │  │   core      │  │ (Phase 4)   │
│ TB iface│   │  mDNS      │  │ transport + │  │ FUSE/WinFsp │
│ detect  │   │ advertise/ │  │ transfer    │  │ virtual     │
│ + addr  │   │  browse    │  │ engine +    │  │ volume      │
│ select  │   │            │  │ protocol    │  │             │
└─────────┘   └────────────┘  └──────┬──────┘  └─────────────┘
                                     │
                         ┌───────────▼────────────┐
                         │  QUIC / TLS 1.3 (quinn) │
                         │  over the IP link       │
                         └────────────────────────┘
```

### Layer responsibilities

**`conduit-net` — link selection.**
Detects available interfaces and identifies the Thunderbolt/USB4 one so the data path can bind to the
fastest link. On Linux, walk `/sys/bus/thunderbolt/devices` and match the resulting netdev; also
detect authorization state and surface a "please authorize the connected device" signal. Falls back
to "any usable interface" (LAN/WiFi) when no TB link exists. Output: a preferred local address to bind
transfers to.

**`conduit-discovery` — finding the peer.**
Advertises a `_conduit._tcp` service via mDNS/DNS-SD (with the device's friendly name, protocol
version, and control port) and browses for peers. Prefer the Thunderbolt interface for advertisement
so peers on the cable are found first. Emits `PeerFound` / `PeerLost` events upward. No manual IP
entry is ever required.

**`conduit-core` — the engine.** Transport (QUIC), the wire protocol (see `PROTOCOL.md`), pairing/auth,
the chunked transfer engine, manifests, resume, and integrity. Pure Rust, no UI/Tauri deps, fully
unit-testable over in-process loopback. This is where most of the work lives.

**`conduit-fs` — the virtual volume (Phase 4).** Presents the peer's shared area as a mounted drive.
FUSE via `fuser` (Linux/macOS + macFUSE), WinFsp (or Dokan) on Windows. Filesystem operations proxy
to `conduit-core` over the live session.

**`src-tauri` + `ui` — the app.** Tauri commands wrap core operations (`start_discovery`,
`pair(peer_id, code)`, `send(paths)`, `mount(peer_id)`, …); Tauri events stream progress and peer
changes to a React UI.

---

## 3. Data flow: sending a file

1. **Link up.** Cable connected → OS creates the IP interface → `conduit-net` reports the preferred
   address.
2. **Discover.** Both apps advertise + browse mDNS; each shows the other in its peer list.
3. **Pair (first time only).** Initiator opens a QUIC/TLS connection; both display a short numeric
   code derived from the session; user confirms on both ends; each side pins the other's certificate
   as a trusted device. Subsequent connects are silent.
4. **Offer.** Sender builds a **manifest** (file tree, sizes, per-chunk BLAKE3 hashes) and sends an
   `Offer` on the control stream. Receiver picks a destination and `Accept`s (or the file lands in the
   receiver's inbox automatically, per settings).
5. **Transfer.** Sender opens **N parallel QUIC streams** and pushes chunks. Receiver writes them to
   disk (streaming, not buffered in RAM), verifying each chunk's hash. Progress events flow to both
   UIs.
6. **Finalize.** Whole-file hash verified; temp file atomically renamed into place. On disconnect
   mid-transfer, the manifest + received-chunk bitmap allow **resume**: on reconnect the receiver
   reports which chunks it has and only the missing ones are re-sent.

The virtual-mount path (Phase 4) is the same engine driven by filesystem callbacks instead of an
explicit "send": a write into the mounted folder becomes an `Offer`+transfer; a read streams chunks on
demand.

---

## 4. Performance model — design around the real bottleneck

Target link is 10–40 Gbps, but the limiting factor is often elsewhere. Approx. sequential ceilings:

| Component | Approx. throughput |
|---|---|
| Thunderbolt 3/4 / USB4 link | 10–40 Gbps |
| NVMe SSD (PCIe 3/4) | ~25–56 Gbps |
| SATA SSD | ~4.4 Gbps |
| BLAKE3 hashing (multicore) | tens of Gbps |
| SHA-256 hashing | often < link speed ← avoid |

Design implications, all mandatory in `conduit-core`:

- **Parallel streams.** A single TCP/QUIC stream rarely saturates a 40 Gbps link; use several
  concurrent streams and reassemble by offset.
- **Large buffers + backpressure.** Size QUIC flow-control windows and I/O buffers for high
  bandwidth-delay; never let one slow consumer stall everything.
- **Stream to disk.** Never hold a whole file in memory. Use sequential writes; on Linux prefer
  `io_uring`/`sendfile`/`splice` for zero-copy where feasible.
- **Fast hashing only.** BLAKE3 (or xxHash3) per chunk. SHA family is a throughput killer here.
- **Chunk size** tunable (e.g. 1–8 MiB); larger chunks amortize overhead, smaller chunks improve
  resume granularity. Make it a config constant with a sane default.

Add a `conduit-cli` benchmark path so throughput can be measured on real hardware from Phase 2 on.

---

## 5. The "USB drive" UX, delivered without USB

Two increasingly magical tiers; ship them in order.

**Tier A — Drop folder + browse (Phase 3).** Each peer exposes a shared folder and an inbox. In the
app you can browse the peer's shared folder and drag files in/out; drops trigger transfers. No kernel
extensions, works everywhere immediately. This already satisfies "a place on the other machine I can
drop files into."

**Tier B — Virtual mounted volume (Phase 4).** `conduit-fs` mounts the peer's shared area as a real
drive in Finder/Explorer/Files. Reads stream chunks lazily; writes stream out. This is the literal
"a drive appeared" experience — implemented as a virtual filesystem, not a USB gadget. Requires
macFUSE (macOS) or WinFsp (Windows) — a one-time driver the installer must help set up, so gate it
behind Tier A and treat the driver bootstrap as real product work.

---

## 6. Platform matrix

| Concern | Linux | macOS | Windows |
|---|---|---|---|
| TB IP link | `thunderbolt-net`, `boltctl authorize` | Thunderbolt Bridge (auto) | USB4/TB networking, Win11 |
| Iface detect | `/sys/bus/thunderbolt`, netdev name | system config APIs | IP Helper / WMI |
| Virtual FS | `fuser` (kernel FUSE) | `fuser` + **macFUSE** (system ext approval) | **WinFsp** or **Dokan** |
| Packaging | `.deb` / AppImage | `.dmg` (notarize) | `.msi` (sign) |

Known friction to document for users: Thunderbolt **security levels** — on Linux/Windows the first
connection of a new device may require explicit authorization before the netdev appears; macFUSE and
WinFsp require a one-time driver install / system-extension approval.

---

## 7. Security model

Threat model is modest (physical cable), but never plaintext:

- **Transport:** all traffic is QUIC/TLS 1.3. No unencrypted mode.
- **Pairing:** trust-on-first-use with a short confirmation code shown on both ends; certificates are
  pinned per trusted device thereafter. Optional upgrade: a PAKE (SPAKE2) so the code also
  authenticates the channel. Details in `PROTOCOL.md`.
- **Authorization:** transfers into a peer require an accepted pairing; inbound files land in a
  sandboxed inbox unless the user grants a broader shared folder.
- **No ambient exposure:** discovery/advertisement is scoped to the direct link where possible, not
  broadcast across every network the machine is on.

---

## 8. Open decisions (resolve during build, record here)

Resolved:

- **Wire encoding (Phase 1): `postcard`**, length-prefixed with a u32 LE, chunk payloads as raw
  bytes after their header frame. Chosen over CBOR because both peers are always this Rust
  codebase, so a compact schema-implied format wins and cross-language readability buys nothing.
  Details in `PROTOCOL.md` and `conduit-core::wire`.
- **Crypto backend (Phase 1): rustls with `ring`**, not aws-lc-rs — builds on Windows without a
  cmake/NASM toolchain. Pairing codes come from the TLS exporter; fingerprints are BLAKE3-256 of
  the DER cert (the project hash everywhere).
- **Defaults stay at 4 MiB chunks, 4 parallel streams** (`DEFAULT_CHUNK_SIZE`,
  `DEFAULT_STREAM_COUNT`). The Phase 2 loopback matrix (`conduit bench`, 1 GiB sparse payload,
  release build, single Windows machine running both peers) measured 1.0–1.3 Gbit/s across
  streams ∈ {1,2,4,8} × chunk ∈ {1,4,8} MiB with 2×8 MiB nominally best — differences within
  ~25%, i.e. loopback is CPU-bound (TLS + BLAKE3 both directions on one box) and cannot rank
  configurations for a real cable. Re-run `conduit bench` (against
  `conduit receive --forever --trust`) on two TB-linked machines before changing defaults.
  QUIC flow-control windows are sized for high BDP in `conduit-core::transport`:
  16 MiB/stream receive window (a stream must hold ≥1 whole chunk in flight), 256 MiB
  connection receive/send windows.

- **Pluggable transports (`docs/Transports.md`) — implemented.** `conduit-net` exposes a
  `Transport` trait + `TransportManager` (Thunderbolt/USB4, Ethernet, WiFi, USB bridge cables),
  ranking links `(direct, speed_tier, base_priority)` descending. Direct = no default gateway +
  link-local-only addressing. One deliberate deviation from that doc: the QUIC endpoint keeps
  binding the **wildcard** address instead of `Link.bind_addr` — a specific-address bind would die
  with its link, whereas wildcard + the app's redial loop + scan-based resume give the "active link
  disappears → fall back and resume" behavior for free. The active link therefore drives ranking,
  discovery preference, and the UI's Connection panel (with manual override), not the socket bind;
  revisit if interface-scoped binding is ever needed for isolation.

- **Per-entry skip (`SkipEntry`) is an appended enum variant, no `PROTOCOL_VERSION` bump.** A
  sender that cannot read one entry mid-transfer drops that entry instead of failing the whole
  payload (PROTOCOL.md §3.2). The variant sits at the end of `ControlMessage`, so every earlier
  variant keeps its postcard index and normal transfers stay wire-compatible with older builds;
  only a transfer that actually skips against an old peer fails to decode — which fails that
  transfer, exactly what the old behavior did anyway. Bump `PROTOCOL_VERSION` for the next change
  that alters existing frames rather than appending.

- **Mount write semantics: buffered-then-flush** (both backends). A file created in the mount
  spools to a local temp file and is handed to the transfer engine when its last handle closes
  (WinFsp `cleanup`, FUSE `release`) — the chunked pipeline keeps its per-chunk verification and
  resume, which a true streaming write would have to reinvent. The costs are accepted: a spool
  copy on local disk, no in-place overwrite of a remote file (`EPERM`), and writes into a
  subdirectory of the mount landing in the peer's inbox root.
- **Linux FUSE backend uses `fuser` with `default-features = false`** — no libfuse at build time
  (mounting shells out to `fusermount3`), so `conduit-fs` builds on any Linux and only needs
  `/dev/fuse` at runtime.

Still open:

- QUIC (`quinn`) vs parallel TLS-over-TCP: default to QUIC; if profiling shows userspace QUIC is
  CPU-bound near link ceiling, add a TCP+`sendfile` fast path behind the same transport trait.
