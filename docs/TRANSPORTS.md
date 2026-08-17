# TRANSPORTS.md — Pluggable link layer for Conduit

**Status: implemented** (`conduit-net/src/transport/`), with the deviations recorded in
`ARCHITECTURE.md` §8: the endpoint stays bound to the wildcard address (so a mid-session link change
falls back without a rebind — the send retry + scan-based resume absorb the interruption) and the
active link drives ranking/UI rather than the literal socket bind; mDNS remains IPv4-scoped until
the transport goes dual-stack; macOS wired/wireless classification is name-heuristic until
SystemConfiguration probing lands. A CDC/RNDIS device *with a gateway* (e.g. a phone tethered for
internet) is classified as a shared-network "USB network device", not a bridge cable — only
gateway-less link-local CDC links count as direct. Hardware-dependent acceptance items (two-laptop
direct Ethernet, real bridge cable, Thunderbolt cable) remain pending test hardware; everything is
exercised over LAN/loopback plus unit fixtures.

This introduces a transport
abstraction so Conduit runs on **any** link between two laptops, not only Thunderbolt/USB4. It is
**non-breaking**: the existing QUIC/TLS session, protocol, and transfer engine are unchanged — this
only generalizes *how the preferred IP link is chosen*. Read after `ARCHITECTURE.md` and `PROTOCOL.md`.

---

## 1. Why this exists

`conduit-core` was always transport-agnostic: it needs "an IP link and a preferred local address to
bind to." Thunderbolt was just the fastest source of one. But:

- Not every laptop has Thunderbolt (e.g. pre-11th-gen Intel machines may have TB3, or nothing).
- **Direct Ethernet** between two laptops is cheap, needs no special hardware, and is many times
  faster than WiFi — and it's the *exact same IP path* the core already uses.
- A **bridge cable** can link two USB3-only laptops when it enumerates as a USB network device.

So instead of "detect the Thunderbolt interface," Conduit should "**enumerate every usable link, rank
them, pick the fastest, and let the user override.**" Thunderbolt becomes a speed bonus, not a
requirement. Conduit then works on any two laptops.

Key principle unchanged: **the data path is always QUIC over IP.** A transport's job is only to
*produce a usable IP interface + bind address* and describe it. As long as a link yields an IP
interface, the entire rest of the app already works over it.

---

## 2. The `Transport` trait

Lives in `conduit-net`. Each transport detects zero or more concrete `Link`s currently available on
this machine.

```rust
// conduit-net/src/transport/mod.rs

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TransportKind { Thunderbolt, Ethernet, Wifi, Bridge }

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum SpeedTier { SubGig, Gbps1, Gbps5, Gbps10, Gbps20, Gbps40Plus }

/// One concrete, currently-usable link on this machine.
#[derive(Clone, Debug)]
pub struct Link {
    pub transport: TransportKind,
    pub iface_name: String,     // e.g. "thunderbolt0", "enp0s31f6", "wlan0"
    pub bind_addr: IpAddr,      // preferred local addr (link-local is fine)
    pub speed_tier: SpeedTier,
    pub direct: bool,           // point-to-point cable (prefer for discovery)
    pub needs_authorization: bool, // e.g. Thunderbolt device present but not approved
    pub requires_special_hw: bool, // e.g. bridge cable
}

#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    fn kind(&self) -> TransportKind;
    fn display_name(&self) -> &'static str;   // for the UI
    fn base_priority(&self) -> u8;            // tie-breaker; higher = preferred
    async fn detect(&self) -> anyhow::Result<Vec<Link>>;
}
```

A `TransportManager` owns all registered transports, aggregates their `Link`s, ranks them, and exposes
the active choice:

```rust
pub struct TransportManager { transports: Vec<Box<dyn Transport>> }

impl TransportManager {
    pub fn with_defaults() -> Self { /* register Thunderbolt, Ethernet, Wifi, Bridge */ }

    /// Detect across all transports and return links sorted best-first.
    pub async fn available(&self) -> Vec<Link>;

    /// The link the app will use unless the user overrides it.
    pub async fn preferred(&self) -> Option<Link>;
}
```

**Ranking (best first):** sort by `(direct, speed_tier, base_priority)` descending — a direct cable
beats a shared LAN at equal speed; faster beats slower; `base_priority` breaks ties. The UI may pin a
manual override.

Default `base_priority`: Thunderbolt > Bridge > Ethernet > Wifi.

---

## 3. Transport implementations

### 3.1 `ThunderboltTransport` (existing — refactor into the trait)

Move the Phase-2 detection here unchanged: walk `/sys/bus/thunderbolt/devices` (Linux) / OS APIs,
match the resulting netdev, read link-local addr. Set `direct = true`, `speed_tier` = `Gbps10` or
higher, `needs_authorization` when the device is present but unapproved. TB3, TB4 and USB4 all map to
this transport — they share the same host-to-host mode; only `speed_tier` differs.

### 3.2 `EthernetTransport` (new — highest value to add now)

Enumerate up, non-loopback **wired** interfaces (Linux: `/sys/class/net/*` where `type`/driver is
Ethernet and `carrier == 1`; exclude the Thunderbolt netdev, which the TB transport already owns).

**Exclude virtual netdevs** (Linux: no `/sys/class/net/<if>/device` entry — veth, bridge, bond,
dummy). Found the hard way during the first real direct-Ethernet run: Docker's `veth*` pairs report
ethernet `type == 1`, carrier-up, an `fe80::` address, and no gateway — a perfect match for the
direct-cable rule below — so two container veths outranked the actual cable as the preferred link
(fake `~10 Gbps` "direct cable" entries in `doctor`). Physical NICs always have a `device` entry in
sysfs; virtual ones never do, so that one check filters all of them
(`sysfs_is_physical_netdev`, fixture-tested in `conduit-net`).

Classify **direct vs LAN**:
- A wired interface that is carrier-up but has **no default gateway / no DHCP lease**, using only a
  **link-local** address, is treated as a **direct** laptop-to-laptop cable → `direct = true`.
- A wired interface with a normal routable address is a LAN link → `direct = false`.

`speed_tier`: read link speed where available (`/sys/class/net/<if>/speed`), default `Gbps1`.

**Zero-config addressing (important):** direct Ethernet usually has no DHCP server. Do **not** ask
users to set static IPs. Rely on automatic link-local addressing:
- **IPv6 link-local** (`fe80::…`) is always present on an up interface — prefer it. mDNS + QUIC work
  over IPv6 link-local (carry the scope id / `%iface`).
- IPv4 link-local (`169.254.x.x`, RFC 3927) is the fallback if IPv6 is disabled.

This is what makes "plug an Ethernet cable between two laptops and they just find each other" work with
no setup. Modern NICs auto-negotiate, so **no crossover cable is needed**.

### 3.3 `WifiTransport` (new — universal fallback)

Any up wireless interface with a usable address. `direct = false`, `speed_tier` ≈ `SubGig`/`Gbps1`,
lowest priority. This is the always-available floor so the app is never unusable.

### 3.4 `BridgeCableTransport` (new — for USB3-only pairs)

Supports laptop-to-laptop **USB bridge cables** *that enumerate as a USB network device*
(CDC-NCM / CDC-ECM). When such a cable is plugged in, the OS exposes a USB network interface with a
link-local address — from Conduit's view this is **identical to direct Ethernet** and needs no special
data path. Detection: match interface driver/name patterns for USB CDC network gadgets; set
`transport = Bridge`, `direct = true`, `requires_special_hw = true`, `speed_tier = Gbps5`.

> **Out of scope for v1:** older/proprietary bridge chips that expose a *raw pipe* instead of a network
> device (needing a vendor driver). Those would require a separate `PipeTransport` that frames a byte
> stream instead of using QUIC-over-UDP. Note it as future work; prefer/recommend CDC-NCM bridge
> cables so the existing IP path is reused.

---

## 4. Integration points (what actually changes)

This slots into the Phase-3 work with minimal, additive edits:

1. **`conduit-net`:** replace the single "preferred Thunderbolt interface" lookup with
   `TransportManager::preferred()` / `available()`. The TB logic becomes one `Transport` impl among
   several.
2. **`conduit-discovery`:** advertise/browse `_conduit._tcp` on the **selected link(s)**, preferring
   `direct` links. Nothing else changes — mDNS already works over link-local (remember IPv6 scope ids).
3. **`conduit-core`:** still receives a bind address; now it comes from the chosen `Link.bind_addr`.
   No protocol or transfer-engine changes.
4. **`src-tauri` + `ui`:** add a small **"Connection"** surface — show the active transport and its
   speed tier (e.g. "Thunderbolt · ~10 Gbps", "Direct Ethernet · 1 Gbps", "Wi-Fi · shared network"),
   list alternatives from `available()`, and allow a manual override. Surface `needs_authorization`
   and `requires_special_hw` as hints.

Suggested file layout:

```
crates/conduit-net/src/
├── lib.rs
└── transport/
    ├── mod.rs          # Transport trait, Link, TransportKind, SpeedTier, TransportManager
    ├── thunderbolt.rs  # refactored from Phase 2
    ├── ethernet.rs     # new (direct + LAN, link-local addressing)
    ├── wifi.rs         # new
    └── bridge.rs       # new (CDC-NCM/ECM USB bridge cables)
```

---

## 5. Behavior rules

- **Auto-select fastest, allow override.** On launch and whenever links change (cable in/out, WiFi
  join), re-run detection and re-rank. If the active link disappears mid-session, fall back to the next
  best and let `conduit-core`'s resume handle any interrupted transfer.
- **Prefer `direct` links for discovery** so a connected cable peer ranks above the whole WiFi LAN.
- **Never require manual IP/DHCP config.** Link-local + mDNS only.
- **One transport owns each interface.** The Thunderbolt netdev is claimed by `ThunderboltTransport`;
  `EthernetTransport` must exclude it to avoid double-listing.
- **The data path is transport-independent.** No transport-specific code below `conduit-net`.

---

## 6. Acceptance criteria (add to Phase 3)

- App enumerates all transports and shows the **active link + speed tier** in the UI, auto-selecting
  the fastest, with a working manual override.
- **Direct Ethernet:** two laptops joined by a plain Ethernet cable (no DHCP, no static config)
  discover each other and transfer both directions over link-local addressing.
- **WiFi fallback:** with no cable, the same two laptops on one network still discover and transfer.
- **Thunderbolt unchanged:** the TB path still works and now reports through the transport UI; no
  regression.
- **Bridge cable (if hardware available):** a CDC-NCM USB bridge cable is detected and used via the
  Ethernet/IP path with no special-casing in `conduit-core`.
- Unplugging the active link mid-transfer falls back to the next best link and the transfer resumes.

---

## 7. Prompt for Claude Code

> "Read docs/TRANSPORTS.md. Refactor `conduit-net` to the `Transport` trait + `TransportManager`,
> moving the existing Thunderbolt detection into `thunderbolt.rs`. Add `ethernet.rs` (direct + LAN via
> IPv6/IPv4 link-local, excluding the TB netdev), `wifi.rs`, and `bridge.rs` (CDC-NCM). Wire
> `TransportManager::preferred()` into discovery (advertise on direct links first) and into the
> `conduit-core` bind address. Add a Connection panel to the UI showing the active transport and
> alternatives with manual override. Keep `conduit-core` unchanged. Verify with the Phase-3 transport
> acceptance criteria — including a direct-Ethernet, no-DHCP discovery+transfer test."
