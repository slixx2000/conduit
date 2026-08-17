# Conduit — Setup Guide

Conduit moves files between two laptops over the fastest link they share — a
Thunderbolt/USB4 cable, a plain Ethernet cable, a USB bridge cable, or ordinary
WiFi — always encrypted, always verified. This guide is for using the app; the
technical docs live next to it in `docs/`.

## 1. Install

Download the installer for your OS from the project's GitHub Releases page:

- **Windows**: the `.msi` (or the NSIS `-setup.exe`). To use *Mount as drive* you also
  need the free [WinFsp](https://winfsp.dev/rel/) driver (one-time install; Conduit
  tells you if it's missing). Everything else works without it.
- **Linux**: the `.deb` (`sudo dpkg -i conduit_*.deb`) or the AppImage
  (`chmod +x` and run it). To use *Mount as drive* you also need FUSE
  (`sudo apt install fuse3`, or your distribution's equivalent).
- **macOS**: the `.dmg` (universal — Intel and Apple Silicon). *Mount as drive* is not
  available on macOS yet.

> **First launch — one-time "unrecognized app" prompt.** The current builds are
> **unsigned**, so your OS asks for confirmation the first time. This is expected;
> after you allow it once, it never asks again.
>
> - **Windows** — SmartScreen shows *"Windows protected your PC."* Click **More info →
>   Run anyway**.
> - **macOS** — Gatekeeper says it *"cannot check it for malicious software."*
>   **Right-click (or Control-click) the app → Open**, then confirm. (Double-clicking
>   won't give you the Open button; the right-click menu does.)
> - **Linux** — no prompt; nothing to do.
>
> Signed builds will remove these prompts in a future release.

The first launch creates your device identity and starts listening. There is no
account and no server: everything is directly between your two machines.

## 2. Connect the machines

Any of these works — Conduit picks the fastest automatically and shows it in the
**Connection** panel (you can pin a different one):

- **Thunderbolt / USB4 cable** (fastest). On Windows and Linux the first plug-in may
  need you to *authorize* the device: watch for the OS prompt, or on Linux run
  `boltctl list` / `boltctl authorize <uuid>`. Conduit shows a banner while a device
  is waiting for approval.
- **Ethernet cable straight between the two laptops** — no router, no settings.
  Modern network ports handle this automatically (link-local addressing; no
  crossover cable needed). Linux: if the wired connection sticks at
  "Connecting…", see Troubleshooting.
- **USB laptop-to-laptop bridge cable** (CDC-NCM type).
- **Same WiFi network** — the always-works fallback, just slower.

## 3. Pair (first time only)

Open Conduit on both machines. Each sees the other in **Peers** within a few
seconds. Start a transfer (or mount) and both screens show the same **6-digit
code** — confirm it matches on both, once. After that the devices trust each other
and connect silently.

If the code ever *doesn't* match, reject it: something is interfering with the
connection. Manage pairings under **Trusted devices** (rename, revoke).

## 4. Transfer

- **Drag files or a folder onto a peer card** (or use *Send file / Send folder*).
- Progress shows on both machines; every chunk is integrity-checked (BLAKE3) and
  the file is verified whole before it appears — never a silent corruption.
- Incoming files land in your **inbox** (default `Downloads/Conduit`; change it in
  Settings). The inbox is also what peers see when they mount you.
- **Interruptions are safe.** Pull the cable mid-transfer and reconnect: the
  transfer resumes where it stopped. Cancel keeps the partial for the same reason —
  *Resume* from History re-offers it.

## 5. Mount a peer as a drive

Click **Mount as drive** on a peer (Windows, needs WinFsp; Linux, needs fuse3). The
peer's inbox appears as a drive letter in Explorer — or as a folder in your file
manager on Linux: browse it, open files (they stream on demand), copy files off it,
or copy files onto it — those travel through the same verified transfer pipeline.
*Unmount* (or quitting the app) removes the drive.

Current mount limits: copying *over* an existing file on the drive is refused (copy
under a new name instead), deleting folders through the drive is not supported yet,
and a file copied into a *subfolder* of the drive arrives in the peer's inbox root.

## 6. Troubleshooting

| Symptom | Fix |
|---|---|
| Peer doesn't appear | Both apps running? Same network or cable connected? Some networks block mDNS — use "Connect by address" with the ip:port from the other machine's header. |
| Direct Ethernet cable: Linux stuck at "Connecting…" | NetworkManager is waiting for DHCP that a direct cable doesn't have. Switch the wired profile to link-local once: `nmcli con mod "<connection name>" ipv4.method link-local ipv6.method link-local && nmcli con up "<connection name>"` (find the name with `nmcli con show`). Windows/macOS self-assign automatically after ~30 s. |
| "waiting for authorization" banner | Approve the Thunderbolt device in your OS (Linux: `boltctl authorize`, or the desktop prompt). |
| Mount button fails with "WinFsp is required" | Install WinFsp from winfsp.dev and retry. |
| Mount button fails with "FUSE is required" (Linux) | `sudo apt install fuse3` (or your distribution's equivalent) and retry. |
| Pairing code shown again for a known device | Its identity changed (reinstall) — or someone is impersonating it. Verify with the other person, revoke the old entry under Trusted devices, and re-pair. |
| Transfer failed mid-way | Just send again — it resumes from what already arrived intact. |
| Slow over WiFi | That's WiFi. Plug in any cable; the Connection panel shows what's in use. |

## 7. Headless / scripting

The `conduit` CLI drives everything without the GUI: `receive`, `send`, `mount`,
`peers`, `trusted`, `bench`, `hash`. See `README.md` for examples.
