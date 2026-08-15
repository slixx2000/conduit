import { useCallback, useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { open } from "@tauri-apps/plugin-dialog";

/** Mirrors `NodeStatus` in `src-tauri/src/lib.rs`. */
type NodeStatus = {
  device_name: string;
  listen_addr: string;
  inbox: string;
  fingerprint: string;
};

/** Mirrors `PeerRow` in `src-tauri/src/lib.rs`. */
type PeerRow = {
  id: string;
  name: string;
  addr: string;
  trusted: boolean;
  compatible: boolean;
  mounted: string | null;
};

/** Mirrors `LinkRow` / `LinkStatus` in `src-tauri/src/lib.rs`. */
type LinkRow = {
  label: string;
  iface: string;
  addr: string;
  direct: boolean;
  needs_authorization: boolean;
  requires_special_hw: boolean;
  active: boolean;
};
type LinkStatus = { links: LinkRow[]; overridden: boolean };

/** Mirrors `TransferEvent` in `conduit-core` (serde tag = "kind"). */
type TransferEvent =
  | { kind: "offered"; transfer_id: string; name: string; total_bytes: number }
  | { kind: "started"; transfer_id: string; name: string; total_bytes: number }
  | { kind: "resumed"; transfer_id: string; bytes_already: number }
  | {
      kind: "progress";
      transfer_id: string;
      bytes_done: number;
      total_bytes: number;
    }
  | {
      kind: "chunk_resent";
      transfer_id: string;
      entry_index: number;
      chunk_index: number;
    }
  | { kind: "verifying"; transfer_id: string }
  | { kind: "completed"; transfer_id: string; path: string | null }
  | { kind: "failed"; transfer_id: string; reason: string };

type TransferNotification = { direction: "incoming" | "outgoing"; event: TransferEvent };
type PairingPrompt = { code: string; peer_name: string; direction: string };

/** Mirrors `TrustedRow` in `src-tauri/src/lib.rs`. */
type TrustedRow = { fingerprint: string; short: string; name: string; device_id: string };

/** Mirrors `HistoryEntry` in `src-tauri/src/lib.rs`. */
type HistoryEntry = {
  time_unix: number;
  direction: string;
  name: string;
  bytes: number;
  peer: string;
  status: string;
  path: string | null;
  target: string | null;
};

/** Mirrors `Settings` in `src-tauri/src/lib.rs`. */
type Settings = {
  inbox_dir: string | null;
  chunk_mib: number;
  streams: number;
  notifications: boolean;
};

type Transfer = {
  id: string;
  direction: "incoming" | "outgoing";
  name: string;
  totalBytes: number;
  bytesDone: number;
  state: "running" | "verifying" | "done" | "failed";
  detail?: string;
  /** Smoothed bytes/second, derived here — the backend only reports byte counts. */
  rate: number;
  /** Recent rate readings, oldest first, for the sparkline. */
  samples: number[];
  /** Last point the rate was sampled at, so sub-sample events do not skew it. */
  sampleAt?: number;
  sampleBytes?: number;
};

/** Which footer panel is open, if any. */
type Sheet = "link" | "trusted" | "settings";

/** How long to wait between rate samples. Progress lands every ~150 ms; sampling
    every third one keeps the number readable instead of twitching. */
const SAMPLE_MS = 350;
/** Sparkline width, in samples (~17 s of history at SAMPLE_MS). */
const SAMPLE_WINDOW = 48;

function splitBytes(b: number): [string, string] {
  if (b < 1024) return [String(Math.round(b)), "B"];
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let v = b;
  let i = -1;
  do {
    v /= 1024;
    i++;
  } while (v >= 1024 && i < units.length - 1);
  return [v.toFixed(2), units[i]];
}

function humanBytes(b: number): string {
  const [v, u] = splitBytes(b);
  return `${v} ${u}`;
}

function humanEta(seconds: number): string {
  if (!isFinite(seconds) || seconds <= 0) return "";
  if (seconds < 60) return `${Math.ceil(seconds)} s left`;
  if (seconds < 3600) return `${Math.ceil(seconds / 60)} min left`;
  return `${(seconds / 3600).toFixed(1)} h left`;
}

export default function App() {
  const [status, setStatus] = useState<NodeStatus | null>(null);
  const [bridgeError, setBridgeError] = useState<string | null>(null);
  const [peers, setPeers] = useState<PeerRow[]>([]);
  const [manualAddr, setManualAddr] = useState("");
  const [lastError, setLastError] = useState<string | null>(null);
  const [pairing, setPairing] = useState<PairingPrompt | null>(null);
  const [link, setLink] = useState<LinkStatus | null>(null);
  const [trusted, setTrusted] = useState<TrustedRow[]>([]);
  const [historyList, setHistoryList] = useState<HistoryEntry[]>([]);
  const [settings, setSettings] = useState<Settings | null>(null);
  const [renaming, setRenaming] = useState<{ id: string; draft: string } | null>(null);
  const [transfers, setTransfers] = useState<Map<string, Transfer>>(new Map());
  const [sheet, setSheet] = useState<Sheet | null>(null);
  const [mountBusy, setMountBusy] = useState<string | null>(null);
  /** Live drag: how many files are held, and which peer card is under the cursor. */
  const [drag, setDrag] = useState<{ count: number; targetId: string | null } | null>(null);

  // The transfer list renders newest-first; keep insertion order for stability.
  const orderRef = useRef<string[]>([]);
  const peersRef = useRef<PeerRow[]>([]);
  peersRef.current = peers;
  const dragRef = useRef<{ count: number; targetId: string | null } | null>(null);
  dragRef.current = drag;

  const applyEvent = useCallback((n: TransferNotification) => {
    setTransfers((prev) => {
      const next = new Map(prev);
      const e = n.event;
      const existing = next.get(e.transfer_id);
      const base: Transfer = existing ?? {
        id: e.transfer_id,
        direction: n.direction,
        name: "…",
        totalBytes: 0,
        bytesDone: 0,
        state: "running",
        rate: 0,
        samples: [],
      };
      if (!existing) orderRef.current.unshift(e.transfer_id);

      switch (e.kind) {
        case "offered":
        case "started":
          next.set(e.transfer_id, {
            ...base,
            name: e.name,
            totalBytes: e.total_bytes,
            state: "running", // a redialed transfer goes back to running
          });
          break;
        case "resumed":
          // Bytes already staged are not throughput: restart the measurement from
          // here, or the first sample reports the whole partial as instantaneous.
          next.set(e.transfer_id, {
            ...base,
            bytesDone: e.bytes_already,
            rate: 0,
            samples: [],
            sampleAt: Date.now(),
            sampleBytes: e.bytes_already,
            detail: `resumed — ${humanBytes(e.bytes_already)} already transferred`,
          });
          break;
        case "progress": {
          const now = Date.now();
          const sampleAt = base.sampleAt ?? now;
          const sampleBytes = base.sampleBytes ?? e.bytes_done;
          const dt = (now - sampleAt) / 1000;
          let { rate, samples } = base;
          let nextAt = sampleAt;
          let nextBytes = sampleBytes;
          if (dt * 1000 >= SAMPLE_MS) {
            const instant = Math.max(0, e.bytes_done - sampleBytes) / dt;
            // Exponential smoothing: chunk boundaries make the raw figure jump.
            rate = rate === 0 ? instant : rate * 0.65 + instant * 0.35;
            samples = [...samples, rate].slice(-SAMPLE_WINDOW);
            nextAt = now;
            nextBytes = e.bytes_done;
          }
          next.set(e.transfer_id, {
            ...base,
            bytesDone: e.bytes_done,
            totalBytes: e.total_bytes,
            rate,
            samples,
            sampleAt: nextAt,
            sampleBytes: nextBytes,
          });
          break;
        }
        case "chunk_resent":
          next.set(e.transfer_id, {
            ...base,
            detail: `chunk ${e.chunk_index} failed its hash — re-sent`,
          });
          break;
        case "verifying":
          next.set(e.transfer_id, { ...base, state: "verifying" });
          break;
        case "completed":
          next.set(e.transfer_id, {
            ...base,
            state: "done",
            bytesDone: base.totalBytes,
            detail: e.path ?? undefined,
          });
          break;
        case "failed":
          next.set(e.transfer_id, { ...base, state: "failed", detail: e.reason });
          break;
      }
      return next;
    });
  }, []);

  const sendPaths = useCallback((target: string, paths: string[]) => {
    setLastError(null);
    for (const path of paths) {
      invoke("send_to_peer", { target, path }).catch((e: unknown) =>
        setLastError(e instanceof Error ? e.message : String(e)),
      );
    }
  }, []);

  useEffect(() => {
    // Running under `vite` alone (no Tauri host) there is no IPC bridge. That is a
    // normal way to work on the UI, so report it as a state rather than an error.
    invoke<NodeStatus>("node_status")
      .then(setStatus)
      .catch((e: unknown) => setBridgeError(e instanceof Error ? e.message : String(e)));
    invoke<PeerRow[]>("peers_snapshot").then(setPeers).catch(() => {});
    const fetchTrusted = () =>
      invoke<TrustedRow[]>("trusted_peers").then(setTrusted).catch(() => {});
    fetchTrusted();
    invoke<HistoryEntry[]>("history").then(setHistoryList).catch(() => {});
    invoke<Settings>("get_settings").then(setSettings).catch(() => {});

    // Poll the link so plugging in the cable (or an authorization prompt appearing)
    // shows up without a restart.
    const pollLink = () => invoke<LinkStatus>("link_status").then(setLink).catch(() => {});
    pollLink();
    const linkTimer = setInterval(pollLink, 5000);

    // Event subscriptions and drag-and-drop only exist inside the Tauri host. Under
    // plain `vite` they throw, which would take the whole tree down — catch so the
    // UI still renders (with the bridge banner) while working on it in a browser.
    let unlistens: Promise<() => void>[] = [];
    let dragUnlisten: Promise<() => void> | null = null;

    // The card under the drop point decides where files go. `enter` carries the
    // paths, so the card can say exactly what will be sent; `over` carries only a
    // position, which we hit-test to highlight one card rather than all of them.
    const cardUnder = (x: number, y: number): string | null => {
      const scale = window.devicePixelRatio || 1;
      const el = document.elementFromPoint(x / scale, y / scale);
      return el?.closest<HTMLElement>("[data-peer-id]")?.dataset.peerId ?? null;
    };
    const soleTarget = (): string | null => {
      const usable = peersRef.current.filter((p) => p.compatible);
      return usable.length === 1 ? usable[0].id : null;
    };

    try {
      unlistens = [
        listen<TransferNotification>("conduit://transfer", (ev) => applyEvent(ev.payload)),
        listen<PairingPrompt>("conduit://pairing", (ev) => setPairing(ev.payload)),
        listen<PeerRow[]>("conduit://peers", (ev) => {
          setPeers(ev.payload);
          fetchTrusted(); // pairing/renaming/revoking all surface through this event
        }),
        listen<HistoryEntry[]>("conduit://history", (ev) => setHistoryList(ev.payload)),
        listen<{ message: string }>("conduit://error", (ev) => setLastError(ev.payload.message)),
      ];

      dragUnlisten = getCurrentWebview().onDragDropEvent((event) => {
        const p = event.payload;
        if (p.type === "enter") {
          setDrag({ count: p.paths.length, targetId: cardUnder(p.position.x, p.position.y) });
          return;
        }
        if (p.type === "over") {
          const targetId = cardUnder(p.position.x, p.position.y);
          if (dragRef.current && dragRef.current.targetId !== targetId) {
            setDrag({ count: dragRef.current.count, targetId });
          }
          return;
        }
        if (p.type === "leave") {
          setDrag(null);
          return;
        }
        // drop
        setDrag(null);
        if (p.paths.length === 0) return;
        const targetId = cardUnder(p.position.x, p.position.y) ?? soleTarget();
        if (targetId) {
          sendPaths(targetId, p.paths);
        } else {
          setLastError("Drop the files onto a device to choose where they go.");
        }
      });
    } catch (e) {
      // No Tauri host: `node_status` above already set the bridge banner.
      console.warn("Tauri event bridge unavailable", e);
    }

    return () => {
      clearInterval(linkTimer);
      for (const u of unlistens) u.then((f) => f()).catch(() => {});
      dragUnlisten?.then((f) => f()).catch(() => {});
    };
  }, [applyEvent, sendPaths]);

  async function chooseAndSend(target: string) {
    const file = await open({ multiple: true, directory: false });
    if (Array.isArray(file)) sendPaths(target, file);
    else if (typeof file === "string") sendPaths(target, [file]);
  }

  async function chooseFolderAndSend(target: string) {
    const dir = await open({ multiple: false, directory: true });
    if (typeof dir === "string") sendPaths(target, [dir]);
  }

  async function answerPairing(accept: boolean) {
    setPairing(null);
    await invoke("confirm_pairing", { accept });
  }

  function cancelTransfer(id: string) {
    invoke("cancel_transfer", { transferId: id }).catch(() => {});
  }

  async function toggleMount(p: PeerRow) {
    setMountBusy(p.id);
    setLastError(null);
    try {
      if (p.mounted) {
        await invoke("unmount_peer", { peerId: p.id });
      } else {
        await invoke("mount_peer", { peerId: p.id });
      }
    } catch (e) {
      setLastError(e instanceof Error ? e.message : String(e));
    } finally {
      setMountBusy(null);
    }
  }

  function setOverride(iface: string | null) {
    // Move the selection now and reconcile with the backend's answer after: the
    // round trip is set_link_override + a fresh probe, which is long enough for a
    // click to feel like it did nothing.
    setLink((prev) =>
      prev
        ? {
            ...prev,
            overridden: iface !== null,
            links: prev.links.map((l) => ({
              ...l,
              active: iface === null ? l.active : l.iface === iface,
            })),
          }
        : prev,
    );
    invoke("set_link_override", { iface })
      .then(() => invoke<LinkStatus>("link_status").then(setLink).catch(() => {}))
      .catch(() => {});
  }

  async function saveSettings(patch: Partial<Settings>) {
    if (!settings) return;
    const next = { ...settings, ...patch };
    setSettings(next);
    try {
      await invoke("set_settings", { settings: next });
      invoke<NodeStatus>("node_status").then(setStatus).catch(() => {});
    } catch (e) {
      setLastError(e instanceof Error ? e.message : String(e));
    }
  }

  async function pickInbox() {
    const dir = await open({ directory: true, multiple: false });
    if (typeof dir === "string") await saveSettings({ inbox_dir: dir });
  }

  async function commitRename() {
    if (!renaming) return;
    const { id: fingerprint, draft } = renaming;
    setRenaming(null);
    if (draft.trim() === "") return;
    try {
      await invoke("rename_trusted", { fingerprint, name: draft.trim() });
      setTrusted(await invoke<TrustedRow[]>("trusted_peers"));
    } catch (e) {
      setLastError(e instanceof Error ? e.message : String(e));
    }
  }

  async function revoke(fingerprint: string) {
    try {
      await invoke("revoke_trusted", { fingerprint });
      setTrusted(await invoke<TrustedRow[]>("trusted_peers"));
    } catch (e) {
      setLastError(e instanceof Error ? e.message : String(e));
    }
  }

  function sendAgain(h: HistoryEntry) {
    if (h.target && h.path) sendPaths(h.target, [h.path]);
  }

  const transferList = orderRef.current
    .map((id) => transfers.get(id))
    .filter((t): t is Transfer => t !== undefined);
  const running = transferList.filter((t) => t.state === "running" || t.state === "verifying");
  const activeLink = link?.links.find((l) => l.active) ?? null;
  const unauthorized = link?.links.filter((l) => l.needs_authorization) ?? [];

  return (
    <main className="flex h-full flex-col bg-conduit-bg text-slate-200">
      {/* Status bar: who this machine is, and what link it would use. */}
      <header className="flex shrink-0 flex-wrap items-center justify-between gap-3 border-b border-white/10 px-5 py-3">
        <div className="flex min-w-0 items-baseline gap-3">
          <span className="text-[15px] font-semibold tracking-tight text-white">Conduit</span>
          <span className="truncate text-sm text-slate-400">
            {status ? status.device_name : "starting…"}
          </span>
          {status && (
            <span className="font-mono text-[11px] text-slate-500">fp {status.fingerprint}</span>
          )}
        </div>
        <button
          onClick={() => setSheet("link")}
          className={`flex items-center gap-2 rounded-full border px-3 py-1 text-xs ${
            activeLink?.direct
              ? "border-conduit-accent/40 bg-conduit-accent/10 text-slate-100"
              : "border-white/15 text-slate-300"
          }`}
        >
          {activeLink?.direct && <span className="text-conduit-accent">⚡</span>}
          <span>{activeLink ? activeLink.label : "no link yet"}</span>
          {link?.overridden && <span className="text-slate-500">· pinned</span>}
        </button>
      </header>

      {(unauthorized.length > 0 || bridgeError || lastError) && (
        <div className="flex shrink-0 flex-col gap-2 px-5 pt-3">
          {unauthorized.length > 0 && (
            <p className="rounded-lg bg-amber-950/60 px-4 py-2.5 text-sm text-amber-300 ring-1 ring-amber-500/30">
              Thunderbolt device{unauthorized.length > 1 ? "s" : ""}{" "}
              <span className="font-medium">{unauthorized.map((l) => l.iface).join(", ")}</span>{" "}
              {unauthorized.length > 1 ? "are" : "is"} waiting for authorization. Approve it in your
              OS (Linux: <code className="rounded bg-black/30 px-1">boltctl authorize</code>) to
              unlock the fast link — transfers use the next best link until then.
            </p>
          )}
          {bridgeError && (
            <p className="rounded-lg bg-conduit-panel px-4 py-2.5 text-sm text-amber-300 ring-1 ring-white/10">
              No Tauri backend attached — run{" "}
              <code className="rounded bg-black/30 px-1">npm run tauri dev</code> instead of{" "}
              <code className="rounded bg-black/30 px-1">npm run dev</code>.
            </p>
          )}
          {lastError && (
            <p className="flex items-start justify-between gap-3 rounded-lg bg-red-950/60 px-4 py-2.5 text-sm text-red-300 ring-1 ring-red-500/30">
              <span>{lastError}</span>
              <button onClick={() => setLastError(null)} className="shrink-0 text-red-400/70">
                Dismiss
              </button>
            </p>
          )}
        </div>
      )}

      {/* Two panes: what you send to, and what is in flight. Neither pushes the
          other out of view, which is what the old single scrolling column did. */}
      <div className="grid min-h-0 flex-1 md:grid-cols-[minmax(300px,36%)_1fr]">
        <section className="flex min-h-0 flex-col gap-3 overflow-y-auto p-5">
          <div className="flex items-baseline justify-between gap-3">
            <h2 className="text-[11px] font-semibold uppercase tracking-[0.14em] text-slate-500">
              Devices
            </h2>
            <span className="font-mono text-[11px] text-slate-500">
              {peers.length === 0 ? "scanning…" : `${peers.length} found`}
            </span>
          </div>

          {peers.length === 0 && (
            <div className="rounded-xl border border-dashed border-white/10 px-5 py-7 text-center text-sm text-slate-500">
              <p className="font-medium text-slate-400">Looking for devices</p>
              <p className="mt-1">
                Start Conduit on the other machine — same network, or joined by a cable — and it
                appears here on its own.
              </p>
            </div>
          )}

          {peers.map((p) => (
            <DeviceCard
              key={p.id}
              peer={p}
              drag={drag}
              mountBusy={mountBusy === p.id}
              onSendFiles={() => chooseAndSend(p.id)}
              onSendFolder={() => chooseFolderAndSend(p.id)}
              onToggleMount={() => toggleMount(p)}
            />
          ))}

          <details className="rounded-xl border border-dashed border-white/10 px-4 py-3">
            <summary className="cursor-pointer text-sm text-slate-500">
              Connect by address — when discovery is blocked
            </summary>
            <div className="mt-3 flex gap-2">
              <input
                value={manualAddr}
                onChange={(e) => setManualAddr(e.target.value)}
                placeholder="ip:port, e.g. 169.254.10.5:4433"
                spellCheck={false}
                className="min-w-0 flex-1 rounded-lg bg-black/30 px-3 py-2 font-mono text-sm text-slate-100 outline-none ring-1 ring-white/10 placeholder:text-slate-600 focus:ring-conduit-accent"
              />
              <button
                onClick={() => chooseAndSend(manualAddr)}
                disabled={manualAddr.trim() === ""}
                className="shrink-0 rounded-lg bg-white/10 px-3 py-2 text-sm text-slate-200 disabled:opacity-40"
              >
                Send…
              </button>
            </div>
          </details>
        </section>

        <section className="flex min-h-0 flex-col gap-3 overflow-y-auto border-t border-white/10 p-5 md:border-l md:border-t-0">
          <div className="flex items-baseline justify-between gap-3">
            <h2 className="text-[11px] font-semibold uppercase tracking-[0.14em] text-slate-500">
              Activity
            </h2>
            {running.length > 0 && (
              <span className="font-mono text-[11px] text-slate-500">
                {running.length} running
              </span>
            )}
          </div>

          {transferList.length === 0 ? (
            <div className="rounded-xl border border-dashed border-white/10 px-5 py-7 text-center text-sm text-slate-500">
              <p className="font-medium text-slate-400">Nothing transferring</p>
              <p className="mt-1">
                Drop files onto a device, or use Send files. Anything sent to this machine arrives
                on its own.
              </p>
            </div>
          ) : (
            transferList.map((t) => (
              <TransferCard key={t.id} t={t} onCancel={() => cancelTransfer(t.id)} />
            ))
          )}

          {historyList.length > 0 && (
            <>
              <div className="mt-2 flex items-center gap-3">
                <h3 className="text-[11px] font-semibold uppercase tracking-[0.14em] text-slate-500">
                  Recent
                </h3>
                <span className="h-px flex-1 bg-white/10" />
              </div>
              <ul>
                {historyList.slice(0, 12).map((h, i) => (
                  <li
                    key={`${h.time_unix}-${i}`}
                    className="flex items-center gap-3 border-b border-white/5 py-2 text-sm last:border-0"
                  >
                    <span className="text-slate-500">{h.direction === "incoming" ? "↓" : "↑"}</span>
                    <span className="min-w-0 flex-1 truncate text-slate-200">{h.name}</span>
                    <span className="shrink-0 font-mono text-[11px] tabular-nums text-slate-500">
                      {humanBytes(h.bytes)} ·{" "}
                      {new Date(h.time_unix * 1000).toLocaleString(undefined, {
                        month: "short",
                        day: "numeric",
                        hour: "2-digit",
                        minute: "2-digit",
                      })}
                    </span>
                    {h.direction === "outgoing" && h.target && h.path ? (
                      <button
                        onClick={() => sendAgain(h)}
                        className="shrink-0 rounded bg-white/10 px-2 py-0.5 text-xs text-slate-300"
                        title="Re-offer the same content — resumes if a partial is staged on the peer"
                      >
                        {h.status === "done" ? "Send again" : "Resume"}
                      </button>
                    ) : (
                      <span
                        className={`shrink-0 text-[11px] ${
                          h.status === "done" ? "text-emerald-400" : "text-red-400"
                        }`}
                      >
                        {h.status === "done" ? "done" : "failed"}
                      </span>
                    )}
                  </li>
                ))}
              </ul>
            </>
          )}
        </section>
      </div>

      {/* Reference, not the job: where files land and who this machine trusts. */}
      <footer className="flex shrink-0 flex-wrap items-center justify-between gap-3 border-t border-white/10 bg-black/20 px-5 py-2.5 text-xs text-slate-500">
        <span className="min-w-0 truncate">
          Receiving into{" "}
          <span className="font-mono text-slate-400">
            {settings?.inbox_dir ?? status?.inbox ?? "…"}
          </span>
        </span>
        <span className="flex shrink-0 gap-4">
          <button onClick={() => setSheet("trusted")} className="text-slate-400 hover:text-white">
            Trusted devices{trusted.length > 0 ? ` (${trusted.length})` : ""}
          </button>
          <button onClick={() => setSheet("settings")} className="text-slate-400 hover:text-white">
            Settings
          </button>
        </span>
      </footer>

      {sheet === "link" && (
        <SheetPanel title="Connection" onClose={() => setSheet(null)}>
          {link && link.links.length > 0 ? (
            <>
              <ul className="space-y-2">
                {link.links.map((l) => (
                  <li
                    key={l.iface}
                    className={`flex items-center justify-between gap-3 rounded-lg px-3 py-2 text-sm ring-1 ${
                      l.active
                        ? "bg-conduit-accent/10 ring-conduit-accent/60"
                        : "bg-black/20 ring-white/10"
                    }`}
                  >
                    <span className="min-w-0">
                      <span className={l.active ? "text-slate-100" : "text-slate-300"}>
                        {l.label}
                      </span>
                      <span className="ml-2 font-mono text-[11px] text-slate-500">
                        {l.iface} · {l.addr}
                      </span>
                    </span>
                    {l.active ? (
                      <span className="shrink-0 text-xs font-medium text-conduit-accent">
                        active
                      </span>
                    ) : l.needs_authorization ? (
                      <span className="shrink-0 text-xs text-amber-400">needs authorization</span>
                    ) : (
                      <button
                        onClick={() => setOverride(l.iface)}
                        className="shrink-0 rounded bg-white/10 px-2 py-0.5 text-xs text-slate-300"
                      >
                        Use
                      </button>
                    )}
                  </li>
                ))}
              </ul>
              {link.overridden && (
                <button
                  onClick={() => setOverride(null)}
                  className="mt-3 rounded bg-white/10 px-3 py-1 text-xs text-slate-300"
                >
                  Back to automatic (fastest link)
                </button>
              )}
            </>
          ) : (
            <p className="text-sm text-slate-500">No usable links detected yet.</p>
          )}
        </SheetPanel>
      )}

      {sheet === "trusted" && (
        <SheetPanel title="Trusted devices" onClose={() => setSheet(null)}>
          {trusted.length === 0 ? (
            <p className="text-sm text-slate-500">
              Nothing pinned yet. The first transfer with a device shows a pairing code; confirm it
              and the device is remembered here.
            </p>
          ) : (
            <ul className="space-y-2">
              {trusted.map((t) => (
                <li
                  key={t.fingerprint}
                  className="flex items-center justify-between gap-3 rounded-lg bg-black/20 px-3 py-2 text-sm ring-1 ring-white/10"
                >
                  <span className="min-w-0 truncate">
                    {renaming?.id === t.fingerprint ? (
                      <input
                        autoFocus
                        value={renaming.draft}
                        onChange={(e) => setRenaming({ id: t.fingerprint, draft: e.target.value })}
                        onKeyDown={(e) => {
                          if (e.key === "Enter") commitRename();
                          if (e.key === "Escape") setRenaming(null);
                        }}
                        onBlur={commitRename}
                        className="rounded bg-black/40 px-2 py-0.5 text-sm text-slate-100 outline-none ring-1 ring-conduit-accent"
                      />
                    ) : (
                      <span className="text-slate-100">{t.name}</span>
                    )}
                    <span className="ml-2 font-mono text-[11px] text-slate-500">fp:{t.short}</span>
                  </span>
                  <span className="flex shrink-0 gap-2">
                    <button
                      onClick={() => setRenaming({ id: t.fingerprint, draft: t.name })}
                      className="rounded bg-white/10 px-2 py-0.5 text-xs text-slate-300"
                    >
                      Rename
                    </button>
                    <button
                      onClick={() => revoke(t.fingerprint)}
                      className="rounded bg-red-500/20 px-2 py-0.5 text-xs text-red-300"
                      title="Forget this device — the next connection shows a pairing code again"
                    >
                      Revoke
                    </button>
                  </span>
                </li>
              ))}
            </ul>
          )}
        </SheetPanel>
      )}

      {sheet === "settings" && settings && (
        <SheetPanel title="Settings" onClose={() => setSheet(null)}>
          <div className="space-y-4 text-sm">
            <div className="flex items-center justify-between gap-4">
              <span className="min-w-0 text-slate-300">
                Inbox / shared folder
                <span className="ml-2 truncate font-mono text-[11px] text-slate-500">
                  {settings.inbox_dir ?? status?.inbox ?? "default"}
                </span>
              </span>
              <span className="flex shrink-0 gap-2">
                <button
                  onClick={pickInbox}
                  className="rounded bg-white/10 px-2 py-0.5 text-xs text-slate-300"
                >
                  Change…
                </button>
                {settings.inbox_dir && (
                  <button
                    onClick={() => saveSettings({ inbox_dir: null })}
                    className="rounded bg-white/10 px-2 py-0.5 text-xs text-slate-300"
                  >
                    Default
                  </button>
                )}
              </span>
            </div>

            <NumberSetting
              label="Chunk size (MiB)"
              hint="smaller resumes finer, larger moves faster"
              value={settings.chunk_mib}
              min={1}
              max={64}
              onCommit={(chunk_mib) => saveSettings({ chunk_mib })}
            />
            <NumberSetting
              label="Parallel streams"
              hint="one stream cannot saturate a fast link"
              value={settings.streams}
              min={1}
              max={32}
              onCommit={(streams) => saveSettings({ streams })}
            />

            <label className="flex items-center justify-between gap-4">
              <span className="text-slate-300">Notify when transfers finish or fail</span>
              <input
                type="checkbox"
                checked={settings.notifications}
                onChange={(e) => saveSettings({ notifications: e.target.checked })}
                className="h-4 w-4 accent-[oklch(0.72_0.16_195)]"
              />
            </label>
          </div>
        </SheetPanel>
      )}

      {pairing && (
        <div className="fixed inset-0 z-20 flex items-center justify-center bg-black/70 p-6">
          <div className="w-full max-w-md rounded-2xl bg-conduit-panel p-7 shadow-2xl ring-1 ring-white/15">
            <h2 className="text-lg font-semibold text-white">
              Is this the same code on {pairing.peer_name}?
            </h2>
            <p className="mt-2 text-sm text-slate-400">
              Both machines derive this code from the encrypted connection itself. If they match,
              nobody is sitting in the middle.
            </p>
            <p className="mt-5 rounded-xl bg-black/40 py-4 text-center font-mono text-4xl font-bold tracking-[0.25em] tabular-nums text-conduit-accent ring-1 ring-white/10">
              {pairing.code.slice(0, 3)} {pairing.code.slice(3)}
            </p>
            <p className="mt-3 text-xs text-slate-500">
              Confirming pins this device, so you are only asked once.
            </p>
            <div className="mt-6 flex justify-end gap-3">
              <button
                onClick={() => answerPairing(false)}
                className="rounded-lg bg-white/10 px-4 py-2 text-sm text-slate-200"
              >
                They differ — cancel
              </button>
              <button
                onClick={() => answerPairing(true)}
                className="rounded-lg bg-conduit-accent px-4 py-2 text-sm font-semibold text-black"
              >
                Codes match
              </button>
            </div>
          </div>
        </div>
      )}
    </main>
  );
}

function DeviceCard({
  peer,
  drag,
  mountBusy,
  onSendFiles,
  onSendFolder,
  onToggleMount,
}: {
  peer: PeerRow;
  drag: { count: number; targetId: string | null } | null;
  mountBusy: boolean;
  onSendFiles: () => void;
  onSendFolder: () => void;
  onToggleMount: () => void;
}) {
  const armed = drag !== null && peer.compatible && drag.targetId === peer.id;

  if (!peer.compatible) {
    return (
      <article className="rounded-xl bg-conduit-panel/60 p-4 opacity-60 ring-1 ring-white/5">
        <div className="flex items-center justify-between gap-3">
          <span className="font-medium text-slate-300">{peer.name}</span>
          <span className="rounded-full bg-amber-400/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-amber-400">
            Incompatible
          </span>
        </div>
        <p className="mt-2 text-xs text-amber-400/80">
          Different protocol version — update Conduit on both machines.
        </p>
      </article>
    );
  }

  return (
    <article
      data-peer-id={peer.id}
      className={`flex flex-col gap-3 rounded-xl p-4 ring-1 transition-colors ${
        armed
          ? "bg-conduit-accent/10 ring-conduit-accent"
          : "bg-conduit-panel ring-white/10"
      }`}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="truncate font-medium text-slate-100">{peer.name}</div>
          <div className="font-mono text-[11px] text-slate-500">{peer.addr}</div>
        </div>
        <span
          className={`shrink-0 rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${
            peer.mounted
              ? "bg-conduit-accent/15 text-conduit-accent"
              : peer.trusted
                ? "bg-emerald-400/10 text-emerald-400"
                : "bg-amber-400/10 text-amber-400"
          }`}
        >
          {peer.mounted ? `Mounted ${peer.mounted}` : peer.trusted ? "Paired" : "Not paired"}
        </span>
      </div>

      <div className="flex flex-wrap gap-2">
        <button
          onClick={onSendFiles}
          className="rounded-md bg-conduit-accent px-3 py-1.5 text-xs font-semibold text-black"
        >
          Send files…
        </button>
        <button
          onClick={onSendFolder}
          className="rounded-md bg-white/10 px-3 py-1.5 text-xs text-slate-200"
        >
          Send folder…
        </button>
        <button
          onClick={onToggleMount}
          disabled={mountBusy}
          className="rounded-md bg-white/10 px-3 py-1.5 text-xs text-slate-200 disabled:opacity-40"
        >
          {mountBusy ? "Working…" : peer.mounted ? "Unmount" : "Mount as drive"}
        </button>
      </div>

      <div
        className={`rounded-lg border border-dashed px-3 py-2 text-center text-xs ${
          armed
            ? "border-conduit-accent text-conduit-accent"
            : "border-white/10 text-slate-500"
        }`}
      >
        {armed
          ? `Release to send ${drag.count} ${drag.count === 1 ? "item" : "items"}`
          : "⤓ Drop files here to send"}
      </div>

      {!peer.trusted && (
        <p className="text-[11px] text-slate-500">
          First transfer shows a pairing code on both screens.
        </p>
      )}
    </article>
  );
}

function TransferCard({ t, onCancel }: { t: Transfer; onCancel: () => void }) {
  const pct =
    t.state === "done" ? 100 : t.totalBytes === 0 ? 0 : (t.bytesDone / t.totalBytes) * 100;
  const [rateValue, rateUnit] = splitBytes(t.rate);
  const eta = t.rate > 0 ? humanEta((t.totalBytes - t.bytesDone) / t.rate) : "";
  const live = t.state === "running";

  return (
    <article className="flex flex-col gap-3 rounded-xl bg-conduit-panel p-4 ring-1 ring-white/10">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex min-w-0 items-baseline gap-2">
            <span className="text-conduit-accent">{t.direction === "incoming" ? "↓" : "↑"}</span>
            <span className="truncate font-medium text-slate-100">{t.name}</span>
          </div>
          {t.detail && <p className="mt-0.5 truncate text-xs text-slate-500">{t.detail}</p>}
        </div>
        {live || t.state === "verifying" ? (
          <button
            onClick={onCancel}
            className="shrink-0 rounded bg-white/10 px-2 py-0.5 text-xs text-slate-300"
          >
            Cancel
          </button>
        ) : (
          <span
            className={`shrink-0 text-xs ${
              t.state === "done" ? "text-emerald-400" : "text-red-400"
            }`}
          >
            {t.state === "done" ? "done" : "failed"}
          </span>
        )}
      </div>

      {/* The rate is the point of the product; give it the room to say so. */}
      {live && (
        <div className="flex items-baseline gap-2">
          <span className="font-mono text-3xl font-semibold leading-none tabular-nums tracking-tight text-conduit-accent">
            {rateValue}
          </span>
          <span className="text-xs text-slate-400">{rateUnit}/s</span>
          {eta && (
            <span className="ml-auto font-mono text-xs tabular-nums text-slate-400">{eta}</span>
          )}
        </div>
      )}
      {t.state === "verifying" && (
        <p className="text-sm text-amber-400">Verifying every chunk hash…</p>
      )}

      {live && <Spark samples={t.samples} />}

      <div className="h-2 overflow-hidden rounded-full bg-black/40 ring-1 ring-white/5">
        <div
          className={`h-full rounded-full transition-[width] duration-150 ${
            t.state === "failed"
              ? "bg-red-500"
              : t.state === "verifying"
                ? "bg-amber-400"
                : "bg-conduit-accent"
          }`}
          style={{ width: `${Math.min(100, pct)}%` }}
        />
      </div>
      <p className="font-mono text-[11px] tabular-nums text-slate-500">
        {humanBytes(t.bytesDone)} of {humanBytes(t.totalBytes)} · {pct.toFixed(1)}%
      </p>
    </article>
  );
}

/** Throughput over the last few seconds. Flat while a transfer warms up, which is
    itself informative — a stalled link shows as a line running into the floor. */
function Spark({ samples }: { samples: number[] }) {
  if (samples.length < 3) return <div className="h-8" />;
  const max = Math.max(...samples) || 1;
  const n = samples.length;
  const pt = (s: number, i: number) => [(i / (n - 1)) * 100, 30 - (s / max) * 26];
  const line = samples
    .map((s, i) => {
      const [x, y] = pt(s, i);
      return `${i === 0 ? "M" : "L"}${x.toFixed(2)},${y.toFixed(2)}`;
    })
    .join(" ");
  const [lastX, lastY] = pt(samples[n - 1], n - 1);

  return (
    <svg
      viewBox="0 0 100 32"
      preserveAspectRatio="none"
      className="h-8 w-full"
      aria-label="Throughput over the last few seconds"
    >
      <path d={`${line} L100,32 L0,32 Z`} fill="oklch(0.72 0.16 195 / 0.10)" />
      <path
        d={line}
        fill="none"
        stroke="oklch(0.72 0.16 195)"
        strokeWidth={1.5}
        strokeLinejoin="round"
        vectorEffect="non-scaling-stroke"
      />
      <circle cx={lastX} cy={lastY} r={1.6} fill="oklch(0.72 0.16 195)" vectorEffect="non-scaling-stroke" />
    </svg>
  );
}

/** Number field that saves when you leave it, not on every keystroke — each save
    writes settings.json and refetches status, which made typing feel sticky. */
function NumberSetting({
  label,
  hint,
  value,
  min,
  max,
  onCommit,
}: {
  label: string;
  hint: string;
  value: number;
  min: number;
  max: number;
  onCommit: (v: number) => void;
}) {
  const [draft, setDraft] = useState(String(value));
  useEffect(() => setDraft(String(value)), [value]);

  const commit = () => {
    const n = Math.min(max, Math.max(min, Number(draft) || value));
    setDraft(String(n));
    if (n !== value) onCommit(n);
  };

  return (
    <div className="flex items-center justify-between gap-4">
      <span className="text-slate-300">
        {label} <span className="text-xs text-slate-500">— {hint}</span>
      </span>
      <input
        type="number"
        min={min}
        max={max}
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
        onBlur={commit}
        onKeyDown={(e) => {
          if (e.key === "Enter") e.currentTarget.blur();
        }}
        className="w-20 shrink-0 rounded bg-black/30 px-2 py-1 text-right font-mono text-sm tabular-nums text-slate-100 ring-1 ring-white/10"
      />
    </div>
  );
}

function SheetPanel({
  title,
  onClose,
  children,
}: {
  title: string;
  onClose: () => void;
  children: React.ReactNode;
}) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div
      className="fixed inset-0 z-10 flex items-end justify-center bg-black/60 p-0 sm:items-center sm:p-6"
      onClick={onClose}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        className="max-h-[80vh] w-full max-w-lg overflow-y-auto rounded-t-2xl bg-conduit-panel p-6 shadow-2xl ring-1 ring-white/15 sm:rounded-2xl"
      >
        <div className="mb-4 flex items-baseline justify-between gap-3">
          <h2 className="text-sm font-semibold uppercase tracking-[0.14em] text-slate-400">
            {title}
          </h2>
          <button onClick={onClose} className="text-xs text-slate-400 hover:text-white">
            Close
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}
