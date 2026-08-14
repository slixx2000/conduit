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

type Transfer = {
  id: string;
  direction: "incoming" | "outgoing";
  name: string;
  totalBytes: number;
  bytesDone: number;
  state: "running" | "verifying" | "done" | "failed";
  detail?: string;
};

function humanBytes(b: number): string {
  if (b < 1024) return `${b} B`;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let v = b;
  let i = -1;
  do {
    v /= 1024;
    i++;
  } while (v >= 1024 && i < units.length - 1);
  return `${v.toFixed(2)} ${units[i]}`;
}

export default function App() {
  const [status, setStatus] = useState<NodeStatus | null>(null);
  const [bridgeError, setBridgeError] = useState<string | null>(null);
  const [peers, setPeers] = useState<PeerRow[]>([]);
  const [manualAddr, setManualAddr] = useState("");
  const [lastError, setLastError] = useState<string | null>(null);
  const [pairing, setPairing] = useState<PairingPrompt | null>(null);
  const [link, setLink] = useState<LinkStatus | null>(null);
  const [dragging, setDragging] = useState(false);
  const [transfers, setTransfers] = useState<Map<string, Transfer>>(new Map());
  // The transfer list renders newest-first; keep insertion order for stability.
  const orderRef = useRef<string[]>([]);
  const peersRef = useRef<PeerRow[]>([]);
  peersRef.current = peers;

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
          next.set(e.transfer_id, {
            ...base,
            bytesDone: e.bytes_already,
            detail: `resumed — ${humanBytes(e.bytes_already)} already transferred`,
          });
          break;
        case "progress":
          next.set(e.transfer_id, {
            ...base,
            bytesDone: e.bytes_done,
            totalBytes: e.total_bytes,
          });
          break;
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

    // Poll the link so plugging in the cable (or an authorization prompt appearing)
    // shows up without a restart.
    const pollLink = () => invoke<LinkStatus>("link_status").then(setLink).catch(() => {});
    pollLink();
    const linkTimer = setInterval(pollLink, 5000);

    const unlistens = [
      listen<TransferNotification>("conduit://transfer", (ev) => applyEvent(ev.payload)),
      listen<PairingPrompt>("conduit://pairing", (ev) => setPairing(ev.payload)),
      listen<PeerRow[]>("conduit://peers", (ev) => setPeers(ev.payload)),
      listen<{ message: string }>("conduit://error", (ev) => setLastError(ev.payload.message)),
    ];

    // Native drag-and-drop: dropping files onto a peer card sends them there. The
    // event carries physical coordinates; convert to CSS pixels to hit-test cards.
    const dragUnlisten = getCurrentWebview().onDragDropEvent((event) => {
      if (event.payload.type === "over") {
        setDragging(true);
        return;
      }
      setDragging(false);
      if (event.payload.type !== "drop") return;

      const { paths, position } = event.payload;
      const scale = window.devicePixelRatio || 1;
      const el = document.elementFromPoint(position.x / scale, position.y / scale);
      const targetId =
        el?.closest<HTMLElement>("[data-peer-id]")?.dataset.peerId ??
        // No card under the cursor: an unambiguous single peer still works.
        (peersRef.current.filter((p) => p.compatible).length === 1
          ? peersRef.current.filter((p) => p.compatible)[0].id
          : null);
      if (targetId && paths.length > 0) {
        sendPaths(targetId, paths);
      } else if (paths.length > 0) {
        setLastError("Drop the files onto a specific peer in the list.");
      }
    });

    return () => {
      clearInterval(linkTimer);
      for (const u of unlistens) u.then((f) => f());
      dragUnlisten.then((f) => f());
    };
  }, [applyEvent, sendPaths]);

  async function chooseAndSend(target: string) {
    const file = await open({ multiple: false, directory: false });
    if (typeof file === "string") sendPaths(target, [file]);
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

  function setOverride(iface: string | null) {
    invoke("set_link_override", { iface })
      .then(() => invoke<LinkStatus>("link_status").then(setLink).catch(() => {}))
      .catch(() => {});
  }

  const transferList = orderRef.current
    .map((id) => transfers.get(id))
    .filter((t): t is Transfer => t !== undefined);
  const activeLink = link?.links.find((l) => l.active) ?? null;
  const unauthorized = link?.links.filter((l) => l.needs_authorization) ?? [];

  return (
    <main className="flex h-full flex-col gap-6 overflow-y-auto bg-conduit-bg p-8 text-slate-200">
      <header className="flex items-baseline justify-between">
        <div>
          <h1 className="text-3xl font-semibold tracking-tight text-white">Conduit</h1>
          <p className="mt-1 text-sm text-slate-400">
            {status
              ? `${status.device_name} · listening on ${status.listen_addr}`
              : "starting backend…"}
          </p>
          {activeLink && (
            <p className="mt-0.5 text-xs text-conduit-accent">
              {activeLink.label}
              {link?.overridden ? " · pinned" : ""}
            </p>
          )}
        </div>
        {status && (
          <p className="font-mono text-xs text-slate-500">id {status.fingerprint}</p>
        )}
      </header>

      {unauthorized.length > 0 && (
        <section className="rounded-xl bg-amber-950/60 p-4 text-sm text-amber-300 ring-1 ring-amber-500/30">
          Thunderbolt device{unauthorized.length > 1 ? "s" : ""}{" "}
          <span className="font-medium">
            {unauthorized.map((l) => l.iface).join(", ")}
          </span>{" "}
          {unauthorized.length > 1 ? "are" : "is"} waiting for authorization. Approve
          the connection in your OS (Linux:{" "}
          <code className="rounded bg-black/30 px-1">boltctl authorize</code> or the
          desktop prompt) to unlock the fast link — transfers fall back to the next
          best link until then.
        </section>
      )}

      {bridgeError && (
        <section className="rounded-xl bg-conduit-panel p-4 text-sm text-amber-300 ring-1 ring-white/10">
          No Tauri backend attached — run{" "}
          <code className="rounded bg-black/30 px-1">npm run tauri dev</code> instead of{" "}
          <code className="rounded bg-black/30 px-1">npm run dev</code>.
        </section>
      )}

      {/* Peers */}
      <section className="rounded-xl bg-conduit-panel p-6 shadow-lg ring-1 ring-white/10">
        <h2 className="text-sm font-medium uppercase tracking-wide text-slate-400">
          Peers
        </h2>
        {peers.length === 0 ? (
          <p className="mt-3 text-sm text-slate-500">
            Looking for peers… start Conduit on the other machine (same network or a
            direct cable) and it appears here automatically.
          </p>
        ) : (
          <ul className="mt-3 grid gap-3 sm:grid-cols-2">
            {peers.map((p) => (
              <li
                key={p.id}
                data-peer-id={p.compatible ? p.id : undefined}
                className={`rounded-lg p-4 ring-1 transition-colors ${
                  p.compatible
                    ? dragging
                      ? "bg-conduit-accent/10 ring-conduit-accent"
                      : "bg-black/20 ring-white/10"
                    : "bg-black/10 opacity-50 ring-white/5"
                }`}
              >
                <div className="flex items-baseline justify-between">
                  <span className="font-medium text-slate-100">{p.name}</span>
                  <span className="text-xs text-slate-500">
                    {p.trusted ? "paired" : "not paired"}
                  </span>
                </div>
                <p className="mt-0.5 font-mono text-xs text-slate-500">{p.addr}</p>
                {p.compatible ? (
                  <div className="mt-3 flex gap-2">
                    <button
                      onClick={() => chooseAndSend(p.id)}
                      className="rounded-md bg-conduit-accent px-3 py-1.5 text-xs font-semibold text-black"
                    >
                      Send file
                    </button>
                    <button
                      onClick={() => chooseFolderAndSend(p.id)}
                      className="rounded-md bg-white/10 px-3 py-1.5 text-xs text-slate-200"
                    >
                      Send folder
                    </button>
                    <span className="ml-auto self-center text-[11px] text-slate-500">
                      or drop files here
                    </span>
                  </div>
                ) : (
                  <p className="mt-3 text-xs text-amber-400/80">
                    Different protocol version — update Conduit on both machines.
                  </p>
                )}
              </li>
            ))}
          </ul>
        )}

        <details className="mt-4">
          <summary className="cursor-pointer text-xs text-slate-500">
            Connect by address (when discovery is blocked)
          </summary>
          <div className="mt-2 flex gap-2">
            <input
              value={manualAddr}
              onChange={(e) => setManualAddr(e.target.value)}
              placeholder="ip:port, e.g. 169.254.10.5:4433"
              spellCheck={false}
              className="flex-1 rounded-lg bg-black/30 px-3 py-2 font-mono text-sm text-slate-100 outline-none ring-1 ring-white/10 placeholder:text-slate-500 focus:ring-conduit-accent"
            />
            <button
              onClick={() => chooseAndSend(manualAddr)}
              disabled={manualAddr.trim() === ""}
              className="rounded-lg bg-white/10 px-4 py-2 text-sm text-slate-200 disabled:opacity-40"
            >
              Send file…
            </button>
          </div>
        </details>
      </section>

      {/* Connection */}
      {link && link.links.length > 0 && (
        <section className="rounded-xl bg-conduit-panel p-6 shadow-lg ring-1 ring-white/10">
          <div className="flex items-baseline justify-between">
            <h2 className="text-sm font-medium uppercase tracking-wide text-slate-400">
              Connection
            </h2>
            {link.overridden && (
              <button
                onClick={() => setOverride(null)}
                className="rounded bg-white/10 px-2 py-0.5 text-xs text-slate-300 hover:bg-white/20"
              >
                Auto (fastest)
              </button>
            )}
          </div>
          <ul className="mt-3 space-y-2">
            {link.links.map((l) => (
              <li
                key={l.iface}
                className={`flex items-center justify-between rounded-lg px-3 py-2 text-sm ring-1 ${
                  l.active
                    ? "bg-conduit-accent/10 ring-conduit-accent/60"
                    : "bg-black/20 ring-white/10"
                }`}
              >
                <span>
                  <span className={l.active ? "text-slate-100" : "text-slate-300"}>
                    {l.label}
                  </span>
                  <span className="ml-2 font-mono text-xs text-slate-500">
                    {l.iface} · {l.addr}
                  </span>
                  {l.requires_special_hw && (
                    <span className="ml-2 text-xs text-slate-500">(bridge cable)</span>
                  )}
                </span>
                {l.active ? (
                  <span className="text-xs font-medium text-conduit-accent">active</span>
                ) : l.needs_authorization ? (
                  <span className="text-xs text-amber-400">needs authorization</span>
                ) : (
                  <button
                    onClick={() => setOverride(l.iface)}
                    className="rounded bg-white/10 px-2 py-0.5 text-xs text-slate-300 hover:bg-white/20"
                  >
                    Use
                  </button>
                )}
              </li>
            ))}
          </ul>
        </section>
      )}

      {/* Receive info */}
      {status && (
        <section className="rounded-xl bg-conduit-panel p-6 shadow-lg ring-1 ring-white/10">
          <h2 className="text-sm font-medium uppercase tracking-wide text-slate-400">
            Receiving
          </h2>
          <p className="mt-2 text-sm text-slate-300">
            Always listening. Incoming files land in{" "}
            <code className="rounded bg-black/30 px-1 font-mono">{status.inbox}</code>.
          </p>
        </section>
      )}

      {lastError && (
        <section className="rounded-xl bg-red-950/60 p-4 text-sm text-red-300 ring-1 ring-red-500/30">
          {lastError}
        </section>
      )}

      {/* Transfers */}
      {transferList.length > 0 && (
        <section className="rounded-xl bg-conduit-panel p-6 shadow-lg ring-1 ring-white/10">
          <h2 className="text-sm font-medium uppercase tracking-wide text-slate-400">
            Transfers
          </h2>
          <ul className="mt-3 space-y-4">
            {transferList.map((t) => (
              <TransferRow key={t.id} t={t} onCancel={() => cancelTransfer(t.id)} />
            ))}
          </ul>
        </section>
      )}

      {/* Pairing modal */}
      {pairing && (
        <div className="fixed inset-0 z-10 flex items-center justify-center bg-black/60">
          <div className="w-full max-w-sm rounded-2xl bg-conduit-panel p-8 text-center shadow-2xl ring-1 ring-white/15">
            <h2 className="text-lg font-semibold text-white">
              {pairing.direction === "incoming" ? "Pairing request" : "Pair with"}{" "}
              {pairing.peer_name}
            </h2>
            <p className="mt-2 text-sm text-slate-400">
              Confirm that the same code is shown on the other device:
            </p>
            <p className="mt-4 font-mono text-4xl font-bold tracking-[0.3em] text-conduit-accent">
              {pairing.code.slice(0, 3)} {pairing.code.slice(3)}
            </p>
            <div className="mt-6 flex justify-center gap-3">
              <button
                onClick={() => answerPairing(false)}
                className="rounded-lg bg-white/10 px-4 py-2 text-sm text-slate-200"
              >
                Reject
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

function TransferRow({ t, onCancel }: { t: Transfer; onCancel: () => void }) {
  const pct =
    t.state === "done"
      ? 100
      : t.totalBytes === 0
        ? 0
        : Math.min(100, (t.bytesDone / t.totalBytes) * 100);
  const stateLabel =
    t.state === "running"
      ? `${pct.toFixed(1)}%`
      : t.state === "verifying"
        ? "verifying…"
        : t.state === "done"
          ? "done"
          : "failed";

  return (
    <li>
      <div className="flex items-baseline justify-between gap-3 text-sm">
        <span className="truncate font-medium text-slate-100">
          <span className="mr-2 text-slate-500">{t.direction === "incoming" ? "↓" : "↑"}</span>
          {t.name}
        </span>
        <span className="flex items-center gap-3">
          <span
            className={
              t.state === "failed"
                ? "text-red-400"
                : t.state === "done"
                  ? "text-emerald-400"
                  : "text-slate-400"
            }
          >
            {stateLabel}
          </span>
          {(t.state === "running" || t.state === "verifying") && (
            <button
              onClick={onCancel}
              className="rounded bg-white/10 px-2 py-0.5 text-xs text-slate-300 hover:bg-white/20"
            >
              Cancel
            </button>
          )}
        </span>
      </div>
      <div className="mt-1.5 h-2 overflow-hidden rounded-full bg-black/40">
        <div
          className={`h-full rounded-full transition-[width] duration-150 ${
            t.state === "failed" ? "bg-red-500" : "bg-conduit-accent"
          }`}
          style={{ width: `${pct}%` }}
        />
      </div>
      <p className="mt-1 text-xs text-slate-500">
        {humanBytes(t.bytesDone)} / {humanBytes(t.totalBytes)}
        {t.detail ? ` — ${t.detail}` : ""}
      </p>
    </li>
  );
}
