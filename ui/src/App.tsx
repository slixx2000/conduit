import { useCallback, useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { open } from "@tauri-apps/plugin-dialog";

/** Mirrors `NodeStatus` in `src-tauri/src/lib.rs`. */
type NodeStatus = {
  device_name: string;
  listen_addr: string;
  inbox: string;
  fingerprint: string;
};

/** Mirrors `TransferEvent` in `conduit-core` (serde tag = "kind"). */
type TransferEvent =
  | { kind: "offered"; transfer_id: string; name: string; total_bytes: number }
  | { kind: "started"; transfer_id: string; name: string; total_bytes: number }
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

/** Mirrors `LinkStatus` in `src-tauri/src/lib.rs`. */
type LinkStatus = { preferred: string | null; unauthorized: string[] };

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
  const [peerAddr, setPeerAddr] = useState("");
  const [sending, setSending] = useState(false);
  const [lastError, setLastError] = useState<string | null>(null);
  const [pairing, setPairing] = useState<PairingPrompt | null>(null);
  const [link, setLink] = useState<LinkStatus | null>(null);
  const [transfers, setTransfers] = useState<Map<string, Transfer>>(new Map());
  // The transfer list renders newest-first; keep insertion order for stability.
  const orderRef = useRef<string[]>([]);

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
          next.set(e.transfer_id, { ...base, name: e.name, totalBytes: e.total_bytes });
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

  useEffect(() => {
    // Running under `vite` alone (no Tauri host) there is no IPC bridge. That is a
    // normal way to work on the UI, so report it as a state rather than an error.
    invoke<NodeStatus>("node_status")
      .then(setStatus)
      .catch((e: unknown) => setBridgeError(e instanceof Error ? e.message : String(e)));

    // Poll the link so plugging in the cable (or an authorization prompt appearing)
    // shows up without a restart. Discovery events replace this in Phase 3.
    const pollLink = () => invoke<LinkStatus>("link_status").then(setLink).catch(() => {});
    pollLink();
    const linkTimer = setInterval(pollLink, 5000);

    const unlistens = [
      listen<TransferNotification>("conduit://transfer", (ev) => applyEvent(ev.payload)),
      listen<PairingPrompt>("conduit://pairing", (ev) => setPairing(ev.payload)),
      listen<{ message: string }>("conduit://error", (ev) => setLastError(ev.payload.message)),
    ];
    return () => {
      clearInterval(linkTimer);
      for (const u of unlistens) u.then((f) => f());
    };
  }, [applyEvent]);

  async function chooseAndSend() {
    setLastError(null);
    const file = await open({ multiple: false, directory: false });
    if (typeof file !== "string") return;
    setSending(true);
    try {
      await invoke("send_to_peer", { addr: peerAddr, path: file });
    } catch (e) {
      setLastError(e instanceof Error ? e.message : String(e));
    } finally {
      setSending(false);
    }
  }

  async function answerPairing(accept: boolean) {
    setPairing(null);
    await invoke("confirm_pairing", { accept });
  }

  const transferList = orderRef.current
    .map((id) => transfers.get(id))
    .filter((t): t is Transfer => t !== undefined);

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
          {link?.preferred && (
            <p className="mt-0.5 text-xs text-conduit-accent">link: {link.preferred}</p>
          )}
        </div>
        {status && (
          <p className="font-mono text-xs text-slate-500">id {status.fingerprint}</p>
        )}
      </header>

      {link && link.unauthorized.length > 0 && (
        <section className="rounded-xl bg-amber-950/60 p-4 text-sm text-amber-300 ring-1 ring-amber-500/30">
          Thunderbolt device{link.unauthorized.length > 1 ? "s" : ""}{" "}
          <span className="font-medium">{link.unauthorized.join(", ")}</span>{" "}
          {link.unauthorized.length > 1 ? "are" : "is"} waiting for authorization.
          Approve the connection in your OS (Linux: <code className="rounded bg-black/30 px-1">boltctl authorize</code> or
          the desktop prompt) to unlock the fast link — transfers fall back to
          LAN/WiFi until then.
        </section>
      )}

      {bridgeError && (
        <section className="rounded-xl bg-conduit-panel p-4 text-sm text-amber-300 ring-1 ring-white/10">
          No Tauri backend attached — run{" "}
          <code className="rounded bg-black/30 px-1">npm run tauri dev</code> instead of{" "}
          <code className="rounded bg-black/30 px-1">npm run dev</code>.
        </section>
      )}

      {/* Send */}
      <section className="rounded-xl bg-conduit-panel p-6 shadow-lg ring-1 ring-white/10">
        <h2 className="text-sm font-medium uppercase tracking-wide text-slate-400">
          Send a file
        </h2>
        <div className="mt-3 flex gap-3">
          <input
            value={peerAddr}
            onChange={(e) => setPeerAddr(e.target.value)}
            placeholder="peer address, e.g. 192.168.1.20:4433"
            spellCheck={false}
            className="flex-1 rounded-lg bg-black/30 px-3 py-2 font-mono text-sm text-slate-100 outline-none ring-1 ring-white/10 placeholder:text-slate-500 focus:ring-conduit-accent"
          />
          <button
            onClick={chooseAndSend}
            disabled={sending || peerAddr.trim() === ""}
            className="rounded-lg bg-conduit-accent px-4 py-2 text-sm font-semibold text-black transition-opacity disabled:opacity-40"
          >
            {sending ? "Sending…" : "Choose file & send"}
          </button>
        </div>
        <p className="mt-2 text-xs text-slate-500">
          The other machine shows its address in this header. Peers appear automatically
          once discovery lands (Phase 3).
        </p>
      </section>

      {/* Receive info */}
      {status && (
        <section className="rounded-xl bg-conduit-panel p-6 shadow-lg ring-1 ring-white/10">
          <h2 className="text-sm font-medium uppercase tracking-wide text-slate-400">
            Receiving
          </h2>
          <p className="mt-2 text-sm text-slate-300">
            Always listening on{" "}
            <code className="rounded bg-black/30 px-1 font-mono">{status.listen_addr}</code>.
            Incoming files land in{" "}
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
              <TransferRow key={t.id} t={t} />
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

function TransferRow({ t }: { t: Transfer }) {
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
      <div className="flex items-baseline justify-between text-sm">
        <span className="truncate font-medium text-slate-100">
          <span className="mr-2 text-slate-500">{t.direction === "incoming" ? "↓" : "↑"}</span>
          {t.name}
        </span>
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
