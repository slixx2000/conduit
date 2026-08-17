//! Tauri glue.
//!
//! Everything here is a thin wrapper over the `conduit-*` crates: commands marshal
//! arguments, call into the core, and turn typed errors into strings the UI can show.
//! Business logic belongs in the crates, not here — that is what keeps the core
//! testable headless.
//!
//! The app binds a QUIC endpoint on startup, always listens, and announces itself
//! over mDNS while browsing for peers — nobody types an IP. Inbound transfers land in
//! `Downloads/Conduit`. Both directions run the TOFU pairing-code flow; outgoing
//! sends retry on disconnect (the receiver resumes from its staged partial). Live
//! state streams to the frontend as events:
//!   "conduit://peers"     [{ id, name, addr, trusted, compatible }]  (full list)
//!   "conduit://pairing"   { code, peer_name, direction }
//!   "conduit://transfer"  { direction, event: TransferEvent }
//!   "conduit://error"     { message }

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_notification::NotificationExt;
use tokio::sync::{mpsc, oneshot, Mutex};

use conduit_core::{
    ByeReason, ConduitEndpoint, DeviceId, DeviceIdentity, FsClient, PeerSession, ReceiveOptions,
    SendOptions, Served, TransferEvent, TransferId, TrustStatus, TrustStore,
};
use conduit_discovery::{Discovery, Peer, PeerEvent};

/// How often a dropped connection is redialed before an outgoing transfer gives up.
const SEND_RETRIES: u32 = 5;
const SEND_RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(2);

/// Snapshot of what the backend is and what link it would use. Rendered by the
/// window header, and useful as a smoke test that the UI↔Rust bridge works.
#[derive(Debug, Serialize)]
pub struct AppInfo {
    pub app_version: String,
    pub protocol_version: u16,
    pub service_type: String,
    pub default_chunk_size: u32,
    pub mount_driver: String,
    /// Interface the data path would bind to, or `None` while link detection is a
    /// Phase 2 stub (meaning: let the OS route over LAN/loopback).
    pub preferred_link: Option<String>,
}

#[tauri::command]
async fn app_info() -> Result<AppInfo, String> {
    let preferred_link = conduit_net::TransportManager::with_defaults()
        .preferred()
        .await
        .map(|l| format!("{} — {}", l.iface_name, l.label()));

    Ok(AppInfo {
        app_version: env!("CARGO_PKG_VERSION").to_string(),
        protocol_version: conduit_core::PROTOCOL_VERSION,
        service_type: conduit_discovery::SERVICE_TYPE.to_string(),
        default_chunk_size: conduit_core::DEFAULT_CHUNK_SIZE,
        mount_driver: conduit_fs::REQUIRED_DRIVER.to_string(),
        preferred_link,
    })
}

struct AppState {
    endpoint: Arc<ConduitEndpoint>,
    trust: Arc<Mutex<TrustStore>>,
    /// The one pairing prompt that may be on screen; `confirm_pairing` resolves it.
    pending_pairing: Arc<Mutex<Option<oneshot::Sender<bool>>>>,
    /// Peers currently visible via mDNS.
    peers: Arc<Mutex<HashMap<DeviceId, Peer>>>,
    /// Abort handles for in-flight transfers, keyed by transfer id — how the UI's
    /// cancel button reaches a running task. Aborting drops the QUIC connection;
    /// the receiver keeps its staged partial, so a cancelled transfer can resume.
    active: Arc<Mutex<HashMap<TransferId, tokio::task::AbortHandle>>>,
    /// Keeps the mDNS advertisement alive for the app's lifetime.
    _discovery: Discovery,
    /// Live mounts of peers as local drives, keyed by peer.
    mounts: Arc<Mutex<HashMap<DeviceId, ActiveMount>>>,
    /// One-transfer-at-a-time gate per send target. A multi-file drop otherwise
    /// opens a QUIC connection per file, all racing each other.
    /// ponytail: entries are never pruned — bounded by distinct targets, which is tiny.
    send_queues: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
    /// The pluggable link layer (`docs/Transports.md`).
    transports: conduit_net::TransportManager,
    /// User-pinned interface name; `None` = auto-select the fastest link.
    link_override: Arc<Mutex<Option<String>>>,
    settings: Arc<Mutex<Settings>>,
    settings_path: PathBuf,
    history: Arc<Mutex<Vec<HistoryEntry>>>,
    history_path: PathBuf,
    listen_addr: SocketAddr,
    /// Fallback inbox when settings name none (Downloads/Conduit).
    default_inbox: PathBuf,
    device_name: String,
    fingerprint_short: String,
}

/// What the UI shows about this device: who we are and where peers reach us.
#[derive(Debug, Serialize)]
struct NodeStatus {
    device_name: String,
    listen_addr: String,
    inbox: String,
    fingerprint: String,
}

/// One link in the Connection panel.
#[derive(Debug, Serialize, Clone)]
struct LinkRow {
    /// e.g. "Thunderbolt / USB4 · ~20 Gbps · direct cable".
    label: String,
    iface: String,
    addr: String,
    direct: bool,
    needs_authorization: bool,
    requires_special_hw: bool,
    /// The link the app is currently using (auto-selected or overridden).
    active: bool,
}

/// Live link report for the UI: every detected link ranked best-first, the active
/// choice marked, plus whether a manual override is in force. Computed fresh per
/// call — the UI polls it so plugging/unplugging a cable mid-session is reflected.
#[derive(Debug, Serialize)]
struct LinkStatus {
    links: Vec<LinkRow>,
    overridden: bool,
}

#[tauri::command]
async fn link_status(state: State<'_, AppState>) -> Result<LinkStatus, String> {
    let links = state.transports.available().await;
    let override_iface = state.link_override.lock().await.clone();

    // The override only holds while its link is still present and usable;
    // otherwise fall back to the automatic best choice.
    let active_iface = override_iface
        .as_deref()
        .filter(|name| links.iter().any(|l| l.iface_name == *name && l.is_usable()))
        .map(str::to_string)
        .or_else(|| {
            links
                .iter()
                .find(|l| l.is_usable())
                .map(|l| l.iface_name.clone())
        });

    Ok(LinkStatus {
        overridden: override_iface.is_some(),
        links: links
            .into_iter()
            .map(|l| LinkRow {
                label: l.label(),
                addr: l.bind_addr.to_string(),
                direct: l.direct,
                needs_authorization: l.needs_authorization,
                requires_special_hw: l.requires_special_hw,
                active: active_iface.as_deref() == Some(l.iface_name.as_str()),
                iface: l.iface_name,
            })
            .collect(),
    })
}

/// Pin the active link to `iface`, or pass `None` to return to automatic
/// (fastest-link) selection.
#[tauri::command]
async fn set_link_override(
    state: State<'_, AppState>,
    iface: Option<String>,
) -> Result<(), String> {
    *state.link_override.lock().await = iface;
    Ok(())
}

#[tauri::command]
async fn node_status(state: State<'_, AppState>) -> Result<NodeStatus, String> {
    Ok(NodeStatus {
        device_name: state.device_name.clone(),
        listen_addr: state.listen_addr.to_string(),
        inbox: inbox_dir(&state).await.display().to_string(),
        fingerprint: state.fingerprint_short.clone(),
    })
}

#[tauri::command]
async fn get_settings(state: State<'_, AppState>) -> Result<Settings, String> {
    Ok(state.settings.lock().await.clone())
}

#[tauri::command]
async fn set_settings(state: State<'_, AppState>, settings: Settings) -> Result<(), String> {
    let json = serde_json::to_vec_pretty(&settings).map_err(|e| e.to_string())?;
    std::fs::write(&state.settings_path, json).map_err(|e| e.to_string())?;
    *state.settings.lock().await = settings;
    Ok(())
}

#[tauri::command]
async fn history(state: State<'_, AppState>) -> Result<Vec<HistoryEntry>, String> {
    Ok(state.history.lock().await.clone())
}

/// One pinned device in the trust store. `fingerprint` (full hex) is the handle
/// rename/revoke act on; `short` and `device_id` are for display.
#[derive(Debug, Serialize)]
struct TrustedRow {
    fingerprint: String,
    short: String,
    name: String,
    device_id: String,
}

#[tauri::command]
async fn trusted_peers(state: State<'_, AppState>) -> Result<Vec<TrustedRow>, String> {
    let trust = state.trust.lock().await;
    let mut rows: Vec<TrustedRow> = trust
        .peers()
        .map(|(fp, peer)| TrustedRow {
            short: fp[..8.min(fp.len())].to_string(),
            fingerprint: fp.clone(),
            name: peer.name.clone(),
            device_id: peer.device_id.to_string(),
        })
        .collect();
    rows.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(rows)
}

#[tauri::command]
async fn rename_trusted(
    app: AppHandle,
    state: State<'_, AppState>,
    fingerprint: String,
    name: String,
) -> Result<(), String> {
    let name = name.trim();
    if name.is_empty() {
        return Err("the name cannot be empty".into());
    }
    state
        .trust
        .lock()
        .await
        .rename(&fingerprint, name)
        .map_err(|e| e.to_string())?;
    let _ = app.emit("conduit://peers", peer_rows(&state).await);
    Ok(())
}

/// Un-pin a device. The next connection from it shows the pairing code again.
#[tauri::command]
async fn revoke_trusted(
    app: AppHandle,
    state: State<'_, AppState>,
    fingerprint: String,
) -> Result<(), String> {
    state
        .trust
        .lock()
        .await
        .remove(&fingerprint)
        .map_err(|e| e.to_string())?;
    let _ = app.emit("conduit://peers", peer_rows(&state).await);
    Ok(())
}

/// A peer mounted as a local drive.
struct ActiveMount {
    handle: conduit_fs::MountHandle,
    client: FsClient,
}

/// User-tunable knobs, persisted as `settings.json` in the app config dir.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
struct Settings {
    /// Where incoming files land (and what peers see when they mount us).
    /// `None` = the default `Downloads/Conduit`.
    inbox_dir: Option<String>,
    /// Transfer chunk size in MiB.
    chunk_mib: u32,
    /// Parallel data streams per transfer.
    streams: usize,
    /// Desktop notifications on finished/failed transfers.
    notifications: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            inbox_dir: None,
            chunk_mib: 4,
            streams: conduit_core::DEFAULT_STREAM_COUNT,
            notifications: true,
        }
    }
}

impl Settings {
    fn send_options(&self) -> SendOptions {
        SendOptions {
            chunk_size: self.chunk_mib.clamp(1, 64) * 1024 * 1024,
            streams: self.streams.clamp(1, 32),
            corrupt_chunk_once: None,
        }
    }
}

/// One finished (or failed) transfer, newest first, persisted as `history.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct HistoryEntry {
    time_unix: u64,
    /// "incoming" | "outgoing".
    direction: String,
    name: String,
    bytes: u64,
    peer: String,
    /// "done" or "failed: <reason>".
    status: String,
    /// Destination path for incoming, source path for outgoing.
    path: Option<String>,
    /// Outgoing only: the target this went to, so "Send again" can re-offer —
    /// which resumes instead of restarting if a partial is staged over there.
    target: Option<String>,
}

const HISTORY_CAP: usize = 200;

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

async fn append_history(app: &AppHandle, entry: HistoryEntry) {
    let state = app.state::<AppState>();
    let snapshot = {
        let mut history = state.history.lock().await;
        history.insert(0, entry);
        history.truncate(HISTORY_CAP);
        history.clone()
    };
    if let Ok(json) = serde_json::to_vec_pretty(&snapshot) {
        let _ = std::fs::write(&state.history_path, json);
    }
    let _ = app.emit("conduit://history", snapshot);
}

/// Desktop notification, honoring the settings toggle. Never fails a transfer.
async fn notify(app: &AppHandle, title: &str, body: &str) {
    let enabled = app.state::<AppState>().settings.lock().await.notifications;
    if enabled {
        let _ = app
            .notification()
            .builder()
            .title(title)
            .body(body)
            .show();
    }
}

/// The current inbox/shared directory, per settings.
async fn inbox_dir(state: &AppState) -> PathBuf {
    state
        .settings
        .lock()
        .await
        .inbox_dir
        .as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(|| state.default_inbox.clone())
}

/// One row of the UI's peer list.
#[derive(Debug, Serialize, Clone)]
struct PeerRow {
    id: String,
    name: String,
    addr: String,
    /// Already pinned — connecting will not prompt for a code.
    trusted: bool,
    /// Speaks our protocol major; incompatible peers render greyed out.
    compatible: bool,
    /// Where this peer is currently mounted as a drive, if it is.
    mounted: Option<String>,
}

async fn peer_rows(state: &AppState) -> Vec<PeerRow> {
    let trust = state.trust.lock().await;
    let peers = state.peers.lock().await;
    let mounts = state.mounts.lock().await;
    let mut rows: Vec<PeerRow> = peers
        .values()
        .map(|p| PeerRow {
            id: p.id.to_string(),
            name: p.name.clone(),
            addr: p.socket_addr().to_string(),
            // Peers advertise a short fingerprint over mDNS; the badge means "a
            // certificate with this prefix is pinned".
            trusted: trust.is_pinned_prefix(&p.fingerprint),
            compatible: p.is_compatible(),
            mounted: mounts.get(&p.id).map(|m| m.handle.mountpoint().to_string()),
        })
        .collect();
    rows.sort_by(|a, b| a.name.cmp(&b.name).then(a.id.cmp(&b.id)));
    rows
}

/// Where a peer's drive appears: a free drive letter on Windows (the first with
/// nothing behind it, scanning backwards from Z:), a folder under the
/// home directory elsewhere (FUSE mounts onto a directory, which `conduit-fs`
/// creates if it is missing).
fn mountpoint_for(home: Option<PathBuf>, peer: &str) -> Option<String> {
    #[cfg(windows)]
    {
        let _ = (home, peer);
        ('D'..='Z')
            .rev()
            .map(|c| format!("{c}:"))
            .find(|d| !std::path::Path::new(&format!("{d}\\")).exists())
    }
    #[cfg(not(windows))]
    {
        let safe: String = peer
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || matches!(c, '-' | '_' | ' ') {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let name = match safe.trim() {
            "" => "peer",
            name => name,
        };
        Some(
            home?
                .join("Conduit")
                .join(name)
                .to_string_lossy()
                .into_owned(),
        )
    }
}

/// Mount `peer_id`'s shared folder as a local drive. Returns the mount point.
#[tauri::command]
async fn mount_peer(
    app: AppHandle,
    state: State<'_, AppState>,
    peer_id: String,
) -> Result<String, String> {
    let id = DeviceId(peer_id.parse::<uuid::Uuid>().map_err(|_| "bad peer id")?);
    if let Some(existing) = state.mounts.lock().await.get(&id) {
        return Ok(existing.handle.mountpoint().to_string());
    }
    let peer = state
        .peers
        .lock()
        .await
        .get(&id)
        .cloned()
        .ok_or("that peer is no longer visible on the network")?;
    let mountpoint =
        mountpoint_for(app.path().home_dir().ok(), &peer.name).ok_or("no free mount point")?;

    let session = state
        .endpoint
        .connect_any(&peer.socket_addrs())
        .await
        .map_err(|e| e.to_string())?;
    let session = pair_with_ui(&app, session, "outgoing")
        .await
        .map_err(|e| e.to_string())?;
    let client = FsClient::start(session).map_err(|e| e.to_string())?;

    // Files written into the mount ship to the peer as ordinary transfers, with
    // progress in the UI like any other outgoing send.
    let on_write: conduit_fs::WriteHandler = {
        let app = app.clone();
        let peer_id = peer_id.clone();
        let rt = tokio::runtime::Handle::current();
        Arc::new(move |name, spool| {
            let app = app.clone();
            let peer_id = peer_id.clone();
            rt.spawn(async move {
                let state = app.state::<AppState>();
                let result: Result<(), String> = async {
                    let candidates = resolve_target(&state, &peer_id).await?;
                    let session = state
                        .endpoint
                        .connect_any(&candidates)
                        .await
                        .map_err(|e| e.to_string())?;
                    let session = pair_with_ui(&app, session, "outgoing")
                        .await
                        .map_err(|e| e.to_string())?;
                    let opts = state.settings.lock().await.send_options();
                    let events = forward_events(app.clone(), "outgoing", None);
                    conduit_core::send_path(session, &spool, opts, events)
                        .await
                        .map_err(|e| e.to_string())
                }
                .await;
                if let Err(e) = result {
                    emit_error(&app, format!("writing {name} to the peer failed: {e}"));
                }
                let _ = std::fs::remove_file(&spool);
                if let Some(parent) = spool.parent() {
                    let _ = std::fs::remove_dir(parent);
                }
            });
        })
    };

    let handle = conduit_fs::mount(
        client.clone(),
        tokio::runtime::Handle::current(),
        &mountpoint,
        conduit_fs::MountOptions {
            volume_label: peer.name.clone(),
        },
        on_write,
    )
    .map_err(|e| e.to_string())?;

    state
        .mounts
        .lock()
        .await
        .insert(id, ActiveMount { handle, client });
    let _ = app.emit("conduit://peers", peer_rows(&state).await);
    Ok(mountpoint)
}

/// Remove a peer's drive.
#[tauri::command]
async fn unmount_peer(
    app: AppHandle,
    state: State<'_, AppState>,
    peer_id: String,
) -> Result<(), String> {
    let id = DeviceId(peer_id.parse::<uuid::Uuid>().map_err(|_| "bad peer id")?);
    if let Some(mount) = state.mounts.lock().await.remove(&id) {
        // Unmount blocks on the host thread joining; keep the async runtime free.
        let _ = tokio::task::spawn_blocking(move || {
            mount.handle.unmount();
            mount.client.close();
        })
        .await;
    }
    let _ = app.emit("conduit://peers", peer_rows(&state).await);
    Ok(())
}

/// Snapshot for initial render; afterwards "conduit://peers" pushes updates.
#[tauri::command]
async fn peers_snapshot(state: State<'_, AppState>) -> Result<Vec<PeerRow>, String> {
    Ok(peer_rows(&state).await)
}

/// Resolve a UI target — a discovered peer's device id, or a typed ip:port for
/// networks where mDNS is blocked — into dial candidates, best-first.
async fn resolve_target(state: &AppState, target: &str) -> Result<Vec<SocketAddr>, String> {
    let target = target.trim();
    if let Ok(addr) = target.parse::<SocketAddr>() {
        return Ok(vec![addr]);
    }
    if let Ok(uuid) = target.parse::<uuid::Uuid>() {
        if let Some(peer) = state.peers.lock().await.get(&DeviceId(uuid)) {
            return Ok(peer.socket_addrs());
        }
        return Err("that peer is no longer visible on the network".into());
    }
    Err("expected a discovered peer or an ip:port address".into())
}

/// Android's file picker hands back a provider-owned `content://` URI, not a path.
/// The transfer engine re-opens its source by path (manifest, rehash-on-resume), so
/// spool the content into the app cache and send that — the same spool-then-ship
/// shape as the mount's write path.
#[cfg(target_os = "android")]
fn materialize_content_uri(app: &AppHandle, uri: &str) -> Result<String, String> {
    use std::os::fd::AsRawFd;
    use tauri_plugin_fs::{FilePath, FsExt, OpenOptions};

    let parsed: FilePath = uri
        .parse()
        .map_err(|e| format!("unusable picked file ({e})"))?;
    let mut opts = OpenOptions::new();
    opts.read(true);
    let mut src = app
        .fs()
        .open(parsed, opts)
        .map_err(|e| format!("could not open the picked file: {e}"))?;

    // The provider's fd usually points at the real file, whose basename is the
    // human-readable name; pipe-backed providers fall back to the URI tail.
    let name = std::fs::read_link(format!("/proc/self/fd/{}", src.as_raw_fd()))
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .unwrap_or_else(|| {
            uri.rsplit('/')
                .next()
                .filter(|t| !t.is_empty())
                .unwrap_or("picked-file")
                .to_string()
        });

    let dir = app
        .path()
        .app_cache_dir()
        .map_err(|e| e.to_string())?
        .join("outgoing");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let dest = dir.join(&name);
    let mut out = std::fs::File::create(&dest).map_err(|e| e.to_string())?;
    std::io::copy(&mut src, &mut out).map_err(|e| e.to_string())?;
    Ok(dest.to_string_lossy().into_owned())
}

/// Start sending `path` to `target` (peer id or address). Returns as soon as the job
/// is spawned; progress, errors, and completion arrive as events. On connection loss
/// the job redials and re-offers — the receiver's staged partial turns that into a
/// resume rather than a restart.
#[tauri::command]
async fn send_to_peer(
    app: AppHandle,
    state: State<'_, AppState>,
    target: String,
    path: String,
) -> Result<(), String> {
    // Validate the target once up front so a typo fails the command visibly.
    resolve_target(&state, &target).await?;

    // ponytail: the spool copy finishes before this command returns, so a huge pick
    // sits silent until staged; stream progress events if that ever matters.
    #[cfg(target_os = "android")]
    let path = if path.starts_with("content://") {
        let app = app.clone();
        tauri::async_runtime::spawn_blocking(move || materialize_content_uri(&app, &path))
            .await
            .map_err(|e| e.to_string())??
    } else {
        path
    };

    let active = Arc::clone(&state.active);
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let abort_slot = Arc::new(std::sync::OnceLock::new());
        let events = forward_events(app.clone(), "outgoing", Some(Arc::clone(&abort_slot)));

        let task = tokio::spawn({
            let app = app.clone();
            async move {
                let mut outcome: Result<(), String> = Err("never attempted".into());

                // Hash the source once, with UI feedback — a large folder takes real
                // time to manifest, and re-hashing it on every retry doubled the pain.
                let prep_name = Path::new(&path)
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| path.clone());
                let _ = app.emit(
                    "conduit://preparing",
                    serde_json::json!({ "name": prep_name, "done": false }),
                );
                let chunk_size = {
                    let state = app.state::<AppState>();
                    let s = state.settings.lock().await.send_options();
                    s.chunk_size
                };
                let manifest =
                    match conduit_core::manifest_for_path(Path::new(&path), chunk_size).await {
                        Ok(m) => Some(Arc::new(m)),
                        Err(e) => {
                            outcome = Err(format!("could not read {prep_name}: {e}"));
                            None
                        }
                    };
                let _ = app.emit(
                    "conduit://preparing",
                    serde_json::json!({ "name": prep_name, "done": true }),
                );

                // One transfer at a time per target (see AppState::send_queues).
                let queue = {
                    let state = app.state::<AppState>();
                    let mut queues = state.send_queues.lock().await;
                    Arc::clone(queues.entry(target.clone()).or_default())
                };
                let _turn = queue.lock().await;

                for attempt in 0..=SEND_RETRIES {
                    let Some(manifest) = manifest.as_ref() else { break };
                    if attempt > 0 {
                        tokio::time::sleep(SEND_RETRY_DELAY).await;
                    }
                    let state = app.state::<AppState>();
                    // Re-resolve each attempt: the peer's address may have changed
                    // when the link came back.
                    let candidates = match resolve_target(&state, &target).await {
                        Ok(a) => a,
                        Err(_) if attempt < SEND_RETRIES => continue,
                        Err(e) => {
                            outcome = Err(e);
                            break;
                        }
                    };
                    let opts = state.settings.lock().await.send_options();
                    let result = async {
                        let session = state.endpoint.connect_any(&candidates).await?;
                        let session = pair_with_ui(&app, session, "outgoing").await?;
                        conduit_core::send_manifest(
                            session,
                            Arc::clone(manifest),
                            Path::new(&path),
                            opts,
                            events.clone(),
                        )
                        .await
                    }
                    .await;

                    match result {
                        Ok(()) => {
                            outcome = Ok(());
                            break;
                        }
                        // The pairing verdict is final — never redial into a second
                        // prompt, and a rejected pairing is not history-worthy.
                        Err(conduit_core::Error::PairingRejected) => return,
                        Err(e @ conduit_core::Error::Connection(_)) => {
                            outcome = Err(e.to_string());
                            continue; // transient: redial and resume
                        }
                        Err(e) => {
                            outcome = Err(e.to_string());
                            break;
                        }
                    }
                }

                let source = Path::new(&path);
                let name = source
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| path.clone());
                let bytes = std::fs::metadata(source).map(|m| m.len()).unwrap_or(0);
                let peer_name = {
                    let state = app.state::<AppState>();
                    let peers = state.peers.lock().await;
                    target
                        .parse::<uuid::Uuid>()
                        .ok()
                        .and_then(|u| peers.get(&DeviceId(u)).map(|p| p.name.clone()))
                        .unwrap_or_else(|| target.clone())
                };
                match &outcome {
                    Ok(()) => notify(&app, "Transfer complete", &format!("Sent {name} to {peer_name}")).await,
                    Err(e) => {
                        emit_error(&app, format!("send failed: {e}"));
                        notify(&app, "Transfer failed", &format!("{name}: {e}")).await;
                    }
                }
                append_history(
                    &app,
                    HistoryEntry {
                        time_unix: now_unix(),
                        direction: "outgoing".into(),
                        name,
                        bytes,
                        peer: peer_name,
                        status: match &outcome {
                            Ok(()) => "done".into(),
                            Err(e) => format!("failed: {e}"),
                        },
                        path: Some(path.clone()),
                        target: Some(target.clone()),
                    },
                )
                .await;
            }
        });
        let _ = abort_slot.set(task.abort_handle());

        let _ = task.await;
        // Whatever id this job registered under, it is over now.
        active.lock().await.retain(|_, h| !h.is_finished());
    });
    Ok(())
}

/// Cancel a running transfer (either direction). The task is aborted, dropping the
/// QUIC connection; the receiving side keeps its staged partial, so re-sending the
/// same content later resumes instead of restarting.
#[tauri::command]
async fn cancel_transfer(state: State<'_, AppState>, transfer_id: String) -> Result<(), String> {
    let id: TransferId = transfer_id.parse().map_err(|_| "bad transfer id".to_string())?;
    if let Some(handle) = state.active.lock().await.remove(&id) {
        handle.abort();
    }
    Ok(())
}

/// The user clicked Confirm/Reject in the pairing dialog.
#[tauri::command]
async fn confirm_pairing(state: State<'_, AppState>, accept: bool) -> Result<(), String> {
    if let Some(tx) = state.pending_pairing.lock().await.take() {
        let _ = tx.send(accept);
    }
    Ok(())
}

#[derive(Debug, Serialize, Clone)]
struct PairingPrompt {
    code: String,
    peer_name: String,
    direction: &'static str,
}

#[derive(Debug, Serialize, Clone)]
struct TransferNotification {
    direction: &'static str,
    event: TransferEvent,
}

#[derive(Debug, Serialize, Clone)]
struct ErrorNotification {
    message: String,
}

fn emit_error(app: &AppHandle, message: String) {
    let _ = app.emit("conduit://error", ErrorNotification { message });
}

fn transfer_id_of(event: &TransferEvent) -> TransferId {
    match event {
        TransferEvent::Offered { transfer_id, .. }
        | TransferEvent::Started { transfer_id, .. }
        | TransferEvent::Resumed { transfer_id, .. }
        | TransferEvent::Progress { transfer_id, .. }
        | TransferEvent::ChunkResent { transfer_id, .. }
        | TransferEvent::EntrySkipped { transfer_id, .. }
        | TransferEvent::Verifying { transfer_id }
        | TransferEvent::Completed { transfer_id, .. }
        | TransferEvent::Failed { transfer_id, .. } => *transfer_id,
    }
}

/// Bridge a core event channel onto the Tauri event bus. When `abort_slot` is given,
/// the events also maintain the cancel registry: the transfer id (learned from the
/// first event) maps to the task's abort handle until the transfer ends.
fn forward_events(
    app: AppHandle,
    direction: &'static str,
    abort_slot: Option<Arc<std::sync::OnceLock<tokio::task::AbortHandle>>>,
) -> mpsc::Sender<TransferEvent> {
    let (tx, mut rx) = mpsc::channel::<TransferEvent>(256);
    tauri::async_runtime::spawn(async move {
        while let Some(event) = rx.recv().await {
            let tid = transfer_id_of(&event);
            let active = Arc::clone(&app.state::<AppState>().active);
            match &event {
                TransferEvent::Completed { .. } | TransferEvent::Failed { .. } => {
                    active.lock().await.remove(&tid);
                }
                _ => {
                    if let Some(handle) = abort_slot.as_ref().and_then(|s| s.get()) {
                        active.lock().await.entry(tid).or_insert_with(|| handle.clone());
                    }
                }
            }
            let _ = app.emit("conduit://transfer", TransferNotification { direction, event });
        }
    });
    tx
}

/// TOFU gate for both directions: trusted peers pass silently, unknown peers show the
/// 6-digit code and wait for the user, changed fingerprints are refused loudly.
async fn pair_with_ui(
    app: &AppHandle,
    session: PeerSession,
    direction: &'static str,
) -> conduit_core::Result<PeerSession> {
    let state = app.state::<AppState>();
    let status = {
        let trust = state.trust.lock().await;
        trust.status(&session.peer.fingerprint)
    };

    match status {
        TrustStatus::Trusted => Ok(session),
        TrustStatus::Unknown => {
            let code = session.pairing_code()?;
            let (tx, rx) = oneshot::channel();
            // Replacing an in-flight prompt implicitly rejects it — its sender drops.
            *state.pending_pairing.lock().await = Some(tx);
            let _ = app.emit(
                "conduit://pairing",
                PairingPrompt {
                    code,
                    peer_name: session.peer.name.clone(),
                    direction,
                },
            );

            let confirmed = matches!(
                tokio::time::timeout(std::time::Duration::from_secs(120), rx).await,
                Ok(Ok(true))
            );
            if confirmed {
                let mut trust = state.trust.lock().await;
                trust.pin(
                    &session.peer.fingerprint,
                    session.peer.device_id,
                    &session.peer.name,
                )?;
                Ok(session)
            } else {
                session.bye(ByeReason::PairingRejected).await;
                Err(conduit_core::Error::PairingRejected)
            }
        }
    }
}

/// Always-on listener: every inbound connection is paired (if new) and its single
/// transfer received into the inbox.
async fn accept_loop(app: AppHandle) {
    loop {
        let endpoint = Arc::clone(&app.state::<AppState>().endpoint);
        let accepted = endpoint.accept().await;
        match accepted {
            None => break, // endpoint closed — app shutting down
            Some(Err(e)) => emit_error(&app, format!("inbound connection failed: {e}")),
            Some(Ok(session)) => {
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    let inbox = inbox_dir(&app.state::<AppState>()).await;
                    let session = match pair_with_ui(&app, session, "incoming").await {
                        Ok(s) => s,
                        Err(conduit_core::Error::PairingRejected) => return,
                        Err(e) => {
                            emit_error(&app, e.to_string());
                            return;
                        }
                    };
                    let peer_name = session.peer.name.clone();
                    // Registered for cancellation like outgoing sends; an aborted
                    // receive keeps its staged partial for a later resume.
                    let abort_slot = Arc::new(std::sync::OnceLock::new());
                    let events =
                        forward_events(app.clone(), "incoming", Some(Arc::clone(&abort_slot)));
                    let task = tokio::spawn({
                        let app = app.clone();
                        async move {
                            // The inbox doubles as this device's shared folder: it
                            // receives transfers and backs peers' mounts of us.
                            match conduit_core::serve_session(
                                session,
                                ReceiveOptions {
                                    dest_dir: inbox.clone(),
                                },
                                inbox,
                                events,
                            )
                            .await
                            {
                                Ok(Served::Transfer(path)) => {
                                    let name = path
                                        .file_name()
                                        .map(|n| n.to_string_lossy().into_owned())
                                        .unwrap_or_else(|| path.display().to_string());
                                    let bytes =
                                        std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                                    notify(
                                        &app,
                                        "File received",
                                        &format!("{name} from {peer_name}"),
                                    )
                                    .await;
                                    append_history(
                                        &app,
                                        HistoryEntry {
                                            time_unix: now_unix(),
                                            direction: "incoming".into(),
                                            name,
                                            bytes,
                                            peer: peer_name,
                                            status: "done".into(),
                                            path: Some(path.display().to_string()),
                                            target: None,
                                        },
                                    )
                                    .await;
                                }
                                Ok(Served::FsSession) => {}
                                // Connection loss is routine (sender will redial and
                                // resume); anything else deserves a visible error on
                                // top of the transfer's own Failed event.
                                Err(conduit_core::Error::Connection(_)) => {}
                                Err(e) => {
                                    emit_error(&app, e.to_string());
                                    notify(
                                        &app,
                                        "Transfer failed",
                                        &format!("from {peer_name}: {e}"),
                                    )
                                    .await;
                                }
                            }
                        }
                    });
                    let _ = abort_slot.set(task.abort_handle());
                    let _ = task.await;
                });
            }
        }
    }
}

fn host_name() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "conduit-device".into())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init());
    // Only Android needs the fs plugin, and only from Rust (content:// spooling in
    // `send_to_peer`) — it is not exposed to the webview.
    #[cfg(target_os = "android")]
    let builder = builder.plugin(tauri_plugin_fs::init());
    builder
        .setup(|app| {
            let identity_dir = app.path().app_config_dir()?;
            let default_inbox = app
                .path()
                .download_dir()
                .map(|d| d.join("Conduit"))
                .unwrap_or_else(|_| identity_dir.join("inbox"));

            let settings_path = identity_dir.join("settings.json");
            let settings: Settings = std::fs::read(&settings_path)
                .ok()
                .and_then(|b| serde_json::from_slice(&b).ok())
                .unwrap_or_default();
            let history_path = identity_dir.join("history.json");
            let history: Vec<HistoryEntry> = std::fs::read(&history_path)
                .ok()
                .and_then(|b| serde_json::from_slice(&b).ok())
                .unwrap_or_default();

            let identity = Arc::new(DeviceIdentity::load_or_create(&identity_dir, &host_name())?);
            let trust = TrustStore::load(&identity_dir)?;
            // Bind on all interfaces: Phase 2 narrows this to the preferred
            // (Thunderbolt) interface reported by conduit-net. quinn needs a tokio
            // runtime context to register its socket, and the setup hook runs
            // outside one — enter Tauri's runtime for the bind.
            let endpoint = tauri::async_runtime::block_on(async {
                ConduitEndpoint::bind(
                    Arc::clone(&identity),
                    "0.0.0.0:0".parse().expect("static addr parses"),
                )
            })?;
            let endpoint = Arc::new(endpoint);
            let listen_addr = endpoint.local_addr()?;

            // Announce ourselves and browse for peers: nobody types an IP.
            let discovery = Discovery::start(&conduit_discovery::Announcement {
                device_id: identity.device_id,
                device_name: identity.device_name.clone(),
                port: listen_addr.port(),
                fingerprint: identity.fingerprint().short(),
            })?;
            let mut peer_events = discovery.subscribe(identity.device_id)?;

            app.manage(AppState {
                listen_addr,
                endpoint,
                trust: Arc::new(Mutex::new(trust)),
                pending_pairing: Arc::new(Mutex::new(None)),
                peers: Arc::new(Mutex::new(HashMap::new())),
                active: Arc::new(Mutex::new(HashMap::new())),
                mounts: Arc::new(Mutex::new(HashMap::new())),
                send_queues: Arc::new(Mutex::new(HashMap::new())),
                _discovery: discovery,
                transports: conduit_net::TransportManager::with_defaults(),
                link_override: Arc::new(Mutex::new(None)),
                settings: Arc::new(Mutex::new(settings)),
                settings_path,
                history: Arc::new(Mutex::new(history)),
                history_path,
                default_inbox,
                device_name: identity.device_name.clone(),
                fingerprint_short: identity.fingerprint().short(),
            });

            // Peer pump: fold Found/Lost into the map and push the whole list — a
            // full snapshot per change keeps the frontend trivially consistent.
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                while let Some(event) = peer_events.recv().await {
                    let state = handle.state::<AppState>();
                    {
                        let mut peers = state.peers.lock().await;
                        match event {
                            PeerEvent::Found(p) => {
                                peers.insert(p.id, p);
                            }
                            PeerEvent::Lost(id) => {
                                peers.remove(&id);
                            }
                        }
                    }
                    let rows = peer_rows(&state).await;
                    let _ = handle.emit("conduit://peers", rows);
                }
            });

            tauri::async_runtime::spawn(accept_loop(app.handle().clone()));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            app_info,
            node_status,
            link_status,
            set_link_override,
            peers_snapshot,
            send_to_peer,
            cancel_transfer,
            mount_peer,
            unmount_peer,
            confirm_pairing,
            get_settings,
            set_settings,
            history,
            trusted_peers,
            rename_trusted,
            revoke_trusted
        ])
        .run(tauri::generate_context!())
        .expect("error while running Conduit");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn app_info_reports_the_current_protocol() {
        let info = app_info().await.expect("link detection must not fail");
        assert_eq!(info.protocol_version, conduit_core::PROTOCOL_VERSION);
        assert!(info.service_type.contains("_conduit"));
    }

    #[tokio::test]
    async fn app_info_serializes_for_the_ui_bridge() {
        let json =
            serde_json::to_string(&app_info().await.unwrap()).expect("must serialize");
        assert!(json.contains("protocolVersion") || json.contains("protocol_version"));
    }

    #[test]
    #[cfg(not(windows))]
    fn mount_points_are_named_folders_under_home() {
        let home = Some(PathBuf::from("/home/u"));
        assert_eq!(
            mountpoint_for(home.clone(), "Shaun's Laptop").unwrap(),
            "/home/u/Conduit/Shaun_s Laptop",
            "path separators and quotes must not escape the Conduit folder"
        );
        assert_eq!(
            mountpoint_for(home.clone(), "../../etc").unwrap(),
            "/home/u/Conduit/______etc"
        );
        assert_eq!(
            mountpoint_for(home, "  ").unwrap(),
            "/home/u/Conduit/peer",
            "a blank name still needs somewhere to mount"
        );
        assert!(mountpoint_for(None, "any").is_none());
    }
}
