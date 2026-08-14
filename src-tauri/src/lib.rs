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

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::{mpsc, oneshot, Mutex};

use conduit_core::{
    ByeReason, ConduitEndpoint, DeviceId, DeviceIdentity, PeerSession, ReceiveOptions,
    SendOptions, TransferEvent, TransferId, TrustStatus, TrustStore,
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
    /// The pluggable link layer (`docs/Transports.md`).
    transports: conduit_net::TransportManager,
    /// User-pinned interface name; `None` = auto-select the fastest link.
    link_override: Arc<Mutex<Option<String>>>,
    listen_addr: SocketAddr,
    inbox: PathBuf,
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
fn node_status(state: State<'_, AppState>) -> NodeStatus {
    NodeStatus {
        device_name: state.device_name.clone(),
        listen_addr: state.listen_addr.to_string(),
        inbox: state.inbox.display().to_string(),
        fingerprint: state.fingerprint_short.clone(),
    }
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
}

async fn peer_rows(state: &AppState) -> Vec<PeerRow> {
    let trust = state.trust.lock().await;
    let peers = state.peers.lock().await;
    let mut rows: Vec<PeerRow> = peers
        .values()
        .map(|p| PeerRow {
            id: p.id.to_string(),
            name: p.name.clone(),
            addr: p.socket_addr().to_string(),
            trusted: trust.peers().any(|(id, _)| *id == p.id),
            compatible: p.is_compatible(),
        })
        .collect();
    rows.sort_by(|a, b| a.name.cmp(&b.name).then(a.id.cmp(&b.id)));
    rows
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

    let active = Arc::clone(&state.active);
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let abort_slot = Arc::new(std::sync::OnceLock::new());
        let events = forward_events(app.clone(), "outgoing", Some(Arc::clone(&abort_slot)));

        let task = tokio::spawn({
            let app = app.clone();
            async move {
                let mut last_err: Option<String> = None;
                for attempt in 0..=SEND_RETRIES {
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
                            last_err = Some(e);
                            break;
                        }
                    };
                    let result = async {
                        let session = state.endpoint.connect_any(&candidates).await?;
                        let session = pair_with_ui(&app, session, "outgoing").await?;
                        conduit_core::send_path(
                            session,
                            Path::new(&path),
                            SendOptions::default(),
                            events.clone(),
                        )
                        .await
                    }
                    .await;

                    match result {
                        Ok(()) => return,
                        // The pairing verdict is final — never redial into a second prompt.
                        Err(conduit_core::Error::PairingRejected) => return,
                        Err(e @ conduit_core::Error::Connection(_)) => {
                            last_err = Some(e.to_string());
                            continue; // transient: redial and resume
                        }
                        Err(e) => {
                            last_err = Some(e.to_string());
                            break;
                        }
                    }
                }
                if let Some(e) = last_err {
                    emit_error(&app, format!("send failed: {e}"));
                }
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
        trust.status(session.peer.device_id, &session.peer.fingerprint)
    };

    match status {
        TrustStatus::Trusted => Ok(session),
        TrustStatus::Mismatch { pinned } => {
            let presented = session.peer.fingerprint.hex();
            session
                .bye(ByeReason::Other("fingerprint mismatch".into()))
                .await;
            Err(conduit_core::Error::FingerprintMismatch { pinned, presented })
        }
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
                    session.peer.device_id,
                    &session.peer.name,
                    &session.peer.fingerprint,
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
                    let inbox = app.state::<AppState>().inbox.clone();
                    let session = match pair_with_ui(&app, session, "incoming").await {
                        Ok(s) => s,
                        Err(conduit_core::Error::PairingRejected) => return,
                        Err(e) => {
                            emit_error(&app, e.to_string());
                            return;
                        }
                    };
                    // Registered for cancellation like outgoing sends; an aborted
                    // receive keeps its staged partial for a later resume.
                    let abort_slot = Arc::new(std::sync::OnceLock::new());
                    let events =
                        forward_events(app.clone(), "incoming", Some(Arc::clone(&abort_slot)));
                    let task = tokio::spawn({
                        let app = app.clone();
                        async move {
                            if let Err(e) = conduit_core::receive_one(
                                session,
                                ReceiveOptions { dest_dir: inbox },
                                events,
                            )
                            .await
                            {
                                // Connection loss is routine (sender will redial and
                                // resume); anything else deserves a visible error on
                                // top of the transfer's own Failed event.
                                if !matches!(e, conduit_core::Error::Connection(_)) {
                                    emit_error(&app, e.to_string());
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

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let identity_dir = app.path().app_config_dir()?;
            let inbox = app
                .path()
                .download_dir()
                .map(|d| d.join("Conduit"))
                .unwrap_or_else(|_| identity_dir.join("inbox"));

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
                _discovery: discovery,
                transports: conduit_net::TransportManager::with_defaults(),
                link_override: Arc::new(Mutex::new(None)),
                inbox,
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
            confirm_pairing
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
}
