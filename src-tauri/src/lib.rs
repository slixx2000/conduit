//! Tauri glue.
//!
//! Everything here is a thin wrapper over the `conduit-*` crates: commands marshal
//! arguments, call into the core, and turn typed errors into strings the UI can show.
//! Business logic belongs in the crates, not here — that is what keeps the core
//! testable headless.
//!
//! Phase 1 surface: the app binds a QUIC endpoint on startup and always listens.
//! Inbound transfers land in `Downloads/Conduit`. The UI can dial a peer by address
//! (discovery replaces typing an address in Phase 3), both directions run the TOFU
//! pairing-code flow, and live progress streams to the frontend as events:
//!   "conduit://pairing"   { code, peer_name, direction }
//!   "conduit://transfer"  { direction, event: TransferEvent }
//!   "conduit://error"     { message }

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::{mpsc, oneshot, Mutex};

use conduit_core::{
    ByeReason, ConduitEndpoint, DeviceIdentity, PeerSession, ReceiveOptions, SendOptions,
    TransferEvent, TrustStatus, TrustStore,
};

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
fn app_info() -> Result<AppInfo, String> {
    let links = conduit_net::detect_links().map_err(|e| e.to_string())?;
    let preferred_link = conduit_net::select_preferred(&links)
        .map(|l| format!("{} ({:?})", l.interface, l.kind));

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

/// Live link report for the UI: which interface the data path prefers, and any
/// Thunderbolt peer stuck waiting for OS authorization. Computed fresh per call —
/// the UI polls it so plugging/unplugging the cable mid-session is reflected.
#[derive(Debug, Serialize)]
struct LinkStatus {
    /// e.g. "thunderbolt0 — 169.254.10.5" or None when the OS routes (loopback/LAN).
    preferred: Option<String>,
    /// Device names awaiting authorization; non-empty means the UI should tell the
    /// user to approve the connection instead of silently using WiFi.
    unauthorized: Vec<String>,
}

#[tauri::command]
fn link_status() -> Result<LinkStatus, String> {
    let links = conduit_net::detect_links().map_err(|e| e.to_string())?;
    Ok(LinkStatus {
        preferred: conduit_net::select_preferred(&links)
            .map(|l| format!("{} — {}", l.interface, l.addr)),
        unauthorized: links
            .iter()
            .filter(|l| l.kind.needs_user_action())
            .map(|l| l.interface.clone())
            .collect(),
    })
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

/// Dial `addr`, pair if needed, and send `path`. Progress arrives as events; the
/// returned future resolves when the receiver acknowledged (or with the error).
#[tauri::command]
async fn send_to_peer(
    app: AppHandle,
    state: State<'_, AppState>,
    addr: String,
    path: String,
) -> Result<(), String> {
    let addr: SocketAddr = addr
        .trim()
        .parse()
        .map_err(|_| "invalid peer address — expected ip:port, e.g. 192.168.1.20:4433".to_string())?;

    let session = state.endpoint.connect(addr).await.map_err(|e| e.to_string())?;
    let session = pair_with_ui(&app, session, "outgoing")
        .await
        .map_err(|e| e.to_string())?;

    let events = forward_events(app.clone(), "outgoing");
    conduit_core::send_file(session, Path::new(&path), SendOptions::default(), events)
        .await
        .map_err(|e| e.to_string())
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

/// Bridge a core event channel onto the Tauri event bus.
fn forward_events(app: AppHandle, direction: &'static str) -> mpsc::Sender<TransferEvent> {
    let (tx, mut rx) = mpsc::channel::<TransferEvent>(256);
    tauri::async_runtime::spawn(async move {
        while let Some(event) = rx.recv().await {
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
                    let events = forward_events(app.clone(), "incoming");
                    if let Err(e) =
                        conduit_core::receive_one(session, ReceiveOptions { dest_dir: inbox }, events)
                            .await
                    {
                        // The transfer's Failed event already carries the details;
                        // this catches pre-transfer failures too.
                        emit_error(&app, e.to_string());
                    }
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

            app.manage(AppState {
                listen_addr: endpoint.local_addr()?,
                endpoint,
                trust: Arc::new(Mutex::new(trust)),
                pending_pairing: Arc::new(Mutex::new(None)),
                inbox,
                device_name: identity.device_name.clone(),
                fingerprint_short: identity.fingerprint().short(),
            });

            tauri::async_runtime::spawn(accept_loop(app.handle().clone()));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            app_info,
            node_status,
            link_status,
            send_to_peer,
            confirm_pairing
        ])
        .run(tauri::generate_context!())
        .expect("error while running Conduit");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_info_reports_the_current_protocol() {
        let info = app_info().expect("link detection must not fail");
        assert_eq!(info.protocol_version, conduit_core::PROTOCOL_VERSION);
        assert!(info.service_type.contains("_conduit"));
    }

    #[test]
    fn app_info_serializes_for_the_ui_bridge() {
        let json = serde_json::to_string(&app_info().unwrap()).expect("must serialize");
        assert!(json.contains("protocolVersion") || json.contains("protocol_version"));
    }
}
