//! Zero-config peer discovery over mDNS/DNS-SD.
//!
//! Advertises this device as `_conduit._tcp` and browses for peers, so a user never
//! types an IP address. `mdns-sd` handles interface enumeration and re-announcement;
//! address ranking (prefer the cable's link over WiFi) reuses
//! [`conduit_net::best_address`], so a Thunderbolt address advertised by the peer
//! outranks its LAN one automatically.
//!
//! Lifecycle: [`Discovery::start`] registers the advertisement and returns a handle;
//! [`Discovery::subscribe`] yields a stream of [`PeerEvent`]s (own advertisement
//! filtered out). Dropping the handle unregisters the service and shuts the daemon
//! down, which is what makes peers disappear from the far end's list when the app
//! closes or the cable is pulled.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use conduit_core::DeviceId;
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use uuid::Uuid;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("mDNS error: {0}")]
    Mdns(String),
}

impl From<mdns_sd::Error> for Error {
    fn from(e: mdns_sd::Error) -> Self {
        Error::Mdns(e.to_string())
    }
}

/// DNS-SD service type. Must match `docs/PROTOCOL.md` §1.
pub const SERVICE_TYPE: &str = "_conduit._tcp.local.";

/// TXT record keys advertised alongside the service.
pub mod txt_keys {
    /// Protocol major version.
    pub const VERSION: &str = "v";
    /// Stable device UUID.
    pub const DEVICE_ID: &str = "id";
    /// Human-friendly device name.
    pub const NAME: &str = "name";
    /// QUIC/control port.
    pub const PORT: &str = "port";
    /// Short fingerprint of the device's long-term certificate, for reconnection trust.
    pub const FINGERPRINT: &str = "fp";
}

/// A peer seen on the link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    pub id: DeviceId,
    pub name: String,
    /// Every address the peer advertises, best-first (per
    /// [`conduit_net::best_address`] ranking: dialable IPv4 — APIPA included —
    /// before IPv6). Connect logic should try them in order: a peer on a direct
    /// cable plus WiFi advertises several, and not all are reachable from here.
    pub addrs: Vec<IpAddr>,
    pub port: u16,
    /// Short certificate fingerprint; matched against the pinned value for trusted
    /// devices so a known peer reconnects without showing a pairing code again.
    pub fingerprint: String,
    /// Protocol major the peer advertises.
    pub version: u16,
}

impl Peer {
    /// The most promising single address (first of `addrs`).
    pub fn best_addr(&self) -> IpAddr {
        self.addrs[0]
    }

    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.best_addr(), self.port)
    }

    /// All dial candidates, best-first.
    pub fn socket_addrs(&self) -> Vec<SocketAddr> {
        self.addrs
            .iter()
            .map(|a| SocketAddr::new(*a, self.port))
            .collect()
    }

    /// Whether this peer speaks a protocol major we can talk to. Incompatible peers are
    /// still listed in the UI, but greyed out with an explanation rather than hidden —
    /// a peer that silently fails to appear is the harder bug to report.
    pub fn is_compatible(&self) -> bool {
        self.version == conduit_core::PROTOCOL_VERSION
    }
}

/// Emitted upward to the app as the peer set changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerEvent {
    Found(Peer),
    Lost(DeviceId),
}

/// What this device advertises about itself.
#[derive(Debug, Clone)]
pub struct Announcement {
    pub device_id: DeviceId,
    pub device_name: String,
    /// The QUIC port the endpoint is listening on.
    pub port: u16,
    /// Short fingerprint (`Fingerprint::short()`).
    pub fingerprint: String,
}

/// A running advertisement + browser. Drop to withdraw the advertisement.
pub struct Discovery {
    daemon: ServiceDaemon,
    fullname: String,
}

impl Discovery {
    /// Register this device's advertisement on all usable interfaces (mdns-sd tracks
    /// interface changes, so plugging in the cable re-announces there automatically).
    pub fn start(announcement: &Announcement) -> Result<Self> {
        let daemon = ServiceDaemon::new()?;
        // The QUIC endpoint binds an IPv4 socket, so IPv6 addresses (typically
        // link-local, which also need a zone index to dial) are not usable dial
        // targets. Scope mDNS to IPv4 until the transport goes dual-stack.
        daemon.disable_interface(mdns_sd::IfKind::IPv6)?;

        let instance = format!("conduit-{}", announcement.device_id);
        let host = format!("conduit-{}.local.", announcement.device_id);
        let properties = [
            (txt_keys::VERSION, conduit_core::PROTOCOL_VERSION.to_string()),
            (txt_keys::DEVICE_ID, announcement.device_id.to_string()),
            (txt_keys::NAME, announcement.device_name.clone()),
            (txt_keys::PORT, announcement.port.to_string()),
            (txt_keys::FINGERPRINT, announcement.fingerprint.clone()),
        ];
        let service = ServiceInfo::new(
            SERVICE_TYPE,
            &instance,
            &host,
            (), // no fixed address: enable_addr_auto tracks the interfaces
            announcement.port,
            &properties[..],
        )?
        .enable_addr_auto();
        let fullname = service.get_fullname().to_string();
        daemon.register(service)?;

        Ok(Self { daemon, fullname })
    }

    /// Browse for peers. Events arrive on the returned channel until the `Discovery`
    /// handle is dropped. `own_id` filters out this device's own advertisement.
    pub fn subscribe(&self, own_id: DeviceId) -> Result<tokio::sync::mpsc::Receiver<PeerEvent>> {
        let browser = self.daemon.browse(SERVICE_TYPE)?;
        let (tx, rx) = tokio::sync::mpsc::channel(64);

        // Bridge mdns-sd's flume channel onto tokio from a plain thread: the daemon
        // is callback/thread based and this crate must not require a runtime.
        std::thread::spawn(move || {
            // fullname → device id, so ServiceRemoved (which carries no TXT) can be
            // translated into a Lost event.
            let mut known: HashMap<String, DeviceId> = HashMap::new();
            while let Ok(event) = browser.recv() {
                match event {
                    ServiceEvent::ServiceResolved(info) => {
                        let Some(peer) = peer_from_service(&info) else {
                            tracing::debug!(
                                "ignoring unparseable advertisement {}",
                                info.get_fullname()
                            );
                            continue;
                        };
                        if peer.id == own_id {
                            continue;
                        }
                        known.insert(info.get_fullname().to_string(), peer.id);
                        if tx.blocking_send(PeerEvent::Found(peer)).is_err() {
                            break;
                        }
                    }
                    ServiceEvent::ServiceRemoved(_ty, fullname) => {
                        if let Some(id) = known.remove(&fullname) {
                            if tx.blocking_send(PeerEvent::Lost(id)).is_err() {
                                break;
                            }
                        }
                    }
                    ServiceEvent::SearchStopped(_) => break,
                    _ => {}
                }
            }
        });
        Ok(rx)
    }
}

impl Drop for Discovery {
    fn drop(&mut self) {
        // Best-effort goodbye packets so peers drop us promptly instead of waiting
        // for the TTL to lapse.
        let _ = self.daemon.unregister(&self.fullname);
        let _ = self.daemon.shutdown();
    }
}

fn peer_from_service(info: &ServiceInfo) -> Option<Peer> {
    let txt = |key: &str| info.get_property_val_str(key).map(str::to_string);

    let id = DeviceId(Uuid::from_str(&txt(txt_keys::DEVICE_ID)?).ok()?);
    let version = txt(txt_keys::VERSION)?.parse().ok()?;
    let name = txt(txt_keys::NAME)?;
    let fingerprint = txt(txt_keys::FINGERPRINT).unwrap_or_default();

    // The advertised addresses span every interface the peer answers on; rank them
    // the same way we rank our own (cable-friendly v4 first) and drop loopback.
    // Stable sort: equal-rank candidates (e.g. two global v4s) keep their record
    // order — any of them is an acceptable first dial.
    let mut addrs: Vec<IpAddr> = info.get_addresses().iter().copied().collect();
    addrs.retain(|a| conduit_net::address_rank(a) > 0);
    addrs.sort_by_key(|a| std::cmp::Reverse(conduit_net::address_rank(a)));
    if addrs.is_empty() {
        return None;
    }
    // Prefer the explicit TXT port (survives SRV rewriting by helpful resolvers).
    let port = txt(txt_keys::PORT)
        .and_then(|p| p.parse().ok())
        .unwrap_or_else(|| info.get_port());

    Some(Peer {
        id,
        name,
        addrs,
        port,
        fingerprint,
        version,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    fn peer(version: u16) -> Peer {
        Peer {
            id: DeviceId::new_random(),
            name: "Test Device".into(),
            addrs: vec![
                IpAddr::V4(Ipv4Addr::new(169, 254, 0, 2)),
                "fe80::1".parse().unwrap(),
            ],
            port: 7420,
            fingerprint: "ab:cd".into(),
            version,
        }
    }

    #[test]
    fn service_type_matches_the_protocol_doc() {
        assert!(SERVICE_TYPE.starts_with("_conduit._tcp"));
    }

    #[test]
    fn peers_on_the_current_protocol_are_compatible() {
        assert!(peer(conduit_core::PROTOCOL_VERSION).is_compatible());
        assert!(!peer(conduit_core::PROTOCOL_VERSION + 1).is_compatible());
    }

    #[test]
    fn socket_addr_combines_advertised_address_and_port() {
        let p = peer(conduit_core::PROTOCOL_VERSION);
        assert_eq!(p.socket_addr().to_string(), "169.254.0.2:7420");
        assert_eq!(p.socket_addrs().len(), 2, "all candidates stay dialable");
    }

    /// Two daemons on one machine must find each other over loopback multicast.
    /// Environment-dependent (firewalls can eat multicast), so generous timeouts.
    #[tokio::test(flavor = "multi_thread")]
    async fn two_instances_discover_each_other() {
        let a_id = DeviceId::new_random();
        let b_id = DeviceId::new_random();
        let a = Discovery::start(&Announcement {
            device_id: a_id,
            device_name: "Peer A".into(),
            port: 40001,
            fingerprint: "aaaaaaaa".into(),
        })
        .unwrap();
        let b = Discovery::start(&Announcement {
            device_id: b_id,
            device_name: "Peer B".into(),
            port: 40002,
            fingerprint: "bbbbbbbb".into(),
        })
        .unwrap();

        let mut a_events = a.subscribe(a_id).unwrap();
        let found = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                match a_events.recv().await {
                    Some(PeerEvent::Found(p)) if p.id == b_id => break p,
                    Some(_) => continue,
                    None => panic!("event stream ended before finding Peer B"),
                }
            }
        })
        .await
        .expect("Peer B must be discovered within the timeout");

        assert_eq!(found.name, "Peer B");
        assert_eq!(found.port, 40002);
        assert_eq!(found.fingerprint, "bbbbbbbb");
        assert!(found.is_compatible());

        // Dropping B must surface as Lost on A's stream.
        drop(b);
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                match a_events.recv().await {
                    Some(PeerEvent::Lost(id)) if id == b_id => break,
                    Some(_) => continue,
                    None => panic!("event stream ended before losing Peer B"),
                }
            }
        })
        .await
        .expect("Peer B's departure must be noticed within the timeout");
    }
}
