//! Zero-config peer discovery over mDNS/DNS-SD.
//!
//! Advertises this device as `_conduit._tcp` and browses for peers, so a user never
//! types an IP address. Advertisement is scoped to the preferred interface (from
//! `conduit-net`) where possible, so plugging in a cable surfaces that peer first and
//! we avoid broadcasting across every network the machine is attached to.
//!
//! Phase 0 provides the service definition and event vocabulary. The `mdns-sd` wiring
//! lands in Phase 3 — see `docs/ROADMAP.md`.

use std::net::{IpAddr, SocketAddr};

use conduit_core::DeviceId;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("mDNS error: {0}")]
    Mdns(String),

    #[error("{what} is not implemented yet (planned for {phase})")]
    NotImplemented {
        what: &'static str,
        phase: &'static str,
    },
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
    pub addr: IpAddr,
    pub port: u16,
    /// Short certificate fingerprint; matched against the pinned value for trusted
    /// devices so a known peer reconnects without showing a pairing code again.
    pub fingerprint: String,
    /// Protocol major the peer advertises.
    pub version: u16,
}

impl Peer {
    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.addr, self.port)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn peer(version: u16) -> Peer {
        Peer {
            id: DeviceId::new_random(),
            name: "Test Device".into(),
            addr: IpAddr::V4(Ipv4Addr::new(169, 254, 0, 2)),
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
    }
}
