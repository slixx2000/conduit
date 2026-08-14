//! Wire vocabulary shared by both peers.
//!
//! `docs/PROTOCOL.md` is normative: any change to the shapes here must be made in the
//! same commit as the corresponding edit to that document, and any wire-incompatible
//! change must bump [`PROTOCOL_VERSION`].
//!
//! Note the message *encoding* (`postcard` vs CBOR) is still an open decision recorded
//! in `docs/ARCHITECTURE.md` §8 — it is deliberately not resolved in Phase 0, so these
//! types derive serde without committing to a format.

use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Bumped on any wire-incompatible change. Majors must match or the session aborts.
pub const PROTOCOL_VERSION: u16 = 1;

/// Stable per-device identity. Generated once, persisted locally, advertised over mDNS
/// as the `id` TXT key, and used to key pinned certificate fingerprints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeviceId(pub Uuid);

impl DeviceId {
    /// Mint a new identity. Called once per install; persist the result.
    pub fn new_random() -> Self {
        Self(Uuid::new_v4())
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Negotiated feature bits exchanged in [`Hello`]. Unknown bits are ignored, so a newer
/// peer advertising capabilities we do not understand still interoperates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Capabilities(pub u32);

impl Capabilities {
    pub const NONE: Self = Self(0);
    /// Peer can resume an interrupted transfer from a received-chunk bitmap.
    pub const RESUME: Self = Self(1 << 0);
    /// Peer can expose its shared area as a virtual mounted volume (Phase 4).
    pub const MOUNT: Self = Self(1 << 1);
    /// Peer accepts compressed chunk payloads.
    pub const COMPRESSION: Self = Self(1 << 2);

    pub fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Capabilities usable in a session — only those both peers advertise.
    pub fn intersect(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }
}

/// Exchanged on the control stream at the start of every session, in both directions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    pub version: u16,
    pub device_id: DeviceId,
    pub device_name: String,
    pub capabilities: Capabilities,
}

impl Hello {
    /// Build this device's `Hello` for the current protocol version.
    pub fn new(device_id: DeviceId, device_name: impl Into<String>, capabilities: Capabilities) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            device_id,
            device_name: device_name.into(),
            capabilities,
        }
    }

    /// Peers interoperate when their protocol majors match. Returns the error the
    /// session should abort with otherwise.
    pub fn check_compatible(&self) -> crate::Result<()> {
        if self.version == PROTOCOL_VERSION {
            Ok(())
        } else {
            Err(crate::Error::VersionMismatch {
                local: PROTOCOL_VERSION,
                peer: self.version,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_ids_are_unique() {
        assert_ne!(DeviceId::new_random(), DeviceId::new_random());
    }

    #[test]
    fn hello_accepts_matching_version_and_rejects_mismatch() {
        let id = DeviceId::new_random();
        let ours = Hello::new(id, "Test", Capabilities::RESUME);
        assert!(ours.check_compatible().is_ok());

        let theirs = Hello {
            version: PROTOCOL_VERSION + 1,
            ..ours.clone()
        };
        assert!(matches!(
            theirs.check_compatible(),
            Err(crate::Error::VersionMismatch { .. })
        ));
    }

    #[test]
    fn capabilities_intersect_to_what_both_peers_support() {
        let ours = Capabilities::RESUME.union(Capabilities::MOUNT);
        let theirs = Capabilities::RESUME.union(Capabilities::COMPRESSION);
        let session = ours.intersect(theirs);

        assert!(session.contains(Capabilities::RESUME));
        assert!(!session.contains(Capabilities::MOUNT));
        assert!(!session.contains(Capabilities::COMPRESSION));
    }

    #[test]
    fn unknown_capability_bits_do_not_break_matching() {
        let future_peer = Capabilities(0xFFFF_FFFF);
        assert!(future_peer.contains(Capabilities::RESUME));
        assert_eq!(
            future_peer.intersect(Capabilities::RESUME),
            Capabilities::RESUME
        );
    }
}
