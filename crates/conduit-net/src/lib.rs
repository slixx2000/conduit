//! Link selection: identify the Thunderbolt/USB4 interface so the data path binds to
//! the fastest available link, and fall back to any usable interface otherwise.
//!
//! This crate exists so that `conduit-core` never learns what Thunderbolt is. The core
//! is handed a [`PreferredLink`] and transfers over whatever it names — which is why
//! the whole stack is testable over loopback and LAN with no special hardware.
//!
//! Phase 0 provides the types and the fallback path only. Real detection (Linux
//! `/sys/bus/thunderbolt` + netdev match, macOS system config APIs, Windows IP Helper)
//! lands in Phase 2 — see `docs/ROADMAP.md`.

use std::net::IpAddr;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io error while probing interfaces: {0}")]
    Io(#[from] std::io::Error),

    #[error("{what} is not implemented yet (planned for {phase})")]
    NotImplemented {
        what: &'static str,
        phase: &'static str,
    },
}

/// How a candidate link is expected to perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LinkKind {
    /// Ordinary LAN/WiFi. Always usable; the graceful-degradation path.
    Fallback,
    /// A Thunderbolt/USB4 peer is present but the OS has not authorized it yet, so no
    /// netdev exists. The UI must prompt the user to approve the connection rather
    /// than silently using WiFi.
    ThunderboltUnauthorized,
    /// An authorized Thunderbolt/USB4 link with a live network interface.
    Thunderbolt,
}

impl LinkKind {
    /// Whether transfers can actually be bound to this link right now.
    pub fn is_usable(self) -> bool {
        matches!(self, LinkKind::Fallback | LinkKind::Thunderbolt)
    }

    /// Whether the user must take an action (authorize the device) to unlock the link.
    pub fn needs_user_action(self) -> bool {
        matches!(self, LinkKind::ThunderboltUnauthorized)
    }
}

/// A candidate local address to bind transfers and mDNS advertisement to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreferredLink {
    pub kind: LinkKind,
    /// OS interface name, e.g. `thunderbolt0` / `bridge0` / a Windows adapter name.
    pub interface: String,
    pub addr: IpAddr,
}

/// Pick the best link from a candidate set: highest-ranked *usable* kind wins.
///
/// An unauthorized Thunderbolt link never wins — it cannot carry traffic — but callers
/// should still surface it so the UI can prompt for authorization while transfers
/// proceed over the fallback.
pub fn select_preferred(candidates: &[PreferredLink]) -> Option<&PreferredLink> {
    candidates
        .iter()
        .filter(|c| c.kind.is_usable())
        .max_by_key(|c| c.kind)
}

/// Enumerate candidate links on this machine.
///
/// Phase 2 implements the per-platform probes. Until then this reports nothing, and
/// callers fall back to letting the OS route (bind to unspecified address), which is
/// exactly the LAN/localhost path Phase 1 is proven over.
pub fn detect_links() -> Result<Vec<PreferredLink>> {
    tracing::debug!("interface detection is a Phase 2 feature; using OS routing");
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn link(kind: LinkKind, name: &str) -> PreferredLink {
        PreferredLink {
            kind,
            interface: name.into(),
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
        }
    }

    #[test]
    fn thunderbolt_outranks_lan() {
        let candidates = vec![
            link(LinkKind::Fallback, "eth0"),
            link(LinkKind::Thunderbolt, "thunderbolt0"),
        ];
        let chosen = select_preferred(&candidates).expect("a usable link");
        assert_eq!(chosen.interface, "thunderbolt0");
    }

    #[test]
    fn unauthorized_thunderbolt_never_wins_over_a_usable_link() {
        let candidates = vec![
            link(LinkKind::ThunderboltUnauthorized, "thunderbolt0"),
            link(LinkKind::Fallback, "eth0"),
        ];
        let chosen = select_preferred(&candidates).expect("a usable link");
        assert_eq!(chosen.interface, "eth0");
    }

    #[test]
    fn unauthorized_thunderbolt_alone_yields_nothing_usable_but_flags_user_action() {
        let candidates = vec![link(LinkKind::ThunderboltUnauthorized, "thunderbolt0")];
        assert!(select_preferred(&candidates).is_none());
        assert!(candidates[0].kind.needs_user_action());
    }

    #[test]
    fn no_candidates_is_not_an_error() {
        assert!(select_preferred(&[]).is_none());
        assert!(detect_links().expect("probe must not fail").is_empty());
    }
}
