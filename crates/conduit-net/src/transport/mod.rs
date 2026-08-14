//! The pluggable link layer (`docs/Transports.md`).
//!
//! A transport's only job is to *detect* zero or more currently-usable IP links and
//! describe them; the data path is always QUIC over IP, so anything that yields an IP
//! interface works with the rest of the app unchanged. The [`TransportManager`]
//! aggregates every registered transport's links and ranks them best-first:
//! `(direct, speed_tier, base_priority)` descending — a direct cable beats a shared
//! LAN at equal speed, faster beats slower, and `base_priority` breaks ties
//! (Thunderbolt > Bridge > Ethernet > WiFi).

use std::net::IpAddr;

pub mod bridge;
pub mod ethernet;
mod probe;
pub mod thunderbolt;
pub mod wifi;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TransportKind {
    Thunderbolt,
    Ethernet,
    Wifi,
    Bridge,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum SpeedTier {
    SubGig,
    Gbps1,
    Gbps5,
    Gbps10,
    Gbps20,
    Gbps40Plus,
}

impl SpeedTier {
    /// UI-facing label, e.g. "~10 Gbps".
    pub fn label(self) -> &'static str {
        match self {
            SpeedTier::SubGig => "<1 Gbps",
            SpeedTier::Gbps1 => "~1 Gbps",
            SpeedTier::Gbps5 => "~5 Gbps",
            SpeedTier::Gbps10 => "~10 Gbps",
            SpeedTier::Gbps20 => "~20 Gbps",
            SpeedTier::Gbps40Plus => "40+ Gbps",
        }
    }

    /// Map a raw link speed in Mbit/s onto a tier; `default` covers unknown speeds.
    pub fn from_mbps(mbps: Option<u64>, default: SpeedTier) -> SpeedTier {
        match mbps {
            None | Some(0) => default,
            Some(m) if m < 1_000 => SpeedTier::SubGig,
            Some(m) if m < 5_000 => SpeedTier::Gbps1,
            Some(m) if m < 10_000 => SpeedTier::Gbps5,
            Some(m) if m < 20_000 => SpeedTier::Gbps10,
            Some(m) if m < 40_000 => SpeedTier::Gbps20,
            Some(_) => SpeedTier::Gbps40Plus,
        }
    }
}

/// One concrete, currently-usable link on this machine.
#[derive(Clone, Debug)]
pub struct Link {
    pub transport: TransportKind,
    /// e.g. "thunderbolt0", "enp0s31f6", "Ethernet 2".
    pub iface_name: String,
    /// Preferred local address (link-local is fine — expected on a direct cable).
    pub bind_addr: IpAddr,
    pub speed_tier: SpeedTier,
    /// Point-to-point cable rather than a shared network. Preferred for discovery.
    pub direct: bool,
    /// e.g. a Thunderbolt device is present but the OS has not approved it: the
    /// link cannot carry traffic until the user acts.
    pub needs_authorization: bool,
    /// e.g. a USB bridge cable — works, but only with that hardware in the middle.
    pub requires_special_hw: bool,
}

impl Link {
    /// Whether transfers can be carried right now.
    pub fn is_usable(&self) -> bool {
        !self.needs_authorization
    }

    /// UI-facing one-liner, e.g. "Thunderbolt / USB4 · ~20 Gbps · direct cable".
    pub fn label(&self) -> String {
        let kind = match self.transport {
            TransportKind::Thunderbolt => "Thunderbolt / USB4",
            TransportKind::Ethernet => {
                if self.direct {
                    "Direct Ethernet"
                } else {
                    "Ethernet"
                }
            }
            TransportKind::Wifi => "Wi-Fi",
            TransportKind::Bridge => {
                if self.direct {
                    "USB bridge cable"
                } else {
                    // A CDC/RNDIS device with a gateway is a routed tether
                    // (e.g. phone internet sharing), not a laptop-to-laptop cable.
                    "USB network device"
                }
            }
        };
        let scope = if self.direct {
            "direct cable"
        } else {
            "shared network"
        };
        format!("{kind} · {} · {scope}", self.speed_tier.label())
    }
}

#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    fn kind(&self) -> TransportKind;
    /// For the UI.
    fn display_name(&self) -> &'static str;
    /// Tie-breaker; higher = preferred.
    fn base_priority(&self) -> u8;
    async fn detect(&self) -> anyhow::Result<Vec<Link>>;
}

/// Owns all registered transports; aggregates, ranks, and picks the active link.
pub struct TransportManager {
    transports: Vec<Box<dyn Transport>>,
}

impl TransportManager {
    /// The default roster: Thunderbolt, Ethernet, WiFi, USB bridge cables.
    pub fn with_defaults() -> Self {
        Self {
            transports: vec![
                Box::new(thunderbolt::ThunderboltTransport),
                Box::new(bridge::BridgeCableTransport),
                Box::new(ethernet::EthernetTransport),
                Box::new(wifi::WifiTransport),
            ],
        }
    }

    pub fn transports(&self) -> &[Box<dyn Transport>] {
        &self.transports
    }

    /// Detect across all transports and return links sorted best-first. A transport
    /// that fails to probe is logged and skipped — one bad probe must never blind
    /// the whole app.
    pub async fn available(&self) -> Vec<Link> {
        let mut links = Vec::new();
        for transport in &self.transports {
            match transport.detect().await {
                Ok(found) => links.extend(found),
                Err(e) => {
                    tracing::warn!("{} detection failed: {e}", transport.display_name())
                }
            }
        }
        self.rank(&mut links);
        links
    }

    /// The link the app will use unless the user overrides it: the best *usable*
    /// candidate (an unauthorized Thunderbolt link never wins — it cannot carry
    /// traffic — but it stays in `available()` so the UI can prompt).
    pub async fn preferred(&self) -> Option<Link> {
        self.available()
            .await
            .into_iter()
            .find(|l| l.is_usable())
    }

    fn rank(&self, links: &mut [Link]) {
        let priority = |kind: TransportKind| {
            self.transports
                .iter()
                .find(|t| t.kind() == kind)
                .map(|t| t.base_priority())
                .unwrap_or(0)
        };
        links.sort_by_key(|l| {
            std::cmp::Reverse((l.direct, l.speed_tier, priority(l.transport)))
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn link(transport: TransportKind, tier: SpeedTier, direct: bool) -> Link {
        Link {
            transport,
            iface_name: format!("{transport:?}"),
            bind_addr: IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1)),
            speed_tier: tier,
            direct,
            needs_authorization: false,
            requires_special_hw: false,
        }
    }

    fn manager() -> TransportManager {
        TransportManager::with_defaults()
    }

    #[test]
    fn ranking_prefers_direct_then_speed_then_priority() {
        let mgr = manager();
        let mut links = vec![
            link(TransportKind::Wifi, SpeedTier::Gbps1, false),
            link(TransportKind::Ethernet, SpeedTier::Gbps1, true),
            link(TransportKind::Thunderbolt, SpeedTier::Gbps20, true),
            link(TransportKind::Ethernet, SpeedTier::Gbps10, false),
        ];
        mgr.rank(&mut links);
        let order: Vec<TransportKind> = links.iter().map(|l| l.transport).collect();
        assert_eq!(
            order,
            vec![
                TransportKind::Thunderbolt, // direct + fastest
                TransportKind::Ethernet,    // direct beats the faster shared LAN
                TransportKind::Ethernet,    // shared 10G
                TransportKind::Wifi,
            ]
        );
    }

    #[test]
    fn equal_links_fall_back_to_base_priority() {
        let mgr = manager();
        let mut links = vec![
            link(TransportKind::Ethernet, SpeedTier::Gbps10, true),
            link(TransportKind::Bridge, SpeedTier::Gbps10, true),
            link(TransportKind::Thunderbolt, SpeedTier::Gbps10, true),
        ];
        mgr.rank(&mut links);
        let order: Vec<TransportKind> = links.iter().map(|l| l.transport).collect();
        assert_eq!(
            order,
            vec![
                TransportKind::Thunderbolt,
                TransportKind::Bridge,
                TransportKind::Ethernet,
            ]
        );
    }

    #[tokio::test]
    async fn preferred_skips_links_needing_authorization() {
        let mgr = manager();
        let mut links = vec![
            {
                let mut l = link(TransportKind::Thunderbolt, SpeedTier::Gbps40Plus, true);
                l.needs_authorization = true;
                l
            },
            link(TransportKind::Wifi, SpeedTier::SubGig, false),
        ];
        mgr.rank(&mut links);
        // The unauthorized link ranks first in the list...
        assert!(links[0].needs_authorization);
        // ...but can never be the active choice.
        let usable = links.iter().find(|l| l.is_usable()).unwrap();
        assert_eq!(usable.transport, TransportKind::Wifi);
    }

    #[test]
    fn speed_tiers_map_from_raw_mbps() {
        assert_eq!(SpeedTier::from_mbps(Some(100), SpeedTier::Gbps1), SpeedTier::SubGig);
        assert_eq!(SpeedTier::from_mbps(Some(1_000), SpeedTier::SubGig), SpeedTier::Gbps1);
        assert_eq!(SpeedTier::from_mbps(Some(2_500), SpeedTier::SubGig), SpeedTier::Gbps1);
        assert_eq!(SpeedTier::from_mbps(Some(10_000), SpeedTier::SubGig), SpeedTier::Gbps10);
        assert_eq!(SpeedTier::from_mbps(Some(40_000), SpeedTier::SubGig), SpeedTier::Gbps40Plus);
        assert_eq!(SpeedTier::from_mbps(None, SpeedTier::Gbps5), SpeedTier::Gbps5);
        assert_eq!(SpeedTier::from_mbps(Some(0), SpeedTier::Gbps1), SpeedTier::Gbps1);
    }

    #[test]
    fn labels_read_like_the_ui_spec() {
        assert_eq!(
            link(TransportKind::Thunderbolt, SpeedTier::Gbps10, true).label(),
            "Thunderbolt / USB4 · ~10 Gbps · direct cable"
        );
        assert_eq!(
            link(TransportKind::Wifi, SpeedTier::SubGig, false).label(),
            "Wi-Fi · <1 Gbps · shared network"
        );
        assert_eq!(
            link(TransportKind::Ethernet, SpeedTier::Gbps1, true).label(),
            "Direct Ethernet · ~1 Gbps · direct cable"
        );
        assert_eq!(
            link(TransportKind::Bridge, SpeedTier::Gbps5, true).label(),
            "USB bridge cable · ~5 Gbps · direct cable"
        );
        assert_eq!(
            link(TransportKind::Bridge, SpeedTier::SubGig, false).label(),
            "USB network device · <1 Gbps · shared network",
            "a routed USB tether is not presented as a bridge cable"
        );
    }
}
