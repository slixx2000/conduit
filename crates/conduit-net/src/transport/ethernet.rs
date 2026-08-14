//! Wired Ethernet — both a shared LAN and, more interestingly, a **direct
//! laptop-to-laptop cable**. Modern NICs auto-negotiate (no crossover cable
//! needed), and with no DHCP server on a direct cable both ends fall back to
//! automatic link-local addressing (IPv4 169.254/16, IPv6 fe80::/10) — which is
//! exactly how a direct link is recognized: carrier up, **no default gateway, only
//! link-local addresses**. No static IP setup, ever.
//!
//! The Thunderbolt netdev and USB CDC gadgets are excluded here: those interfaces
//! are owned by their own transports (one transport owns each interface).

use super::probe::{self, KindHint};
use super::{Link, SpeedTier, Transport, TransportKind};

pub struct EthernetTransport;

#[async_trait::async_trait]
impl Transport for EthernetTransport {
    fn kind(&self) -> TransportKind {
        TransportKind::Ethernet
    }

    fn display_name(&self) -> &'static str {
        "Ethernet"
    }

    fn base_priority(&self) -> u8 {
        60
    }

    async fn detect(&self) -> anyhow::Result<Vec<Link>> {
        Ok(probe::interfaces()?
            .into_iter()
            .filter(|i| {
                i.hint == KindHint::Wired && !i.is_thunderbolt && !i.is_usb_cdc
            })
            .map(|i| Link {
                transport: TransportKind::Ethernet,
                bind_addr: i.addrs[0],
                speed_tier: SpeedTier::from_mbps(i.speed_mbps, SpeedTier::Gbps1),
                direct: probe::is_direct(i.has_gateway, &i.addrs),
                needs_authorization: false,
                requires_special_hw: false,
                iface_name: i.name,
            })
            .collect())
    }
}
