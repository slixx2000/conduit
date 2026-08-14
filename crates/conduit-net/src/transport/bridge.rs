//! USB laptop-to-laptop **bridge cables** that enumerate as a USB network device
//! (CDC-NCM / CDC-ECM / RNDIS). From Conduit's point of view these are identical to
//! direct Ethernet — the OS exposes a network interface with link-local addressing
//! and the whole IP data path just works. They matter for USB3-only machine pairs
//! with no Thunderbolt.
//!
//! Out of scope (documented future work): proprietary bridge chips that expose a
//! raw pipe instead of a network device — those would need a `PipeTransport` that
//! frames a byte stream instead of QUIC-over-UDP. Prefer CDC-NCM cables.

use super::probe;
use super::{Link, SpeedTier, Transport, TransportKind};

pub struct BridgeCableTransport;

#[async_trait::async_trait]
impl Transport for BridgeCableTransport {
    fn kind(&self) -> TransportKind {
        TransportKind::Bridge
    }

    fn display_name(&self) -> &'static str {
        "USB bridge cable"
    }

    fn base_priority(&self) -> u8 {
        80
    }

    async fn detect(&self) -> anyhow::Result<Vec<Link>> {
        Ok(probe::interfaces()?
            .into_iter()
            .filter(|i| i.is_usb_cdc && !i.is_thunderbolt)
            .map(|i| Link {
                transport: TransportKind::Bridge,
                bind_addr: i.addrs[0],
                speed_tier: SpeedTier::from_mbps(i.speed_mbps, SpeedTier::Gbps5),
                // Same rule as Ethernet: a real host-to-host bridge cable has no
                // gateway and link-local addressing. A USB device with a gateway is
                // a routed tether (e.g. phone internet sharing) — usable, but a
                // shared network, not a direct cable.
                direct: probe::is_direct(i.has_gateway, &i.addrs),
                needs_authorization: false,
                requires_special_hw: true,
                iface_name: i.name,
            })
            .collect())
    }
}
