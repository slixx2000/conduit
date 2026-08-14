//! WiFi — the universal fallback. Never `direct`, lowest priority; exists so the
//! app is never unusable: two laptops on the same wireless network still discover
//! each other and transfer, just not at cable speed.

use super::probe::{self, KindHint};
use super::{Link, SpeedTier, Transport, TransportKind};

pub struct WifiTransport;

#[async_trait::async_trait]
impl Transport for WifiTransport {
    fn kind(&self) -> TransportKind {
        TransportKind::Wifi
    }

    fn display_name(&self) -> &'static str {
        "Wi-Fi"
    }

    fn base_priority(&self) -> u8 {
        10
    }

    async fn detect(&self) -> anyhow::Result<Vec<Link>> {
        Ok(probe::interfaces()?
            .into_iter()
            .filter(|i| i.hint == KindHint::Wireless)
            .map(|i| Link {
                transport: TransportKind::Wifi,
                bind_addr: i.addrs[0],
                speed_tier: SpeedTier::from_mbps(i.speed_mbps, SpeedTier::SubGig),
                direct: false,
                needs_authorization: false,
                requires_special_hw: false,
                iface_name: i.name,
            })
            .collect())
    }
}
