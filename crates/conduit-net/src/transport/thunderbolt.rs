//! Thunderbolt / USB4 host-to-host networking, refactored from the Phase-2
//! detection. TB3, TB4 and USB4 all land here — they share the same host-to-host
//! mode; only the speed tier differs.
//!
//! Linux additionally surfaces peers that are plugged in but **not authorized**
//! (`/sys/bus/thunderbolt/devices/*/authorized == 0`): those have no netdev yet, so
//! they appear as unusable links flagged `needs_authorization` for the UI to prompt
//! (`boltctl authorize` / the desktop's Bolt dialog).

use super::probe;
use super::{Link, SpeedTier, Transport, TransportKind};

pub struct ThunderboltTransport;

#[async_trait::async_trait]
impl Transport for ThunderboltTransport {
    fn kind(&self) -> TransportKind {
        TransportKind::Thunderbolt
    }

    fn display_name(&self) -> &'static str {
        "Thunderbolt / USB4"
    }

    fn base_priority(&self) -> u8 {
        100
    }

    async fn detect(&self) -> anyhow::Result<Vec<Link>> {
        #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
        let mut links: Vec<Link> = probe::interfaces()?
            .into_iter()
            .filter(|i| i.is_thunderbolt)
            .map(|i| Link {
                transport: TransportKind::Thunderbolt,
                bind_addr: i.addrs[0],
                speed_tier: SpeedTier::from_mbps(i.speed_mbps, SpeedTier::Gbps10),
                direct: true,
                needs_authorization: false,
                requires_special_hw: false,
                iface_name: i.name,
            })
            .collect();

        #[cfg(target_os = "linux")]
        for (_node, name) in crate::sysfs_unauthorized_devices(std::path::Path::new("/sys")) {
            links.push(Link {
                transport: TransportKind::Thunderbolt,
                iface_name: name,
                bind_addr: std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                speed_tier: SpeedTier::Gbps10,
                direct: true,
                needs_authorization: true,
                requires_special_hw: false,
            });
        }

        Ok(links)
    }
}
