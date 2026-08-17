//! Shared interface probing for the transport implementations.
//!
//! Each platform enumerates its interfaces once into a common [`RawIface`] shape;
//! the individual transports then filter and claim what belongs to them (one
//! transport owns each interface — see `docs/Transports.md` §5). All classification
//! logic is pure functions over that shape so it unit-tests on every platform.

use std::net::IpAddr;

/// Rough class of an interface, before a transport claims it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KindHint {
    Wired,
    Wireless,
    /// Loopback, tunnels, and anything else that can never carry the data path.
    Excluded,
    /// Only the Windows and macOS classifiers produce this; sysfs always decides.
    #[cfg_attr(target_os = "linux", allow(dead_code))]
    Unknown,
}

/// Platform-neutral description of one up, addressable interface.
#[derive(Clone, Debug)]
pub struct RawIface {
    pub name: String,
    /// Windows: adapter description; Linux: kernel driver name; macOS: empty.
    pub description: String,
    /// Non-loopback addresses, ranked dial-preference-first.
    pub addrs: Vec<IpAddr>,
    pub hint: KindHint,
    /// Whether the interface has a default gateway (route to elsewhere).
    pub has_gateway: bool,
    /// Raw link speed in Mbit/s when the OS reports one.
    pub speed_mbps: Option<u64>,
    /// Claimed by the Thunderbolt transport.
    pub is_thunderbolt: bool,
    /// Looks like a USB CDC network gadget (bridge cable / RNDIS).
    pub is_usb_cdc: bool,
}

/// A direct (point-to-point cable) link: nowhere to route to (no gateway) and only
/// link-local addressing — exactly what two laptops and a cable produce with no DHCP.
pub fn is_direct(has_gateway: bool, addrs: &[IpAddr]) -> bool {
    !has_gateway
        && !addrs.is_empty()
        && addrs.iter().all(|a| match a {
            IpAddr::V4(v4) => v4.is_link_local(),
            IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
        })
}

/// USB CDC network gadget drivers/descriptions — how a laptop-to-laptop bridge cable
/// (CDC-NCM / CDC-ECM / RNDIS) shows up. USB *ethernet dongles* use vendor drivers
/// (asix, r8152, …) and are deliberately not matched: they are real Ethernet.
pub fn is_usb_cdc_network(driver_or_description: &str) -> bool {
    let d = driver_or_description.to_ascii_lowercase();
    ["cdc_ncm", "cdc_ether", "cdc_eem", "cdc_subset", "rndis", "plusb"]
        .iter()
        .any(|p| d.contains(p))
        || d.contains("usb ethernet")
        || d.contains("remote ndis")
        || d.contains("cdc-ncm")
        || d.contains("cdc-ecm")
}

/// Linux `/proc/net/route`: which interfaces carry a default route. Each line is
/// `Iface Destination Gateway ...` in kernel hex; a default route has destination
/// `00000000` and a non-zero gateway.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn ifaces_with_default_route(route_table: &str) -> std::collections::HashSet<String> {
    route_table
        .lines()
        .skip(1)
        .filter_map(|line| {
            let mut cols = line.split_whitespace();
            let iface = cols.next()?;
            let dest = cols.next()?;
            let gateway = cols.next()?;
            (dest == "00000000" && gateway != "00000000").then(|| iface.to_string())
        })
        .collect()
}

/// Enumerate this machine's interfaces. Loopback-only and downed interfaces are
/// excluded; everything else is returned for the transports to claim.
pub fn interfaces() -> anyhow::Result<Vec<RawIface>> {
    let ifaces = platform_interfaces()?;
    for i in &ifaces {
        tracing::debug!(
            "iface {} ({}) {:?} addrs={:?} gw={} speed={:?} tb={} cdc={}",
            i.name,
            i.description,
            i.hint,
            i.addrs,
            i.has_gateway,
            i.speed_mbps,
            i.is_thunderbolt,
            i.is_usb_cdc,
        );
    }
    Ok(ifaces)
}

#[cfg(windows)]
fn platform_interfaces() -> anyhow::Result<Vec<RawIface>> {
    let adapters = ipconfig::get_adapters().map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut out = Vec::new();
    for adapter in adapters {
        if adapter.oper_status() != ipconfig::OperStatus::IfOperStatusUp {
            continue;
        }
        use ipconfig::IfType;
        let hint = match adapter.if_type() {
            IfType::EthernetCsmacd => KindHint::Wired,
            IfType::Ieee80211 => KindHint::Wireless,
            IfType::SoftwareLoopback | IfType::Tunnel => KindHint::Excluded,
            _ => KindHint::Unknown,
        };
        // Hypervisor/VPN virtual adapters carry addresses but are never the fast
        // path to a cable peer.
        let description = adapter.description().to_string();
        let lower = description.to_ascii_lowercase();
        if ["hyper-v virtual", "vmware virtual", "virtualbox", "tap-windows"]
            .iter()
            .any(|v| lower.contains(v))
        {
            continue;
        }

        let mut addrs: Vec<IpAddr> = adapter.ip_addresses().to_vec();
        addrs.retain(|a| crate::address_rank(a) > 0);
        addrs.sort_by_key(|a| std::cmp::Reverse(crate::address_rank(a)));
        if addrs.is_empty() {
            continue;
        }

        let speed_bps = adapter.transmit_link_speed();
        out.push(RawIface {
            name: adapter.friendly_name().to_string(),
            is_thunderbolt: crate::description_is_thunderbolt(&description)
                || crate::description_is_thunderbolt(adapter.friendly_name()),
            is_usb_cdc: is_usb_cdc_network(&description),
            addrs,
            hint,
            has_gateway: !adapter.gateways().is_empty(),
            speed_mbps: (speed_bps > 0).then_some(speed_bps / 1_000_000),
            description,
        });
    }
    Ok(out)
}

#[cfg(target_os = "linux")]
fn platform_interfaces() -> anyhow::Result<Vec<RawIface>> {
    use std::path::Path;

    let sysfs = Path::new("/sys");
    let default_routes = std::fs::read_to_string("/proc/net/route")
        .map(|t| ifaces_with_default_route(&t))
        .unwrap_or_default();

    // Group addresses by interface first.
    let mut by_iface: std::collections::BTreeMap<String, Vec<IpAddr>> = Default::default();
    for iface in if_addrs::get_if_addrs()? {
        if iface.is_loopback() {
            continue;
        }
        by_iface.entry(iface.name.clone()).or_default().push(iface.ip());
    }

    let mut out = Vec::new();
    for (name, mut addrs) in by_iface {
        addrs.retain(|a| crate::address_rank(a) > 0);
        addrs.sort_by_key(|a| std::cmp::Reverse(crate::address_rank(a)));
        if addrs.is_empty() {
            continue;
        }

        let class = sysfs.join("class/net").join(&name);
        let read = |file: &str| std::fs::read_to_string(class.join(file)).ok();
        let hint = if class.join("wireless").exists() || class.join("phy80211").exists() {
            KindHint::Wireless
        } else if !crate::sysfs_is_physical_netdev(sysfs, &name) {
            KindHint::Excluded // veth/bridge/bond: virtual, never the data path
        } else if read("type").map(|t| t.trim() == "1").unwrap_or(false) {
            KindHint::Wired
        } else {
            KindHint::Excluded // tunnels, ppp, etc.
        };
        // Interfaces without carrier can hold stale addresses; skip them.
        if read("carrier").map(|c| c.trim() != "1").unwrap_or(false) {
            continue;
        }
        let driver = class
            .join("device/driver")
            .read_link()
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
            .unwrap_or_default();

        out.push(RawIface {
            is_thunderbolt: crate::sysfs_is_thunderbolt_netdev(sysfs, &name),
            is_usb_cdc: is_usb_cdc_network(&driver),
            has_gateway: default_routes.contains(&name),
            speed_mbps: read("speed").and_then(|s| s.trim().parse::<i64>().ok()).and_then(
                |s| u64::try_from(s).ok(), // -1 means "unknown"
            ),
            description: driver,
            addrs,
            hint,
            name,
        });
    }
    Ok(out)
}

#[cfg(all(unix, not(target_os = "linux")))]
fn platform_interfaces() -> anyhow::Result<Vec<RawIface>> {
    // macOS: if-addrs gives names + addresses; wired vs wireless needs
    // SystemConfiguration, which is future work. `en*` is treated as wired (the
    // Ethernet transport claims it), `bridge*` as Thunderbolt, and Apple's
    // point-to-point helpers (awdl/llw/utun) are excluded.
    let mut by_iface: std::collections::BTreeMap<String, Vec<IpAddr>> = Default::default();
    for iface in if_addrs::get_if_addrs()? {
        if iface.is_loopback() {
            continue;
        }
        by_iface.entry(iface.name.clone()).or_default().push(iface.ip());
    }
    let mut out = Vec::new();
    for (name, mut addrs) in by_iface {
        addrs.retain(|a| crate::address_rank(a) > 0);
        addrs.sort_by_key(|a| std::cmp::Reverse(crate::address_rank(a)));
        if addrs.is_empty() {
            continue;
        }
        let hint = if name.starts_with("awdl")
            || name.starts_with("llw")
            || name.starts_with("utun")
            || name.starts_with("gif")
            || name.starts_with("stf")
        {
            KindHint::Excluded
        } else if name.starts_with("en") || name.starts_with("bridge") {
            KindHint::Wired
        } else {
            KindHint::Unknown
        };
        out.push(RawIface {
            is_thunderbolt: name.starts_with("bridge"),
            is_usb_cdc: false,
            has_gateway: false, // unknown without SC; direct-ness relies on link-local addrs
            speed_mbps: None,
            description: String::new(),
            addrs,
            hint,
            name,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_means_no_gateway_and_link_local_only() {
        let apipa: IpAddr = "169.254.10.5".parse().unwrap();
        let fe80: IpAddr = "fe80::1".parse().unwrap();
        let lan: IpAddr = "192.168.1.20".parse().unwrap();

        assert!(is_direct(false, &[apipa]));
        assert!(is_direct(false, &[fe80]));
        assert!(is_direct(false, &[apipa, fe80]));
        assert!(!is_direct(true, &[apipa]), "a gateway means a routed network");
        assert!(!is_direct(false, &[lan]), "a routable address means a LAN");
        assert!(!is_direct(false, &[apipa, lan]));
        assert!(!is_direct(false, &[]), "no addresses at all is not a link");
    }

    #[test]
    fn cdc_gadgets_match_but_ethernet_dongles_do_not() {
        for cdc in [
            "cdc_ncm",
            "cdc_ether",
            "rndis_host",
            "plusb",
            "USB Ethernet (CDC-NCM) Device",
            "Remote NDIS Compatible Device",
        ] {
            assert!(is_usb_cdc_network(cdc), "{cdc}");
        }
        for not_cdc in [
            "asix",
            "r8152",
            "Realtek Gaming 2.5GbE Family Controller",
            "Intel(R) Ethernet Connection I219-LM",
        ] {
            assert!(!is_usb_cdc_network(not_cdc), "{not_cdc}");
        }
    }

    #[test]
    fn default_routes_parse_from_proc_net_route() {
        let table = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n\
                     eth0\t00000000\t0100A8C0\t0003\t0\t0\t100\t00000000\n\
                     eth0\t0000A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\n\
                     tb0\t0000FEA9\t00000000\t0001\t0\t0\t0\t0000FFFF\n";
        let routes = ifaces_with_default_route(table);
        assert!(routes.contains("eth0"), "eth0 has a default route");
        assert!(!routes.contains("tb0"), "tb0 only has a link route");
    }

    #[test]
    fn probing_this_machine_does_not_fail() {
        // Environment-dependent contents; the invariant is "no error, no loopback".
        let ifaces = interfaces().expect("probe must not fail");
        assert!(ifaces.iter().all(|i| !i.addrs.is_empty()));
    }
}
