//! Link selection: identify the Thunderbolt/USB4 interface so the data path can use
//! the fastest available link, and fall back to any usable interface otherwise.
//!
//! This crate exists so that `conduit-core` never learns what Thunderbolt is. The core
//! is handed a [`PreferredLink`] and transfers over whatever it names — which is why
//! the whole stack is testable over loopback and LAN with no special hardware.
//!
//! Per-platform detection:
//! - **Linux**: a netdev is Thunderbolt when its sysfs device node lives on the
//!   `thunderbolt` bus (`/sys/class/net/<if>/device/subsystem` → `.../bus/thunderbolt`).
//!   Devices on that bus with `authorized == 0` are surfaced as
//!   [`LinkKind::ThunderboltUnauthorized`] so the app can tell the user to approve the
//!   connection (`boltctl authorize` or the desktop's Bolt prompt).
//! - **Windows**: adapters are classified by description/friendly name — Intel's
//!   driver advertises "Thunderbolt(TM) Networking", Windows 11's native stack says
//!   "USB4". Authorization prompts are owned by the OS/vendor software, so an
//!   unauthorized peer is invisible here (no adapter appears until approved).
//! - **macOS**: the Thunderbolt Bridge appears as `bridgeN`; membership is taken as
//!   Thunderbolt. macOS auto-authorizes cable peers, so there is no unauthorized
//!   state to detect.
//!
//! The sysfs walkers are compiled (and unit-tested with fixture trees) on every
//! platform; only [`detect_links`] wires them to the real filesystem, and only on
//! Linux.

use std::net::IpAddr;
use std::path::Path;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io error while probing interfaces: {0}")]
    Io(#[from] std::io::Error),
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
    /// For [`LinkKind::ThunderboltUnauthorized`] this is the Thunderbolt device name
    /// (there is no netdev yet).
    pub interface: String,
    /// Best address on the interface. Unspecified (`0.0.0.0`) for unauthorized links.
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

/// Enumerate candidate links on this machine. Loopback is never a candidate; an empty
/// result means "let the OS route" (bind unspecified), which is the LAN/localhost path.
pub fn detect_links() -> Result<Vec<PreferredLink>> {
    platform::detect()
}

/// Whether an adapter description / friendly name identifies a Thunderbolt or USB4
/// networking adapter. The strings to match come from real drivers: Intel's
/// "Thunderbolt(TM) Networking", Apple's "Thunderbolt Bridge", Windows 11's
/// "USB4 Host Router"-style names.
pub fn description_is_thunderbolt(description: &str) -> bool {
    let d = description.to_ascii_lowercase();
    d.contains("thunderbolt") || d.contains("usb4")
}

/// Rank an interface's addresses and return the one peers should dial.
///
/// IPv4 beats IPv6 because it needs no scope-id to type or advertise; a link-local
/// 169.254.x.x is *expected* on a direct cable with no DHCP, so it is not filtered.
/// Globally-routable v4 still outranks it for ordinary LAN adapters.
pub fn best_address(addrs: &[IpAddr]) -> Option<IpAddr> {
    let score = |a: &IpAddr| match a {
        IpAddr::V4(v4) if v4.is_loopback() => 0,
        IpAddr::V4(v4) if v4.is_link_local() => 2,
        IpAddr::V4(_) => 3,
        IpAddr::V6(v6) if v6.is_loopback() => 0,
        IpAddr::V6(_) => 1,
    };
    addrs
        .iter()
        .max_by_key(|a| score(a))
        .filter(|a| score(a) > 0)
        .copied()
}

// ---------------------------------------------------------------------------
// Linux sysfs walkers — pure path logic, compiled and tested on every platform.
// ---------------------------------------------------------------------------

/// Whether `/sys/class/net/<interface>` (under `sysfs_root`) is a Thunderbolt netdev:
/// its device's subsystem symlink resolves to the `thunderbolt` bus.
pub fn sysfs_is_thunderbolt_netdev(sysfs_root: &Path, interface: &str) -> bool {
    let subsystem = sysfs_root
        .join("class/net")
        .join(interface)
        .join("device/subsystem");
    match std::fs::read_link(&subsystem) {
        Ok(target) => target
            .file_name()
            .is_some_and(|n| n == "thunderbolt"),
        Err(_) => false,
    }
}

/// Thunderbolt devices that are present but not authorized (`authorized == 0`).
/// Returns `(device_node_name, human_name)` pairs; `human_name` falls back to the
/// node name when the device exposes none.
pub fn sysfs_unauthorized_devices(sysfs_root: &Path) -> Vec<(String, String)> {
    let devices_dir = sysfs_root.join("bus/thunderbolt/devices");
    let Ok(entries) = std::fs::read_dir(&devices_dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let node = entry.file_name().to_string_lossy().into_owned();
        let authorized = entry.path().join("authorized");
        let Ok(contents) = std::fs::read_to_string(&authorized) else {
            continue; // host controllers and retimers have no `authorized` file
        };
        if contents.trim() == "0" {
            let name = std::fs::read_to_string(entry.path().join("device_name"))
                .map(|s| s.trim().to_string())
                .ok()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| node.clone());
            out.push((node, name));
        }
    }
    out.sort();
    out
}

// ---------------------------------------------------------------------------
// Platform probes
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod platform {
    use super::*;

    pub fn detect() -> Result<Vec<PreferredLink>> {
        let adapters = ipconfig::get_adapters()
            .map_err(|e| Error::Io(std::io::Error::other(e.to_string())))?;

        let mut links = Vec::new();
        for adapter in adapters {
            if adapter.oper_status() != ipconfig::OperStatus::IfOperStatusUp {
                continue;
            }
            use ipconfig::IfType;
            // Loopback and tunnels can never be the transfer path. Thunderbolt/USB4
            // networking presents as an ethernet-class adapter.
            if matches!(
                adapter.if_type(),
                IfType::SoftwareLoopback | IfType::Tunnel
            ) {
                continue;
            }
            // Hypervisor/VPN virtual adapters carry addresses but are never the
            // fast path to a cable peer; they'd otherwise pollute selection.
            let desc = adapter.description().to_ascii_lowercase();
            if ["hyper-v virtual", "vmware virtual", "virtualbox", "tap-windows"]
                .iter()
                .any(|v| desc.contains(v))
            {
                continue;
            }
            let Some(addr) = best_address(adapter.ip_addresses()) else {
                continue;
            };
            let kind = if description_is_thunderbolt(adapter.description())
                || description_is_thunderbolt(adapter.friendly_name())
            {
                LinkKind::Thunderbolt
            } else {
                LinkKind::Fallback
            };
            links.push(PreferredLink {
                kind,
                interface: adapter.friendly_name().to_string(),
                addr,
            });
        }
        Ok(links)
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::*;
    use std::net::Ipv4Addr;
    use std::path::PathBuf;

    pub fn detect() -> Result<Vec<PreferredLink>> {
        let sysfs = PathBuf::from("/sys");
        let mut links = Vec::new();

        // Group addresses by interface, then classify each interface via sysfs.
        let mut by_iface: std::collections::BTreeMap<String, Vec<IpAddr>> = Default::default();
        for iface in if_addrs::get_if_addrs()? {
            if iface.is_loopback() {
                continue;
            }
            by_iface.entry(iface.name.clone()).or_default().push(iface.ip());
        }
        for (name, addrs) in by_iface {
            let Some(addr) = best_address(&addrs) else { continue };
            let kind = if sysfs_is_thunderbolt_netdev(&sysfs, &name) {
                LinkKind::Thunderbolt
            } else {
                LinkKind::Fallback
            };
            links.push(PreferredLink { kind, interface: name, addr });
        }

        // Peers waiting for authorization have no netdev yet; surface them so the app
        // can prompt instead of silently using WiFi.
        for (_node, name) in sysfs_unauthorized_devices(&sysfs) {
            links.push(PreferredLink {
                kind: LinkKind::ThunderboltUnauthorized,
                interface: name,
                addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            });
        }
        Ok(links)
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
mod platform {
    use super::*;

    pub fn detect() -> Result<Vec<PreferredLink>> {
        // macOS: the Thunderbolt Bridge service is a bridge interface (bridge0 by
        // default). Naming it Thunderbolt is a heuristic; refine with
        // SystemConfiguration once a macOS machine is in the loop.
        let mut by_iface: std::collections::BTreeMap<String, Vec<IpAddr>> = Default::default();
        for iface in if_addrs::get_if_addrs()? {
            if iface.is_loopback() {
                continue;
            }
            by_iface.entry(iface.name.clone()).or_default().push(iface.ip());
        }
        let mut links = Vec::new();
        for (name, addrs) in by_iface {
            let Some(addr) = best_address(&addrs) else { continue };
            let kind = if name.starts_with("bridge") {
                LinkKind::Thunderbolt
            } else {
                LinkKind::Fallback
            };
            links.push(PreferredLink { kind, interface: name, addr });
        }
        Ok(links)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

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
        // Real machines have interfaces; the probe must simply not error.
        detect_links().expect("probe must not fail");
    }

    #[test]
    fn descriptions_from_real_drivers_classify_as_thunderbolt() {
        for desc in [
            "Thunderbolt(TM) Networking",
            "Intel(R) Thunderbolt(TM) 4 Networking",
            "USB4 Host Networking",
            "Apple Thunderbolt Bridge",
        ] {
            assert!(description_is_thunderbolt(desc), "{desc}");
        }
        for desc in [
            "Intel(R) Wi-Fi 6E AX211 160MHz",
            "Realtek Gaming 2.5GbE Family Controller",
            "Hyper-V Virtual Ethernet Adapter",
        ] {
            assert!(!description_is_thunderbolt(desc), "{desc}");
        }
    }

    #[test]
    fn best_address_prefers_v4_and_tolerates_apipa() {
        let global_v4: IpAddr = "192.168.1.20".parse().unwrap();
        let apipa: IpAddr = "169.254.10.5".parse().unwrap();
        let v6: IpAddr = "fe80::1".parse().unwrap();

        assert_eq!(best_address(&[v6, apipa, global_v4]), Some(global_v4));
        // A direct cable with no DHCP: APIPA is the usable address.
        assert_eq!(best_address(&[v6, apipa]), Some(apipa));
        assert_eq!(best_address(&[v6]), Some(v6));
        assert_eq!(best_address(&[IpAddr::V4(Ipv4Addr::LOCALHOST)]), None);
        assert_eq!(best_address(&[IpAddr::V6(Ipv6Addr::LOCALHOST)]), None);
        assert_eq!(best_address(&[]), None);
    }

    /// Build a fake sysfs tree:
    ///   class/net/<if>/device/subsystem -> bus/<bus>
    ///   bus/thunderbolt/devices/<node>/{authorized,device_name}
    struct FakeSysfs(tempfile::TempDir);

    impl FakeSysfs {
        fn new() -> Self {
            Self(tempfile::tempdir().unwrap())
        }

        fn root(&self) -> &Path {
            self.0.path()
        }

        fn add_netdev(&self, name: &str, bus: &str) {
            let bus_dir = self.root().join("bus").join(bus);
            std::fs::create_dir_all(&bus_dir).unwrap();
            let dev_dir = self.root().join("class/net").join(name).join("device");
            std::fs::create_dir_all(&dev_dir).unwrap();
            symlink_dir(&bus_dir, &dev_dir.join("subsystem"));
        }

        fn add_tb_device(&self, node: &str, authorized: &str, device_name: Option<&str>) {
            let dir = self.root().join("bus/thunderbolt/devices").join(node);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("authorized"), authorized).unwrap();
            if let Some(n) = device_name {
                std::fs::write(dir.join("device_name"), n).unwrap();
            }
        }
    }

    fn symlink_dir(target: &Path, link: &Path) {
        #[cfg(unix)]
        std::os::unix::fs::symlink(target, link).unwrap();
        #[cfg(windows)]
        // Directory symlinks need privileges on Windows; junctions do not, but
        // read_link does not resolve junctions the same way. Fall back to a real
        // symlink and skip gracefully when the privilege is missing.
        if std::os::windows::fs::symlink_dir(target, link).is_err() {
            eprintln!("skipping symlink-dependent assertion: no symlink privilege");
        }
    }

    #[test]
    fn sysfs_netdev_classification_matches_the_bus() {
        let fake = FakeSysfs::new();
        fake.add_netdev("thunderbolt0", "thunderbolt");
        fake.add_netdev("eth0", "pci");

        // Only assert when the symlink was actually created (Windows CI runners
        // grant the privilege; a local non-admin shell may not).
        if fake
            .root()
            .join("class/net/thunderbolt0/device/subsystem")
            .read_link()
            .is_ok()
        {
            assert!(sysfs_is_thunderbolt_netdev(fake.root(), "thunderbolt0"));
            assert!(!sysfs_is_thunderbolt_netdev(fake.root(), "eth0"));
        }
        assert!(!sysfs_is_thunderbolt_netdev(fake.root(), "missing0"));
    }

    #[test]
    fn sysfs_unauthorized_devices_are_reported_with_names() {
        let fake = FakeSysfs::new();
        fake.add_tb_device("0-1", "0", Some("Peer Laptop"));
        fake.add_tb_device("0-2", "1", Some("Dock"));
        fake.add_tb_device("domain0", "", None); // no authorized file content → skipped

        let unauthorized = sysfs_unauthorized_devices(fake.root());
        assert_eq!(
            unauthorized,
            vec![("0-1".to_string(), "Peer Laptop".to_string())]
        );
    }

    #[test]
    fn sysfs_unauthorized_scan_of_missing_tree_is_empty() {
        let fake = FakeSysfs::new();
        assert!(sysfs_unauthorized_devices(fake.root()).is_empty());
    }
}
