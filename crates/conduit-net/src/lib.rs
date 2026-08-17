//! Link selection: enumerate every usable IP link between this machine and a peer,
//! rank them, pick the fastest, and let the user override (`docs/Transports.md`).
//!
//! This crate exists so that `conduit-core` never learns what a Thunderbolt (or
//! Ethernet, WiFi, USB-bridge) link is. The core is handed an address and transfers
//! over whatever it names — which is why the whole stack is testable over loopback
//! and LAN with no special hardware. A transport's only job is to *produce a usable
//! IP interface + address* and describe it.
//!
//! Layout:
//! - [`transport`] — the `Transport` trait, `Link`, and the ranking
//!   [`transport::TransportManager`]; one implementation per link type.
//! - Crate-root helpers shared by the transports and by `conduit-discovery`:
//!   address ranking and the Linux sysfs walkers (compiled and unit-tested with
//!   fixture trees on every platform; only the Linux probe wires them to `/sys`).

use std::net::IpAddr;
use std::path::Path;

pub mod transport;

pub use transport::{Link, SpeedTier, Transport, TransportKind, TransportManager};

/// Whether an adapter description / friendly name identifies a Thunderbolt or USB4
/// networking adapter. The strings to match come from real drivers: Intel's
/// "Thunderbolt(TM) Networking", Apple's "Thunderbolt Bridge", Windows 11's
/// "USB4 Host Router"-style names.
pub fn description_is_thunderbolt(description: &str) -> bool {
    let d = description.to_ascii_lowercase();
    d.contains("thunderbolt") || d.contains("usb4")
}

/// Dial-preference rank of an address; higher is better, 0 means "never dial".
///
/// IPv4 beats IPv6 because it needs no scope-id to type or advertise; a link-local
/// 169.254.x.x is *expected* on a direct cable with no DHCP, so it is not filtered.
/// Globally-routable v4 still outranks it for ordinary LAN adapters.
pub fn address_rank(a: &IpAddr) -> u8 {
    match a {
        IpAddr::V4(v4) if v4.is_loopback() => 0,
        IpAddr::V4(v4) if v4.is_link_local() => 2,
        IpAddr::V4(_) => 3,
        IpAddr::V6(v6) if v6.is_loopback() => 0,
        IpAddr::V6(_) => 1,
    }
}

/// The single address peers should dial first, per [`address_rank`].
pub fn best_address(addrs: &[IpAddr]) -> Option<IpAddr> {
    addrs
        .iter()
        .max_by_key(|a| address_rank(a))
        .filter(|a| address_rank(a) > 0)
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
        Ok(target) => target.file_name().is_some_and(|n| n == "thunderbolt"),
        Err(_) => false,
    }
}

/// Whether `/sys/class/net/<interface>` (under `sysfs_root`) is backed by real
/// hardware: physical NICs expose a `device` entry; veth/bridge/bond/dummy don't,
/// yet still report ethernet `type == 1` and can look like a "direct cable"
/// (carrier-up, link-local-only, no gateway).
pub fn sysfs_is_physical_netdev(sysfs_root: &Path, interface: &str) -> bool {
    sysfs_root
        .join("class/net")
        .join(interface)
        .join("device")
        .exists()
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

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
        // Directory symlinks need privileges on Windows; skip gracefully when the
        // privilege is missing (CI runners grant it).
        if std::os::windows::fs::symlink_dir(target, link).is_err() {
            eprintln!("skipping symlink-dependent assertion: no symlink privilege");
        }
    }

    #[test]
    fn sysfs_netdev_classification_matches_the_bus() {
        let fake = FakeSysfs::new();
        fake.add_netdev("thunderbolt0", "thunderbolt");
        fake.add_netdev("eth0", "pci");

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
    fn virtual_netdevs_are_not_physical() {
        let fake = FakeSysfs::new();
        fake.add_netdev("eth0", "pci");
        // veths and bridges have a class/net entry but no device/ underneath.
        std::fs::create_dir_all(fake.root().join("class/net/veth0")).unwrap();

        assert!(sysfs_is_physical_netdev(fake.root(), "eth0"));
        assert!(!sysfs_is_physical_netdev(fake.root(), "veth0"));
        assert!(!sysfs_is_physical_netdev(fake.root(), "missing0"));
    }

    #[test]
    fn sysfs_unauthorized_devices_are_reported_with_names() {
        let fake = FakeSysfs::new();
        fake.add_tb_device("0-1", "0", Some("Peer Laptop"));
        fake.add_tb_device("0-2", "1", Some("Dock"));
        fake.add_tb_device("domain0", "", None); // empty authorized file → skipped

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

    #[tokio::test]
    async fn manager_probes_this_machine_without_failing() {
        let mgr = TransportManager::with_defaults();
        let links = mgr.available().await;
        // Contents are machine-dependent; the invariants are "no panic, no
        // loopback, ranked output".
        for l in &links {
            assert!(!l.bind_addr.is_loopback() || l.needs_authorization);
        }
        let _ = mgr.preferred().await;
    }
}
