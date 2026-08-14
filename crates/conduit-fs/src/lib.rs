//! Virtual mounted volume — the "a drive appeared" experience (Phase 4, Tier B).
//!
//! This is *not* a USB gadget: two laptops are both USB hosts and cannot present as
//! mass-storage devices to one another (`docs/ARCHITECTURE.md` §1). Instead we mount a
//! virtual filesystem whose reads and writes stream over the live peer session, which
//! looks identical to the user in Finder/Explorer/Files.
//!
//! Backends: FUSE via `fuser` on Linux and macOS (the latter needs macFUSE), WinFsp or
//! Dokan on Windows. Each requires a one-time driver install, which is why this is
//! gated behind the Tier A drop-folder UX that works everywhere with no driver.
//!
//! Phase 0 is a stub: it defines the mount surface and reports honestly that it is not
//! built yet.

use std::path::{Path, PathBuf};

use conduit_core::DeviceId;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The platform's userspace-filesystem driver is absent. The installer flow must
    /// detect this and guide the user through it rather than failing opaquely.
    #[error("{driver} is required to mount a peer as a drive, and is not installed")]
    DriverMissing { driver: &'static str },

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{what} is not implemented yet (planned for {phase})")]
    NotImplemented {
        what: &'static str,
        phase: &'static str,
    },
}

/// The userspace-filesystem driver this platform mounts through.
pub const REQUIRED_DRIVER: &str = if cfg!(target_os = "windows") {
    "WinFsp"
} else if cfg!(target_os = "macos") {
    "macFUSE"
} else {
    "FUSE"
};

/// A live mount of a peer's shared area.
#[derive(Debug)]
pub struct Mount {
    peer: DeviceId,
    mountpoint: PathBuf,
}

impl Mount {
    pub fn peer(&self) -> DeviceId {
        self.peer
    }

    pub fn mountpoint(&self) -> &Path {
        &self.mountpoint
    }
}

/// Mount `peer`'s shared area at `mountpoint`.
pub fn mount(_peer: DeviceId, _mountpoint: &Path) -> Result<Mount> {
    Err(Error::NotImplemented {
        what: "virtual volume mounting",
        phase: "Phase 4",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mounting_reports_the_phase_rather_than_failing_opaquely() {
        let err = mount(DeviceId::new_random(), Path::new("/mnt/conduit"))
            .expect_err("Phase 4 is not built yet");
        let msg = err.to_string();
        assert!(msg.contains("Phase 4"), "{msg}");
    }

    #[test]
    fn required_driver_is_named_for_this_platform() {
        assert!(matches!(REQUIRED_DRIVER, "WinFsp" | "macFUSE" | "FUSE"));
    }
}
