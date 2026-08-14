//! Virtual mounted volume — the "a drive appeared" experience (Phase 4, Tier B).
//!
//! This is *not* a USB gadget: two laptops are both USB hosts and cannot present as
//! mass-storage devices to one another (`docs/ARCHITECTURE.md` §1). Instead we mount
//! a virtual filesystem whose reads stream over the live peer session
//! ([`conduit_core::FsClient`]) and whose writes spool locally and re-use the
//! chunked transfer engine on close (`docs/PROTOCOL.md` §4).
//!
//! Backends: **WinFsp on Windows (implemented)**; FUSE via `fuser` on Linux and
//! macFUSE on macOS are pending a machine to validate on — [`mount`] reports that
//! honestly rather than pretending.
//!
//! The mount host runs on its own thread (the WinFsp host type is not `Send`);
//! filesystem callbacks bridge onto the app's tokio runtime with `block_on`.

use std::path::PathBuf;
use std::sync::Arc;

use conduit_core::FsClient;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The platform's userspace-filesystem driver is absent. The UI must guide the
    /// user through installing it rather than failing opaquely.
    #[error(
        "{driver} is required to mount a peer as a drive and is not installed — \
         install it from https://winfsp.dev and try again"
    )]
    DriverMissing { driver: &'static str },

    #[error("mount failed: {0}")]
    Mount(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("mounting is not implemented on this platform yet (FUSE port pending)")]
    Unsupported,
}

/// The userspace-filesystem driver this platform mounts through.
pub const REQUIRED_DRIVER: &str = if cfg!(target_os = "windows") {
    "WinFsp"
} else if cfg!(target_os = "macos") {
    "macFUSE"
} else {
    "FUSE"
};

/// Called when a file written into the mount is complete (handle closed): the app
/// sends the spool file to the peer with the ordinary transfer engine. Arguments:
/// the file's name (as the user named it in the mount) and the local spool path.
pub type WriteHandler = Arc<dyn Fn(String, PathBuf) + Send + Sync>;

#[derive(Debug, Clone)]
pub struct MountOptions {
    /// Explorer/Finder volume label, e.g. the peer's device name.
    pub volume_label: String,
}

/// A live mount. Dropping (or calling [`MountHandle::unmount`]) removes the drive.
pub struct MountHandle {
    mountpoint: String,
    stop: Option<std::sync::mpsc::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl MountHandle {
    pub fn mountpoint(&self) -> &str {
        &self.mountpoint
    }

    /// Cleanly remove the drive and stop the host.
    pub fn unmount(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for MountHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl std::fmt::Debug for MountHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MountHandle")
            .field("mountpoint", &self.mountpoint)
            .finish_non_exhaustive()
    }
}

/// Mount a peer's shared area at `mountpoint` (e.g. `"X:"` on Windows). `client`
/// must be an established, **trusted** filesystem session; `runtime` is the tokio
/// runtime the client lives on; `on_write` ships completed writes to the peer.
pub fn mount(
    client: FsClient,
    runtime: tokio::runtime::Handle,
    mountpoint: &str,
    options: MountOptions,
    on_write: WriteHandler,
) -> Result<MountHandle> {
    #[cfg(windows)]
    {
        windows_mount::mount(client, runtime, mountpoint, options, on_write)
    }
    #[cfg(not(windows))]
    {
        let _ = (client, runtime, mountpoint, options, on_write);
        Err(Error::Unsupported)
    }
}

#[cfg(windows)]
mod windows_mount;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_driver_is_named_for_this_platform() {
        assert!(matches!(REQUIRED_DRIVER, "WinFsp" | "macFUSE" | "FUSE"));
    }
}
