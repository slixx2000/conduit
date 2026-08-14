//! Device identity and trust-on-first-use pinning (`docs/PROTOCOL.md` §2).
//!
//! Each install mints a stable UUID and a self-signed TLS certificate once, then
//! reuses them forever — the certificate *is* the device identity at the transport
//! layer. Trust is a local map of peer device UUID → pinned certificate fingerprint,
//! written after the user confirms a pairing code. A fingerprint is the BLAKE3-256 of
//! the peer's DER certificate, rendered as lowercase hex.
//!
//! Storage layout inside the identity directory (supplied by the caller — this crate
//! never guesses OS paths):
//!   device.json   { device_id, device_name }
//!   cert.der      self-signed certificate
//!   key.der       PKCS#8 private key
//!   trusted.json  pinned peers, human-readable on purpose

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize};

use crate::protocol::DeviceId;
use crate::{Error, Result};

/// BLAKE3-256 of a DER certificate. The project-wide hash keeps showing up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fingerprint(pub [u8; 32]);

impl Fingerprint {
    pub fn of_cert_der(der: &[u8]) -> Self {
        Self(*blake3::hash(der).as_bytes())
    }

    /// Full lowercase hex, as stored in `trusted.json`.
    pub fn hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// First 8 hex chars — enough for logs and the mDNS `fp` TXT key.
    pub fn short(&self) -> String {
        self.hex()[..8].to_string()
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.hex())
    }
}

#[derive(Serialize, Deserialize)]
struct DeviceFile {
    device_id: DeviceId,
    device_name: String,
}

/// This device's long-term identity: UUID + self-signed cert + private key.
pub struct DeviceIdentity {
    pub device_id: DeviceId,
    pub device_name: String,
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
}

impl fmt::Debug for DeviceIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceIdentity")
            .field("device_id", &self.device_id)
            .field("device_name", &self.device_name)
            .field("fingerprint", &self.fingerprint().short())
            .finish_non_exhaustive()
    }
}

impl DeviceIdentity {
    /// Load the identity from `dir`, or mint and persist a fresh one. `default_name`
    /// is only used on first creation (callers pass the hostname).
    pub fn load_or_create(dir: &Path, default_name: &str) -> Result<Self> {
        std::fs::create_dir_all(dir)?;
        let device_path = dir.join("device.json");
        let cert_path = dir.join("cert.der");
        let key_path = dir.join("key.der");

        if device_path.exists() && cert_path.exists() && key_path.exists() {
            let device: DeviceFile = serde_json::from_slice(&std::fs::read(&device_path)?)
                .map_err(|e| Error::Crypto(format!("corrupt device.json: {e}")))?;
            let cert = CertificateDer::from(std::fs::read(&cert_path)?);
            let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(std::fs::read(&key_path)?));
            return Ok(Self {
                device_id: device.device_id,
                device_name: device.device_name,
                cert,
                key,
            });
        }

        let device_id = DeviceId::new_random();
        // The SAN is a fixed label: identity comes from the pinned fingerprint, not
        // from the name, and the client-side verifier never checks SNI.
        let certified = rcgen::generate_simple_self_signed(vec!["conduit".to_string()])
            .map_err(|e| Error::Crypto(format!("certificate generation failed: {e}")))?;
        let cert = certified.cert.der().clone();
        let key_der = certified.key_pair.serialize_der();

        let device = DeviceFile {
            device_id,
            device_name: default_name.to_string(),
        };
        std::fs::write(&device_path, serde_json::to_vec_pretty(&device).unwrap())?;
        std::fs::write(&cert_path, cert.as_ref())?;
        std::fs::write(&key_path, &key_der)?;

        Ok(Self {
            device_id,
            device_name: device.device_name,
            cert,
            key: PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key_der)),
        })
    }

    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::of_cert_der(self.cert.as_ref())
    }

    pub fn cert_der(&self) -> CertificateDer<'static> {
        self.cert.clone()
    }

    pub fn key_der(&self) -> PrivateKeyDer<'static> {
        self.key.clone_key()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustedPeer {
    pub name: String,
    /// Full lowercase hex BLAKE3-256 of the peer's DER certificate.
    pub fingerprint: String,
}

/// Outcome of checking a connection's presented certificate against the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustStatus {
    /// Pinned fingerprint matches — connect silently.
    Trusted,
    /// Never seen this device: run the pairing-code flow.
    Unknown,
    /// Pinned fingerprint does NOT match — treat as possible impersonation.
    Mismatch { pinned: String },
}

/// Pinned peers, persisted as human-readable JSON so a user can audit or hand-revoke
/// trust before the Phase 5 management UI exists.
#[derive(Debug)]
pub struct TrustStore {
    path: PathBuf,
    peers: HashMap<DeviceId, TrustedPeer>,
}

impl TrustStore {
    /// Load from `dir/trusted.json`; an absent file is an empty store.
    pub fn load(dir: &Path) -> Result<Self> {
        let path = dir.join("trusted.json");
        let peers = if path.exists() {
            serde_json::from_slice(&std::fs::read(&path)?)
                .map_err(|e| Error::Crypto(format!("corrupt trusted.json: {e}")))?
        } else {
            HashMap::new()
        };
        Ok(Self { path, peers })
    }

    pub fn status(&self, peer: DeviceId, presented: &Fingerprint) -> TrustStatus {
        match self.peers.get(&peer) {
            None => TrustStatus::Unknown,
            Some(t) if t.fingerprint == presented.hex() => TrustStatus::Trusted,
            Some(t) => TrustStatus::Mismatch {
                pinned: t.fingerprint.clone(),
            },
        }
    }

    /// Pin a peer after the user confirmed the pairing code. Persists immediately —
    /// trust decisions must never be lost to a crash.
    pub fn pin(&mut self, peer: DeviceId, name: &str, fingerprint: &Fingerprint) -> Result<()> {
        self.peers.insert(
            peer,
            TrustedPeer {
                name: name.to_string(),
                fingerprint: fingerprint.hex(),
            },
        );
        self.save()
    }

    pub fn remove(&mut self, peer: DeviceId) -> Result<bool> {
        let removed = self.peers.remove(&peer).is_some();
        if removed {
            self.save()?;
        }
        Ok(removed)
    }

    /// Give a pinned peer a new display name (the fingerprint stays untouched).
    pub fn rename(&mut self, peer: DeviceId, name: &str) -> Result<bool> {
        match self.peers.get_mut(&peer) {
            Some(entry) => {
                entry.name = name.to_string();
                self.save()?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    pub fn peers(&self) -> impl Iterator<Item = (&DeviceId, &TrustedPeer)> {
        self.peers.iter()
    }

    fn save(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Write-then-rename so a crash never truncates the trust database.
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(&self.peers).unwrap())?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_is_created_once_and_reloaded_identically() {
        let dir = tempfile::tempdir().unwrap();
        let a = DeviceIdentity::load_or_create(dir.path(), "Machine A").unwrap();
        let b = DeviceIdentity::load_or_create(dir.path(), "ignored-on-reload").unwrap();
        assert_eq!(a.device_id, b.device_id);
        assert_eq!(a.fingerprint(), b.fingerprint());
        assert_eq!(b.device_name, "Machine A");
    }

    #[test]
    fn distinct_directories_mint_distinct_identities() {
        let d1 = tempfile::tempdir().unwrap();
        let d2 = tempfile::tempdir().unwrap();
        let a = DeviceIdentity::load_or_create(d1.path(), "A").unwrap();
        let b = DeviceIdentity::load_or_create(d2.path(), "B").unwrap();
        assert_ne!(a.device_id, b.device_id);
        assert_ne!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn trust_store_pins_detects_mismatch_and_persists() {
        let dir = tempfile::tempdir().unwrap();
        let peer = DeviceId::new_random();
        let fp = Fingerprint([7u8; 32]);
        let other = Fingerprint([8u8; 32]);

        let mut store = TrustStore::load(dir.path()).unwrap();
        assert_eq!(store.status(peer, &fp), TrustStatus::Unknown);

        store.pin(peer, "Other laptop", &fp).unwrap();
        assert_eq!(store.status(peer, &fp), TrustStatus::Trusted);
        assert!(matches!(
            store.status(peer, &other),
            TrustStatus::Mismatch { .. }
        ));

        // A fresh load sees the same pin.
        let reloaded = TrustStore::load(dir.path()).unwrap();
        assert_eq!(reloaded.status(peer, &fp), TrustStatus::Trusted);

        let mut reloaded = reloaded;
        assert!(reloaded.rename(peer, "Renamed laptop").unwrap());
        assert_eq!(
            reloaded.peers().find(|(id, _)| **id == peer).unwrap().1.name,
            "Renamed laptop"
        );
        assert_eq!(
            reloaded.status(peer, &fp),
            TrustStatus::Trusted,
            "renaming must not touch the pin"
        );

        assert!(reloaded.remove(peer).unwrap());
        assert_eq!(reloaded.status(peer, &fp), TrustStatus::Unknown);
        assert!(!reloaded.rename(peer, "gone").unwrap());
    }

    #[test]
    fn fingerprints_render_as_hex() {
        let fp = Fingerprint([0xab; 32]);
        assert_eq!(fp.hex().len(), 64);
        assert!(fp.hex().starts_with("abab"));
        assert_eq!(fp.short().len(), 8);
    }
}
