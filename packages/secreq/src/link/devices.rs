//! Persisted credentials for devices paired through `secreq link`.
//!
//! This registry deliberately outlives the daemon, unlike the approvals
//! cache in [`crate::consent`]. A remembered approval is a cached decision
//! that should evaporate when `secreq daemon stop` clears the daemon's
//! in-memory state. A paired device is a credential that should remain
//! enrolled across daemon stops, restarts, and upgrades.
//!
//! The file contains public keys, but its permissions are still a security
//! boundary: anyone who can replace the registry can enroll their own key and
//! gain approval authority. Loading therefore refuses any group or world
//! permissions instead of treating the file as harmless public data.

use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// One enrolled device and the public key it uses to sign decisions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Device {
    pub nickname: String,
    pub public_key_b64: String,
    pub enrolled_at: u64,
    pub last_seen: Option<u64>,
}

/// Load the paired-device registry.
///
/// A missing file is an empty registry: `devices.json` does not exist before
/// the first device is paired.
pub fn load(path: &Path) -> Result<Vec<Device>> {
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => {
            return Err(err)
                .with_context(|| format!("open paired-device registry: {}", path.display()));
        }
    };
    let mode = file
        .metadata()
        .with_context(|| format!("stat paired-device registry: {}", path.display()))?
        .permissions()
        .mode()
        & 0o777;
    if mode & 0o077 != 0 {
        anyhow::bail!(
            "paired-device registry {} has insecure permissions {mode:04o}; \
             expected no group or world permissions (normally 0600)",
            path.display()
        );
    }

    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .with_context(|| format!("read paired-device registry: {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("parse paired-device registry: {}", path.display()))
}

/// Atomically save the registry with an owner-only mode.
pub fn save(path: &Path, devices: &[Device]) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(devices).context("serialize paired-device registry")?;
    crate::atomic::replace(path, &bytes, crate::atomic::Mode::Exactly(0o600))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_saved_registry_loads_back_identically() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("devices.json");
        let devices = vec![Device {
            nickname: "Craig's iPhone".into(),
            public_key_b64: "BExample==".into(),
            enrolled_at: 1_753_000_000,
            last_seen: None,
        }];

        save(&path, &devices).unwrap();

        assert_eq!(load(&path).unwrap(), devices);
    }

    #[test]
    fn a_missing_registry_is_an_empty_list_not_an_error() {
        let dir = tempfile::tempdir().unwrap();

        assert!(load(&dir.path().join("nope.json")).unwrap().is_empty());
    }

    #[test]
    #[cfg(unix)]
    fn a_group_readable_registry_is_refused() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("devices.json");
        save(&path, &[]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();

        let err = load(&path).expect_err("0640 must be refused");
        let message = err.to_string();
        assert!(
            message.contains("permissions") && message.contains("0640"),
            "error should name the offending mode: {err}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn an_owner_only_registry_is_accepted() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("devices.json");
        save(&path, &[]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        load(&path).expect("0600 must be accepted");
    }
}
