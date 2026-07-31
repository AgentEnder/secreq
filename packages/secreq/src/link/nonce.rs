//! In-memory replay protection for linked-device decisions.
//!
//! This store deliberately does not persist. Pending asks die with the daemon,
//! so a restart invalidates every outstanding request and a replayed nonce has
//! nothing left to target. Device identity persists in `devices.json`;
//! decision-shaped state does not.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use anyhow::{anyhow, Result};

/// Single-use nonces, scoped to the live request that consumed them.
///
/// The mutex makes checking and consuming a nonce one atomic operation across
/// the LAN listener's thread-per-request handlers.
#[derive(Default)]
pub struct NonceStore {
    used: Mutex<HashMap<String, HashSet<String>>>,
}

impl NonceStore {
    /// Consume a fresh nonce, or refuse it if this request already used it.
    pub fn accept(&self, request_id: &str, nonce: &str) -> Result<()> {
        let mut used = self
            .used
            .lock()
            .map_err(|_| anyhow!("nonce store unavailable"))?;
        if !used
            .entry(request_id.to_owned())
            .or_default()
            .insert(nonce.to_owned())
        {
            return Err(anyhow!("decision nonce already used"));
        }
        Ok(())
    }

    /// Drop replay state once its ask is no longer pending.
    pub fn retire(&self, request_id: &str) -> Result<()> {
        self.used
            .lock()
            .map_err(|_| anyhow!("nonce store unavailable"))?
            .remove(request_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_nonce_is_accepted() {
        let store = NonceStore::default();

        store
            .accept("request-123", "nonce-456")
            .expect("a fresh nonce");
    }

    #[test]
    fn a_replayed_nonce_is_refused() {
        let store = NonceStore::default();
        store.accept("request-123", "nonce-456").unwrap();

        store
            .accept("request-123", "nonce-456")
            .expect_err("a nonce is single-use within its request");
    }

    #[test]
    fn the_same_nonce_is_independent_between_requests() {
        let store = NonceStore::default();
        store.accept("request-123", "nonce-456").unwrap();

        store
            .accept("request-789", "nonce-456")
            .expect("nonces are scoped to a request id");
    }

    #[test]
    fn retiring_a_request_drops_its_nonces() {
        let store = NonceStore::default();
        store.accept("request-123", "nonce-456").unwrap();

        store.retire("request-123").unwrap();

        store
            .accept("request-123", "nonce-456")
            .expect("the retired request no longer occupies replay state");
    }
}
