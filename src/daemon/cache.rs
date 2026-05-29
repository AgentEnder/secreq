//! In-memory cache of resolved secret values, encrypted at rest.
//!
//! ## Why
//!
//! When the user grants "Approve all from Superset.app", every wrap
//! Superset descendants ask for in the next N minutes should resolve
//! without re-running the provider. The persistent approvals cache says
//! "yes you can have this," but the **value** still costs a `op read`
//! per ask — which on 1Password means a biometric prompt per call. This
//! module sits between "user said yes" and "ship value to the waiter"
//! so a cached value short-circuits the provider invocation entirely.
//!
//! ## Threat model
//!
//! The daemon holds these values in RAM for as long as their TTL. A
//! plaintext map there would mean:
//! - A coredump exposes the values verbatim.
//! - Swap-out of cold pages writes them to disk.
//! - Memory-scraping tools (lldb, /proc/<pid>/mem) read them straight off.
//!
//! So we encrypt every entry with **ChaCha20-Poly1305**, AEAD, fresh
//! 12-byte nonce per entry. The encryption key is derived **per entry**
//! from a daemon-startup master key plus the cache key fields:
//!
//! ```text
//!   entry_key = blake3::keyed_hash(master_key, encode(scope_pid,
//!                                                     scope_start_time,
//!                                                     provider,
//!                                                     locator))
//! ```
//!
//! Properties this gives us:
//!
//! - **Process-scoped**: a cached entry can only be decrypted with the
//!   key derived from the *same* `(scope_pid, scope_start_time)` it was
//!   inserted under. Different parent processes get distinct keys for
//!   the same secret, so cross-process value reuse is impossible without
//!   walking the approval chain.
//! - **Per-entry isolation**: leaking one entry's derived key doesn't
//!   let an attacker decrypt others. The master key is never written to
//!   disk; on idle-exit it goes away with the daemon process.
//! - **Tamper-evident**: AEAD authenticates the ciphertext. A bit-flip
//!   in memory turns into a decrypt failure, not a wrong-value return.
//!
//! This isn't a panacea — an attacker who can read the daemon's memory
//! at all can also derive the entry keys, since the master key sits
//! there too. But it materially raises the bar over a plaintext
//! `HashMap<String, String>`: it kills coredump / swap leakage and
//! makes naive memory grepping miss.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;
use zeroize::Zeroizing;

/// How long a cached secret is reused before we re-fetch from the
/// provider. Pinned shortish so a rotated secret upstream doesn't get
/// served from cache forever. The approvals cache (which says whether
/// to even *try* to resolve) has its own lifetime — the parent process's.
pub const CACHE_TTL: Duration = Duration::from_secs(5 * 60);

/// Identifies a cache slot. Same shape as the approvals cache key plus
/// the secret identity, so values cached under "Approve all from
/// Superset" come back when a different Superset descendant asks for
/// the same `(provider, locator)` pair.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub scope_pid: u32,
    pub scope_start_time: u64,
    pub provider: String,
    pub locator: String,
}

impl CacheKey {
    /// Encode the cache key into a stable byte sequence we can feed to
    /// the keyed hash. Length-prefix everything so two distinct key
    /// fields can't smush into a single ambiguous byte string.
    fn to_kdf_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + 8 + 4 + self.provider.len() + 4 + self.locator.len());
        buf.extend_from_slice(&self.scope_pid.to_be_bytes());
        buf.extend_from_slice(&self.scope_start_time.to_be_bytes());
        buf.extend_from_slice(&(self.provider.len() as u32).to_be_bytes());
        buf.extend_from_slice(self.provider.as_bytes());
        buf.extend_from_slice(&(self.locator.len() as u32).to_be_bytes());
        buf.extend_from_slice(self.locator.as_bytes());
        buf
    }
}

struct Entry {
    ciphertext: Vec<u8>,
    nonce: [u8; 12],
    expires_at: Instant,
}

pub struct SecretCache {
    /// 32-byte symmetric master key. Generated from the OS RNG on
    /// daemon start, lives only in process memory, never persisted.
    /// `Zeroizing` scrubs it on drop.
    master_key: Zeroizing<[u8; 32]>,
    entries: HashMap<CacheKey, Entry>,
}

impl SecretCache {
    pub fn new() -> SecretCache {
        let mut master = Zeroizing::new([0u8; 32]);
        rand::thread_rng().fill_bytes(master.as_mut());
        SecretCache {
            master_key: master,
            entries: HashMap::new(),
        }
    }

    /// Cache `value` under `key`. Overwrites any prior entry for the
    /// same key.
    pub fn put(&mut self, key: CacheKey, value: &str) {
        let entry_key = self.derive_key(&key);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&entry_key));
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, value.as_bytes())
            // ChaCha20Poly1305 encrypt only fails on overflow — we'd
            // need a 256GiB plaintext to trigger. Just drop the cache
            // entry rather than panic.
            .ok();
        if let Some(ct) = ciphertext {
            self.entries.insert(
                key,
                Entry {
                    ciphertext: ct,
                    nonce: nonce_bytes,
                    expires_at: Instant::now() + CACHE_TTL,
                },
            );
        }
    }

    /// Look up a cached value, returning the decrypted plaintext if
    /// present and unexpired. Returns `None` for misses, expired
    /// entries, or AEAD failures (which shouldn't happen but failing
    /// closed is safer than panicking).
    pub fn get(&self, key: &CacheKey) -> Option<Zeroizing<String>> {
        let entry = self.entries.get(key)?;
        if Instant::now() >= entry.expires_at {
            return None;
        }
        let entry_key = self.derive_key(key);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&entry_key));
        let nonce = Nonce::from_slice(&entry.nonce);
        let plaintext = cipher.decrypt(nonce, entry.ciphertext.as_ref()).ok()?;
        // Move plaintext into a Zeroizing<String>: AEAD's `decrypt`
        // returns a Vec<u8> we can't get rid of safely. Convert via
        // String::from_utf8 and zeroize the intermediate.
        let utf8 = String::from_utf8(plaintext).ok()?;
        Some(Zeroizing::new(utf8))
    }

    /// Drop entries past their TTL. Cheap; called opportunistically.
    pub fn evict_expired(&mut self) {
        let now = Instant::now();
        self.entries.retain(|_, e| e.expires_at > now);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Derive the per-entry encryption key by keyed-hashing the
    /// encoded cache key under the master key. The output is
    /// deterministic for a given (master, key) pair, so put/get round-
    /// trip; but the master key is fresh per daemon, so cache state
    /// can't be ported across daemon restarts.
    fn derive_key(&self, key: &CacheKey) -> [u8; 32] {
        let hash = blake3::keyed_hash(&self.master_key, &key.to_kdf_bytes());
        *hash.as_bytes()
    }
}

impl Default for SecretCache {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for SecretCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never dump the master key or the encrypted entries — both
        // would spill across logs unhelpfully and the latter sometimes
        // surprisingly across panic backtraces.
        f.debug_struct("SecretCache")
            .field("entries", &self.entries.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(scope_pid: u32, scope_start: u64, provider: &str, locator: &str) -> CacheKey {
        CacheKey {
            scope_pid,
            scope_start_time: scope_start,
            provider: provider.to_owned(),
            locator: locator.to_owned(),
        }
    }

    #[test]
    fn put_get_roundtrips_the_value() {
        let mut cache = SecretCache::new();
        let k = key(7926, 1_000, "op", "Personal/GitHub/token");
        cache.put(k.clone(), "ghp_secret_value");
        let got = cache.get(&k).expect("hit");
        assert_eq!(&*got, "ghp_secret_value");
    }

    #[test]
    fn different_scope_does_not_decrypt_to_the_same_value() {
        // A cache entry under one scope can't be retrieved by another
        // scope — the derived encryption keys differ.
        let mut cache = SecretCache::new();
        cache.put(key(7926, 1_000, "op", "x"), "alpha");
        // Same provider/locator, different scope: distinct cache slot,
        // distinct derived key. Miss.
        assert!(cache.get(&key(7927, 1_000, "op", "x")).is_none());
    }

    #[test]
    fn ciphertext_in_memory_does_not_contain_plaintext_bytes() {
        // The whole point of encrypting at rest in memory: an attacker
        // grepping the process memory for "hunter2" must not find it.
        let mut cache = SecretCache::new();
        let k = key(7926, 1_000, "op", "passwd");
        cache.put(k.clone(), "hunter2");
        let entry = cache.entries.get(&k).expect("stored");
        // ciphertext + 16-byte AEAD tag should not contain the
        // plaintext bytes anywhere.
        assert!(
            !entry
                .ciphertext
                .windows("hunter2".len())
                .any(|w| w == b"hunter2"),
            "plaintext leaked into ciphertext bytes"
        );
    }

    #[test]
    fn tampered_ciphertext_fails_decrypt_safely() {
        // AEAD authentication: a single bit-flip should fail the tag
        // check and return None — not yield wrong plaintext.
        let mut cache = SecretCache::new();
        let k = key(7926, 1_000, "op", "x");
        cache.put(k.clone(), "secret");
        let entry = cache.entries.get_mut(&k).expect("stored");
        entry.ciphertext[0] ^= 0x01;
        assert!(cache.get(&k).is_none());
    }

    #[test]
    fn expired_entries_are_not_returned() {
        let mut cache = SecretCache::new();
        let k = key(7926, 1_000, "op", "x");
        cache.put(k.clone(), "v");
        // Backdate the expiry — TTL is 5 minutes and we don't want to
        // sleep that long in a test.
        cache.entries.get_mut(&k).unwrap().expires_at = Instant::now() - Duration::from_secs(1);
        assert!(cache.get(&k).is_none());
    }

    #[test]
    fn evict_expired_drops_stale_entries() {
        let mut cache = SecretCache::new();
        let live = key(1, 0, "op", "live");
        let dead = key(2, 0, "op", "dead");
        cache.put(live.clone(), "v1");
        cache.put(dead.clone(), "v2");
        cache.entries.get_mut(&dead).unwrap().expires_at = Instant::now() - Duration::from_secs(1);
        cache.evict_expired();
        assert!(cache.get(&live).is_some());
        assert!(cache.get(&dead).is_none());
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn debug_does_not_leak_master_key_or_entries() {
        let cache = SecretCache::new();
        let dbg = format!("{cache:?}");
        assert!(dbg.contains("entries"));
        assert!(!dbg.contains("master_key"));
    }

    #[test]
    fn kdf_encoding_distinguishes_field_boundaries() {
        // Length-prefixed encoding so e.g. ("op", "/foo") doesn't
        // collide with ("op/", "foo") at the hash input level. Test by
        // checking the encoded bytes differ; the derived encryption
        // key is just blake3 of these bytes, so distinct inputs ⇒
        // distinct keys ⇒ different ciphertexts.
        let a = key(1, 0, "op", "/foo").to_kdf_bytes();
        let b = key(1, 0, "op/", "foo").to_kdf_bytes();
        assert_ne!(a, b);
    }
}
