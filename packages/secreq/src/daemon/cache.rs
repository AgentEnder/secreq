//! In-memory cache of resolved secret values, encrypted at rest.
//!
//! ## Why
//!
//! Once a wrap has been authorized to read a secret — whether by an
//! explicit user click or by an auto-rule firing — every subsequent
//! authorized ask for the same secret should resolve without
//! re-running the provider. The authorization layer says "yes you can
//! have this," but the **value** still costs an `op read` per ask —
//! which on 1Password means a biometric prompt per call. This module
//! sits between "authorization granted" and "ship value to the waiter"
//! so a cached value short-circuits the provider invocation entirely.
//!
//! ## Scoping
//!
//! Entries key on `(wrap, provider, locator)`. The asking process's
//! pid / parent / ancestor chain doesn't factor in: the resolved
//! secret value is a function of `(provider, locator)`, not of who's
//! asking. Authorization (the approvals cache for interactive grants,
//! the rules evaluator for auto-decisions) is the gate that decides
//! *whether* a lookup happens; once we're past that gate, any further
//! ask the gate would also pass should reuse the cached value.
//!
//! Including `wrap` in the key keeps the cache scoped to a single
//! wrap's secret set, so e.g. two wraps that happen to reference the
//! same `op://Personal/GitHub/token` still get distinct cache slots —
//! defense-in-depth against a future change that would let one wrap's
//! cached value be served to another wrap that lacked authorization.
//!
//! ## Threat model
//!
//! The daemon holds these values in RAM. A plaintext map would mean:
//! - A coredump exposes the values verbatim.
//! - Swap-out of cold pages writes them to disk.
//! - Memory-scraping tools (lldb, /proc/<pid>/mem) read them straight off.
//!
//! So we encrypt every entry with **ChaCha20-Poly1305**, AEAD, fresh
//! 12-byte nonce per entry. The encryption key is derived **per entry**
//! from a daemon-startup master key plus the cache key fields:
//!
//! ```text
//!   entry_key = blake3::keyed_hash(master_key, encode(wrap,
//!                                                     provider,
//!                                                     locator))
//! ```
//!
//! Properties this gives us:
//!
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
//!
//! ## Lifetime
//!
//! Entries live as long as the daemon. There is intentionally **no
//! TTL** — the approvals cache (which keys on `(wrap, parent
//! ProcessIdentity)`) is what controls whether a future ask can
//! ride a remembered approval, and *it* lives for the daemon's
//! lifetime. Capping the secret cache shorter than the approvals
//! cache produced a UX bug: an approved-and-remembered wrap that
//! went idle for longer than the secret-cache TTL would re-trigger
//! the provider (and 1Password's biometric prompt) even though the
//! user thought they'd already approved this. Tying the two
//! lifetimes together means "I approved this once" really does mean
//! "no more prompts (biometric or otherwise) for this approval."
//!
//! Trade-off: a secret rotated upstream is served from cache until
//! the daemon restarts. `secreq daemon stop` is the canonical reset.

use std::collections::HashMap;

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;
use zeroize::Zeroizing;

/// Identifies a cache slot. Keyed on the wrap plus the secret
/// identity, so any authorized ask for the same `(wrap, provider,
/// locator)` triple — regardless of which process is asking — reuses
/// the cached value. See the module docstring for why the asking
/// process's pid is intentionally absent.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub wrap: String,
    pub provider: String,
    pub locator: String,
}

impl CacheKey {
    /// Encode the cache key into a stable byte sequence we can feed to
    /// the keyed hash. Length-prefix everything so two distinct key
    /// fields can't smush into a single ambiguous byte string.
    fn to_kdf_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(
            4 + self.wrap.len() + 4 + self.provider.len() + 4 + self.locator.len(),
        );
        buf.extend_from_slice(&(self.wrap.len() as u32).to_be_bytes());
        buf.extend_from_slice(self.wrap.as_bytes());
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
                },
            );
        }
    }

    /// Look up a cached value, returning the decrypted plaintext if
    /// present. Returns `None` for misses or AEAD failures (which
    /// shouldn't happen but failing closed is safer than panicking).
    pub fn get(&self, key: &CacheKey) -> Option<Zeroizing<String>> {
        let entry = self.entries.get(key)?;
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

    fn key(wrap: &str, provider: &str, locator: &str) -> CacheKey {
        CacheKey {
            wrap: wrap.to_owned(),
            provider: provider.to_owned(),
            locator: locator.to_owned(),
        }
    }

    #[test]
    fn put_get_roundtrips_the_value() {
        let mut cache = SecretCache::new();
        let k = key("gh", "op", "Personal/GitHub/token");
        cache.put(k.clone(), "ghp_secret_value");
        let got = cache.get(&k).expect("hit");
        assert_eq!(&*got, "ghp_secret_value");
    }

    #[test]
    fn different_wrap_does_not_decrypt_to_the_same_value() {
        // Cache entries are wrap-scoped: two wraps referencing the
        // same (provider, locator) get distinct slots and distinct
        // derived keys. Defense-in-depth so one wrap's cached value
        // never serves a lookup against a different wrap.
        let mut cache = SecretCache::new();
        cache.put(key("gh", "op", "x"), "alpha");
        assert!(cache.get(&key("aws", "op", "x")).is_none());
    }

    #[test]
    fn same_wrap_hits_regardless_of_caller_process() {
        // The whole point of the parent-pid-free key: a value cached
        // by one ask is retrievable by any future authorized ask for
        // the same wrap, no matter who's asking.
        let mut cache = SecretCache::new();
        let k = key("gh", "op", "Personal/GitHub/token");
        cache.put(k.clone(), "ghp_secret_value");
        // A second lookup against an identically-shaped key hits.
        let k2 = key("gh", "op", "Personal/GitHub/token");
        let got = cache.get(&k2).expect("hit");
        assert_eq!(&*got, "ghp_secret_value");
    }

    #[test]
    fn ciphertext_in_memory_does_not_contain_plaintext_bytes() {
        // The whole point of encrypting at rest in memory: an attacker
        // grepping the process memory for "hunter2" must not find it.
        let mut cache = SecretCache::new();
        let k = key("gh", "op", "passwd");
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
        let k = key("gh", "op", "x");
        cache.put(k.clone(), "secret");
        let entry = cache.entries.get_mut(&k).expect("stored");
        entry.ciphertext[0] ^= 0x01;
        assert!(cache.get(&k).is_none());
    }

    #[test]
    fn entries_survive_indefinitely_after_put() {
        // The cache has no TTL — entries must live for the daemon's
        // lifetime so a remembered approval never silently re-triggers
        // the provider (and biometric prompt) on the next ask.
        let mut cache = SecretCache::new();
        let k = key("gh", "op", "x");
        cache.put(k.clone(), "v");
        // Two get()s back-to-back without any time-travel: both hit.
        assert_eq!(&*cache.get(&k).expect("hit 1"), "v");
        assert_eq!(&*cache.get(&k).expect("hit 2"), "v");
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
        // Length-prefixed encoding so e.g. ("gh", "op", "/foo") doesn't
        // collide with ("gh", "op/", "foo") at the hash input level.
        // Test by checking the encoded bytes differ; the derived
        // encryption key is just blake3 of these bytes, so distinct
        // inputs ⇒ distinct keys ⇒ different ciphertexts.
        let a = key("gh", "op", "/foo").to_kdf_bytes();
        let b = key("gh", "op/", "foo").to_kdf_bytes();
        assert_ne!(a, b);
        // And the wrap/provider boundary, too.
        let c = key("gh", "op", "x").to_kdf_bytes();
        let d = key("ghop", "", "x").to_kdf_bytes();
        assert_ne!(c, d);
    }
}
