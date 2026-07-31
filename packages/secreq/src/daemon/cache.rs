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
//! Entries key on `(provider, locator)` — the secret's identity, and
//! nothing else. The asking process's pid / parent / ancestor chain
//! doesn't factor in, and neither does the wrap: the resolved value is
//! a function of the reference. Authorization (the approvals cache for
//! interactive grants, the rules evaluator for auto-decisions) is the
//! gate that decides *whether* a lookup happens; once we're past that
//! gate, any further ask the gate would also pass should reuse the
//! cached value.
//!
//! The key used to carry a `wrap` too, as defense-in-depth against a
//! future change that let one wrap's cached value serve another wrap
//! that lacked authorization. That was a hedge, not a live property:
//! authorization is a separate gate and is unchanged: wrap B still
//! needs its own approval (or a matching auto-rule) before it reaches
//! this module at all. All the extra field ever decided was whether
//! the *provider* re-ran after that gate passed — so it cost a second
//! biometric prompt for a secret the user had already approved
//! elsewhere, and bought nothing.
//!
//! Dropping it is also what makes the TTL below coherent. A TTL is a
//! property of the secret; with `wrap` in the key one declared secret
//! had N slots and N independent expiries, and "this secret is cached
//! for 15 minutes" was not a true sentence about any of them.
//!
//! Note the field was never only a wrap name: the SSH sign path stored
//! `wrap: "ssh:<key_id>"`, using it as a namespace. Collapsing to
//! `(provider, locator)` therefore means an SSH identity and a wrap
//! naming the same reference share one slot. That is deliberate — it
//! is the same secret — and `daemon/in_flight.rs`, which keys its
//! singleflight map on this same type, follows automatically.
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
//!   entry_key = blake3::keyed_hash(master_key, encode(provider,
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
//! **The daemon's own lifetime is an entry's default TTL** — not a
//! special "no TTL" case, but the value [`CacheTtl`] takes when a
//! secret's declaration says nothing. So today's behaviour is the
//! unset case, and every other value is a *shortening* of it, declared
//! per secret in the config's `secrets` block:
//!
//! ```toml
//! [secrets.github_token]
//! ref = "secret://op/…/token"
//! ttl = "15m"
//! ```
//!
//! A *global* cap was tried and is why the default has to be the
//! daemon's lifetime. The approvals cache (which keys on
//! `(wrap, parent ProcessIdentity)`) lives for the daemon, so capping
//! every value shorter than it produced a UX bug: an
//! approved-and-remembered wrap that went idle for longer than the cap
//! re-triggered the provider — and 1Password's biometric prompt — even
//! though the user had been told the approval was remembered.
//!
//! A per-secret, opt-in shortening is the fix rather than a repeat of
//! that bug. Setting a TTL on one high-sensitivity secret is the user
//! saying "re-fetch this one, I accept the re-prompt": a local,
//! informed choice about a secret they picked, not a default that
//! surprises everyone about every secret. Left unset — which is every
//! secret unless someone writes a `ttl` — "I approved this once" still
//! means "no more prompts for this approval."
//!
//! **An expiring value does not expire the approval.** The entry is
//! dropped and the next ask re-runs the provider, but the remembered
//! approval still stands, so no consent window opens. A TTL is a
//! statement about how long a *value* may be reused, and re-consent is
//! a different feature that would be wearing this one's name; leaving
//! the question unanswered is how the original bug came back.
//!
//! **Expiry is pruned actively, not lazily.** [`SecretCache::prune_expired`]
//! runs on the daemon's one-second main-loop tick and drops (and
//! zeroizes) whatever has passed, rather than waiting for someone to
//! ask. A secret whose TTL was set precisely because it is sensitive
//! should not sit decryptable in RAM for an hour after it expired just
//! because nobody read it. The prune touches no activity clock, so it
//! cannot resurrect a daemon on its way to an idle exit. [`SecretCache::get`]
//! refuses an expired entry as well, so a read landing between ticks
//! can never be served a stale value.
//!
//! Trade-off, now only for the default: a secret rotated upstream is
//! served from cache until the daemon restarts. `secreq daemon stop` is
//! still the blanket reset, and a `ttl` is the per-secret answer for a
//! secret that rotates.

use std::collections::HashMap;
use std::time::Instant;

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;
use zeroize::Zeroizing;

use crate::wraps::CacheTtl;

/// Identifies a cache slot: the secret's identity, and nothing else.
/// Any authorized ask for the same `(provider, locator)` — whatever
/// wrap it came from, whatever process is asking — reuses the cached
/// value. See the module docstring for why neither the asking
/// process's pid nor the wrap is part of this.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub provider: String,
    pub locator: String,
}

impl CacheKey {
    /// Build a key from a reference's two halves.
    pub fn new(provider: impl Into<String>, locator: impl Into<String>) -> CacheKey {
        CacheKey {
            provider: provider.into(),
            locator: locator.into(),
        }
    }

    /// Encode the cache key into a stable byte sequence we can feed to
    /// the keyed hash. Length-prefix everything so two distinct key
    /// fields can't smush into a single ambiguous byte string.
    fn to_kdf_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + self.provider.len() + 4 + self.locator.len());
        buf.extend_from_slice(&(self.provider.len() as u32).to_be_bytes());
        buf.extend_from_slice(self.provider.as_bytes());
        buf.extend_from_slice(&(self.locator.len() as u32).to_be_bytes());
        buf.extend_from_slice(self.locator.as_bytes());
        buf
    }
}

struct Entry {
    /// `Zeroizing` so every path that removes an entry — an overwrite,
    /// an expiry prune, the map's own drop — scrubs the ciphertext
    /// rather than handing the allocator a readable buffer.
    ciphertext: Zeroizing<Vec<u8>>,
    nonce: [u8; 12],
    /// When this value was cached. Paired with `ttl` rather than
    /// pre-computing a deadline so the daemon-lifetime default needs no
    /// sentinel instant to stand for "never".
    stored_at: Instant,
    ttl: CacheTtl,
}

impl Entry {
    /// Has this entry outlived its TTL as of `now`? Always false for
    /// the daemon-lifetime default.
    fn expired_at(&self, now: Instant) -> bool {
        self.ttl
            .expired_after(now.saturating_duration_since(self.stored_at))
    }
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

    /// Cache `value` under `key` for `ttl`. Overwrites any prior entry
    /// for the same key — including its TTL, so a re-resolve restarts
    /// the clock rather than inheriting the old entry's remaining life.
    pub fn put(&mut self, key: CacheKey, value: &str, ttl: CacheTtl) {
        self.put_at(key, value, ttl, Instant::now());
    }

    /// Clock-injectable [`SecretCache::put`]. The TTL tests drive this
    /// with a synthetic `now` so nothing has to sleep on a guessed
    /// duration.
    pub fn put_at(&mut self, key: CacheKey, value: &str, ttl: CacheTtl, now: Instant) {
        let entry_key = self.derive_key(&key);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&*entry_key));
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
                    ciphertext: Zeroizing::new(ct),
                    nonce: nonce_bytes,
                    stored_at: now,
                    ttl,
                },
            );
        }
    }

    /// Look up a cached value, returning the decrypted plaintext if
    /// present and unexpired. Returns `None` for misses, for an entry
    /// whose TTL has elapsed, and for AEAD failures (which shouldn't
    /// happen but failing closed is safer than panicking).
    ///
    /// An expired entry is refused rather than dropped here, because
    /// `get` takes `&self`; the drop-and-zeroize is
    /// [`SecretCache::prune_expired`]'s job on the daemon tick. This
    /// check is what closes the sub-tick window between the two.
    pub fn get(&self, key: &CacheKey) -> Option<Zeroizing<String>> {
        self.get_at(key, Instant::now())
    }

    /// Clock-injectable [`SecretCache::get`].
    pub fn get_at(&self, key: &CacheKey, now: Instant) -> Option<Zeroizing<String>> {
        let entry = self.entries.get(key)?;
        if entry.expired_at(now) {
            return None;
        }
        let entry_key = self.derive_key(key);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&*entry_key));
        let nonce = Nonce::from_slice(&entry.nonce);
        let plaintext = cipher.decrypt(nonce, entry.ciphertext.as_ref()).ok()?;
        // Move plaintext into a Zeroizing<String>: AEAD's `decrypt`
        // returns a Vec<u8> we can't get rid of safely. Convert via
        // String::from_utf8 and zeroize the intermediate.
        let utf8 = String::from_utf8(plaintext).ok()?;
        Some(Zeroizing::new(utf8))
    }

    /// Drop every entry whose TTL has elapsed, returning how many went.
    /// Removal zeroizes the ciphertext (it is a [`Zeroizing`] buffer),
    /// and the per-entry key is derived on demand so nothing outlives
    /// the entry it belonged to.
    ///
    /// The daemon's main loop calls this once a second. It reads no
    /// activity clock and touches nothing else, so a prune can never
    /// keep an idle-exiting daemon alive.
    pub fn prune_expired(&mut self) -> usize {
        self.prune_expired_at(Instant::now())
    }

    /// Clock-injectable [`SecretCache::prune_expired`].
    pub fn prune_expired_at(&mut self, now: Instant) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, entry| !entry.expired_at(now));
        before - self.entries.len()
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
    ///
    /// `Zeroizing` because this is the key to one entry's plaintext:
    /// an expiry prune that scrubbed the ciphertext but left copies of
    /// its key on the stack would only have moved the problem.
    fn derive_key(&self, key: &CacheKey) -> Zeroizing<[u8; 32]> {
        let hash = blake3::keyed_hash(&self.master_key, &key.to_kdf_bytes());
        Zeroizing::new(*hash.as_bytes())
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
    use std::time::Duration;

    fn key(provider: &str, locator: &str) -> CacheKey {
        CacheKey::new(provider, locator)
    }

    /// A fixed "now" the TTL tests move forward by hand. Nothing here
    /// sleeps: the clock is a parameter, so an expiry test is exact
    /// rather than a guess about how long a sleep takes.
    fn t0() -> Instant {
        Instant::now()
    }

    #[test]
    fn put_get_roundtrips_the_value() {
        let mut cache = SecretCache::new();
        let k = key("op", "Personal/GitHub/token");
        cache.put(k.clone(), "ghp_secret_value", CacheTtl::default());
        let got = cache.get(&k).expect("hit");
        assert_eq!(&*got, "ghp_secret_value");
    }

    #[test]
    fn two_wraps_naming_the_same_reference_share_one_slot() {
        // The wrap left the key. Approving a second wrap for a secret
        // already approved elsewhere must not cost a second provider
        // call (on 1Password, a second biometric prompt) — authorization
        // is a separate gate and is unchanged.
        let mut cache = SecretCache::new();
        cache.put(key("op", "x"), "alpha", CacheTtl::default());
        assert_eq!(&*cache.get(&key("op", "x")).expect("hit"), "alpha");
    }

    #[test]
    fn a_different_reference_is_a_different_slot() {
        let mut cache = SecretCache::new();
        cache.put(key("op", "x"), "alpha", CacheTtl::default());
        assert!(cache.get(&key("op", "y")).is_none());
        assert!(cache.get(&key("keychain", "x")).is_none());
    }

    #[test]
    fn ciphertext_in_memory_does_not_contain_plaintext_bytes() {
        // The whole point of encrypting at rest in memory: an attacker
        // grepping the process memory for "hunter2" must not find it.
        let mut cache = SecretCache::new();
        let k = key("op", "passwd");
        cache.put(k.clone(), "hunter2", CacheTtl::default());
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
        let k = key("op", "x");
        cache.put(k.clone(), "secret", CacheTtl::default());
        let entry = cache.entries.get_mut(&k).expect("stored");
        entry.ciphertext[0] ^= 0x01;
        assert!(cache.get(&k).is_none());
    }

    #[test]
    fn an_unset_ttl_is_the_daemon_lifetime_and_never_expires() {
        // The default is not "no TTL" as a special case — it is the
        // daemon's own lifetime as a value. Nothing this cache can be
        // told about the clock expires it.
        let mut cache = SecretCache::new();
        let k = key("op", "x");
        let now = t0();
        cache.put_at(k.clone(), "v", CacheTtl::default(), now);
        assert_eq!(CacheTtl::default(), CacheTtl::DaemonLifetime);

        let a_week = now + Duration::from_secs(7 * 24 * 60 * 60);
        assert_eq!(&*cache.get_at(&k, a_week).expect("hit"), "v");
        assert_eq!(cache.prune_expired_at(a_week), 0);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn a_set_ttl_shortens_the_lifetime() {
        let mut cache = SecretCache::new();
        let k = key("op", "x");
        let now = t0();
        cache.put_at(k.clone(), "v", CacheTtl::Secs(900), now);

        // Inside the window, the value is served.
        let inside = now + Duration::from_secs(899);
        assert_eq!(&*cache.get_at(&k, inside).expect("hit"), "v");

        // At the boundary and past it, it is not.
        let at = now + Duration::from_secs(900);
        assert!(cache.get_at(&k, at).is_none());
        let past = now + Duration::from_secs(901);
        assert!(cache.get_at(&k, past).is_none());
    }

    #[test]
    fn a_read_between_prune_ticks_is_never_served_a_stale_value() {
        // `get` refuses an expired entry itself, so the up-to-one-second
        // gap between the daemon's prune ticks is not a window in which
        // an expired secret can still be handed out.
        let mut cache = SecretCache::new();
        let k = key("op", "x");
        let now = t0();
        cache.put_at(k.clone(), "v", CacheTtl::Secs(60), now);
        let past = now + Duration::from_secs(61);
        assert!(cache.get_at(&k, past).is_none());
        // Still physically present — nothing has pruned yet.
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn the_active_prune_drops_expired_entries_and_leaves_the_rest() {
        let mut cache = SecretCache::new();
        let now = t0();
        cache.put_at(key("op", "short"), "a", CacheTtl::Secs(60), now);
        cache.put_at(key("op", "long"), "b", CacheTtl::Secs(3600), now);
        cache.put_at(key("op", "forever"), "c", CacheTtl::DaemonLifetime, now);
        assert_eq!(cache.len(), 3);

        let later = now + Duration::from_secs(120);
        assert_eq!(cache.prune_expired_at(later), 1);
        assert_eq!(cache.len(), 2);
        assert!(cache.get_at(&key("op", "short"), later).is_none());
        assert!(cache.get_at(&key("op", "long"), later).is_some());
        assert!(cache.get_at(&key("op", "forever"), later).is_some());

        // Idempotent: a second sweep at the same instant finds nothing.
        assert_eq!(cache.prune_expired_at(later), 0);
    }

    #[test]
    fn expiry_then_re_put_restarts_the_clock() {
        // Re-resolving after an expiry must give a full fresh window,
        // not whatever was left of the old entry's.
        let mut cache = SecretCache::new();
        let k = key("op", "x");
        let now = t0();
        cache.put_at(k.clone(), "old", CacheTtl::Secs(60), now);
        let later = now + Duration::from_secs(61);
        assert_eq!(cache.prune_expired_at(later), 1);

        cache.put_at(k.clone(), "new", CacheTtl::Secs(60), later);
        assert_eq!(
            &*cache
                .get_at(&k, later + Duration::from_secs(59))
                .expect("hit"),
            "new"
        );
        assert!(cache.get_at(&k, later + Duration::from_secs(60)).is_none());
    }

    #[test]
    fn a_zero_ttl_means_never_served_from_cache() {
        let mut cache = SecretCache::new();
        let k = key("op", "x");
        let now = t0();
        cache.put_at(k.clone(), "v", CacheTtl::Secs(0), now);
        assert!(cache.get_at(&k, now).is_none());
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
        // Length-prefixed encoding so ("op", "/foo") doesn't collide
        // with ("op/", "foo") at the hash input level. Test by checking
        // the encoded bytes differ; the derived encryption key is just
        // blake3 of these bytes, so distinct inputs ⇒ distinct keys ⇒
        // different ciphertexts.
        assert_ne!(
            key("op", "/foo").to_kdf_bytes(),
            key("op/", "foo").to_kdf_bytes()
        );
        assert_ne!(key("op", "x").to_kdf_bytes(), key("opx", "").to_kdf_bytes());
    }
}
