//! The zeroizing secret value type.
//!
//! Per the design (§5), resolved secret values live only in the Rust core.
//! [`SecretValue`] scrubs the buffer it owns when it drops, so a value held
//! only in one does not linger in freed memory. We wrap [`Zeroizing<String>`]
//! rather than rolling our own so the scrubbing is handled by the audited
//! `zeroize` crate.
//!
//! **The guarantee ends at the first copy, and the copy is the caller's to
//! scrub.** Output masking now does: `exec.rs` holds the values as
//! `Zeroizing<Vec<u8>>` and hands each masking thread a clone of the same type,
//! and the masker's own buffers — the values it matches against and its carry —
//! are `Zeroizing` too, so the longest-lived copies (one set per masker, for
//! the child's whole run) all scrub. See `mask.rs`. So does `provider.rs` on
//! both sides of a provider call: the batch reader's stdout (one buffer holding
//! every value the batch resolved) and the argv a `store` builds.
//!
//! **The environment and the daemon's own wire do not**, so this type is not a
//! claim that plaintext exists nowhere else in the process. `commands/run.rs`
//! and `daemon/state.rs` move resolved values straight into a
//! `Vec<(String, String)>` and a `HashMap<String, String>` on the way to the
//! child's environment and across `consent.sock`. Wrapping the local there
//! changes nothing; the fix is a different collection and wire type. **That
//! remainder of finding 018 is declined, not pending** — the daemon's
//! long-lived copy is already encrypted (`daemon/cache.rs`), what is left is a
//! transient map, and the same plaintext sits in the child's environment for
//! the child's whole life regardless. The decline expires if tokens ever leave
//! the env channel; see the security review in brain.
//!
//! The **scoped agent's** wire is not in that list any more:
//! `scoped_agent::write_response` scrubs both the response's own string and
//! the encoded frame on every path out, including the `MAX_FRAME_LEN` bail a
//! certificate or a large key can reach. It borrows `&mut Response` so that is
//! a postcondition a test can observe, rather than a claim.
//!
//! **Nor does a copy we hand to another process.** `std`'s `Command` keeps its
//! own `CString` of every argument and every env value, out of reach behind a
//! `&str` bound; and a provider whose store capability takes the value on argv
//! (`ValueMode::Arg`) puts it in a child's argv, where the process table has it
//! for as long as that child runs. Scrubbing our own buffers is worth doing
//! against a coredump or a swapped-out page. It is not a defence against a
//! local observer, and no amount of `Zeroizing` on this side makes it one.

use std::fmt;

use zeroize::Zeroizing;

/// A resolved secret value. The buffer this owns is zeroized when dropped, and
/// the value is never `Display`ed or logged. Copies taken out of it through
/// [`expose`](Self::expose) or [`as_bytes`](Self::as_bytes) are the caller's to
/// scrub — see the module comment for which callers do.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretValue(Zeroizing<String>);

impl SecretValue {
    /// Wrap a freshly-resolved value.
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    /// Borrow the underlying string. The caller must not persist a copy.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// The value's bytes, for the masking matcher.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Redacted debug output — the value never appears, even via `{:?}`.
impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretValue(***)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expose_returns_value_but_debug_redacts() {
        let s = SecretValue::new("hunter2".to_owned());
        assert_eq!(s.expose(), "hunter2");
        assert_eq!(s.as_bytes(), b"hunter2");
        assert_eq!(format!("{s:?}"), "SecretValue(***)");
    }
}
