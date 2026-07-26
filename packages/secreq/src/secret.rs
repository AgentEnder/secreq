//! The zeroizing secret value type.
//!
//! Per the design (§5), resolved secret values live only in the Rust core.
//! [`SecretValue`] scrubs the buffer it owns when it drops, so a value held
//! only in one does not linger in freed memory. We wrap [`Zeroizing<String>`]
//! rather than rolling our own so the scrubbing is handled by the audited
//! `zeroize` crate.
//!
//! **The guarantee ends at the first copy, and two paths take one.** Neither
//! is scrubbed today, so this type is not a claim that plaintext exists
//! nowhere else in the process:
//!
//! - **Output masking.** `exec.rs` copies the values into a `Vec<Vec<u8>>` and
//!   clones that once per masking thread. Closing it means changing `exec.rs`'s
//!   own signatures and `Masker::new`'s `AsRef<[u8]>` bound — a hot path, and
//!   not attempted. What *is* scrubbed is the masker's own copies: the values
//!   it matches against and its carry buffer are both `Zeroizing`, and those
//!   are the copies that live longest (one set per masker, for the child's
//!   whole run). See `mask.rs`.
//! - **The environment and the wire.** `commands.rs` and `daemon/state.rs`
//!   move resolved values straight into a `Vec<(String, String)>` and a
//!   `HashMap<String, String>` on the way to the child's environment and
//!   across the daemon socket. Wrapping the local there changes nothing; the
//!   fix is a different collection and wire type, which was judged not worth
//!   the churn.

use std::fmt;

use zeroize::Zeroizing;

/// A resolved secret value. The buffer this owns is zeroized when dropped, and
/// the value is never `Display`ed or logged. Copies taken out of it through
/// [`expose`](Self::expose) or [`as_bytes`](Self::as_bytes) are the caller's to
/// scrub — see the module comment for the two that aren't.
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
