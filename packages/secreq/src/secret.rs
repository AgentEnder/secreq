//! The zeroizing secret value type.
//!
//! Per the design (§5), resolved secret values live only in the Rust core and
//! are zeroized on drop so they never linger in freed memory. We wrap
//! [`Zeroizing<String>`] rather than rolling our own so the scrubbing is
//! handled by the audited `zeroize` crate.

use std::fmt;

use zeroize::Zeroizing;

/// A resolved secret value. Zeroized when dropped; never `Display`ed or logged.
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
