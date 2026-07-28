//! Parsing of `secret://<provider>/<locator>` references.
//!
//! `<provider>` names a `providers` entry; `<locator>` is everything after the
//! first `/` and is substituted into that provider's read template. The same
//! syntax appears both as a manifest value and inline in ambient env vars (§6).

/// A parsed `secret://provider/locator` reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    pub provider: String,
    pub locator: String,
}

/// The URI scheme prefix every reference starts with.
pub const SCHEME: &str = "secret://";

impl Reference {
    /// Parse a full reference, or `None` if `input` is not a well-formed one.
    /// Requires the `secret://` scheme — used when scanning env values, where
    /// a bare `provider/locator` must *not* be mistaken for a reference.
    pub fn parse(input: &str) -> Option<Reference> {
        let rest = input.strip_prefix(SCHEME)?;
        Self::parse_body(rest)
    }

    /// Parse a `secreq read` argument: either a full `secret://provider/locator`
    /// reference or the bare `provider/locator` shorthand. The scheme is
    /// optional here because the argument position is unambiguous — every
    /// `read` arg is a reference, so there's nothing for a bare locator to be
    /// confused with.
    pub fn parse_arg(input: &str) -> Option<Reference> {
        let rest = input.strip_prefix(SCHEME).unwrap_or(input);
        Self::parse_body(rest)
    }

    /// Split `provider/locator` (the part after any scheme prefix), rejecting
    /// an empty provider or locator.
    fn parse_body(rest: &str) -> Option<Reference> {
        let (provider, locator) = rest.split_once('/')?;
        if provider.is_empty() || locator.is_empty() {
            return None;
        }
        Some(Reference {
            provider: provider.to_owned(),
            locator: locator.to_owned(),
        })
    }

    /// Cheap check: does this string look like a reference (`secret://…`)?
    pub fn looks_like_ref(input: &str) -> bool {
        input.starts_with(SCHEME)
    }
}

/// On disk a reference is its `secret://provider/locator` string, so it
/// round-trips through [`Reference::parse`] and [`std::fmt::Display`]. A
/// malformed one is a deserialization error naming the offending value —
/// which is how a bad `private_key` gets caught at load rather than at sign
/// time.
impl<'de> serde::Deserialize<'de> for Reference {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Reference, D::Error> {
        let raw = String::deserialize(d)?;
        Reference::parse(&raw).ok_or_else(|| {
            serde::de::Error::custom(format!(
                "`{raw}` is not a `{SCHEME}provider/locator` reference"
            ))
        })
    }
}

impl serde::Serialize for Reference {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl std::fmt::Display for Reference {
    /// Reconstruct the `secret://provider/locator` string. Round-trips through
    /// [`Reference::parse`].
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{SCHEME}{}/{}", self.provider, self.locator)
    }
}

/// On disk a reference is the string [`Reference::parse`] reads, so that is
/// what the published schema says — with the pattern that parse enforces, so
/// an editor rejects `op/thing` before secreq has to.
///
/// Inlined rather than referenced: a `$ref` cannot carry the sibling
/// `description` its field wants under draft-07.
#[cfg(feature = "schema")]
impl schemars::JsonSchema for Reference {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Reference".into()
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "pattern": r"^secret://[^/]+/.+$"
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_provider_and_multi_segment_locator() {
        let r = Reference::parse("secret://op/Work/Stripe/api_key").unwrap();
        assert_eq!(r.provider, "op");
        assert_eq!(r.locator, "Work/Stripe/api_key");
    }

    #[test]
    fn parses_single_segment_locator() {
        let r = Reference::parse("secret://keychain/myapp").unwrap();
        assert_eq!(r.provider, "keychain");
        assert_eq!(r.locator, "myapp");
    }

    #[test]
    fn rejects_non_refs_and_malformed() {
        assert!(Reference::parse("plainvalue").is_none());
        assert!(Reference::parse("secret://op").is_none()); // no locator
        assert!(Reference::parse("secret:///locator").is_none()); // empty provider
        assert!(Reference::parse("secret://op/").is_none()); // empty locator
    }

    #[test]
    fn display_round_trips_through_parse() {
        for input in [
            "secret://op/Work/Stripe/api_key",
            "secret://keychain/myapp",
            "secret://op/Private/GitHub/private key",
        ] {
            let r = Reference::parse(input).unwrap();
            assert_eq!(r.to_string(), input);
            assert_eq!(Reference::parse(&r.to_string()).unwrap(), r);
        }
    }

    #[test]
    fn looks_like_ref_is_a_cheap_prefix_test() {
        assert!(Reference::looks_like_ref("secret://x/y"));
        assert!(!Reference::looks_like_ref("postgres://x/y"));
    }

    #[test]
    fn parse_arg_accepts_both_scheme_and_bare_forms() {
        let with_scheme = Reference::parse_arg("secret://op/Work/Stripe/api_key").unwrap();
        let bare = Reference::parse_arg("op/Work/Stripe/api_key").unwrap();
        assert_eq!(with_scheme, bare);
        assert_eq!(bare.provider, "op");
        assert_eq!(bare.locator, "Work/Stripe/api_key");
    }

    #[test]
    fn parse_arg_rejects_malformed_bare_refs() {
        assert!(Reference::parse_arg("noslash").is_none()); // no locator segment
        assert!(Reference::parse_arg("/locator").is_none()); // empty provider
        assert!(Reference::parse_arg("op/").is_none()); // empty locator
        assert!(Reference::parse_arg("secret://op").is_none()); // scheme, no locator
    }
}
