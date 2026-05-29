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
    pub fn parse(input: &str) -> Option<Reference> {
        let rest = input.strip_prefix(SCHEME)?;
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
    fn looks_like_ref_is_a_cheap_prefix_test() {
        assert!(Reference::looks_like_ref("secret://x/y"));
        assert!(!Reference::looks_like_ref("postgres://x/y"));
    }
}
