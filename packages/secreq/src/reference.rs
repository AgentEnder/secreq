//! Parsing of `secret://…` references, in both of the forms the scheme has.
//!
//! `secret://<provider>/<locator>` names a `providers` entry plus everything
//! after the first `/`, substituted into that provider's read template. The
//! same syntax appears both as a config value and inline in ambient env vars
//! (§6).
//!
//! `secret://<name>` names a secret declared once in the config's `secrets`
//! block, which supplies the provider reference *and* its cache TTL. **The
//! slash is the whole rule**: a name contains none, a provider reference always
//! has one, so telling the two apart needs no lookahead and no config. Nothing
//! existing changes meaning, because a no-slash reference was simply invalid
//! before — `secret://op` has never parsed. The empty case (`secret://`) stays
//! invalid so the rule remains total.
//!
//! Resolving a name needs the config, so it lives on
//! [`crate::wraps::WrapsConfig::resolve_ref`] rather than here; this module
//! only decides which of the two forms a string is.

/// A parsed `secret://provider/locator` reference — a provider scheme and the
/// locator to hand it. This is the *resolved* form: a named reference becomes
/// one of these at config load, so nothing downstream of the loader ever holds
/// an unresolved reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    pub provider: String,
    pub locator: String,
}

/// Which of the scheme's two forms a `secret://…` string is.
///
/// Produced by [`Reference::parse_form`] / [`Reference::parse_arg_form`]. The
/// plain [`Reference::parse`] returns only the direct form, so every existing
/// caller — including the guest-facing `scoped_agent` path — keeps refusing
/// names unless it opts in by asking for the form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefForm {
    /// `secret://<provider>/<locator>` — resolvable on its own.
    Direct(Reference),
    /// `secret://<name>` — a name declared in the config's `secrets` block.
    Named(String),
}

/// The URI scheme prefix every reference starts with.
pub const SCHEME: &str = "secret://";

/// The error text for a `secret://<name>` naming no declared secret.
///
/// It has to state **both** readings. Before named references existed,
/// `secret://op` failed as a malformed reference — the right diagnosis for the
/// common mistake, which is forgetting the locator. Under the slash rule that
/// same string is now a name, and "unknown named secret `op`" would send a user
/// who mistyped a provider reference off to write a declaration they do not
/// want.
pub fn undeclared_secret_message(name: &str) -> String {
    format!(
        "`{name}` is not a declared secret; if you meant a provider reference it needs a locator (`{SCHEME}{name}/<locator>`)"
    )
}

impl Reference {
    /// Parse a full `secret://provider/locator` reference, or `None` if `input`
    /// is not a well-formed one. Requires the `secret://` scheme — used when
    /// scanning env values, where a bare `provider/locator` must *not* be
    /// mistaken for a reference.
    ///
    /// A named reference (`secret://github_token`) yields `None` here, which is
    /// what keeps every pre-existing caller — the scoped agent's guest-facing
    /// parse above all — refusing names by construction. Ask for
    /// [`Reference::parse_form`] to accept one.
    pub fn parse(input: &str) -> Option<Reference> {
        match Self::parse_form(input)? {
            RefForm::Direct(reference) => Some(reference),
            RefForm::Named(_) => None,
        }
    }

    /// Parse a `secret://…` value into whichever form it is, or `None` if it is
    /// neither.
    pub fn parse_form(input: &str) -> Option<RefForm> {
        let rest = input.strip_prefix(SCHEME)?;
        Self::parse_body(rest)
    }

    /// Parse a `secreq read` argument: either a full `secret://provider/locator`
    /// reference or the bare `provider/locator` shorthand. The scheme is
    /// optional here because the argument position is unambiguous — every
    /// `read` arg is a reference, so there's nothing for a bare locator to be
    /// confused with.
    pub fn parse_arg(input: &str) -> Option<Reference> {
        match Self::parse_arg_form(input)? {
            RefForm::Direct(reference) => Some(reference),
            RefForm::Named(_) => None,
        }
    }

    /// [`Reference::parse_arg`]'s form-preserving twin: the scheme is optional,
    /// and a no-slash argument is a declared secret's name rather than an error.
    pub fn parse_arg_form(input: &str) -> Option<RefForm> {
        let rest = input.strip_prefix(SCHEME).unwrap_or(input);
        Self::parse_body(rest)
    }

    /// Split the part after any scheme prefix. With a `/` it is
    /// `provider/locator` (neither half may be empty); without one it is a
    /// declared secret's name (which may not be empty either).
    fn parse_body(rest: &str) -> Option<RefForm> {
        let Some((provider, locator)) = rest.split_once('/') else {
            if rest.is_empty() {
                return None;
            }
            return Some(RefForm::Named(rest.to_owned()));
        };
        if provider.is_empty() || locator.is_empty() {
            return None;
        }
        Some(RefForm::Direct(Reference {
            provider: provider.to_owned(),
            locator: locator.to_owned(),
        }))
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

/// On disk a [`Reference`] is the string [`Reference::parse`] reads, so that is
/// what the published schema says — with the pattern that parse enforces, so
/// an editor rejects `op/thing` before secreq has to.
///
/// The pattern stays **direct-only**, without the named form. Every field typed
/// as a `Reference` is one that resolves a name rather than holding one — a
/// declaration's own `ref`, and an SSH identity's `private_key` — so admitting
/// `secret://<name>` here would publish a shape the loader refuses. The place a
/// named reference is legal is a wrap's `env` value, whose pattern lives on
/// [`crate::schema::SecretRefMap`] and does admit it.
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
        assert!(Reference::parse("secret://op").is_none()); // a name, not a reference
        assert!(Reference::parse("secret:///locator").is_none()); // empty provider
        assert!(Reference::parse("secret://op/").is_none()); // empty locator
    }

    #[test]
    fn the_slash_is_the_whole_rule_for_telling_the_two_forms_apart() {
        assert_eq!(
            Reference::parse_form("secret://github_token"),
            Some(RefForm::Named("github_token".to_owned()))
        );
        assert_eq!(
            Reference::parse_form("secret://op/Personal/GitHub/token"),
            Some(RefForm::Direct(Reference {
                provider: "op".to_owned(),
                locator: "Personal/GitHub/token".to_owned(),
            }))
        );
    }

    #[test]
    fn the_empty_case_stays_invalid_so_the_rule_is_total() {
        assert!(Reference::parse_form("secret://").is_none());
        assert!(Reference::parse_arg_form("").is_none());
        assert!(Reference::parse_form("nope").is_none());
    }

    #[test]
    fn parse_refuses_a_named_reference_so_pre_existing_callers_still_do() {
        // The guest-facing `scoped_agent` parse is one of these: admitting a
        // name there would change what the host-declared scope is a scope
        // *of*, so the safe default is that only callers asking for the form
        // ever see one.
        assert!(Reference::parse("secret://github_token").is_none());
        assert!(Reference::parse_arg("github_token").is_none());
    }

    #[test]
    fn the_undeclared_name_message_states_both_readings() {
        let msg = undeclared_secret_message("op");
        assert!(msg.contains("not a declared secret"), "{msg}");
        assert!(msg.contains("secret://op/<locator>"), "{msg}");
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
        assert!(Reference::parse_arg("noslash").is_none()); // a name, not a reference
        assert!(Reference::parse_arg("/locator").is_none()); // empty provider
        assert!(Reference::parse_arg("op/").is_none()); // empty locator
        assert!(Reference::parse_arg("secret://op").is_none()); // a name again
    }
}
