//! Auto-approve / auto-deny rules — persisted policy evaluated before the
//! consent prompt fires.
//!
//! See `brain: areas/secreq/design/2026-06-02-auto-rules.md` for the design.
//!
//! ## Trust model
//!
//! Rules **survive daemon restarts**, in deliberate contrast to the
//! in-memory approvals cache in [`crate::consent`] (whose lifetime is
//! the daemon process). The user's awareness invariant is enforced
//! differently here:
//!
//! 1. Rules are created from the UI's Rules tab (or via CLI verbs),
//!    never implicitly from a live ask.
//! 2. The daemon checks the rules file's mtime before each evaluation;
//!    when it has advanced past the daemon's startup mtime, the daemon
//!    shuts down so the next ask respawns it with fresh rules — the
//!    same "restart is the revoke primitive" semantics documented in
//!    `consent.rs:11`.
//! 3. Auto-decisions show up in the audit log under distinct
//!    [`crate::consent::Decision`] variants (`ApproveAuto` /
//!    `DenyAuto`) with the firing rule's id, so the audit pill is
//!    self-describing.
//! 4. Each rule carries a `trained_secrets` snapshot of the env-var
//!    names it was created against; the evaluator refuses to fire if
//!    the live ask requests anything outside that set. This prevents
//!    a rule from silently auto-releasing newly-added env vars when
//!    the user edits a wrap.
//!
//! ## Layering
//!
//! This module deliberately avoids `crate::daemon::proto` so the
//! evaluator is unit-testable without spinning up wire types. The
//! caller in `daemon::server` builds an [`EvalCtx`] from an `Ask` and
//! passes it in.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::wasm_rules::{Decision as WasmDecision, RuleModule};

/// Taplo schema directive written at the top of `auto-rules.toml`.
pub const AUTO_RULES_SCHEMA_URL: &str =
    "https://craigory.dev/secreq/schemas/auto-rules.schema.json";

/// One persisted rule: the fields every rule carries, plus a [`RuleBody`]
/// holding the half that differs between the two kinds.
///
/// The declarative-XOR-wasm shape is the *type*, not a runtime check —
/// there is no way to hold a rule that is both, or neither. The file on
/// disk still has to be checked, and it is: `Rule` deserializes through
/// [`RuleWire`], so a malformed rule is rejected once, at the parse, with
/// an error naming the rule and the offending field.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(try_from = "RuleWire", into = "RuleWire")]
pub struct Rule {
    /// Stable identifier. Generated once on creation, never mutated.
    /// Surfaces in the audit log so users can trace which rule fired.
    pub id: String,
    /// Human label shown in the UI and the audit pill.
    pub name: String,
    /// `false` ⇒ rule is in the file but the evaluator skips it. Used
    /// for "pause this rule without losing the configuration."
    pub enabled: bool,
    /// Env var names the rule was created against. The evaluator
    /// refuses to fire if the live ask requests any name outside this
    /// set — the trained-secrets guard. **Empty set means the guard
    /// is disabled**, which is the legitimate behavior for hand-edited
    /// rules where the user has explicitly opted out. UI-created rules
    /// always populate it.
    pub trained_secrets: BTreeSet<String>,
    /// Seconds since the Unix epoch at creation time. Informational
    /// (lets the UI show "created 3 days ago").
    pub created_at_unix: u64,
    /// What decides this rule: a match clause carrying a static
    /// decision, or a compiled module.
    pub body: RuleBody,
}

/// The two rule kinds, and the fields that belong to each.
///
/// - **Declarative**: a match clause plus the static decision it carries.
/// - **Wasm**: a compiled rule module evaluated in the sandbox of
///   [`crate::wasm_rules`]. The decision is whatever the module *returns*
///   at evaluation time (approve / pass / deny-with-reason), so a static
///   `decide` or `deny_message` would be dead weight at best and
///   misleading at worst — the deserializer rejects them loudly rather
///   than silently ignoring them.
// `Declarative` is ~290 bytes to `Wasm`'s 48, which trips
// `large_enum_variant`. Boxing the match clause is not the win it looks
// like: the flat `Rule` this replaced carried the same `RuleMatch` inline
// *and* the wasm reference beside it, so every rule is smaller now than it
// was, and the ruleset is a `Vec` of tens of entries loaded once per daemon
// start. An allocation per declarative rule buys nothing measurable and
// costs a `Box::new` at every construction site.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq)]
pub enum RuleBody {
    Declarative {
        r#match: RuleMatch,
        /// The rule's decision whenever the match clause fires — and,
        /// on the deny side, the message that explains it.
        decide: StaticDecision,
    },
    Wasm(WasmRule),
}

/// What a declarative rule does when its match clause fires.
///
/// The deny message lives **inside** `Deny` because an approve has
/// nothing to explain: nobody is being refused, so there is no place in
/// the UI or on a wrap's stderr where the string could appear. Holding
/// it beside `decide` made "approve, with a reason for denying"
/// representable, and three separate places — the evaluator, the UI
/// form, the CLI's `rules show` — each dropped it by hand.
///
/// A *file* may still say both, because files on disk do and refusing
/// to load one would break a configuration that works today. That is
/// resolved on the way in, not in the type: [`load_rules`] records a
/// [`StrayDenyMessage`] and warns by file and rule name, and the next
/// write drops the key.
#[derive(Debug, Clone, PartialEq)]
pub enum StaticDecision {
    Approve,
    Deny {
        /// Message shown to the user on auto-deny — the wrap client
        /// prints it to stderr, the consent window renders it in a
        /// toast row. `None` denies without elaborating.
        message: Option<String>,
    },
}

impl StaticDecision {
    /// The direction alone, for the audit pill and [`RuleHit`].
    pub fn decision(&self) -> RuleDecision {
        match self {
            StaticDecision::Approve => RuleDecision::Approve,
            StaticDecision::Deny { .. } => RuleDecision::Deny,
        }
    }

    /// The configured deny message, if this is a deny that carries one.
    pub fn deny_message(&self) -> Option<&str> {
        match self {
            StaticDecision::Approve => None,
            StaticDecision::Deny { message } => message.as_deref(),
        }
    }
}

impl From<RuleDecision> for StaticDecision {
    /// The direction with no message yet — the inverse of
    /// [`StaticDecision::decision`], for a caller that has picked which
    /// way a rule fires before it has anything to say about it.
    fn from(decide: RuleDecision) -> StaticDecision {
        match decide {
            RuleDecision::Approve => StaticDecision::Approve,
            RuleDecision::Deny => StaticDecision::Deny { message: None },
        }
    }
}

/// A rule's published schema is [`RuleWire`]'s, whole — the same delegation
/// serde already does through `try_from`/`into`.
///
/// Written out rather than `schemars(with = "RuleWire")` because the derive
/// would also stamp *this* type's doc comment over the definition's
/// `description`, and this one is written for a contributor reading the sum
/// type, not for someone editing `auto-rules.toml`.
#[cfg(feature = "schema")]
impl schemars::JsonSchema for Rule {
    fn inline_schema() -> bool {
        RuleWire::inline_schema()
    }

    fn schema_name() -> std::borrow::Cow<'static, str> {
        RuleWire::schema_name()
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        RuleWire::schema_id()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        RuleWire::json_schema(generator)
    }
}

impl Rule {
    /// Does this rule's decision come from a compiled module?
    pub fn is_wasm(&self) -> bool {
        matches!(self.body, RuleBody::Wasm(_))
    }

    /// The module reference, for a wasm rule.
    pub fn wasm(&self) -> Option<&WasmRule> {
        match &self.body {
            RuleBody::Wasm(wasm) => Some(wasm),
            RuleBody::Declarative { .. } => None,
        }
    }
}

/// One auto-decision rule. Exactly one of two shapes: declarative (`decide` +
/// `match`, `wasm` absent) or wasm (`wasm` alone — the compiled module returns
/// approve/pass/deny at evaluation time, so `decide` and `deny_message` must be
/// absent).
//
// That is written for the reader of `docs/auto-rules.schema.json`, because
// this type is what generates it: `RuleWire` is the flat object users
// hand-edit, and every `///` below is published as that property's
// `description`. The declarative-XOR-wasm constraint, which no combination of
// `Option`s expresses, is the `oneOf` in `extend`.
//
// The type exists so [`Rule`] can be a sum type *and* leave the file format
// exactly where it is. The two obvious alternatives both move it.
// `#[serde(flatten)]` writes the flattened keys last, shuffling
// `decide`/`match` past `created_at_unix` in every newly-written rule.
// `#[serde(untagged)]`
// matches the first variant that fits and **drops the leftover keys**, so a
// wasm rule carrying `decide: "deny"` would load as "whatever the module
// returns" where today it is a loud error; `deny_unknown_fields` cannot be
// combined with `flatten` to rescue it.
//
// Field order here is the written key order — see
// `a_rule_is_written_in_this_key_order`.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(rename = "Rule", deny_unknown_fields))]
#[cfg_attr(feature = "schema", schemars(extend("oneOf" = rule_one_of())))]
pub(crate) struct RuleWire {
    /// Stable identifier (12 random bytes as lowercase hex, generated by
    /// `secreq` when the rule is created). Never re-mint for an existing rule
    /// — it surfaces in the audit log.
    id: String,
    /// Human label shown in the UI and the audit pill.
    name: String,
    /// `false` ⇒ rule is in the file but the evaluator skips it. Used for
    /// "pause this rule without losing the configuration".
    enabled: bool,
    /// Direction a declarative rule fires when it matches. Among matching
    /// rules, any deny wins; otherwise the most-specific approve wins (a wasm
    /// rule that returns a decision counts as maximally specific). Forbidden
    /// on wasm rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    decide: Option<RuleDecision>,
    #[serde(rename = "match", default, skip_serializing_if = "Option::is_none")]
    r#match: Option<RuleMatch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    wasm: Option<WasmRule>,
    /// Snapshot of env-var names the rule was created against. The rule will
    /// NOT fire if the ask requests anything outside this set — the
    /// trained-secrets guard, applied to declarative and wasm rules alike (a
    /// wasm module is never even run for an out-of-snapshot ask). An empty
    /// array disables the guard, which is legitimate for a hand-edited rule.
    #[serde(default)]
    trained_secrets: BTreeSet<String>,
    /// Message printed to stderr on auto-deny and shown in the consent
    /// window's toast. Belongs to `decide: deny`: an approve rule refuses
    /// nobody, so a `deny_message` beside `decide: approve` is ignored, warned
    /// about by rule name in the daemon log, and removed the next time secreq
    /// writes the file. Forbidden outright on wasm rules — the module returns
    /// its own reason.
    //
    // Skipped when absent so saved rules validate against the schema (which
    // types it as a string, and forbids the key entirely on wasm rules).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    deny_message: Option<String>,
    /// Seconds since the Unix epoch at creation. Informational only.
    #[serde(default)]
    created_at_unix: u64,
}

impl TryFrom<RuleWire> for Rule {
    type Error = anyhow::Error;

    /// Enforce declarative-XOR-wasm once, where the untrusted bytes come
    /// in. Every rejection names the rule and the field that made it
    /// wrong, because the reader is whoever hand-edited the file.
    fn try_from(wire: RuleWire) -> Result<Rule> {
        let label = format!("rule `{}` (id {})", wire.name, wire.id);
        let body = match (wire.wasm, wire.r#match) {
            (Some(_), Some(_)) => bail!(
                "{label} has both a `match` clause and a `wasm` module — a rule \
                 is either declarative (`decide` + `match`) or wasm (`wasm` \
                 alone); split it into two rules"
            ),
            (None, None) => bail!(
                "{label} has neither a `match` clause nor a `wasm` module — a \
                 rule must be declarative (`decide` + `match`) or wasm (`wasm`)"
            ),
            (Some(wasm), None) => {
                if wire.decide.is_some() {
                    bail!(
                        "{label} is a wasm rule but sets `decide` — a wasm rule's \
                         decision is whatever its module returns at evaluation \
                         time; remove `decide`"
                    );
                }
                if wire.deny_message.is_some() {
                    bail!(
                        "{label} is a wasm rule but sets `deny_message` — a wasm \
                         deny carries the reason returned by the module; remove \
                         `deny_message`"
                    );
                }
                RuleBody::Wasm(wasm)
            }
            (None, Some(r#match)) => {
                let Some(decide) = wire.decide else {
                    bail!("{label} has a `match` clause but no `decide` (approve or deny)");
                };
                // An approve's `deny_message` is dropped here rather
                // than refused: files carrying one load today, and
                // breaking them would be a worse trade than losing a
                // string that could never have been shown. The drop is
                // not silent — `load_rules` spots it on the wire first
                // and warns by file and rule. See [`StrayDenyMessage`].
                let decide = match decide {
                    RuleDecision::Approve => StaticDecision::Approve,
                    RuleDecision::Deny => StaticDecision::Deny {
                        message: wire.deny_message,
                    },
                };
                RuleBody::Declarative { r#match, decide }
            }
        };
        Ok(Rule {
            id: wire.id,
            name: wire.name,
            enabled: wire.enabled,
            trained_secrets: wire.trained_secrets,
            created_at_unix: wire.created_at_unix,
            body,
        })
    }
}

impl From<Rule> for RuleWire {
    fn from(rule: Rule) -> RuleWire {
        let (decide, r#match, wasm, deny_message) = match rule.body {
            RuleBody::Declarative { r#match, decide } => match decide {
                StaticDecision::Approve => (Some(RuleDecision::Approve), Some(r#match), None, None),
                StaticDecision::Deny { message } => {
                    (Some(RuleDecision::Deny), Some(r#match), None, message)
                }
            },
            RuleBody::Wasm(wasm) => (None, None, Some(wasm), None),
        };
        RuleWire {
            id: rule.id,
            name: rule.name,
            enabled: rule.enabled,
            decide,
            r#match,
            wasm,
            trained_secrets: rule.trained_secrets,
            deny_message,
            created_at_unix: rule.created_at_unix,
        }
    }
}

/// The `oneOf` that pins declarative-XOR-wasm in the published schema.
///
/// Lives beside [`TryFrom<RuleWire> for Rule`], which refuses exactly these
/// shapes at the parse, because the two are one rule stated twice: an editor
/// validating against the schema and secreq loading the file have to agree on
/// which rules are legal, and they only do if this moves when that does.
///
/// No `Option` combination expresses it, which is why it is written out rather
/// than derived — everything else in the definition comes from the fields.
#[cfg(feature = "schema")]
pub(crate) fn rule_one_of() -> serde_json::Value {
    serde_json::json!([
        {
            "description": "Declarative rule: static decide + match clause.",
            "required": ["decide", "match"],
            "not": { "required": ["wasm"] }
        },
        {
            "description": "Wasm rule: the module decides. `decide`/`match`/`deny_message` are forbidden — the decision (and any deny reason) is the module's return value.",
            "required": ["wasm"],
            "allOf": [
                { "not": { "required": ["decide"] } },
                { "not": { "required": ["match"] } },
                { "not": { "required": ["deny_message"] } }
            ]
        }
    ])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum RuleDecision {
    Approve,
    Deny,
}

/// Reference to a compiled wasm rule module, evaluated in the secreq sandbox
/// (no WASI, fuel-metered, memory-capped). The module exports `decide(ctx)`
/// returning approve, pass (rule does not match), or deny with a reason. A
/// runtime error makes the rule not match — the ask falls through to the
/// interactive prompt, never to an auto-approve.
//
// The module bytes live on disk (canonically `rules/<id>.wasm` under the
// secreq root — see [`crate::paths::rule_wasm_path`]); the rules file pins
// them by content hash.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(deny_unknown_fields))]
pub struct WasmRule {
    /// Path to the compiled `.wasm` module. Relative paths resolve against the
    /// directory containing `auto-rules.toml`; the canonical home is
    /// `rules/<id>.wasm` under the secreq root.
    pub path: String,
    /// Hex SHA-256 of the module bytes, recorded at registration and verified
    /// on every load. A mismatch refuses this rule (it can never fire) with a
    /// loud daemon-log error; other rules keep working.
    #[cfg_attr(feature = "schema", schemars(regex(pattern = r"^[0-9a-fA-F]{64}$")))]
    pub sha256: String,
}

/// Why a wasm rule was refused, coarse enough for a one-word list
/// marker. The full reason string lives on [`WasmRefusal::reason`];
/// this enum exists so `rules list` and the UI badge can say *what
/// kind* of refusal happened without parsing prose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WasmRefusalCategory {
    /// The referenced module file could not be read.
    MissingModule,
    /// The module bytes hash to something other than the recorded
    /// sha256 — the module changed since registration.
    Sha256Mismatch,
    /// The module was read and hash-verified but the sandbox rejected
    /// it (bad imports, wrong abort signature, oversized memory,
    /// missing exports, …).
    ModuleRejected,
}

impl WasmRefusalCategory {
    /// Short human label for compact display (`rules list`, UI badge).
    pub fn label(self) -> &'static str {
        match self {
            WasmRefusalCategory::MissingModule => "module missing",
            WasmRefusalCategory::Sha256Mismatch => "sha256 mismatch",
            WasmRefusalCategory::ModuleRejected => "module rejected",
        }
    }
}

/// One wasm rule refused at load time, retained so the refusal is
/// visible outside the daemon log: `rules list`/`show` and the UI
/// badge all render from this. Value-free by construction — `reason`
/// names rules, files, and hashes, never secret values.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WasmRefusal {
    /// Id of the refused rule (it stays in the ruleset, module-less,
    /// so it can never fire).
    pub rule_id: String,
    pub category: WasmRefusalCategory,
    /// Full formatted error chain naming the rule and module path.
    pub reason: String,
}

/// Which clause of a [`RuleMatch`] a [`PatternRefusal`] came from.
/// `wrap` is absent on purpose: it is an exact string, never a glob, and
/// so has nothing to refuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PatternField {
    Argv,
    Ancestor,
    Cwd,
}

impl PatternField {
    /// The field's name as it is spelled in the rules file — which is
    /// the only name the operator has for it.
    pub fn as_str(self) -> &'static str {
        match self {
            PatternField::Argv => "argv",
            PatternField::Ancestor => "ancestor",
            PatternField::Cwd => "cwd",
        }
    }
}

/// One match pattern that would not compile as a glob, retained so the
/// refusal is visible where the rule is: `rules list`/`show` and the UI
/// badge render from this, exactly as they do from [`WasmRefusal`].
///
/// Value-free by construction — it names a rule, a field and the
/// operator's own pattern text, never a secret.
///
/// One entry **per broken clause**, not per rule: a rule with a typo in
/// both `argv` and `cwd` has two things wrong with it and a reader
/// fixing one should still see the other.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PatternRefusal {
    /// Id of the rule carrying it (the rule stays in the ruleset).
    pub rule_id: String,
    pub field: PatternField,
    /// The pattern's source text, verbatim.
    pub pattern: String,
    /// Operator-facing explanation: the glob parser's complaint plus
    /// what the rule now does instead. See [`pattern_refusals`].
    pub reason: String,
}

impl PatternRefusal {
    /// Short human label for compact display (`rules list`, UI badge),
    /// in the same register as [`WasmRefusalCategory::label`].
    pub fn label(&self) -> String {
        format!("bad {} glob", self.field.as_str())
    }
}

/// What a refused pattern costs the operator, which is not the same
/// thing for the two decisions — and the operator is the one who has to
/// act on the difference.
///
/// A broken **deny** fails open: secreq cannot tell whether the block
/// applies, so the ask goes to the human rather than to a competing
/// approve. A broken **approve** fails closed: it simply never fires.
///
/// Shared with the rule form in `daemon::ui`, which refuses the same
/// patterns at authoring time and quotes this same sentence — the two
/// surfaces disagreeing about what a broken glob costs would be worse
/// than either of them saying nothing.
pub fn refused_pattern_consequence(decision: RuleDecision) -> &'static str {
    match decision {
        RuleDecision::Deny => {
            "this rule cannot be evaluated, so every ask it might have \
             denied now goes to the consent prompt instead of being \
             released by another rule's approve"
        }
        RuleDecision::Approve => {
            "this rule never fires; asks it was meant to approve prompt \
             as they did before it was written"
        }
    }
}

/// Every refused pattern across `rules`, in rule order and then clause
/// order.
///
/// A pure function of the ruleset, and deliberately not stored anywhere:
/// unlike a [`WasmRefusal`], which depends on bytes on disk that can
/// change under a rule that did not, a pattern refusal depends on
/// nothing but the rule's own text. Recomputing it is cheaper than the
/// bookkeeping that would keep a cached copy honest across
/// add/update/delete.
pub fn pattern_refusals(rules: &[Rule]) -> Vec<PatternRefusal> {
    let mut out = Vec::new();
    for rule in rules {
        let RuleBody::Declarative { r#match, decide } = &rule.body else {
            // A wasm rule has no match clause; its module decides.
            continue;
        };
        for (field, pattern) in [
            (PatternField::Argv, r#match.argv.as_ref()),
            (PatternField::Ancestor, r#match.ancestor.as_ref()),
            (PatternField::Cwd, r#match.cwd.as_ref()),
        ] {
            let Some(pattern) = pattern else { continue };
            let Some(err) = pattern.invalid_reason() else {
                continue;
            };
            let consequence = refused_pattern_consequence(decide.decision());
            out.push(PatternRefusal {
                rule_id: rule.id.clone(),
                field,
                pattern: pattern.as_str().to_owned(),
                reason: format!(
                    "rule `{}` (id {}): the `{}` pattern `{}` is not a valid glob \
                     ({err}) — {consequence}",
                    rule.name,
                    rule.id,
                    field.as_str(),
                    pattern.as_str(),
                ),
            });
        }
    }
    out
}

/// Every reason a rule in the current ruleset cannot fire as written.
///
/// The two kinds travel together because every consumer wants both:
/// `rules list`, `rules show`, the `RulesList` reply, the wire snapshot
/// and the Rules-tab badge each ask one question — "is there anything
/// wrong with this rule?" — and answering it from two parallel slices is
/// how one of them ends up unrendered.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RuleRefusals {
    /// Wasm rules refused at load time (missing module, sha256
    /// mismatch, sandbox rejection).
    #[serde(default)]
    pub wasm: Vec<WasmRefusal>,
    /// Match patterns that would not compile as globs.
    #[serde(default)]
    pub patterns: Vec<PatternRefusal>,
}

impl RuleRefusals {
    /// Everything recorded against one rule, as `(label, reason)` pairs
    /// ready for a badge. A declarative rule can only produce pattern
    /// refusals and a wasm rule only a wasm refusal, so in practice this
    /// yields one kind or the other — but the caller should not have to
    /// know that to render it.
    pub fn for_rule(&self, rule_id: &str) -> Vec<(String, &str)> {
        self.wasm
            .iter()
            .filter(|r| r.rule_id == rule_id)
            .map(|r| (r.category.label().to_owned(), r.reason.as_str()))
            .chain(
                self.patterns
                    .iter()
                    .filter(|r| r.rule_id == rule_id)
                    .map(|r| (r.label(), r.reason.as_str())),
            )
            .collect()
    }

    pub fn is_empty(&self) -> bool {
        self.wasm.is_empty() && self.patterns.is_empty()
    }
}

/// The ruleset as a reader sees it: the rules themselves plus every
/// refusal recorded against them.
///
/// Named because it is the reply to `rules list` and the two halves are
/// not interchangeable — a bare `(Vec<Rule>, Vec<WasmRefusal>)` return
/// says nothing about which is which, and it grew a third member the
/// moment patterns could be refused too.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RuleListing {
    pub rules: Vec<Rule>,
    #[serde(default)]
    pub refusals: RuleRefusals,
}

/// Error from [`load_rule_module`]: the anyhow chain plus the coarse
/// [`WasmRefusalCategory`] the refusal surfaces under. Converts into
/// `anyhow::Error` (dropping the category) for mutation paths that
/// abort outright rather than retaining refusal state.
#[derive(Debug)]
pub struct WasmLoadError {
    pub category: WasmRefusalCategory,
    pub source: anyhow::Error,
}

impl From<WasmLoadError> for anyhow::Error {
    fn from(err: WasmLoadError) -> Self {
        err.source
    }
}

/// Lowercase-hex SHA-256 of `bytes`. Used to pin wasm rule modules in
/// the rules file and to verify them on every load.
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(&mut s, "{b:02x}");
            s
        })
}

/// Read, hash-verify, and compile the wasm module for `rule`. Returns
/// `Ok(None)` for declarative rules. `rules_dir` is the directory
/// containing the rules file — relative module paths resolve against
/// it. Every failure (missing file, sha256 mismatch, compile/sandbox
/// rejection) is an error naming the rule and the module path.
pub fn load_rule_module(
    rule: &Rule,
    rules_dir: &Path,
) -> Result<Option<RuleModule>, WasmLoadError> {
    let RuleBody::Wasm(wasm) = &rule.body else {
        return Ok(None);
    };
    let path = rules_dir.join(&wasm.path);
    let bytes = std::fs::read(&path)
        .with_context(|| {
            format!(
                "read wasm module for rule `{}` (id {}): {}",
                rule.name,
                rule.id,
                path.display()
            )
        })
        .map_err(|source| WasmLoadError {
            category: WasmRefusalCategory::MissingModule,
            source,
        })?;
    let actual = sha256_hex(&bytes);
    if !actual.eq_ignore_ascii_case(&wasm.sha256) {
        return Err(WasmLoadError {
            category: WasmRefusalCategory::Sha256Mismatch,
            source: anyhow::anyhow!(
                "sha256 mismatch for wasm rule `{}` (id {}): {} hashes to {actual} \
                 but the rules file expects {} — the module changed since the rule \
                 was registered; refusing to load this rule",
                rule.name,
                rule.id,
                path.display(),
                wasm.sha256,
            ),
        });
    }
    let module = RuleModule::from_binary(&bytes)
        .with_context(|| {
            format!(
                "compile wasm module for rule `{}` (id {}): {}",
                rule.name,
                rule.id,
                path.display()
            )
        })
        .map_err(|source| WasmLoadError {
            category: WasmRefusalCategory::ModuleRejected,
            source,
        })?;
    Ok(Some(module))
}

/// The match clause. All present fields must match (logical AND); absent
/// fields are unconstrained ("any"). `wrap` is required and exact; the rest are
/// patterns: glob if they contain `*`, `?`, or `[`, otherwise literal. A
/// literal `argv` matches as a plain prefix; a literal `cwd` matches as a
/// path-segment-aware prefix; a literal `ancestor` matches as a substring
/// against the caller's executable path (friendlier for `.app` bundle names,
/// and not self-reported).
//
// These doc comments are the published contract: `schema.rs` derives
// `docs/auto-rules.schema.json` from this type, and every `///` below reaches
// secreq.dev as that field's `description`. Two of them have already been
// wrong in print — write them as claims you would have to defend.
//
// The evaluator's side of each clause: `argv` reads `ask.command.join(" ")`,
// `cwd` reads `ask.cwd`, and `ancestor` walks the caller chain through
// [`Pattern::matches_ancestor`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(deny_unknown_fields))]
pub struct RuleMatch {
    /// Wrap name (exact match).
    pub wrap: String,
    /// Pattern against the joined argv of the wrapped command (`secreq`
    /// reconstructs this as `command.join(" ")`). A literal matches as a plain
    /// prefix — argv has no segment structure to respect, so `gh api` is meant
    /// to match `gh api --get /repos/x`.
    #[serde(default)]
    pub argv: Option<Pattern>,
    /// Pattern matched against each caller in the process tree; the clause
    /// matches if ANY caller satisfies it. Tested against the caller's
    /// executable path as the kernel reports it (e.g.
    /// `/Applications/Cursor.app/Contents/MacOS/Cursor`). Only when the kernel
    /// gives no `exe` does it fall back to the process's self-reported short
    /// name (typically the basename, like `zsh` or `Cursor`) and its joined
    /// command line. Preferring `exe` is what stops a process from satisfying
    /// `ancestor: "Cursor.app"` by putting that text in an argv it chose for
    /// itself. Substring match for literals, full-string glob for wildcards.
    #[serde(default)]
    pub ancestor: Option<Pattern>,
    /// Pattern against the requesting process's current working directory. A
    /// literal matches as a path-segment-aware prefix: it must cover the whole
    /// path or stop on a `/` boundary, so `/Users/me/oss` matches
    /// `/Users/me/oss` and `/Users/me/oss/pkg` but NOT `/Users/me/ossuary`. A
    /// trailing `/` on the pattern is optional and means the same thing. A glob
    /// is matched against the whole path.
    #[serde(default)]
    pub cwd: Option<Pattern>,
}

/// A match pattern. A string with no wildcard chars (`*`, `?`, `[`)
/// is a **literal**; otherwise it's a **glob**.
///
/// Literals match by *prefix* for argv/cwd and by *substring* for
/// ancestor. Globs use [`glob::Pattern`] semantics regardless of which
/// field they're matched against.
///
/// A wildcard string [`glob::Pattern`] refuses is neither: it is
/// [refused](PatternRefusal), matches nothing, and is reported. See
/// [`Pattern::parse`].
///
/// Serializes as the raw source string, refused or not. A pattern secreq could
/// not consult is the last thing it should silently correct during an edit.
#[derive(Debug, Clone)]
pub struct Pattern {
    raw: String,
    kind: PatternKind,
}

#[derive(Debug, Clone)]
enum PatternKind {
    Literal,
    Glob(glob::Pattern),
    /// The source text used wildcard syntax and `glob` would not compile
    /// it. Carries the parser's message so the refusal can quote it.
    Invalid(String),
}

impl Pattern {
    /// Parse a pattern string. A string with no wildcard char is a
    /// literal; one `glob` accepts is a glob; one `glob` **rejects** is
    /// refused and matches nothing.
    ///
    /// This used to re-read a broken glob as a literal, on the grounds
    /// that "rule too narrow" is the safe failure. That is true of an
    /// approve and false of a deny, which is the whole problem: an
    /// operator's `deny` on `gh api /repos/*/actions/secrets*[` became a
    /// literal matching a command nobody runs, so the deny covered
    /// nothing, a broader approve carried the ask, and the rule still
    /// read correct in the file. Nothing said a word.
    ///
    /// Refusing is not merely louder, it is also *narrower in the same
    /// direction the fallback already was*: a literal built from glob
    /// syntax matches essentially nothing anyway. What changes is that
    /// the nothing is now recorded ([`pattern_refusals`], the Rules tab
    /// badge) and that a refused **deny** takes the ask to the human
    /// rather than leaving it to a competing approve — see
    /// [`evaluate`].
    pub fn parse(raw: impl Into<String>) -> Pattern {
        let raw = raw.into();
        let kind = if has_wildcards(&raw) {
            match glob::Pattern::new(&raw) {
                Ok(g) => PatternKind::Glob(g),
                Err(err) => PatternKind::Invalid(err.to_string()),
            }
        } else {
            PatternKind::Literal
        };
        Pattern { raw, kind }
    }

    /// The pattern's source text (round-trips through serialization).
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// The glob parser's complaint, when this pattern was refused;
    /// `None` for a pattern that compiled (or never needed to).
    pub fn invalid_reason(&self) -> Option<&str> {
        match &self.kind {
            PatternKind::Invalid(err) => Some(err),
            PatternKind::Literal | PatternKind::Glob(_) => None,
        }
    }

    /// Whether this pattern can be consulted at all. A `true` here is
    /// what turns a rule's clause from a predicate into an unknown; see
    /// [`ClauseOutcome`].
    pub fn is_invalid(&self) -> bool {
        self.invalid_reason().is_some()
    }

    /// Match for the argv field. Literal = prefix; glob = full pattern
    /// match.
    ///
    /// Raw byte prefixing is correct here and deliberate: `gh api` should
    /// match `gh api --get /repos/x`, and argv has no segment structure to
    /// respect. Paths do — see [`Pattern::matches_path_prefix`].
    pub fn matches_prefix(&self, s: &str) -> bool {
        match &self.kind {
            PatternKind::Literal => s.starts_with(&self.raw),
            PatternKind::Glob(g) => g.matches(s),
            PatternKind::Invalid(_) => false,
        }
    }

    /// Match for the `cwd` field. Literal = **path-segment-aware** prefix;
    /// glob = full pattern match.
    ///
    /// A literal here must match whole path segments. Plain `starts_with`
    /// would let `cwd: "/Users/me/oss"` match `/Users/me/ossuary` and
    /// `/Users/me/oss-scratch` — directories the user never named, matched by
    /// a rule they believed was scoped to one checkout. So a literal matches
    /// only when it covers `s` exactly or stops on a `/` boundary.
    ///
    /// A trailing `/` on the pattern is tolerated so a hand-written
    /// `~/oss/` and `~/oss` mean the same thing; without this they would
    /// differ, and the one that reads as "more explicitly a directory" would
    /// be the one that failed to match the directory itself.
    pub fn matches_path_prefix(&self, s: &str) -> bool {
        match &self.kind {
            PatternKind::Glob(g) => g.matches(s),
            PatternKind::Invalid(_) => false,
            PatternKind::Literal => {
                let want = self.raw.strip_suffix('/').unwrap_or(&self.raw);
                // An empty pattern (or bare "/") constrains nothing beyond
                // "is a path", which every cwd is.
                if want.is_empty() {
                    return true;
                }
                let Some(rest) = s.strip_prefix(want) else {
                    return false;
                };
                rest.is_empty() || rest.starts_with('/')
            }
        }
    }

    /// Match one caller for the `ancestor` field.
    ///
    /// Tested against the caller's **`exe`** when the kernel gave one, and
    /// against its self-reported `name`/`command` only when it did not.
    ///
    /// The pair is attacker-chosen: a process sets `comm` on itself and picks
    /// its own argv, so `ancestor: "Cursor.app"` — the example in the docs,
    /// the tests and the schema — used to be satisfied by any process that
    /// merely put that text in its command line. The canonical example still
    /// works against the path, because
    /// `/Applications/Cursor.app/Contents/MacOS/Cursor` *is* the exe.
    pub fn matches_ancestor(&self, caller: &EvalCaller<'_>) -> bool {
        match caller.exe {
            Some(exe) => self.matches_substring(exe),
            None => self.matches_substring(caller.name) || self.matches_substring(caller.command),
        }
    }

    /// Substring (literal) or full-pattern (glob) match. Substring is
    /// friendlier than prefix for matching `.app` bundle names inside a
    /// noisy path like
    /// `/Applications/Cursor.app/Contents/MacOS/Cursor --psn_0_12345`.
    pub fn matches_substring(&self, s: &str) -> bool {
        match &self.kind {
            PatternKind::Literal => s.contains(&self.raw),
            PatternKind::Glob(g) => g.matches(s),
            PatternKind::Invalid(_) => false,
        }
    }
}

impl PartialEq for Pattern {
    fn eq(&self, other: &Self) -> bool {
        // Source text is the canonical identity; the parsed Glob/Literal
        // is derived, so comparing raw strings is sufficient and lets us
        // skip implementing PartialEq for `glob::Pattern` (which doesn't
        // derive it upstream).
        self.raw == other.raw
    }
}

impl Serialize for Pattern {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.raw)
    }
}

/// A pattern is a bare string on disk, and inlined rather than referenced so
/// each clause's own `description` stays attached to it — a `$ref` with a
/// sibling `description` is not legal draft-07, and schemars would wrap it in
/// an `allOf` to say the same thing at three times the width.
#[cfg(feature = "schema")]
impl schemars::JsonSchema for Pattern {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Pattern".into()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        String::json_schema(generator)
    }
}

impl<'de> Deserialize<'de> for Pattern {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        Ok(Pattern::parse(raw))
    }
}

fn has_wildcards(s: &str) -> bool {
    s.chars().any(|c| matches!(c, '*' | '?' | '['))
}

/// Persisted auto-approve / auto-deny rules for `secreq`
/// (`~/.secreq/auto-rules.toml`, or `$SECREQ_HOME/auto-rules.toml`). Owned by
/// the consent daemon; clients normally don't edit the file directly.
//
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(title = "secreq auto-rules config"))]
#[cfg_attr(feature = "schema", schemars(extend("$id" = crate::schema::AUTO_RULES_ID)))]
#[cfg_attr(feature = "schema", schemars(deny_unknown_fields))]
pub struct RulesFile {
    /// Ordered list of rules. Order does not affect precedence (deny-wins,
    /// then most-specific approve), but is preserved on read/write so
    /// hand-edits stay stable.
    #[serde(default)]
    pub rules: Vec<Rule>,
}

/// The same file, read one layer lower: rules still in their
/// [`RuleWire`] form. [`load_rules`] parses through this rather than
/// straight into [`Rule`] so it can see the `deny_message` an approve
/// rule wrote *before* the conversion drops it, and name the rule in the
/// warning. The shape check is unchanged — it still runs in
/// `TryFrom<RuleWire> for Rule`, one line later.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RulesFileWire {
    #[serde(default)]
    rules: Vec<RuleWire>,
}

/// A `deny_message` found on a rule that decides `approve`, and can
/// therefore never show it.
///
/// The file is accepted — one that says both loads today, and refusing
/// it would invalidate a working configuration — but the key is dropped
/// on the way in and gone the next time the daemon writes the file.
/// **That drop must never be silent**, which is what this type is for:
/// [`load_rules`] records one per offending rule and warns through the
/// daemon log with [`stray_deny_message_warning`], naming the file and
/// the rule. A quietly-vanishing policy field is the failure mode this
/// module's deserializer is built to avoid, not one to introduce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrayDenyMessage {
    pub rule_id: String,
    pub rule_name: String,
}

/// The operator-facing warning for one [`StrayDenyMessage`]. Pure, so
/// the wording is testable, and one line so it sits in `daemon.log`
/// beside the other rules-load warnings.
pub fn stray_deny_message_warning(path: &Path, stray: &StrayDenyMessage) -> String {
    format!(
        "{}: rule `{}` (id {}) decides `approve` but sets `deny_message` — \
         an approve refuses nobody, so the message is ignored now and will be \
         removed the next time secreq writes this file. Change `decide` to \
         \"deny\" if the message was meant to fire.",
        path.display(),
        stray.rule_name,
        stray.rule_id
    )
}

/// Compiled wasm modules keyed by rule id. Built once per rules load
/// ([`load_rules`]) so evaluation never compiles; a wasm rule whose id
/// is absent here was refused at load time (and warned about then) —
/// the evaluator treats it as never matching.
pub type RuleModules = HashMap<String, RuleModule>;

/// Result of [`load_rules`]: the parsed rule list plus the file's
/// `mtime` at load time (used by the daemon's freshness check) and the
/// compiled wasm modules for the rules that reference one.
#[derive(Debug, Default)]
pub struct LoadedRules {
    pub rules: Vec<Rule>,
    /// `None` if the file didn't exist.
    pub mtime: Option<SystemTime>,
    /// Compiled + hash-verified modules for the wasm rules in `rules`.
    pub modules: RuleModules,
    /// Everything wrong with the rules in `rules`, which stay in the
    /// list — visible to the UI and CLI — and cannot fire as written.
    /// A refused wasm rule has no entry in `modules`; a refused pattern
    /// matches nothing. The caller must surface these loudly (the daemon
    /// logs each one and passes them on so list/show/UI render them).
    pub refusals: RuleRefusals,
    /// One entry per rule whose `deny_message` was dropped because the
    /// rule decides `approve`. [`load_rules`] has already warned about
    /// each of these through the daemon log; the list is here so a
    /// caller (and the tests) can see what was dropped.
    pub stray_deny_messages: Vec<StrayDenyMessage>,
}

/// Load rules from `path`. A missing file returns an empty
/// `LoadedRules` (not an error) — the daemon should run normally
/// when no rules are configured. Malformed files DO return an error;
/// the daemon turns that into a stderr warning + empty ruleset.
///
/// ## Failure granularity (deliberate, two-tier)
///
/// - **File-level**: unparseable TOML or a rule whose *shape* is
///   invalid (both `match` and `wasm`, neither, a wasm rule with
///   `decide`/`deny_message`) errors the whole load — the file was
///   authored wrong, same class as a syntax error, and the daemon's
///   existing "warn + empty ruleset" contract applies. Both are
///   literally the same check now: the shape lives in
///   `TryFrom<RuleWire> for Rule`, run on every rule as it is converted.
/// - **Tolerated, and warned about**: a `deny_message` on a rule that
///   decides `approve`. Files carrying one load today, so refusing them
///   would break a working configuration; the key is dropped instead
///   (and so gone the next time the file is written) and every
///   occurrence is logged by file and rule name. See
///   [`StrayDenyMessage`].
/// - **Per-rule**: a wasm rule whose *referenced module* fails to load
///   (missing file, sha256 mismatch, sandbox rejection) refuses just
///   that rule, recorded in [`RuleRefusals::wasm`]. A tampered or stale
///   module is a loud security event, but it must not knock out the
///   user's other rules — in particular their protective *deny* rules,
///   which would otherwise stop firing exactly when something on disk
///   is being tampered with.
/// - **Per-clause**: a match pattern that will not compile as a glob
///   refuses that clause, recorded in [`RuleRefusals::patterns`]. Same
///   reasoning one level down — a typo in one rule's `argv` is not a
///   reason to stop consulting the rest of the file. What it *is* a
///   reason to do is take the ask to the human when the typo is on a
///   deny; see [`evaluate`].
pub fn load_rules(path: &Path) -> Result<LoadedRules> {
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(LoadedRules::default());
        }
        Err(e) => {
            return Err(anyhow::Error::from(e))
                .with_context(|| format!("stat auto-rules file: {}", path.display()));
        }
    };
    let mtime = meta.modified().ok();
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read auto-rules file: {}", path.display()))?;
    let parsed: RulesFileWire = toml::from_str(&text)
        .with_context(|| format!("parse auto-rules file: {}", path.display()))?;
    // Spot the stray `deny_message`s on the wire, where the key still
    // exists, then convert. Warning here rather than in the conversion
    // is what lets the message name the file the rule came from.
    let mut stray_deny_messages = Vec::new();
    let mut rules = Vec::with_capacity(parsed.rules.len());
    for wire in parsed.rules {
        if wire.decide == Some(RuleDecision::Approve) && wire.deny_message.is_some() {
            let stray = StrayDenyMessage {
                rule_id: wire.id.clone(),
                rule_name: wire.name.clone(),
            };
            crate::daemon::log::log_at(
                "rules",
                format_args!("WARN: {}", stray_deny_message_warning(path, &stray)),
            );
            stray_deny_messages.push(stray);
        }
        rules.push(
            Rule::try_from(wire)
                .with_context(|| format!("in auto-rules file: {}", path.display()))?,
        );
    }
    // Relative wasm paths anchor at the rules file's directory.
    let rules_dir = path.parent().unwrap_or(Path::new(""));
    let mut modules = RuleModules::new();
    let mut wasm_refusals = Vec::new();
    for rule in &rules {
        match load_rule_module(rule, rules_dir) {
            Ok(Some(module)) => {
                modules.insert(rule.id.clone(), module);
            }
            Ok(None) => {}
            Err(err) => wasm_refusals.push(WasmRefusal {
                rule_id: rule.id.clone(),
                category: err.category,
                reason: format!("{:#}", err.source),
            }),
        }
    }
    let refusals = RuleRefusals {
        patterns: pattern_refusals(&rules),
        wasm: wasm_refusals,
    };
    Ok(LoadedRules {
        rules,
        mtime,
        modules,
        refusals,
        stray_deny_messages,
    })
}

/// Atomically update the rules file to contain `rules`. Used by the
/// AddRule / UpdateRule / DeleteRule / SetRuleEnabled IPC paths. The
/// daemon owns all writes; users hand-edit only when the daemon is
/// stopped.
///
/// **Why this goes through `atomic::replace`.** The two things
/// that module exists to prevent were both live here: a fixed
/// `.json5.tmp` staging name every writer of this destination shared,
/// and a staging file created at `0666 & !umask` whose mode the rename
/// then published. Under the `umask 000` that container and CI images
/// routinely set, the second one left `auto-rules.toml`
/// **world-writable** — and this file is the list of commands that skip
/// the consent prompt, so a stranger who can append to it can approve
/// their own.
///
/// **Why `Mode::Like` and not `Mode::Exactly(0o600)`.** The mode source is
/// the destination itself: preserve whatever the user chose, fall back
/// to owner-only when there is nothing to preserve. That fallback is the
/// fix — a file secreq creates is 0600 whatever the umask says — while
/// the preservation keeps secreq from undoing a deliberate `chmod`.
/// This is a config users hand-edit (there is a published schema for
/// their editor), and migration 0001 already commits to exactly this
/// policy for this exact filename: its
/// `moved_config_keeps_the_mode_the_user_chose` migrates an
/// `auto-rules.toml` at 0640 and asserts it survives. Forcing 0600 here
/// would mean secreq preserves the user's mode across an upgrade and
/// then clobbers it on their next rule edit.
///
/// `.migration-state` and `filemap.json` chose `Exactly(0o600)` because
/// nothing but secreq ever writes or reads them, so there is no user
/// choice to preserve; `~/.ssh/config` is forced because its *reader*
/// dictates the mode. Neither is true of this file.
///
/// **The directory too.** `atomic::replace` makes the parent with a bare
/// `create_dir_all`, which takes the umask's answer — an owner-only file
/// inside a 0777 directory is still a file anyone can replace by
/// rename. The parent here is the secreq root itself (the daemon passes
/// [`crate::paths::rules_path`]), never a path a user named on the
/// command line, so [`crate::paths::ensure_private_dir`] is safe to
/// point at it: it narrows as well as creates, and narrowing the root is
/// exactly what it documents.
pub fn save_rules(path: &Path, rules: &[Rule]) -> Result<()> {
    // Empty parent means a bare relative filename — `.`, already there.
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        crate::paths::ensure_private_dir(parent)
            .with_context(|| format!("create dir {}", parent.display()))?;
    }
    let existing = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            format!("#:schema {AUTO_RULES_SCHEMA_URL}\n")
        }
        Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
    };
    let mut doc: toml_edit::DocumentMut = existing
        .parse()
        .with_context(|| format!("{} is not valid TOML", path.display()))?;
    // Refuse to edit a document the typed loader would reject. `toml_edit`
    // intentionally preserves unknown material, but this file's schema is
    // closed: carrying a misspelled policy field forward would make it look
    // live when the daemon never consults it.
    toml::from_str::<RulesFileWire>(&existing)
        .with_context(|| format!("parse auto-rules file: {}", path.display()))?;

    let target = toml_edit::ser::to_document(&RulesFile {
        rules: rules.to_vec(),
    })
    .context("serialize rules as TOML")?;
    reconcile_rule_tables(&mut doc, &target)?;

    let text = doc.to_string();
    toml::from_str::<RulesFileWire>(&text)
        .context("internal: edited auto-rules file doesn't re-parse")?;
    crate::atomic::replace(path, text.as_bytes(), crate::atomic::Mode::Like(path))
}

/// Reconcile the one mutable key in the document while preserving the parsed
/// tables for rules that still exist. Rule ids are stable, so they are the
/// identity across add/update/delete operations.
fn reconcile_rule_tables(
    doc: &mut toml_edit::DocumentMut,
    target: &toml_edit::DocumentMut,
) -> Result<()> {
    use toml_edit::{ArrayOfTables, Item};

    let Some(target_item) = target.get("rules") else {
        bail!("internal: serialized rules document has no `rules` key");
    };
    let Ok(target_tables) = target_item.clone().into_array_of_tables() else {
        // An empty Vec serializes as `rules = []`. Keeping an already-empty
        // value retains its comments and spacing; otherwise every old rule is
        // intentionally being deleted.
        if doc
            .get("rules")
            .and_then(Item::as_value)
            .zip(target_item.as_value())
            .is_some_and(|(old, new)| same_toml_value(old, new))
        {
            return Ok(());
        }
        crate::rule_scaffold::set_preserving_decor(
            doc.as_table_mut(),
            "rules",
            target_item.clone(),
        );
        return Ok(());
    };
    let mut old: Vec<Option<toml_edit::Table>> = doc
        .get("rules")
        .and_then(Item::as_array_of_tables)
        .map(|tables| tables.iter().cloned().map(Some).collect())
        .unwrap_or_default();
    let mut reconciled = ArrayOfTables::new();
    for serialized_table in target_tables.iter() {
        let mut target_table = serialized_table.clone();
        let id = target_table
            .get("id")
            .and_then(Item::as_str)
            .context("internal: serialized rule has no string `id`")?;
        let found = old.iter().position(|candidate| {
            candidate
                .as_ref()
                .is_some_and(|table| table.get("id").and_then(Item::as_str) == Some(id))
        });
        let table = if let Some(mut table) = found
            .and_then(|index| old.get_mut(index))
            .and_then(Option::take)
        {
            shape_rule_table_like(&mut target_table, &table);
            merge_rule_table(&mut table, &target_table);
            table
        } else {
            shape_rule_table(&mut target_table);
            target_table
        };
        reconciled.push(table);
    }

    crate::rule_scaffold::set_preserving_decor(
        doc.as_table_mut(),
        "rules",
        Item::ArrayOfTables(reconciled),
    );
    Ok(())
}

/// Match the nested-table style of an existing rule before merging it.
///
/// TOML permits `match = { wrap = "gh" }` as well as `[rules.match]`.
/// Promoting an existing inline table would discard its value decoration,
/// including a comment after the closing brace.
fn shape_rule_table_like(target: &mut toml_edit::Table, existing: &toml_edit::Table) {
    use toml_edit::Item;

    for key in ["match", "wasm"] {
        if existing.get(key).is_some_and(Item::is_table) {
            shape_rule_field(target, key);
        }
    }
}

/// The serializer uses inline tables for nested structs. Promote the two rule
/// bodies so generated files use readable `[rules.match]` / `[rules.wasm]`
/// stanzas and the targeted merger can edit their fields independently.
fn shape_rule_table(table: &mut toml_edit::Table) {
    for key in ["match", "wasm"] {
        shape_rule_field(table, key);
    }
}

fn shape_rule_field(table: &mut toml_edit::Table, key: &str) {
    use toml_edit::{Item, Value};

    let Some(Item::Value(Value::InlineTable(_))) = table.get(key) else {
        return;
    };
    let Some(Item::Value(Value::InlineTable(inline))) = table.remove(key) else {
        unreachable!("just matched an inline table at {key}");
    };
    table.insert(key, Item::Table(inline.into_table()));
}

/// Apply only changed fields from one serialized rule. Assigning through an
/// existing item retains the key decoration; copying the value/table
/// decoration retains inline comments and comments on nested headers.
fn merge_rule_table(existing: &mut toml_edit::Table, target: &toml_edit::Table) {
    use toml_edit::Item;

    let target_keys: Vec<String> = target.iter().map(|(key, _)| key.to_owned()).collect();
    let removed: Vec<String> = existing
        .iter()
        .map(|(key, _)| key.to_owned())
        .filter(|key| !target.contains_key(key))
        .collect();
    for key in removed {
        existing.remove(&key);
    }

    for key in target_keys {
        let Some(target_item) = target.get(&key) else {
            continue;
        };
        match existing.get_mut(&key) {
            Some(Item::Value(old)) => {
                let Some(new) = target_item.as_value() else {
                    *existing.get_mut(&key).expect("entry exists") = target_item.clone();
                    continue;
                };
                if !same_toml_value(old, new) {
                    let mut replacement = new.clone();
                    *replacement.decor_mut() = old.decor().clone();
                    *old = replacement;
                }
            }
            Some(Item::Table(old)) => {
                let Some(new) = target_item.as_table() else {
                    *existing.get_mut(&key).expect("entry exists") = target_item.clone();
                    continue;
                };
                merge_rule_table(old, new);
            }
            Some(slot) => *slot = target_item.clone(),
            None => {
                existing.insert(&key, target_item.clone());
            }
        }
    }
}

/// TOML data equality without formatting decoration.
fn same_toml_value(left: &toml_edit::Value, right: &toml_edit::Value) -> bool {
    use toml_edit::Value;

    match (left, right) {
        (Value::String(a), Value::String(b)) => a.value() == b.value(),
        (Value::Integer(a), Value::Integer(b)) => a.value() == b.value(),
        (Value::Float(a), Value::Float(b)) => a.value() == b.value(),
        (Value::Boolean(a), Value::Boolean(b)) => a.value() == b.value(),
        (Value::Datetime(a), Value::Datetime(b)) => a.value() == b.value(),
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b.iter()).all(|(a, b)| same_toml_value(a, b))
        }
        (Value::InlineTable(a), Value::InlineTable(b)) => {
            a.len() == b.len()
                && a.iter()
                    .all(|(key, a)| b.get(key).is_some_and(|b| same_toml_value(a, b)))
        }
        _ => false,
    }
}

/// `mtime` of the rules file, or `None` if it doesn't exist. The daemon
/// stats this at the top of every message; an mtime that has advanced past
/// the one it last loaded triggers a **reload in place** —
/// `daemon::state::State::reload_rules_if_changed`, which documents why the
/// original shutdown-on-change design was dropped.
pub fn file_mtime(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).ok().and_then(|m| m.modified().ok())
}

/// Generate a fresh rule id. 12 random bytes as lowercase hex — short
/// enough to fit in audit-log lines, long enough that collisions
/// across a single user's lifetime are negligible.
pub fn new_rule_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().fold(String::with_capacity(24), |mut s, b| {
        use std::fmt::Write;
        let _ = write!(&mut s, "{b:02x}");
        s
    })
}

/// Seconds since the Unix epoch (for `Rule::created_at_unix`).
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

// ── Evaluation ────────────────────────────────────────────────────────────

/// What the evaluator needs from one live ask. Built by the daemon
/// caller (`daemon::server`) so this module stays free of wire types.
pub struct EvalCtx<'a> {
    /// The wrap name being asked for.
    pub wrap: &'a str,
    /// The joined argv of the wrapped command (e.g. `"gh api --get /repos/x"`).
    pub joined_argv: &'a str,
    /// Caller chain, nearest-first. Matched against the `ancestor` pattern.
    pub callers: &'a [EvalCaller<'a>],
    /// Working directory of the requesting process.
    pub cwd: &'a str,
    /// Names of the secrets requested. Checked against the rule's
    /// `trained_secrets` guard.
    pub secrets: &'a [&'a str],
}

/// One caller as a rule sees it.
///
/// `exe` is the kernel's record of what was loaded. `name` and `command` are
/// `comm` and argv, both of which the process chooses for itself: one
/// `prctl(PR_SET_NAME)` on Linux, or an argv element on any platform. So
/// `ancestor: "Cursor.app"` matched against `command` was satisfiable by
/// `sh -c '# /Applications/Cursor.app/Contents/MacOS/Cursor'`.
///
/// [`Pattern::matches_ancestor`] prefers the path for that reason, and falls
/// back to the self-reported pair only when the kernel would not give one.
#[derive(Debug, Clone, Copy)]
pub struct EvalCaller<'a> {
    pub name: &'a str,
    pub command: &'a str,
    pub exe: Option<&'a str>,
}

/// One rule's hit, returned by [`evaluate`].
#[derive(Debug, Clone, PartialEq)]
pub struct RuleHit {
    pub rule_id: String,
    pub rule_name: String,
    pub decide: RuleDecision,
    /// Deny reason, when `decide == Deny`: the configured
    /// `deny_message` for declarative rules, the module's returned
    /// reason for wasm rules. The wrap client prints this to stderr;
    /// the consent UI surfaces it as a toast.
    pub deny_message: Option<String>,
    /// Per-secret approver attribution on an approve: each requested
    /// secret name → the id of the rule that blessed it. `rule_id`
    /// above is only the *representative* (most-specific) approver, so
    /// on a multi-secret ask blessed by several rules it names one of
    /// them; this map is the whole answer. Empty on a deny — a deny
    /// grants nothing, so there is nothing to attribute.
    pub approvals: BTreeMap<String, String>,
}

/// A wasm rule that errored at evaluation time (trap, abort, fuel
/// exhaustion, malformed decision). The evaluator treats the rule as
/// not matching — **fail safe to the interactive prompt, never to an
/// auto-approve** — and reports the failure here so the caller can log
/// it; a rule that silently stops firing would otherwise be
/// indistinguishable from one that decided to pass.
#[derive(Debug, Clone, PartialEq)]
pub struct WasmFailure {
    pub rule_id: String,
    pub rule_name: String,
    /// Formatted error chain from the wasm host.
    pub error: String,
}

/// Why an evaluation refuses to let anything auto-approve, even though no
/// deny fired. Either a rule asked for a human ([`WasmDecision::Prompt`]),
/// or a rule that might have denied could not be consulted at all.
#[derive(Debug, Clone, PartialEq)]
pub struct PromptMandate {
    /// The rule that mandated it, for the daemon log.
    pub rule_id: String,
    pub rule_name: String,
    /// The module's stated reason, or a description of why the rule could
    /// not be consulted. Shown to the user alongside the prompt.
    pub reason: String,
}

/// What [`evaluate`] produced: the winning hit (if any), any mandate that
/// suppressed an approve, and every wasm-rule runtime failure along the way.
#[derive(Debug, Default, PartialEq)]
pub struct Evaluation {
    pub hit: Option<RuleHit>,
    /// `Some` when an approve was suppressed in favour of the interactive
    /// prompt. `hit` is `None` whenever this is set (a deny outranks it, and
    /// would have produced a hit instead), so the daemon's existing
    /// fall-through already does the right thing — this is here so the reason
    /// can be logged and shown rather than the ask silently looking like
    /// "no rule matched".
    pub mandated_prompt: Option<PromptMandate>,
    pub wasm_failures: Vec<WasmFailure>,
}

/// Specificity assigned to a wasm rule that returns a non-Pass
/// decision: maximal. A declarative rule's specificity counts how many
/// optional match clauses constrain it (0–3); a wasm rule that chose
/// to approve or deny made a deliberate, programmatic decision about
/// this exact ask, which is as constrained as it gets. Ties (two wasm
/// rules both deciding) break on the existing smallest-id rule. Note
/// deny-wins already dominates specificity entirely: any deny — wasm
/// or declarative — beats every approve.
pub const WASM_DECISION_SPECIFICITY: u32 = u32::MAX;

/// One matching rule competing for the hit — as the whole-ask deny, or
/// as the approver of one requested secret.
///
/// Carries no `decide`: which side a candidate is on is the slot it
/// lands in ([`record_deny`] vs [`record_approval`]), not a field that
/// could disagree with it. `Clone` because a single approving rule is
/// recorded against every secret it blesses.
#[derive(Clone)]
struct Candidate<'r> {
    rule: &'r Rule,
    deny_message: Option<String>,
    specificity: u32,
}

/// Evaluate `rules` against `ctx` in a single pass — declarative and
/// wasm rules compete in the same precedence order. `modules` holds
/// the compiled module for every loadable wasm rule (see
/// [`RuleModules`]); a wasm rule with no entry was refused at load
/// time and never matches.
///
/// Approval is aggregated **per secret** (#265): a rule approves the
/// secrets it is responsible for, and the ask is approved only when
/// every requested secret reached an approved state. Denial stays a
/// whole-ask veto.
///
/// Returns an [`Evaluation`] whose `hit` is:
///
/// - `Some(RuleHit { Deny, .. })` if any enabled, candidate-matching
///   deny fires — a declarative deny match or a wasm `Deny(reason)`
///   return. A deny is a **whole-ask veto** and is never scoped by the
///   denying rule's trained snapshot: rules see the full ask so they can
///   refuse a *combination* that no individual secret would justify.
///   Among multiple denies the most specific wins (deterministic for
///   audit clarity); semantically all denies block, so the "winner" only
///   matters for which rule_id is logged.
/// - `Some(RuleHit { Approve, .. })` if no deny fires, no prompt is
///   mandated, and **every** requested secret was blessed:
///   - a wasm `Approve` blesses only `requested ∩ trained_secrets`, so
///     it is structurally unable to approve a secret outside its
///     trained set;
///   - a declarative `Approve` whose clause matched blesses the whole
///     ask, but only when the ask is a subset of its `trained_secrets`
///     snapshot (empty = unbounded). Declarative rules are transparent
///     and stay whole-ask-scoped by decision; only wasm approvals are
///     intersected per secret.
///
///   The most-specific approver wins **per secret**; [`RuleHit::approvals`]
///   records which rule blessed which, and `rule_id` names the
///   most-specific approver overall.
/// - `None` if any requested secret went unblessed. The ask is
///   **atomic** — one uncovered secret sends the *whole* ask to the
///   interactive prompt, rather than granting the covered subset.
///
/// Stricter coverage is the intent: dropping the old whole-ask
/// subset-gate means every rule that *overlaps* the ask now runs, but
/// each is only credited with the secrets it actually vouches for.
///
/// Declarative semantics within the pass:
///
/// - A clause that cannot be consulted — a match pattern that would not
///   compile as a glob — is not a clause that failed. On a **deny** it
///   mandates the prompt ([`Evaluation::mandated_prompt`]), because the
///   alternative is that the operator's typo lets another rule's approve
///   carry an ask their deny was written to stop. On an **approve** it
///   simply drops the rule, which is where a broken approve already
///   fails: closed.
/// - The mandate is only reached when every *other* clause on the rule
///   was consulted and matched. See [`clause_outcome`].
///
/// Wasm semantics within the pass:
///
/// - A wasm rule runs when it **overlaps** the ask — the ask requests at
///   least one name in its trained snapshot (empty snapshot =
///   `--all-secrets`, overlaps everything). This replaces the old
///   subset-gate: a rule trained on `{A}` now runs on an `{A, B}` ask
///   and blesses only `A`, where before it was skipped entirely and its
///   opinion on `A` was lost.
/// - A `Pass` return means "no opinion": the rule contributes nothing.
/// - A `Prompt(reason)` return removes the option of an approve without
///   producing a hit — a deny still outranks it.
/// - A runtime error (trap, fuel, bad decision) means the rule's opinion
///   is unavailable, which mandates the prompt for the same reason a
///   refused module does, and is reported in
///   [`Evaluation::wasm_failures`] for the caller to log.
pub fn evaluate(rules: &[Rule], modules: &RuleModules, ctx: &EvalCtx) -> Evaluation {
    let mut best_deny: Option<Candidate> = None;
    // The most-specific rule that approved each requested secret, keyed
    // by the secret name (borrowed from `ctx.secrets`).
    let mut approvers: HashMap<&str, Candidate> = HashMap::new();
    let mut mandated_prompt: Option<PromptMandate> = None;
    let mut wasm_failures = Vec::new();

    // First mandate wins. Which rule is named matters only for the log line;
    // any one of them suppresses every approve identically.
    let mut mandate = |rule: &Rule, reason: String| {
        if mandated_prompt.is_none() {
            mandated_prompt = Some(PromptMandate {
                rule_id: rule.id.clone(),
                rule_name: rule.name.clone(),
                reason,
            });
        }
    };

    for rule in rules {
        if !rule.enabled {
            continue;
        }
        match &rule.body {
            RuleBody::Wasm(_) => {
                // Overlap, not subset: a rule with nothing to say about
                // any requested secret is not consulted at all, so its
                // module never sees an ask outside its remit.
                if !wasm_overlaps(rule, ctx) {
                    continue;
                }
                let Some(module) = modules.get(&rule.id) else {
                    // Refused at load time (sha256 mismatch, missing file).
                    // "Cannot be consulted" is not "passed": this rule may have
                    // been the deny protecting the ask, and letting a surviving
                    // approve carry it means tampering with one module both
                    // disables the guard and leaves the guarded thing enabled.
                    // Fall through to the human instead.
                    mandate(
                        rule,
                        "a rule module could not be loaded, so the ruleset is incomplete"
                            .to_owned(),
                    );
                    continue;
                };
                match module.evaluate(ctx) {
                    Ok(WasmDecision::Pass) => {}
                    Ok(WasmDecision::Approve) => {
                        let candidate = Candidate {
                            rule,
                            deny_message: None,
                            specificity: WASM_DECISION_SPECIFICITY,
                        };
                        // Per-secret scoping — the structural half of
                        // #265. The module said "approve"; it is only
                        // credited with the requested secrets inside its
                        // trained set, so a rule cannot bless a secret it
                        // was never trained on however it decides.
                        for secret in ctx.secrets {
                            if rule.trained_secrets.is_empty()
                                || rule.trained_secrets.contains(*secret)
                            {
                                record_approval(&mut approvers, secret, &candidate);
                            }
                        }
                    }
                    Ok(WasmDecision::Deny(reason)) => record_deny(
                        &mut best_deny,
                        Candidate {
                            rule,
                            deny_message: Some(reason),
                            specificity: WASM_DECISION_SPECIFICITY,
                        },
                    ),
                    Ok(WasmDecision::Prompt(reason)) => {
                        // Approves nothing and denies nothing: `Prompt`
                        // produces no hit, it removes the option of one.
                        // A deny still outranks it.
                        mandate(rule, reason);
                    }
                    Err(err) => {
                        // Same reasoning as a refused module: a rule that trapped
                        // is a rule whose opinion we do not have.
                        wasm_failures.push(WasmFailure {
                            rule_id: rule.id.clone(),
                            rule_name: rule.name.clone(),
                            error: format!("{err:#}"),
                        });
                        mandate(
                            rule,
                            "a rule module errored, so the ruleset is incomplete".to_owned(),
                        );
                    }
                }
            }
            RuleBody::Declarative { r#match, decide } => match clause_outcome(r#match, ctx) {
                ClauseOutcome::NoMatch => continue,
                // A pattern that would not compile is not a narrower
                // rule — it is a rule whose question nobody got to ask.
                // The two decisions want opposite treatment, and the
                // split is the whole point rather than an oversight:
                ClauseOutcome::Unconsultable => {
                    match decide.decision() {
                        // A deny the operator wrote and secreq cannot
                        // evaluate must not leave a competing approve
                        // holding the ask — the same fail-open a refused
                        // wasm module opens, and closed the same way.
                        RuleDecision::Deny => mandate(
                            rule,
                            "a deny rule's pattern is not a valid glob, so the \
                             ruleset is incomplete"
                                .to_owned(),
                        ),
                        // An approve that cannot be evaluated already
                        // fails in the safe direction: it approves
                        // nothing. Mandating a prompt here would turn one
                        // typo into a prompt on every ask the rule's wrap
                        // covers, buying no safety at all.
                        RuleDecision::Approve => {}
                    }
                    continue;
                }
                ClauseOutcome::Match => match decide.decision() {
                    RuleDecision::Deny => record_deny(
                        &mut best_deny,
                        Candidate {
                            rule,
                            deny_message: decide.deny_message().map(str::to_owned),
                            specificity: specificity(r#match),
                        },
                    ),
                    RuleDecision::Approve => {
                        // A declarative approve stays whole-ask (#265
                        // decision 2A) but keeps the trained-snapshot
                        // subset guard: a transparent rule may bless the
                        // whole ask, and must not silently widen to env
                        // vars added since it was written. No deny_message
                        // — an approve has nothing to explain.
                        if declarative_approve_in_scope(rule, ctx) {
                            let candidate = Candidate {
                                rule,
                                deny_message: None,
                                specificity: specificity(r#match),
                            };
                            for secret in ctx.secrets {
                                record_approval(&mut approvers, secret, &candidate);
                            }
                        }
                    }
                },
            },
        }
    }

    // Deny > Prompt > Approve. A deny wins outright: refusing is strictly
    // stronger than asking, and a mandate that could veto a deny would let a
    // broken module turn a block into a dialog. A mandate outranks the
    // aggregate approve for the same reason it outranked the single one — it
    // exists precisely to stop an approve from carrying the ask.
    let hit = match (best_deny, &mandated_prompt) {
        (Some(deny), _) => Some(RuleHit {
            rule_id: deny.rule.id.clone(),
            rule_name: deny.rule.name.clone(),
            decide: RuleDecision::Deny,
            deny_message: deny.deny_message,
            // A deny grants nothing, so there is nothing to attribute.
            approvals: BTreeMap::new(),
        }),
        (None, Some(_)) => None,
        (None, None) => approve_hit(ctx, &approvers),
    };
    // A mandate that lost to a deny is spent: the ask is already blocked, and
    // reporting "we also wanted to ask you" alongside it would only be noise.
    if hit.is_some() {
        mandated_prompt = None;
    }
    Evaluation {
        hit,
        mandated_prompt,
        wasm_failures,
    }
}

/// The aggregation step: approve iff **every** requested secret was
/// blessed. One uncovered secret sends the whole ask to the prompt —
/// asks are atomic, so there is no "approve the covered subset".
///
/// An ask requesting *no* secrets never approves. `.all()` over an empty
/// iterator is vacuously true, which would make an empty ask satisfy any
/// ruleset at all; callers mint a subject for each ask kind that resolves
/// nothing (`ssh:<key_id>`, `wrap:<name>`), so this should be unreachable —
/// it is here so the next ask kind fails closed on the day someone adds one
/// and forgets.
fn approve_hit(ctx: &EvalCtx, approvers: &HashMap<&str, Candidate>) -> Option<RuleHit> {
    if ctx.secrets.is_empty() || !ctx.secrets.iter().all(|s| approvers.contains_key(*s)) {
        return None;
    }
    let approvals: BTreeMap<String, String> = ctx
        .secrets
        .iter()
        .map(|s| ((*s).to_owned(), approvers[*s].rule.id.clone()))
        .collect();
    // The representative for the whole-ask attribution: the most-specific
    // approver across all secrets (id tiebreak). `approvals` above is the
    // complete answer; this is what a single-rule-id audit field can hold.
    let winner = approvers
        .values()
        .reduce(|acc, cur| if beats(cur, acc) { cur } else { acc })
        .expect("full coverage of a non-empty ask implies at least one approver");
    Some(RuleHit {
        rule_id: winner.rule.id.clone(),
        rule_name: winner.rule.name.clone(),
        decide: RuleDecision::Approve,
        deny_message: None,
        approvals,
    })
}

/// Record a whole-ask deny candidate, keeping the most specific (the rule
/// whose id the audit row will name). Semantically any deny blocks; the
/// choice only decides which rule is attributed.
fn record_deny<'r>(slot: &mut Option<Candidate<'r>>, candidate: Candidate<'r>) {
    if slot.as_ref().is_none_or(|cur| beats(&candidate, cur)) {
        *slot = Some(candidate);
    }
}

/// Record that `candidate` approved `secret`, keeping the most-specific
/// approver for that secret (id tiebreak) — the per-secret analogue of the
/// single `best_approve` slot this replaced.
fn record_approval<'a, 'r>(
    approvers: &mut HashMap<&'a str, Candidate<'r>>,
    secret: &'a str,
    candidate: &Candidate<'r>,
) {
    if approvers
        .get(secret)
        .is_none_or(|cur| beats(candidate, cur))
    {
        approvers.insert(secret, candidate.clone());
    }
}

/// Whether a wasm rule is consulted at all: the ask must request at least
/// one name in its trained snapshot (empty = `--all-secrets`, overlapping
/// everything). Overlap rather than subset is the point of #265 — a rule
/// trained on `{A}` runs on an `{A, B}` ask and blesses only `A`.
fn wasm_overlaps(rule: &Rule, ctx: &EvalCtx) -> bool {
    rule.trained_secrets.is_empty()
        || ctx
            .secrets
            .iter()
            .any(|n| rule.trained_secrets.contains(*n))
}

/// Whether a declarative rule's whole-ask `Approve` may fire: the ask must
/// be a subset of its trained snapshot (empty = unbounded). The retained
/// trained-secrets guard, now scoped to declarative approvals only — wasm
/// approvals are scoped per secret instead, and denies are never
/// trained-scoped.
fn declarative_approve_in_scope(rule: &Rule, ctx: &EvalCtx) -> bool {
    if rule.trained_secrets.is_empty() {
        return true;
    }
    // Vacuous-truth guard, for the reason spelled out on `approve_hit`.
    // Redundant with that check today; kept because this predicate reads as
    // a standalone "is this rule in scope?" and must not answer yes to an
    // ask it knows nothing about.
    if ctx.secrets.is_empty() {
        return false;
    }
    ctx.secrets
        .iter()
        .all(|n| rule.trained_secrets.contains(*n))
}

/// What a declarative rule's match clause says about one ask. Three
/// states rather than a bool, because a [refused pattern](PatternRefusal)
/// makes "does this rule match?" a question with no answer, and the two
/// ways of not matching call for different handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClauseOutcome {
    /// Every clause was consulted, and every one matched.
    Match,
    /// At least one clause definitively did not match. The rule does not
    /// apply to this ask and nothing further is owed.
    NoMatch,
    /// Nothing definitively excluded the ask, but at least one clause
    /// carried a pattern that would not compile. Whether the rule
    /// matches is unknown — not false.
    Unconsultable,
}

/// Evaluate the declarative match clause `m` against `ctx`. Pure — no
/// I/O, no allocation beyond what the patterns themselves do.
///
/// A definite `NoMatch` beats an unknown, which is just how `AND` works:
/// a rule scoped to `cwd: /home/x/oss` does not apply to an ask from
/// `/home/x/elsewhere` however broken its `argv` is. That precision is
/// what keeps one typo from mandating a prompt on asks the rule never
/// covered.
fn clause_outcome(m: &RuleMatch, ctx: &EvalCtx) -> ClauseOutcome {
    // `wrap` is exact, never a glob, so it can always be consulted.
    if m.wrap != ctx.wrap {
        return ClauseOutcome::NoMatch;
    }
    let mut unconsultable = false;
    if let Some(p) = &m.argv {
        if p.is_invalid() {
            unconsultable = true;
        } else if !p.matches_prefix(ctx.joined_argv) {
            return ClauseOutcome::NoMatch;
        }
    }
    if let Some(p) = &m.ancestor {
        if p.is_invalid() {
            unconsultable = true;
        } else if !ctx.callers.iter().any(|c| p.matches_ancestor(c)) {
            return ClauseOutcome::NoMatch;
        }
    }
    if let Some(p) = &m.cwd {
        if p.is_invalid() {
            unconsultable = true;
        } else if !p.matches_path_prefix(ctx.cwd) {
            return ClauseOutcome::NoMatch;
        }
    }
    if unconsultable {
        ClauseOutcome::Unconsultable
    } else {
        ClauseOutcome::Match
    }
}

/// Does `a` beat `b` for "most specific" ranking? Higher specificity
/// wins; ties break in favor of the lexically-smaller `id`.
fn beats(a: &Candidate, b: &Candidate) -> bool {
    if a.specificity != b.specificity {
        return a.specificity > b.specificity;
    }
    a.rule.id < b.rule.id
}

fn specificity(m: &RuleMatch) -> u32 {
    // The wrap field is always present, so it doesn't differentiate.
    u32::from(m.argv.is_some()) + u32::from(m.ancestor.is_some()) + u32::from(m.cwd.is_some())
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Compiled AssemblyScript fixtures shared with the wasm_rules host
    // tests — see tests/fixtures/wasm_rules/rebuild.sh.
    const ALWAYS_PASS: &[u8] = include_bytes!("../tests/fixtures/wasm_rules/always_pass.wasm");
    const APPROVE_IF: &[u8] = include_bytes!("../tests/fixtures/wasm_rules/approve_if.wasm");
    const DENY_ECHO: &[u8] = include_bytes!("../tests/fixtures/wasm_rules/deny_echo.wasm");
    const ABORTS: &[u8] = include_bytes!("../tests/fixtures/wasm_rules/aborts.wasm");
    const PROMPTS: &[u8] = include_bytes!("../tests/fixtures/wasm_rules/prompts.wasm");

    fn rule_id(id: &str) -> String {
        id.to_owned()
    }

    fn mk_rule(id: &str, name: &str, decide: RuleDecision, m: RuleMatch, trained: &[&str]) -> Rule {
        Rule {
            id: rule_id(id),
            name: name.to_owned(),
            enabled: true,
            trained_secrets: trained.iter().map(|s| (*s).to_owned()).collect(),
            created_at_unix: 0,
            body: RuleBody::Declarative {
                r#match: m,
                decide: decide.into(),
            },
        }
    }

    /// A wasm rule whose module the tests register directly in a
    /// [`RuleModules`] map (the sha256 here is only exercised by the
    /// load-path tests, which compute a real one).
    fn mk_wasm_rule(id: &str, name: &str, trained: &[&str]) -> Rule {
        Rule {
            id: rule_id(id),
            name: name.to_owned(),
            enabled: true,
            trained_secrets: trained.iter().map(|s| (*s).to_owned()).collect(),
            created_at_unix: 0,
            body: RuleBody::Wasm(WasmRule {
                path: format!("{id}.wasm"),
                sha256: "unverified-in-eval-tests".to_owned(),
            }),
        }
    }

    /// Set (or clear) a declarative deny rule's message in place.
    /// Panics on anything that isn't a deny — nothing else can hold one.
    fn set_deny_message(rule: &mut Rule, msg: Option<&str>) {
        let RuleBody::Declarative {
            decide: StaticDecision::Deny { message },
            ..
        } = &mut rule.body
        else {
            panic!("not a declarative deny rule");
        };
        *message = msg.map(str::to_owned);
    }

    /// Replace a rule's module reference in place. Panics on a
    /// declarative rule.
    fn set_wasm(rule: &mut Rule, wasm: WasmRule) {
        let RuleBody::Wasm(slot) = &mut rule.body else {
            panic!("not a wasm rule");
        };
        *slot = wasm;
    }

    fn modules_for(entries: &[(&str, &[u8])]) -> RuleModules {
        entries
            .iter()
            .map(|(id, bytes)| {
                (
                    (*id).to_owned(),
                    RuleModule::from_binary(bytes).expect("fixture module loads"),
                )
            })
            .collect()
    }

    /// Declarative-only shorthand: evaluate with no wasm modules and
    /// return just the hit, keeping the pre-wasm tests focused.
    fn eval(rules: &[Rule], ctx: &EvalCtx) -> Option<RuleHit> {
        evaluate(rules, &RuleModules::new(), ctx).hit
    }

    fn match_for(
        wrap: &str,
        argv: Option<&str>,
        ancestor: Option<&str>,
        cwd: Option<&str>,
    ) -> RuleMatch {
        RuleMatch {
            wrap: wrap.to_owned(),
            argv: argv.map(Pattern::parse),
            ancestor: ancestor.map(Pattern::parse),
            cwd: cwd.map(Pattern::parse),
        }
    }

    fn ctx<'a>(
        wrap: &'a str,
        joined_argv: &'a str,
        callers: &'a [EvalCaller<'a>],
        cwd: &'a str,
        secrets: &'a [&'a str],
    ) -> EvalCtx<'a> {
        EvalCtx {
            wrap,
            joined_argv,
            callers,
            cwd,
            secrets,
        }
    }

    // ── Pattern semantics ─────────────────────────────────────────────

    #[test]
    fn glob_matches_full_string() {
        let p = Pattern::parse("gh api --get /repos/*/pulls*");
        assert!(p.matches_prefix("gh api --get /repos/me/x/pulls/3"));
        assert!(!p.matches_prefix("gh repo delete"));
    }

    #[test]
    fn literal_argv_acts_as_prefix_not_exact() {
        let p = Pattern::parse("gh api");
        assert!(p.matches_prefix("gh api --get /repos/me/x"));
        assert!(p.matches_prefix("gh api"));
        assert!(!p.matches_prefix("gh repo delete"));
        // Prefix is strict — leading whitespace doesn't get a free pass.
        assert!(!p.matches_prefix(" gh api"));
    }

    #[test]
    fn literal_ancestor_acts_as_substring() {
        // The whole point: the .app bundle name must match inside a
        // noisy full-command string the way users expect.
        let p = Pattern::parse("Cursor.app");
        let command = "/Applications/Cursor.app/Contents/MacOS/Cursor --psn_0_12345";
        assert!(p.matches_substring(command));
        // And matching against the process name still works.
        assert!(p.matches_substring("Cursor.app"));
        assert!(!p.matches_substring("Code Helper (GPU)"));
    }

    #[test]
    fn a_malformed_glob_matches_nothing_rather_than_posing_as_a_literal() {
        // `[` opens a char class; no closing `]` makes this a bad glob.
        // The old behaviour re-read it as the literal `foo[bar`, which
        // matched a string nobody wrote a rule for and — far worse — read
        // as a working rule in the file. It now matches nothing at all, and
        // says why.
        let p = Pattern::parse("foo[bar");
        assert!(!p.matches_prefix("foo[bar baz"));
        assert!(!p.matches_prefix("foo bar"));
        assert!(!p.matches_path_prefix("foo[bar/x"));
        assert!(!p.matches_substring("a foo[bar b"));
        assert!(
            p.invalid_reason().is_some(),
            "the glob error is kept, not discarded"
        );
        // The source text still round-trips: a refused pattern must come back
        // out byte-for-byte rather than being helpfully corrected.
        assert_eq!(p.as_str(), "foo[bar");
    }

    #[test]
    fn a_wildcardless_pattern_is_a_literal_not_a_refusal() {
        let p = Pattern::parse("gh api");
        assert_eq!(p.invalid_reason(), None);
        assert!(p.matches_prefix("gh api --get /x"));
    }

    // ── Refused patterns ──────────────────────────────────────────────

    #[test]
    fn a_malformed_deny_glob_does_not_let_a_competing_approve_win() {
        // The repro. An operator writes a deny they believe covers the
        // GitHub secrets endpoints, and fat-fingers the glob. Under the
        // literal fallback the deny quietly covered nothing and the broad
        // approve released the ask with no prompt and no warning.
        let deny = mk_rule(
            "01",
            "never touch repo secrets",
            RuleDecision::Deny,
            match_for("gh", Some("gh api /repos/*/actions/secrets*["), None, None),
            &[],
        );
        let approve = mk_rule(
            "02",
            "gh is fine",
            RuleDecision::Approve,
            match_for("gh", None, None, None),
            &[],
        );
        let c = ctx(
            "gh",
            "gh api /repos/me/x/actions/secrets",
            &[],
            "/home/x",
            &["GITHUB_TOKEN"],
        );
        let ev = evaluate(&[deny, approve], &RuleModules::new(), &c);
        assert_eq!(ev.hit, None, "the approve must not carry this ask");
        let mandate = ev.mandated_prompt.expect("the human decides instead");
        assert_eq!(mandate.rule_id, "01");
        assert!(
            mandate.reason.contains("glob"),
            "reason: {}",
            mandate.reason
        );
    }

    #[test]
    fn a_malformed_approve_glob_fails_closed_without_mandating_a_prompt() {
        // The other half of the asymmetry. A broken approve already fails
        // in the safe direction — it approves nothing — so suppressing every
        // other rule over it would turn one typo into a prompt storm.
        let approve = mk_rule(
            "01",
            "typo",
            RuleDecision::Approve,
            match_for("gh", Some("gh api /repos/*["), None, None),
            &[],
        );
        let other = mk_rule(
            "02",
            "narrower approve",
            RuleDecision::Approve,
            match_for("gh", Some("gh api"), None, None),
            &[],
        );
        let c = ctx(
            "gh",
            "gh api /repos/me/x",
            &[],
            "/home/x",
            &["GITHUB_TOKEN"],
        );
        let ev = evaluate(&[approve, other], &RuleModules::new(), &c);
        assert_eq!(ev.mandated_prompt, None);
        assert_eq!(
            ev.hit.expect("the intact approve still fires").rule_id,
            "02"
        );
    }

    #[test]
    fn a_deny_whose_other_clause_rules_the_ask_out_mandates_nothing() {
        // Precision: an unconsultable clause only matters when nothing else
        // on the rule already excludes the ask. `wrap` is exact, so a deny
        // scoped to another wrap is not "incomplete" here — it is
        // inapplicable, and prompting on it would be noise.
        let deny = mk_rule(
            "01",
            "aws only",
            RuleDecision::Deny,
            match_for("aws", Some("aws s3 *["), None, None),
            &[],
        );
        let approve = mk_rule(
            "02",
            "gh is fine",
            RuleDecision::Approve,
            match_for("gh", None, None, None),
            &[],
        );
        let c = ctx("gh", "gh api /x", &[], "/home/x", &["GITHUB_TOKEN"]);
        let ev = evaluate(&[deny, approve], &RuleModules::new(), &c);
        assert_eq!(ev.mandated_prompt, None);
        assert_eq!(ev.hit.expect("the approve still fires").rule_id, "02");
    }

    #[test]
    fn a_deny_ruled_out_by_an_intact_sibling_clause_mandates_nothing() {
        // Same, one level finer: the broken `argv` sits beside a `cwd` that
        // definitively does not match. AND with a definite false is false,
        // whatever the unknown says.
        let deny = mk_rule(
            "01",
            "only in one checkout",
            RuleDecision::Deny,
            match_for("gh", Some("gh api *["), None, Some("/home/x/oss")),
            &[],
        );
        let approve = mk_rule(
            "02",
            "gh is fine",
            RuleDecision::Approve,
            match_for("gh", None, None, None),
            &[],
        );
        let c = ctx(
            "gh",
            "gh api /x",
            &[],
            "/home/x/elsewhere",
            &["GITHUB_TOKEN"],
        );
        let ev = evaluate(&[deny, approve], &RuleModules::new(), &c);
        assert_eq!(ev.mandated_prompt, None);
        assert_eq!(ev.hit.expect("the approve still fires").rule_id, "02");
    }

    #[test]
    fn a_deny_still_outranks_a_mandate_from_another_broken_deny() {
        let broken = mk_rule(
            "01",
            "broken deny",
            RuleDecision::Deny,
            match_for("gh", Some("gh *["), None, None),
            &[],
        );
        let intact = mk_rule(
            "02",
            "intact deny",
            RuleDecision::Deny,
            match_for("gh", Some("gh api"), None, None),
            &[],
        );
        let c = ctx("gh", "gh api /x", &[], "/home/x", &["GITHUB_TOKEN"]);
        let ev = evaluate(&[broken, intact], &RuleModules::new(), &c);
        assert_eq!(ev.mandated_prompt, None, "a block beats a dialog");
        let hit = ev.hit.expect("the intact deny blocks");
        assert_eq!(hit.rule_id, "02");
        assert_eq!(hit.decide, RuleDecision::Deny);
    }

    #[test]
    fn a_disabled_rule_with_a_broken_glob_mandates_nothing() {
        let deny = Rule {
            enabled: false,
            ..mk_rule(
                "01",
                "off",
                RuleDecision::Deny,
                match_for("gh", Some("gh *["), None, None),
                &[],
            )
        };
        let c = ctx("gh", "gh api /x", &[], "/home/x", &["GITHUB_TOKEN"]);
        let ev = evaluate(&[deny], &RuleModules::new(), &c);
        assert_eq!(ev.mandated_prompt, None);
        assert_eq!(ev.hit, None);
    }

    #[test]
    fn a_refusal_names_the_rule_the_field_and_the_pattern() {
        let rules = vec![
            mk_rule(
                "01",
                "never touch repo secrets",
                RuleDecision::Deny,
                match_for("gh", Some("gh api /repos/*/secrets*["), None, None),
                &[],
            ),
            mk_rule(
                "02",
                "fine",
                RuleDecision::Approve,
                match_for("gh", Some("gh api"), None, None),
                &[],
            ),
        ];
        let refusals = pattern_refusals(&rules);
        assert_eq!(refusals.len(), 1, "{refusals:?}");
        let r = &refusals[0];
        assert_eq!(r.rule_id, "01");
        assert_eq!(r.field, PatternField::Argv);
        assert_eq!(r.pattern, "gh api /repos/*/secrets*[");
        assert!(
            r.reason.contains("never touch repo secrets"),
            "reason: {}",
            r.reason
        );
        assert!(r.reason.contains("argv"), "reason: {}", r.reason);
    }

    #[test]
    fn a_refusal_says_which_way_the_rule_now_fails() {
        // The consequence differs by decision, so the operator-facing text
        // has to as well: a refused deny sends every ask it covered to the
        // prompt, a refused approve simply stops approving.
        let deny = pattern_refusals(&[mk_rule(
            "01",
            "d",
            RuleDecision::Deny,
            match_for("gh", Some("gh *["), None, None),
            &[],
        )]);
        let approve = pattern_refusals(&[mk_rule(
            "02",
            "a",
            RuleDecision::Approve,
            match_for("gh", Some("gh *["), None, None),
            &[],
        )]);
        assert!(deny[0].reason.contains("prompt"), "{}", deny[0].reason);
        assert_ne!(deny[0].reason, approve[0].reason);
    }

    #[test]
    fn every_broken_clause_on_a_rule_is_refused_separately() {
        let refusals = pattern_refusals(&[mk_rule(
            "01",
            "three typos",
            RuleDecision::Deny,
            match_for("gh", Some("a*["), Some("b*["), Some("c*[")),
            &[],
        )]);
        let fields: Vec<_> = refusals.iter().map(|r| r.field).collect();
        assert_eq!(
            fields,
            vec![
                PatternField::Argv,
                PatternField::Ancestor,
                PatternField::Cwd
            ]
        );
    }

    #[test]
    fn a_wasm_rule_has_no_patterns_to_refuse() {
        assert!(pattern_refusals(&[mk_wasm_rule("01", "w", &[])]).is_empty());
    }

    // ── Rule matching (whole-rule predicate) ──────────────────────────

    #[test]
    fn wrap_mismatch_short_circuits() {
        let r = mk_rule(
            "01",
            "r",
            RuleDecision::Approve,
            match_for("gh", None, None, None),
            &["GITHUB_TOKEN"],
        );
        let c = ctx("aws", "aws s3 ls", &[], "/home/x", &["AWS_ACCESS_KEY_ID"]);
        assert_eq!(eval(&[r], &c), None);
    }

    #[test]
    fn ancestor_pattern_walks_the_whole_chain() {
        // The .app sits deep in the chain (the immediate parent is
        // zsh); the rule should still match.
        let r = mk_rule(
            "01",
            "Cursor reads",
            RuleDecision::Approve,
            match_for("gh", None, Some("Cursor.app"), None),
            &["GITHUB_TOKEN"],
        );
        let callers = &[
            EvalCaller {
                name: "zsh",
                command: "-zsh",
                exe: None,
            },
            EvalCaller {
                name: "Cursor",
                command: "/Applications/Cursor.app/Contents/MacOS/Cursor --psn_0_12345",
                exe: Some("/Applications/Cursor.app/Contents/MacOS/Cursor"),
            },
        ];
        let c = ctx(
            "gh",
            "gh api --get /repos/me/x/pulls",
            callers,
            "/home/me/x",
            &["GITHUB_TOKEN"],
        );
        let hit = eval(&[r], &c).expect("rule should match");
        assert_eq!(hit.decide, RuleDecision::Approve);
    }

    #[test]
    fn disabled_rule_does_not_fire() {
        let mut r = mk_rule(
            "01",
            "r",
            RuleDecision::Approve,
            match_for("gh", None, None, None),
            &["GITHUB_TOKEN"],
        );
        r.enabled = false;
        let c = ctx("gh", "gh api", &[], "/x", &["GITHUB_TOKEN"]);
        assert_eq!(eval(&[r], &c), None);
    }

    // ── Trained-secrets guard ─────────────────────────────────────────

    #[test]
    fn declarative_approve_blocked_when_ask_widens_past_trained_snapshot() {
        // Rule was trained on {GITHUB_TOKEN}; the ask now also wants
        // GITHUB_REPO_TOKEN (a newly-added env var in the wrap). The
        // declarative rule must NOT fire, otherwise the user silently
        // leaks the new env var they never approved.
        let r = mk_rule(
            "01",
            "r",
            RuleDecision::Approve,
            match_for("gh", None, None, None),
            &["GITHUB_TOKEN"],
        );
        let c = ctx(
            "gh",
            "gh api",
            &[],
            "/x",
            &["GITHUB_TOKEN", "GITHUB_REPO_TOKEN"],
        );
        assert_eq!(eval(&[r], &c), None);
    }

    #[test]
    fn declarative_approve_covers_a_subset_ask() {
        // Trained on {A, B}; ask only wants {A}. Subset of trained — the
        // whole-ask approval blesses the one requested secret.
        let r = mk_rule(
            "01",
            "r",
            RuleDecision::Approve,
            match_for("gh", None, None, None),
            &["A", "B"],
        );
        let c = ctx("gh", "gh api", &[], "/x", &["A"]);
        assert!(eval(&[r], &c).is_some());
    }

    #[test]
    fn declarative_approve_covers_all_secrets_in_a_matched_ask() {
        // The whole-ask nature (decision 2A): one declarative rule
        // trained on {A, B} blesses BOTH secrets of an ask for {A, B} —
        // you don't need a rule per secret. The approvals map attributes
        // each secret to that rule.
        let r = mk_rule(
            "01",
            "covers both",
            RuleDecision::Approve,
            match_for("gh", None, None, None),
            &["A", "B"],
        );
        let c = ctx("gh", "gh api", &[], "/x", &["A", "B"]);
        let hit = eval(&[r], &c).expect("should approve the whole ask");
        assert_eq!(hit.decide, RuleDecision::Approve);
        assert_eq!(hit.approvals.get("A").map(String::as_str), Some("01"));
        assert_eq!(hit.approvals.get("B").map(String::as_str), Some("01"));
    }

    #[test]
    fn empty_trained_secrets_makes_declarative_approve_unbounded() {
        // Hand-edited rule with no trained_secrets field. The scope is
        // unbounded; the rule blesses whatever the ask requests as long
        // as the match clauses pass.
        let r = mk_rule(
            "01",
            "r",
            RuleDecision::Approve,
            match_for("gh", None, None, None),
            &[],
        );
        let c = ctx("gh", "gh api", &[], "/x", &["ANYTHING"]);
        assert!(eval(&[r], &c).is_some());
    }

    #[test]
    fn ask_with_no_requested_secrets_falls_through_to_the_prompt() {
        // Nothing to bless ⇒ no auto-approval, even with a matching
        // unbounded rule. Guards the vacuous-`all()` trap: an empty
        // requested set must not read as "every secret approved."
        let r = mk_rule(
            "01",
            "r",
            RuleDecision::Approve,
            match_for("gh", None, None, None),
            &[],
        );
        let c = ctx("gh", "gh api", &[], "/x", &[]);
        assert_eq!(eval(&[r], &c), None);
    }

    // ── Precedence: deny-wins → most-specific approve → id tiebreak ──

    #[test]
    fn deny_wins_when_both_match() {
        let approve = mk_rule(
            "01",
            "approve from Cursor",
            RuleDecision::Approve,
            match_for("gh", None, Some("Cursor.app"), None),
            &["GITHUB_TOKEN"],
        );
        let deny = mk_rule(
            "02",
            "deny destructive",
            RuleDecision::Deny,
            match_for("gh", Some("gh repo delete *"), None, None),
            &["GITHUB_TOKEN"],
        );
        let c = ctx(
            "gh",
            "gh repo delete me/x",
            &[EvalCaller {
                name: "Cursor",
                command: "Cursor.app",
                exe: None,
            }],
            "/x",
            &["GITHUB_TOKEN"],
        );
        let hit = eval(&[approve, deny], &c).expect("a rule should fire");
        assert_eq!(hit.decide, RuleDecision::Deny);
        assert_eq!(hit.rule_id, "02");
    }

    #[test]
    fn most_specific_approve_wins() {
        // R1 matches on ancestor only; R2 matches on ancestor + argv.
        // Both fire; R2 should be the one whose id ends up in the
        // audit log.
        let r1 = mk_rule(
            "01",
            "broad",
            RuleDecision::Approve,
            match_for("gh", None, Some("Cursor.app"), None),
            &["GITHUB_TOKEN"],
        );
        let r2 = mk_rule(
            "02",
            "narrow",
            RuleDecision::Approve,
            match_for("gh", Some("gh api *"), Some("Cursor.app"), None),
            &["GITHUB_TOKEN"],
        );
        let c = ctx(
            "gh",
            "gh api --get /repos/x",
            &[EvalCaller {
                name: "Cursor",
                command: "Cursor.app",
                exe: None,
            }],
            "/x",
            &["GITHUB_TOKEN"],
        );
        let hit = eval(&[r1, r2], &c).expect("should fire");
        assert_eq!(hit.rule_id, "02");
    }

    #[test]
    fn specificity_ties_break_on_lexically_smallest_id() {
        // Both have the same specificity (1 field); id ordering picks
        // r_aaa over r_bbb so the choice is predictable across runs.
        let r_b = mk_rule(
            "r_bbb",
            "bbb",
            RuleDecision::Approve,
            match_for("gh", None, Some("Cursor.app"), None),
            &["GITHUB_TOKEN"],
        );
        let r_a = mk_rule(
            "r_aaa",
            "aaa",
            RuleDecision::Approve,
            match_for("gh", None, Some("Cursor.app"), None),
            &["GITHUB_TOKEN"],
        );
        let c = ctx(
            "gh",
            "gh api",
            &[EvalCaller {
                name: "Cursor",
                command: "Cursor.app",
                exe: None,
            }],
            "/x",
            &["GITHUB_TOKEN"],
        );
        let hit = eval(&[r_b, r_a], &c).expect("should fire");
        assert_eq!(hit.rule_id, "r_aaa");
    }

    #[test]
    fn deny_specificity_tiebreak_picks_most_specific_for_audit_clarity() {
        // Semantically any deny would block; we pick the most-specific
        // one so the audit row points at the rule that most-precisely
        // describes the blocked operation.
        let d_broad = mk_rule(
            "02",
            "block all gh",
            RuleDecision::Deny,
            match_for("gh", None, None, None),
            &["GITHUB_TOKEN"],
        );
        let d_specific = mk_rule(
            "01",
            "block deletes",
            RuleDecision::Deny,
            match_for("gh", Some("gh repo delete *"), None, None),
            &["GITHUB_TOKEN"],
        );
        let c = ctx("gh", "gh repo delete me/x", &[], "/x", &["GITHUB_TOKEN"]);
        let hit = eval(&[d_broad, d_specific], &c).expect("should deny");
        assert_eq!(hit.decide, RuleDecision::Deny);
        // The more-specific rule (id 01) wins the audit-row honor.
        assert_eq!(hit.rule_id, "01");
    }

    // ── Deny message round-trips ──────────────────────────────────────

    #[test]
    fn deny_message_round_trips_to_hit() {
        let mut deny = mk_rule(
            "01",
            "block deletes",
            RuleDecision::Deny,
            match_for("gh", Some("gh repo delete *"), None, None),
            &["GITHUB_TOKEN"],
        );
        set_deny_message(&mut deny, Some("Use the UI instead."));
        let c = ctx("gh", "gh repo delete me/x", &[], "/x", &["GITHUB_TOKEN"]);
        let hit = eval(&[deny], &c).expect("should deny");
        assert_eq!(hit.deny_message.as_deref(), Some("Use the UI instead."));
    }

    // ── File I/O round-trip ───────────────────────────────────────────

    #[test]
    fn save_then_load_round_trips() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("auto-rules.toml");
        let rules = vec![mk_rule(
            "01",
            "r",
            RuleDecision::Approve,
            match_for("gh", Some("gh api *"), Some("Cursor.app"), None),
            &["GITHUB_TOKEN"],
        )];
        save_rules(&path, &rules).expect("save");
        let loaded = load_rules(&path).expect("load");
        assert_eq!(loaded.rules, rules);
        assert!(loaded.mtime.is_some());
    }

    // ── The rules file's mode and staging (finding A8) ────────────────

    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).expect("stat").permissions().mode() & 0o777
    }

    /// A8's second half, which the pass that fixed `audit.log` missed.
    /// `save_rules` staged through `fs::write`, so the destination came
    /// out of the rename carrying the staging file's `0666 & !umask` —
    /// 0644 under the common 022 and **0666** under the `umask 000` that
    /// container and CI images set. This file lists the commands that
    /// skip the consent prompt: readable, it is a map of what a stranger
    /// can run unprompted; writable, it is where they add themselves.
    ///
    /// Asserted exactly. `mode & 0o022 == 0` passes on any 022 machine
    /// while the file is world-*readable*, which is the disclosure half
    /// of the finding still shipping under a green test.
    #[test]
    fn a_rules_file_secreq_creates_is_owner_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("auto-rules.toml");

        save_rules(&path, &[]).expect("save");

        assert_eq!(mode_of(&path), 0o600, "{}", path.display());
    }

    /// The other direction, and the reason the mode source is the
    /// destination rather than a blanket `Mode::Exactly(0o600)`: a mode
    /// the user chose survives every subsequent rule edit. Migration
    /// 0001 already promises this for this exact filename
    /// (`moved_config_keeps_the_mode_the_user_chose`), and a save path
    /// that clamped would make the migration's promise last until the
    /// user's next click.
    #[test]
    fn saving_keeps_a_mode_the_user_chose() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("auto-rules.toml");
        save_rules(&path, &[]).expect("first save");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).expect("chmod");

        save_rules(&path, &[]).expect("re-save");

        assert_eq!(mode_of(&path), 0o640);
    }

    /// An owner-only file inside a directory anyone can write is still a
    /// file anyone can replace by rename, and `atomic::replace` makes the
    /// parent with a bare `create_dir_all`. This half is umask-independent
    /// on purpose: an existing root left 0777 by an older secreq (or by a
    /// container image's `umask 000`) is narrowed rather than merely not
    /// re-widened, which is what `ensure_private_dir` buys over a
    /// `DirBuilder::mode`.
    #[test]
    fn saving_narrows_a_rules_directory_anyone_could_write() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("root");
        std::fs::create_dir(&root).expect("mkdir");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o777)).expect("chmod");

        save_rules(&root.join("auto-rules.toml"), &[]).expect("save");

        assert_eq!(mode_of(&root), 0o700, "{}", root.display());
    }

    /// The M5 shape in this file: the staging name was a fixed
    /// `auto-rules.toml.tmp`, one inode every writer of this
    /// destination shared. Planting the old name is how a test can see
    /// that we no longer touch it — and the directory listing catches
    /// staging litter left beside the destination on the happy path.
    #[test]
    fn saving_does_not_reuse_the_old_fixed_staging_name() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("auto-rules.toml");
        let squatted = path.with_extension("json5.tmp");
        std::fs::write(&squatted, b"another writer's half-written payload").expect("plant");

        save_rules(&path, &[]).expect("save");

        assert_eq!(
            std::fs::read_to_string(&squatted).expect("read back"),
            "another writer's half-written payload",
            "staging files must not be shared between writers"
        );
        let mut names: Vec<String> = std::fs::read_dir(dir.path())
            .expect("read_dir")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec![
                "auto-rules.json5.tmp".to_owned(),
                "auto-rules.toml".to_owned()
            ],
            "a successful save leaves no staging file behind"
        );
    }

    #[test]
    fn load_returns_empty_when_file_missing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("nonexistent.toml");
        let loaded = load_rules(&path).expect("missing file is not an error");
        assert!(loaded.rules.is_empty());
        assert!(loaded.mtime.is_none());
    }

    #[test]
    fn load_returns_error_on_malformed_file() {
        // The daemon turns this into a stderr warning + empty ruleset;
        // we just need the function to surface the failure so the
        // daemon's caller can log it.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("broken.toml");
        std::fs::write(&path, "this is not = valid TOML").expect("write");
        assert!(load_rules(&path).is_err());
    }

    #[test]
    fn load_parses_a_hand_authored_file() {
        // This is also the shape m0003 writes. A loader still pointed at
        // the old JSON5 format cannot read the migration's own output.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("auto-rules.toml");
        std::fs::write(
            &path,
            r#"
# Auto-rules — generated by the UI; hand-edits welcome.
[[rules]]
id = "01"
name = "Cursor reads via gh"
enabled = true
decide = "approve"
trained_secrets = ["GITHUB_TOKEN"]

[rules.match]
wrap = "gh"
argv = "gh api --get /repos/*/pulls*"
ancestor = "Cursor.app"
"#,
        )
        .expect("write");
        let loaded = load_rules(&path).expect("load");
        assert_eq!(loaded.rules.len(), 1);
        let r = &loaded.rules[0];
        assert_eq!(r.id, "01");
        assert!(r.enabled);
        let RuleBody::Declarative {
            r#match: m, decide, ..
        } = &r.body
        else {
            panic!("declarative rule");
        };
        assert_eq!(*decide, StaticDecision::Approve);
        assert_eq!(m.wrap, "gh");
        assert_eq!(
            m.argv.as_ref().map(Pattern::as_str),
            Some("gh api --get /repos/*/pulls*")
        );
    }

    #[test]
    fn load_rejects_unknown_toml_keys_at_every_level() {
        let dir = tempfile::tempdir().expect("tempdir");
        for (name, text, unknown) in [
            ("root", "bogus = true\n", "bogus"),
            (
                "rule",
                r#"
[[rules]]
id = "01"
name = "rule"
enabled = true
decide = "approve"
bogus = true

[rules.match]
wrap = "gh"
"#,
                "bogus",
            ),
            (
                "match",
                r#"
[[rules]]
id = "01"
name = "rule"
enabled = true
decide = "approve"

[rules.match]
wrap = "gh"
bogus = true
"#,
                "bogus",
            ),
        ] {
            let path = dir.path().join(format!("{name}.toml"));
            std::fs::write(&path, text).expect("write");
            let err = format!(
                "{:#}",
                load_rules(&path).expect_err("must reject unknown key")
            );
            assert!(err.contains(unknown), "{name}: {err}");
        }
    }

    #[test]
    fn saving_one_changed_rule_preserves_toml_comments() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("auto-rules.toml");
        std::fs::write(
            &path,
            r#"#:schema https://craigory.dev/secreq/schemas/auto-rules.schema.json
# Keep the rule disabled during incident response.
[[rules]]
id = "01" # stable audit identity
name = "Cursor reads via gh"
enabled = true # toggled from the UI
decide = "approve"
trained_secrets = ["GITHUB_TOKEN"]

[rules.match]
wrap = "gh" # only GitHub CLI
"#,
        )
        .expect("write");

        let mut loaded = load_rules(&path).expect("load");
        loaded.rules[0].enabled = false;
        save_rules(&path, &loaded.rules).expect("save");

        let written = std::fs::read_to_string(&path).expect("read back");
        for comment in [
            "#:schema https://craigory.dev/secreq/schemas/auto-rules.schema.json",
            "# Keep the rule disabled during incident response.",
            "# stable audit identity",
            "# toggled from the UI",
            "# only GitHub CLI",
        ] {
            assert!(written.contains(comment), "lost {comment:?}:\n{written}");
        }
        assert!(written.contains("enabled = false"), "{written}");
        toml::from_str::<RulesFileWire>(&written).expect("saved file is TOML");
    }

    #[test]
    fn saving_an_unrelated_field_preserves_an_inline_match_table() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("auto-rules.toml");
        std::fs::write(
            &path,
            r#"
[[rules]]
id = "01"
name = "compact rule"
enabled = true
decide = "approve"
match = { wrap = "gh" } # keep this compact
"#,
        )
        .expect("write");

        let mut loaded = load_rules(&path).expect("load");
        loaded.rules[0].enabled = false;
        save_rules(&path, &loaded.rules).expect("save");

        let written = std::fs::read_to_string(&path).expect("read back");
        assert!(
            written.contains(r#"match = { wrap = "gh" } # keep this compact"#),
            "{written}"
        );
        assert!(!written.contains("[rules.match]"), "{written}");
    }

    // ── Wasm rules in the same evaluation pass ────────────────────────

    #[test]
    fn wasm_deny_beats_declarative_approve() {
        // Mixed ruleset: a declarative glob approve and a wasm rule that
        // denies. Deny-wins must apply across kinds, and the module's
        // returned reason must ride the hit like a deny_message.
        let approve = mk_rule(
            "01",
            "approve gh api",
            RuleDecision::Approve,
            match_for("gh", Some("gh api"), None, None),
            &["GITHUB_TOKEN"],
        );
        let deny = mk_wasm_rule("02", "wasm deny", &["GITHUB_TOKEN"]);
        let modules = modules_for(&[("02", DENY_ECHO)]);
        let c = ctx("gh", "gh api --get /repos/x", &[], "/x", &["GITHUB_TOKEN"]);
        let out = evaluate(&[approve, deny], &modules, &c);
        let hit = out.hit.expect("deny should fire");
        assert_eq!(hit.decide, RuleDecision::Deny);
        assert_eq!(hit.rule_id, "02");
        // deny_echo echoes the ctx as its reason — presence + prefix is
        // enough here (fidelity is covered by the wasm_rules tests).
        assert!(
            hit.deny_message.as_deref().unwrap().starts_with("wrap=gh"),
            "module's returned reason should be the deny message: {hit:?}"
        );
        assert!(out.wasm_failures.is_empty());
    }

    #[test]
    fn declarative_deny_beats_wasm_approve_despite_lower_specificity() {
        // The inverse direction of deny-wins across kinds: a bare
        // declarative deny (specificity 0) must beat a wasm Approve
        // (WASM_DECISION_SPECIFICITY). Pins the invariant that denies
        // and approves compete in *separate* slots — deny-wins is
        // decided before specificity ever gets a say — against a
        // future refactor collapsing them into one max-by-specificity
        // pass.
        let deny = mk_rule(
            "01",
            "block gh",
            RuleDecision::Deny,
            match_for("gh", None, None, None),
            &["GITHUB_TOKEN"],
        );
        let wasm_approve = mk_wasm_rule("02", "wasm approve", &["GITHUB_TOKEN"]);
        let modules = modules_for(&[("02", APPROVE_IF)]);
        let callers = &[EvalCaller {
            name: "Cursor",
            command: "/Applications/Cursor.app/Contents/MacOS/Cursor",
            exe: None,
        }];
        let c = ctx(
            "gh",
            "gh api --get /repos/me/x/pulls",
            callers,
            "/x",
            &["GITHUB_TOKEN"],
        );
        let out = evaluate(&[deny, wasm_approve], &modules, &c);
        let hit = out.hit.expect("deny should fire");
        assert_eq!(hit.decide, RuleDecision::Deny);
        assert_eq!(hit.rule_id, "01");
        assert!(out.wasm_failures.is_empty());
    }

    #[test]
    fn deciding_wasm_approve_outranks_the_most_specific_declarative_approve() {
        // The declarative rule pins all three optional clauses
        // (specificity 3) and has the smaller id; the wasm rule that
        // returns Approve still wins because a programmatic non-Pass
        // decision counts as maximally specific.
        let declarative = mk_rule(
            "01",
            "fully pinned",
            RuleDecision::Approve,
            match_for("gh", Some("gh api"), Some("Cursor.app"), Some("/home")),
            &["GITHUB_TOKEN"],
        );
        let wasm = mk_wasm_rule("02", "wasm approve", &["GITHUB_TOKEN"]);
        let modules = modules_for(&[("02", APPROVE_IF)]);
        let callers = &[EvalCaller {
            name: "Cursor",
            command: "/Applications/Cursor.app/Contents/MacOS/Cursor",
            exe: Some("/Applications/Cursor.app/Contents/MacOS/Cursor"),
        }];
        let c = ctx(
            "gh",
            "gh api --get /repos/me/x/pulls",
            callers,
            "/home/me/x",
            &["GITHUB_TOKEN"],
        );
        let hit = evaluate(&[declarative, wasm], &modules, &c)
            .hit
            .expect("should fire");
        assert_eq!(hit.decide, RuleDecision::Approve);
        assert_eq!(hit.rule_id, "02");
    }

    #[test]
    fn two_deciding_wasm_rules_tie_break_on_smallest_id() {
        let b = mk_wasm_rule("r_bbb", "bbb", &["GITHUB_TOKEN"]);
        let a = mk_wasm_rule("r_aaa", "aaa", &["GITHUB_TOKEN"]);
        let modules = modules_for(&[("r_bbb", APPROVE_IF), ("r_aaa", APPROVE_IF)]);
        let callers = &[EvalCaller {
            name: "Cursor",
            command: "/Applications/Cursor.app/Contents/MacOS/Cursor",
            exe: None,
        }];
        let c = ctx(
            "gh",
            "gh api --get /repos/me/x/pulls",
            callers,
            "/x",
            &["GITHUB_TOKEN"],
        );
        let hit = evaluate(&[b, a], &modules, &c).hit.expect("should fire");
        assert_eq!(hit.rule_id, "r_aaa");
    }

    #[test]
    fn wasm_pass_means_the_rule_does_not_match() {
        let rule = mk_wasm_rule("01", "passes", &["GITHUB_TOKEN"]);
        let modules = modules_for(&[("01", ALWAYS_PASS)]);
        let c = ctx("gh", "gh api", &[], "/x", &["GITHUB_TOKEN"]);
        let out = evaluate(&[rule], &modules, &c);
        assert_eq!(out.hit, None);
        assert!(out.wasm_failures.is_empty());
    }

    // ── Wasm per-secret approval scoping (#265) ───────────────────────

    /// Cursor.app caller + `gh api --get …` ask that makes the APPROVE_IF
    /// fixture return Approve. The `secrets` list is the only thing that
    /// varies across the per-secret tests below (the fixture ignores it).
    fn approve_if_callers() -> [EvalCaller<'static>; 1] {
        [EvalCaller {
            name: "Cursor",
            command: "/Applications/Cursor.app/Contents/MacOS/Cursor",
            exe: None,
        }]
    }

    #[test]
    fn wasm_rule_contributes_its_trained_secret_but_ask_still_prompts_when_another_is_uncovered() {
        // A wasm rule trained on {NPM_TOKEN} now RUNS for an ask that
        // also wants SSH_KEY (the old subset-gate would have skipped it
        // entirely). It blesses NPM_TOKEN — but SSH_KEY has no approver,
        // so the atomic ask still falls through to the prompt.
        let rule = mk_wasm_rule("01", "npm approver", &["NPM_TOKEN"]);
        let modules = modules_for(&[("01", APPROVE_IF)]);
        let callers = approve_if_callers();
        let c = ctx(
            "gh",
            "gh api --get /repos/me/x/pulls",
            &callers,
            "/x",
            &["NPM_TOKEN", "SSH_KEY"],
        );
        assert_eq!(
            evaluate(&[rule], &modules, &c).hit,
            None,
            "SSH_KEY is uncovered, so the whole ask must prompt"
        );
    }

    #[test]
    fn two_wasm_rules_each_trained_on_one_secret_together_cover_the_ask() {
        // Composition: neither rule alone covers {A, B}, but together
        // they bless both — approved, with per-secret attribution.
        let a = mk_wasm_rule("01", "A approver", &["A"]);
        let b = mk_wasm_rule("02", "B approver", &["B"]);
        let modules = modules_for(&[("01", APPROVE_IF), ("02", APPROVE_IF)]);
        let callers = approve_if_callers();
        let c = ctx(
            "gh",
            "gh api --get /repos/me/x/pulls",
            &callers,
            "/x",
            &["A", "B"],
        );
        let hit = evaluate(&[a, b], &modules, &c)
            .hit
            .expect("both secrets covered ⇒ approve");
        assert_eq!(hit.decide, RuleDecision::Approve);
        assert_eq!(hit.approvals.get("A").map(String::as_str), Some("01"));
        assert_eq!(hit.approvals.get("B").map(String::as_str), Some("02"));
    }

    #[test]
    fn a_wasm_approve_does_not_bless_a_secret_outside_its_trained_set() {
        // Structural scoping: a rule trained on {A} that returns Approve
        // must NOT approve B, even though the module said "approve." B is
        // covered here by a second rule trained on {B}, and the approvals
        // map proves A came from rule 01 and B from rule 02 — the {A}
        // rule never reached across to B.
        let a_only = mk_wasm_rule("01", "A only", &["A"]);
        let b_only = mk_wasm_rule("02", "B only", &["B"]);
        let modules = modules_for(&[("01", APPROVE_IF), ("02", APPROVE_IF)]);
        let callers = approve_if_callers();
        let c = ctx(
            "gh",
            "gh api --get /repos/me/x/pulls",
            &callers,
            "/x",
            &["A", "B"],
        );
        let hit = evaluate(&[a_only, b_only], &modules, &c)
            .hit
            .expect("both covered");
        assert_eq!(hit.approvals.get("A").map(String::as_str), Some("01"));
        assert_ne!(
            hit.approvals.get("B").map(String::as_str),
            Some("01"),
            "the {{A}}-trained rule must not approve B"
        );
        assert_eq!(hit.approvals.get("B").map(String::as_str), Some("02"));
    }

    #[test]
    fn a_wasm_approve_alone_cannot_cover_a_secret_outside_its_trained_set() {
        // The same structural property viewed as a veto: with ONLY the
        // {A}-trained rule present, B is uncovered and the ask prompts —
        // the wasm Approve cannot stretch to bless B.
        let a_only = mk_wasm_rule("01", "A only", &["A"]);
        let modules = modules_for(&[("01", APPROVE_IF)]);
        let callers = approve_if_callers();
        let c = ctx(
            "gh",
            "gh api --get /repos/me/x/pulls",
            &callers,
            "/x",
            &["A", "B"],
        );
        assert_eq!(evaluate(&[a_only], &modules, &c).hit, None);
    }

    #[test]
    fn an_all_secrets_wasm_rule_covers_every_requested_secret() {
        // An empty trained snapshot is `--all-secrets`: it overlaps every
        // ask and its Approve blesses all requested secrets at once.
        let rule = mk_wasm_rule("01", "all secrets", &[]);
        let modules = modules_for(&[("01", APPROVE_IF)]);
        let callers = approve_if_callers();
        let c = ctx(
            "gh",
            "gh api --get /repos/me/x/pulls",
            &callers,
            "/x",
            &["A", "B", "C"],
        );
        let hit = evaluate(&[rule], &modules, &c)
            .hit
            .expect("all-secrets rule covers everything");
        assert_eq!(hit.approvals.get("A").map(String::as_str), Some("01"));
        assert_eq!(hit.approvals.get("B").map(String::as_str), Some("01"));
        assert_eq!(hit.approvals.get("C").map(String::as_str), Some("01"));
    }

    #[test]
    fn a_non_overlapping_wasm_rule_is_never_instantiated() {
        // A rule trained on {OTHER} shares no secret with an ask for
        // {A, B}, so it does not overlap and never runs. Pointing it at a
        // module that would trap proves the module was never touched:
        // no wasm_failure is recorded (an instantiated ABORTS traps).
        let rule = mk_wasm_rule("01", "unrelated", &["OTHER"]);
        let modules = modules_for(&[("01", ABORTS)]);
        let callers = approve_if_callers();
        let c = ctx(
            "gh",
            "gh api --get /repos/me/x/pulls",
            &callers,
            "/x",
            &["A", "B"],
        );
        let out = evaluate(&[rule], &modules, &c);
        assert_eq!(out.hit, None);
        assert!(
            out.wasm_failures.is_empty(),
            "non-overlapping rule must not run: {:?}",
            out.wasm_failures
        );
    }

    #[test]
    fn a_deny_vetoes_the_whole_ask_even_when_every_secret_is_approved() {
        // Every secret is blessed by the all-secrets approver, but an
        // overlapping deny kills the entire ask — deny beats the
        // per-secret AND.
        let approver = mk_wasm_rule("01", "all secrets", &[]);
        let deny = mk_rule(
            "02",
            "block deletes",
            RuleDecision::Deny,
            match_for("gh", None, None, None),
            &[],
        );
        let modules = modules_for(&[("01", APPROVE_IF)]);
        let callers = approve_if_callers();
        let c = ctx(
            "gh",
            "gh api --get /repos/me/x/pulls",
            &callers,
            "/x",
            &["A", "B"],
        );
        let hit = evaluate(&[approver, deny], &modules, &c)
            .hit
            .expect("deny should fire");
        assert_eq!(hit.decide, RuleDecision::Deny);
        assert_eq!(hit.rule_id, "02");
        assert!(
            hit.approvals.is_empty(),
            "a deny hit carries no per-secret approvals"
        );
    }

    #[test]
    fn a_wasm_deny_vetoes_a_dangerous_combination_it_only_partly_overlaps() {
        // Decision 1: a deny is a whole-ask veto and is NOT
        // trained-scoped. A rule trained on {NPM_TOKEN} still runs for an
        // ask for {NPM_TOKEN, SSH_KEY} (overlap on NPM_TOKEN), sees the
        // full requested set, and denies the combination.
        let combo_deny = mk_wasm_rule("01", "combo deny", &["NPM_TOKEN"]);
        let modules = modules_for(&[("01", DENY_ECHO)]);
        let callers = approve_if_callers();
        let c = ctx(
            "gh",
            "gh api --get /repos/me/x/pulls",
            &callers,
            "/x",
            &["NPM_TOKEN", "SSH_KEY"],
        );
        let hit = evaluate(&[combo_deny], &modules, &c)
            .hit
            .expect("the combination should be denied");
        assert_eq!(hit.decide, RuleDecision::Deny);
        assert_eq!(hit.rule_id, "01");
    }

    #[test]
    fn per_secret_precedence_picks_the_most_specific_approver_for_each_secret() {
        // A broad all-secrets declarative approve (specificity 0) covers
        // both A and B; a narrow wasm rule trained on {A}
        // (WASM_DECISION_SPECIFICITY) also approves A. Per secret, A goes
        // to the more-specific wasm rule while B stays with the
        // declarative one — precedence resolved independently per secret.
        let broad = mk_rule(
            "01",
            "broad approve",
            RuleDecision::Approve,
            match_for("gh", None, None, None),
            &[],
        );
        let narrow_a = mk_wasm_rule("02", "narrow A", &["A"]);
        let modules = modules_for(&[("02", APPROVE_IF)]);
        let callers = approve_if_callers();
        let c = ctx(
            "gh",
            "gh api --get /repos/me/x/pulls",
            &callers,
            "/x",
            &["A", "B"],
        );
        let hit = evaluate(&[broad, narrow_a], &modules, &c)
            .hit
            .expect("both covered");
        assert_eq!(
            hit.approvals.get("A").map(String::as_str),
            Some("02"),
            "A resolves to the most-specific (wasm) approver"
        );
        assert_eq!(
            hit.approvals.get("B").map(String::as_str),
            Some("01"),
            "B resolves to the only approver, the declarative rule"
        );
        // The whole-ask representative is the most-specific approver.
        assert_eq!(hit.rule_id, "02");
    }

    #[test]
    fn erroring_wasm_rule_falls_through_to_the_prompt_and_is_reported() {
        // Fail-safe policy: a module that traps at evaluate time is
        // treated as NOT matching (interactive consent, never an
        // auto-approve) and the failure is surfaced for logging.
        let rule = mk_wasm_rule("01", "aborts", &["GITHUB_TOKEN"]);
        let modules = modules_for(&[("01", ABORTS)]);
        let c = ctx("gh", "gh api", &[], "/x", &["GITHUB_TOKEN"]);
        let out = evaluate(&[rule], &modules, &c);
        assert_eq!(out.hit, None, "an erroring rule must not decide");
        assert_eq!(out.wasm_failures.len(), 1);
        let failure = &out.wasm_failures[0];
        assert_eq!(failure.rule_id, "01");
        assert_eq!(failure.rule_name, "aborts");
        assert!(
            failure.error.contains("trapped"),
            "error should carry the host chain: {}",
            failure.error
        );
    }

    #[test]
    fn an_erroring_wasm_rule_suppresses_a_competing_approve() {
        // The composition the docs encourage: a broad declarative approve
        // plus a wasm rule carrying nuance the match clause cannot express
        // ("never auto-approve `gh repo delete`"). When the module stops
        // working, "the rule does not match" used to mean the approve won
        // and the ask was released with no prompt — so tampering with one
        // file both disabled the guard and left the guarded thing enabled.
        let broken = mk_wasm_rule("01", "aborts", &["GITHUB_TOKEN"]);
        let approve = mk_rule(
            "02",
            "declarative approve",
            RuleDecision::Approve,
            match_for("gh", None, None, None),
            &["GITHUB_TOKEN"],
        );
        let modules = modules_for(&[("01", ABORTS)]);
        let c = ctx("gh", "gh api", &[], "/x", &["GITHUB_TOKEN"]);
        let out = evaluate(&[broken, approve], &modules, &c);

        assert!(
            out.hit.is_none(),
            "an approve must not win an evaluation that could not consult every rule"
        );
        let mandate = out
            .mandated_prompt
            .expect("the unconsultable rule should mandate a prompt");
        assert_eq!(mandate.rule_id, "01");
        assert_eq!(out.wasm_failures.len(), 1);
    }

    /// A refused module (sha256 mismatch, missing file) is the same class of
    /// hazard as one that trapped: an opinion we do not have. The existing
    /// load-path test proves a tampered module does not knock out the user's
    /// other rules; this proves it does not silently promote them either.
    #[test]
    fn a_refused_wasm_module_suppresses_a_competing_approve() {
        let refused = mk_wasm_rule("01", "never loaded", &["GITHUB_TOKEN"]);
        let approve = mk_rule(
            "02",
            "declarative approve",
            RuleDecision::Approve,
            match_for("gh", None, None, None),
            &["GITHUB_TOKEN"],
        );
        // No module registered for "01" — exactly what a load refusal leaves.
        let modules = RuleModules::new();
        let c = ctx("gh", "gh api", &[], "/x", &["GITHUB_TOKEN"]);
        let out = evaluate(&[refused, approve], &modules, &c);

        assert!(
            out.hit.is_none(),
            "incomplete ruleset must not auto-approve"
        );
        assert_eq!(out.mandated_prompt.expect("mandate").rule_id, "01");
    }

    /// A deny still outranks a mandate. Refusing is strictly stronger than
    /// asking, and a mandate that could veto a deny would let a broken module
    /// turn a block into a dialog the user can click through.
    #[test]
    fn a_deny_still_wins_over_a_mandated_prompt() {
        let broken = mk_wasm_rule("01", "aborts", &["GITHUB_TOKEN"]);
        let deny = mk_rule(
            "02",
            "declarative deny",
            RuleDecision::Deny,
            match_for("gh", None, None, None),
            &["GITHUB_TOKEN"],
        );
        let modules = modules_for(&[("01", ABORTS)]);
        let c = ctx("gh", "gh api", &[], "/x", &["GITHUB_TOKEN"]);
        let out = evaluate(&[broken, deny], &modules, &c);

        let hit = out.hit.expect("the deny still fires");
        assert_eq!(hit.decide, RuleDecision::Deny);
        assert_eq!(hit.rule_id, "02");
        // Spent: the ask is blocked, so "we also wanted to ask you" is noise.
        assert!(out.mandated_prompt.is_none());
    }

    #[test]
    fn wasm_rule_without_a_loaded_module_never_fires() {
        // A rule refused at load time (sha256 mismatch etc.) has no
        // entry in the modules map. It must not fire — and must not be
        // re-reported here, since the load path already warned.
        let rule = mk_wasm_rule("01", "refused", &["GITHUB_TOKEN"]);
        let c = ctx("gh", "gh api", &[], "/x", &["GITHUB_TOKEN"]);
        let out = evaluate(&[rule], &RuleModules::new(), &c);
        assert_eq!(out.hit, None);
        assert!(out.wasm_failures.is_empty());
    }

    // ── Rule shape: declarative XOR wasm ──────────────────────────────

    // The shape is now the type — [`RuleBody`] cannot hold both kinds
    // or neither — so what is left to check is the *bytes*. These run
    // against the deserializer, which is the only door a hand-edited
    // file or an IPC message has into a [`Rule`], and they pin the
    // message each rejection gives its reader.

    /// Deserialize one rule object, expecting rejection, and return the
    /// message.
    fn reject(rule: serde_json::Value) -> String {
        serde_json::from_value::<Rule>(rule)
            .expect_err("must reject")
            .to_string()
    }

    #[test]
    fn shape_rejects_both_match_and_wasm() {
        let err = reject(serde_json::json!({
            "id": "01", "name": "confused", "enabled": true,
            "decide": "approve",
            "match": { "wrap": "gh" },
            "wasm": { "path": "01.wasm", "sha256": "00" },
        }));
        assert!(err.contains("both") && err.contains("confused"), "{err}");
    }

    #[test]
    fn shape_rejects_neither_match_nor_wasm() {
        let err = reject(serde_json::json!({
            "id": "01", "name": "empty", "enabled": true,
        }));
        assert!(err.contains("neither"), "{err}");
    }

    #[test]
    fn shape_rejects_static_decide_on_a_wasm_rule() {
        let err = reject(serde_json::json!({
            "id": "01", "name": "w", "enabled": true,
            "decide": "approve",
            "wasm": { "path": "01.wasm", "sha256": "00" },
        }));
        assert!(err.contains("decide"), "{err}");
    }

    #[test]
    fn shape_rejects_static_deny_message_on_a_wasm_rule() {
        let err = reject(serde_json::json!({
            "id": "01", "name": "w", "enabled": true,
            "deny_message": "static",
            "wasm": { "path": "01.wasm", "sha256": "00" },
        }));
        assert!(err.contains("deny_message"), "{err}");
    }

    #[test]
    fn declarative_rule_without_decide_is_rejected() {
        let err = reject(serde_json::json!({
            "id": "01", "name": "no decide", "enabled": true,
            "match": { "wrap": "gh" },
        }));
        assert!(err.contains("decide"), "{err}");
    }

    #[test]
    fn load_rejects_a_rule_with_both_shapes_loudly() {
        // The shape check is a *file-level* error — same class as bad
        // TOML — so the whole load fails and the daemon's existing
        // warn-and-continue-empty contract kicks in.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("auto-rules.toml");
        std::fs::write(
            &path,
            r#"
[[rules]]
id = "01"
name = "confused"
enabled = true
decide = "approve"

[rules.match]
wrap = "gh"

[rules.wasm]
path = "01.wasm"
sha256 = "00"
"#,
        )
        .expect("write");
        let err = format!("{:#}", load_rules(&path).expect_err("must reject"));
        assert!(err.contains("both") && err.contains("confused"), "{err}");
    }

    // ── Wasm storage: sha256 pinning at load time ─────────────────────

    /// Write a rules file + module bytes into a tempdir and load it.
    fn load_with_module(rule: Rule, module_file: &str, bytes: &[u8]) -> LoadedRules {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("auto-rules.toml");
        std::fs::write(dir.path().join(module_file), bytes).expect("write module");
        save_rules(&path, std::slice::from_ref(&rule)).expect("save");
        load_rules(&path).expect("load")
    }

    #[test]
    fn load_compiles_and_verifies_a_wasm_rule_end_to_end() {
        let mut rule = mk_wasm_rule("01", "wasm approve", &["GITHUB_TOKEN"]);
        set_wasm(
            &mut rule,
            WasmRule {
                path: "mod.wasm".to_owned(),
                sha256: sha256_hex(APPROVE_IF),
            },
        );
        let loaded = load_with_module(rule.clone(), "mod.wasm", APPROVE_IF);
        assert_eq!(loaded.rules, vec![rule]);
        assert!(
            loaded.refusals.wasm.is_empty(),
            "{:?}",
            loaded.refusals.wasm
        );
        assert!(loaded.modules.contains_key("01"));
        // And the loaded module actually evaluates.
        let callers = &[EvalCaller {
            name: "Cursor",
            command: "/Applications/Cursor.app/Contents/MacOS/Cursor",
            exe: None,
        }];
        let c = ctx(
            "gh",
            "gh api --get /repos/me/x/pulls",
            callers,
            "/x",
            &["GITHUB_TOKEN"],
        );
        let hit = evaluate(&loaded.rules, &loaded.modules, &c)
            .hit
            .expect("should fire");
        assert_eq!(hit.rule_id, "01");
    }

    #[test]
    fn sha256_is_case_insensitive() {
        let mut rule = mk_wasm_rule("01", "wasm approve", &[]);
        set_wasm(
            &mut rule,
            WasmRule {
                path: "mod.wasm".to_owned(),
                sha256: sha256_hex(APPROVE_IF).to_uppercase(),
            },
        );
        let loaded = load_with_module(rule, "mod.wasm", APPROVE_IF);
        assert!(
            loaded.refusals.wasm.is_empty(),
            "{:?}",
            loaded.refusals.wasm
        );
        assert!(loaded.modules.contains_key("01"));
    }

    #[test]
    fn sha256_mismatch_refuses_that_rule_but_keeps_the_rest() {
        // A tampered module is a per-rule refusal, not a file-level
        // failure: the user's other rules — critically their protective
        // deny rules — keep working while the bad module is loudly
        // reported. See the load_rules doc for the two-tier rationale.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("auto-rules.toml");
        std::fs::write(dir.path().join("mod.wasm"), APPROVE_IF).expect("write module");
        let mut tampered = mk_wasm_rule("01", "tampered", &[]);
        set_wasm(
            &mut tampered,
            WasmRule {
                path: "mod.wasm".to_owned(),
                sha256: sha256_hex(b"different bytes entirely"),
            },
        );
        let deny = mk_rule(
            "02",
            "block deletes",
            RuleDecision::Deny,
            match_for("gh", Some("gh repo delete *"), None, None),
            &[],
        );
        save_rules(&path, &[tampered, deny]).expect("save");
        let loaded = load_rules(&path).expect("per-rule refusal is not a load error");
        assert_eq!(loaded.rules.len(), 2);
        assert!(loaded.modules.is_empty());
        assert_eq!(loaded.refusals.wasm.len(), 1);
        let refusal = &loaded.refusals.wasm[0];
        assert_eq!(refusal.rule_id, "01");
        assert_eq!(refusal.category, WasmRefusalCategory::Sha256Mismatch);
        let msg = &refusal.reason;
        assert!(
            msg.contains("sha256 mismatch") && msg.contains("tampered") && msg.contains("mod.wasm"),
            "error must name the rule and path: {msg}"
        );
        // The tampered rule can never fire; the deny still does.
        let c = ctx("gh", "gh repo delete me/x", &[], "/x", &[]);
        let hit = evaluate(&loaded.rules, &loaded.modules, &c)
            .hit
            .expect("deny still fires");
        assert_eq!(hit.rule_id, "02");
    }

    #[test]
    fn missing_module_file_is_a_per_rule_error_naming_rule_and_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("auto-rules.toml");
        let mut rule = mk_wasm_rule("01", "gone", &[]);
        set_wasm(
            &mut rule,
            WasmRule {
                path: "nonexistent.wasm".to_owned(),
                sha256: sha256_hex(APPROVE_IF),
            },
        );
        save_rules(&path, &[rule]).expect("save");
        let loaded = load_rules(&path).expect("load");
        assert_eq!(loaded.refusals.wasm.len(), 1);
        let refusal = &loaded.refusals.wasm[0];
        assert_eq!(refusal.rule_id, "01");
        assert_eq!(refusal.category, WasmRefusalCategory::MissingModule);
        let msg = &refusal.reason;
        assert!(
            msg.contains("gone") && msg.contains("nonexistent.wasm"),
            "{msg}"
        );
    }

    #[test]
    fn declarative_rule_serialization_gains_no_wasm_noise() {
        // The optional wasm/decide/match fields must not change what a
        // declarative rule looks like on disk (hand-edits, schema).
        let rule = mk_rule(
            "01",
            "r",
            RuleDecision::Approve,
            match_for("gh", None, None, None),
            &[],
        );
        let json = serde_json::to_value(&rule).expect("serialize");
        assert!(json.get("wasm").is_none());
        assert_eq!(json["decide"], "approve");
        assert_eq!(json["match"]["wrap"], "gh");
        // And a wasm rule serializes without declarative fields.
        let wasm = mk_wasm_rule("02", "w", &[]);
        let json = serde_json::to_value(&wasm).expect("serialize");
        assert!(json.get("decide").is_none());
        assert!(json.get("match").is_none());
        assert_eq!(json["wasm"]["path"], "02.wasm");
    }

    // ── The on-disk format, pinned ────────────────────────────────────
    //
    // `auto-rules.toml` is a file users have on disk today and
    // hand-edit. `docs/auto-rules.schema.json` is now derived from
    // [`RuleWire`], so `tests/schema_drift.rs` covers the *shape* — what
    // keys exist, which are required, what each one may hold.
    //
    // These tests cover the bytes, which no schema constrains: the exact
    // object each legal rule serializes to, and the order the keys come out
    // in. A refactor of the type (nesting the declarative-XOR-wasm shape
    // into a sum type, say) can leave the schema entirely valid and still
    // shuffle every line of a user's file the next time the daemon writes
    // it. That is what fails here.

    #[test]
    fn a_declarative_rule_serializes_to_exactly_this_object() {
        let mut rule = mk_rule(
            "0a1b2c3d4e5f",
            "Cursor reads via gh",
            RuleDecision::Deny,
            match_for(
                "gh",
                Some("gh repo delete *"),
                Some("Cursor.app"),
                Some("/Users/me/oss"),
            ),
            &["GITHUB_TOKEN", "GITHUB_REPO_TOKEN"],
        );
        set_deny_message(&mut rule, Some("Use the UI instead."));
        rule.created_at_unix = 1_700_000_000;
        assert_eq!(
            serde_json::to_value(&rule).expect("serialize"),
            serde_json::json!({
                "id": "0a1b2c3d4e5f",
                "name": "Cursor reads via gh",
                "enabled": true,
                "decide": "deny",
                "match": {
                    "wrap": "gh",
                    // Patterns serialize as their source text, and an
                    // absent clause is an explicit null rather than an
                    // omitted key — `RuleMatch`'s options carry
                    // `default` but no `skip_serializing_if`.
                    "argv": "gh repo delete *",
                    "ancestor": "Cursor.app",
                    "cwd": "/Users/me/oss"
                },
                "trained_secrets": ["GITHUB_REPO_TOKEN", "GITHUB_TOKEN"],
                "deny_message": "Use the UI instead.",
                "created_at_unix": 1_700_000_000
            })
        );
    }

    #[test]
    fn an_unconstrained_declarative_rule_writes_null_match_clauses() {
        // The counterpart to the test above: `wasm` and `deny_message`
        // vanish when absent (`skip_serializing_if`), but the match
        // clause's optional patterns do not.
        let rule = mk_rule(
            "01",
            "r",
            RuleDecision::Approve,
            match_for("gh", None, None, None),
            &[],
        );
        assert_eq!(
            serde_json::to_value(&rule).expect("serialize"),
            serde_json::json!({
                "id": "01",
                "name": "r",
                "enabled": true,
                "decide": "approve",
                "match": { "wrap": "gh", "argv": null, "ancestor": null, "cwd": null },
                "trained_secrets": [],
                "created_at_unix": 0
            })
        );
    }

    #[test]
    fn a_wasm_rule_serializes_to_exactly_this_object() {
        let rule = mk_wasm_rule("0a1b2c3d4e5f", "npm publish guard", &["NPM_TOKEN"]);
        assert_eq!(
            serde_json::to_value(&rule).expect("serialize"),
            serde_json::json!({
                "id": "0a1b2c3d4e5f",
                "name": "npm publish guard",
                "enabled": true,
                "wasm": {
                    "path": "0a1b2c3d4e5f.wasm",
                    "sha256": "unverified-in-eval-tests"
                },
                "trained_secrets": ["NPM_TOKEN"],
                "created_at_unix": 0
            })
        );
    }

    #[test]
    fn a_rule_is_written_in_this_key_order() {
        // Cosmetic but user-visible for every newly-added rule. Serde emits
        // fields in declaration order — but a `flatten`ed
        // body would emit the flattened keys last, silently shuffling
        // `decide` and `match` past `created_at_unix` in every file on
        // every machine. If you mean to reorder, change it here
        // deliberately.
        let mut rule = mk_rule(
            "01",
            "r",
            RuleDecision::Deny,
            match_for("gh", None, None, None),
            &["GITHUB_TOKEN"],
        );
        set_deny_message(&mut rule, Some("no"));
        let text = serde_json::to_string_pretty(&rule).expect("serialize");
        let keys: Vec<&str> = text
            .lines()
            .filter_map(|l| l.strip_prefix("  \""))
            .filter_map(|l| l.split('"').next())
            .collect();
        assert_eq!(
            keys,
            [
                "id",
                "name",
                "enabled",
                "decide",
                "match",
                "trained_secrets",
                "deny_message",
                "created_at_unix"
            ]
        );
    }

    #[test]
    fn a_hand_authored_file_round_trips_through_save_and_load() {
        // The whole path a user's file takes: hand-written TOML in,
        // parsed, rewritten by the daemon, re-read. Both rule shapes
        // must survive it byte-stable — a second save of what the
        // first save produced has to be identical, or the daemon
        // rewrites the user's file differently on every mutation.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("auto-rules.toml");
        std::fs::write(
            &path,
            r#"
[[rules]]
id = "01"
name = "Cursor reads via gh"
enabled = true
decide = "approve"
trained_secrets = ["GITHUB_TOKEN"]
created_at_unix = 1700000000

[rules.match]
wrap = "gh"
argv = "gh api --get /repos/*"

[[rules]]
id = "02"
name = "block deletes"
enabled = false
decide = "deny"
deny_message = "Use the UI instead."
trained_secrets = []

[rules.match]
wrap = "gh"
ancestor = "Cursor.app"
cwd = "/Users/me/oss"

[[rules]]
id = "03"
name = "npm publish guard"
enabled = true
trained_secrets = ["NPM_TOKEN"]

[rules.wasm]
path = "rules/03.wasm"
sha256 = "00"
"#,
        )
        .expect("write");
        let first = load_rules(&path).expect("load hand-authored file");
        assert_eq!(first.rules.len(), 3);

        // Rewriting and re-reading must not change a single rule.
        save_rules(&path, &first.rules).expect("save");
        let written = std::fs::read_to_string(&path).expect("read back");
        let second = load_rules(&path).expect("reload");
        assert_eq!(second.rules, first.rules);
        save_rules(&path, &second.rules).expect("re-save");
        assert_eq!(
            std::fs::read_to_string(&path).expect("read back"),
            written,
            "the daemon must write the same bytes for the same ruleset"
        );

        // And the fields the user wrote are the fields we hold.
        let declarative = &first.rules[0];
        assert_eq!(declarative.created_at_unix, 1_700_000_000);
        let RuleBody::Declarative { decide, .. } = &declarative.body else {
            panic!("rule 01 is declarative");
        };
        assert_eq!(*decide, StaticDecision::Approve);
        let deny = &first.rules[1];
        assert!(!deny.enabled);
        let RuleBody::Declarative { r#match, decide } = &deny.body else {
            panic!("rule 02 is declarative");
        };
        assert_eq!(decide.deny_message(), Some("Use the UI instead."));
        assert_eq!(
            r#match.cwd.as_ref().map(Pattern::as_str),
            Some("/Users/me/oss")
        );
        let wasm = &first.rules[2];
        assert_eq!(wasm.wasm().map(|w| w.path.as_str()), Some("rules/03.wasm"));
    }

    #[test]
    fn load_rejects_a_wasm_rule_carrying_declarative_fields() {
        // The shape check has to run on the *file*, not just on the
        // API. A `decide` or `deny_message` beside a `wasm` module is
        // a rule whose author believes a static decision is in force
        // when the module's return value is what actually decides —
        // so the load fails loudly rather than ignoring the key.
        //
        // This is the case a permissive deserializer (an `untagged`
        // sum type, say) would silently accept by matching the first
        // variant that fits and dropping the rest.
        let dir = tempfile::tempdir().expect("tempdir");
        for (field, snippet) in [
            ("decide", r#"decide = "deny""#),
            ("deny_message", r#"deny_message = "blocked""#),
        ] {
            let path = dir.path().join(format!("{field}.toml"));
            std::fs::write(
                &path,
                format!(
                    r#"
[[rules]]
id = "01"
name = "confused"
enabled = true
{snippet}

[rules.wasm]
path = "01.wasm"
sha256 = "00"
"#
                ),
            )
            .expect("write");
            let err = format!("{:#}", load_rules(&path).expect_err("must reject"));
            assert!(
                err.contains(field) && err.contains("confused"),
                "rejecting `{field}` must name the field and the rule: {err}"
            );
        }
    }

    #[test]
    fn load_rejects_a_match_clause_with_no_decide() {
        // The other silently-droppable half: a declarative rule that
        // never says which way it fires. The evaluator's defensive
        // `let (Some(m), Some(decide)) = …else { continue }` would
        // skip it, so an operator's *deny* would stop covering what
        // they wrote without a word anywhere.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("auto-rules.toml");
        std::fs::write(
            &path,
            r#"
[[rules]]
id = "01"
name = "half a rule"
enabled = true

[rules.match]
wrap = "gh"
"#,
        )
        .expect("write");
        let err = format!("{:#}", load_rules(&path).expect_err("must reject"));
        assert!(
            err.contains("decide") && err.contains("half a rule"),
            "{err}"
        );
    }

    // ── A `deny_message` on a rule that never denies ──────────────────
    //
    // Files carrying `decide: "approve"` beside a `deny_message` load
    // today, so refusing them would break a configuration that works.
    // They are still wrong — the message can never be shown — so the
    // load warns by name and the next write drops the key. That warning
    // is what separates this from the silent-drop failure mode which
    // disqualified `#[serde(untagged)]` for the very same file.

    /// A file whose one rule approves and carries a `deny_message`.
    fn stray_deny_message_file(dir: &Path) -> std::path::PathBuf {
        let path = dir.join("auto-rules.toml");
        std::fs::write(
            &path,
            r#"
[[rules]]
id = "0a1b2c3d4e5f"
name = "Cursor reads via gh"
enabled = true
decide = "approve"
deny_message = "Use the UI instead."
trained_secrets = ["GITHUB_TOKEN"]
created_at_unix = 1700000000

[rules.match]
wrap = "gh"
argv = "gh api --get /repos/*"
"#,
        )
        .expect("write");
        path
    }

    #[test]
    fn an_approve_rule_carrying_a_deny_message_loads_as_a_plain_approve() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = stray_deny_message_file(dir.path());
        let loaded = load_rules(&path).expect("a stray deny_message must not fail the load");
        assert_eq!(loaded.rules.len(), 1);
        let rule = &loaded.rules[0];
        // The rule behaves as the plain approve it says it is …
        let hit = evaluate(
            std::slice::from_ref(rule),
            &RuleModules::new(),
            &ctx(
                "gh",
                "gh api --get /repos/secreq",
                &[],
                "/tmp",
                &["GITHUB_TOKEN"],
            ),
        )
        .hit
        .expect("the approve fires");
        assert_eq!(hit.decide, RuleDecision::Approve);
        assert_eq!(hit.deny_message, None);
        // … and holds no message to be written back.
        let json = serde_json::to_value(rule).expect("serialize");
        assert!(
            json.get("deny_message").is_none(),
            "an approve rule must not carry a deny message: {json}"
        );
    }

    #[test]
    fn loading_a_stray_deny_message_warns_naming_the_file_and_the_rule() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = stray_deny_message_file(dir.path());
        let loaded = load_rules(&path).expect("load");
        assert_eq!(
            loaded.stray_deny_messages,
            vec![StrayDenyMessage {
                rule_id: "0a1b2c3d4e5f".to_owned(),
                rule_name: "Cursor reads via gh".to_owned(),
            }]
        );
        let warning = stray_deny_message_warning(&path, &loaded.stray_deny_messages[0]);
        // Naming the file is the whole point: without it this reads
        // exactly like the silent drop it exists not to be.
        assert!(warning.contains(&path.display().to_string()), "{warning}");
        assert!(warning.contains("Cursor reads via gh"), "{warning}");
        assert!(warning.contains("0a1b2c3d4e5f"), "{warning}");
        assert!(warning.contains("deny_message"), "{warning}");
        // And it says what happens: ignored now, gone on the next write.
        assert!(warning.contains("ignored"), "{warning}");
        assert!(warning.contains("next time"), "{warning}");
    }

    #[test]
    fn saving_after_a_stray_deny_message_drops_only_that_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = stray_deny_message_file(dir.path());
        let loaded = load_rules(&path).expect("load");
        save_rules(&path, &loaded.rules).expect("save");
        let written = std::fs::read_to_string(&path).expect("read back");

        // The same rule authored without the stray key must produce
        // byte-identical output — the drop is the only difference.
        let clean_path = dir.path().join("clean.toml");
        std::fs::write(
            &clean_path,
            r#"
[[rules]]
id = "0a1b2c3d4e5f"
name = "Cursor reads via gh"
enabled = true
decide = "approve"
trained_secrets = ["GITHUB_TOKEN"]
created_at_unix = 1700000000

[rules.match]
wrap = "gh"
argv = "gh api --get /repos/*"
"#,
        )
        .expect("write");
        let clean = load_rules(&clean_path).expect("load");
        assert!(clean.stray_deny_messages.is_empty());
        save_rules(&clean_path, &clean.rules).expect("save");
        assert_eq!(
            written,
            std::fs::read_to_string(&clean_path).expect("read back"),
            "dropping the stray key must be the only change to the file"
        );
        assert!(!written.contains("deny_message"), "{written}");
    }

    #[test]
    fn a_deny_rules_message_survives_load_and_save_unchanged() {
        // The guard, not the repro: this passed before the nesting and
        // must pass after it. A legitimate deny message is part of the
        // format and nothing here may move it.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("auto-rules.toml");
        std::fs::write(
            &path,
            r#"
[[rules]]
id = "0a1b2c3d4e5f"
name = "block deletes"
enabled = true
decide = "deny"
deny_message = "Use the UI instead."
trained_secrets = ["GITHUB_TOKEN"]
created_at_unix = 1700000000

[rules.match]
wrap = "gh"
argv = "gh repo delete *"
"#,
        )
        .expect("write");
        let loaded = load_rules(&path).expect("load");
        assert!(loaded.stray_deny_messages.is_empty());
        save_rules(&path, &loaded.rules).expect("save");
        let written = std::fs::read_to_string(&path).expect("read back");
        assert!(
            written.contains(r#"deny_message = "Use the UI instead.""#),
            "{written}"
        );
        // And a second pass writes the same bytes.
        let again = load_rules(&path).expect("reload");
        save_rules(&path, &again.rules).expect("re-save");
        assert_eq!(std::fs::read_to_string(&path).expect("read back"), written);
    }

    // ── ID generation ─────────────────────────────────────────────────

    #[test]
    fn new_rule_id_is_lowercase_hex_and_24_chars() {
        let id = new_rule_id();
        assert_eq!(id.len(), 24);
        assert!(id
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
    }

    #[test]
    fn new_rule_id_is_unique_across_many_calls() {
        // 12 random bytes = 96 bits of entropy; collisions across 1000
        // generations are vanishingly unlikely. Sanity check the
        // generator isn't constant.
        let mut ids = BTreeSet::new();
        for _ in 0..1000 {
            ids.insert(new_rule_id());
        }
        assert_eq!(ids.len(), 1000);
    }

    /// A literal `cwd` must match whole path segments. Plain `starts_with`
    /// let a rule the user scoped to one checkout also fire from any sibling
    /// directory sharing that name as a byte prefix.
    #[test]
    fn literal_cwd_matches_whole_segments_only() {
        let p = Pattern::parse("/Users/me/oss");
        assert!(p.matches_path_prefix("/Users/me/oss"));
        assert!(p.matches_path_prefix("/Users/me/oss/repo"));
        assert!(!p.matches_path_prefix("/Users/me/ossuary"));
        assert!(!p.matches_path_prefix("/Users/me/oss-scratch"));
        assert!(!p.matches_path_prefix("/Users/me/other"));
    }

    /// `~/oss/` and `~/oss` must mean the same thing — otherwise the spelling
    /// that reads as "explicitly a directory" is the one that fails to match
    /// the directory itself.
    #[test]
    fn a_trailing_slash_on_a_cwd_pattern_is_optional() {
        let with = Pattern::parse("/Users/me/oss/");
        assert!(with.matches_path_prefix("/Users/me/oss"));
        assert!(with.matches_path_prefix("/Users/me/oss/repo"));
        assert!(!with.matches_path_prefix("/Users/me/ossuary"));
    }

    /// argv keeps raw-prefix semantics: `gh api` must still match
    /// `gh api --get /repos/x`, which has no segment structure to respect.
    #[test]
    fn argv_prefix_stays_byte_wise() {
        let p = Pattern::parse("gh api");
        assert!(p.matches_prefix("gh api --get /repos/x"));
        assert!(p.matches_prefix("gh api"));
        assert!(!p.matches_prefix("gh pr list"));
    }

    /// `pass()` leaves a competing approve free to release the ask silently.
    /// `prompt()` is the difference: it suppresses the approve and sends the
    /// ask to the user instead.
    #[test]
    fn a_wasm_prompt_suppresses_a_competing_approve() {
        let asks_human = mk_wasm_rule("01", "needs a human", &["NPM_TOKEN"]);
        let approve = mk_rule(
            "02",
            "declarative approve",
            RuleDecision::Approve,
            match_for("npm", None, None, None),
            &["NPM_TOKEN"],
        );
        let modules = modules_for(&[("01", PROMPTS)]);
        let c = ctx("npm", "npm publish", &[], "/x", &["NPM_TOKEN"]);
        let out = evaluate(&[asks_human, approve], &modules, &c);

        assert!(out.hit.is_none(), "the approve must not win");
        let mandate = out.mandated_prompt.expect("a mandate");
        assert_eq!(mandate.rule_id, "01");
        assert_eq!(mandate.reason, "needs a human for wrap=npm");
        assert!(out.wasm_failures.is_empty(), "a mandate is not a failure");
    }

    /// Contrast, so the distinction from `pass()` is pinned rather than
    /// implied: the same ruleset with a passing module releases silently.
    #[test]
    fn a_wasm_pass_leaves_a_competing_approve_alone() {
        let passes = mk_wasm_rule("01", "no opinion", &["NPM_TOKEN"]);
        let approve = mk_rule(
            "02",
            "declarative approve",
            RuleDecision::Approve,
            match_for("npm", None, None, None),
            &["NPM_TOKEN"],
        );
        let modules = modules_for(&[("01", ALWAYS_PASS)]);
        let c = ctx("npm", "npm publish", &[], "/x", &["NPM_TOKEN"]);
        let out = evaluate(&[passes, approve], &modules, &c);

        assert_eq!(out.hit.expect("the approve fires").rule_id, "02");
        assert!(out.mandated_prompt.is_none());
    }

    /// Deny > Prompt: a module asking for a human cannot soften another
    /// rule's refusal into a dialog.
    #[test]
    fn a_deny_outranks_a_wasm_prompt() {
        let asks_human = mk_wasm_rule("01", "needs a human", &["NPM_TOKEN"]);
        let deny = mk_rule(
            "02",
            "declarative deny",
            RuleDecision::Deny,
            match_for("npm", None, None, None),
            &["NPM_TOKEN"],
        );
        let modules = modules_for(&[("01", PROMPTS)]);
        let c = ctx("npm", "npm publish", &[], "/x", &["NPM_TOKEN"]);
        let out = evaluate(&[asks_human, deny], &modules, &c);

        assert_eq!(out.hit.expect("the deny fires").decide, RuleDecision::Deny);
        assert!(out.mandated_prompt.is_none());
    }

    /// `name` is `comm` and `command` is argv; a process picks both. So
    /// `ancestor: "Cursor.app"` — the example in the docs, the tests and the
    /// schema — used to be satisfied by anything that merely put that text in
    /// its command line.
    #[test]
    fn an_ancestor_pattern_is_not_satisfied_by_a_self_reported_name() {
        let p = Pattern::parse("Cursor.app");

        // The real editor: the text is in the path the kernel recorded.
        assert!(p.matches_ancestor(&EvalCaller {
            name: "Cursor",
            command: "/Applications/Cursor.app/Contents/MacOS/Cursor --psn_0_1",
            exe: Some("/Applications/Cursor.app/Contents/MacOS/Cursor"),
        }));

        // An impostor: `sh -c '# /Applications/Cursor.app/…'`. The argv says
        // Cursor, the binary does not.
        assert!(!p.matches_ancestor(&EvalCaller {
            name: "Cursor",
            command: "sh -c # /Applications/Cursor.app/Contents/MacOS/Cursor",
            exe: Some("/bin/sh"),
        }));
    }

    /// sysinfo cannot always resolve an exe. Falling back to the pair keeps
    /// existing rules working there rather than silently never matching —
    /// weaker, but honest about which of the two states it is in.
    #[test]
    fn an_ancestor_pattern_falls_back_to_the_pair_without_an_exe() {
        let p = Pattern::parse("Cursor.app");
        assert!(p.matches_ancestor(&EvalCaller {
            name: "Cursor",
            command: "/Applications/Cursor.app/Contents/MacOS/Cursor",
            exe: None,
        }));
    }
}
