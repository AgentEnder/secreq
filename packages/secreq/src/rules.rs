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

use std::collections::{BTreeSet, HashMap};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::wasm_rules::{Decision as WasmDecision, RuleModule};

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
        /// The rule's decision whenever the match clause fires.
        decide: RuleDecision,
        /// Message shown to the user on auto-deny — the wrap client
        /// prints it to stderr, the consent window renders it in a toast
        /// row. Only consulted when `decide == Deny`; an approve rule may
        /// carry one, because files on disk do and refusing to load them
        /// would be a format change rather than a type cleanup.
        deny_message: Option<String>,
    },
    Wasm(WasmRule),
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

/// The on-disk / on-the-wire shape of a [`Rule`]: the flat object with
/// four optional fields that users hand-edit in `auto-rules.json5`.
///
/// This exists so `Rule` can be a sum type *and* leave the file format
/// exactly where it is. The two obvious alternatives both move it.
/// `#[serde(flatten)]` writes the flattened keys last, shuffling
/// `decide`/`match` past `created_at_unix` in every file the daemon
/// rewrites — and it rewrites the whole file on every mutation.
/// `#[serde(untagged)]` matches the first variant that fits and **drops
/// the leftover keys**, so a wasm rule carrying `decide: "deny"` would
/// load as "whatever the module returns" where today it is a loud error;
/// `deny_unknown_fields` cannot be combined with `flatten` to rescue it.
///
/// Field order here is the written key order — see
/// `a_rule_is_written_in_this_key_order`.
#[derive(Serialize, Deserialize)]
struct RuleWire {
    id: String,
    name: String,
    enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    decide: Option<RuleDecision>,
    #[serde(rename = "match", default, skip_serializing_if = "Option::is_none")]
    r#match: Option<RuleMatch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    wasm: Option<WasmRule>,
    #[serde(default)]
    trained_secrets: BTreeSet<String>,
    /// Skipped when absent so saved rules validate against the schema
    /// (which types it as a string, and forbids the key entirely on wasm
    /// rules).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    deny_message: Option<String>,
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
                RuleBody::Declarative {
                    r#match,
                    decide,
                    deny_message: wire.deny_message,
                }
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
            RuleBody::Declarative {
                r#match,
                decide,
                deny_message,
            } => (Some(decide), Some(r#match), None, deny_message),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleDecision {
    Approve,
    Deny,
}

/// Reference to a compiled wasm rule module. The module bytes live on
/// disk (canonically `rules/<id>.wasm` under the secreq root — see
/// [`crate::paths::rule_wasm_path`]); the rules file pins them by
/// content hash.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WasmRule {
    /// Path to the compiled `.wasm` module. Relative paths resolve
    /// against the directory containing `auto-rules.json5`.
    pub path: String,
    /// Lowercase-hex SHA-256 of the module bytes, recorded when the
    /// rule was registered and **verified on every load**. A mismatch
    /// refuses this rule (it can never fire) with a loud error naming
    /// the rule and path.
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

/// The match clause. All present fields must match for the rule to
/// fire; absent fields are unconstrained ("any"). `wrap` is exact
/// (no glob); the rest go through [`Pattern`].
///
/// **What each pattern is matched against**:
/// - `argv`: the joined argv of the wrapped command,
///   `ask.command.join(" ")`. Literal = prefix; glob = full pattern.
/// - `ancestor`: for each caller in the process chain, the pattern
///   is tested against BOTH the caller's short process name
///   (`sysinfo::Process::name()`, typically the executable basename
///   like `zsh`, `Cursor`) AND the caller's full joined command line
///   (`sysinfo::Process::cmd()` joined with spaces, e.g.
///   `/Applications/Cursor.app/Contents/MacOS/Cursor --psn_0_12345`).
///   First match anywhere in the chain wins. The caller's executable
///   path (`exe`) is **not** currently part of the match input — only
///   what's reflected in `name` and `command`. Literal = substring;
///   glob = full pattern.
/// - `cwd`: the requesting process's working directory,
///   `ask.cwd`. Literal = **path-segment-aware** prefix (`/Users/me/oss`
///   matches `/Users/me/oss` and `/Users/me/oss/repo`, but **not**
///   `/Users/me/ossuary`); a trailing `/` on the pattern is optional. Glob =
///   full pattern. Unlike `argv`, which prefixes raw bytes, a path prefix that
///   stops mid-segment names no directory and would silently widen the rule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuleMatch {
    pub wrap: String,
    #[serde(default)]
    pub argv: Option<Pattern>,
    #[serde(default)]
    pub ancestor: Option<Pattern>,
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
/// Serializes as the raw source string.
#[derive(Debug, Clone)]
pub struct Pattern {
    raw: String,
    kind: PatternKind,
}

#[derive(Debug, Clone)]
enum PatternKind {
    Literal,
    Glob(glob::Pattern),
}

impl Pattern {
    /// Parse a pattern string. A bad glob falls back to a literal —
    /// we never reject a rule purely because its glob didn't compile.
    pub fn parse(raw: impl Into<String>) -> Pattern {
        let raw = raw.into();
        let kind = if has_wildcards(&raw) {
            match glob::Pattern::new(&raw) {
                Ok(g) => PatternKind::Glob(g),
                Err(_) => PatternKind::Literal,
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

impl<'de> Deserialize<'de> for Pattern {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        Ok(Pattern::parse(raw))
    }
}

fn has_wildcards(s: &str) -> bool {
    s.chars().any(|c| matches!(c, '*' | '?' | '['))
}

/// The on-disk file shape. Top-level wrapper around a rule list so we
/// can add metadata fields ($schema, $version) later without breaking
/// the format.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RulesFile {
    #[serde(default)]
    pub rules: Vec<Rule>,
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
    /// One [`WasmRefusal`] per wasm rule refused at load time (missing
    /// module file, sha256 mismatch, compile/sandbox rejection). The
    /// rule itself stays in `rules` — visible to the UI and CLI — but
    /// has no entry in `modules`, so it can never fire. The caller
    /// must surface these loudly (the daemon logs each one and retains
    /// them so list/show/UI render the refusal).
    pub wasm_refusals: Vec<WasmRefusal>,
}

/// Load rules from `path`. A missing file returns an empty
/// `LoadedRules` (not an error) — the daemon should run normally
/// when no rules are configured. Malformed files DO return an error;
/// the daemon turns that into a stderr warning + empty ruleset.
///
/// ## Failure granularity (deliberate, two-tier)
///
/// - **File-level**: unparseable JSON5 or a rule whose *shape* is
///   invalid (both `match` and `wasm`, neither, a wasm rule with
///   `decide`/`deny_message`) errors the whole load — the file was
///   authored wrong, same class as a syntax error, and the daemon's
///   existing "warn + empty ruleset" contract applies. Both are
///   literally the same error now: the shape check lives in
///   `TryFrom<RuleWire> for Rule`, so it runs inside the parse.
/// - **Per-rule**: a wasm rule whose *referenced module* fails to load
///   (missing file, sha256 mismatch, sandbox rejection) refuses just
///   that rule, recorded in [`LoadedRules::wasm_refusals`]. A tampered
///   or stale module is a loud security event, but it must not knock
///   out the user's other rules — in particular their protective
///   *deny* rules, which would otherwise stop firing exactly when
///   something on disk is being tampered with.
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
    let parsed: RulesFile = json5::from_str(&text)
        .with_context(|| format!("parse auto-rules file: {}", path.display()))?;
    // Relative wasm paths anchor at the rules file's directory.
    let rules_dir = path.parent().unwrap_or(Path::new(""));
    let mut modules = RuleModules::new();
    let mut wasm_refusals = Vec::new();
    for rule in &parsed.rules {
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
    Ok(LoadedRules {
        rules: parsed.rules,
        mtime,
        modules,
        wasm_refusals,
    })
}

/// Atomically replace the rules file with `rules`. Used by the
/// AddRule / UpdateRule / DeleteRule / SetRuleEnabled IPC paths. The
/// daemon owns all writes; users hand-edit only when the daemon is
/// stopped.
pub fn save_rules(path: &Path, rules: &[Rule]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create dir {}", parent.display()))?;
    }
    let file = RulesFile {
        rules: rules.to_vec(),
    };
    // Pretty JSON. JSON5 is a superset, so this round-trips cleanly.
    let json = serde_json::to_string_pretty(&file).context("serialize rules")?;
    // Write through a temp file + rename for atomic replace, so a
    // crash mid-write can't leave a half-written file.
    let tmp = path.with_extension("json5.tmp");
    std::fs::write(&tmp, json).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

/// `mtime` of the rules file, or `None` if it doesn't exist. The
/// daemon's freshness check stats this before each ask; an mtime that
/// has advanced past the daemon's startup-time value triggers a
/// clean shutdown.
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

/// One matching rule with its (possibly wasm-computed) decision,
/// competing for the hit.
struct Candidate<'r> {
    rule: &'r Rule,
    decide: RuleDecision,
    deny_message: Option<String>,
    specificity: u32,
}

/// Evaluate `rules` against `ctx` in a single pass — declarative and
/// wasm rules compete in the same precedence order. `modules` holds
/// the compiled module for every loadable wasm rule (see
/// [`RuleModules`]); a wasm rule with no entry was refused at load
/// time and never matches.
///
/// Returns an [`Evaluation`] whose `hit` is:
///
/// - `Some(RuleHit { Deny, .. })` if any enabled, candidate-matching
///   deny fires — a declarative deny match or a wasm `Deny(reason)`
///   return. Among multiple denies the most specific wins
///   (deterministic for audit clarity); semantically all denies block,
///   so the "winner" only matters for which rule_id is logged.
/// - `Some(RuleHit { Approve, .. })` if no deny matches and at least
///   one approve does — declarative or a wasm `Approve` return.
///   Most-specific approve wins ([`WASM_DECISION_SPECIFICITY`] for
///   wasm); ties broken by lexically-smallest `id`.
/// - `None` if nothing matches. The daemon falls through to the
///   interactive prompt.
///
/// Wasm semantics within the pass:
///
/// - The trained-secrets guard applies **before** the module runs — a
///   wasm rule must not even see an ask that requests secrets outside
///   its trained snapshot, let alone decide it.
/// - A `Pass` return means "no opinion": the rule does not match.
/// - A runtime error (trap, fuel, bad decision) means the rule does
///   not match either — fail safe to the prompt — and is reported in
///   [`Evaluation::wasm_failures`] for the caller to log.
pub fn evaluate(rules: &[Rule], modules: &RuleModules, ctx: &EvalCtx) -> Evaluation {
    let mut best_deny: Option<Candidate> = None;
    let mut best_approve: Option<Candidate> = None;
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
        if !rule.enabled || !trained_secrets_allow(rule, ctx) {
            continue;
        }
        let candidate = match &rule.body {
            RuleBody::Wasm(_) => {
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
                    Ok(WasmDecision::Pass) => continue,
                    Ok(WasmDecision::Approve) => Candidate {
                        rule,
                        decide: RuleDecision::Approve,
                        deny_message: None,
                        specificity: WASM_DECISION_SPECIFICITY,
                    },
                    Ok(WasmDecision::Deny(reason)) => Candidate {
                        rule,
                        decide: RuleDecision::Deny,
                        deny_message: Some(reason),
                        specificity: WASM_DECISION_SPECIFICITY,
                    },
                    Ok(WasmDecision::Prompt(reason)) => {
                        // Not a candidate: `Prompt` produces no hit, it removes
                        // the option of one. A deny still outranks it.
                        mandate(rule, reason);
                        continue;
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
                        continue;
                    }
                }
            }
            RuleBody::Declarative {
                r#match,
                decide,
                deny_message,
            } => {
                if !match_clause_matches(r#match, ctx) {
                    continue;
                }
                Candidate {
                    rule,
                    decide: *decide,
                    deny_message: if *decide == RuleDecision::Deny {
                        deny_message.clone()
                    } else {
                        None
                    },
                    specificity: specificity(r#match),
                }
            }
        };
        let slot = match candidate.decide {
            RuleDecision::Deny => &mut best_deny,
            RuleDecision::Approve => &mut best_approve,
        };
        if slot.as_ref().is_none_or(|cur| beats(&candidate, cur)) {
            *slot = Some(candidate);
        }
    }

    // Deny > Prompt > Approve. A deny still wins outright: refusing is
    // strictly stronger than asking, and a mandate that could veto a deny
    // would let a broken module turn a block into a dialog.
    let winner = match (best_deny, &mandated_prompt) {
        (Some(deny), _) => Some(deny),
        (None, Some(_)) => None,
        (None, None) => best_approve,
    };
    let hit = winner.map(|c| RuleHit {
        rule_id: c.rule.id.clone(),
        rule_name: c.rule.name.clone(),
        decide: c.decide,
        deny_message: c.deny_message,
    });
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

/// The trained-secrets guard, applied to declarative and wasm rules
/// alike: with a non-empty snapshot, the rule may only fire when every
/// requested secret is inside it. Empty set = guard disabled (see
/// [`Rule::trained_secrets`]).
fn trained_secrets_allow(rule: &Rule, ctx: &EvalCtx) -> bool {
    if rule.trained_secrets.is_empty() {
        return true;
    }
    // `.all()` over an empty iterator is vacuously true, so an ask declaring
    // no subject would satisfy *every* rule's snapshot — the opposite of what
    // a guard means. Callers mint a subject for each ask kind that resolves
    // nothing (`ssh:<key_id>`, `wrap:<name>`), so this should be unreachable;
    // it is here so the next ask kind fails closed on the day someone adds
    // one and forgets, rather than silently consulting every rule.
    if ctx.secrets.is_empty() {
        return false;
    }
    ctx.secrets
        .iter()
        .all(|n| rule.trained_secrets.contains(*n))
}

/// Does the declarative match clause `m` match `ctx`? Pure predicate —
/// no I/O, no allocation beyond what the patterns themselves do.
fn match_clause_matches(m: &RuleMatch, ctx: &EvalCtx) -> bool {
    if m.wrap != ctx.wrap {
        return false;
    }
    if let Some(p) = &m.argv {
        if !p.matches_prefix(ctx.joined_argv) {
            return false;
        }
    }
    if let Some(p) = &m.ancestor {
        if !ctx.callers.iter().any(|c| p.matches_ancestor(c)) {
            return false;
        }
    }
    if let Some(p) = &m.cwd {
        if !p.matches_path_prefix(ctx.cwd) {
            return false;
        }
    }
    true
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
                decide,
                deny_message: None,
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

    /// Set (or clear) a declarative rule's `deny_message` in place.
    /// Panics on a wasm rule, which cannot carry one.
    fn set_deny_message(rule: &mut Rule, msg: Option<&str>) {
        let RuleBody::Declarative { deny_message, .. } = &mut rule.body else {
            panic!("not a declarative rule");
        };
        *deny_message = msg.map(str::to_owned);
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
    fn malformed_glob_falls_back_to_literal() {
        // `[` opens a char class; no closing `]` makes this a bad glob.
        // Rather than rejecting the rule entirely we fall back to a
        // literal — the worst case is "rule too narrow," which is the
        // safer failure mode for an unparseable security policy.
        let p = Pattern::parse("foo[bar");
        assert!(p.matches_prefix("foo[bar baz"));
        assert!(!p.matches_prefix("foo bar"));
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
    fn trained_secrets_guard_blocks_rule_when_ask_widens() {
        // Rule was trained on {GITHUB_TOKEN}; the ask now also wants
        // GITHUB_REPO_TOKEN (a newly-added env var in the wrap). The
        // rule must NOT fire, otherwise the user silently leaks the
        // new env var they never approved.
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
    fn trained_secrets_guard_allows_subset_asks() {
        // Trained on {A, B}; ask only wants {A}. Subset of trained — fine.
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
    fn empty_trained_secrets_disables_the_guard() {
        // Hand-edited rule with no trained_secrets field. Caller's
        // requested set is irrelevant; rule still fires if the rest
        // of the match clauses pass.
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
        let path = dir.path().join("auto-rules.json5");
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

    #[test]
    fn load_returns_empty_when_file_missing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("nonexistent.json5");
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
        let path = dir.path().join("broken.json5");
        std::fs::write(&path, "{ this is not json5 }").expect("write");
        assert!(load_rules(&path).is_err());
    }

    #[test]
    fn load_parses_a_hand_authored_file() {
        // Smoke test that the JSON5 features users will reach for
        // (trailing commas, unquoted keys, comments) all work for the
        // hand-edit path.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("auto-rules.json5");
        std::fs::write(
            &path,
            r#"{
                // Auto-rules — generated by the UI; hand-edits welcome.
                rules: [
                    {
                        id: "01",
                        name: "Cursor reads via gh",
                        enabled: true,
                        decide: "approve",
                        match: {
                            wrap: "gh",
                            argv: "gh api --get /repos/*/pulls*",
                            ancestor: "Cursor.app",
                        },
                        trained_secrets: ["GITHUB_TOKEN"],
                    },
                ],
            }"#,
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
        assert_eq!(*decide, RuleDecision::Approve);
        assert_eq!(m.wrap, "gh");
        assert_eq!(
            m.argv.as_ref().map(Pattern::as_str),
            Some("gh api --get /repos/*/pulls*")
        );
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

    #[test]
    fn trained_secrets_guard_blocks_a_wasm_rule_before_it_runs() {
        // The ctx would make APPROVE_IF approve, but the ask requests a
        // secret outside the rule's trained snapshot — the guard must
        // veto the rule exactly like it does declarative ones.
        let rule = mk_wasm_rule("01", "wasm approve", &["GITHUB_TOKEN"]);
        let modules = modules_for(&[("01", APPROVE_IF)]);
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
            &["GITHUB_TOKEN", "GITHUB_REPO_TOKEN"],
        );
        assert_eq!(evaluate(&[rule], &modules, &c).hit, None);
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
        // JSON5 — so the whole load fails and the daemon's existing
        // warn-and-continue-empty contract kicks in.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("auto-rules.json5");
        std::fs::write(
            &path,
            r#"{ rules: [ {
                id: "01", name: "confused", enabled: true,
                decide: "approve",
                match: { wrap: "gh" },
                wasm: { path: "01.wasm", sha256: "00" },
            } ] }"#,
        )
        .expect("write");
        let err = format!("{:#}", load_rules(&path).expect_err("must reject"));
        assert!(err.contains("both") && err.contains("confused"), "{err}");
    }

    // ── Wasm storage: sha256 pinning at load time ─────────────────────

    /// Write a rules file + module bytes into a tempdir and load it.
    fn load_with_module(rule: Rule, module_file: &str, bytes: &[u8]) -> LoadedRules {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("auto-rules.json5");
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
            loaded.wasm_refusals.is_empty(),
            "{:?}",
            loaded.wasm_refusals
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
            loaded.wasm_refusals.is_empty(),
            "{:?}",
            loaded.wasm_refusals
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
        let path = dir.path().join("auto-rules.json5");
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
        assert_eq!(loaded.wasm_refusals.len(), 1);
        let refusal = &loaded.wasm_refusals[0];
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
        let path = dir.path().join("auto-rules.json5");
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
        assert_eq!(loaded.wasm_refusals.len(), 1);
        let refusal = &loaded.wasm_refusals[0];
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
    // `auto-rules.json5` is a file users have on disk today and
    // hand-edit, and `docs/auto-rules.schema.json` is published to
    // secreq.dev as its contract. Neither is protected by the schema
    // drift test: `schema.rs` builds that schema as a hand-written
    // `json!` tree, so it can agree with the committed file while
    // disagreeing with [`Rule`]. These tests are the guard that
    // `tests/schema_drift.rs` is often assumed to be — they pin the
    // exact bytes `Rule` reads and writes, so a refactor of the type
    // (nesting the declarative-XOR-wasm shape into a sum type, say)
    // fails here if it moves the format under a user's file.

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
        // Cosmetic but user-visible: the daemon rewrites the whole
        // file on every mutation, and the user reads what it wrote.
        // Serde emits fields in declaration order — but a `flatten`ed
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
        // The whole path a user's file takes: hand-written JSON5 in,
        // parsed, rewritten by the daemon, re-read. Both rule shapes
        // must survive it byte-stable — a second save of what the
        // first save produced has to be identical, or the daemon
        // rewrites the user's file differently on every mutation.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("auto-rules.json5");
        std::fs::write(
            &path,
            r#"{
                rules: [
                    {
                        id: "01",
                        name: "Cursor reads via gh",
                        enabled: true,
                        decide: "approve",
                        match: { wrap: "gh", argv: "gh api --get /repos/*" },
                        trained_secrets: ["GITHUB_TOKEN"],
                        created_at_unix: 1700000000,
                    },
                    {
                        id: "02",
                        name: "block deletes",
                        enabled: false,
                        decide: "deny",
                        match: { wrap: "gh", ancestor: "Cursor.app", cwd: "/Users/me/oss" },
                        deny_message: "Use the UI instead.",
                        trained_secrets: [],
                    },
                    {
                        id: "03",
                        name: "npm publish guard",
                        enabled: true,
                        wasm: { path: "rules/03.wasm", sha256: "00" },
                        trained_secrets: ["NPM_TOKEN"],
                    },
                ],
            }"#,
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
        assert_eq!(*decide, RuleDecision::Approve);
        let deny = &first.rules[1];
        assert!(!deny.enabled);
        let RuleBody::Declarative {
            r#match,
            deny_message,
            ..
        } = &deny.body
        else {
            panic!("rule 02 is declarative");
        };
        assert_eq!(deny_message.as_deref(), Some("Use the UI instead."));
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
            ("decide", r#"decide: "deny","#),
            ("deny_message", r#"deny_message: "blocked","#),
        ] {
            let path = dir.path().join(format!("{field}.json5"));
            std::fs::write(
                &path,
                format!(
                    r#"{{ rules: [ {{
                        id: "01", name: "confused", enabled: true,
                        {snippet}
                        wasm: {{ path: "01.wasm", sha256: "00" }},
                    }} ] }}"#
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
        let path = dir.path().join("auto-rules.json5");
        std::fs::write(
            &path,
            r#"{ rules: [ {
                id: "01", name: "half a rule", enabled: true,
                match: { wrap: "gh" },
            } ] }"#,
        )
        .expect("write");
        let err = format!("{:#}", load_rules(&path).expect_err("must reject"));
        assert!(
            err.contains("decide") && err.contains("half a rule"),
            "{err}"
        );
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
