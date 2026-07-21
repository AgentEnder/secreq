//! Auto-approve / auto-deny rules — persisted policy evaluated before the
//! consent prompt fires.
//!
//! See `dev-docs/plans/2026-06-02-auto-rules.md` for the design.
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

/// One persisted rule. Comes in exactly two shapes, enforced by
/// [`Rule::validate_shape`] at every load and mutation:
///
/// - **Declarative**: `decide` + `match` present, `wasm` absent. The
///   static `decide` field is the rule's decision whenever the match
///   clause fires.
/// - **Wasm**: `wasm` present; `decide`, `match`, and `deny_message`
///   absent. The decision is whatever the compiled module *returns*
///   at evaluation time (approve / pass / deny-with-reason), so a
///   static `decide` or `deny_message` would be dead weight at best
///   and misleading at worst — we reject them loudly rather than
///   silently ignoring them.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Rule {
    /// Stable identifier. Generated once on creation, never mutated.
    /// Surfaces in the audit log so users can trace which rule fired.
    pub id: String,
    /// Human label shown in the UI and the audit pill.
    pub name: String,
    /// `false` ⇒ rule is in the file but the evaluator skips it. Used
    /// for "pause this rule without losing the configuration."
    pub enabled: bool,
    /// Static decision — declarative rules only. `None` for wasm rules,
    /// whose decision is the module's return value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decide: Option<RuleDecision>,
    #[serde(rename = "match", default, skip_serializing_if = "Option::is_none")]
    pub r#match: Option<RuleMatch>,
    /// The wasm alternative to `decide` + `match`: a compiled rule
    /// module evaluated in the sandbox of [`crate::wasm_rules`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wasm: Option<WasmRule>,
    /// Env var names the rule was created against. The evaluator
    /// refuses to fire if the live ask requests any name outside this
    /// set — the trained-secrets guard. **Empty set means the guard
    /// is disabled**, which is the legitimate behavior for hand-edited
    /// rules where the user has explicitly opted out. UI-created rules
    /// always populate it.
    #[serde(default)]
    pub trained_secrets: BTreeSet<String>,
    /// Message shown to the user on auto-deny. Only meaningful when
    /// `decide == Deny`; forbidden on wasm rules (the module returns
    /// its own reason). The wrap client prints it to stderr; the
    /// consent window renders it in a toast row. Skipped when absent
    /// so saved rules validate against the schema (which types it as a
    /// string, and forbids the key entirely on wasm rules).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny_message: Option<String>,
    /// Seconds since the Unix epoch at creation time. Informational
    /// (lets the UI show "created 3 days ago").
    #[serde(default)]
    pub created_at_unix: u64,
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

impl Rule {
    /// Enforce the declarative-XOR-wasm shape (see the type-level doc).
    /// Called by [`load_rules`] for every parsed rule and by the
    /// daemon's rule-mutation paths, so an invalid shape can neither be
    /// loaded from disk nor inserted over IPC.
    pub fn validate_shape(&self) -> Result<()> {
        let label = format!("rule `{}` (id {})", self.name, self.id);
        match (&self.wasm, &self.r#match) {
            (Some(_), Some(_)) => bail!(
                "{label} has both a `match` clause and a `wasm` module — a rule \
                 is either declarative (`decide` + `match`) or wasm (`wasm` \
                 alone); split it into two rules"
            ),
            (None, None) => bail!(
                "{label} has neither a `match` clause nor a `wasm` module — a \
                 rule must be declarative (`decide` + `match`) or wasm (`wasm`)"
            ),
            (Some(_), None) => {
                if self.decide.is_some() {
                    bail!(
                        "{label} is a wasm rule but sets `decide` — a wasm rule's \
                         decision is whatever its module returns at evaluation \
                         time; remove `decide`"
                    );
                }
                if self.deny_message.is_some() {
                    bail!(
                        "{label} is a wasm rule but sets `deny_message` — a wasm \
                         deny carries the reason returned by the module; remove \
                         `deny_message`"
                    );
                }
            }
            (None, Some(_)) => {
                if self.decide.is_none() {
                    bail!("{label} has a `match` clause but no `decide` (approve or deny)");
                }
            }
        }
        Ok(())
    }
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
    let Some(wasm) = &rule.wasm else {
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
///   `ask.cwd`. Literal = prefix; glob = full pattern.
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

    /// Match for argv / cwd fields. Literal = prefix; glob = full
    /// pattern match.
    pub fn matches_prefix(&self, s: &str) -> bool {
        match &self.kind {
            PatternKind::Literal => s.starts_with(&self.raw),
            PatternKind::Glob(g) => g.matches(s),
        }
    }

    /// Match for the ancestor field. Literal = substring; glob = full
    /// pattern match. Substring is friendlier than prefix for matching
    /// `.app` bundle names against noisy macOS argv strings like
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
///   existing "warn + empty ruleset" contract applies.
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
    for rule in &parsed.rules {
        rule.validate_shape()
            .with_context(|| format!("invalid rule in {}", path.display()))?;
    }
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
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ── Evaluation ────────────────────────────────────────────────────────────

/// What the evaluator needs from one live ask. Built by the daemon
/// caller (`daemon::server`) so this module stays free of wire types.
pub struct EvalCtx<'a> {
    /// The wrap name being asked for.
    pub wrap: &'a str,
    /// The joined argv of the wrapped command (e.g. `"gh api --get /repos/x"`).
    pub joined_argv: &'a str,
    /// Caller chain, nearest-first. Each entry is `(name, command)`.
    /// Matched against the `ancestor` pattern.
    pub callers: &'a [(&'a str, &'a str)],
    /// Working directory of the requesting process.
    pub cwd: &'a str,
    /// Names of the secrets requested. Checked against the rule's
    /// `trained_secrets` guard.
    pub requested_secret_names: &'a [&'a str],
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

/// What [`evaluate`] produced: the winning hit (if any) plus every
/// wasm-rule runtime failure encountered along the way.
#[derive(Debug, Default, PartialEq)]
pub struct Evaluation {
    pub hit: Option<RuleHit>,
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
    let mut wasm_failures = Vec::new();

    for rule in rules {
        if !rule.enabled || !trained_secrets_allow(rule, ctx) {
            continue;
        }
        let candidate = if rule.wasm.is_some() {
            let Some(module) = modules.get(&rule.id) else {
                // Refused at load time (sha256 mismatch, missing file);
                // already warned about then. Never matches.
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
                Err(err) => {
                    wasm_failures.push(WasmFailure {
                        rule_id: rule.id.clone(),
                        rule_name: rule.name.clone(),
                        error: format!("{err:#}"),
                    });
                    continue;
                }
            }
        } else {
            // Shape invariant: a non-wasm rule has `match` + `decide`.
            // Defensively skip rather than panic if a caller bypassed
            // `validate_shape`.
            let (Some(m), Some(decide)) = (&rule.r#match, rule.decide) else {
                continue;
            };
            if !match_clause_matches(m, ctx) {
                continue;
            }
            Candidate {
                rule,
                decide,
                deny_message: if decide == RuleDecision::Deny {
                    rule.deny_message.clone()
                } else {
                    None
                },
                specificity: specificity(m),
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

    // Deny wins, then most-specific approve.
    let hit = best_deny.or(best_approve).map(|c| RuleHit {
        rule_id: c.rule.id.clone(),
        rule_name: c.rule.name.clone(),
        decide: c.decide,
        deny_message: c.deny_message,
    });
    Evaluation { hit, wasm_failures }
}

/// The trained-secrets guard, applied to declarative and wasm rules
/// alike: with a non-empty snapshot, the rule may only fire when every
/// requested secret is inside it. Empty set = guard disabled (see
/// [`Rule::trained_secrets`]).
fn trained_secrets_allow(rule: &Rule, ctx: &EvalCtx) -> bool {
    rule.trained_secrets.is_empty()
        || ctx
            .requested_secret_names
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
        let any_caller_matches = ctx
            .callers
            .iter()
            .any(|(name, command)| p.matches_substring(name) || p.matches_substring(command));
        if !any_caller_matches {
            return false;
        }
    }
    if let Some(p) = &m.cwd {
        if !p.matches_prefix(ctx.cwd) {
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
    m.argv.is_some() as u32 + m.ancestor.is_some() as u32 + m.cwd.is_some() as u32
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

    fn rule_id(id: &str) -> String {
        id.to_owned()
    }

    fn mk_rule(id: &str, name: &str, decide: RuleDecision, m: RuleMatch, trained: &[&str]) -> Rule {
        Rule {
            id: rule_id(id),
            name: name.to_owned(),
            enabled: true,
            decide: Some(decide),
            r#match: Some(m),
            wasm: None,
            trained_secrets: trained.iter().map(|s| (*s).to_owned()).collect(),
            deny_message: None,
            created_at_unix: 0,
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
            decide: None,
            r#match: None,
            wasm: Some(WasmRule {
                path: format!("{id}.wasm"),
                sha256: "unverified-in-eval-tests".to_owned(),
            }),
            trained_secrets: trained.iter().map(|s| (*s).to_owned()).collect(),
            deny_message: None,
            created_at_unix: 0,
        }
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
        callers: &'a [(&'a str, &'a str)],
        cwd: &'a str,
        secrets: &'a [&'a str],
    ) -> EvalCtx<'a> {
        EvalCtx {
            wrap,
            joined_argv,
            callers,
            cwd,
            requested_secret_names: secrets,
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
            ("zsh", "-zsh"),
            (
                "Cursor",
                "/Applications/Cursor.app/Contents/MacOS/Cursor --psn_0_12345",
            ),
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
            &[("Cursor", "Cursor.app")],
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
            &[("Cursor", "Cursor.app")],
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
            &[("Cursor", "Cursor.app")],
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
        deny.deny_message = Some("Use the UI instead.".into());
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
        assert_eq!(r.decide, Some(RuleDecision::Approve));
        let m = r.r#match.as_ref().expect("declarative rule has a match");
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
        let callers = &[("Cursor", "/Applications/Cursor.app/Contents/MacOS/Cursor")];
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
        let callers = &[(
            "Cursor",
            "/Applications/Cursor.app/Contents/MacOS/Cursor --psn_0_12345",
        )];
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
        let callers = &[("Cursor", "/Applications/Cursor.app/Contents/MacOS/Cursor")];
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
        let callers = &[("Cursor", "/Applications/Cursor.app/Contents/MacOS/Cursor")];
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
    fn erroring_wasm_rule_does_not_block_other_rules() {
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
        assert_eq!(out.hit.expect("declarative rule still fires").rule_id, "02");
        assert_eq!(out.wasm_failures.len(), 1);
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

    #[test]
    fn shape_rejects_both_match_and_wasm() {
        let mut r = mk_rule(
            "01",
            "confused",
            RuleDecision::Approve,
            match_for("gh", None, None, None),
            &[],
        );
        r.wasm = Some(WasmRule {
            path: "01.wasm".to_owned(),
            sha256: "00".to_owned(),
        });
        let err = r.validate_shape().expect_err("must reject").to_string();
        assert!(err.contains("both") && err.contains("confused"), "{err}");
    }

    #[test]
    fn shape_rejects_neither_match_nor_wasm() {
        let mut r = mk_wasm_rule("01", "empty", &[]);
        r.wasm = None;
        let err = r.validate_shape().expect_err("must reject").to_string();
        assert!(err.contains("neither"), "{err}");
    }

    #[test]
    fn shape_rejects_static_decide_on_a_wasm_rule() {
        let mut r = mk_wasm_rule("01", "w", &[]);
        r.decide = Some(RuleDecision::Approve);
        let err = r.validate_shape().expect_err("must reject").to_string();
        assert!(err.contains("decide"), "{err}");
    }

    #[test]
    fn shape_rejects_static_deny_message_on_a_wasm_rule() {
        let mut r = mk_wasm_rule("01", "w", &[]);
        r.deny_message = Some("static".to_owned());
        let err = r.validate_shape().expect_err("must reject").to_string();
        assert!(err.contains("deny_message"), "{err}");
    }

    #[test]
    fn declarative_rule_without_decide_is_rejected() {
        let mut r = mk_rule(
            "01",
            "no decide",
            RuleDecision::Approve,
            match_for("gh", None, None, None),
            &[],
        );
        r.decide = None;
        let err = r.validate_shape().expect_err("must reject").to_string();
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
        rule.wasm = Some(WasmRule {
            path: "mod.wasm".to_owned(),
            sha256: sha256_hex(APPROVE_IF),
        });
        let loaded = load_with_module(rule.clone(), "mod.wasm", APPROVE_IF);
        assert_eq!(loaded.rules, vec![rule]);
        assert!(
            loaded.wasm_refusals.is_empty(),
            "{:?}",
            loaded.wasm_refusals
        );
        assert!(loaded.modules.contains_key("01"));
        // And the loaded module actually evaluates.
        let callers = &[("Cursor", "/Applications/Cursor.app/Contents/MacOS/Cursor")];
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
        rule.wasm = Some(WasmRule {
            path: "mod.wasm".to_owned(),
            sha256: sha256_hex(APPROVE_IF).to_uppercase(),
        });
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
        tampered.wasm = Some(WasmRule {
            path: "mod.wasm".to_owned(),
            sha256: sha256_hex(b"different bytes entirely"),
        });
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
        rule.wasm = Some(WasmRule {
            path: "nonexistent.wasm".to_owned(),
            sha256: sha256_hex(APPROVE_IF),
        });
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
}
