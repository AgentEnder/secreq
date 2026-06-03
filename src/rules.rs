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

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// One persisted rule.
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
    pub decide: RuleDecision,
    #[serde(rename = "match")]
    pub r#match: RuleMatch,
    /// Env var names the rule was created against. The evaluator
    /// refuses to fire if the live ask requests any name outside this
    /// set — the trained-secrets guard. **Empty set means the guard
    /// is disabled**, which is the legitimate behavior for hand-edited
    /// rules where the user has explicitly opted out. UI-created rules
    /// always populate it.
    #[serde(default)]
    pub trained_secrets: BTreeSet<String>,
    /// Message shown to the user on auto-deny. Only meaningful when
    /// `decide == Deny`. The wrap client prints it to stderr; the
    /// consent window renders it in a toast row.
    #[serde(default)]
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

/// Result of [`load_rules`]: the parsed rule list plus the file's
/// `mtime` at load time (used by the daemon's freshness check).
#[derive(Debug, Default)]
pub struct LoadedRules {
    pub rules: Vec<Rule>,
    /// `None` if the file didn't exist.
    pub mtime: Option<SystemTime>,
}

/// Load rules from `path`. A missing file returns an empty
/// `LoadedRules` (not an error) — the daemon should run normally
/// when no rules are configured. Malformed files DO return an error;
/// the daemon turns that into a stderr warning + empty ruleset.
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
    Ok(LoadedRules {
        rules: parsed.rules,
        mtime,
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

/// `$XDG_CONFIG_HOME/secreq/auto-rules.json5` (or
/// `~/.config/secreq/auto-rules.json5`). Mirrors [`crate::wraps::default_config_path`].
pub fn default_rules_path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| dirs::home_dir().map(|h| h.join(".config")))?;
    Some(base.join("secreq").join("auto-rules.json5"))
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
    /// Configured deny message, when `decide == Deny`. The wrap client
    /// prints this to stderr; the consent UI surfaces it as a toast.
    pub deny_message: Option<String>,
}

/// Evaluate `rules` against `ctx`. Returns:
///
/// - `Some(RuleHit { Deny, .. })` if any enabled, candidate-matching
///   deny rule fires. Among multiple denies the most specific wins
///   (deterministic for audit clarity); semantically all denies block,
///   so the "winner" only matters for which rule_id is logged.
/// - `Some(RuleHit { Approve, .. })` if no deny matches and at least
///   one approve does. Most-specific approve wins; ties broken by
///   lexically-smallest `id` so the choice is predictable.
/// - `None` if nothing matches. The daemon falls through to the
///   interactive prompt.
pub fn evaluate(rules: &[Rule], ctx: &EvalCtx) -> Option<RuleHit> {
    let mut best_deny: Option<&Rule> = None;
    let mut best_approve: Option<&Rule> = None;

    for rule in rules {
        if !rule.enabled || !rule_matches(rule, ctx) {
            continue;
        }
        match rule.decide {
            RuleDecision::Deny => {
                if best_deny.is_none_or(|cur| beats(rule, cur)) {
                    best_deny = Some(rule);
                }
            }
            RuleDecision::Approve => {
                if best_approve.is_none_or(|cur| beats(rule, cur)) {
                    best_approve = Some(rule);
                }
            }
        }
    }

    // Deny wins, then most-specific approve.
    if let Some(r) = best_deny {
        return Some(RuleHit {
            rule_id: r.id.clone(),
            rule_name: r.name.clone(),
            decide: RuleDecision::Deny,
            deny_message: r.deny_message.clone(),
        });
    }
    best_approve.map(|r| RuleHit {
        rule_id: r.id.clone(),
        rule_name: r.name.clone(),
        decide: RuleDecision::Approve,
        deny_message: None,
    })
}

/// Does `rule` match `ctx`? Pure predicate — no I/O, no allocation
/// beyond what the patterns themselves do.
fn rule_matches(rule: &Rule, ctx: &EvalCtx) -> bool {
    if rule.r#match.wrap != ctx.wrap {
        return false;
    }
    if let Some(p) = &rule.r#match.argv {
        if !p.matches_prefix(ctx.joined_argv) {
            return false;
        }
    }
    if let Some(p) = &rule.r#match.ancestor {
        let any_caller_matches = ctx
            .callers
            .iter()
            .any(|(name, command)| p.matches_substring(name) || p.matches_substring(command));
        if !any_caller_matches {
            return false;
        }
    }
    if let Some(p) = &rule.r#match.cwd {
        if !p.matches_prefix(ctx.cwd) {
            return false;
        }
    }
    // Trained-secrets guard. Empty set = guard disabled (see Rule doc).
    if !rule.trained_secrets.is_empty() {
        let all_in_trained = ctx
            .requested_secret_names
            .iter()
            .all(|n| rule.trained_secrets.contains(*n));
        if !all_in_trained {
            return false;
        }
    }
    true
}

/// Does `a` beat `b` for "most specific" ranking? Higher specificity
/// wins; ties break in favor of the lexically-smaller `id`.
fn beats(a: &Rule, b: &Rule) -> bool {
    let sa = specificity(&a.r#match);
    let sb = specificity(&b.r#match);
    if sa != sb {
        return sa > sb;
    }
    a.id < b.id
}

fn specificity(m: &RuleMatch) -> u32 {
    // The wrap field is always present, so it doesn't differentiate.
    m.argv.is_some() as u32 + m.ancestor.is_some() as u32 + m.cwd.is_some() as u32
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn rule_id(id: &str) -> String {
        id.to_owned()
    }

    fn mk_rule(id: &str, name: &str, decide: RuleDecision, m: RuleMatch, trained: &[&str]) -> Rule {
        Rule {
            id: rule_id(id),
            name: name.to_owned(),
            enabled: true,
            decide,
            r#match: m,
            trained_secrets: trained.iter().map(|s| (*s).to_owned()).collect(),
            deny_message: None,
            created_at_unix: 0,
        }
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
        assert_eq!(evaluate(&[r], &c), None);
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
        let hit = evaluate(&[r], &c).expect("rule should match");
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
        assert_eq!(evaluate(&[r], &c), None);
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
        assert_eq!(evaluate(&[r], &c), None);
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
        assert!(evaluate(&[r], &c).is_some());
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
        assert!(evaluate(&[r], &c).is_some());
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
        let hit = evaluate(&[approve, deny], &c).expect("a rule should fire");
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
        let hit = evaluate(&[r1, r2], &c).expect("should fire");
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
        let hit = evaluate(&[r_b, r_a], &c).expect("should fire");
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
        let hit = evaluate(&[d_broad, d_specific], &c).expect("should deny");
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
        let hit = evaluate(&[deny], &c).expect("should deny");
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
        assert_eq!(r.decide, RuleDecision::Approve);
        assert_eq!(r.r#match.wrap, "gh");
        assert_eq!(
            r.r#match.argv.as_ref().map(Pattern::as_str),
            Some("gh api --get /repos/*/pulls*")
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
}
