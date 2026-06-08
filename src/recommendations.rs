//! Rule recommendations derived from recent audit history.
//!
//! When the user keeps clicking Approve (or Deny) on a recurring shape of
//! ask, the Rules tab surfaces it as a one-click "Suggested rule" card so
//! the next pile of identical asks resolves without prompting. This module
//! is the pure clustering/aggregation pass; the UI consumes [`Suggestion`]
//! values and renders them.
//!
//! ## Layering
//!
//! The function takes plain slices of [`crate::audit::AuditEntry`] and
//! [`crate::rules::Rule`] — no daemon, no wire types, no I/O. It runs
//! inline on every Rules-tab paint (cheap; one linear pass over the
//! capped 5k-entry audit cache), so we keep it allocation-light and
//! free of `Result`s.
//!
//! ## Trust model
//!
//! A suggestion is a **template**, not a rule. Saving it still routes
//! through the existing Rules-tab form and `AddRule` IPC, so §4 of the
//! design plan's "rules are created from the UI, never implicitly"
//! invariant stays intact. The engine is also conservative on purpose:
//!
//! - We never suggest from `*+auto` rows — those are already covered.
//! - We require ≥ [`MIN_CLUSTER_SIZE`] hits before suggesting anything,
//!   to avoid noise from one-off explorations.
//! - We **drop** a cluster when an existing enabled rule already would
//!   have fired for the cluster's representative ask. Most such asks
//!   would have been logged as `*+auto` and excluded upstream, but this
//!   guards the racy edge case where the user just authored a rule
//!   that retroactively covers prior history.

use std::collections::BTreeSet;

use crate::audit::AuditEntry;
use crate::rules::{self, EvalCtx, Rule};

/// Window we cluster over. Matches the `AUDIT_WINDOW_SECS` value the
/// UI uses for the per-wrap history summary, so suggestions and the
/// "12 asks in the last 30 days" footer in audit cards talk about the
/// same time slice.
pub const SUGGESTION_WINDOW_SECS: u64 = 30 * 24 * 3600;

/// Minimum number of audit hits before a cluster is worth suggesting.
/// Three is "enough to recognize a pattern" without exposing one-offs.
pub const MIN_CLUSTER_SIZE: usize = 3;

/// Per-cluster cap on distinct argv samples retained for the merge.
/// A cluster could in principle hold thousands of audit rows; the
/// merger only needs enough unique shapes to capture which positions
/// vary, so we cap at a number large enough that a real workload's
/// natural diversity fits, and dedup on insert.
const MAX_ARGV_SAMPLES: usize = 100;

/// One recommended rule, ready to seed the Rules-tab form. The fields
/// are deliberately shaped like a [`RuleDraft`](`crate::rules::Rule`)
/// so the UI's existing `from_*` constructors can absorb it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Suggestion {
    /// Stable per-cluster key. Used by the UI to remember dismissals
    /// across paints. Format: `"{side}:{wrap}:{ancestor}"`.
    pub key: String,
    pub decide: SuggestionDecision,
    pub wrap: String,
    /// Suggested argv pattern. Either the literal longest-common
    /// prefix (if the entire cluster shares one verbatim) or that
    /// prefix with a trailing `*` when any row in the cluster has
    /// more text past it. `None` when no useful prefix exists
    /// (typically: an `args: []` cluster).
    pub argv: Option<String>,
    /// Suggested ancestor pattern — the cluster's first-caller name.
    /// Always populated; the cluster key requires a non-empty
    /// ancestor (an empty one isn't a meaningful identity).
    pub ancestor: String,
    /// Longest common literal prefix of cluster cwds, or `None` when
    /// it collapses to the filesystem root (`"/"`), which is too
    /// broad to be a useful match clause.
    pub cwd: Option<String>,
    /// Union of secret names requested across the cluster. Drives
    /// the trained-secrets guard on the resulting rule.
    pub trained_secrets: BTreeSet<String>,
    /// How many cluster rows backed this suggestion (within the
    /// window). Surfaced in the UI as "N asks in the last 30 days".
    pub count: usize,
    /// Most-recent cluster row's timestamp; used for tie-breaking
    /// and as the secondary sort key.
    pub last_ts_unix: u64,
}

/// Approve / Deny side of a suggestion. Distinct from
/// [`rules::RuleDecision`] so the UI can map it onto its
/// `RuleDecisionDraft` (which exists for the same draft-vs-rule
/// reason) without a `rules::` round-trip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuggestionDecision {
    Approve,
    Deny,
}

/// How the Rules tab orders the suggestion cards. The user flips this
/// with the segmented toggle in the "Suggested rules" header; it's
/// session-scoped UI state. Both orders use the *other* key as the
/// tiebreak and `key` as the final stable tiebreak, so the ordering is
/// total and deterministic regardless of which mode is active.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SuggestionSort {
    /// Highest cluster count first; most-recent breaks ties. This is
    /// the default — frequency is the stronger "you'll want a rule"
    /// signal than a single recent hit.
    #[default]
    MostUsed,
    /// Most-recent last-seen first; higher count breaks ties. Surfaces
    /// a freshly-recurring pattern that hasn't yet out-counted an old
    /// high-volume cluster.
    MostRecent,
}

impl SuggestionSort {
    /// Order `suggestions` in place per the selected mode. Stable and
    /// total: ties fall through to the other ranking key and finally to
    /// the cluster `key`.
    pub fn sort(self, suggestions: &mut [Suggestion]) {
        match self {
            SuggestionSort::MostUsed => suggestions.sort_by(|a, b| {
                b.count
                    .cmp(&a.count)
                    .then_with(|| b.last_ts_unix.cmp(&a.last_ts_unix))
                    .then_with(|| a.key.cmp(&b.key))
            }),
            SuggestionSort::MostRecent => suggestions.sort_by(|a, b| {
                b.last_ts_unix
                    .cmp(&a.last_ts_unix)
                    .then_with(|| b.count.cmp(&a.count))
                    .then_with(|| a.key.cmp(&b.key))
            }),
        }
    }
}

impl SuggestionDecision {
    /// Map an audit row's decision string to a side. Returns `None`
    /// for `*+auto` decisions (already covered by a rule) and for
    /// unknown decision strings (forward-compat).
    fn from_audit(decision: &str) -> Option<SuggestionDecision> {
        match decision {
            "approve" | "approve+remember" | "approve+cached" => Some(SuggestionDecision::Approve),
            "deny" => Some(SuggestionDecision::Deny),
            _ => None,
        }
    }

    fn key_str(self) -> &'static str {
        match self {
            SuggestionDecision::Approve => "approve",
            SuggestionDecision::Deny => "deny",
        }
    }
}

/// Produce a ranked list of rule suggestions from `entries`, skipping
/// clusters already covered by an enabled rule in `rules`.
///
/// `now_unix` is injected so tests can use a fixed clock without
/// reaching into `SystemTime::now`.
pub fn suggest(entries: &[AuditEntry], rules: &[Rule], now_unix: u64) -> Vec<Suggestion> {
    let cutoff = now_unix.saturating_sub(SUGGESTION_WINDOW_SECS);
    let mut clusters: Vec<Cluster> = Vec::new();

    for entry in entries {
        if entry.ts_unix < cutoff {
            continue;
        }
        let Some(side) = SuggestionDecision::from_audit(&entry.decision) else {
            continue;
        };
        let Some(ancestor) = entry.callers.first().map(|c| c.name.as_str()) else {
            continue;
        };
        if ancestor.is_empty() {
            continue;
        }
        let key = format!("{}:{}:{}", side.key_str(), entry.wrap, ancestor);
        let argv = joined_argv(entry);
        let cwd = entry.cwd.as_str();

        if let Some(c) = clusters.iter_mut().find(|c| c.key == key) {
            c.absorb(argv, cwd, &entry.secrets, entry.ts_unix);
        } else {
            clusters.push(Cluster::seed(key, side, entry, argv, cwd));
        }
    }

    let mut suggestions: Vec<Suggestion> = clusters
        .into_iter()
        .filter(|c| c.count >= MIN_CLUSTER_SIZE)
        .filter_map(|c| c.into_suggestion())
        .filter(|s| !redundant_with_existing_rules(s, rules))
        .collect();

    // Default ordering. The Rules tab re-applies the user's chosen
    // `SuggestionSort` to the filtered list each paint; producing a
    // deterministic default here keeps `suggest()` self-contained and
    // its tests independent of the UI's toggle state.
    SuggestionSort::MostUsed.sort(&mut suggestions);
    suggestions
}

fn joined_argv(entry: &AuditEntry) -> String {
    if entry.args.is_empty() {
        entry.wrap.clone()
    } else {
        format!("{} {}", entry.wrap, entry.args.join(" "))
    }
}

/// Would an enabled rule already fire (with the same side) for a
/// representative ask from this cluster? If so, the suggestion is
/// noise — skip it.
fn redundant_with_existing_rules(s: &Suggestion, rules: &[Rule]) -> bool {
    let joined_argv = s.argv.clone().unwrap_or_else(|| s.wrap.clone());
    let cwd = s.cwd.clone().unwrap_or_else(|| "/".to_owned());
    let secrets: Vec<&str> = s.trained_secrets.iter().map(String::as_str).collect();
    let callers = [(s.ancestor.as_str(), s.ancestor.as_str())];
    let ctx = EvalCtx {
        wrap: &s.wrap,
        joined_argv: &joined_argv,
        callers: &callers,
        cwd: &cwd,
        requested_secret_names: &secrets,
    };
    match rules::evaluate(rules, &ctx) {
        Some(hit) => matches!(
            (hit.decide, s.decide),
            (rules::RuleDecision::Approve, SuggestionDecision::Approve)
                | (rules::RuleDecision::Deny, SuggestionDecision::Deny)
        ),
        None => false,
    }
}

// ── Cluster aggregation ────────────────────────────────────────────────

struct Cluster {
    key: String,
    side: SuggestionDecision,
    wrap: String,
    ancestor: String,
    /// Distinct argv samples seen across the cluster, capped at
    /// [`MAX_ARGV_SAMPLES`]. Merged into a single pattern at
    /// finalisation time so we can do per-token alignment instead
    /// of a fragile incremental common-prefix.
    argv_samples: Vec<String>,
    cwd_prefix: String,
    trained_secrets: BTreeSet<String>,
    count: usize,
    last_ts_unix: u64,
}

impl Cluster {
    fn seed(
        key: String,
        side: SuggestionDecision,
        entry: &AuditEntry,
        argv: String,
        cwd: &str,
    ) -> Cluster {
        let ancestor = entry
            .callers
            .first()
            .map(|c| c.name.clone())
            .unwrap_or_default();
        let argv_samples = if argv.is_empty() {
            Vec::new()
        } else {
            vec![argv]
        };
        Cluster {
            key,
            side,
            wrap: entry.wrap.clone(),
            ancestor,
            argv_samples,
            cwd_prefix: cwd.to_owned(),
            trained_secrets: entry.secrets.iter().cloned().collect(),
            count: 1,
            last_ts_unix: entry.ts_unix,
        }
    }

    fn absorb(&mut self, argv: String, cwd: &str, secrets: &[String], ts_unix: u64) {
        self.count += 1;
        if ts_unix > self.last_ts_unix {
            self.last_ts_unix = ts_unix;
        }
        for s in secrets {
            self.trained_secrets.insert(s.clone());
        }
        if !argv.is_empty()
            && self.argv_samples.len() < MAX_ARGV_SAMPLES
            && !self.argv_samples.iter().any(|s| s == &argv)
        {
            self.argv_samples.push(argv);
        }
        let common = common_prefix_len(self.cwd_prefix.as_bytes(), cwd.as_bytes());
        self.cwd_prefix.truncate(common);
    }

    fn into_suggestion(self) -> Option<Suggestion> {
        let argv = merge_argv_samples(&self.argv_samples);
        let cwd = if self.cwd_prefix.is_empty() || self.cwd_prefix == "/" {
            None
        } else {
            Some(self.cwd_prefix)
        };
        Some(Suggestion {
            key: self.key,
            decide: self.side,
            wrap: self.wrap,
            argv,
            ancestor: self.ancestor,
            cwd,
            trained_secrets: self.trained_secrets,
            count: self.count,
            last_ts_unix: self.last_ts_unix,
        })
    }
}

fn common_prefix_len(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b.iter()).take_while(|(x, y)| x == y).count()
}

/// Merge a set of argv samples into a single glob pattern, aligning
/// tokens left-to-right.
///
/// The algorithm tokenises each sample on whitespace and walks the
/// resulting columns. At each column:
///
/// - **All samples agree on the token verbatim:** emit the literal.
/// - **They disagree, but the token is a `/`-delimited path with the
///   same segment count in every sample:** emit the per-segment merge
///   (`repos/*/*/commits/*/statuses`), then glue a trailing `*` and
///   stop — anything past a variable path is assumed volatile and
///   shouldn't be pinned to a literal.
/// - **They disagree in any other shape** (single tokens differing,
///   path lengths differing across samples): emit a bare `*` and stop.
///
/// If we run off the end with no divergence but the samples had
/// differing lengths, append a space-separated trailing `*` so the
/// rule still matches shorter and longer variants.
fn merge_argv_samples(samples: &[String]) -> Option<String> {
    if samples.is_empty() {
        return None;
    }
    let tokenised: Vec<Vec<&str>> = samples
        .iter()
        .map(|s| s.split_whitespace().collect())
        .collect();
    let min_len = tokenised.iter().map(|t| t.len()).min().unwrap_or(0);
    let max_len = tokenised.iter().map(|t| t.len()).max().unwrap_or(0);

    let mut out_tokens: Vec<String> = Vec::new();
    let mut stopped_on_divergence = false;

    for i in 0..min_len {
        let column: Vec<&str> = tokenised.iter().map(|t| t[i]).collect();
        let merged = merge_token_column(&column);
        if merged.contains('*') {
            // Path-segmented merge ("repos/*/*/commits/*/statuses") or
            // single-token divergence (bare "*"). Either way, glue a
            // trailing `*` so the rule absorbs whatever comes after
            // this volatile slot.
            let with_tail = if merged.ends_with('*') {
                merged
            } else {
                format!("{merged}*")
            };
            out_tokens.push(with_tail);
            stopped_on_divergence = true;
            break;
        }
        out_tokens.push(merged);
    }

    if !stopped_on_divergence && min_len != max_len && !out_tokens.is_empty() {
        // Every column agreed up to the shortest sample, but some
        // samples have more tokens past it. A space-separated `*`
        // lets the rule absorb the extra args.
        out_tokens.push("*".to_owned());
    }

    let result = out_tokens.join(" ");
    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

/// Merge one column of aligned tokens. Returns either a literal (when
/// every sample agrees), a `/`-delimited per-segment merge (when the
/// token looks like a path and the segment counts line up), or a
/// bare `"*"` when no structure can be preserved.
fn merge_token_column(samples: &[&str]) -> String {
    if samples.iter().all(|s| *s == samples[0]) {
        return samples[0].to_owned();
    }
    let sub_lists: Vec<Vec<&str>> = samples.iter().map(|s| s.split('/').collect()).collect();
    let lens: Vec<usize> = sub_lists.iter().map(|s| s.len()).collect();
    let min_len = *lens.iter().min().unwrap_or(&0);
    let max_len = *lens.iter().max().unwrap_or(&0);
    if min_len <= 1 || min_len != max_len {
        return "*".to_owned();
    }
    let mut out: Vec<String> = Vec::with_capacity(min_len);
    let mut any_literal = false;
    for i in 0..min_len {
        let col: Vec<&str> = sub_lists.iter().map(|s| s[i]).collect();
        if col.iter().all(|s| *s == col[0]) {
            out.push(col[0].to_owned());
            any_literal = true;
        } else {
            out.push("*".to_owned());
        }
    }
    if any_literal {
        out.join("/")
    } else {
        // Every segment differed — preserving the `/` structure isn't
        // any more informative than a single `*`.
        "*".to_owned()
    }
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{AuditCaller, AuditEntry};
    use crate::rules::{Pattern, RuleDecision, RuleMatch};

    fn entry(
        ts_unix: u64,
        wrap: &str,
        args: &[&str],
        ancestor: &str,
        cwd: &str,
        secrets: &[&str],
        decision: &str,
    ) -> AuditEntry {
        AuditEntry {
            ts_unix,
            cwd: cwd.to_owned(),
            wrap: wrap.to_owned(),
            args: args.iter().map(|s| (*s).to_owned()).collect(),
            callers: vec![AuditCaller {
                pid: 1,
                name: ancestor.to_owned(),
                command: ancestor.to_owned(),
            }],
            secrets: secrets.iter().map(|s| (*s).to_owned()).collect(),
            decision: decision.to_owned(),
            rule_id: None,
            fingerprint: None,
        }
    }

    fn mk_rule(id: &str, decide: RuleDecision, m: RuleMatch) -> Rule {
        Rule {
            id: id.to_owned(),
            name: id.to_owned(),
            enabled: true,
            decide,
            r#match: m,
            trained_secrets: BTreeSet::new(),
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

    // ── Cluster threshold ───────────────────────────────────────

    #[test]
    fn under_threshold_clusters_do_not_surface() {
        // Two hits is one short of MIN_CLUSTER_SIZE — we should
        // hear nothing back.
        let now = 10_000;
        let entries = vec![
            entry(
                now - 10,
                "gh",
                &["api", "x"],
                "Cursor",
                "/",
                &["GITHUB_TOKEN"],
                "approve",
            ),
            entry(
                now - 5,
                "gh",
                &["api", "y"],
                "Cursor",
                "/",
                &["GITHUB_TOKEN"],
                "approve",
            ),
        ];
        let suggestions = suggest(&entries, &[], now);
        assert!(
            suggestions.is_empty(),
            "two hits is below MIN_CLUSTER_SIZE; got {suggestions:?}"
        );
    }

    #[test]
    fn exactly_threshold_clusters_surface() {
        let now = 10_000;
        let entries: Vec<AuditEntry> = (0..MIN_CLUSTER_SIZE)
            .map(|i| {
                entry(
                    now - i as u64,
                    "gh",
                    &["api"],
                    "Cursor",
                    "/Users/x",
                    &["GITHUB_TOKEN"],
                    "approve",
                )
            })
            .collect();
        let suggestions = suggest(&entries, &[], now);
        assert_eq!(suggestions.len(), 1);
        assert_eq!(suggestions[0].count, MIN_CLUSTER_SIZE);
    }

    // ── Auto-* exclusion ────────────────────────────────────────

    #[test]
    fn auto_decisions_are_excluded() {
        // If existing rules are firing for these asks (so they're
        // logged as `*+auto`), they're already covered — we must not
        // suggest a redundant rule.
        let now = 10_000;
        let entries: Vec<AuditEntry> = (0..5)
            .map(|i| {
                entry(
                    now - i,
                    "gh",
                    &["api"],
                    "Cursor",
                    "/x",
                    &["GITHUB_TOKEN"],
                    "approve+auto",
                )
            })
            .collect();
        assert!(suggest(&entries, &[], now).is_empty());
    }

    // ── Window cutoff ───────────────────────────────────────────

    #[test]
    fn old_entries_outside_window_dont_count() {
        let now = SUGGESTION_WINDOW_SECS * 2;
        // Two old (> 30d ago) entries + two recent — only the recent
        // ones count, so we're below threshold and nothing surfaces.
        let entries = vec![
            entry(0, "gh", &["api"], "Cursor", "/x", &["A"], "approve"),
            entry(1, "gh", &["api"], "Cursor", "/x", &["A"], "approve"),
            entry(now - 10, "gh", &["api"], "Cursor", "/x", &["A"], "approve"),
            entry(now - 5, "gh", &["api"], "Cursor", "/x", &["A"], "approve"),
        ];
        assert!(suggest(&entries, &[], now).is_empty());
    }

    // ── argv prefix aggregation ─────────────────────────────────

    #[test]
    fn common_prefix_keeps_glob_tail_when_args_diverge() {
        let now = 10_000;
        // Three asks that share the path prefix but differ in commit SHA.
        let entries = vec![
            entry(
                now - 30,
                "gh",
                &["api", "repos/x/y/commits/aaa/statuses"],
                "Superset",
                "/Users/x",
                &["GITHUB_TOKEN"],
                "approve",
            ),
            entry(
                now - 20,
                "gh",
                &["api", "repos/x/y/commits/bbb/statuses"],
                "Superset",
                "/Users/x",
                &["GITHUB_TOKEN"],
                "approve",
            ),
            entry(
                now - 10,
                "gh",
                &["api", "repos/x/y/commits/ccc/statuses"],
                "Superset",
                "/Users/x",
                &["GITHUB_TOKEN"],
                "approve",
            ),
        ];
        let s = &suggest(&entries, &[], now)[0];
        // The longest shared boundary is `gh api repos/x/y/commits/`
        // — the SHAs diverge immediately after that path segment.
        // A trailing `*` makes the rule cover the variation.
        let argv = s.argv.as_deref().unwrap();
        assert!(
            argv.starts_with("gh api repos/x/y/commits/"),
            "argv should keep the shared path prefix: {argv:?}"
        );
        assert!(
            argv.ends_with('*'),
            "argv should end in `*` because entries diverge: {argv:?}"
        );
    }

    #[test]
    fn identical_argvs_yield_a_literal_pattern_with_no_star() {
        let now = 10_000;
        let entries: Vec<AuditEntry> = (0..3)
            .map(|i| {
                entry(
                    now - i,
                    "gh",
                    &["auth", "token"],
                    "claude",
                    "/Users/x",
                    &["GITHUB_TOKEN"],
                    "deny",
                )
            })
            .collect();
        let s = &suggest(&entries, &[], now)[0];
        // Every row's argv is identical: no divergence ⇒ no `*`.
        assert_eq!(s.argv.as_deref(), Some("gh auth token"));
        assert_eq!(s.decide, SuggestionDecision::Deny);
    }

    // ── cwd prefix aggregation ──────────────────────────────────

    #[test]
    fn cwd_common_prefix_collapses_to_none_at_root() {
        // Two cwds that share only `/` shouldn't produce a cwd clause
        // — `/` is "any absolute path", which is useless as a match
        // constraint.
        let now = 10_000;
        let entries = vec![
            entry(
                now - 30,
                "gh",
                &["api"],
                "Cursor",
                "/etc/x",
                &["A"],
                "approve",
            ),
            entry(
                now - 20,
                "gh",
                &["api"],
                "Cursor",
                "/var/y",
                &["A"],
                "approve",
            ),
            entry(
                now - 10,
                "gh",
                &["api"],
                "Cursor",
                "/tmp/z",
                &["A"],
                "approve",
            ),
        ];
        let s = &suggest(&entries, &[], now)[0];
        assert_eq!(s.cwd, None);
    }

    #[test]
    fn cwd_common_prefix_is_kept_when_meaningful() {
        let now = 10_000;
        let entries = vec![
            entry(
                now - 30,
                "gh",
                &["api"],
                "Cursor",
                "/Users/x/repos/foo",
                &["A"],
                "approve",
            ),
            entry(
                now - 20,
                "gh",
                &["api"],
                "Cursor",
                "/Users/x/repos/bar",
                &["A"],
                "approve",
            ),
            entry(
                now - 10,
                "gh",
                &["api"],
                "Cursor",
                "/Users/x/repos/baz",
                &["A"],
                "approve",
            ),
        ];
        let s = &suggest(&entries, &[], now)[0];
        assert_eq!(s.cwd.as_deref(), Some("/Users/x/repos/"));
    }

    // ── trained_secrets union ───────────────────────────────────

    #[test]
    fn trained_secrets_union_includes_every_name_seen() {
        let now = 10_000;
        let entries = vec![
            entry(now - 30, "gh", &["api"], "Cursor", "/x", &["A"], "approve"),
            entry(
                now - 20,
                "gh",
                &["api"],
                "Cursor",
                "/x",
                &["A", "B"],
                "approve",
            ),
            entry(
                now - 10,
                "gh",
                &["api"],
                "Cursor",
                "/x",
                &["B", "C"],
                "approve",
            ),
        ];
        let s = &suggest(&entries, &[], now)[0];
        let want: BTreeSet<String> = ["A", "B", "C"].into_iter().map(str::to_owned).collect();
        assert_eq!(s.trained_secrets, want);
    }

    // ── Side mapping & clustering ───────────────────────────────

    #[test]
    fn approve_remember_and_cached_collapse_into_approve_cluster() {
        let now = 10_000;
        let entries = vec![
            entry(now - 30, "gh", &["api"], "Cursor", "/x", &["A"], "approve"),
            entry(
                now - 20,
                "gh",
                &["api"],
                "Cursor",
                "/x",
                &["A"],
                "approve+remember",
            ),
            entry(
                now - 10,
                "gh",
                &["api"],
                "Cursor",
                "/x",
                &["A"],
                "approve+cached",
            ),
        ];
        let suggestions = suggest(&entries, &[], now);
        assert_eq!(suggestions.len(), 1, "should collapse into one cluster");
        assert_eq!(suggestions[0].decide, SuggestionDecision::Approve);
        assert_eq!(suggestions[0].count, 3);
    }

    #[test]
    fn approves_and_denies_form_separate_clusters() {
        let now = 10_000;
        let mut entries: Vec<AuditEntry> = (0..3)
            .map(|i| entry(now - i, "gh", &["api"], "Cursor", "/x", &["A"], "approve"))
            .collect();
        entries.extend((0..3).map(|i| {
            entry(
                now - 100 - i,
                "gh",
                &["api"],
                "Cursor",
                "/x",
                &["A"],
                "deny",
            )
        }));
        let suggestions = suggest(&entries, &[], now);
        assert_eq!(suggestions.len(), 2);
        assert!(suggestions
            .iter()
            .any(|s| s.decide == SuggestionDecision::Approve));
        assert!(suggestions
            .iter()
            .any(|s| s.decide == SuggestionDecision::Deny));
    }

    // ── Redundancy filter ───────────────────────────────────────

    #[test]
    fn cluster_already_covered_by_an_enabled_rule_is_filtered() {
        let now = 10_000;
        // An approve rule that covers the cluster's representative ask.
        let r = mk_rule(
            "01",
            RuleDecision::Approve,
            match_for("gh", Some("gh api*"), Some("Cursor"), None),
        );
        let entries: Vec<AuditEntry> = (0..5)
            .map(|i| {
                entry(
                    now - i,
                    "gh",
                    &["api"],
                    "Cursor",
                    "/x",
                    &["A"],
                    // Audit row predates the rule — recorded as plain
                    // approve, not approve+auto. The filter should
                    // still drop the suggestion now that the rule exists.
                    "approve",
                )
            })
            .collect();
        assert!(
            suggest(&entries, std::slice::from_ref(&r), now).is_empty(),
            "an existing rule that already covers this should suppress the suggestion"
        );
    }

    #[test]
    fn opposite_side_rule_does_not_suppress() {
        // A deny rule must not suppress an approve suggestion — the
        // user is approving anyway, and a "suggest the matching deny"
        // would be the wrong fix.
        let now = 10_000;
        let r = mk_rule(
            "01",
            RuleDecision::Deny,
            match_for("gh", Some("gh api*"), Some("Cursor"), None),
        );
        let entries: Vec<AuditEntry> = (0..5)
            .map(|i| entry(now - i, "gh", &["api"], "Cursor", "/x", &["A"], "approve"))
            .collect();
        // Note: this test exercises the *filter*, but in production the
        // deny rule would have fired and the row would be `deny+auto`
        // (excluded upstream). We still verify the filter doesn't
        // over-prune when sides differ.
        assert_eq!(
            suggest(&entries, std::slice::from_ref(&r), now).len(),
            1,
            "deny rule must not suppress an approve cluster"
        );
    }

    // ── Ranking ─────────────────────────────────────────────────

    #[test]
    fn ranking_is_by_count_desc_then_recency_desc() {
        let now = 10_000;
        // Cluster A: 5 hits, oldest at t-50.
        let mut entries: Vec<AuditEntry> = (0..5)
            .map(|i| {
                entry(
                    now - 50 + i,
                    "gh",
                    &["api"],
                    "Cursor",
                    "/x",
                    &["A"],
                    "approve",
                )
            })
            .collect();
        // Cluster B: 3 hits, newer than A.
        entries.extend((0..3).map(|i| {
            entry(
                now - i,
                "aws",
                &["s3", "ls"],
                "Cursor",
                "/x",
                &["B"],
                "approve",
            )
        }));
        let s = suggest(&entries, &[], now);
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].wrap, "gh", "higher count wins regardless of recency");
        assert_eq!(s[1].wrap, "aws");
    }

    #[test]
    fn most_recent_sort_flips_a_low_count_recent_cluster_to_the_top() {
        let now = 10_000;
        // Cluster A: 5 hits but older (newest at t-50).
        let mut entries: Vec<AuditEntry> = (0..5)
            .map(|i| {
                entry(
                    now - 50 + i,
                    "gh",
                    &["api"],
                    "Cursor",
                    "/x",
                    &["A"],
                    "approve",
                )
            })
            .collect();
        // Cluster B: 3 hits but newer than every A row.
        entries.extend((0..3).map(|i| {
            entry(
                now - i,
                "aws",
                &["s3", "ls"],
                "Cursor",
                "/x",
                &["B"],
                "approve",
            )
        }));
        let mut s = suggest(&entries, &[], now);
        // Default (MostUsed) ranks the high-count cluster first…
        assert_eq!(s[0].wrap, "gh");

        // …but MostRecent promotes the fresher, lower-count cluster.
        SuggestionSort::MostRecent.sort(&mut s);
        assert_eq!(s[0].wrap, "aws", "newer last-seen wins under MostRecent");
        assert_eq!(s[1].wrap, "gh");
    }

    // ── Edge cases ──────────────────────────────────────────────

    #[test]
    fn entries_with_no_callers_are_skipped() {
        let now = 10_000;
        let mut e = entry(now - 10, "gh", &["api"], "Cursor", "/x", &["A"], "approve");
        e.callers.clear();
        let entries = vec![e; 5];
        assert!(suggest(&entries, &[], now).is_empty());
    }

    #[test]
    fn empty_args_cluster_yields_no_argv_clause() {
        // A cluster of asks with `args: []` should still surface, but
        // without an argv suggestion — the rule will match on
        // wrap+ancestor only.
        let now = 10_000;
        let entries: Vec<AuditEntry> = (0..3)
            .map(|i| entry(now - i, "gh", &[], "Cursor", "/Users/x", &["A"], "approve"))
            .collect();
        // First entry's argv is just "gh"; subsequent entries are also
        // just "gh" — so the prefix stays literal, no `*`. argv suggests
        // exactly "gh" which is the wrap name; that's degenerate but
        // valid (acts as a literal-prefix match against any "gh …" argv).
        let s = &suggest(&entries, &[], now)[0];
        assert_eq!(s.argv.as_deref(), Some("gh"));
    }

    // ── argv merger: token + path-segment alignment ────────────

    #[test]
    fn varying_owner_and_sha_collapse_to_a_segmented_glob() {
        // The motivating real-world case: gh asks that differ on
        // owner / repo / commit SHA but share the rest of the path.
        // The suggestion should pin every literal segment and replace
        // each varying segment with `*`, ending with a glued `*` so
        // trailing flags don't constrain the rule.
        let now = 10_000;
        let entries = vec![
            entry(
                now - 30,
                "gh",
                &[
                    "api",
                    "--method",
                    "GET",
                    "repos/AgentEnder/cli-forge/commits/ac00920844c348da5aff2229bb8d93292cf5ec3a/statuses",
                    "-f",
                    "per_page=10",
                ],
                "Superset",
                "/",
                &["GITHUB_TOKEN"],
                "approve",
            ),
            entry(
                now - 20,
                "gh",
                &[
                    "api",
                    "--method",
                    "GET",
                    "repos/AgentEnder/cli-forge/commits/bcd953e87ffa7b28790968005edb1665c212f373/statuses",
                    "-f",
                    "per_page=10",
                ],
                "Superset",
                "/",
                &["GITHUB_TOKEN"],
                "approve",
            ),
            entry(
                now - 10,
                "gh",
                &[
                    "api",
                    "--method",
                    "GET",
                    "repos/nrwl/nx/commits/ed89bf6b2adfa4e3fbccda2c68e780e22db16545/statuses",
                    "-f",
                    "per_page=100",
                ],
                "Superset",
                "/",
                &["GITHUB_TOKEN"],
                "approve",
            ),
        ];
        let s = &suggest(&entries, &[], now)[0];
        assert_eq!(
            s.argv.as_deref(),
            Some("gh api --method GET repos/*/*/commits/*/statuses*"),
            "owner, repo and SHA should collapse to `*` per-segment, and the trailing flags should fold into a glued `*`",
        );
    }

    #[test]
    fn fully_divergent_single_token_collapses_to_bare_star() {
        // Same wrap + ancestor, but the post-prefix token is a single
        // word that differs across samples (no path structure to
        // preserve). The merger should bail to a bare trailing `*`.
        let now = 10_000;
        let entries = vec![
            entry(
                now - 30,
                "gh",
                &["repo", "delete", "me/x"],
                "zsh",
                "/x",
                &["A"],
                "deny",
            ),
            entry(
                now - 20,
                "gh",
                &["repo", "delete", "me/y"],
                "zsh",
                "/x",
                &["A"],
                "deny",
            ),
            entry(
                now - 10,
                "gh",
                &["repo", "delete", "me/z"],
                "zsh",
                "/x",
                &["A"],
                "deny",
            ),
        ];
        let s = &suggest(&entries, &[], now)[0];
        // `me/x` vs `me/y` vs `me/z` — path-segmented merge keeps the
        // common `me` and stars the leaf, then glues a `*` for the
        // trailing-flag absorber.
        assert_eq!(s.argv.as_deref(), Some("gh repo delete me/*"));
    }

    #[test]
    fn merger_stops_at_first_volatile_slot_even_when_later_tokens_agree() {
        // After the volatile path token, every sample shares
        // `-f per_page=10`. We deliberately drop those — the rule
        // shouldn't pin trailing flags that happen to be identical in
        // this small sample but are clearly volatile in practice.
        let now = 10_000;
        let entries = vec![
            entry(
                now - 30,
                "gh",
                &["api", "repos/a/b/commits/aaa/statuses", "-f", "per_page=10"],
                "Cursor",
                "/x",
                &["A"],
                "approve",
            ),
            entry(
                now - 20,
                "gh",
                &["api", "repos/c/d/commits/bbb/statuses", "-f", "per_page=10"],
                "Cursor",
                "/x",
                &["A"],
                "approve",
            ),
            entry(
                now - 10,
                "gh",
                &["api", "repos/e/f/commits/ccc/statuses", "-f", "per_page=10"],
                "Cursor",
                "/x",
                &["A"],
                "approve",
            ),
        ];
        let s = &suggest(&entries, &[], now)[0];
        assert_eq!(
            s.argv.as_deref(),
            Some("gh api repos/*/*/commits/*/statuses*")
        );
    }

    #[test]
    fn merger_appends_trailing_star_when_lengths_differ_without_divergence() {
        // Lengths differ but every aligned token agrees. The trailing
        // ` *` lets the rule match both the short and the long forms.
        let now = 10_000;
        let entries = vec![
            entry(now - 30, "gh", &["api"], "Cursor", "/x", &["A"], "approve"),
            entry(now - 20, "gh", &["api"], "Cursor", "/x", &["A"], "approve"),
            entry(
                now - 10,
                "gh",
                &["api", "extra"],
                "Cursor",
                "/x",
                &["A"],
                "approve",
            ),
        ];
        let s = &suggest(&entries, &[], now)[0];
        assert_eq!(s.argv.as_deref(), Some("gh api *"));
    }

    #[test]
    fn cluster_key_format_is_stable() {
        let now = 10_000;
        let entries: Vec<AuditEntry> = (0..3)
            .map(|i| entry(now - i, "gh", &["api"], "Cursor", "/x", &["A"], "approve"))
            .collect();
        let s = &suggest(&entries, &[], now)[0];
        assert_eq!(s.key, "approve:gh:Cursor");
    }
}
