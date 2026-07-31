//! Replay audit asks through the production rules evaluator and report coverage.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use anyhow::Result;
use serde::Serialize;

use crate::audit::AuditEntry;
use crate::rule_health::ScopeFinding;
use crate::rules::{self, EvalCaller, EvalCtx, LoadedRules, RuleDecision};

const MAX_DECISION_CACHE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct ReplayOptions {
    pub since_unix: Option<u64>,
    pub wrap: Option<String>,
    pub top: usize,
    pub verify: bool,
}

impl Default for ReplayOptions {
    fn default() -> Self {
        Self {
            since_unix: None,
            wrap: None,
            top: 15,
            verify: false,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct StatsReport {
    pub schema_version: u32,
    pub filters: ReportFilters,
    pub rows: RowCounts,
    pub outcomes: Outcomes,
    pub attribution: Vec<RuleAttribution>,
    pub prompt_shapes: Vec<CountedLabel>,
    pub prompt_recorded: Vec<RecordedPromptDecision>,
    pub costly: CostlyRows,
    pub health: RuleHealth,
    pub runtime_failures: Vec<RuntimeFailureCount>,
    pub verification: Verification,
}

#[derive(Debug, Serialize)]
pub struct ReportFilters {
    pub since_unix: Option<u64>,
    pub wrap: Option<String>,
    pub audit_path: String,
    pub top: usize,
}

#[derive(Debug, Default, Serialize)]
pub struct RowCounts {
    pub decoded: usize,
    pub replayed: usize,
    pub filtered: usize,
    pub malformed: usize,
    /// Scoped-agent rows are historical traffic, but never enter the live
    /// rules evaluator and therefore are not in the outcomes denominator.
    pub scoped_agent: usize,
    /// Other audit events that did not enter the rules evaluator, currently
    /// `store` decisions. They are history, not replayable asks.
    pub not_evaluated: usize,
}

#[derive(Debug, Default, Serialize)]
pub struct Outcomes {
    pub auto_approve: OutcomeCount,
    pub auto_deny: OutcomeCount,
    pub prompt: PromptCount,
}

#[derive(Debug, Default, Serialize)]
pub struct OutcomeCount {
    pub count: usize,
    pub percent: f64,
}

#[derive(Debug, Default, Serialize)]
pub struct PromptCount {
    pub count: usize,
    pub percent: f64,
    pub mandated: usize,
    pub uncovered: usize,
}

#[derive(Debug, Serialize)]
pub struct RuleAttribution {
    pub rule_id: String,
    pub rule_name: String,
    pub decision: String,
    /// Times this rule was the representative whole-ask winner.
    pub asks: usize,
    /// Requested subjects this rule approved, including contributions to a
    /// multi-rule aggregate approval.
    pub approved_subjects: usize,
}

#[derive(Debug, Serialize)]
pub struct CountedLabel {
    pub label: String,
    pub count: usize,
}

#[derive(Debug, Serialize)]
pub struct RecordedPromptDecision {
    pub traffic: PromptTraffic,
    pub decision: String,
    pub count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PromptTraffic {
    Interactive,
    AutoRule,
    ScopedAgent,
}

#[derive(Debug, Default, Serialize)]
pub struct CostlyRows {
    pub total: usize,
    pub now_automated: usize,
    pub still_prompting: usize,
    pub remaining_shapes: Vec<CountedLabel>,
}

#[derive(Debug, Serialize)]
pub struct RuleHealth {
    pub loaded_rules: usize,
    pub enabled_rules: usize,
    pub scope_findings: Vec<ScopeFinding>,
    pub refusals: rules::RuleRefusals,
}

#[derive(Debug, Serialize)]
pub struct RuntimeFailureCount {
    pub rule_id: String,
    pub rule_name: String,
    pub count: usize,
}

#[derive(Debug, Default, Serialize)]
pub struct Verification {
    pub enabled: bool,
    pub eligible: usize,
    pub agree: usize,
    pub deleted_rule: usize,
    pub disabled_rule: usize,
    pub pre_creation: usize,
    pub scoped_agent: usize,
    pub legacy_ssh_without_rule_id: usize,
    pub missing_rule_id: usize,
    pub disagreements: usize,
    pub failures: Vec<VerificationFailure>,
    pub failures_omitted: usize,
    pub attribution_changed: usize,
    pub attribution_changes: Vec<AttributionChange>,
    pub attribution_changes_omitted: usize,
}

#[derive(Debug, Serialize)]
pub struct VerificationFailure {
    pub timestamp: u64,
    pub wrap: String,
    pub joined_argv: String,
    pub subjects: Vec<String>,
    pub recorded: String,
    pub replayed: String,
}

#[derive(Debug, Serialize)]
pub struct AttributionChange {
    pub timestamp: u64,
    pub wrap: String,
    pub recorded: BTreeMap<String, String>,
    pub replayed: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SimulatedKind {
    Approve,
    Deny,
    Prompt,
}

#[derive(Debug, Clone)]
struct Simulated {
    kind: SimulatedKind,
    rule_id: Option<String>,
    rule_name: Option<String>,
    approvals: BTreeMap<String, String>,
    mandated: bool,
    failures: Vec<(String, String)>,
}

#[derive(Default)]
struct AttributionAccumulator {
    rule_name: String,
    asks: usize,
    approved_subjects: usize,
}

/// Replay every applicable row in `audit_path` through [`rules::evaluate`].
/// The adapter constructs only `EvalCtx`; parsing, wasm execution, precedence,
/// and per-subject aggregation all remain production code.
pub fn replay_audit(
    audit_path: &Path,
    loaded: &LoadedRules,
    scope_findings: Vec<ScopeFinding>,
    options: &ReplayOptions,
) -> Result<StatsReport> {
    let mut rows = RowCounts::default();
    let mut outcomes = Outcomes::default();
    let mut attribution: BTreeMap<(String, String), AttributionAccumulator> = BTreeMap::new();
    let mut prompt_shapes = BTreeMap::new();
    let mut prompt_recorded = BTreeMap::new();
    let mut costly = CostlyRows::default();
    let mut costly_shapes = BTreeMap::new();
    let mut runtime_failures: BTreeMap<(String, String), usize> = BTreeMap::new();
    let mut verification = Verification {
        enabled: options.verify,
        ..Verification::default()
    };
    let rules_by_id: HashMap<&str, &rules::Rule> = loaded
        .rules
        .iter()
        .map(|rule| (rule.id.as_str(), rule))
        .collect();
    let mut decision_cache: HashMap<String, Simulated> = HashMap::new();
    let mut decision_cache_bytes: usize = 0;

    let summary = crate::audit::visit_history(audit_path, |entry| {
        if options
            .since_unix
            .is_some_and(|since| entry.ts_unix < since)
            || options
                .wrap
                .as_deref()
                .is_some_and(|wrap| entry.wrap != wrap)
        {
            rows.filtered += 1;
            return Ok(());
        }

        if scoped_agent_row(&entry) {
            rows.scoped_agent += 1;
            bump_recorded(
                &mut prompt_recorded,
                PromptTraffic::ScopedAgent,
                &entry.decision,
            );
            if options.verify {
                verification.scoped_agent += 1;
            }
            return Ok(());
        }

        if !entry.rules_were_evaluated() {
            rows.not_evaluated += 1;
            return Ok(());
        }

        rows.replayed += 1;
        let joined_argv = entry.joined_argv();
        let subjects = replay_subjects(&entry);
        let projected_callers: Vec<_> = entry
            .callers
            .iter()
            .map(|caller| (&caller.name, &caller.command, &caller.exe))
            .collect();
        let cache_key = serde_json::to_string(&(
            &entry.wrap,
            &joined_argv,
            &projected_callers,
            &entry.cwd,
            &subjects,
        ))?;
        let simulated = if let Some(cached) = decision_cache.get(&cache_key) {
            cached.clone()
        } else {
            let callers: Vec<EvalCaller<'_>> = entry
                .callers
                .iter()
                .map(|caller| EvalCaller {
                    name: &caller.name,
                    command: &caller.command,
                    exe: caller.exe.as_deref(),
                })
                .collect();
            let subject_refs: Vec<&str> = subjects.iter().map(String::as_str).collect();
            let evaluation = rules::evaluate(
                &loaded.rules,
                &loaded.modules,
                &EvalCtx {
                    wrap: &entry.wrap,
                    joined_argv: &joined_argv,
                    callers: &callers,
                    cwd: &entry.cwd,
                    secrets: &subject_refs,
                },
            );
            let simulated = match evaluation.hit {
                Some(hit) => Simulated {
                    kind: match hit.decide {
                        RuleDecision::Approve => SimulatedKind::Approve,
                        RuleDecision::Deny => SimulatedKind::Deny,
                    },
                    rule_id: Some(hit.rule_id),
                    rule_name: Some(hit.rule_name),
                    approvals: hit.approvals,
                    mandated: false,
                    failures: evaluation
                        .wasm_failures
                        .into_iter()
                        .map(|failure| (failure.rule_id, failure.rule_name))
                        .collect(),
                },
                None => Simulated {
                    kind: SimulatedKind::Prompt,
                    rule_id: evaluation
                        .mandated_prompt
                        .as_ref()
                        .map(|mandate| mandate.rule_id.clone()),
                    rule_name: evaluation
                        .mandated_prompt
                        .as_ref()
                        .map(|mandate| mandate.rule_name.clone()),
                    approvals: BTreeMap::new(),
                    mandated: evaluation.mandated_prompt.is_some(),
                    failures: evaluation
                        .wasm_failures
                        .into_iter()
                        .map(|failure| (failure.rule_id, failure.rule_name))
                        .collect(),
                },
            };
            let cache_entry_bytes = cache_key.len() + std::mem::size_of::<Simulated>();
            if decision_cache_bytes.saturating_add(cache_entry_bytes) <= MAX_DECISION_CACHE_BYTES {
                decision_cache_bytes += cache_entry_bytes;
                decision_cache.insert(cache_key, simulated.clone());
            }
            simulated
        };

        for (rule_id, rule_name) in &simulated.failures {
            *runtime_failures
                .entry((rule_id.clone(), rule_name.clone()))
                .or_insert(0) += 1;
        }
        record_outcome(
            &entry,
            &simulated,
            &rules_by_id,
            &mut outcomes,
            &mut attribution,
            &mut prompt_shapes,
            &mut prompt_recorded,
        );

        if entry.decision == "approve+remember" || entry.decision == "abandoned" {
            costly.total += 1;
            if matches!(simulated.kind, SimulatedKind::Approve | SimulatedKind::Deny) {
                costly.now_automated += 1;
            } else {
                costly.still_prompting += 1;
                *costly_shapes.entry(prompt_shape(&entry)).or_insert(0) += 1;
            }
        }

        if options.verify {
            verify_row(
                &entry,
                &subjects,
                &simulated,
                &rules_by_id,
                &mut verification,
                options.top,
            );
        }
        Ok(())
    })?;
    rows.decoded = summary.entries;
    rows.malformed = summary.malformed;

    set_percentages(&mut outcomes, rows.replayed);
    let top = options.top;
    costly.remaining_shapes = top_counts(costly_shapes, top);
    let attribution = attribution
        .into_iter()
        .map(|((rule_id, decision), value)| RuleAttribution {
            rule_id,
            rule_name: value.rule_name,
            decision,
            asks: value.asks,
            approved_subjects: value.approved_subjects,
        })
        .collect();
    let prompt_recorded = prompt_recorded
        .into_iter()
        .map(|((traffic, decision), count)| RecordedPromptDecision {
            traffic,
            decision,
            count,
        })
        .collect();
    let runtime_failures = runtime_failures
        .into_iter()
        .map(|((rule_id, rule_name), count)| RuntimeFailureCount {
            rule_id,
            rule_name,
            count,
        })
        .collect();

    Ok(StatsReport {
        schema_version: 1,
        filters: ReportFilters {
            since_unix: options.since_unix,
            wrap: options.wrap.clone(),
            audit_path: audit_path.display().to_string(),
            top,
        },
        rows,
        outcomes,
        attribution,
        prompt_shapes: top_counts(prompt_shapes, top),
        prompt_recorded,
        costly,
        health: RuleHealth {
            loaded_rules: loaded.rules.len(),
            enabled_rules: loaded.rules.iter().filter(|rule| rule.enabled).count(),
            scope_findings,
            refusals: loaded.refusals.clone(),
        },
        runtime_failures,
        verification,
    })
}

fn record_outcome(
    entry: &AuditEntry,
    simulated: &Simulated,
    rules_by_id: &HashMap<&str, &rules::Rule>,
    outcomes: &mut Outcomes,
    attribution: &mut BTreeMap<(String, String), AttributionAccumulator>,
    prompt_shapes: &mut BTreeMap<String, usize>,
    prompt_recorded: &mut BTreeMap<(PromptTraffic, String), usize>,
) {
    match simulated.kind {
        SimulatedKind::Approve => {
            outcomes.auto_approve.count += 1;
            if let (Some(rule_id), Some(rule_name)) = (&simulated.rule_id, &simulated.rule_name) {
                let winner = attribution
                    .entry((rule_id.clone(), "approve".to_owned()))
                    .or_default();
                winner.rule_name = rule_name.clone();
                winner.asks += 1;
            }
            for rule_id in simulated.approvals.values() {
                let value = attribution
                    .entry((rule_id.clone(), "approve".to_owned()))
                    .or_default();
                value.rule_name = rules_by_id
                    .get(rule_id.as_str())
                    .map_or_else(|| rule_id.clone(), |rule| rule.name.clone());
                value.approved_subjects += 1;
            }
        }
        SimulatedKind::Deny => {
            outcomes.auto_deny.count += 1;
            if let (Some(rule_id), Some(rule_name)) = (&simulated.rule_id, &simulated.rule_name) {
                let value = attribution
                    .entry((rule_id.clone(), "deny".to_owned()))
                    .or_default();
                value.rule_name = rule_name.clone();
                value.asks += 1;
            }
        }
        SimulatedKind::Prompt => {
            outcomes.prompt.count += 1;
            if simulated.mandated {
                outcomes.prompt.mandated += 1;
                if let (Some(rule_id), Some(rule_name)) = (&simulated.rule_id, &simulated.rule_name)
                {
                    let value = attribution
                        .entry((rule_id.clone(), "prompt".to_owned()))
                        .or_default();
                    value.rule_name = rule_name.clone();
                    value.asks += 1;
                }
            } else {
                outcomes.prompt.uncovered += 1;
            }
            *prompt_shapes.entry(prompt_shape(entry)).or_insert(0) += 1;
            let traffic = if entry.decision.ends_with("+auto") {
                PromptTraffic::AutoRule
            } else {
                PromptTraffic::Interactive
            };
            bump_recorded(prompt_recorded, traffic, &entry.decision);
        }
    }
}

fn verify_row(
    entry: &AuditEntry,
    subjects: &[String],
    simulated: &Simulated,
    rules_by_id: &HashMap<&str, &rules::Rule>,
    verification: &mut Verification,
    max_details: usize,
) {
    let recorded_kind = match entry.decision.as_str() {
        "approve+auto" => Some(SimulatedKind::Approve),
        "deny+auto" => Some(SimulatedKind::Deny),
        _ => None,
    };
    let Some(recorded_kind) = recorded_kind else {
        return;
    };
    let Some(rule_id) = entry.rule_id.as_deref() else {
        if entry.wrap.starts_with("ssh:") {
            verification.legacy_ssh_without_rule_id += 1;
        } else {
            verification.missing_rule_id += 1;
        }
        return;
    };
    let Some(rule) = rules_by_id.get(rule_id) else {
        verification.deleted_rule += 1;
        return;
    };
    if entry.ts_unix < rule.created_at_unix {
        verification.pre_creation += 1;
        return;
    }
    if !rule.enabled {
        verification.disabled_rule += 1;
        return;
    }
    verification.eligible += 1;
    if simulated.kind == recorded_kind {
        verification.agree += 1;
        let recorded_attribution = if entry.approvers.is_empty() {
            BTreeMap::from([("representative".to_owned(), rule_id.to_owned())])
        } else {
            entry.approvers.clone()
        };
        let replayed_attribution = if entry.approvers.is_empty() {
            simulated
                .rule_id
                .as_ref()
                .map(|id| BTreeMap::from([("representative".to_owned(), id.clone())]))
                .unwrap_or_default()
        } else {
            simulated.approvals.clone()
        };
        if recorded_attribution != replayed_attribution {
            verification.attribution_changed += 1;
            if verification.attribution_changes.len() < max_details {
                verification.attribution_changes.push(AttributionChange {
                    timestamp: entry.ts_unix,
                    wrap: entry.wrap.clone(),
                    recorded: recorded_attribution,
                    replayed: replayed_attribution,
                });
            } else {
                verification.attribution_changes_omitted += 1;
            }
        }
        return;
    }
    verification.disagreements += 1;
    if verification.failures.len() < max_details {
        verification.failures.push(VerificationFailure {
            timestamp: entry.ts_unix,
            wrap: entry.wrap.clone(),
            joined_argv: prompt_shape(entry),
            subjects: subjects.to_vec(),
            recorded: format!("{} by rule {rule_id}", entry.decision),
            replayed: simulated_label(simulated),
        });
    } else {
        verification.failures_omitted += 1;
    }
}

fn simulated_label(simulated: &Simulated) -> String {
    let kind = match simulated.kind {
        SimulatedKind::Approve => "approve",
        SimulatedKind::Deny => "deny",
        SimulatedKind::Prompt => "prompt",
    };
    simulated.rule_id.as_deref().map_or_else(
        || kind.to_owned(),
        |rule_id| format!("{kind} by rule {rule_id}"),
    )
}

fn scoped_agent_row(entry: &AuditEntry) -> bool {
    entry.wrap.starts_with("agent:")
        || matches!(
            entry.decision.as_str(),
            "approve+agent-session" | "deny+out-of-scope"
        )
}

fn replay_subjects(entry: &AuditEntry) -> Vec<String> {
    rules::evaluation_subjects(&entry.wrap, entry.secrets.iter().map(String::as_str))
        .into_iter()
        .map(std::borrow::Cow::into_owned)
        .collect()
}

fn replay_command(entry: &AuditEntry) -> Vec<String> {
    entry.evaluator_command()
}

fn prompt_shape(entry: &AuditEntry) -> String {
    // `read` arguments are secret references and `store` carries the child
    // command rather than a structural subcommand. Neither belongs in a
    // report intended for sharing.
    if matches!(entry.wrap.as_str(), "read" | "store") || entry.wrap.starts_with("ssh:") {
        return entry.wrap.clone();
    }
    let command = replay_command(entry);
    let skip = usize::from(command.first() == Some(&entry.wrap));
    let suffix = command
        .iter()
        .skip(skip)
        .take(2)
        .map(|token| bounded(token, 80))
        .collect::<Vec<_>>()
        .join(" ");
    if suffix.is_empty() {
        entry.wrap.clone()
    } else {
        format!("{} {suffix}", entry.wrap)
    }
}

fn bounded(value: &str, max_chars: usize) -> String {
    let mut chars = value.chars();
    let prefix: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        format!("{prefix}…")
    } else {
        prefix
    }
}

fn bump_recorded(
    counts: &mut BTreeMap<(PromptTraffic, String), usize>,
    traffic: PromptTraffic,
    decision: &str,
) {
    *counts.entry((traffic, decision.to_owned())).or_insert(0) += 1;
}

fn top_counts(counts: BTreeMap<String, usize>, top: usize) -> Vec<CountedLabel> {
    let mut values: Vec<_> = counts
        .into_iter()
        .map(|(label, count)| CountedLabel { label, count })
        .collect();
    values.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.label.cmp(&right.label))
    });
    values.truncate(top);
    values
}

fn set_percentages(outcomes: &mut Outcomes, total: usize) {
    outcomes.auto_approve.percent = percent(outcomes.auto_approve.count, total);
    outcomes.auto_deny.percent = percent(outcomes.auto_deny.count, total);
    outcomes.prompt.percent = percent(outcomes.prompt.count, total);
}

fn percent(count: usize, total: usize) -> f64 {
    if total == 0 {
        0.0
    } else {
        (count as f64 / total as f64 * 10_000.0).round() / 100.0
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::io::Write as _;

    use crate::audit::{AuditCaller, AuditEntry};
    use crate::rules::{
        LoadedRules, Rule, RuleBody, RuleDecision, RuleMatch, StaticDecision, WasmRule,
    };
    use crate::wasm_rules::RuleModule;

    use super::{replay_audit, ReplayOptions};

    const APPROVE_IF: &[u8] = include_bytes!("../tests/fixtures/wasm_rules/approve_if.wasm");
    const PROMPTS: &[u8] = include_bytes!("../tests/fixtures/wasm_rules/prompts.wasm");

    fn declarative(id: &str, wrap: &str, decision: RuleDecision, subjects: &[&str]) -> Rule {
        Rule {
            id: id.to_owned(),
            name: id.to_owned(),
            enabled: true,
            wraps: None,
            trained_secrets: subjects
                .iter()
                .map(|s| (*s).to_owned())
                .collect::<BTreeSet<_>>(),
            created_at_unix: 10,
            body: RuleBody::Declarative {
                r#match: RuleMatch {
                    wrap: wrap.to_owned(),
                    argv: None,
                    ancestor: None,
                    cwd: None,
                },
                decide: StaticDecision::from(decision),
            },
        }
    }

    fn wasm(id: &str, subjects: &[&str]) -> Rule {
        Rule {
            id: id.to_owned(),
            name: id.to_owned(),
            enabled: true,
            wraps: None,
            trained_secrets: subjects.iter().map(|s| (*s).to_owned()).collect(),
            created_at_unix: 10,
            body: RuleBody::Wasm(WasmRule {
                path: format!("rules/{id}.wasm"),
                sha256: "0".repeat(64),
                declared_secrets: None,
            }),
        }
    }

    fn row(
        ts: u64,
        wrap: &str,
        args: &[&str],
        secrets: &[&str],
        decision: &str,
        rule_id: Option<&str>,
    ) -> AuditEntry {
        AuditEntry {
            ts_unix: ts,
            cwd: "/home/me/oss/project".to_owned(),
            wrap: wrap.to_owned(),
            args: args.iter().map(|s| (*s).to_owned()).collect(),
            command: None,
            callers: vec![AuditCaller {
                pid: 1,
                name: "Cursor".to_owned(),
                command: "/Applications/Cursor.app/Contents/MacOS/Cursor".to_owned(),
                exe: Some("/Applications/Cursor.app/Contents/MacOS/Cursor".to_owned()),
            }],
            callers_truncated: Some(false),
            secrets: secrets.iter().map(|s| (*s).to_owned()).collect(),
            decision: decision.to_owned(),
            deciding_device: None,
            reason: None,
            rule_id: rule_id.map(str::to_owned),
            approvers: BTreeMap::new(),
            fingerprint: None,
            sign_anchor: None,
            declared_by: None,
            unverified_guest_chain: None,
        }
    }

    #[test]
    fn fixture_covers_replay_aggregation_history_classes_and_concatenation() {
        let rules = vec![
            declarative("approve", "gh", RuleDecision::Approve, &["GITHUB_TOKEN"]),
            declarative("deny", "npm", RuleDecision::Deny, &["NPM_TOKEN"]),
            wasm("prompt", &["DEPLOY_TOKEN"]),
            wasm("wasm-a", &["A"]),
            wasm("wasm-b", &["B"]),
        ];
        let mut modules = crate::rules::RuleModules::new();
        modules.insert(
            "prompt".to_owned(),
            RuleModule::from_binary(PROMPTS).expect("prompt wasm"),
        );
        modules.insert(
            "wasm-a".to_owned(),
            RuleModule::from_binary(APPROVE_IF).expect("approve wasm A"),
        );
        modules.insert(
            "wasm-b".to_owned(),
            RuleModule::from_binary(APPROVE_IF).expect("approve wasm B"),
        );
        let loaded = LoadedRules {
            rules,
            modules,
            ..LoadedRules::default()
        };
        let rows = [
            row(
                20,
                "gh",
                &["api"],
                &["GITHUB_TOKEN"],
                "approve+auto",
                Some("approve"),
            ),
            row(
                20,
                "npm",
                &["publish"],
                &["NPM_TOKEN"],
                "deny+auto",
                Some("deny"),
            ),
            row(20, "deploy", &["prod"], &["DEPLOY_TOKEN"], "approve", None),
            row(
                20,
                "cargo",
                &["publish"],
                &["CARGO_TOKEN"],
                "abandoned",
                None,
            ),
            row(
                20,
                "gh",
                &["api", "--get", "/repos/me/x"],
                &["A", "B"],
                "approve+auto",
                Some("wasm-a"),
            ),
            row(
                20,
                "old",
                &[],
                &["OLD_TOKEN"],
                "approve+auto",
                Some("deleted"),
            ),
            row(
                5,
                "gh",
                &["api"],
                &["GITHUB_TOKEN"],
                "approve+auto",
                Some("approve"),
            ),
            row(
                20,
                "agent:sandbox",
                &[],
                &["secret://op/item/token"],
                "approve+agent-session",
                None,
            ),
        ];
        let mut log = tempfile::NamedTempFile::new().expect("audit fixture");
        for pair in rows.chunks(2) {
            for entry in pair {
                write!(
                    log,
                    "{}",
                    serde_json::to_string(entry).expect("serialize row")
                )
                .expect("write row");
            }
            writeln!(log).expect("finish physical line");
        }
        log.flush().expect("flush audit fixture");

        let report = replay_audit(
            log.path(),
            &loaded,
            Vec::new(),
            &ReplayOptions {
                verify: true,
                ..ReplayOptions::default()
            },
        )
        .expect("replay fixture");

        assert_eq!(report.rows.replayed, 7);
        assert_eq!(report.rows.scoped_agent, 1);
        assert_eq!(report.outcomes.auto_approve.count, 3);
        assert_eq!(report.outcomes.auto_deny.count, 1);
        assert_eq!(report.outcomes.prompt.count, 3);
        assert_eq!(report.outcomes.prompt.mandated, 1);
        assert_eq!(report.outcomes.prompt.uncovered, 2);
        assert_eq!(report.verification.eligible, 3);
        assert_eq!(report.verification.agree, 3);
        assert_eq!(report.verification.deleted_rule, 1);
        assert_eq!(report.verification.pre_creation, 1);
        assert_eq!(report.verification.scoped_agent, 1);
        assert!(report.verification.failures.is_empty());
        assert_eq!(report.costly.total, 1);
        assert_eq!(report.costly.still_prompting, 1);
        assert!(report
            .attribution
            .iter()
            .any(|item| item.rule_id == "wasm-b" && item.rule_name == "wasm-b"));
        assert!(report.attribution.iter().any(|item| {
            item.rule_id == "prompt" && item.decision == "prompt" && item.asks == 1
        }));

        let json = serde_json::to_value(&report).expect("stable JSON report");
        assert_eq!(json["schema_version"], 1);
        let keys: BTreeSet<&str> = json
            .as_object()
            .expect("report object")
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            [
                "attribution",
                "costly",
                "filters",
                "health",
                "outcomes",
                "prompt_recorded",
                "prompt_shapes",
                "rows",
                "runtime_failures",
                "schema_version",
                "verification",
            ]
            .into_iter()
            .collect()
        );
        assert!(!json.to_string().contains("fingerprint"));
    }

    #[test]
    fn verify_classifies_history_for_a_disabled_rule_without_comparing_it() {
        let mut rule = declarative("paused", "gh", RuleDecision::Approve, &["GITHUB_TOKEN"]);
        rule.enabled = false;
        let loaded = LoadedRules {
            rules: vec![rule],
            ..LoadedRules::default()
        };
        let entry = row(
            20,
            "gh",
            &["api", "/user"],
            &["GITHUB_TOKEN"],
            "approve+auto",
            Some("paused"),
        );
        let mut log = tempfile::NamedTempFile::new().expect("audit fixture");
        writeln!(
            log,
            "{}",
            serde_json::to_string(&entry).expect("serialize row")
        )
        .expect("write row");

        let report = replay_audit(
            log.path(),
            &loaded,
            Vec::new(),
            &ReplayOptions {
                verify: true,
                ..ReplayOptions::default()
            },
        )
        .expect("replay fixture");

        assert_eq!(report.verification.eligible, 0);
        assert_eq!(report.verification.disagreements, 0);
        assert_eq!(report.verification.disabled_rule, 1);
    }

    #[test]
    fn store_history_is_not_replayed_as_an_ask() {
        let loaded = LoadedRules::default();
        let entry = row(
            20,
            "store",
            &["npm", "publish"],
            &["NPM_TOKEN"],
            "approve",
            None,
        );
        let mut log = tempfile::NamedTempFile::new().expect("audit fixture");
        writeln!(
            log,
            "{}",
            serde_json::to_string(&entry).expect("serialize row")
        )
        .expect("write row");

        let report = replay_audit(log.path(), &loaded, Vec::new(), &ReplayOptions::default())
            .expect("replay fixture");

        assert_eq!(report.rows.replayed, 0);
        assert_eq!(report.rows.not_evaluated, 1);
        assert_eq!(report.outcomes.prompt.count, 0);
    }

    #[test]
    fn legacy_ssh_auto_rows_without_attribution_are_classified_explicitly() {
        let loaded = LoadedRules::default();
        let entry = row(20, "ssh:github", &[], &[], "approve+auto", None);
        let mut log = tempfile::NamedTempFile::new().expect("audit fixture");
        writeln!(
            log,
            "{}",
            serde_json::to_string(&entry).expect("serialize row")
        )
        .expect("write row");

        let report = replay_audit(
            log.path(),
            &loaded,
            Vec::new(),
            &ReplayOptions {
                verify: true,
                ..ReplayOptions::default()
            },
        )
        .expect("replay fixture");

        assert_eq!(report.verification.eligible, 0);
        assert_eq!(report.verification.legacy_ssh_without_rule_id, 1);
        assert_eq!(report.verification.missing_rule_id, 0);
    }

    #[test]
    fn verification_mismatch_is_loud_and_reproducible() {
        let loaded = LoadedRules {
            rules: vec![declarative(
                "approve",
                "gh",
                RuleDecision::Approve,
                &["GITHUB_TOKEN"],
            )],
            ..LoadedRules::default()
        };
        let entry = row(
            20,
            "gh",
            &["api", "--method", "DELETE"],
            &["GITHUB_TOKEN"],
            "deny+auto",
            Some("approve"),
        );
        let mut log = tempfile::NamedTempFile::new().expect("audit fixture");
        writeln!(log, "{}", serde_json::to_string(&entry).expect("serialize")).expect("write");

        let report = replay_audit(
            log.path(),
            &loaded,
            Vec::new(),
            &ReplayOptions {
                verify: true,
                ..ReplayOptions::default()
            },
        )
        .expect("replay mismatch");

        assert_eq!(report.verification.eligible, 1);
        assert_eq!(report.verification.agree, 0);
        assert_eq!(report.verification.failures.len(), 1);
        assert_eq!(
            report.verification.failures[0].joined_argv,
            "gh api --method"
        );
        assert_eq!(
            report.verification.failures[0].subjects,
            vec!["GITHUB_TOKEN"]
        );
    }

    #[test]
    fn legacy_rows_reconstruct_the_live_command_for_each_ask_path() {
        let cases = [
            ("gh", vec!["api", "/user"], "gh api /user"),
            ("run", vec!["npm", "publish"], "npm publish"),
            ("read", vec!["read", "github_token"], "read github_token"),
            ("ssh:work", vec![], "ssh-sign work"),
        ];

        for (wrap, args, expected) in cases {
            let entry = row(20, wrap, &args, &[], "approve", None);
            assert_eq!(
                crate::rules::joined_argv(&super::replay_command(&entry)),
                expected,
                "legacy {wrap} row"
            );
        }
    }

    #[test]
    fn a_changed_approver_is_informational_when_the_decision_still_agrees() {
        let loaded = LoadedRules {
            rules: vec![
                declarative("a-new", "gh", RuleDecision::Approve, &["TOKEN"]),
                declarative("z-old", "gh", RuleDecision::Approve, &["TOKEN"]),
            ],
            ..LoadedRules::default()
        };
        let mut entry = row(
            20,
            "gh",
            &["api"],
            &["TOKEN"],
            "approve+auto",
            Some("z-old"),
        );
        entry
            .approvers
            .insert("TOKEN".to_owned(), "z-old".to_owned());
        let mut log = tempfile::NamedTempFile::new().expect("audit fixture");
        writeln!(log, "{}", serde_json::to_string(&entry).expect("serialize")).expect("write");

        let report = replay_audit(
            log.path(),
            &loaded,
            Vec::new(),
            &ReplayOptions {
                verify: true,
                ..ReplayOptions::default()
            },
        )
        .expect("replay attribution change");

        assert_eq!(report.verification.eligible, 1);
        assert_eq!(report.verification.agree, 1);
        assert_eq!(report.verification.disagreements, 0);
        assert_eq!(report.verification.attribution_changed, 1);
        assert_eq!(report.verification.attribution_changes.len(), 1);
    }

    #[test]
    fn verification_redacts_read_references_but_keeps_audit_subject_names() {
        let loaded = LoadedRules {
            rules: vec![declarative(
                "approve",
                "read",
                RuleDecision::Approve,
                &["SUBJECT_NAME_MARKER"],
            )],
            ..LoadedRules::default()
        };
        let entry = row(
            20,
            "read",
            &["read", "REFERENCE_MARKER"],
            &["SUBJECT_NAME_MARKER"],
            "deny+auto",
            Some("approve"),
        );
        let mut log = tempfile::NamedTempFile::new().expect("audit fixture");
        writeln!(log, "{}", serde_json::to_string(&entry).expect("serialize")).expect("write");

        let report = replay_audit(
            log.path(),
            &loaded,
            Vec::new(),
            &ReplayOptions {
                verify: true,
                ..ReplayOptions::default()
            },
        )
        .expect("replay read mismatch");
        let json = serde_json::to_string(&report).expect("serialize report");

        assert!(!json.contains("REFERENCE_MARKER"));
        assert!(json.contains("SUBJECT_NAME_MARKER"));
        assert_eq!(report.verification.failures[0].joined_argv, "read");
    }
}
