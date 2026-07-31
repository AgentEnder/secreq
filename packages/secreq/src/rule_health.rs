//! Cross-check configured auto-rule scopes against subjects real asks declare.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::rules::{self, Rule, RuleBody, RuleDecision};
use crate::wraps::WrapsConfig;

/// Whether a scope finding makes the live ruleset invalid or is a risky but
/// explicit configuration worth surfacing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeSeverity {
    Error,
    Warning,
}

/// Stable machine-readable category for one scope finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeFindingCode {
    UnknownSubject,
    NamedSecretIsNotSubject,
    UnknownSshIdentity,
    UnscopedApprover,
    NeverConsulted,
}

/// One rule/config mismatch. Messages name only configured subject names,
/// never references or resolved values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScopeFinding {
    pub severity: ScopeSeverity,
    pub code: ScopeFindingCode,
    pub rule_id: String,
    pub rule_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    pub message: String,
}

#[derive(Default)]
struct SubjectUniverse {
    /// Ask subject -> wraps capable of declaring it.
    reaches: BTreeMap<String, BTreeSet<String>>,
    /// Named secret declaration -> env keys that actually bind it.
    named_bindings: BTreeMap<String, BTreeSet<String>>,
}

impl SubjectUniverse {
    fn from_config(config: &WrapsConfig) -> SubjectUniverse {
        let mut out = SubjectUniverse::default();
        for (wrap_name, wrap) in &config.wraps {
            for subject in
                rules::evaluation_subjects(wrap_name, wrap.env.keys().map(String::as_str))
            {
                out.reaches
                    .entry(subject.into_owned())
                    .or_default()
                    .insert(wrap_name.clone());
            }
            for (env_name, raw) in &wrap.env {
                if let Ok(resolved) = config.resolve_ref(raw) {
                    if let Some(name) = resolved.declared_as {
                        out.named_bindings
                            .entry(name)
                            .or_default()
                            .insert(env_name.clone());
                    }
                }
            }
        }
        for key_id in config.ssh.keys() {
            let subject = format!("ssh:{key_id}");
            for evaluated in rules::evaluation_subjects(&subject, std::iter::empty()) {
                out.reaches
                    .entry(evaluated.into_owned())
                    .or_default()
                    .insert(subject.clone());
            }
        }
        // `secreq read <name>` puts a declared name itself into SecretAsk;
        // it is not limited to env keys used by configured wraps.
        for name in config.secrets.keys() {
            for subject in rules::evaluation_subjects("read", std::iter::once(name.as_str())) {
                out.reaches
                    .entry(subject.into_owned())
                    .or_default()
                    .insert("read".to_owned());
            }
        }
        out
    }
}

/// Validate every rule against the subjects the current config can put into
/// the production evaluator: wrap env keys, `ssh:<key_id>`, and
/// `wrap:<name>` for gate-only wraps.
pub fn validate_rule_scopes(config: &WrapsConfig, rules: &[Rule]) -> Vec<ScopeFinding> {
    let universe = SubjectUniverse::from_config(config);
    let candidates: Vec<&str> = universe.reaches.keys().map(String::as_str).collect();
    let mut findings = Vec::new();

    for rule in rules {
        let mut subjects = rule.trained_secrets.clone();
        if let Some(declared) = rule.wasm().and_then(|wasm| wasm.declared_secrets.as_ref()) {
            subjects.extend(declared.iter().cloned());
        }
        if rule.trained_secrets.is_empty() && rule_can_approve(rule) {
            findings.push(finding(
                rule,
                ScopeSeverity::Warning,
                ScopeFindingCode::UnscopedApprover,
                None,
                format!(
                    "rule `{}` has no trained subjects; an approve can apply to every ask",
                    rule.name
                ),
            ));
        }
        if subjects.is_empty() {
            continue;
        }

        let mut reachable_wraps = BTreeSet::new();
        let mut invalid = false;
        for subject in &subjects {
            if config.secrets.contains_key(subject) {
                if let RuleBody::Declarative { r#match, decide } = &rule.body {
                    let directly_declared_for_wrap = universe
                        .reaches
                        .get(subject)
                        .is_some_and(|wraps| wraps.contains(&r#match.wrap));
                    if r#match.wrap != "read"
                        && !directly_declared_for_wrap
                        && decide.decision() == RuleDecision::Approve
                    {
                        let bindings = universe.named_bindings.get(subject);
                        let message = match bindings {
                            Some(bindings) if !bindings.is_empty() => format!(
                                "`{subject}` is a valid `secreq read` subject, but wrap `{}` asks declare env keys; use {} for this approval",
                                r#match.wrap,
                                quoted(bindings)
                            ),
                            _ => format!(
                                "`{subject}` is a valid `secreq read` subject, but no `{}` ask declares it",
                                r#match.wrap
                            ),
                        };
                        findings.push(finding(
                            rule,
                            ScopeSeverity::Error,
                            ScopeFindingCode::NamedSecretIsNotSubject,
                            Some(subject.clone()),
                            message,
                        ));
                        invalid = true;
                        continue;
                    }
                }
            }
            if let Some(wraps) = universe.reaches.get(subject) {
                if rule.trained_secrets.contains(subject) {
                    reachable_wraps.extend(wraps.iter().cloned());
                }
                continue;
            }
            invalid = true;
            let suggestion_candidates: Vec<&str> = if subject.starts_with("ssh:") {
                candidates
                    .iter()
                    .copied()
                    .filter(|candidate| candidate.starts_with("ssh:"))
                    .collect()
            } else {
                candidates.clone()
            };
            let suggestion = closest(subject, &suggestion_candidates)
                .map(|candidate| format!("; did you mean `{candidate}`?"))
                .unwrap_or_default();
            let severity = if subject.starts_with("ssh:")
                || matches!(
                    &rule.body,
                    RuleBody::Declarative { r#match, .. } if r#match.wrap != "run"
                ) {
                ScopeSeverity::Error
            } else {
                ScopeSeverity::Warning
            };
            let (code, message) = if subject.starts_with("ssh:") {
                (
                    ScopeFindingCode::UnknownSshIdentity,
                    format!("`{subject}` names no configured SSH identity{suggestion}"),
                )
            } else {
                let run_note = if severity == ScopeSeverity::Warning {
                    "; it may still be supplied by `secreq run`"
                } else {
                    ""
                };
                (
                    ScopeFindingCode::UnknownSubject,
                    format!(
                        "`{subject}` matches no configured wrap env key, SSH identity, named read subject, or gate-only wrap{suggestion}{run_note}"
                    ),
                )
            };
            findings.push(finding(
                rule,
                severity,
                code,
                Some(subject.clone()),
                message,
            ));
        }

        if !invalid {
            if let Some(scope) = &rule.wraps {
                reachable_wraps.retain(|wrap| scope.contains(wrap));
            }
            if let RuleBody::Declarative { r#match, decide } = &rule.body {
                if rule
                    .wraps
                    .as_ref()
                    .is_some_and(|scope| !scope.contains(&r#match.wrap))
                {
                    findings.push(finding(
                        rule,
                        ScopeSeverity::Error,
                        ScopeFindingCode::NeverConsulted,
                        None,
                        format!(
                            "rule `{}` matches wrap `{}`, but its consultation scope excludes that wrap",
                            rule.name, r#match.wrap
                        ),
                    ));
                    continue;
                }
                // Declarative denies are whole-ask vetoes and deliberately
                // ignore the trained-subject snapshot. A mismatched snapshot
                // can make an approval dead, but never makes a deny
                // unconsultable.
                if decide.decision() == RuleDecision::Deny {
                    continue;
                }
                if !reachable_wraps.contains(&r#match.wrap) {
                    let actual = if reachable_wraps.is_empty() {
                        "no configured wrap".to_owned()
                    } else {
                        reachable_wraps
                            .iter()
                            .cloned()
                            .collect::<Vec<_>>()
                            .join(", ")
                    };
                    findings.push(finding(
                        rule,
                        ScopeSeverity::Error,
                        ScopeFindingCode::NeverConsulted,
                        None,
                        format!(
                            "rule `{}` matches wrap `{}`, but its subjects are declared by {actual}; it can never be consulted",
                            rule.name, r#match.wrap
                        ),
                    ));
                }
            } else if !rule.trained_secrets.is_empty() && reachable_wraps.is_empty() {
                findings.push(finding(
                    rule,
                    ScopeSeverity::Error,
                    ScopeFindingCode::NeverConsulted,
                    None,
                    format!(
                        "rule `{}` has no trained subject reachable inside its consultation wrap scope",
                        rule.name
                    ),
                ));
            }
        }
    }
    findings
}

fn rule_can_approve(rule: &Rule) -> bool {
    match &rule.body {
        RuleBody::Wasm(_) => true,
        RuleBody::Declarative { decide, .. } => decide.decision() == RuleDecision::Approve,
    }
}

fn finding(
    rule: &Rule,
    severity: ScopeSeverity,
    code: ScopeFindingCode,
    subject: Option<String>,
    message: String,
) -> ScopeFinding {
    ScopeFinding {
        severity,
        code,
        rule_id: rule.id.clone(),
        rule_name: rule.name.clone(),
        subject,
        message,
    }
}

fn quoted(values: &BTreeSet<String>) -> String {
    values
        .iter()
        .map(|value| format!("`{value}`"))
        .collect::<Vec<_>>()
        .join(" or ")
}

fn closest<'a>(needle: &str, candidates: &[&'a str]) -> Option<&'a str> {
    if needle.chars().count() > 128 {
        return None;
    }
    let needle = needle.to_ascii_lowercase();
    candidates
        .iter()
        .filter_map(|candidate| {
            let distance = edit_distance(&needle, &candidate.to_ascii_lowercase());
            let limit = 2_usize.max(candidate.chars().count() / 3);
            (distance <= limit).then_some((*candidate, distance))
        })
        .min_by(|(left_name, left_distance), (right_name, right_distance)| {
            left_distance
                .cmp(right_distance)
                .then_with(|| left_name.cmp(right_name))
        })
        .map(|(candidate, _)| candidate)
}

fn edit_distance(left: &str, right: &str) -> usize {
    let mut previous: Vec<usize> = (0..=right.chars().count()).collect();
    for (left_index, left_char) in left.chars().enumerate() {
        let mut current = Vec::with_capacity(previous.len());
        current.push(left_index + 1);
        for (right_index, right_char) in right.chars().enumerate() {
            let insertion = current
                .get(right_index)
                .copied()
                .expect("the row starts with one element and grows once per character")
                + 1;
            let deletion = previous
                .get(right_index + 1)
                .copied()
                .expect("the previous row has one element per right character plus its origin")
                + 1;
            let substitution = previous
                .get(right_index)
                .copied()
                .expect("the previous row includes the preceding right character")
                + usize::from(left_char != right_char);
            current.push(insertion.min(deletion).min(substitution));
        }
        previous = current;
    }
    previous.last().copied().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use crate::rules::{Rule, RuleBody, RuleDecision, RuleMatch, StaticDecision, WasmRule};
    use crate::wraps::WrapsConfig;

    use super::{validate_rule_scopes, ScopeFindingCode, ScopeSeverity};

    fn approve(id: &str, wrap: &str, subjects: &[&str]) -> Rule {
        Rule {
            id: id.to_owned(),
            name: id.to_owned(),
            enabled: true,
            wraps: None,
            trained_secrets: subjects
                .iter()
                .map(|s| (*s).to_owned())
                .collect::<BTreeSet<_>>(),
            created_at_unix: 1,
            body: RuleBody::Declarative {
                r#match: RuleMatch {
                    wrap: wrap.to_owned(),
                    argv: None,
                    ancestor: None,
                    cwd: None,
                },
                decide: StaticDecision::from(RuleDecision::Approve),
            },
        }
    }

    fn config() -> WrapsConfig {
        WrapsConfig::parse(
            r#"
                [secrets.github_token]
                ref = "secret://op/GitHub/token"

                [wraps.gh.env]
                GITHUB_TOKEN = "secret://github_token"

                [wraps.npm.env]
                NPM_TOKEN = "secret://op/npm/token"

                [wraps.op]

                [ssh.deploy]
                public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE2v7v98VSZ3zAZ7Qyn3YrVPaPyAwzp4RmaXxNQQZbwu"
                private_key = "secret://op/SSH/private key"
            "#,
            "fixture",
        )
        .expect("valid config")
    }

    #[test]
    fn reports_unknown_named_ssh_and_unscoped_subjects_with_targeted_help() {
        let rules = [
            approve("typo", "gh", &["GITHUB_TOKN"]),
            approve("named", "gh", &["github_token"]),
            approve("ssh", "ssh:deploy", &["ssh:deply"]),
            approve("unscoped", "npm", &[]),
        ];

        let findings = validate_rule_scopes(&config(), &rules);

        assert!(findings.iter().any(|f| {
            f.code == ScopeFindingCode::UnknownSubject
                && f.message.contains("GITHUB_TOKEN")
                && f.severity == ScopeSeverity::Error
        }));
        assert!(findings.iter().any(|f| {
            f.code == ScopeFindingCode::NamedSecretIsNotSubject
                && f.message.contains("github_token")
                && f.message.contains("GITHUB_TOKEN")
        }));
        assert!(findings.iter().any(|f| {
            f.code == ScopeFindingCode::UnknownSshIdentity && f.message.contains("ssh:deploy")
        }));
        assert!(findings.iter().any(|f| {
            f.code == ScopeFindingCode::UnscopedApprover
                && f.rule_id == "unscoped"
                && f.severity == ScopeSeverity::Warning
        }));
    }

    #[test]
    fn reports_a_rule_whose_valid_subject_can_never_reach_its_wrap() {
        let rule = approve("impossible", "npm", &["GITHUB_TOKEN"]);
        let findings = validate_rule_scopes(&config(), &[rule]);

        assert!(findings.iter().any(|f| {
            f.code == ScopeFindingCode::NeverConsulted
                && f.severity == ScopeSeverity::Error
                && f.message.contains("npm")
                && f.message.contains("gh")
        }));
    }

    #[test]
    fn deny_scope_does_not_claim_the_rule_is_unconsultable() {
        let mut rule = approve("deny", "npm", &["GITHUB_TOKEN"]);
        rule.body = RuleBody::Declarative {
            r#match: RuleMatch {
                wrap: "npm".to_owned(),
                argv: None,
                ancestor: None,
                cwd: None,
            },
            decide: StaticDecision::from(RuleDecision::Deny),
        };

        let findings = validate_rule_scopes(&config(), &[rule]);

        assert!(!findings
            .iter()
            .any(|finding| finding.code == ScopeFindingCode::NeverConsulted));
    }

    #[test]
    fn declared_name_is_a_valid_read_subject() {
        let rule = approve("read-named", "read", &["github_token"]);

        assert!(validate_rule_scopes(&config(), &[rule]).is_empty());
    }

    #[test]
    fn a_named_secret_that_is_also_the_env_key_is_valid_for_that_wrap() {
        let config = WrapsConfig::parse(
            r#"
                [secrets.GITHUB_TOKEN]
                ref = "secret://op/GitHub/token"

                [wraps.brain.env]
                GITHUB_TOKEN = "secret://GITHUB_TOKEN"
            "#,
            "fixture",
        )
        .expect("valid config");
        let rule = approve("brain", "brain", &["GITHUB_TOKEN"]);

        assert!(validate_rule_scopes(&config, &[rule]).is_empty());
    }

    #[test]
    fn run_subjects_are_open_ended_and_only_advisory() {
        let rule = approve("run-ambient", "run", &["CI_JOB_TOKEN"]);
        let findings = validate_rule_scopes(&config(), &[rule]);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, ScopeFindingCode::UnknownSubject);
        assert_eq!(findings[0].severity, ScopeSeverity::Warning);
        assert!(findings[0].message.contains("secreq run"));
    }

    #[test]
    fn consultation_scope_that_excludes_the_match_is_never_consulted() {
        let mut rule = approve("scoped", "gh", &["GITHUB_TOKEN"]);
        rule.wraps = Some(["npm".to_owned()].into_iter().collect());

        let findings = validate_rule_scopes(&config(), &[rule]);

        assert!(findings.iter().any(|finding| {
            finding.code == ScopeFindingCode::NeverConsulted
                && finding.message.contains("consultation scope excludes")
        }));
    }

    #[test]
    fn validates_wasm_declared_subjects_as_well_as_the_operator_grant() {
        let rule = Rule {
            id: "wasm".to_owned(),
            name: "wasm".to_owned(),
            enabled: true,
            wraps: Some(["gh".to_owned()].into_iter().collect()),
            trained_secrets: ["GITHUB_TOKEN".to_owned()].into_iter().collect(),
            created_at_unix: 1,
            body: RuleBody::Wasm(WasmRule {
                path: "rules/wasm.wasm".to_owned(),
                sha256: "0".repeat(64),
                declared_secrets: Some(
                    ["GITHUB_TOKEN".to_owned(), "GITHUB_TOKN".to_owned()]
                        .into_iter()
                        .collect(),
                ),
            }),
        };

        let findings = validate_rule_scopes(&config(), &[rule]);

        assert!(findings.iter().any(|finding| {
            finding.code == ScopeFindingCode::UnknownSubject
                && finding.subject.as_deref() == Some("GITHUB_TOKN")
        }));
    }
}
